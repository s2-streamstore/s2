use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum_server::tls_rustls::RustlsConfig;
use bytesize::ByteSize;
use http::header::AUTHORIZATION;
use s2_common::encryption::S2_ENCRYPTION_KEY_HEADER;
use slatedb::object_store;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::time::Instant;
use tower_http::{
    cors::CorsLayer,
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::{info, warn};

use crate::{backend::Backend, dashboard, handlers, init};

#[derive(clap::Args, Debug, Clone)]
pub struct TlsConfig {
    /// Use a self-signed certificate for TLS
    #[arg(long, conflicts_with_all = ["tls_cert", "tls_key"])]
    pub tls_self: bool,

    /// Path to the TLS certificate file (e.g., cert.pem)
    /// Must be used together with --tls-key
    #[arg(long, requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// Path to the private key file (e.g., key.pem)
    /// Must be used together with --tls-cert
    #[arg(long, requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,
}

#[derive(clap::Args, Debug, Clone)]
pub struct LiteArgs {
    /// Name of the S3 bucket to back the database.
    ///
    /// If not specified, in-memory storage is used unless --local-root is set.
    /// Uses the standard AWS configuration for the endpoint, region and credentials.
    #[arg(long, group = "main_store")]
    pub bucket: Option<String>,

    /// Root directory to back the database on the local filesystem.
    ///
    /// Conflicts with --bucket.
    #[arg(
        long,
        value_name = "DIR",
        conflicts_with = "bucket",
        group = "main_store"
    )]
    pub local_root: Option<PathBuf>,

    /// Name of the S3 bucket to back the write-ahead log (WAL).
    ///
    /// If not specified, the main store is used unless --wal-local-root is set.
    /// Uses the same AWS configuration as --bucket, with optional
    /// S2LITE_WAL_AWS_* overrides for the endpoint, region and credentials.
    ///
    /// Requires --bucket or --local-root. Conflicts with --wal-local-root.
    #[arg(
        long,
        env = "S2LITE_WAL_BUCKET",
        requires = "main_store",
        conflicts_with = "wal_local_root"
    )]
    pub wal_bucket: Option<String>,

    /// Root directory to back the write-ahead log (WAL) on the local filesystem.
    ///
    /// Requires --bucket or --local-root. Conflicts with --wal-bucket.
    #[arg(
        long,
        env = "S2LITE_WAL_LOCAL_ROOT",
        value_name = "DIR",
        requires = "main_store"
    )]
    pub wal_local_root: Option<PathBuf>,

    /// Base path on object storage.
    #[arg(long, default_value = "")]
    pub path: String,

    /// TLS configuration (defaults to plain HTTP if not specified).
    #[command(flatten)]
    pub tls: TlsConfig,

    /// IP address to listen on [default: ::, or 0.0.0.0 if IPv6 is unavailable]
    ///
    /// :: listens on both IPv4 and IPv6. Use 0.0.0.0 to listen on IPv4 only, or
    /// a specific address such as 127.0.0.1 or ::1 to listen on a single interface.
    #[arg(long, value_name = "IP")]
    pub bind_address: Option<IpAddr>,

    /// Port to listen on [default: 443 if HTTPS configured, otherwise 80 for HTTP]
    #[arg(long)]
    pub port: Option<u16>,

    /// Disable permissive CORS headers.
    ///
    /// By default, Lite sends CORS headers that allow browser-based clients
    /// on any origin to connect (e.g. the S2 console). Pass this flag to
    /// suppress those headers for stricter deployments where browser access
    /// should be denied at the HTTP layer.
    #[arg(long)]
    pub no_cors: bool,

    /// Do not serve the web dashboard at /dashboard.
    ///
    /// Can also be set via S2LITE_NO_DASHBOARD environment variable.
    #[arg(
        long,
        env = "S2LITE_NO_DASHBOARD",
        value_parser = clap::builder::FalseyValueParser::new()
    )]
    pub no_dashboard: bool,

    /// Path to a JSON file defining basins and streams to create at startup.
    ///
    /// Creates missing resources and updates existing configs to match the file,
    /// so it is safe to run on repeated restarts. Can also be set via
    /// S2LITE_INIT_FILE environment variable.
    #[arg(long, env = "S2LITE_INIT_FILE")]
    pub init_file: Option<PathBuf>,

    /// Maximum in-flight append metered bytes across all streams before admission blocks.
    #[arg(long, default_value = "128MiB")]
    pub append_inflight_bytes: ByteSize,
}

#[derive(Debug, Clone)]
enum StoreType {
    S3Bucket(String),
    LocalFileSystem(PathBuf),
    InMemory,
}

impl StoreType {
    fn info(&self) -> dashboard::StoreInfo {
        match self {
            StoreType::S3Bucket(bucket) => dashboard::StoreInfo::S3 {
                bucket: bucket.clone(),
            },
            StoreType::LocalFileSystem(root) => dashboard::StoreInfo::Local {
                root: root.display().to_string(),
            },
            StoreType::InMemory => dashboard::StoreInfo::Memory,
        }
    }

    fn default_flush_interval(&self) -> Duration {
        Duration::from_millis(match self {
            StoreType::S3Bucket(_) => 50,
            StoreType::LocalFileSystem(_) | StoreType::InMemory => 5,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerProtocol {
    Http,
    Https { self_signed: bool },
}

impl ServerProtocol {
    fn from_args(args: &LiteArgs) -> Self {
        if args.tls.tls_self {
            Self::Https { self_signed: true }
        } else if args.tls.tls_cert.is_some() {
            Self::Https { self_signed: false }
        } else {
            Self::Http
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::Http => "none",
            Self::Https { self_signed: true } => "self_signed",
            Self::Https { self_signed: false } => "certificate",
        }
    }

    fn scheme(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https { .. } => "https",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https { .. } => 443,
        }
    }

    fn requires_ssl_no_verify(self) -> bool {
        matches!(self, Self::Https { self_signed: true })
    }
}

fn cli_endpoint(protocol: ServerProtocol, ip: IpAddr, port: u16) -> String {
    let scheme = protocol.scheme();
    // `localhost` only stands for the wildcards and the two canonical loopback
    // addresses. Any other loopback address (e.g. 127.0.0.2) must be printed as-is,
    // or the hint points at a different address than the one the server bound.
    let uses_localhost = ip.is_unspecified()
        || ip == IpAddr::V4(Ipv4Addr::LOCALHOST)
        || ip == IpAddr::V6(Ipv6Addr::LOCALHOST);
    if uses_localhost {
        format!("{scheme}://localhost:{port}")
    } else {
        // `SocketAddr` formatting brackets IPv6 addresses, e.g. `[2001:db8::1]:8080`.
        format!("{scheme}://{}", SocketAddr::new(ip, port))
    }
}

fn cli_env_hint(protocol: ServerProtocol, ip: IpAddr, port: u16, dashboard: bool) -> String {
    let endpoint = cli_endpoint(protocol, ip, port);
    let mut lines = vec![
        "copy/paste into a new terminal to point the S2 CLI at this server:".to_string(),
        format!("export S2_ACCOUNT_ENDPOINT={endpoint}"),
        format!("export S2_BASIN_ENDPOINT={endpoint}"),
        "export S2_ACCESS_TOKEN=ignored".to_string(),
    ];

    if protocol.requires_ssl_no_verify() {
        lines.push("export S2_SSL_NO_VERIFY=1".to_string());
    }

    if dashboard {
        lines.push(String::new());
        lines.push(format!("or use the dashboard at {endpoint}/dashboard"));
    }

    lines.join("\n")
}

pub async fn run(args: LiteArgs) -> eyre::Result<()> {
    info!(?args);

    let protocol = ServerProtocol::from_args(&args);
    let port = args.port.unwrap_or_else(|| protocol.default_port());

    // Bind before opening the database, which fences out any other instance
    // using the same store, so that a bad address or a port already in use fails
    // first. Connections are only accepted once the server is ready to serve.
    let socket = BoundSocket::bind(args.bind_address, port)?;
    let addr = socket.addr;
    let cli_hint = cli_env_hint(protocol, addr.ip(), port, !args.no_dashboard);

    let store_type = if let Some(bucket) = args.bucket {
        StoreType::S3Bucket(bucket)
    } else if let Some(local_root) = args.local_root {
        StoreType::LocalFileSystem(local_root)
    } else {
        StoreType::InMemory
    };

    let object_store = init_object_store(&store_type, None).await?;
    let wal_store_type = if let Some(bucket) = args.wal_bucket {
        Some(StoreType::S3Bucket(bucket))
    } else {
        args.wal_local_root.map(StoreType::LocalFileSystem)
    };
    let wal_object_store = match &wal_store_type {
        Some(wal_store_type) => {
            let s3_overrides = match wal_store_type {
                StoreType::S3Bucket(_) => Some(WalS3Overrides::from_env()?),
                StoreType::LocalFileSystem(_) | StoreType::InMemory => None,
            };
            Some(init_object_store(wal_store_type, s3_overrides).await?)
        }
        None => None,
    };

    let db_settings = slatedb::Settings::from_env_with_default(
        "SL8_",
        slatedb::Settings {
            flush_interval: Some(
                wal_store_type
                    .as_ref()
                    .unwrap_or(&store_type)
                    .default_flush_interval(),
            ),
            ..Default::default()
        },
    )?;

    let manifest_poll_interval = db_settings.manifest_poll_interval;

    let server_info = dashboard::ServerInfo {
        version: env!("CARGO_PKG_VERSION"),
        started_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?,
        store: store_type.info(),
        wal: wal_store_type.as_ref().map(StoreType::info),
        path: args.path.clone(),
        flush_interval_ms: db_settings
            .flush_interval
            .map(|d| d.as_millis().try_into().unwrap_or(u64::MAX)),
        tls: protocol.describe(),
        bind_address: addr.ip(),
        port,
        cors: !args.no_cors,
        init_file: args.init_file.as_ref().map(|p| p.display().to_string()),
        append_inflight_bytes: args.append_inflight_bytes.as_u64(),
    };

    let mut builder = slatedb::Db::builder(args.path, object_store).with_settings(db_settings);
    if let Some(wal_object_store) = wal_object_store {
        info!(store = ?wal_store_type, "using dedicated WAL object store");
        builder = builder.with_wal_object_store(wal_object_store);
    }
    let db = builder.build().await?;

    info!(
        ?manifest_poll_interval,
        "sleeping to ensure prior instance fenced out"
    );

    tokio::time::sleep(manifest_poll_interval).await;

    info!(%args.append_inflight_bytes, "starting backend");
    let backend = Backend::new(db, args.append_inflight_bytes);
    let shutdown_backend = backend.clone();
    crate::backend::bgtasks::spawn(&backend);

    if let Some(init_file) = &args.init_file {
        let spec = init::load(init_file)?;
        init::apply(&backend, spec).await?;
    }

    let mut app = handlers::router();
    if !args.no_dashboard {
        app = app.merge(dashboard::router(&server_info));
    }
    let mut app = app
        .with_state(backend)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(tracing::Level::INFO))
                .on_request(DefaultOnRequest::new().level(tracing::Level::DEBUG))
                .on_response(DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .layer(SetSensitiveRequestHeadersLayer::new([
            AUTHORIZATION,
            S2_ENCRYPTION_KEY_HEADER.clone(),
        ]));

    if !args.no_cors {
        app = app.layer(CorsLayer::very_permissive());
    }

    let listener = socket.listen()?;
    let server_handle = axum_server::Handle::new();
    tokio::spawn(shutdown_signal(server_handle.clone()));
    match (
        args.tls.tls_self,
        args.tls.tls_cert.clone(),
        args.tls.tls_key.clone(),
    ) {
        (false, Some(cert_path), Some(key_path)) => {
            info!(
                %addr,
                ?cert_path,
                "starting https server with provided certificate"
            );
            let rustls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
            info!("{}", cli_hint);
            axum_server::from_tcp_rustls(listener, rustls_config)?
                .handle(server_handle)
                .serve(app.into_make_service())
                .await?;
        }
        (true, None, None) => {
            info!(
                %addr,
                "starting https server with self-signed certificate, clients will need to use --insecure"
            );
            let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed([
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ])?;
            let rustls_config = RustlsConfig::from_pem(
                cert.pem().into_bytes(),
                signing_key.serialize_pem().into_bytes(),
            )
            .await?;
            info!("{}", cli_hint);
            axum_server::from_tcp_rustls(listener, rustls_config)?
                .handle(server_handle)
                .serve(app.into_make_service())
                .await?;
        }
        (false, None, None) => {
            info!(%addr, "starting plain http server");
            info!("{}", cli_hint);
            axum_server::from_tcp(listener)?
                .handle(server_handle)
                .serve(app.into_make_service())
                .await?;
        }
        _ => {
            // This shouldn't happen due to clap validation...
            return Err(eyre::eyre!("Invalid TLS configuration"));
        }
    }

    info!("http server stopped; closing SlateDB");
    let close_started = Instant::now();
    shutdown_backend
        .close()
        .await
        .map_err(|error| eyre::eyre!("SlateDB close: {error}"))?;
    info!(
        elapsed_ms = close_started.elapsed().as_millis(),
        "SlateDB closed"
    );

    Ok(())
}

async fn init_object_store(
    store_type: &StoreType,
    s3_overrides: Option<WalS3Overrides>,
) -> eyre::Result<Arc<dyn object_store::ObjectStore>> {
    let store: Arc<dyn object_store::ObjectStore> = match store_type {
        StoreType::S3Bucket(bucket) => {
            info!(bucket, "using s3 object store");
            let mut builder = s3_builder().await;
            if let Some(overrides) = s3_overrides {
                builder = overrides.apply(builder);
            }
            Arc::new(builder.with_bucket_name(bucket).build()?)
        }
        StoreType::LocalFileSystem(local_root) => {
            std::fs::create_dir_all(local_root)?;
            info!(
                root = %local_root.display(),
                "using local filesystem object store"
            );
            Arc::new(
                // Match the durability contract of remote object stores: an
                // acknowledged SlateDB write must survive a host crash.
                object_store::local::LocalFileSystem::new_with_prefix(local_root)?.with_fsync(true),
            )
        }
        StoreType::InMemory => {
            info!("using in-memory object store");
            Arc::new(object_store::memory::InMemory::new())
        }
    };
    Ok(store)
}

// Both buckets start with the same AWS configuration and credential chain.
async fn s3_builder() -> object_store::aws::AmazonS3Builder {
    let mut builder = object_store::aws::AmazonS3Builder::from_env();

    if let Some(endpoint) =
        std::env::var_os("AWS_ENDPOINT_URL_S3").and_then(|s| s.into_string().ok())
    {
        if endpoint.starts_with("http://") {
            builder = builder.with_allow_http(true);
        }
        builder = builder.with_endpoint(endpoint);
    }

    match (
        std::env::var_os("AWS_ACCESS_KEY_ID").and_then(|s| s.into_string().ok()),
        std::env::var_os("AWS_SECRET_ACCESS_KEY").and_then(|s| s.into_string().ok()),
    ) {
        (Some(key_id), Some(secret_key)) => {
            info!(key_id, "using static credentials from env vars");

            let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            if let Some(region) = aws_config.region() {
                info!(region = region.as_ref());
                builder = builder.with_region(region.to_string());
            }

            let token = std::env::var_os("AWS_SESSION_TOKEN").and_then(|s| s.into_string().ok());
            builder = builder.with_credentials(Arc::new(
                object_store::StaticCredentialProvider::new(object_store::aws::AwsCredential {
                    key_id,
                    secret_key,
                    token,
                }),
            ));
        }
        _ => {
            let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            if let Some(region) = aws_config.region() {
                info!(region = region.as_ref());
                builder = builder.with_region(region.to_string());
            }
            if let Some(credentials_provider) = aws_config.credentials_provider() {
                info!("using aws-config credentials provider");
                builder = builder.with_credentials(Arc::new(S3CredentialProvider {
                    aws: credentials_provider.clone(),
                    cache: tokio::sync::Mutex::new(None),
                }));
            }
        }
    }
    builder
}

// Keep credentials out of LiteArgs and its startup Debug log. Only supplied
// fields override the shared AWS configuration; credentials are replaced as a set.
struct WalS3Overrides {
    endpoint: Option<String>,
    region: Option<String>,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    session_token: Option<String>,
}

impl WalS3Overrides {
    fn from_env() -> eyre::Result<Self> {
        Self::from_getter(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(eyre::eyre!("{name} must contain valid UTF-8"))
            }
        })
    }

    fn from_getter(get: impl Fn(&str) -> eyre::Result<Option<String>>) -> eyre::Result<Self> {
        let config = Self {
            endpoint: get("S2LITE_WAL_AWS_ENDPOINT_URL_S3")?,
            region: get("S2LITE_WAL_AWS_REGION")?,
            access_key_id: get("S2LITE_WAL_AWS_ACCESS_KEY_ID")?,
            secret_access_key: get("S2LITE_WAL_AWS_SECRET_ACCESS_KEY")?,
            session_token: get("S2LITE_WAL_AWS_SESSION_TOKEN")?,
        };
        eyre::ensure!(
            config.access_key_id.is_some() == config.secret_access_key.is_some(),
            "S2LITE_WAL_AWS_ACCESS_KEY_ID and S2LITE_WAL_AWS_SECRET_ACCESS_KEY must be set together"
        );
        eyre::ensure!(
            config.session_token.is_none() || config.access_key_id.is_some(),
            "S2LITE_WAL_AWS_SESSION_TOKEN requires the WAL access key and secret key"
        );
        Ok(config)
    }

    fn apply(
        self,
        mut builder: object_store::aws::AmazonS3Builder,
    ) -> object_store::aws::AmazonS3Builder {
        if let Some(endpoint) = &self.endpoint {
            // Override the S3-specific endpoint inherited from the main store.
            builder = builder
                .with_allow_http(endpoint.starts_with("http://"))
                .with_config(object_store::aws::AmazonS3ConfigKey::S3Endpoint, endpoint);
        }
        if let Some(region) = self.region {
            builder = builder.with_region(region);
        }
        if let (Some(key_id), Some(secret_key)) = (self.access_key_id, self.secret_access_key) {
            builder = builder.with_credentials(Arc::new(
                object_store::StaticCredentialProvider::new(object_store::aws::AwsCredential {
                    key_id,
                    secret_key,
                    token: self.session_token,
                }),
            ));
        }
        builder
    }
}

/// A TCP socket bound to the server address but not yet listening.
///
/// Until [`BoundSocket::listen`] is called, the kernel does not accept
/// connections for it (Linux refuses them).
#[derive(Debug)]
struct BoundSocket {
    socket: Socket,
    addr: SocketAddr,
}

impl BoundSocket {
    /// Binds `bind_address`, or `::` if not specified, falling back to
    /// `0.0.0.0` when IPv6 is unavailable.
    fn bind(bind_address: Option<IpAddr>, port: u16) -> eyre::Result<Self> {
        let (ip, socket) = match bind_address {
            // An IPv4-mapped address such as `::ffff:127.0.0.1` cannot be bound by
            // an IPv6-only socket (Linux returns EINVAL), so bind it as IPv4.
            Some(ip) => {
                let ip = ip.to_canonical();
                (ip, new_socket(ip))
            }
            None => {
                let ip = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
                match new_socket(ip) {
                    Ok(socket) => (ip, Ok(socket)),
                    Err(error) => {
                        warn!(%error, "IPv6 is unavailable, listening on IPv4 only");
                        let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                        (ip, new_socket(ip))
                    }
                }
            }
        };
        let addr = SocketAddr::new(ip, port);
        socket
            .and_then(|socket| {
                socket.bind(&addr.into())?;
                Ok(Self { socket, addr })
            })
            .map_err(|error| listen_error(addr, error))
    }

    fn listen(self) -> eyre::Result<std::net::TcpListener> {
        let Self { socket, addr } = self;
        let listen = || -> io::Result<()> {
            socket.listen(1024)?;
            // `axum_server::from_tcp` hands the listener to tokio as-is, which
            // requires it to be non-blocking.
            socket.set_nonblocking(true)
        };
        listen().map_err(|error| listen_error(addr, error))?;
        Ok(socket.into())
    }
}

/// Creates a TCP socket for `ip`.
///
/// For `::`, `IPV6_V6ONLY` is cleared so the socket also accepts IPv4
/// connections regardless of the platform default (such as Linux's
/// `net.ipv6.bindv6only` sysctl).
fn new_socket(ip: IpAddr) -> io::Result<Socket> {
    let domain = if ip.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if ip.is_ipv6() {
        socket.set_only_v6(!ip.is_unspecified())?;
    }
    // Matches what tokio and std do when binding listeners on Unix.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    Ok(socket)
}

// The CLI only prints the outermost error, so include the OS error: "address
// in use" vs. "cannot assign address" matters to the user.
fn listen_error(addr: SocketAddr, error: io::Error) -> eyre::Report {
    eyre::eyre!("failed to listen on {addr}: {error}")
}

async fn shutdown_signal(handle: axum_server::Handle<SocketAddr>) {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("ctrl-c");
    };

    #[cfg(unix)]
    let term = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("received Ctrl+C, starting graceful shutdown");
        },
        _ = term => {
            info!("received SIGTERM, starting graceful shutdown");
        },
    }

    handle.graceful_shutdown(Some(Duration::from_secs(10)));
}

#[derive(Debug)]
struct CachedCredential {
    credential: Arc<object_store::aws::AwsCredential>,
    expiry: Option<SystemTime>,
}

impl CachedCredential {
    fn is_valid(&self) -> bool {
        self.expiry
            .is_none_or(|exp| exp > SystemTime::now() + Duration::from_secs(60))
    }
}

#[derive(Debug)]
struct S3CredentialProvider {
    aws: aws_credential_types::provider::SharedCredentialsProvider,
    cache: tokio::sync::Mutex<Option<CachedCredential>>,
}

#[async_trait::async_trait]
impl object_store::CredentialProvider for S3CredentialProvider {
    type Credential = object_store::aws::AwsCredential;

    async fn get_credential(&self) -> object_store::Result<Arc<object_store::aws::AwsCredential>> {
        let mut cached = self.cache.lock().await;
        if let Some(cached) = cached.as_ref().filter(|c| c.is_valid()) {
            return Ok(cached.credential.clone());
        }

        use aws_credential_types::provider::ProvideCredentials as _;

        let start = Instant::now();
        let creds =
            self.aws
                .provide_credentials()
                .await
                .map_err(|e| object_store::Error::Generic {
                    store: "S3",
                    source: Box::new(e),
                })?;
        info!(
            key_id = creds.access_key_id(),
            expiry_s = creds
                .expiry()
                .and_then(|t| t.duration_since(SystemTime::now()).ok())
                .map(|d| d.as_secs()),
            elapsed_ms = start.elapsed().as_millis(),
            "fetched credentials"
        );
        let credential = Arc::new(object_store::aws::AwsCredential {
            key_id: creds.access_key_id().to_owned(),
            secret_key: creds.secret_access_key().to_owned(),
            token: creds.session_token().map(|s| s.to_owned()),
        });
        *cached = Some(CachedCredential {
            credential: credential.clone(),
            expiry: creds.expiry(),
        });
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};

    use clap::Parser;
    use rstest::rstest;

    use super::{
        BoundSocket, LiteArgs, ServerProtocol, WalS3Overrides, cli_endpoint, cli_env_hint,
    };

    const ANY_V4: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        lite: LiteArgs,
    }

    fn listen_on(bind_address: Option<IpAddr>) -> TcpListener {
        BoundSocket::bind(bind_address, 0)
            .unwrap()
            .listen()
            .unwrap()
    }

    #[test]
    fn bind_address_is_unset_by_default() {
        let cli = TestCli::try_parse_from(["lite"]).unwrap();
        assert_eq!(cli.lite.bind_address, None);
    }

    #[rstest]
    #[case::ipv6_unspecified("::")]
    #[case::ipv6_loopback("::1")]
    #[case::ipv4_loopback("127.0.0.1")]
    #[case::ipv6_global("2001:db8::1")]
    fn bind_address_accepts_ip_addresses(#[case] arg: &str) {
        let cli = TestCli::try_parse_from(["lite", "--bind-address", arg]).unwrap();
        assert_eq!(cli.lite.bind_address, Some(arg.parse().unwrap()));
    }

    #[rstest]
    #[case::bracketed("[::1]")]
    #[case::hostname("localhost")]
    #[case::with_port("0.0.0.0:80")]
    #[case::empty("")]
    fn bind_address_rejects_non_ip_values(#[case] arg: &str) {
        assert!(TestCli::try_parse_from(["lite", "--bind-address", arg]).is_err());
    }

    #[rstest]
    #[case::default(None)]
    #[case::explicit(Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)))]
    fn unspecified_ipv6_is_dual_stack(#[case] bind_address: Option<IpAddr>) {
        let listener = listen_on(bind_address);
        let port = listener.local_addr().unwrap().port();
        TcpStream::connect((Ipv6Addr::LOCALHOST, port)).unwrap();
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    }

    #[test]
    fn listen_on_ipv4() {
        let listener = listen_on(Some(Ipv4Addr::LOCALHOST.into()));
        TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    }

    #[test]
    fn listen_on_specific_ipv6() {
        let listener = listen_on(Some(Ipv6Addr::LOCALHOST.into()));
        TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    }

    #[test]
    fn listen_on_ipv4_mapped_address_binds_as_ipv4() {
        let listener = listen_on(Some("::ffff:127.0.0.1".parse().unwrap()));
        let addr = listener.local_addr().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        TcpStream::connect(addr).unwrap();
    }

    #[test]
    fn listener_is_non_blocking() {
        let error = listen_on(Some(Ipv4Addr::LOCALHOST.into()))
            .accept()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bound_socket_refuses_connections_until_listening() {
        let bound = BoundSocket::bind(Some(Ipv4Addr::LOCALHOST.into()), 0).unwrap();
        let addr = bound.socket.local_addr().unwrap().as_socket().unwrap();
        let error = TcpStream::connect(addr).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        let _listener = bound.listen().unwrap();
        TcpStream::connect(addr).unwrap();
    }

    #[test]
    fn bind_error_names_the_address() {
        let first = listen_on(Some(Ipv4Addr::LOCALHOST.into()));
        let addr = first.local_addr().unwrap();
        let error = BoundSocket::bind(Some(addr.ip()), addr.port())
            .unwrap_err()
            .to_string();
        assert!(error.starts_with(&format!("failed to listen on {addr}: ")));
    }

    #[rstest]
    #[case::ipv4_unspecified("0.0.0.0")]
    #[case::ipv6_unspecified("::")]
    #[case::ipv4_loopback("127.0.0.1")]
    #[case::ipv6_loopback("::1")]
    fn cli_endpoint_uses_localhost_for_wildcard_and_canonical_loopback(#[case] host: &str) {
        assert_eq!(
            cli_endpoint(ServerProtocol::Http, host.parse().unwrap(), 8080),
            "http://localhost:8080"
        );
    }

    #[test]
    fn cli_endpoint_uses_specific_host_address() {
        // 127.0.0.2 is loopback but not `localhost`; the hint must name it.
        assert_eq!(
            cli_endpoint(ServerProtocol::Http, "127.0.0.2".parse().unwrap(), 8080),
            "http://127.0.0.2:8080"
        );
        assert_eq!(
            cli_endpoint(ServerProtocol::Http, "192.0.2.10".parse().unwrap(), 8080),
            "http://192.0.2.10:8080"
        );
        assert_eq!(
            cli_endpoint(
                ServerProtocol::Https { self_signed: false },
                "2001:db8::1".parse().unwrap(),
                8443
            ),
            "https://[2001:db8::1]:8443"
        );
    }

    fn wal_config(values: &[(&str, &str)]) -> eyre::Result<WalS3Overrides> {
        WalS3Overrides::from_getter(|name| {
            Ok(values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned()))
        })
    }

    #[test]
    fn wal_static_credentials_must_be_complete() {
        for values in [
            vec![("S2LITE_WAL_AWS_ACCESS_KEY_ID", "test-key")],
            vec![("S2LITE_WAL_AWS_SECRET_ACCESS_KEY", "do-not-log-this-secret")],
            vec![("S2LITE_WAL_AWS_SESSION_TOKEN", "do-not-log-this-token")],
        ] {
            let error = wal_config(&values)
                .err()
                .expect("invalid credentials")
                .to_string();
            assert!(error.contains("S2LITE_WAL_AWS_"));
            assert!(!error.contains("do-not-log-this"));
        }
        assert!(wal_config(&[]).is_ok());
    }

    #[test]
    fn cli_endpoint_uses_localhost_with_explicit_port() {
        assert_eq!(
            cli_endpoint(ServerProtocol::Http, ANY_V4, 80),
            "http://localhost:80"
        );
        assert_eq!(
            cli_endpoint(ServerProtocol::Https { self_signed: false }, ANY_V4, 443),
            "https://localhost:443"
        );
    }

    #[test]
    fn cli_env_hint_includes_exports_for_http() {
        assert_eq!(
            cli_env_hint(ServerProtocol::Http, ANY_V4, 8080, true),
            concat!(
                "copy/paste into a new terminal to point the S2 CLI at this server:\n",
                "export S2_ACCOUNT_ENDPOINT=http://localhost:8080\n",
                "export S2_BASIN_ENDPOINT=http://localhost:8080\n",
                "export S2_ACCESS_TOKEN=ignored\n",
                "\n",
                "or use the dashboard at http://localhost:8080/dashboard",
            )
        );
    }

    #[test]
    fn cli_env_hint_includes_ssl_no_verify_for_self_signed_tls() {
        assert_eq!(
            cli_env_hint(
                ServerProtocol::Https { self_signed: true },
                ANY_V4,
                8443,
                false
            ),
            concat!(
                "copy/paste into a new terminal to point the S2 CLI at this server:\n",
                "export S2_ACCOUNT_ENDPOINT=https://localhost:8443\n",
                "export S2_BASIN_ENDPOINT=https://localhost:8443\n",
                "export S2_ACCESS_TOKEN=ignored\n",
                "export S2_SSL_NO_VERIFY=1",
            )
        );
    }
}
