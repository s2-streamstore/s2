use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum_server::tls_rustls::RustlsConfig;
use bytesize::ByteSize;
use http::header::AUTHORIZATION;
use s2_common::encryption::S2_ENCRYPTION_KEY_HEADER;
use slatedb::object_store;
use tokio::time::Instant;
use tower_http::{
    cors::CorsLayer,
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::info;

use crate::{backend::Backend, handlers, init};

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

fn cli_endpoint(protocol: ServerProtocol, port: u16) -> String {
    format!("{}://localhost:{port}", protocol.scheme())
}

fn cli_env_hint(protocol: ServerProtocol, port: u16) -> String {
    let endpoint = cli_endpoint(protocol, port);
    let mut lines = vec![
        "copy/paste into a new terminal to point the S2 CLI at this server:".to_string(),
        format!("export S2_ACCOUNT_ENDPOINT={endpoint}"),
        format!("export S2_BASIN_ENDPOINT={endpoint}"),
        "export S2_ACCESS_TOKEN=ignored".to_string(),
    ];

    if protocol.requires_ssl_no_verify() {
        lines.push("export S2_SSL_NO_VERIFY=1".to_string());
    }

    lines.join("\n")
}

pub async fn run(args: LiteArgs) -> eyre::Result<()> {
    info!(?args);

    let protocol = ServerProtocol::from_args(&args);
    let port = args.port.unwrap_or_else(|| protocol.default_port());
    let addr = format!("0.0.0.0:{port}");
    let cli_hint = cli_env_hint(protocol, port);

    let store_type = if let Some(bucket) = args.bucket {
        StoreType::S3Bucket(bucket)
    } else if let Some(local_root) = args.local_root {
        StoreType::LocalFileSystem(local_root)
    } else {
        StoreType::InMemory
    };

    let object_store = init_object_store(&store_type).await?;
    let wal_store_type = if let Some(bucket) = args.wal_bucket {
        Some(StoreType::S3Bucket(bucket))
    } else {
        args.wal_local_root.map(StoreType::LocalFileSystem)
    };
    let wal_object_store = match &wal_store_type {
        Some(StoreType::S3Bucket(bucket)) => Some(Arc::new(
            WalS3Overrides::from_env()?
                .apply(s3_builder().await)
                .with_bucket_name(bucket)
                .build()?,
        ) as Arc<dyn object_store::ObjectStore>),
        Some(store_type) => Some(init_object_store(store_type).await?),
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

    let mut app = handlers::router()
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

    let server_handle = axum_server::Handle::new();
    tokio::spawn(shutdown_signal(server_handle.clone()));
    match (
        args.tls.tls_self,
        args.tls.tls_cert.clone(),
        args.tls.tls_key.clone(),
    ) {
        (false, Some(cert_path), Some(key_path)) => {
            info!(
                addr,
                ?cert_path,
                "starting https server with provided certificate"
            );
            let rustls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
            info!("{}", cli_hint);
            axum_server::bind_rustls(addr.parse()?, rustls_config)
                .handle(server_handle)
                .serve(app.into_make_service())
                .await?;
        }
        (true, None, None) => {
            info!(
                addr,
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
            axum_server::bind_rustls(addr.parse()?, rustls_config)
                .handle(server_handle)
                .serve(app.into_make_service())
                .await?;
        }
        (false, None, None) => {
            info!(addr, "starting plain http server");
            info!("{}", cli_hint);
            axum_server::bind(addr.parse()?)
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
) -> eyre::Result<Arc<dyn object_store::ObjectStore>> {
    Ok(match store_type {
        StoreType::S3Bucket(bucket) => {
            info!(bucket, "using s3 object store");
            Arc::new(s3_builder().await.with_bucket_name(bucket).build()?)
                as Arc<dyn object_store::ObjectStore>
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
    })
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
            builder = builder
                .with_allow_http(endpoint.starts_with("http://"))
                .with_endpoint(endpoint);
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
    use super::{ServerProtocol, WalS3Overrides, cli_endpoint, cli_env_hint};

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

    #[tokio::test]
    async fn wal_s3_inherits_main_settings_and_applies_explicit_overrides() {
        use std::sync::{Arc, Mutex};

        use axum::{
            Router,
            body::Bytes,
            http::{HeaderMap, Uri},
            routing::put,
        };
        use slatedb::object_store::{
            ObjectStoreExt, StaticCredentialProvider,
            aws::{AmazonS3Builder, AwsCredential},
            path::Path,
        };

        for (override_endpoint, override_credentials, wal_token, wal_region) in [
            (false, false, None, None), // Only the bucket changes.
            (true, false, None, None),  // Another server, same credentials.
            (false, true, None, None),  // New keys must not inherit the main token.
            (true, true, Some("wal-token"), Some("eu-west-1")),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let (tx, rx) = tokio::sync::oneshot::channel();
            let tx = Arc::new(Mutex::new(Some(tx)));
            let app = Router::new().route(
                "/{*path}",
                put(move |uri: Uri, headers: HeaderMap, body: Bytes| {
                    let tx = tx.clone();
                    async move {
                        tx.lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send((uri, headers, body))
                            .unwrap();
                        ([("etag", "\"test-etag\"")], "")
                    }
                }),
            );
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let main_builder = AmazonS3Builder::new()
                .with_bucket_name("main-bucket")
                .with_region("us-east-1")
                .with_endpoint(if override_endpoint {
                    "http://127.0.0.1:1"
                } else {
                    &endpoint
                })
                .with_allow_http(true)
                .with_credentials(Arc::new(StaticCredentialProvider::new(AwsCredential {
                    key_id: "main-key".into(),
                    secret_key: "main-secret".into(),
                    token: Some("main-token".into()),
                })));
            let mut values = Vec::new();
            if override_endpoint {
                values.push(("S2LITE_WAL_AWS_ENDPOINT_URL_S3", endpoint.as_str()));
            }
            if override_credentials {
                values.extend([
                    ("S2LITE_WAL_AWS_ACCESS_KEY_ID", "wal-key"),
                    ("S2LITE_WAL_AWS_SECRET_ACCESS_KEY", "wal-secret"),
                ]);
            }
            if let Some(token) = wal_token {
                values.push(("S2LITE_WAL_AWS_SESSION_TOKEN", token));
            }
            if let Some(region) = wal_region {
                values.push(("S2LITE_WAL_AWS_REGION", region));
            }
            let store = wal_config(&values)
                .unwrap()
                .apply(main_builder)
                .with_bucket_name("wal-bucket")
                .build()
                .unwrap();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                store.put(
                    &Path::from("db/wal/probe"),
                    Bytes::from_static(b"wal-data").into(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            let (uri, headers, body) = rx.await.unwrap();
            assert_eq!(uri.path(), "/wal-bucket/db/wal/probe");
            let authorization = headers["authorization"].to_str().unwrap();
            let key = if override_credentials {
                "wal-key"
            } else {
                "main-key"
            };
            assert!(authorization.contains(&format!("Credential={key}/")));
            let region = wal_region.unwrap_or("us-east-1");
            assert!(authorization.contains(&format!("/{region}/s3/aws4_request")));
            let token = if override_credentials {
                wal_token
            } else {
                Some("main-token")
            };
            assert_eq!(
                headers
                    .get("x-amz-security-token")
                    .map(|v| v.to_str().unwrap()),
                token
            );
            assert_eq!(body, "wal-data");
            server.abort();
        }
    }

    #[test]
    fn cli_endpoint_uses_localhost_with_explicit_port() {
        assert_eq!(
            cli_endpoint(ServerProtocol::Http, 80),
            "http://localhost:80"
        );
        assert_eq!(
            cli_endpoint(ServerProtocol::Https { self_signed: false }, 443),
            "https://localhost:443"
        );
    }

    #[test]
    fn cli_env_hint_includes_exports_for_http() {
        assert_eq!(
            cli_env_hint(ServerProtocol::Http, 8080),
            concat!(
                "copy/paste into a new terminal to point the S2 CLI at this server:\n",
                "export S2_ACCOUNT_ENDPOINT=http://localhost:8080\n",
                "export S2_BASIN_ENDPOINT=http://localhost:8080\n",
                "export S2_ACCESS_TOKEN=ignored",
            )
        );
    }

    #[test]
    fn cli_env_hint_includes_ssl_no_verify_for_self_signed_tls() {
        assert_eq!(
            cli_env_hint(ServerProtocol::Https { self_signed: true }, 8443),
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
