#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum_server::tls_rustls::RustlsConfig;
use bytesize::ByteSize;
use clap::Parser as _;
use s2_lite::{backend::Backend, handlers};
use slatedb::object_store;
use tokio::time::Instant;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(clap::Args, Debug, Clone)]
struct TlsConfig {
    /// Use a self-signed certificate for TLS
    #[arg(long, conflicts_with_all = ["tls_cert", "tls_key"])]
    tls_self: bool,

    /// Path to the TLS certificate file (e.g., cert.pem)
    /// Must be used together with --tls-key
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// Path to the private key file (e.g., key.pem)
    /// Must be used together with --tls-cert
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the S3 bucket to back the database.
    ///
    /// If not specified, in-memory storage is used (unless --local-path is set).
    #[arg(long, conflicts_with = "local_path")]
    bucket: Option<String>,

    /// Local filesystem path for storage.
    ///
    /// Use this for persistent local storage instead of S3 or in-memory.
    #[arg(long, conflicts_with = "bucket")]
    local_path: Option<PathBuf>,

    /// Base path on object storage.
    #[arg(long, default_value = "")]
    path: String,

    /// TLS configuration (defaults to plain HTTP if not specified).
    #[command(flatten)]
    tls: TlsConfig,

    /// Port to listen on [default: 443 if HTTPS configured, otherwise 80 for HTTP]
    #[arg(long)]
    port: Option<u16>,

    /// Root public key for verifying access tokens (base58-encoded P-256 compressed public key).
    /// Required to enable authentication.
    #[arg(long, env = "S2_ROOT_PUBLIC_KEY")]
    root_public_key: Option<String>,

    /// Root private key for signing new access tokens (base58-encoded P-256 private key).
    /// Only needed if server should issue tokens via /access-tokens endpoint.
    /// If provided without --root-public-key, derives the public key automatically.
    #[arg(long, env = "S2_ROOT_PRIVATE_KEY")]
    root_private_key: Option<String>,

    /// Signature timestamp window in seconds (default 300).
    /// Requests with signatures older than this are rejected.
    #[arg(long, env = "S2_SIGNATURE_WINDOW", default_value = "300")]
    signature_window: u64,

    /// Bearer token for metrics endpoints.
    /// If set, metrics endpoints require "Authorization: Bearer <token>".
    /// If not set, metrics endpoints are publicly accessible.
    #[arg(long, env = "S2_METRICS_TOKEN")]
    metrics_token: Option<String>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    info!(?args);

    // Parse and validate auth keys
    let root_private_key = args
        .root_private_key
        .as_ref()
        .map(|k| s2_lite::auth::RootKey::from_base58(k))
        .transpose()
        .map_err(|e| eyre::eyre!("invalid root private key: {}", e))?;

    let root_public_key = match (&args.root_public_key, &root_private_key) {
        (Some(pk), _) => {
            // Explicit public key provided
            Some(
                s2_lite::auth::RootPublicKey::from_base58(pk)
                    .map_err(|e| eyre::eyre!("invalid root public key: {}", e))?,
            )
        }
        (None, Some(sk)) => {
            // Derive public key from private key
            Some(sk.public_key())
        }
        (None, None) => None,
    };

    match (&root_public_key, &root_private_key) {
        (Some(pk), Some(_)) => {
            info!(public_key = %pk, "auth enabled (can issue tokens)");
        }
        (Some(pk), None) => {
            info!(public_key = %pk, "auth enabled (verify only)");
        }
        (None, None) => {
            info!("auth disabled (no root key provided)");
        }
        (None, Some(_)) => unreachable!(),
    }

    let addr = {
        let port = args.port.unwrap_or_else(|| {
            if args.tls.tls_self || args.tls.tls_cert.is_some() {
                443
            } else {
                80
            }
        });
        format!("0.0.0.0:{port}")
    };

    let object_store =
        init_object_store(args.bucket.as_deref(), args.local_path.as_deref()).await?;

    let uses_remote_storage = args.bucket.is_some();
    let default_flush_interval = Duration::from_millis(if uses_remote_storage { 50 } else { 5 });

    let db_settings = slatedb::Settings::from_env_with_default(
        "SL8_",
        slatedb::Settings {
            flush_interval: Some(default_flush_interval),
            ..Default::default()
        },
    )?;

    let append_inflight_max = if std::env::var("S2LITE_PIPELINE")
        .is_ok_and(|v| v.eq_ignore_ascii_case("true") || v == "1")
    {
        info!("pipelining enabled on append sessions up to 25MiB");
        ByteSize::mib(25)
    } else {
        info!("pipelining disabled");
        ByteSize::b(1)
    };

    let db = slatedb::Db::builder(args.path, object_store)
        .with_settings(db_settings)
        .build()
        .await?;

    let backend = Backend::new(db, append_inflight_max);

    // Create auth state
    let auth_state = match (root_public_key, root_private_key) {
        (Some(pk), Some(sk)) => {
            // Full mode: can verify and issue tokens
            // Verify the keys match
            if pk != sk.public_key() {
                return Err(eyre::eyre!(
                    "root-public-key does not match root-private-key"
                ));
            }
            s2_lite::auth::AuthState::new(sk, args.signature_window, args.metrics_token.clone())
        }
        (Some(pk), None) => {
            // Verify-only mode: can verify but not issue tokens
            s2_lite::auth::AuthState::verify_only(
                pk,
                args.signature_window,
                args.metrics_token.clone(),
            )
        }
        (None, None) => {
            // Auth disabled
            match args.metrics_token {
                Some(token) => s2_lite::auth::AuthState::metrics_only(token),
                None => s2_lite::auth::AuthState::disabled(),
            }
        }
        (None, Some(_)) => unreachable!(),
    };

    if auth_state.metrics_token().is_some() {
        info!("metrics auth enabled");
    } else {
        info!("metrics endpoints are publicly accessible");
    }

    let app = handlers::router(backend, auth_state).layer(
        TraceLayer::new_for_http()
            .make_span_with(DefaultMakeSpan::new().level(tracing::Level::INFO))
            .on_request(DefaultOnRequest::new().level(tracing::Level::DEBUG))
            .on_response(DefaultOnResponse::new().level(tracing::Level::INFO)),
    );

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
            axum_server::bind_rustls(addr.parse()?, rustls_config)
                .handle(server_handle)
                .serve(app.into_make_service())
                .await?;
        }
        (false, None, None) => {
            info!(addr, "starting plain http server");
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

    Ok(())
}

async fn init_object_store(
    bucket: Option<&str>,
    local_path: Option<&std::path::Path>,
) -> eyre::Result<Arc<dyn object_store::ObjectStore>> {
    // Local filesystem takes precedence
    if let Some(path) = local_path {
        info!(?path, "using local filesystem object store");
        return Ok(Arc::new(
            object_store::local::LocalFileSystem::new_with_prefix(path)?,
        ));
    }

    match bucket {
        Some(bucket) if !bucket.is_empty() => {
            info!(bucket, "using s3 object store");
            let mut builder =
                object_store::aws::AmazonS3Builder::from_env().with_bucket_name(bucket);
            match (
                std::env::var_os("AWS_ENDPOINT_URL_S3").and_then(|s| s.into_string().ok()),
                std::env::var_os("AWS_ACCESS_KEY_ID").and_then(|s| s.into_string().ok()),
                std::env::var_os("AWS_SECRET_ACCESS_KEY").and_then(|s| s.into_string().ok()),
            ) {
                (endpoint, Some(key_id), Some(secret_key)) => {
                    info!(key_id, "using static credentials from env vars");
                    if let Some(endpoint) = endpoint {
                        builder = builder.with_endpoint(endpoint);
                    }
                    builder = builder.with_credentials(Arc::new(
                        object_store::StaticCredentialProvider::new(
                            object_store::aws::AwsCredential {
                                key_id,
                                secret_key,
                                token: None,
                            },
                        ),
                    ));
                }
                _ => {
                    let aws_config =
                        aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
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
            Ok(Arc::new(builder.build()?))
        }
        _ => {
            info!("using in-memory object store");
            Ok(Arc::new(object_store::memory::InMemory::new()))
        }
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
    let terminate = std::future::pending::<()>();

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
