use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use colored::Colorize;
use miette::Diagnostic;
use rand::Rng as _;
use reqwest::Url;
use s2_sdk::types::{AccessTokenProvider, AccessTokenProviderError, S2Config};
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::{Mutex as AsyncMutex, oneshot},
    task::JoinError,
    time::timeout,
};
use uuid::Uuid;

use crate::{
    access_token::{self, AccessTokenError},
    cli::{LoginArgs, LogoutArgs},
    config::{
        AuthMethod, CliConfig, CredentialStore, OAuthSession, access_token_from_environment,
        acquire_config_lock, config_path, load_cli_config, load_config_file, save_cli_config,
    },
    credential_store::{self, CredentialKind, CredentialStoreError},
    error::{CliConfigError, TokenSource},
};

mod destination;

use destination::validate_endpoint_binding;
pub(crate) use destination::{effective_endpoints, uses_loopback_endpoints};

const DEFAULT_OAUTH_ISSUER: &str = "https://clerk.s2.dev";
const DEFAULT_OAUTH_CLIENT_ID: &str = "9zTKDS3tHSmaWl33";
const DEFAULT_OAUTH_COMPLETION_URL: &str = "https://s2.dev/cli/login";
const OAUTH_SCOPES: &str = "offline_access user:org:read";
const OAUTH_CREDENTIAL_KIND: &str = "s2_oauth";
const CREDENTIAL_VERSION: u8 = 1;
const REFRESH_SKEW: Duration = Duration::from_secs(60);
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OAUTH_RESPONSE_BYTES: usize = 64 * 1024;
const CALLBACK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const REFRESH_LOCK_TIMEOUT: Duration = Duration::from_secs(60);

type CallbackOutcome = Result<String, String>;
type CallbackSender = Arc<Mutex<Option<oneshot::Sender<CallbackOutcome>>>>;

#[derive(Debug, Error, Diagnostic)]
pub enum LoginError {
    #[error("Invalid OAuth issuer: {0}")]
    InvalidIssuer(String),

    #[error("Invalid OAuth completion URL: {0}")]
    InvalidCompletionUrl(String),

    #[error("Failed to initialize the OAuth HTTP client")]
    HttpClient(#[source] reqwest::Error),

    #[error("OAuth {operation} request failed")]
    Request {
        operation: &'static str,
        #[source]
        source: reqwest::Error,
    },

    #[error("OAuth {operation} was rejected ({status}): {message}")]
    Rejected {
        operation: &'static str,
        status: StatusCode,
        message: String,
    },

    #[error("OAuth {operation} returned an invalid response")]
    InvalidResponse {
        operation: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("OAuth {operation} response exceeded 64 KiB")]
    ResponseTooLarge { operation: &'static str },

    #[error("Invalid OAuth authorization-server metadata: {0}")]
    InvalidMetadata(String),

    #[error("OAuth token response was incomplete: {0}")]
    InvalidTokenResponse(String),

    #[error("Failed to listen for the browser callback")]
    #[diagnostic(help(
        "Check whether local applications may listen on 127.0.0.1, then retry `s2 login`."
    ))]
    Listen(#[source] std::io::Error),

    #[error("The browser callback server failed")]
    CallbackServer(#[source] std::io::Error),

    #[error("The browser callback task failed")]
    CallbackTask(#[source] JoinError),

    #[error("Timed out waiting for browser authorization")]
    #[diagnostic(help("Run `s2 login` again and finish authorization in the browser."))]
    TimedOut,

    #[error("Browser authorization ended before a code was received")]
    CallbackClosed,

    #[error("S2 login was not authorized: {0}")]
    AuthorizationRejected(String),

    #[error("Failed to serialize OAuth credentials")]
    SerializeCredentials(#[source] serde_json::Error),

    #[error("Stored OAuth credentials are invalid")]
    ParseCredentials(#[source] serde_json::Error),

    #[error("Stored OAuth credentials do not match the active login")]
    CredentialBindingMismatch,

    #[error("Browser login changed while credentials were being refreshed")]
    #[diagnostic(help("Retry the command to use the current authentication selection."))]
    SessionChanged,

    #[error("Refusing to send browser-login credentials to an untrusted S2 endpoint")]
    #[diagnostic(help(
        "Use the matching HTTPS S2 endpoints. Development browser logins may use loopback endpoints; use an S2-issued access token for other custom endpoints."
    ))]
    UnsafeBrowserDestination,

    #[error("The browser login was revoked, but local configuration could not be updated")]
    #[diagnostic(help("Run `s2 logout --local-only` to finish removing it locally."))]
    RevokedButNotRemoved(#[source] CliConfigError),

    #[error("OAuth tokens were refreshed, but the rotated credential could not be saved")]
    #[diagnostic(help("Run `s2 login` again before the current access token expires."))]
    RefreshPersistence(#[source] Box<LoginError>),

    #[error("The browser login was deactivated, but its local credential could not be deleted")]
    #[diagnostic(help(
        "Retry `s2 logout --local-only`; the credential remains queued for cleanup at {recovery}."
    ))]
    LogoutIncomplete { recovery: String },

    #[error("Could not finish cleaning up an older browser login: {details}")]
    #[diagnostic(help(
        "Restore access to the credential store and OAuth provider, then retry. To abandon server-side revocation, run `s2 logout --local-only`."
    ))]
    PendingLoginCleanup { details: String },

    #[error(
        "Failed to update the config ({config}) and clean up the newly issued OAuth credential ({cleanup}); cleanup remains queued at {recovery}"
    )]
    LoginRollback {
        #[source]
        config: Box<CliConfigError>,
        cleanup: Box<LoginError>,
        recovery: String,
    },

    #[error(
        "Failed to store OAuth credentials ({write}) and clean up the newly issued grant ({cleanup}); cleanup remains queued at {recovery}"
    )]
    CredentialWriteRollback {
        write: Box<LoginError>,
        cleanup: Box<LoginError>,
        recovery: String,
    },

    #[error(
        "Failed to journal the newly issued OAuth credential ({config}) and revoke its grant ({revocation}); the provider may still retain the grant"
    )]
    UnjournaledGrant {
        config: Box<CliConfigError>,
        revocation: Box<LoginError>,
    },

    #[cfg(unix)]
    #[error("Failed to {action} the OAuth credentials file")]
    CredentialFile {
        action: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to acquire the OAuth refresh lock")]
    RefreshLock(#[source] std::io::Error),

    #[error("Timed out waiting for another S2 process to refresh OAuth credentials")]
    RefreshLockTimedOut,

    #[error(transparent)]
    #[diagnostic(transparent)]
    Config(#[from] CliConfigError),

    #[error(transparent)]
    #[diagnostic(transparent)]
    Credential(#[from] CredentialStoreError),

    #[error(transparent)]
    #[diagnostic(transparent)]
    StoredAccessToken(#[from] AccessTokenError),
}

impl LoginError {
    pub(crate) fn is_transient(&self) -> bool {
        match self {
            Self::Request { source, .. } => source.is_connect() || source.is_timeout(),
            Self::Rejected { status, .. } => {
                status.is_server_error()
                    || matches!(
                        *status,
                        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
                    )
            }
            #[cfg(unix)]
            Self::CredentialFile { source, .. } => matches!(
                source.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ),
            Self::RefreshLock(source) => matches!(
                source.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ),
            Self::Config(CliConfigError::LockTimedOut) => true,
            Self::Config(CliConfigError::Lock(source)) => matches!(
                source.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ),
            Self::RefreshPersistence(error) => error.is_transient(),
            Self::Credential(error) => error.is_transient(),
            Self::RefreshLockTimedOut => true,
            _ => false,
        }
    }

    fn is_credential_not_found(&self) -> bool {
        matches!(
            self,
            Self::Credential(CredentialStoreError::CredentialNotFound)
        ) || matches!(self, Self::StoredAccessToken(error) if error.is_not_found())
    }

    fn should_reload_auth_config(&self) -> bool {
        self.is_credential_not_found() || matches!(self, Self::SessionChanged)
    }
}

pub struct ResolvedCredential {
    access_token: SecretString,
    source: TokenSource,
    oauth_session: Option<OAuthSession>,
    oauth_tokens: Option<TokenSet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialChoice {
    Environment,
    BrowserLogin,
    StoredAccessToken,
}

impl ResolvedCredential {
    pub fn access_token(&self) -> &str {
        self.access_token.expose_secret()
    }

    pub fn source(&self) -> TokenSource {
        self.source
    }

    pub fn validate_destination(&self, config: &CliConfig) -> Result<(), LoginError> {
        let Some(session) = self.oauth_session.as_ref() else {
            return Ok(());
        };
        let (account_endpoint, basin_endpoint) = effective_endpoints(config);
        if account_endpoint != session.account_endpoint || basin_endpoint != session.basin_endpoint
        {
            return Err(LoginError::UnsafeBrowserDestination);
        }
        validate_endpoint_binding(
            &session.issuer,
            &account_endpoint,
            &basin_endpoint,
            config.ssl_no_verify == Some(true),
        )
    }

    pub fn configure_sdk(&self, config: S2Config) -> S2Config {
        match (self.oauth_session.as_ref(), self.oauth_tokens.as_ref()) {
            (Some(session), Some(tokens)) => config.with_access_token_provider(
                OAuthAccessTokenProvider::new(session.clone(), tokens.clone()),
            ),
            _ => config,
        }
    }
}

struct OAuthAccessTokenProvider {
    session: OAuthSession,
    state: AsyncMutex<ProviderTokenState>,
    rejected_access_tokens: Mutex<HashSet<String>>,
}

struct ProviderTokenState {
    tokens: TokenSet,
    persist_pending: bool,
}

impl OAuthAccessTokenProvider {
    fn new(session: OAuthSession, tokens: TokenSet) -> Self {
        Self {
            session,
            state: AsyncMutex::new(ProviderTokenState {
                tokens,
                persist_pending: false,
            }),
            rejected_access_tokens: Mutex::new(HashSet::new()),
        }
    }
}

impl std::fmt::Debug for OAuthAccessTokenProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthAccessTokenProvider")
            .field("session", &self.session)
            .field("state", &"<redacted>")
            .field("rejected_access_tokens", &"<redacted>")
            .finish()
    }
}

#[async_trait]
impl AccessTokenProvider for OAuthAccessTokenProvider {
    async fn access_token(&self) -> Result<String, AccessTokenProviderError> {
        // Drain rejection signals only after serializing token selection to prevent replay.
        let mut state = self.state.lock().await;
        let rejected_access_tokens = {
            let mut rejected = self
                .rejected_access_tokens
                .lock()
                .expect("rejected access-token mutex poisoned");
            std::mem::take(&mut *rejected)
        };
        match refresh_cached_tokens_if_needed(&self.session, &mut state, &rejected_access_tokens)
            .await
        {
            Ok(()) => Ok(state.tokens.access_token.expose_secret().to_owned()),
            Err(error) => {
                if !rejected_access_tokens.is_empty() {
                    // Keep rejection signals until a refresh succeeds. Signals that
                    // arrive concurrently while refreshing are retained too.
                    self.rejected_access_tokens
                        .lock()
                        .expect("rejected access-token mutex poisoned")
                        .extend(rejected_access_tokens);
                }
                if error.is_transient() {
                    Err(AccessTokenProviderError::transient(error.to_string()))
                } else {
                    Err(AccessTokenProviderError::permanent(error.to_string()))
                }
            }
        }
    }

    fn invalidate_access_token(&self, rejected_access_token: &str) {
        self.rejected_access_tokens
            .lock()
            .expect("rejected access-token mutex poisoned")
            .insert(rejected_access_token.to_owned());
    }
}

#[derive(Clone)]
struct CallbackState {
    expected_state: String,
    sender: CallbackSender,
    completion_url: Option<Url>,
}

#[derive(Clone, Copy)]
enum CallbackStatus {
    Authorized,
    Denied,
    Error,
    AlreadyCompleted,
}

impl CallbackStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Denied => "denied",
            Self::Error => "error",
            Self::AlreadyCompleted => "already-completed",
        }
    }
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: Option<String>,
    #[serde(default)]
    response_types_supported: Vec<String>,
    #[serde(default)]
    grant_types_supported: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
}

struct OAuthEndpoints {
    issuer: Url,
    authorization: Url,
    token: Url,
    revocation: Url,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
    token_type: String,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    error: Option<String>,
}

#[derive(Deserialize, PartialEq, Eq)]
struct OAuthIdentity {
    sub: String,
    org_id: String,
}

#[derive(Clone)]
struct TokenSet {
    access_token: SecretString,
    refresh_token: SecretString,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct StoredTokenSet {
    version: u8,
    kind: String,
    credential_id: String,
    issuer: String,
    client_id: String,
    access_token: String,
    refresh_token: String,
    expires_at: u64,
}

struct Pkce {
    verifier: String,
    challenge: String,
}

struct RefreshLock {
    file: File,
}

impl Drop for RefreshLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub async fn login(args: &LoginArgs) -> Result<(), LoginError> {
    let issuer = oauth_issuer(args.issuer.as_deref())?;
    let client_id = oauth_client_id(args.client_id.as_deref());
    let credential_store = if args.insecure_storage {
        CredentialStore::File
    } else {
        CredentialStore::Keyring
    };
    let destination_config = load_cli_config()?;
    let (account_endpoint, basin_endpoint) = effective_endpoints(&destination_config);
    validate_endpoint_binding(
        issuer.as_str(),
        &account_endpoint,
        &basin_endpoint,
        destination_config.ssl_no_verify == Some(true),
    )?;
    {
        let _config_lock = acquire_config_lock().await?;
        let mut config = load_config_file()?;
        prepare_login_store(&mut config, credential_store).await?;
    }
    let completion_url = oauth_completion_url()?;
    let http = oauth_http_client()?;
    let endpoints = discover(&http, &issuer).await?;
    let pkce = Pkce::random();
    let state = random_base64url();

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(LoginError::Listen)?;
    let callback_url = format!(
        "http://127.0.0.1:{}/callback",
        listener.local_addr().map_err(LoginError::Listen)?.port()
    );
    let authorization_url = authorization_url(
        &endpoints.authorization,
        &client_id,
        &callback_url,
        &state,
        &pkce.challenge,
    );

    let (callback_tx, callback_rx) = oneshot::channel();
    let callback_state = CallbackState {
        expected_state: state,
        sender: Arc::new(Mutex::new(Some(callback_tx))),
        completion_url,
    };
    let app = Router::new()
        .route("/callback", get(handle_callback))
        .with_state(callback_state);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    show_authorization_url(&authorization_url, args.no_open);

    let callback_result = timeout(args.timeout, callback_rx).await;
    let _ = shutdown_tx.send(());
    match timeout(CALLBACK_SHUTDOWN_TIMEOUT, &mut server).await {
        Ok(result) => result
            .map_err(LoginError::CallbackTask)?
            .map_err(LoginError::CallbackServer)?,
        Err(_) => {
            server.abort();
            let _ = server.await;
        }
    }

    let code = callback_result
        .map_err(|_| LoginError::TimedOut)?
        .map_err(|_| LoginError::CallbackClosed)?
        .map_err(LoginError::AuthorizationRejected)?;
    let _config_lock = acquire_config_lock().await?;
    let mut config = load_config_file()?;
    prepare_login_store(&mut config, credential_store).await?;
    let current_destination_config = load_cli_config()?;
    let (account_endpoint, basin_endpoint) = effective_endpoints(&current_destination_config);
    validate_endpoint_binding(
        issuer.as_str(),
        &account_endpoint,
        &basin_endpoint,
        current_destination_config.ssl_no_verify == Some(true),
    )?;
    let previous_session = config.oauth.clone();
    let token_set = exchange_code(
        &http,
        &endpoints,
        &client_id,
        &callback_url,
        &code,
        &pkce.verifier,
    )
    .await?;

    let reference = crate::config::StoredCredentialReference {
        credential_id: Uuid::new_v4().to_string(),
        credential_store,
    };
    let session = OAuthSession {
        issuer: endpoints.issuer.to_string(),
        client_id,
        account_endpoint,
        basin_endpoint,
        credential_id: reference.credential_id.clone(),
        credential_store,
    };
    let grant_may_be_reused = previous_session.as_ref().is_some_and(|previous| {
        let previous_tokens = load_credentials(previous).ok();
        oauth_grant_may_be_reused(previous, previous_tokens.as_ref(), &session, &token_set)
    });

    // Journal the new credential before writing it so a crash leaves enough
    // information to either revoke it or delete it without revoking a reused grant.
    let mut prepared_config = config.clone();
    if grant_may_be_reused {
        prepared_config
            .pending_oauth_cleanup
            .push(reference.clone());
    } else {
        prepared_config
            .pending_oauth_revocation
            .push(session.clone());
    }
    if let Err(error) = save_cli_config(&prepared_config) {
        if !grant_may_be_reused
            && let Err(revocation) = revoke_token(
                &http,
                &endpoints,
                &session.client_id,
                &token_set.refresh_token,
            )
            .await
        {
            return Err(LoginError::UnjournaledGrant {
                config: Box::new(error),
                revocation: Box::new(revocation),
            });
        }
        return Err(error.into());
    }

    if let Err(error) = save_credentials(&session, &token_set) {
        if let Err(cleanup) =
            cleanup_new_credential(&http, &endpoints, &session, &token_set, grant_may_be_reused)
                .await
        {
            return Err(LoginError::CredentialWriteRollback {
                write: Box::new(error),
                cleanup: Box::new(cleanup),
                recovery: credential_store::credential_location(
                    CredentialKind::OAuth,
                    &session.credential_id,
                    session.credential_store,
                ),
            });
        }
        return Err(error);
    }

    let mut config = prepared_config;
    config
        .pending_oauth_cleanup
        .retain(|pending| pending != &reference);
    config
        .pending_oauth_revocation
        .retain(|pending| pending != &session);
    config.auth_method = Some(AuthMethod::BrowserLogin);
    config.oauth = Some(session.clone());
    if let Some(previous) = previous_session.as_ref() {
        queue_replaced_session(&mut config, previous, grant_may_be_reused);
    }
    let saved_path = match save_cli_config(&config) {
        Ok(path) => path,
        Err(error) => {
            let cleanup = cleanup_new_credential(
                &http,
                &endpoints,
                &session,
                &token_set,
                grant_may_be_reused,
            )
            .await;
            return Err(match cleanup {
                Err(cleanup) => LoginError::LoginRollback {
                    config: Box::new(error),
                    cleanup: Box::new(cleanup),
                    recovery: credential_store::credential_location(
                        CredentialKind::OAuth,
                        &session.credential_id,
                        session.credential_store,
                    ),
                },
                Ok(()) => error.into(),
            });
        }
    };

    let replaced_existing_login = previous_session.is_some();
    let (cleanup_changed, mut cleanup_warning) = cleanup_pending_oauth(&mut config, true).await;
    if cleanup_changed && let Err(error) = save_cli_config(&config) {
        append_cleanup_warning(
            &mut cleanup_warning,
            format!("could not update OAuth credential cleanup metadata: {error}"),
        );
    }

    eprintln!("{}", "✓ Logged in to S2".green().bold());
    eprintln!("  - Browser login selected.");
    if replaced_existing_login {
        eprintln!("  - Previous browser login replaced.");
    }
    match session.credential_store {
        CredentialStore::Keyring => {
            eprintln!("  - Credentials saved to: {}", "OS credential store".cyan());
        }
        CredentialStore::File => {
            #[cfg(unix)]
            eprintln!(
                "{}",
                "  - Warning: credentials are stored in a plaintext file with user-only permissions."
                    .yellow()
            );
            #[cfg(not(unix))]
            eprintln!(
                "{}",
                "  - Warning: credentials are stored in a plaintext file using the platform's \
                 default user-directory permissions."
                    .yellow()
            );
            eprintln!(
                "  - Credentials saved to: {}",
                credential_file_path(&session)?.display().to_string().cyan()
            );
        }
    }
    eprintln!(
        "  - Configuration saved to: {}",
        saved_path.display().to_string().cyan()
    );
    if let Some(error) = cleanup_warning {
        eprintln!(
            "{}",
            format!(
                "  - Warning: could not finish cleaning up an older browser login; it remains queued for cleanup: {error}"
            )
            .yellow()
        );
    }

    if has_access_token_environment_variable() {
        eprintln!(
            "{}",
            "  - Warning: S2_ACCESS_TOKEN is set and remains active. Unset it to use browser login."
                .yellow()
        );
    }

    Ok(())
}

async fn cleanup_new_credential(
    http: &reqwest::Client,
    endpoints: &OAuthEndpoints,
    session: &OAuthSession,
    token_set: &TokenSet,
    grant_may_be_reused: bool,
) -> Result<(), LoginError> {
    if !grant_may_be_reused {
        revoke_token(
            http,
            endpoints,
            &session.client_id,
            &token_set.refresh_token,
        )
        .await?;
    }
    credential_store::delete(
        CredentialKind::OAuth,
        &session.credential_id,
        session.credential_store,
    )?;
    Ok(())
}

fn same_oauth_client(left: &OAuthSession, right: &OAuthSession) -> bool {
    if left.client_id != right.client_id {
        return false;
    }
    match (Url::parse(&left.issuer), Url::parse(&right.issuer)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left.issuer == right.issuer,
    }
}

fn oauth_grant_may_be_reused(
    previous_session: &OAuthSession,
    previous_tokens: Option<&TokenSet>,
    next_session: &OAuthSession,
    next_tokens: &TokenSet,
) -> bool {
    if !same_oauth_client(previous_session, next_session) {
        return false;
    }

    match (
        previous_tokens.and_then(|tokens| oauth_identity(&tokens.access_token)),
        oauth_identity(&next_tokens.access_token),
    ) {
        (Some(previous), Some(next)) => previous == next,
        // The token endpoint is trusted, but identity extraction is only a
        // conservative grant-reuse heuristic. Unknown token formats must not
        // risk revoking a grant the new login may share.
        _ => true,
    }
}

fn oauth_identity(access_token: &SecretString) -> Option<OAuthIdentity> {
    let mut parts = access_token.expose_secret().split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if signature.is_empty() || parts.next().is_some() {
        return None;
    }
    let payload = Base64UrlUnpadded::decode_vec(payload).ok()?;
    let identity: OAuthIdentity = serde_json::from_slice(&payload).ok()?;
    (!identity.sub.is_empty() && !identity.org_id.is_empty()).then_some(identity)
}

fn has_pending_oauth_in_store(config: &CliConfig, store: CredentialStore) -> bool {
    config
        .pending_oauth_cleanup
        .iter()
        .any(|reference| reference.credential_store == store)
        || config
            .pending_oauth_revocation
            .iter()
            .any(|session| session.credential_store == store)
}

async fn prepare_login_store(
    config: &mut CliConfig,
    store: CredentialStore,
) -> Result<(), LoginError> {
    let (cleanup_changed, cleanup_warning) = cleanup_pending_oauth(config, true).await;
    if cleanup_changed {
        save_cli_config(config)?;
    }
    if has_pending_oauth_in_store(config, store) {
        return Err(LoginError::PendingLoginCleanup {
            details: cleanup_warning
                .unwrap_or_else(|| "the previous cleanup is still pending".to_owned()),
        });
    }
    Ok(())
}

fn queue_replaced_session(
    config: &mut CliConfig,
    previous: &OAuthSession,
    grant_may_be_reused: bool,
) {
    if grant_may_be_reused {
        let reference = previous.credential_reference();
        if !config.pending_oauth_cleanup.contains(&reference) {
            config.pending_oauth_cleanup.push(reference);
        }
    } else if !config.pending_oauth_revocation.contains(previous) {
        config.pending_oauth_revocation.push(previous.clone());
    }
}

pub async fn logout(args: &LogoutArgs) -> Result<(), LoginError> {
    let _config_lock = acquire_config_lock().await?;
    let mut config = load_config_file()?;
    let Some(session) = config.oauth.clone() else {
        let (cleanup_changed, cleanup_warning) =
            cleanup_pending_oauth(&mut config, !args.local_only).await;
        if cleanup_changed {
            save_cli_config(&config)?;
        }
        eprintln!("{}", "✓ No browser login to remove".green().bold());
        if has_access_token_environment_variable() {
            eprintln!(
                "{}",
                "  - Warning: S2_ACCESS_TOKEN is set and remains active.".yellow()
            );
        } else if config.has_stored_access_token() {
            eprintln!("  - Access token remains configured.");
        }
        if let Some(error) = cleanup_warning {
            eprintln!(
                "{}",
                format!(
                    "  - Warning: could not finish cleaning up an older browser login; it remains queued for cleanup: {error}"
                )
                .yellow()
            );
        }
        return Ok(());
    };

    let refresh_lock = acquire_refresh_lock(&session).await?;
    let mut remotely_revoked = false;
    if !args.local_only {
        let token_set = load_credentials(&session)?;
        let issuer = oauth_issuer(Some(&session.issuer))?;
        let http = oauth_http_client()?;
        let endpoints = discover(&http, &issuer).await?;
        revoke_token(
            &http,
            &endpoints,
            &session.client_id,
            &token_set.refresh_token,
        )
        .await?;
        remotely_revoked = true;
    }

    let reference = session.credential_reference();
    config.oauth = None;
    config.auth_method = config
        .has_stored_access_token()
        .then_some(AuthMethod::AccessToken);
    if !config.pending_oauth_cleanup.contains(&reference) {
        config.pending_oauth_cleanup.push(reference.clone());
    }
    if let Err(error) = save_cli_config(&config) {
        if remotely_revoked {
            return Err(LoginError::RevokedButNotRemoved(error));
        }
        return Err(error.into());
    }

    // The config no longer selects this credential. Release its refresh lock
    // before the generic cleanup path takes the same lock.
    drop(refresh_lock);
    let (cleanup_changed, mut cleanup_warning) =
        cleanup_pending_oauth(&mut config, !args.local_only).await;
    if cleanup_changed && let Err(error) = save_cli_config(&config) {
        append_cleanup_warning(
            &mut cleanup_warning,
            format!("could not update OAuth credential cleanup metadata: {error}"),
        );
    }
    if config.pending_oauth_cleanup.contains(&reference) {
        return Err(LoginError::LogoutIncomplete {
            recovery: credential_store::credential_location(
                CredentialKind::OAuth,
                &reference.credential_id,
                reference.credential_store,
            ),
        });
    }

    eprintln!("{}", "✓ Browser login removed".green().bold());
    if has_access_token_environment_variable() {
        eprintln!(
            "{}",
            "  - Warning: S2_ACCESS_TOKEN is set and remains active.".yellow()
        );
    } else if config.has_stored_access_token() {
        eprintln!("  - Access token selected.");
    }
    if args.local_only {
        eprintln!(
            "{}",
            "  - Local credentials were removed without server-side revocation.".yellow()
        );
    }
    if let Some(error) = cleanup_warning {
        eprintln!(
            "{}",
            format!(
                "  - Warning: could not finish cleaning up an older browser login; it remains queued for cleanup: {error}"
            )
            .yellow()
        );
    }

    Ok(())
}

pub async fn resolve_access_token() -> Result<(CliConfig, ResolvedCredential), LoginError> {
    let mut snapshot = load_cli_config()?;
    let environment_access_token = access_token_from_environment()?;
    if let Some(access_token) = environment_access_token {
        access_token::validate(&access_token)?;
        return Ok((
            snapshot,
            ResolvedCredential {
                access_token: access_token.into(),
                source: TokenSource::Environment,
                oauth_session: None,
                oauth_tokens: None,
            },
        ));
    }

    for attempt in 0..4 {
        match resolve_persistent_access_token(&snapshot).await {
            Err(error) if error.should_reload_auth_config() && attempt < 3 => {
                let latest = load_cli_config()?;
                if !authentication_config_changed(&snapshot, &latest) {
                    return Err(error);
                }
                snapshot = latest;
            }
            result => return result.map(|credential| (snapshot, credential)),
        }
    }
    unreachable!("the final authentication attempt returns")
}

async fn resolve_persistent_access_token(
    config: &CliConfig,
) -> Result<ResolvedCredential, LoginError> {
    match credential_choice(config, false)? {
        CredentialChoice::Environment => unreachable!("environment access is handled first"),
        CredentialChoice::BrowserLogin => {
            let session = config
                .oauth
                .as_ref()
                .ok_or(CliConfigError::MissingAccessToken)?;
            let rejected_access_tokens = HashSet::new();
            let token_set = load_fresh_tokens(session, &rejected_access_tokens).await?;
            Ok(ResolvedCredential {
                access_token: token_set.access_token.clone(),
                source: TokenSource::BrowserLogin,
                oauth_session: Some(session.clone()),
                oauth_tokens: Some(token_set.clone()),
            })
        }
        CredentialChoice::StoredAccessToken => Ok(ResolvedCredential {
            access_token: access_token::load(config)?,
            source: if config.stored_access_token.is_some() {
                TokenSource::StoredAccessToken
            } else {
                TokenSource::ConfigFile
            },
            oauth_session: None,
            oauth_tokens: None,
        }),
    }
}

fn authentication_config_changed(previous: &CliConfig, latest: &CliConfig) -> bool {
    previous.auth_method != latest.auth_method
        || previous.oauth != latest.oauth
        || previous.stored_access_token != latest.stored_access_token
        || previous.access_token != latest.access_token
}

fn credential_choice(
    config: &CliConfig,
    has_environment_token: bool,
) -> Result<CredentialChoice, CliConfigError> {
    if has_environment_token {
        return Ok(CredentialChoice::Environment);
    }

    match config.auth_method {
        Some(AuthMethod::BrowserLogin) if config.oauth.is_some() => {
            Ok(CredentialChoice::BrowserLogin)
        }
        Some(AuthMethod::AccessToken) if config.has_stored_access_token() => {
            Ok(CredentialChoice::StoredAccessToken)
        }
        Some(_) => Err(CliConfigError::MissingAccessToken),
        None if config.has_stored_access_token() => Ok(CredentialChoice::StoredAccessToken),
        None if config.oauth.is_some() => Ok(CredentialChoice::BrowserLogin),
        None => Err(CliConfigError::MissingAccessToken),
    }
}

async fn load_fresh_tokens(
    session: &OAuthSession,
    rejected_access_tokens: &HashSet<String>,
) -> Result<TokenSet, LoginError> {
    let _config_lock = acquire_config_lock().await?;
    let config = load_config_file()?;
    if config.oauth.as_ref() != Some(session) {
        return Err(LoginError::SessionChanged);
    }
    let _lock = acquire_refresh_lock(session).await?;
    let token_set = load_credentials(session)?;
    if !rejected_access_tokens.contains(token_set.access_token.expose_secret())
        && token_is_fresh(&token_set)?
    {
        // Another process may have refreshed while this process waited for the lock.
        return Ok(token_set);
    }

    let issuer = oauth_issuer(Some(&session.issuer))?;
    let http = oauth_http_client()?;
    let endpoints = discover(&http, &issuer).await?;
    let refreshed = refresh_token(
        &http,
        &endpoints,
        &session.client_id,
        &token_set.refresh_token,
    )
    .await?;
    save_credentials(session, &refreshed)
        .map_err(|error| LoginError::RefreshPersistence(Box::new(error)))?;
    Ok(refreshed)
}

async fn refresh_cached_tokens_if_needed(
    session: &OAuthSession,
    state: &mut ProviderTokenState,
    rejected_access_tokens: &HashSet<String>,
) -> Result<(), LoginError> {
    let rejected = rejected_access_tokens.contains(state.tokens.access_token.expose_secret());
    if !state.persist_pending && !rejected && token_is_fresh(&state.tokens)? {
        return Ok(());
    }

    // Keep config -> refresh-lock ordering consistent with login/logout cleanup.
    let _config_lock = acquire_config_lock().await?;
    let config = load_config_file()?;
    if config.oauth.as_ref() != Some(session) {
        return Err(LoginError::SessionChanged);
    }
    let _refresh_lock = acquire_refresh_lock(session).await?;

    if !state.persist_pending {
        match load_credentials(session) {
            Ok(tokens) => state.tokens = tokens,
            Err(error) if error.is_credential_not_found() => {}
            Err(error) => return Err(error),
        }
    }

    if state.persist_pending {
        save_credentials(session, &state.tokens)
            .map_err(|error| LoginError::RefreshPersistence(Box::new(error)))?;
        state.persist_pending = false;
    }

    let rejected = rejected_access_tokens.contains(state.tokens.access_token.expose_secret());
    if !rejected && token_is_fresh(&state.tokens)? {
        return Ok(());
    }

    let issuer = oauth_issuer(Some(&session.issuer))?;
    let http = oauth_http_client()?;
    let endpoints = discover(&http, &issuer).await?;
    let refreshed = refresh_token(
        &http,
        &endpoints,
        &session.client_id,
        &state.tokens.refresh_token,
    )
    .await?;
    state.tokens = refreshed;
    if let Err(error) = save_credentials(session, &state.tokens) {
        state.persist_pending = true;
        return Err(LoginError::RefreshPersistence(Box::new(error)));
    }
    Ok(())
}

fn oauth_http_client() -> Result<reqwest::Client, LoginError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HTTP_TIMEOUT)
        .user_agent(concat!("s2-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(LoginError::HttpClient)
}

fn oauth_issuer(override_url: Option<&str>) -> Result<Url, LoginError> {
    let raw = override_url
        .map(str::to_owned)
        .or_else(|| std::env::var("S2_OAUTH_ISSUER").ok())
        .unwrap_or_else(|| DEFAULT_OAUTH_ISSUER.to_owned());
    let url = Url::parse(&raw).map_err(|error| LoginError::InvalidIssuer(error.to_string()))?;

    if url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(LoginError::InvalidIssuer(
            "expected an HTTP(S) origin without credentials, path, query, or fragment".to_owned(),
        ));
    }

    match url.scheme() {
        "https" => {}
        "http" if url.host_str().is_some_and(is_loopback_host) => {}
        _ => {
            return Err(LoginError::InvalidIssuer(
                "HTTPS is required unless the issuer is on loopback".to_owned(),
            ));
        }
    }

    Ok(url)
}

fn oauth_client_id(override_id: Option<&str>) -> String {
    override_id
        .filter(|client_id| !client_id.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var("S2_OAUTH_CLIENT_ID")
                .ok()
                .filter(|client_id| !client_id.trim().is_empty())
        })
        .unwrap_or_else(|| DEFAULT_OAUTH_CLIENT_ID.to_owned())
}

fn oauth_completion_url() -> Result<Option<Url>, LoginError> {
    let raw = std::env::var("S2_OAUTH_COMPLETION_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_OAUTH_COMPLETION_URL.to_owned());
    let url =
        Url::parse(&raw).map_err(|error| LoginError::InvalidCompletionUrl(error.to_string()))?;

    if url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(LoginError::InvalidCompletionUrl(
            "expected an HTTP(S) URL without credentials, query, or fragment".to_owned(),
        ));
    }

    match url.scheme() {
        "https" => {}
        "http" if url.host_str().is_some_and(is_loopback_host) => {}
        _ => {
            return Err(LoginError::InvalidCompletionUrl(
                "HTTPS is required unless the website is on loopback".to_owned(),
            ));
        }
    }

    Ok(Some(url))
}

async fn discover(http: &reqwest::Client, issuer: &Url) -> Result<OAuthEndpoints, LoginError> {
    let metadata_url = issuer
        .join("/.well-known/oauth-authorization-server")
        .expect("validated issuer is a base URL");
    let response = http
        .get(metadata_url)
        .send()
        .await
        .map_err(|source| LoginError::Request {
            operation: "discovery",
            source,
        })?;
    let (status, bytes) = read_oauth_response(response, "discovery").await?;
    let metadata: AuthorizationServerMetadata = parse_oauth_response("discovery", status, &bytes)?;
    validate_metadata(issuer, metadata)
}

fn validate_metadata(
    expected_issuer: &Url,
    metadata: AuthorizationServerMetadata,
) -> Result<OAuthEndpoints, LoginError> {
    let issuer = Url::parse(&metadata.issuer)
        .map_err(|error| LoginError::InvalidMetadata(format!("invalid issuer: {error}")))?;
    if &issuer != expected_issuer {
        return Err(LoginError::InvalidMetadata(format!(
            "issuer mismatch: expected {expected_issuer}, received {issuer}"
        )));
    }
    if !metadata
        .code_challenge_methods_supported
        .iter()
        .any(|method| method == "S256")
    {
        return Err(LoginError::InvalidMetadata(
            "the provider does not support PKCE S256".to_owned(),
        ));
    }
    if !metadata
        .response_types_supported
        .iter()
        .any(|response_type| response_type == "code")
    {
        return Err(LoginError::InvalidMetadata(
            "the provider does not support the code response type".to_owned(),
        ));
    }
    if !metadata
        .token_endpoint_auth_methods_supported
        .iter()
        .any(|method| method == "none")
    {
        return Err(LoginError::InvalidMetadata(
            "the provider does not support public OAuth clients".to_owned(),
        ));
    }
    for grant in ["authorization_code", "refresh_token"] {
        if !metadata
            .grant_types_supported
            .iter()
            .any(|supported| supported == grant)
        {
            return Err(LoginError::InvalidMetadata(format!(
                "the provider does not support the {grant} grant"
            )));
        }
    }
    for scope in OAUTH_SCOPES.split_ascii_whitespace() {
        if !metadata
            .scopes_supported
            .iter()
            .any(|supported| supported == scope)
        {
            return Err(LoginError::InvalidMetadata(format!(
                "the provider does not support the {scope} scope"
            )));
        }
    }

    let revocation_endpoint = metadata.revocation_endpoint.as_deref().ok_or_else(|| {
        LoginError::InvalidMetadata("the provider does not advertise token revocation".to_owned())
    })?;

    Ok(OAuthEndpoints {
        authorization: trusted_endpoint(
            &issuer,
            &metadata.authorization_endpoint,
            "authorization_endpoint",
        )?,
        token: trusted_endpoint(&issuer, &metadata.token_endpoint, "token_endpoint")?,
        revocation: trusted_endpoint(&issuer, revocation_endpoint, "revocation_endpoint")?,
        issuer,
    })
}

fn trusted_endpoint(issuer: &Url, raw: &str, field: &str) -> Result<Url, LoginError> {
    let endpoint = Url::parse(raw)
        .map_err(|error| LoginError::InvalidMetadata(format!("invalid {field}: {error}")))?;
    if endpoint.origin() != issuer.origin()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(LoginError::InvalidMetadata(format!(
            "{field} must use the OAuth issuer origin"
        )));
    }
    Ok(endpoint)
}

fn authorization_url(
    authorization_endpoint: &Url,
    client_id: &str,
    callback_url: &str,
    state: &str,
    code_challenge: &str,
) -> Url {
    let mut url = authorization_endpoint.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", callback_url)
        .append_pair("scope", OAUTH_SCOPES)
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    url
}

async fn exchange_code(
    http: &reqwest::Client,
    endpoints: &OAuthEndpoints,
    client_id: &str,
    callback_url: &str,
    code: &str,
    code_verifier: &str,
) -> Result<TokenSet, LoginError> {
    let response = http
        .post(endpoints.token.clone())
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("redirect_uri", callback_url),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|source| LoginError::Request {
            operation: "token exchange",
            source,
        })?;
    parse_token_http_response("token exchange", response, None).await
}

async fn refresh_token(
    http: &reqwest::Client,
    endpoints: &OAuthEndpoints,
    client_id: &str,
    previous_refresh_token: &SecretString,
) -> Result<TokenSet, LoginError> {
    let response = http
        .post(endpoints.token.clone())
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", previous_refresh_token.expose_secret()),
        ])
        .send()
        .await
        .map_err(|source| LoginError::Request {
            operation: "token refresh",
            source,
        })?;
    parse_token_http_response(
        "token refresh",
        response,
        Some(previous_refresh_token.expose_secret()),
    )
    .await
}

async fn revoke_token(
    http: &reqwest::Client,
    endpoints: &OAuthEndpoints,
    client_id: &str,
    refresh_token: &SecretString,
) -> Result<(), LoginError> {
    let response = http
        .post(endpoints.revocation.clone())
        .form(&[
            ("token", refresh_token.expose_secret()),
            ("token_type_hint", "refresh_token"),
            ("client_id", client_id),
        ])
        .send()
        .await
        .map_err(|source| LoginError::Request {
            operation: "token revocation",
            source,
        })?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let (_, bytes) = read_oauth_response(response, "token revocation").await?;
    Err(oauth_rejection("token revocation", status, &bytes))
}

async fn parse_token_http_response(
    operation: &'static str,
    response: reqwest::Response,
    previous_refresh_token: Option<&str>,
) -> Result<TokenSet, LoginError> {
    let (status, bytes) = read_oauth_response(response, operation).await?;
    let response: TokenResponse = parse_oauth_response(operation, status, &bytes)?;
    token_set(response, previous_refresh_token)
}

async fn read_oauth_response(
    mut response: reqwest::Response,
    operation: &'static str,
) -> Result<(StatusCode, Vec<u8>), LoginError> {
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| LoginError::Request { operation, source })?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_OAUTH_RESPONSE_BYTES {
            return Err(LoginError::ResponseTooLarge { operation });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}

fn token_set(
    response: TokenResponse,
    previous_refresh_token: Option<&str>,
) -> Result<TokenSet, LoginError> {
    if response.access_token.is_empty() {
        return Err(LoginError::InvalidTokenResponse(
            "access_token was empty".to_owned(),
        ));
    }
    if !response.token_type.eq_ignore_ascii_case("bearer") {
        return Err(LoginError::InvalidTokenResponse(
            "token_type was not bearer".to_owned(),
        ));
    }
    if response.expires_in == 0 {
        return Err(LoginError::InvalidTokenResponse(
            "expires_in was zero".to_owned(),
        ));
    }
    if let Some(scope) = response.scope.as_deref() {
        for required in OAUTH_SCOPES.split_ascii_whitespace() {
            if !scope
                .split_ascii_whitespace()
                .any(|scope| scope == required)
            {
                return Err(LoginError::InvalidTokenResponse(format!(
                    "the {required} scope was not granted"
                )));
            }
        }
    }
    let refresh_token = response
        .refresh_token
        .as_deref()
        .filter(|token| !token.is_empty())
        .or(previous_refresh_token)
        .ok_or_else(|| LoginError::InvalidTokenResponse("refresh_token was missing".to_owned()))?;
    let expires_at = now_unix_seconds()?
        .checked_add(response.expires_in)
        .ok_or_else(|| LoginError::InvalidTokenResponse("expires_in overflowed".to_owned()))?;

    Ok(TokenSet {
        access_token: response.access_token.into(),
        refresh_token: refresh_token.to_owned().into(),
        expires_at,
    })
}

fn parse_oauth_response<T: DeserializeOwned>(
    operation: &'static str,
    status: StatusCode,
    bytes: &[u8],
) -> Result<T, LoginError> {
    if !status.is_success() {
        return Err(oauth_rejection(operation, status, bytes));
    }
    serde_json::from_slice(bytes)
        .map_err(|source| LoginError::InvalidResponse { operation, source })
}

fn oauth_rejection(operation: &'static str, status: StatusCode, bytes: &[u8]) -> LoginError {
    let message = serde_json::from_slice::<OAuthErrorResponse>(bytes)
        .ok()
        .and_then(|body| body.error)
        .and_then(|error| known_oauth_error(&error).map(str::to_owned))
        .unwrap_or_else(|| "unknown error".to_owned());
    LoginError::Rejected {
        operation,
        status,
        message,
    }
}

fn known_oauth_error(error: &str) -> Option<&str> {
    matches!(
        error,
        "access_denied"
            | "invalid_client"
            | "invalid_grant"
            | "invalid_request"
            | "invalid_scope"
            | "invalid_token"
            | "server_error"
            | "temporarily_unavailable"
            | "unauthorized_client"
            | "unsupported_grant_type"
            | "unsupported_response_type"
            | "unsupported_token_type"
    )
    .then_some(error)
}

async fn handle_callback(
    State(state): State<CallbackState>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    if query.state.as_deref() != Some(&state.expected_state) {
        return callback_response(
            state.completion_url.as_ref(),
            StatusCode::BAD_REQUEST,
            CallbackStatus::Error,
        );
    }

    let provider_denied = query.error.as_deref() == Some("access_denied") && query.code.is_none();
    let outcome = if query.error.is_some() || query.error_description.is_some() {
        if query.code.is_some() {
            Err("authorization callback contained both a code and an error".to_owned())
        } else {
            Err(match (query.error, query.error_description) {
                (Some(error), Some(description)) => {
                    format!(
                        "{}: {}",
                        sanitize_message(&error),
                        sanitize_message(&description)
                    )
                }
                (Some(error), None) => sanitize_message(&error),
                (None, Some(description)) => sanitize_message(&description),
                (None, None) => unreachable!("checked for an OAuth error"),
            })
        }
    } else {
        match query.code {
            Some(code) if !code.is_empty() => Ok(code),
            _ => Err("authorization code was missing".to_owned()),
        }
    };
    let sender = state
        .sender
        .lock()
        .expect("callback sender mutex poisoned")
        .take();
    let Some(sender) = sender else {
        return callback_response(
            state.completion_url.as_ref(),
            StatusCode::CONFLICT,
            CallbackStatus::AlreadyCompleted,
        );
    };

    let authorized = outcome.is_ok();
    let _ = sender.send(outcome);
    if authorized {
        callback_response(
            state.completion_url.as_ref(),
            StatusCode::OK,
            CallbackStatus::Authorized,
        )
    } else if provider_denied {
        callback_response(
            state.completion_url.as_ref(),
            StatusCode::BAD_REQUEST,
            CallbackStatus::Denied,
        )
    } else {
        callback_response(
            state.completion_url.as_ref(),
            StatusCode::BAD_REQUEST,
            CallbackStatus::Error,
        )
    }
}

fn callback_response(
    completion_url: Option<&Url>,
    status: StatusCode,
    callback_status: CallbackStatus,
) -> Response {
    let mut response = match completion_url {
        Some(completion_url) => {
            let mut url = completion_url.clone();
            url.query_pairs_mut()
                .append_pair("status", callback_status.as_str());
            Redirect::to(url.as_str()).into_response()
        }
        None => status.into_response(),
    };
    let headers = response.headers_mut();
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

fn show_authorization_url(url: &Url, no_open: bool) {
    if !no_open {
        match open_browser(url.as_str()) {
            Ok(()) => {
                eprintln!("Opening your browser to finish logging in...");
                eprintln!("If it does not open, visit:\n{}", url.as_str().cyan());
                return;
            }
            Err(error) => {
                eprintln!("Could not open a browser automatically: {error}");
            }
        }
    }

    eprintln!(
        "Open this URL to finish logging in:\n{}",
        url.as_str().cyan()
    );
}

#[cfg(target_os = "macos")]
fn open_browser(url: &str) -> std::io::Result<()> {
    ensure_command_succeeded(Command::new("open").arg(url).status()?)
}

#[cfg(target_os = "windows")]
fn open_browser(url: &str) -> std::io::Result<()> {
    ensure_command_succeeded(
        Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .status()?,
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_browser(url: &str) -> std::io::Result<()> {
    ensure_command_succeeded(Command::new("xdg-open").arg(url).status()?)
}

fn ensure_command_succeeded(status: std::process::ExitStatus) -> std::io::Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "browser command exited with {status}"
        )))
    }
}

fn save_credentials(session: &OAuthSession, token_set: &TokenSet) -> Result<(), LoginError> {
    let stored = StoredTokenSet {
        version: CREDENTIAL_VERSION,
        kind: OAUTH_CREDENTIAL_KIND.to_owned(),
        credential_id: session.credential_id.clone(),
        issuer: session.issuer.clone(),
        client_id: session.client_id.clone(),
        access_token: token_set.access_token.expose_secret().to_owned(),
        refresh_token: token_set.refresh_token.expose_secret().to_owned(),
        expires_at: token_set.expires_at,
    };
    let bytes = SecretBox::new(Box::new(
        serde_json::to_vec(&stored).map_err(LoginError::SerializeCredentials)?,
    ));
    credential_store::save(
        CredentialKind::OAuth,
        &session.credential_id,
        session.credential_store,
        bytes.expose_secret(),
    )?;
    Ok(())
}

fn load_credentials(session: &OAuthSession) -> Result<TokenSet, LoginError> {
    let bytes = SecretBox::new(Box::new(credential_store::load(
        CredentialKind::OAuth,
        &session.credential_id,
        session.credential_store,
    )?));
    decode_credentials(session, bytes.expose_secret())
}

fn decode_credentials(session: &OAuthSession, bytes: &[u8]) -> Result<TokenSet, LoginError> {
    let stored: StoredTokenSet =
        serde_json::from_slice(bytes).map_err(LoginError::ParseCredentials)?;
    if stored.version != CREDENTIAL_VERSION
        || stored.kind != OAUTH_CREDENTIAL_KIND
        || stored.credential_id != session.credential_id
        || stored.issuer != session.issuer
        || stored.client_id != session.client_id
    {
        return Err(LoginError::CredentialBindingMismatch);
    }
    if stored.access_token.is_empty() || stored.refresh_token.is_empty() {
        return Err(LoginError::CredentialBindingMismatch);
    }
    Ok(TokenSet {
        access_token: stored.access_token.into(),
        refresh_token: stored.refresh_token.into(),
        expires_at: stored.expires_at,
    })
}

async fn cleanup_pending_oauth(
    config: &mut CliConfig,
    revoke_pending: bool,
) -> (bool, Option<String>) {
    let (revocation_changed, mut warning) = if revoke_pending {
        cleanup_pending_oauth_revocations(config).await
    } else {
        let pending = std::mem::take(&mut config.pending_oauth_revocation);
        let changed = !pending.is_empty();
        for session in pending {
            let reference = session.credential_reference();
            if !config.pending_oauth_cleanup.contains(&reference) {
                config.pending_oauth_cleanup.push(reference);
            }
        }
        (changed, None)
    };
    let (credential_changed, credential_warning) = cleanup_pending_oauth_credentials(config).await;
    if let Some(credential_warning) = credential_warning {
        append_cleanup_warning(&mut warning, credential_warning);
    }
    (revocation_changed || credential_changed, warning)
}

async fn cleanup_pending_oauth_revocations(config: &mut CliConfig) -> (bool, Option<String>) {
    let pending = std::mem::take(&mut config.pending_oauth_revocation);
    let mut retained = Vec::new();
    let mut errors = Vec::new();
    let mut changed = false;
    for session in pending {
        if config.oauth.as_ref() == Some(&session) {
            errors.push(format!(
                "credential {} is still active",
                session.credential_id
            ));
            retained.push(session);
            continue;
        }
        let _refresh_lock = match acquire_refresh_lock(&session).await {
            Ok(lock) => lock,
            Err(error) => {
                errors.push(format!("credential {}: {error}", session.credential_id));
                retained.push(session);
                continue;
            }
        };
        let token_set = match load_credentials(&session) {
            Ok(tokens) => tokens,
            Err(error) if error.is_credential_not_found() => {
                changed = true;
                continue;
            }
            Err(error) => {
                errors.push(format!("credential {}: {error}", session.credential_id));
                retained.push(session);
                continue;
            }
        };
        let result = async {
            let issuer = oauth_issuer(Some(&session.issuer))?;
            let http = oauth_http_client()?;
            let endpoints = discover(&http, &issuer).await?;
            revoke_token(
                &http,
                &endpoints,
                &session.client_id,
                &token_set.refresh_token,
            )
            .await?;
            credential_store::delete(
                CredentialKind::OAuth,
                &session.credential_id,
                session.credential_store,
            )?;
            Ok::<(), LoginError>(())
        }
        .await;
        match result {
            Ok(()) => changed = true,
            Err(error) => {
                errors.push(format!("credential {}: {error}", session.credential_id));
                retained.push(session);
            }
        }
    }
    config.pending_oauth_revocation = retained;
    (changed, (!errors.is_empty()).then(|| errors.join("; ")))
}

async fn cleanup_pending_oauth_credentials(config: &mut CliConfig) -> (bool, Option<String>) {
    let pending = std::mem::take(&mut config.pending_oauth_cleanup);
    let mut retained = Vec::new();
    let mut errors = Vec::new();
    let mut removed = false;
    for reference in pending {
        if config
            .oauth
            .as_ref()
            .is_some_and(|active| active.credential_reference() == reference)
        {
            errors.push(format!(
                "credential {} is still active",
                reference.credential_id
            ));
            retained.push(reference);
            continue;
        }
        let _refresh_lock = match acquire_refresh_lock_for_id(&reference.credential_id).await {
            Ok(lock) => lock,
            Err(error) => {
                errors.push(format!("credential {}: {error}", reference.credential_id));
                retained.push(reference);
                continue;
            }
        };
        match credential_store::delete(
            CredentialKind::OAuth,
            &reference.credential_id,
            reference.credential_store,
        ) {
            Ok(()) => removed = true,
            Err(error) => {
                errors.push(format!("credential {}: {error}", reference.credential_id));
                retained.push(reference);
            }
        }
    }
    config.pending_oauth_cleanup = retained;
    (removed, (!errors.is_empty()).then(|| errors.join("; ")))
}

fn append_cleanup_warning(warning: &mut Option<String>, message: String) {
    match warning {
        Some(warning) => {
            warning.push_str("; ");
            warning.push_str(&message);
        }
        None => *warning = Some(message),
    }
}

fn credential_file_path(session: &OAuthSession) -> Result<PathBuf, LoginError> {
    Ok(credential_store::credential_file_path(
        CredentialKind::OAuth,
        &session.credential_id,
    )?)
}

fn refresh_lock_path(credential_id: &str) -> Result<PathBuf, LoginError> {
    let digest = Sha256::digest(credential_id.as_bytes());
    let filename = format!(
        "oauth-{}.lock",
        Base64UrlUnpadded::encode_string(digest.as_slice())
    );
    let path = config_path()?;
    Ok(path.with_file_name(filename))
}

async fn acquire_refresh_lock(session: &OAuthSession) -> Result<RefreshLock, LoginError> {
    acquire_refresh_lock_for_id(&session.credential_id).await
}

async fn acquire_refresh_lock_for_id(credential_id: &str) -> Result<RefreshLock, LoginError> {
    let path = refresh_lock_path(credential_id)?;
    let parent = path
        .parent()
        .ok_or_else(|| LoginError::InvalidTokenResponse("invalid lock path".to_owned()))?;
    fs::create_dir_all(parent).map_err(LoginError::RefreshLock)?;
    secure_directory(parent)?;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(LoginError::RefreshLock)?;
    let deadline = tokio::time::Instant::now() + REFRESH_LOCK_TIMEOUT;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(RefreshLock { file }),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(LoginError::RefreshLockTimedOut);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(LoginError::RefreshLock(error)),
        }
    }
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), LoginError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        LoginError::CredentialFile {
            action: "secure the parent directory for",
            source,
        }
    })
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), LoginError> {
    Ok(())
}

impl Pkce {
    fn random() -> Self {
        Self::from_verifier(random_base64url())
    }

    fn from_verifier(verifier: String) -> Self {
        let digest = Sha256::digest(verifier.as_bytes());
        Self {
            verifier,
            challenge: Base64UrlUnpadded::encode_string(digest.as_slice()),
        }
    }
}

fn random_base64url() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    Base64UrlUnpadded::encode_string(&bytes)
}

fn token_is_fresh(token_set: &TokenSet) -> Result<bool, LoginError> {
    Ok(token_set.expires_at > now_unix_seconds()?.saturating_add(REFRESH_SKEW.as_secs()))
}

fn now_unix_seconds() -> Result<u64, LoginError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| LoginError::InvalidTokenResponse("system clock is before 1970".to_owned()))
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

pub(crate) fn has_access_token_environment_variable() -> bool {
    access_token_from_environment().is_ok_and(|token| token.is_some())
}

fn sanitize_message(message: &str) -> String {
    message
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect()
}

#[cfg(test)]
mod tests;
