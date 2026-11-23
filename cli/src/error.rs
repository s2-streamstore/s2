use miette::Diagnostic;
use s2_sdk::error::{ErrorCode, S2Error, ServerError};
use thiserror::Error;

use crate::environment::Target;

const HELP: &str = color_print::cstr!(
    "\n<cyan><bold>Notice something wrong?</bold></cyan>\n\n\
     <green> > Open an issue:</green>\n\
     <bold>https://github.com/s2-streamstore/s2/issues</bold>\n\n\
     <green> > Reach out to us:</green>\n\
     <bold>hi@s2.dev</bold>"
);

const LITE_HELP: &str = color_print::cstr!(
    "If you are using s2-lite, some APIs are not supported.\n\
     More at <bold>https://s2.dev/docs/s2-lite</bold>"
);

const BUG_HELP: &str = color_print::cstr!(
    "\n<cyan><bold>Looks like you may have encountered a bug!</bold></cyan>\n\n\
     <green> > Report this issue here: </green>\n\
     <bold>https://github.com/s2-streamstore/s2/issues</bold>
"
);

pub type SdkError = S2Error;

#[derive(Error, Debug, Diagnostic)]
pub enum CliError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    Config(#[from] CliConfigError),

    #[error("Invalid CLI arguments: {0}")]
    #[diagnostic(transparent)]
    InvalidArgs(miette::Report),

    #[error("Unable to parse S2 endpoints: {0}")]
    #[diagnostic(help(
        "Endpoints can be set in the config file ({}) or via the `S2_ACCOUNT_ENDPOINT` / \
         `S2_BASIN_ENDPOINT` environment variables. Make sure the values are valid URLs \
         (e.g., https://a.s2.dev).",
        crate::config::config_path_string()
    ))]
    EndpointsInvalid(String),

    #[error("Failed to initialize S2 SDK")]
    #[diagnostic(help("{}", HELP))]
    SdkInit(#[source] SdkError),

    #[error("Failed to initialize S2 SDK")]
    #[diagnostic(help(
        "Token loaded from {1}. Verify it does not contain invalid characters.\n{}\n\n{}",
        .1.recovery_command(),
        HELP
    ))]
    MalformedAccessToken(#[source] SdkError, TokenSource),

    #[error(transparent)]
    #[diagnostic(help("{}", BUG_HELP))]
    InvalidConfig(#[from] serde_json::Error),

    #[error("Failed to initialize a `Record Reader`! {0}")]
    RecordReaderInit(String),

    #[error("Failed to write records: {0}")]
    RecordWrite(String),

    #[error("Benchmark verification failed: {0}")]
    #[diagnostic(help(
        "Ensure no other writers are mutating the stream during bench and retry the test."
    ))]
    BenchVerification(String),

    #[error("{0}")]
    #[diagnostic(help("{}", HELP))]
    Operation(OpKind, #[source] SdkError),

    #[error("{0}")]
    #[diagnostic(help(
        "Verify the token loaded from {2} is valid and has permission for this operation, then retry.\n{}",
        .2.recovery_command()
    ))]
    UnauthorizedAccessToken(OpKind, #[source] SdkError, TokenSource),

    #[error("{0}")]
    #[diagnostic(help("{}", LITE_HELP))]
    NotImplemented(OpKind, #[source] SdkError),

    #[error("{0}")]
    #[diagnostic(help(
        "The access token is bound to a network policy that does not permit requests from this \
         network. Retry from a permitted network, or use a token without that restriction."
    ))]
    NetworkPolicyDenied(OpKind, #[source] SdkError),

    #[error("S2 Lite server error: {0}")]
    #[diagnostic(help("{}", HELP))]
    LiteServer(String),

    #[error(transparent)]
    #[diagnostic(transparent)]
    Login(#[from] crate::login::LoginError),

    #[error("Apply failed: {0}")]
    #[diagnostic(help("{}", HELP))]
    Apply(String),

    #[error("Access token '{0}' not found")]
    AccessTokenNotFound(String),

    #[error(transparent)]
    #[diagnostic(transparent)]
    AccessToken(#[from] crate::access_token::AccessTokenError),

    #[error("Invalid configuration returned by S2: {0}")]
    #[diagnostic(help("{}", BUG_HELP))]
    InvalidApiConfig(#[from] s2_common::ValidationError),

    #[error("Update failed: {0}")]
    #[diagnostic(help(
        "Retry, or install the latest release manually:\n\
         https://s2.dev/docs/quickstart#get-started-with-the-cli"
    ))]
    Update(String),
}

impl CliError {
    pub fn op<E: Into<SdkError>>(kind: OpKind, source: E) -> Self {
        Self::Operation(kind, source.into())
    }

    pub fn with_token_source(self, token_source: Option<TokenSource>) -> Self {
        match (self, token_source) {
            (CliError::Operation(kind, source), _) if is_network_policy_denied(&source) => {
                CliError::NetworkPolicyDenied(kind, source)
            }
            (CliError::Operation(kind, source), Some(token_source)) if is_auth_error(&source) => {
                CliError::UnauthorizedAccessToken(kind, source, token_source)
            }
            (err, _) => err,
        }
    }

    /// S2 implements every API, so `not_implemented` from any other endpoint most likely means
    /// s2-lite, which does not.
    pub fn with_target(self, target: Target) -> Self {
        match self {
            CliError::Operation(kind, source)
                if target != Target::S2 && is_not_implemented(&source) =>
            {
                CliError::NotImplemented(kind, source)
            }
            err => err,
        }
    }
}

#[derive(Debug, Clone, Copy, strum::AsRefStr)]
#[strum(serialize_all = "title_case")]
pub enum OpKind {
    ListBasins,
    CreateBasin,
    DeleteBasin,
    GetBasinConfig,
    ReconfigureBasin,
    ListAccessTokens,
    IssueAccessToken,
    RevokeAccessToken,
    ListNetworkPolicies,
    CreateNetworkPolicy,
    GetNetworkPolicy,
    DeleteNetworkPolicy,
    ListLocations,
    GetDefaultLocation,
    SetDefaultLocation,
    GetAccountMetrics,
    GetBasinMetrics,
    GetStreamMetrics,
    ListStreams,
    CreateStream,
    DeleteStream,
    GetStreamConfig,
    ReconfigureStream,
    CheckTail,
    Trim,
    #[strum(serialize = "set fencing token")]
    Fence,
    Append,
    Read,
    Tail,
    Bench,
}

impl std::fmt::Display for OpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to {}", self.as_ref().to_lowercase())
    }
}

impl std::error::Error for OpKind {}

#[derive(Debug, Error)]
pub enum S2UriParseError {
    #[error("S2 URI must begin with `s2://`")]
    MissingUriScheme,
    #[error("Invalid S2 URI scheme `{0}://`. Must be `s2://`")]
    InvalidUriScheme(String),
    #[error("{0}")]
    InvalidBasinName(String),
    #[error("{0}")]
    InvalidStreamName(String),
    #[error("Only basin name expected but found both basin and stream names")]
    UnexpectedStreamName,
    #[error("Missing stream name in S2 URI")]
    MissingStreamName,
}

#[derive(Debug, Clone, Copy)]
pub enum TokenSource {
    Environment,
    BrowserLogin,
    StoredAccessToken,
    ConfigFile,
}

impl TokenSource {
    pub fn recovery_command(self) -> &'static str {
        match self {
            TokenSource::BrowserLogin => "Run `s2 login` again.",
            TokenSource::Environment => "Set S2_ACCESS_TOKEN to a valid access token.",
            TokenSource::StoredAccessToken | TokenSource::ConfigFile => {
                "Run `s2 auth access-token set` to replace it."
            }
        }
    }
}

impl std::fmt::Display for TokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenSource::Environment => write!(f, "environment (S2_ACCESS_TOKEN)"),
            TokenSource::BrowserLogin => write!(f, "browser login"),
            TokenSource::StoredAccessToken => write!(f, "stored access token"),
            TokenSource::ConfigFile => write!(f, "config file"),
        }
    }
}

fn root_server_error(mut err: &SdkError) -> Option<&ServerError> {
    loop {
        if let Some(server) = err.server_error() {
            return Some(server);
        }
        err = err.failure().or_else(|| err.final_attempt_error())?;
    }
}

fn is_auth_error(err: &SdkError) -> bool {
    root_server_error(err)
        .and_then(ServerError::known_code)
        .is_some_and(ErrorCode::is_auth_error)
}

fn is_network_policy_denied(err: &SdkError) -> bool {
    root_server_error(err)
        .and_then(ServerError::known_code)
        .is_some_and(|code| matches!(code, ErrorCode::NetworkPolicyDenied))
}

fn is_not_implemented(err: &SdkError) -> bool {
    root_server_error(err)
        .and_then(ServerError::known_code)
        .is_some_and(|code| matches!(code, ErrorCode::NotImplemented))
}

pub fn is_valid_access_token(token: &str) -> bool {
    !token.is_empty() && reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).is_ok()
}

#[cfg(test)]
impl PartialEq for S2UriParseError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::MissingUriScheme, Self::MissingUriScheme) => true,
            (Self::InvalidUriScheme(s), Self::InvalidUriScheme(o)) if s.eq(o) => true,
            (Self::InvalidBasinName(_), Self::InvalidBasinName(_)) => true,
            (Self::InvalidStreamName(_), Self::InvalidStreamName(_)) => true,
            (Self::MissingStreamName, Self::MissingStreamName) => true,
            (Self::UnexpectedStreamName, Self::UnexpectedStreamName) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpGroupsParseError {
    #[error("Invalid op_group format: '{value}'. Expected 'key=value'")]
    InvalidFormat { value: String },

    #[error("Invalid op_group key: '{key}'. Expected 'account', 'basin', or 'stream'")]
    InvalidKey { key: String },

    #[error("At least one permission ('r' or 'w') must be specified")]
    MissingPermission,

    #[error("Invalid permission character: {0}")]
    InvalidPermissionChar(char),
}

#[derive(Debug, Error)]
pub enum RecordParseError {
    #[error("Error reading: {0}")]
    Io(#[from] std::io::Error),
    #[error("Error parsing: {0}")]
    Parse(String),
}

impl From<String> for RecordParseError {
    fn from(s: String) -> Self {
        RecordParseError::Parse(s)
    }
}

#[derive(Error, Debug, Diagnostic)]
pub enum CliConfigError {
    #[error("Failed to find a home for config directory")]
    DirNotFound,

    #[error("Failed to load config file")]
    #[diagnostic(help(
        "Run `s2 auth access-token set`, or set the `S2_ACCESS_TOKEN` environment variable."
    ))]
    Load,

    #[error("Failed to write config file")]
    Write(#[source] std::io::Error),

    #[error("Failed to acquire the config lock")]
    Lock(#[source] std::io::Error),

    #[error("Timed out waiting for another S2 process to update the config")]
    LockTimedOut,

    #[error("Failed to serialize config")]
    Serialize(#[source] toml::ser::Error),

    #[error("Invalid value '{1}' for config key '{0}'")]
    InvalidValue(String, String),

    #[error("Access tokens are managed separately from ordinary configuration")]
    #[diagnostic(help(
        "Use `s2 auth access-token set` to store a token, or `s2 auth access-token remove` to forget it."
    ))]
    CredentialManagedSeparately,

    #[error("Stored access tokens cannot be read through `s2 config get`")]
    #[diagnostic(help(
        "Use the token's source of truth if it must be exported. The CLI intentionally does not print stored credentials."
    ))]
    CredentialNotReadable,

    #[error("Missing access token")]
    #[diagnostic(help(
        "Run `s2 login`, `s2 auth access-token set`, or set the `S2_ACCESS_TOKEN` environment variable."
    ))]
    MissingAccessToken,

    #[error("S2_ACCESS_TOKEN is not valid Unicode")]
    #[diagnostic(help("Set S2_ACCESS_TOKEN to a valid access token and retry."))]
    InvalidAccessTokenEnvironment,

    #[error("{0} is not valid Unicode")]
    InvalidEnvironmentValue(&'static str),

    #[error("No access token is configured")]
    #[diagnostic(help(
        "Run `s2 auth access-token set` before selecting `s2 auth use access-token`."
    ))]
    StoredAccessTokenNotConfigured,

    #[error("No browser login is configured")]
    #[diagnostic(help("Run `s2 login` before selecting `s2 auth use browser-login`."))]
    BrowserLoginNotConfigured,
}

impl From<config::ConfigError> for CliConfigError {
    fn from(_error: config::ConfigError) -> Self {
        // Parser errors can include source excerpts containing a legacy plaintext token.
        Self::Load
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::browser_login(TokenSource::BrowserLogin, "s2 login")]
    #[case::environment(TokenSource::Environment, "S2_ACCESS_TOKEN")]
    #[case::stored_access_token(TokenSource::StoredAccessToken, "s2 auth access-token set")]
    #[case::config_file(TokenSource::ConfigFile, "s2 auth access-token set")]
    fn token_error_help_matches_token_source(
        #[case] token_source: TokenSource,
        #[case] expected: &str,
    ) {
        let sdk_error = || {
            S2Error::Validation(s2_sdk::error::ValidationError(
                "invalid access token: bad".into(),
            ))
        };
        for error in [
            CliError::UnauthorizedAccessToken(OpKind::ListBasins, sdk_error(), token_source),
            CliError::MalformedAccessToken(sdk_error(), token_source),
        ] {
            let help = error.help().expect("help").to_string();
            assert!(help.contains(expected), "{help}");
            if matches!(token_source, TokenSource::BrowserLogin) {
                assert!(!help.contains("access-token set"), "{help}");
            }
        }
    }

    #[test]
    fn operation_error_report_does_not_duplicate_sdk_error() {
        let sdk_error = S2Error::Validation(s2_sdk::error::ValidationError(
            "stream_not_found: stream 'my-stream' does not exist".into(),
        ));
        let rendered = format!(
            "{:?}",
            miette::Report::new(CliError::Operation(OpKind::Read, sdk_error))
        );
        assert_eq!(rendered.matches("Failed to read").count(), 1, "{rendered}");
        assert_eq!(
            rendered.matches("stream_not_found").count(),
            1,
            "{rendered}"
        );
    }

    #[test]
    fn wrapped_session_and_indefinite_errors_still_classify_server_codes() {
        use s2_sdk::error::{IndefiniteAppendError, SessionClosedError, StatusCode};

        let auth_server =
            ServerError::new(StatusCode::UNAUTHORIZED, "invalid token").with_code("authn");
        let wrapped_auth = S2Error::SessionClosed(SessionClosedError::new(Some(
            S2Error::IndefiniteAppend(IndefiniteAppendError::new(S2Error::Server(auth_server))),
        )));
        assert!(matches!(
            CliError::Operation(OpKind::Append, wrapped_auth)
                .with_token_source(Some(TokenSource::Environment)),
            CliError::UnauthorizedAccessToken(OpKind::Append, _, TokenSource::Environment)
        ));

        let np_server =
            ServerError::new(StatusCode::FORBIDDEN, "denied").with_code("network_policy_denied");
        let wrapped_np =
            S2Error::SessionClosed(SessionClosedError::new(Some(S2Error::Server(np_server))));
        assert!(matches!(
            CliError::Operation(OpKind::Append, wrapped_np)
                .with_token_source(Some(TokenSource::Environment)),
            CliError::NetworkPolicyDenied(OpKind::Append, _)
        ));

        let ni_server = ServerError::new(StatusCode::NOT_IMPLEMENTED, "unsupported")
            .with_code("not_implemented");
        let wrapped_ni =
            S2Error::SessionClosed(SessionClosedError::new(Some(S2Error::Server(ni_server))));
        assert!(matches!(
            CliError::Operation(OpKind::Read, wrapped_ni).with_target(Target::Local),
            CliError::NotImplemented(OpKind::Read, _)
        ));
    }
}
