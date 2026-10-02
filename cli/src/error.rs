use miette::Diagnostic;
use s2_sdk::error::{
    AppendError, AppendSessionError, ErrorCode, ProducerError, ReadError, ReadSessionError,
    RequestError, ServerError,
};
use thiserror::Error;

const HELP: &str = color_print::cstr!(
    "\n<cyan><bold>Notice something wrong?</bold></cyan>\n\n\
     <green> > Open an issue:</green>\n\
     <bold>https://github.com/s2-streamstore/s2/issues</bold>\n\n\
     <green> > Reach out to us:</green>\n\
     <bold>hi@s2.dev</bold>"
);

const BUG_HELP: &str = color_print::cstr!(
    "\n<cyan><bold>Looks like you may have encountered a bug!</bold></cyan>\n\n\
     <green> > Report this issue here: </green>\n\
     <bold>https://github.com/s2-streamstore/s2/issues</bold>
"
);

#[derive(Error, Debug)]
pub enum SdkError {
    #[error(transparent)]
    Request(#[from] RequestError),
    #[error(transparent)]
    Read(#[from] ReadError),
    #[error(transparent)]
    Append(#[from] AppendError),
    #[error(transparent)]
    AppendSession(#[from] AppendSessionError),
    #[error(transparent)]
    ReadSession(#[from] ReadSessionError),
    #[error(transparent)]
    Producer(#[from] ProducerError),
}

impl SdkError {
    fn request_error(&self) -> Option<&RequestError> {
        match self {
            Self::Request(error) => Some(error),
            Self::Read(error) => error.request_error(),
            Self::Append(error) => error.request_error(),
            Self::AppendSession(error) => error.request_error(),
            Self::ReadSession(error) => error.request_error(),
            Self::Producer(error) => error.request_error(),
        }
    }

    fn server_error(&self) -> Option<&ServerError> {
        self.request_error().and_then(RequestError::server_error)
    }
}

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
        "Token loaded from {1}. Verify it does not contain invalid characters.\n\
         {2}\n\n{}",
        HELP
    ))]
    MalformedAccessToken(#[source] SdkError, TokenSource, &'static str),

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

    #[error("{}: {}", .0, .1)]
    #[diagnostic(help("{}", HELP))]
    Operation(OpKind, #[source] SdkError),

    #[error("{}: {}", .0, .1)]
    #[diagnostic(help(
        "Verify the token loaded from {2} is valid and has permission for this operation, then retry.\n\
         {3}"
    ))]
    UnauthorizedAccessToken(OpKind, #[source] SdkError, TokenSource, &'static str),

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
            (CliError::Operation(kind, source), Some(token_source)) if is_auth_error(&source) => {
                CliError::UnauthorizedAccessToken(
                    kind,
                    source,
                    token_source,
                    recovery_command(token_source),
                )
            }
            (CliError::SdkInit(source), Some(token_source))
                if is_malformed_access_token(&source) =>
            {
                CliError::MalformedAccessToken(source, token_source, recovery_command(token_source))
            }
            (err, _) => err,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    Environment,
    BrowserLogin,
    StoredAccessToken,
    ConfigFile,
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

/// Recovery guidance specific to the credential `source` that produced the
/// rejected (or malformed) access token.
///
/// This is the single source of truth for source-specific recovery text; it is
/// shared by the operation error path ([`CliError::UnauthorizedAccessToken`] /
/// [`CliError::MalformedAccessToken`]) and by `s2 auth status`.
pub(crate) fn recovery_command(source: TokenSource) -> &'static str {
    match source {
        TokenSource::BrowserLogin => "Run `s2 login` again.",
        TokenSource::Environment => "Set S2_ACCESS_TOKEN to a valid access token.",
        TokenSource::StoredAccessToken | TokenSource::ConfigFile => {
            "Run `s2 auth access-token set` to replace it."
        }
    }
}

fn is_auth_error(err: &SdkError) -> bool {
    err.server_error()
        .and_then(ServerError::known_code)
        .is_some_and(ErrorCode::is_auth_error)
}

fn is_malformed_access_token(err: &SdkError) -> bool {
    matches!(
        err.request_error(),
        Some(RequestError::MalformedAccessToken(_))
    )
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
    use miette::Diagnostic;
    use s2_sdk::error::ClientError;

    use super::*;
    use crate::error::TokenSource;

    /// A constructible [`SdkError`] used as the `#[source]` field of error
    /// variants in these tests. The exact wrapped error does not affect the
    /// recovery-text behavior under test; it only has to type-check as an
    /// `SdkError`. (`RequestError::Server` / `ServerError` cannot be built from
    /// outside the SDK crate because `ServerError` is `#[non_exhaustive]` with no
    /// public constructor, so the auth-error *routing* is verified end-to-end in
    /// integration tests instead.)
    fn placeholder_sdk_error() -> SdkError {
        SdkError::Request(RequestError::Client(ClientError::Timeout))
    }

    fn malformed_sdk_error() -> SdkError {
        SdkError::Request(RequestError::MalformedAccessToken("bad".to_owned()))
    }

    /// The access-token-only recovery string that used to be hardcoded into both
    /// diagnostics regardless of the token source.
    const OLD_HARDCODED: &str =
        "Store one with `s2 auth access-token set`, or set `S2_ACCESS_TOKEN`.";

    #[test]
    fn recovery_command_is_source_specific() {
        assert_eq!(
            recovery_command(TokenSource::BrowserLogin),
            "Run `s2 login` again."
        );
        assert_eq!(
            recovery_command(TokenSource::Environment),
            "Set S2_ACCESS_TOKEN to a valid access token."
        );
        assert_eq!(
            recovery_command(TokenSource::StoredAccessToken),
            "Run `s2 auth access-token set` to replace it."
        );
        assert_eq!(
            recovery_command(TokenSource::ConfigFile),
            "Run `s2 auth access-token set` to replace it."
        );
    }

    #[test]
    fn unauthorized_access_token_help_is_source_aware_for_every_source() {
        for source in [
            TokenSource::BrowserLogin,
            TokenSource::Environment,
            TokenSource::StoredAccessToken,
            TokenSource::ConfigFile,
        ] {
            let err = CliError::UnauthorizedAccessToken(
                OpKind::ListBasins,
                placeholder_sdk_error(),
                source,
                recovery_command(source),
            );

            let help = err
                .help()
                .expect("UnauthorizedAccessToken should render help")
                .to_string();

            // The first sentence must still name the actual token source.
            assert!(
                help.contains(&source.to_string()),
                "help should mention the token source {source}, got: {help}"
            );
            // The second sentence must be the source-specific recovery command.
            assert!(
                help.contains(recovery_command(source)),
                "help should contain the source-specific recovery text, got: {help}"
            );
            // The access-token-only recovery string must never be rendered.
            assert!(
                !help.contains(OLD_HARDCODED),
                "help must not contain the old access-token-only recovery text, got: {help}"
            );

            // Browser login in particular must direct the user to `s2 login`, not
            // to storing/replacing an access token.
            if source == TokenSource::BrowserLogin {
                assert!(
                    help.contains("`s2 login`"),
                    "browser-login help should suggest `s2 login`, got: {help}"
                );
                assert!(
                    !help.contains("s2 auth access-token set") && !help.contains("S2_ACCESS_TOKEN"),
                    "browser-login help must not suggest access-token recovery, got: {help}"
                );
            } else {
                // Access-token-backed sources must keep directing users to an
                // access-token remediation (no regression for those sources).
                assert!(
                    help.contains("access-token") || help.contains("S2_ACCESS_TOKEN"),
                    "access-token-source help should suggest an access-token remediation, got: {help}"
                );
            }
        }
    }

    #[test]
    fn malformed_access_token_upgrade_carries_source_aware_recovery_for_every_source() {
        for source in [
            TokenSource::BrowserLogin,
            TokenSource::Environment,
            TokenSource::StoredAccessToken,
            TokenSource::ConfigFile,
        ] {
            let err = CliError::SdkInit(malformed_sdk_error()).with_token_source(Some(source));

            let recovery = match err {
                CliError::MalformedAccessToken(_, src, rec) => {
                    assert_eq!(src, source, "token source should round-trip for {source:?}");
                    rec
                }
                other => panic!("expected MalformedAccessToken for {source:?}, got {other:?}"),
            };

            // The upgrade must wire in `recovery_command(source)`.
            assert_eq!(recovery, recovery_command(source));

            let help = err
                .help()
                .expect("MalformedAccessToken should render help")
                .to_string();
            assert!(
                help.contains(&source.to_string()),
                "help should mention the token source {source}, got: {help}"
            );
            assert!(
                help.contains(recovery),
                "help should contain the source-specific recovery text, got: {help}"
            );
            assert!(
                !help.contains(OLD_HARDCODED),
                "help must not contain the old access-token-only recovery text, got: {help}"
            );

            if source == TokenSource::BrowserLogin {
                assert!(
                    help.contains("`s2 login`"),
                    "browser-login help should suggest `s2 login`, got: {help}"
                );
            }
        }
    }
}
