use miette::Diagnostic;
use s2_api::v1::error::ErrorCode;
use s2_sdk::types::S2Error;
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

#[derive(Error, Debug, Diagnostic)]
pub enum CliError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    Config(#[from] CliConfigError),

    #[error("Invalid CLI arguments: {0}")]
    #[diagnostic(transparent)]
    InvalidArgs(miette::Report),

    #[error("Unable to load S2 endpoints from environment: {0}")]
    #[diagnostic(help(
        "Are you overriding `S2_ACCOUNT_ENDPOINT` or `S2_BASIN_ENDPOINT`?
            Make sure the values are in the expected format."
    ))]
    EndpointsFromEnv(String),

    #[error("Failed to initialize S2 SDK")]
    #[diagnostic(help("{}", HELP))]
    SdkInit(#[source] S2Error),

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
    Operation(OpKind, #[source] S2Error),

    #[error("{}: {}", .0, .1)]
    #[diagnostic(help(
        "Verify the token loaded from {2} is valid and has permission for this operation, then retry.\n\
         Update it with `s2 config set access_token <token>` or set `S2_ACCESS_TOKEN`."
    ))]
    OperationWithTokenSource(OpKind, #[source] S2Error, TokenSource),

    #[error("Invalid encryption key: {0}")]
    #[diagnostic(help("Key must be a base64-encoded 32-byte value."))]
    InvalidEncryptionKey(String),

    #[error("S2 Lite server error: {0}")]
    #[diagnostic(help("{}", HELP))]
    LiteServer(String),

    #[error("Apply failed: {0}")]
    #[diagnostic(help("{}", HELP))]
    Apply(String),
}

impl CliError {
    pub fn op(kind: OpKind, source: S2Error) -> Self {
        Self::Operation(kind, source)
    }

    pub fn with_token_source(self, token_source: Option<TokenSource>) -> Self {
        match (self, token_source) {
            (CliError::Operation(kind, source), Some(token_source)) if is_auth_error(&source) => {
                CliError::OperationWithTokenSource(kind, source, token_source)
            }
            (err, _) => err,
        }
    }
}

impl From<S2UriParseError> for CliError {
    fn from(err: S2UriParseError) -> Self {
        Self::InvalidArgs(miette::miette!("{}", err))
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
    ConfigFile,
}

impl std::fmt::Display for TokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenSource::Environment => write!(f, "environment (S2_ACCESS_TOKEN)"),
            TokenSource::ConfigFile => write!(f, "config file"),
        }
    }
}

fn is_auth_error(err: &S2Error) -> bool {
    match err {
        S2Error::Server(response) => is_auth_error_code(&response.code),
        _ => false,
    }
}

fn is_auth_error_code(code: &str) -> bool {
    let Ok(code) = code.parse::<ErrorCode>() else {
        return false;
    };
    matches!(code, ErrorCode::Authn | ErrorCode::Authz)
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
        "Did you run `s2 config set access_token <token>`? or use `S2_ACCESS_TOKEN` environment variable."
    ))]
    Load(#[from] config::ConfigError),

    #[error("Failed to write config file")]
    Write(#[source] std::io::Error),

    #[error("Failed to serialize config")]
    Serialize(#[source] toml::ser::Error),

    #[error("Invalid value '{1}' for config key '{0}'")]
    InvalidValue(String, String),

    #[error("Missing access token")]
    #[diagnostic(help(
        "Run `s2 config set access_token <token>` or set the `S2_ACCESS_TOKEN` environment variable."
    ))]
    MissingAccessToken,
}
