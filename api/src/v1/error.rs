use serde::{Deserialize, Serialize};

/// Structured error codes returned by S2 servers in JSON error responses.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::VariantArray,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
// Keep this alphabetized.
pub enum ErrorCode {
    /// The referenced access token does not exist (HTTP 404).
    AccessTokenNotFound,
    /// Authentication failed because the access token is missing, invalid, or expired (HTTP 401).
    Authn,
    /// An S2S session frame was malformed or exceeded wire limits (HTTP 400).
    BadFrame,
    /// A request HTTP header was missing or malformed (HTTP 400).
    BadHeader,
    /// A JSON request body could not be parsed (HTTP 400).
    BadJson,
    /// The request URL path was malformed (HTTP 400).
    BadPath,
    /// A Protobuf request body could not be decoded (HTTP 400).
    BadProto,
    /// A query string parameter was malformed (HTTP 400).
    BadQuery,
    /// The basin is currently being deleted (HTTP 409).
    BasinDeletionPending,
    /// The referenced basin does not exist (HTTP 404).
    BasinNotFound,
    /// The client closed the connection before the server finished handling the request (HTTP 499).
    ClientHangup,
    /// The server could not decrypt the stream with the supplied encryption key (HTTP 400).
    DecryptionFailed,
    /// The server is overloaded and requested the client reconnect elsewhere (HTTP 502).
    HotServer,
    /// The request was syntactically valid but failed semantic validation (HTTP 422).
    Invalid,
    /// The request was blocked by the access token's network policy (HTTP 403).
    NetworkPolicyDenied,
    /// The network policy cannot be deleted while bound to an access token (HTTP 409).
    NetworkPolicyInUse,
    /// The referenced network policy does not exist (HTTP 404).
    NetworkPolicyNotFound,
    /// The requested endpoint or capability is not implemented (HTTP 501).
    NotImplemented,
    /// An unspecified internal server error occurred (HTTP 500).
    Other,
    /// The authenticated access token is not authorized for this operation or resource (HTTP 403).
    PermissionDenied,
    /// An account or resource quota has been exhausted (HTTP 403).
    QuotaExhausted,
    /// The request was throttled due to rate limiting (HTTP 429).
    RateLimited,
    /// The server timed out waiting for the request (HTTP 408).
    RequestTimeout,
    /// A resource with the same identifier already exists (HTTP 409).
    ResourceAlreadyExists,
    /// The server is draining and will not process further requests on this connection (HTTP 503).
    ServerDraining,
    /// An internal storage backend error occurred (HTTP 500).
    Storage,
    /// The stream is currently being deleted (HTTP 409).
    StreamDeletionPending,
    /// The referenced stream does not exist (HTTP 404).
    StreamNotFound,
    /// A concurrent metadata mutation conflicted; retrying may succeed (HTTP 409).
    TransactionConflict,
    /// The service is temporarily unavailable (HTTP 503).
    Unavailable,
    /// An upstream service timed out (HTTP 504).
    UpstreamTimeout,
}

impl ErrorCode {
    #[doc(hidden)]
    pub const ALL: &'static [Self] = <Self as strum::VariantArray>::VARIANTS;

    /// Return the snake_case wire name of this error code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    /// Whether this code represents an authentication, authorization, or missing/restricted token
    /// error (`authn`, `permission_denied`, `access_token_not_found`, or `network_policy_denied`).
    #[must_use]
    pub fn is_auth_error(self) -> bool {
        matches!(
            self,
            Self::Authn
                | Self::PermissionDenied
                | Self::AccessTokenNotFound
                | Self::NetworkPolicyDenied
        )
    }

    /// HTTP status associated with this error code.
    #[must_use]
    pub fn status(self) -> http::StatusCode {
        match self {
            Self::Authn => http::StatusCode::UNAUTHORIZED,
            Self::DecryptionFailed
            | Self::BadFrame
            | Self::BadHeader
            | Self::BadJson
            | Self::BadPath
            | Self::BadProto
            | Self::BadQuery => http::StatusCode::BAD_REQUEST,
            Self::PermissionDenied | Self::QuotaExhausted | Self::NetworkPolicyDenied => {
                http::StatusCode::FORBIDDEN
            }
            Self::AccessTokenNotFound
            | Self::BasinNotFound
            | Self::NetworkPolicyNotFound
            | Self::StreamNotFound => http::StatusCode::NOT_FOUND,
            Self::RequestTimeout => http::StatusCode::REQUEST_TIMEOUT,
            Self::BasinDeletionPending
            | Self::NetworkPolicyInUse
            | Self::ResourceAlreadyExists
            | Self::StreamDeletionPending
            | Self::TransactionConflict => http::StatusCode::CONFLICT,
            Self::Invalid => http::StatusCode::UNPROCESSABLE_ENTITY,
            Self::NotImplemented => http::StatusCode::NOT_IMPLEMENTED,
            Self::RateLimited => http::StatusCode::TOO_MANY_REQUESTS,
            Self::ClientHangup => http::StatusCode::from_u16(499).expect("valid status code"),
            Self::Other | Self::Storage => http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::HotServer => http::StatusCode::BAD_GATEWAY,
            Self::ServerDraining | Self::Unavailable => http::StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamTimeout => http::StatusCode::GATEWAY_TIMEOUT,
        }
    }

    /// Whether retrying an operation that returned this code is sensible.
    #[must_use]
    pub fn is_retryable(self) -> bool {
        match self {
            Self::RequestTimeout
            | Self::TransactionConflict
            | Self::RateLimited
            | Self::Other
            | Self::ServerDraining
            | Self::Storage
            | Self::HotServer
            | Self::Unavailable
            | Self::UpstreamTimeout => true,
            Self::AccessTokenNotFound
            | Self::Authn
            | Self::BadFrame
            | Self::BadHeader
            | Self::BadJson
            | Self::BadPath
            | Self::BadProto
            | Self::BadQuery
            | Self::BasinDeletionPending
            | Self::BasinNotFound
            | Self::ClientHangup
            | Self::DecryptionFailed
            | Self::Invalid
            | Self::NetworkPolicyDenied
            | Self::NetworkPolicyInUse
            | Self::NetworkPolicyNotFound
            | Self::NotImplemented
            | Self::PermissionDenied
            | Self::QuotaExhausted
            | Self::ResourceAlreadyExists
            | Self::StreamDeletionPending
            | Self::StreamNotFound => false,
        }
    }

    /// Whether the server guarantees that an operation returning this code had no side effects.
    #[must_use]
    pub fn has_no_side_effects(self) -> bool {
        match self {
            Self::AccessTokenNotFound
            | Self::Authn
            | Self::BadFrame
            | Self::BadHeader
            | Self::BadJson
            | Self::BadPath
            | Self::BadProto
            | Self::BadQuery
            | Self::BasinDeletionPending
            | Self::BasinNotFound
            | Self::DecryptionFailed
            | Self::HotServer
            | Self::Invalid
            | Self::NetworkPolicyDenied
            | Self::NetworkPolicyInUse
            | Self::NetworkPolicyNotFound
            | Self::NotImplemented
            | Self::PermissionDenied
            | Self::QuotaExhausted
            | Self::RateLimited
            | Self::ResourceAlreadyExists
            | Self::ServerDraining
            | Self::StreamDeletionPending
            | Self::StreamNotFound
            | Self::TransactionConflict => true,
            Self::ClientHangup
            | Self::Other
            | Self::RequestTimeout
            | Self::Storage
            | Self::Unavailable
            | Self::UpstreamTimeout => false,
        }
    }
}

impl AsRef<str> for ErrorCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<ErrorCode> for String {
    fn from(code: ErrorCode) -> Self {
        code.as_str().to_owned()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ErrorInfo {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct StandardError {
    pub status: http::StatusCode,
    pub info: ErrorInfo,
}

#[derive(Debug, Clone)]
pub enum ErrorResponse {
    AppendConditionFailed(super::stream::AppendConditionFailed),
    Unwritten(super::stream::TailResponse),
    Standard(StandardError),
}

impl ErrorResponse {
    pub fn status(&self) -> http::StatusCode {
        match self {
            ErrorResponse::AppendConditionFailed(_) => http::StatusCode::PRECONDITION_FAILED,
            ErrorResponse::Unwritten(_) => http::StatusCode::RANGE_NOT_SATISFIABLE,
            ErrorResponse::Standard(err) => err.status,
        }
    }

    pub fn to_parts(&self) -> (http::StatusCode, String) {
        (
            self.status(),
            serde_json::to_string(self).expect("basic json ser"),
        )
    }
}

/// Serializes as the response body.
impl Serialize for ErrorResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ErrorResponse::AppendConditionFailed(payload) => payload.serialize(serializer),
            ErrorResponse::Unwritten(payload) => payload.serialize(serializer),
            ErrorResponse::Standard(err) => err.info.serialize(serializer),
        }
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        let (status, json_str) = self.to_parts();
        let mut response = (
            [(
                http::header::CONTENT_TYPE,
                http::header::HeaderValue::from_static(mime::APPLICATION_JSON.as_ref()),
            )],
            json_str,
        )
            .into_response();
        *response.status_mut() = status;
        response
    }
}
