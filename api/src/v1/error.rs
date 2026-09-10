use serde::{Deserialize, Serialize};

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
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
// Keep this alphabetized.
pub enum ErrorCode {
    AccessTokenNotFound,
    Authn,
    BadFrame,
    BadHeader,
    BadJson,
    BadPath,
    BadProto,
    BadQuery,
    BasinDeletionPending,
    BasinNotFound,
    ClientHangup,
    DecryptionFailed,
    HotServer,
    Invalid,
    NotImplemented,
    Other,
    PermissionDenied,
    QuotaExhausted,
    RateLimited,
    RequestTimeout,
    ResourceAlreadyExists,
    ServerDraining,
    Storage,
    StreamDeletionPending,
    StreamNotFound,
    TransactionConflict,
    Unavailable,
    UpstreamTimeout,
}

impl ErrorCode {
    /// Whether this code represents an authentication or authorization failure.
    pub fn is_auth_error(self) -> bool {
        matches!(
            self,
            Self::Authn | Self::PermissionDenied | Self::AccessTokenNotFound
        )
    }

    /// HTTP status associated with this error code.
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
            Self::PermissionDenied | Self::QuotaExhausted => http::StatusCode::FORBIDDEN,
            Self::AccessTokenNotFound | Self::BasinNotFound | Self::StreamNotFound => {
                http::StatusCode::NOT_FOUND
            }
            Self::RequestTimeout => http::StatusCode::REQUEST_TIMEOUT,
            Self::BasinDeletionPending
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
            | Self::NotImplemented
            | Self::PermissionDenied
            | Self::QuotaExhausted
            | Self::ResourceAlreadyExists
            | Self::StreamDeletionPending
            | Self::StreamNotFound => false,
        }
    }

    /// Whether the server guarantees that an operation returning this code had no side effects.
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
    pub fn to_parts(&self) -> (http::StatusCode, String) {
        let (status, res) = match self {
            ErrorResponse::AppendConditionFailed(payload) => (
                http::StatusCode::PRECONDITION_FAILED,
                serde_json::to_string(&payload),
            ),
            ErrorResponse::Unwritten(payload) => (
                http::StatusCode::RANGE_NOT_SATISFIABLE,
                serde_json::to_string(&payload),
            ),
            ErrorResponse::Standard(err) => (err.status, serde_json::to_string(&err.info)),
        };
        (status, res.expect("basic json ser"))
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
