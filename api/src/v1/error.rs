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
// Keep this alphabetized.
pub enum ErrorCode {
    AccessTokenNotFound,
    BadFrame,
    BadHeader,
    BadJson,
    BadPath,
    BadProto,
    BadQuery,
    BasinDeletionPending,
    BasinNotFound,
    ClientHangup,
    HotServer,
    Invalid,
    Other,
    PermissionDenied,
    QuotaExhausted,
    RateLimited,
    ResourceAlreadyExists,
    Storage,
    StreamDeletionPending,
    StreamNotFound,
    Timeout,
    TransactionConflict,
    Unavailable,
}

impl ErrorCode {
    pub fn status(self) -> http::StatusCode {
        match self {
            Self::BadFrame
            | Self::BadHeader
            | Self::BadJson
            | Self::BadPath
            | Self::BadProto
            | Self::BadQuery => http::StatusCode::BAD_REQUEST,
            Self::Invalid => http::StatusCode::UNPROCESSABLE_ENTITY,
            Self::AccessTokenNotFound | Self::BasinNotFound | Self::StreamNotFound => {
                http::StatusCode::NOT_FOUND
            }
            Self::BasinDeletionPending
            | Self::ResourceAlreadyExists
            | Self::StreamDeletionPending
            | Self::TransactionConflict => http::StatusCode::CONFLICT,
            Self::ClientHangup => http::StatusCode::from_u16(499).expect("valid status code"),
            Self::PermissionDenied | Self::QuotaExhausted => http::StatusCode::FORBIDDEN,
            Self::RateLimited => http::StatusCode::TOO_MANY_REQUESTS,
            Self::HotServer | Self::Unavailable => http::StatusCode::SERVICE_UNAVAILABLE,
            Self::Other | Self::Storage => http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::Timeout => http::StatusCode::REQUEST_TIMEOUT,
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
pub struct GenericError {
    pub status: http::StatusCode,
    pub info: ErrorInfo,
}

#[derive(Debug, Clone)]
pub enum ErrorResponse {
    AppendConditionFailed(super::stream::AppendConditionFailed),
    Unwritten(super::stream::TailResponse),
    Generic(GenericError),
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
            ErrorResponse::Generic(err) => (err.status, serde_json::to_string(&err.info)),
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
