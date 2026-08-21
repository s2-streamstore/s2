//! Errors returned by the SDK.
//!
//! Operations return the narrowest error type for their surface. Errors expose classification and
//! accessors relevant to that surface, so callers do not need to inspect display strings or unwrap
//! the complete error hierarchy.

pub use http::StatusCode;
use s2_api::v1 as api;
pub use s2_api::v1::error::ErrorCode;

pub use crate::session::{
    append::AppendSessionError,
    read::{CaughtUpError, ReadSessionError},
};
use crate::{
    api::{ApiError, ServerErrorBody},
    client,
    types::{FencingToken, StreamPosition, ValidationError},
};

/// A classified client-side error.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Failed to establish a connection.
    #[error("connect: {0}")]
    Connect(String),
    /// The request timed out.
    #[error("timeout")]
    Timeout,
    /// The connection closed before the response was complete.
    #[error("connection closed early: {0}")]
    ConnectionClosedEarly(String),
    /// The request was canceled.
    #[error("request canceled: {0}")]
    RequestCanceled(String),
    /// The connection ended unexpectedly.
    #[error("unexpected eof: {0}")]
    UnexpectedEof(String),
    /// The connection was reset.
    #[error("connection reset: {0}")]
    ConnectionReset(String),
    /// The connection was aborted.
    #[error("connection aborted: {0}")]
    ConnectionAborted(String),
    /// The connection was refused.
    #[error("connection refused: {0}")]
    ConnectionRefused(String),
    /// Client configuration prevented a request from being attempted.
    #[error("configuration: {0}")]
    Configuration(String),
    /// The request could not be built or encoded.
    #[error("request build: {0}")]
    RequestBuild(String),
    /// The request body could not be compressed.
    #[error("request compression: {0}")]
    RequestCompression(String),
    /// The response body could not be decompressed.
    #[error("response compression: {0}")]
    ResponseCompression(String),
    /// The response body could not be decoded.
    #[error("response decode: {0}")]
    ResponseDecode(String),
    /// A streaming protocol message could not be decoded.
    #[error("session protocol: {0}")]
    SessionProtocol(String),
    /// An otherwise-unclassified client error.
    #[error("{0}")]
    Other(String),
}

impl ClientError {
    /// Whether retrying the request is safe or sensible.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Connect(_)
                | Self::Timeout
                | Self::ConnectionClosedEarly(_)
                | Self::RequestCanceled(_)
                | Self::UnexpectedEof(_)
                | Self::ConnectionReset(_)
                | Self::ConnectionAborted(_)
                | Self::ConnectionRefused(_)
        )
    }

    /// Whether retrying the request cannot duplicate a mutation.
    pub fn has_no_side_effects(&self) -> bool {
        matches!(
            self,
            Self::Connect(_)
                | Self::ConnectionRefused(_)
                | Self::Configuration(_)
                | Self::RequestBuild(_)
                | Self::RequestCompression(_)
        )
    }
}

impl From<client::HttpError> for ClientError {
    fn from(err: client::HttpError) -> Self {
        let err_msg = err.to_string();
        match err {
            client::HttpError::Send(ref send_err) if send_err.is_connect() => {
                classify_io_source(&err, &err_msg).unwrap_or(Self::Connect(err_msg))
            }
            client::HttpError::Send(_) | client::HttpError::Receive(_) => {
                classify_hyper_source(&err, &err_msg)
                    .or_else(|| classify_io_source(&err, &err_msg))
                    .unwrap_or(Self::Other(err_msg))
            }
            client::HttpError::RequestBuild(message) => Self::RequestBuild(message),
            client::HttpError::RequestCompression(message) => Self::RequestCompression(message),
            client::HttpError::ResponseCompression(message) => Self::ResponseCompression(message),
            client::HttpError::ResponseDecode(error) => Self::ResponseDecode(error.to_string()),
            client::HttpError::Timeout => Self::Timeout,
        }
    }
}

fn classify_hyper_source(err: &client::HttpError, err_msg: &str) -> Option<ClientError> {
    let hyper_err = source_err::<hyper::Error>(err)?;
    let err_msg = format!("{hyper_err} -> {err_msg}");
    if hyper_err.is_incomplete_message() || hyper_err.is_closed() {
        // `is_closed` covers a request dispatched onto a pooled connection
        // that the server had already shut down.
        Some(ClientError::ConnectionClosedEarly(err_msg))
    } else if hyper_err.is_canceled() {
        Some(ClientError::RequestCanceled(err_msg))
    } else {
        None
    }
}

fn classify_io_source(err: &client::HttpError, err_msg: &str) -> Option<ClientError> {
    let io_err = source_err::<std::io::Error>(err)?;
    let err_msg = format!("{io_err} -> {err_msg}");
    Some(match io_err.kind() {
        std::io::ErrorKind::UnexpectedEof => ClientError::UnexpectedEof(err_msg),
        std::io::ErrorKind::ConnectionReset => ClientError::ConnectionReset(err_msg),
        std::io::ErrorKind::ConnectionAborted => ClientError::ConnectionAborted(err_msg),
        std::io::ErrorKind::ConnectionRefused => ClientError::ConnectionRefused(err_msg),
        _ => return None,
    })
}

fn source_err<T: std::error::Error + 'static>(err: &dyn std::error::Error) -> Option<&T> {
    let mut source = err.source();
    while let Some(err) = source {
        if let Some(err) = err.downcast_ref::<T>() {
            return Some(err);
        }
        source = err.source();
    }
    None
}

/// Why an append condition check failed.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AppendConditionFailed {
    /// Fencing token did not match. Contains the expected fencing token.
    #[error("fencing token mismatch, expected: {0}")]
    FencingTokenMismatch(FencingToken),
    /// Sequence number did not match. Contains the expected sequence number.
    #[error("sequence number mismatch, expected: {0}")]
    SeqNumMismatch(u64),
}

impl From<api::stream::AppendConditionFailed> for AppendConditionFailed {
    fn from(value: api::stream::AppendConditionFailed) -> Self {
        match value {
            api::stream::AppendConditionFailed::FencingTokenMismatch(token) => {
                Self::FencingTokenMismatch(FencingToken::from_server(token.to_string()))
            }
            api::stream::AppendConditionFailed::SeqNumMismatch(seq) => Self::SeqNumMismatch(seq),
        }
    }
}

/// Errors that can be returned by any network request.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError {
    /// A client-side error.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// An error returned by the server.
    #[error(transparent)]
    Server(#[from] ServerError),
    /// The access token could not be used as an HTTP header value.
    #[error("malformed access token: {0}")]
    MalformedAccessToken(String),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(crate::types::AccessTokenProviderError),
    /// Input validation failed.
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

impl RequestError {
    /// Whether retrying the operation is safe or sensible.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Client(error) => error.is_retryable(),
            Self::Server(error) => error.is_retryable(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(error) => error.is_retryable(),
            Self::MalformedAccessToken(_) | Self::Validation(_) => false,
        }
    }

    /// Whether retrying the operation cannot duplicate a mutation.
    pub fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Client(error) => error.has_no_side_effects(),
            Self::Server(error) => error.has_no_side_effects(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(_) => true,
            Self::MalformedAccessToken(_) | Self::Validation(_) => true,
        }
    }

    /// Return the server error, if present.
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(error) => Some(error),
            _ => None,
        }
    }

    pub(crate) fn is_authentication_error(&self) -> bool {
        matches!(
            self,
            Self::Server(error)
                if error.status == StatusCode::UNAUTHORIZED && error.code == "authn"
        )
    }
}

impl From<ApiError> for RequestError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::Client(error) => Self::Client(error),
            ApiError::ProtoDecode(error) => {
                Self::Client(ClientError::ResponseDecode(error.to_string()))
            }
            ApiError::TerminalDecode(error) => {
                Self::Client(ClientError::SessionProtocol(error.to_string()))
            }
            ApiError::MalformedAccessToken(error) => Self::MalformedAccessToken(error),
            #[cfg(feature = "_hidden")]
            ApiError::AccessTokenProvider(error) => Self::AccessTokenProvider(error),
            ApiError::Compression(error) => {
                Self::Client(ClientError::ResponseCompression(error.to_string()))
            }
            ApiError::Server(status, response) => {
                Self::Server(ServerError::from_api(status, response))
            }
            other => Self::Client(ClientError::Other(other.to_string())),
        }
    }
}

/// Errors returned by unary read operations.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// A network request error.
    #[error(transparent)]
    Request(#[from] RequestError),
    /// The requested position has not been written.
    #[error("read from an unwritten position. current tail: {0}")]
    ReadUnwritten(StreamPosition),
}

impl ReadError {
    /// Whether retrying the operation is safe or sensible.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Request(error) if error.is_retryable())
    }

    /// Return the underlying request error, if present.
    pub fn request_error(&self) -> Option<&RequestError> {
        match self {
            Self::Request(error) => Some(error),
            Self::ReadUnwritten(_) => None,
        }
    }
}

impl From<ApiError> for ReadError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::ReadUnwritten(tail) => Self::ReadUnwritten(tail.tail.into()),
            other => Self::Request(other.into()),
        }
    }
}

/// Errors returned by unary append operations.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AppendError {
    /// A network request error.
    #[error(transparent)]
    Request(#[from] RequestError),
    /// The append condition did not match.
    #[error(transparent)]
    ConditionFailed(#[from] AppendConditionFailed),
}

impl AppendError {
    /// Whether retrying the operation is safe or sensible.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Request(error) if error.is_retryable())
    }

    /// Whether retrying the operation cannot duplicate a mutation.
    pub fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Request(error) => error.has_no_side_effects(),
            Self::ConditionFailed(_) => true,
        }
    }

    /// Return the underlying request error, if present.
    pub fn request_error(&self) -> Option<&RequestError> {
        match self {
            Self::Request(error) => Some(error),
            Self::ConditionFailed(_) => None,
        }
    }
}

impl From<ApiError> for AppendError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::AppendConditionFailed(condition) => Self::ConditionFailed(condition.into()),
            other => Self::Request(other.into()),
        }
    }
}

/// Errors from producer operations.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ProducerError {
    /// An append-session error encountered while producing records.
    #[error(transparent)]
    Append(#[from] AppendSessionError),
    /// Producer input validation failed before an append was attempted.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// The producer was already closed.
    #[error("producer already closed")]
    ProducerClosed,
    /// The producer is closing.
    #[error("producer is closing")]
    ProducerClosing,
    /// The producer was dropped without being closed.
    #[error("producer dropped without calling close")]
    ProducerDropped,
}

impl ProducerError {
    /// Whether retrying the operation is safe or sensible.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Append(error) => error.is_retryable(),
            Self::Validation(_)
            | Self::ProducerClosed
            | Self::ProducerClosing
            | Self::ProducerDropped => false,
        }
    }

    /// Whether retrying the operation cannot duplicate a mutation.
    pub fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Append(error) => error.has_no_side_effects(),
            Self::Validation(_) | Self::ProducerClosed | Self::ProducerClosing => true,
            Self::ProducerDropped => false,
        }
    }

    /// Return the underlying request error, if present.
    pub fn request_error(&self) -> Option<&RequestError> {
        match self {
            Self::Append(error) => error.request_error(),
            Self::Validation(_)
            | Self::ProducerClosed
            | Self::ProducerClosing
            | Self::ProducerDropped => None,
        }
    }
}

/// An error returned by an S2 server.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code}: {message}")]
#[non_exhaustive]
pub struct ServerError {
    /// HTTP status returned by the server.
    pub status: StatusCode,
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
}

impl ServerError {
    pub(crate) fn from_api(status: StatusCode, response: ServerErrorBody) -> Self {
        Self {
            status,
            code: response.code,
            message: response.message,
        }
    }

    /// Return the server error code when it is recognized by this SDK version.
    ///
    /// The raw [`code`](Self::code) remains available so callers can preserve and report codes
    /// introduced by newer servers.
    pub fn known_code(&self) -> Option<ErrorCode> {
        self.code.parse().ok()
    }

    /// Whether retrying the request is safe or sensible for this server error.
    pub fn is_retryable(&self) -> bool {
        server_error_is_retryable(self.status, &self.code)
    }

    /// Whether retrying the request cannot duplicate a mutation.
    pub fn has_no_side_effects(&self) -> bool {
        server_error_has_no_side_effects(self.status, &self.code)
    }
}

pub(crate) fn server_error_is_retryable(status: StatusCode, code: &str) -> bool {
    match code.parse::<ErrorCode>() {
        Ok(code) if code.status() == status => code.is_retryable(),
        Ok(_) => false,
        Err(_) => matches!(
            status,
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::INTERNAL_SERVER_ERROR
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        ),
    }
}

pub(crate) fn server_error_has_no_side_effects(status: StatusCode, code: &str) -> bool {
    code.parse::<ErrorCode>()
        .is_ok_and(|code| code.status() == status && code.has_no_side_effects())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: StatusCode, code: &str) -> ServerError {
        ServerError::from_api(
            status,
            ServerErrorBody {
                code: code.to_owned(),
                message: "test".to_owned(),
            },
        )
    }

    #[test]
    fn error_response_preserves_raw_and_known_codes() {
        let known = response(StatusCode::NOT_FOUND, "basin_not_found");
        assert_eq!(known.code, "basin_not_found");
        assert_eq!(known.message, "test");
        assert_eq!(known.known_code(), Some(ErrorCode::BasinNotFound));
        assert!(known.to_string().contains("basin_not_found"));

        let unknown = response(StatusCode::BAD_REQUEST, "introduced_by_a_newer_server");
        assert_eq!(unknown.known_code(), None);
        assert_eq!(unknown.code, "introduced_by_a_newer_server");
    }

    #[test]
    fn server_classification_fails_closed_on_status_mismatch() {
        let mismatch = response(StatusCode::INTERNAL_SERVER_ERROR, "rate_limited");
        assert!(!mismatch.is_retryable());
        assert!(!mismatch.has_no_side_effects());
    }

    #[test]
    fn unknown_codes_retain_retryable_status_fallback() {
        let unknown = response(StatusCode::SERVICE_UNAVAILABLE, "future_server_error");
        assert!(unknown.is_retryable());
        assert!(!unknown.has_no_side_effects());
    }

    #[test]
    fn internal_client_errors_preserve_the_failure_stage() {
        assert!(matches!(
            ClientError::from(client::HttpError::RequestBuild("bad request".to_owned())),
            ClientError::RequestBuild(message) if message == "bad request"
        ));
        assert!(matches!(
            ClientError::from(client::HttpError::RequestCompression("encode".to_owned())),
            ClientError::RequestCompression(message) if message == "encode"
        ));
        assert!(matches!(
            ClientError::from(client::HttpError::ResponseCompression("decode".to_owned())),
            ClientError::ResponseCompression(message) if message == "decode"
        ));

        let json_error = serde_json::from_slice::<serde_json::Value>(b"{")
            .expect_err("invalid JSON should fail");
        assert!(matches!(
            ClientError::from(client::HttpError::ResponseDecode(json_error)),
            ClientError::ResponseDecode(_)
        ));
    }

    #[test]
    fn nested_errors_expose_request_and_server_errors() {
        let append = AppendError::Request(RequestError::Server(response(
            StatusCode::CONFLICT,
            "transaction_conflict",
        )));

        assert!(append.is_retryable());
        assert!(append.has_no_side_effects());
        let request = append.request_error().expect("request error");
        assert!(matches!(request, RequestError::Server(_)));
        let server = request.server_error().expect("server error");
        assert_eq!(server.known_code(), Some(ErrorCode::TransactionConflict));
    }
}
