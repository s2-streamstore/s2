//! Errors returned by the SDK.
//!
//! Every operation returns the narrowest error enum for its surface ([`RequestError`],
//! [`ReadError`], [`AppendError`], [`AppendSessionError`], or [`ReadSessionError`]), and every
//! operation error converts into the catch-all [`S2Error`] base type.
//!
//! Every error exposes [`is_retryable`](S2Error::is_retryable) (whether repeating the operation may
//! succeed) and [`has_no_side_effects`](S2Error::has_no_side_effects) (whether the failed attempt
//! certainly had no side effects).

use std::{fmt, sync::Arc};

pub use http::StatusCode;
pub use s2_api::v1::error::ErrorCode;
pub use s2_common::ValidationError;

use crate::{
    api::{ApiError, ServerErrorBody},
    client,
    retry::AppendRetryError,
    types::{FencingToken, StreamPosition},
};

/// Context attached to SDK errors for diagnostic display (`E7`) and read-only classification.
///
/// Stored behind an `Option<Arc<...>>` so error values stay compact on the stack and `Clone` is
/// O(1) without heap allocation on the default path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ErrorContext(Option<Arc<ErrorContextInner>>);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ErrorContextInner {
    operation: Option<&'static str>,
    basin: Option<String>,
    stream: Option<String>,
    attempts: u32,
    read_only: bool,
}

impl ErrorContext {
    pub(crate) fn account(operation: &'static str, read_only: bool) -> Self {
        Self(Some(Arc::new(ErrorContextInner {
            operation: Some(operation),
            basin: None,
            stream: None,
            attempts: 1,
            read_only,
        })))
    }

    pub(crate) fn basin(
        operation: &'static str,
        basin: impl Into<String>,
        read_only: bool,
    ) -> Self {
        Self(Some(Arc::new(ErrorContextInner {
            operation: Some(operation),
            basin: Some(basin.into()),
            stream: None,
            attempts: 1,
            read_only,
        })))
    }

    pub(crate) fn stream(
        operation: &'static str,
        basin: impl Into<String>,
        stream: impl Into<String>,
        read_only: bool,
    ) -> Self {
        Self(Some(Arc::new(ErrorContextInner {
            operation: Some(operation),
            basin: Some(basin.into()),
            stream: Some(stream.into()),
            attempts: 1,
            read_only,
        })))
    }

    fn inner_mut(&mut self) -> &mut ErrorContextInner {
        Arc::make_mut(
            self.0
                .get_or_insert_with(|| Arc::new(ErrorContextInner::default())),
        )
    }

    pub(crate) fn is_read_only(&self) -> bool {
        self.0.as_ref().is_some_and(|inner| inner.read_only)
    }

    pub(crate) fn set_read_only(&mut self) {
        if !self.is_read_only() {
            self.inner_mut().read_only = true;
        }
    }

    pub(crate) fn with_attempts(mut self, attempts: u32) -> Self {
        self.inner_mut().attempts = attempts;
        self
    }

    pub(crate) fn into_read_only(mut self) -> Self {
        self.set_read_only();
        self
    }

    pub(crate) fn merge_missing(&mut self, other: &ErrorContext) {
        let Some(other_inner) = other.0.as_deref() else {
            return;
        };
        if self.0.is_none() {
            self.0 = other.0.clone();
            return;
        }
        let inner = self.inner_mut();
        if inner.operation.is_none() {
            inner.operation = other_inner.operation;
        }
        if inner.basin.is_none() {
            inner.basin.clone_from(&other_inner.basin);
        }
        if inner.stream.is_none() {
            inner.stream.clone_from(&other_inner.stream);
        }
        if inner.attempts <= 1 && other_inner.attempts > 1 {
            inner.attempts = other_inner.attempts;
        }
        inner.read_only = inner.read_only || other_inner.read_only;
    }

    pub(crate) fn format_with(
        &self,
        f: &mut fmt::Formatter<'_>,
        detail: impl fmt::Display,
    ) -> fmt::Result {
        if let Some(inner) = self.0.as_deref()
            && let Some(op) = inner.operation
        {
            write!(f, "{op}")?;
            match (&inner.basin, &inner.stream) {
                (Some(basin), Some(stream)) => write!(f, " (basin={basin}, stream={stream})")?,
                (Some(basin), None) => write!(f, " (basin={basin})")?,
                (None, Some(stream)) => write!(f, " (stream={stream})")?,
                (None, None) => {}
            }
            if inner.attempts > 1 {
                write!(f, " after {} attempts", inner.attempts)?;
            }
            write!(f, ": {detail}")
        } else {
            write!(f, "{detail}")
        }
    }

    pub(crate) fn format_string(&self, detail: &str) -> String {
        struct Wrapper<'a>(&'a ErrorContext, &'a str);
        impl fmt::Display for Wrapper<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.format_with(f, self.1)
            }
        }
        Wrapper(self, detail).to_string()
    }
}

/// An error returned by an S2 server (or any non-2xx HTTP response).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServerError {
    /// HTTP status returned by the server.
    pub status: StatusCode,
    /// Structured server error code, when present in the JSON error response.
    pub code: Option<String>,
    /// Verbatim error message from the response body, or the decimal HTTP status if empty or
    /// unreadable.
    pub message: String,
    pub(crate) context: ErrorContext,
}

impl ServerError {
    pub(crate) fn from_response(status: StatusCode, body: &[u8], context: ErrorContext) -> Self {
        if let Ok(parsed) = serde_json::from_slice::<ServerErrorBody>(body) {
            return Self {
                status,
                code: Some(parsed.code),
                message: parsed.message,
                context,
            };
        }
        let message = match std::str::from_utf8(body) {
            Ok(text) if !text.is_empty() => text.to_owned(),
            _ => status.as_u16().to_string(),
        };
        Self {
            status,
            code: None,
            message,
            context,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        status: StatusCode,
        code: Option<&str>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code: code.map(str::to_owned),
            message: message.into(),
            context: ErrorContext::default(),
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.context.merge_missing(context);
        self
    }

    pub(crate) fn into_read_only(mut self) -> Self {
        self.context.set_read_only();
        self
    }

    /// Return the server error code when it is recognized by this SDK version.
    ///
    /// The raw [`code`](Self::code) remains available so callers can preserve and report codes
    /// introduced by newer servers.
    pub fn known_code(&self) -> Option<ErrorCode> {
        self.code.as_deref().and_then(|c| c.parse().ok())
    }

    /// Whether retrying the request may succeed.
    pub fn is_retryable(&self) -> bool {
        server_error_is_retryable(self.status, self.code.as_deref())
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        self.context.is_read_only()
            || server_error_has_no_side_effects(self.status, self.code.as_deref())
    }

    pub(crate) fn is_authentication_error(&self) -> bool {
        self.status == StatusCode::UNAUTHORIZED && self.code.as_deref() == Some("authn")
    }

    pub(crate) fn is_server_draining(&self) -> bool {
        self.status == StatusCode::SERVICE_UNAVAILABLE
            && self.code.as_deref() == Some("server_draining")
    }

    pub(crate) fn is_hot_server(&self) -> bool {
        self.status == StatusCode::BAD_GATEWAY && self.code.as_deref() == Some("hot_server")
    }

    pub(crate) fn should_retire_connection(&self) -> bool {
        self.is_server_draining() || self.is_hot_server()
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Detail<'a>(&'a ServerError);
        impl fmt::Display for Detail<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0.code.as_deref() {
                    Some(code) => write!(
                        f,
                        "{code} (HTTP {}): {}",
                        self.0.status.as_u16(),
                        self.0.message
                    ),
                    None if self.0.message == self.0.status.as_u16().to_string() => {
                        write!(f, "HTTP {}", self.0.status.as_u16())
                    }
                    None => write!(f, "HTTP {}: {}", self.0.status.as_u16(), self.0.message),
                }
            }
        }
        self.context.format_with(f, Detail(self))
    }
}

impl std::error::Error for ServerError {}

/// A `412` append error indicating that `match_seq_num` did not match the stream's next sequence
/// number.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SeqNumMismatchError {
    /// The sequence number the stream will assign next.
    pub assignable_seq_num: u64,
    /// Underlying HTTP `412` server error.
    pub server: ServerError,
}

impl SeqNumMismatchError {
    pub(crate) fn new(assignable_seq_num: u64, server: ServerError) -> Self {
        Self {
            assignable_seq_num,
            server,
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.server = self.server.with_context(context);
        self
    }

    /// Return the underlying [`ServerError`].
    pub fn server_error(&self) -> &ServerError {
        &self.server
    }

    /// Whether retrying the request may succeed (always `false`).
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects (always `true`).
    pub fn has_no_side_effects(&self) -> bool {
        true
    }
}

impl fmt::Display for SeqNumMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.server.context.format_with(
            f,
            format_args!(
                "sequence number mismatch (assignable_seq_num={})",
                self.assignable_seq_num
            ),
        )
    }
}

impl std::error::Error for SeqNumMismatchError {}

/// A `412` append error indicating that `fencing_token` did not match the stream's current fencing
/// token.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FencingTokenMismatchError {
    /// The stream's current fencing token.
    pub current_fencing_token: FencingToken,
    /// Underlying HTTP `412` server error.
    pub server: ServerError,
}

impl FencingTokenMismatchError {
    pub(crate) fn new(current_fencing_token: FencingToken, server: ServerError) -> Self {
        Self {
            current_fencing_token,
            server,
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.server = self.server.with_context(context);
        self
    }

    /// Return the underlying [`ServerError`].
    pub fn server_error(&self) -> &ServerError {
        &self.server
    }

    /// Whether retrying the request may succeed (always `false`).
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects (always `true`).
    pub fn has_no_side_effects(&self) -> bool {
        true
    }
}

impl fmt::Display for FencingTokenMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.server.context.format_with(
            f,
            format_args!(
                "fencing token mismatch (current_fencing_token={:?})",
                &*self.current_fencing_token
            ),
        )
    }
}

impl std::error::Error for FencingTokenMismatchError {}

/// A `416` read error indicating that the requested position has not been written.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReadUnwrittenError {
    /// The stream's current tail position.
    pub tail: StreamPosition,
    /// Underlying HTTP `416` server error.
    pub server: ServerError,
}

impl ReadUnwrittenError {
    pub(crate) fn new(tail: StreamPosition, server: ServerError) -> Self {
        Self {
            tail,
            server: server.into_read_only(),
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.server = self.server.with_context(context).into_read_only();
        self
    }

    /// Return the underlying [`ServerError`].
    pub fn server_error(&self) -> &ServerError {
        &self.server
    }

    /// Whether retrying the request may succeed (always `false`).
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects (always `true`).
    pub fn has_no_side_effects(&self) -> bool {
        true
    }
}

impl fmt::Display for ReadUnwrittenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.server.context.format_with(
            f,
            format_args!("read from unwritten position (tail={})", self.tail),
        )
    }
}

impl std::error::Error for ReadUnwrittenError {}

/// Failed to establish a connection, or `connection_timeout` elapsed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectError {
    /// Diagnostic detail describing the connection failure.
    pub message: String,
    pub(crate) context: ErrorContext,
}

impl ConnectError {
    pub(crate) fn new(message: impl Into<String>, context: ErrorContext) -> Self {
        Self {
            message: message.into(),
            context,
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.context.merge_missing(context);
        self
    }

    pub(crate) fn into_read_only(mut self) -> Self {
        self.context.set_read_only();
        self
    }

    /// Whether retrying the request may succeed (always `true`).
    pub fn is_retryable(&self) -> bool {
        true
    }

    /// Whether the failed attempt certainly had no side effects (always `true`).
    pub fn has_no_side_effects(&self) -> bool {
        true
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.context
            .format_with(f, format_args!("connect: {}", self.message))
    }
}

impl std::error::Error for ConnectError {}

/// A request or connection broke, or a response ended prematurely.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectionLostError {
    /// Diagnostic detail describing the transport failure.
    pub message: String,
    pub(crate) no_side_effects: bool,
    pub(crate) context: ErrorContext,
}

impl ConnectionLostError {
    pub(crate) fn new(
        message: impl Into<String>,
        no_side_effects: bool,
        context: ErrorContext,
    ) -> Self {
        Self {
            message: message.into(),
            no_side_effects,
            context,
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.context.merge_missing(context);
        self
    }

    pub(crate) fn with_no_side_effects(mut self, no_side_effects: bool) -> Self {
        self.no_side_effects = self.no_side_effects || no_side_effects;
        self
    }

    pub(crate) fn into_read_only(mut self) -> Self {
        self.context.set_read_only();
        self
    }

    /// Whether retrying the request may succeed (always `true`).
    pub fn is_retryable(&self) -> bool {
        true
    }

    /// Whether the failed attempt certainly had no side effects.
    ///
    /// True for read-only operations, when nothing unacked was sent before the connection broke,
    /// or when the server reported the stream unprocessed (such as HTTP/2 `REFUSED_STREAM`).
    pub fn has_no_side_effects(&self) -> bool {
        self.no_side_effects || self.context.is_read_only()
    }
}

impl fmt::Display for ConnectionLostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.context
            .format_with(f, format_args!("connection lost: {}", self.message))
    }
}

impl std::error::Error for ConnectionLostError {}

/// A request, acknowledgement, or read-session heartbeat timed out.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TimeoutError {
    /// Diagnostic detail identifying which timer expired.
    pub message: String,
    pub(crate) context: ErrorContext,
}

impl TimeoutError {
    pub(crate) fn new(message: impl Into<String>, context: ErrorContext) -> Self {
        Self {
            message: message.into(),
            context,
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.context.merge_missing(context);
        self
    }

    pub(crate) fn into_read_only(mut self) -> Self {
        self.context.set_read_only();
        self
    }

    /// Whether retrying the request may succeed (always `true`).
    pub fn is_retryable(&self) -> bool {
        true
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        self.context.is_read_only()
    }
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.context
            .format_with(f, format_args!("timeout: {}", self.message))
    }
}

impl std::error::Error for TimeoutError {}

/// A successful response or session message could not be decoded or violated an SDK check.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProtocolError {
    /// Diagnostic detail describing the protocol failure.
    pub message: String,
    pub(crate) context: ErrorContext,
}

impl ProtocolError {
    pub(crate) fn new(message: impl Into<String>, context: ErrorContext) -> Self {
        Self {
            message: message.into(),
            context,
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.context.merge_missing(context);
        self
    }

    pub(crate) fn into_read_only(mut self) -> Self {
        self.context.set_read_only();
        self
    }

    /// Whether retrying the request may succeed (always `false`).
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        self.context.is_read_only()
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.context
            .format_with(f, format_args!("protocol: {}", self.message))
    }
}

impl std::error::Error for ProtocolError {}

/// A call was made on a client after `close()`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientClosedError {
    pub(crate) context: ErrorContext,
}

impl ClientClosedError {
    pub(crate) fn new(context: ErrorContext) -> Self {
        Self { context }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.context.merge_missing(context);
        self
    }

    /// Whether retrying the request may succeed (always `false`).
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects (always `true`).
    pub fn has_no_side_effects(&self) -> bool {
        true
    }
}

impl fmt::Display for ClientClosedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.context.format_with(f, "client is closed")
    }
}

impl std::error::Error for ClientClosedError {}

/// A session was aborted, a call was canceled, or a unary call was in flight when the client
/// closed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AbortedError {
    /// Diagnostic detail describing why the operation was aborted.
    pub message: String,
    pub(crate) context: ErrorContext,
}

impl AbortedError {
    pub(crate) fn new(message: impl Into<String>, context: ErrorContext) -> Self {
        Self {
            message: message.into(),
            context,
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.context.merge_missing(context);
        self
    }

    pub(crate) fn into_read_only(mut self) -> Self {
        self.context.set_read_only();
        self
    }

    /// Whether retrying the request may succeed (always `false`).
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        self.context.is_read_only()
    }
}

impl fmt::Display for AbortedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.context
            .format_with(f, format_args!("aborted: {}", self.message))
    }
}

impl std::error::Error for AbortedError {}

/// A definite final error on an append followed an earlier attempt that may have taken effect,
/// making the overall append indeterminate.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IndefiniteAppendError<E> {
    /// The definite error returned by the final attempt.
    pub final_attempt_error: Box<E>,
}

impl<E> IndefiniteAppendError<E> {
    pub(crate) fn new(final_attempt_error: E) -> Self {
        Self {
            final_attempt_error: Box::new(final_attempt_error),
        }
    }

    /// Return the definite error returned by the final attempt.
    pub fn final_attempt_error(&self) -> &E {
        &self.final_attempt_error
    }

    /// Whether the append certainly had no side effects (always `false`).
    pub fn has_no_side_effects(&self) -> bool {
        false
    }

    pub(crate) fn map<U>(self, f: impl FnOnce(E) -> U) -> IndefiniteAppendError<U> {
        IndefiniteAppendError {
            final_attempt_error: Box::new(f(*self.final_attempt_error)),
        }
    }
}

impl IndefiniteAppendError<AppendError> {
    /// Whether retrying the underlying error may succeed.
    pub fn is_retryable(&self) -> bool {
        self.final_attempt_error.is_retryable()
    }
}

impl IndefiniteAppendError<AppendSessionError> {
    /// Whether retrying the underlying error may succeed.
    pub fn is_retryable(&self) -> bool {
        self.final_attempt_error.is_retryable()
    }
}

impl IndefiniteAppendError<S2Error> {
    /// Whether retrying the underlying error may succeed.
    pub fn is_retryable(&self) -> bool {
        self.final_attempt_error.is_retryable()
    }
}

impl<E: fmt::Display> fmt::Display for IndefiniteAppendError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "append may have taken effect in an earlier attempt; final attempt failed: {}",
            self.final_attempt_error
        )
    }
}

impl<E: std::error::Error + 'static> std::error::Error for IndefiniteAppendError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.final_attempt_error.as_ref())
    }
}

/// A session closed or began closing before handling the requested operation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionClosedError<E> {
    /// The session's failure, if it closed due to an error.
    pub failure: Option<Box<E>>,
    pub(crate) context: ErrorContext,
}

impl<E> SessionClosedError<E> {
    pub(crate) fn new(failure: Option<E>, context: ErrorContext) -> Self {
        Self {
            failure: failure.map(Box::new),
            context,
        }
    }

    /// Return the session's failure, if it closed due to an error.
    pub fn failure(&self) -> Option<&E> {
        self.failure.as_deref()
    }

    /// Whether retrying the operation on this closed session may succeed (always `false`).
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the rejected call certainly had no side effects (always `true`).
    pub fn has_no_side_effects(&self) -> bool {
        true
    }

    pub(crate) fn map<U>(self, f: impl FnOnce(E) -> U) -> SessionClosedError<U> {
        SessionClosedError {
            failure: self.failure.map(|e| Box::new(f(*e))),
            context: self.context,
        }
    }
}

impl<E: fmt::Display> fmt::Display for SessionClosedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.failure {
            Some(failure) => self
                .context
                .format_with(f, format_args!("session closed: {failure}")),
            None => self.context.format_with(f, "session closed"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SessionClosedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

/// Base error type that every SDK operation error converts into.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum S2Error {
    /// A non-2xx HTTP response from the server.
    #[error(transparent)]
    Server(#[from] ServerError),
    /// Append `match_seq_num` did not match the stream's next sequence number.
    #[error(transparent)]
    SeqNumMismatch(#[from] SeqNumMismatchError),
    /// Append `fencing_token` did not match the stream's current fencing token.
    #[error(transparent)]
    FencingTokenMismatch(#[from] FencingTokenMismatchError),
    /// The requested read position has not been written.
    #[error(transparent)]
    ReadUnwritten(#[from] ReadUnwrittenError),
    /// A definite final error on an append followed an earlier attempt that may have taken effect.
    #[error(transparent)]
    IndefiniteAppend(#[from] IndefiniteAppendError<Self>),
    /// The session closed or began closing before handling the call.
    #[error(transparent)]
    SessionClosed(#[from] SessionClosedError<Self>),
    /// Input or configuration validation failed.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Failed to establish a connection or `connection_timeout` elapsed.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// A request or connection broke, or a response ended prematurely.
    #[error(transparent)]
    ConnectionLost(#[from] ConnectionLostError),
    /// A request, acknowledgement, or heartbeat timed out.
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    /// A successful response or session message violated protocol checks.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// A call was made on a closed client.
    #[error(transparent)]
    ClientClosed(#[from] ClientClosedError),
    /// A session or in-flight call was aborted.
    #[error(transparent)]
    Aborted(#[from] AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(crate::types::AccessTokenProviderError),
}

impl S2Error {
    /// Whether retrying the operation may succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Server(e) => e.is_retryable(),
            Self::SeqNumMismatch(e) => e.is_retryable(),
            Self::FencingTokenMismatch(e) => e.is_retryable(),
            Self::ReadUnwritten(e) => e.is_retryable(),
            Self::IndefiniteAppend(e) => e.is_retryable(),
            Self::SessionClosed(e) => e.is_retryable(),
            Self::Validation(_) => false,
            Self::Connect(e) => e.is_retryable(),
            Self::ConnectionLost(e) => e.is_retryable(),
            Self::Timeout(e) => e.is_retryable(),
            Self::Protocol(e) => e.is_retryable(),
            Self::ClientClosed(e) => e.is_retryable(),
            Self::Aborted(e) => e.is_retryable(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => e.is_retryable(),
        }
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Server(e) => e.has_no_side_effects(),
            Self::SeqNumMismatch(e) => e.has_no_side_effects(),
            Self::FencingTokenMismatch(e) => e.has_no_side_effects(),
            Self::ReadUnwritten(e) => e.has_no_side_effects(),
            Self::IndefiniteAppend(e) => e.has_no_side_effects(),
            Self::SessionClosed(e) => e.has_no_side_effects(),
            Self::Validation(_) => true,
            Self::Connect(e) => e.has_no_side_effects(),
            Self::ConnectionLost(e) => e.has_no_side_effects(),
            Self::Timeout(e) => e.has_no_side_effects(),
            Self::Protocol(e) => e.has_no_side_effects(),
            Self::ClientClosed(e) => e.has_no_side_effects(),
            Self::Aborted(e) => e.has_no_side_effects(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(_) => true,
        }
    }

    /// Return the underlying [`ServerError`] when this error is a direct server error
    /// (including typed `412` and `416` responses).
    ///
    /// Wrapper errors ([`IndefiniteAppend`](Self::IndefiniteAppend) and
    /// [`SessionClosed`](Self::SessionClosed)) return `None`; inspect
    /// [`final_attempt_error`](Self::final_attempt_error) or [`failure`](Self::failure) instead.
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            Self::SeqNumMismatch(e) => Some(&e.server),
            Self::FencingTokenMismatch(e) => Some(&e.server),
            Self::ReadUnwritten(e) => Some(&e.server),
            _ => None,
        }
    }

    /// Return the final attempt's error if this is [`IndefiniteAppend`](Self::IndefiniteAppend).
    pub fn final_attempt_error(&self) -> Option<&Self> {
        match self {
            Self::IndefiniteAppend(e) => Some(e.final_attempt_error()),
            _ => None,
        }
    }

    /// Return the session failure if this is [`SessionClosed`](Self::SessionClosed).
    pub fn failure(&self) -> Option<&Self> {
        match self {
            Self::SessionClosed(e) => e.failure(),
            _ => None,
        }
    }
}

/// Errors returned by account, basin, stream-management, and metrics operations, as well as client
/// construction.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError {
    /// A non-2xx HTTP response from the server.
    #[error(transparent)]
    Server(#[from] ServerError),
    /// Input or configuration validation failed.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Failed to establish a connection or `connection_timeout` elapsed.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// A request or connection broke, or a response ended prematurely.
    #[error(transparent)]
    ConnectionLost(#[from] ConnectionLostError),
    /// The request timed out.
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    /// A successful response violated protocol checks.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// A call was made on a closed client.
    #[error(transparent)]
    ClientClosed(#[from] ClientClosedError),
    /// An in-flight request was aborted.
    #[error(transparent)]
    Aborted(#[from] AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(crate::types::AccessTokenProviderError),
}

impl RequestError {
    /// Whether retrying the operation may succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Server(e) => e.is_retryable(),
            Self::Validation(_) => false,
            Self::Connect(e) => e.is_retryable(),
            Self::ConnectionLost(e) => e.is_retryable(),
            Self::Timeout(e) => e.is_retryable(),
            Self::Protocol(e) => e.is_retryable(),
            Self::ClientClosed(e) => e.is_retryable(),
            Self::Aborted(e) => e.is_retryable(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => e.is_retryable(),
        }
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Server(e) => e.has_no_side_effects(),
            Self::Validation(_) => true,
            Self::Connect(e) => e.has_no_side_effects(),
            Self::ConnectionLost(e) => e.has_no_side_effects(),
            Self::Timeout(e) => e.has_no_side_effects(),
            Self::Protocol(e) => e.has_no_side_effects(),
            Self::ClientClosed(e) => e.has_no_side_effects(),
            Self::Aborted(e) => e.has_no_side_effects(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(_) => true,
        }
    }

    /// Return the server error, if present.
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            _ => None,
        }
    }
}

impl From<RequestError> for S2Error {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::Server(e) => Self::Server(e),
            RequestError::Validation(e) => Self::Validation(e),
            RequestError::Connect(e) => Self::Connect(e),
            RequestError::ConnectionLost(e) => Self::ConnectionLost(e),
            RequestError::Timeout(e) => Self::Timeout(e),
            RequestError::Protocol(e) => Self::Protocol(e),
            RequestError::ClientClosed(e) => Self::ClientClosed(e),
            RequestError::Aborted(e) => Self::Aborted(e),
            #[cfg(feature = "_hidden")]
            RequestError::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

impl From<ApiError> for RequestError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::Server(e) => Self::Server(e),
            ApiError::SeqNumMismatch(e) => Self::Server(e.server),
            ApiError::FencingTokenMismatch(e) => Self::Server(e.server),
            ApiError::ReadUnwritten(e) => Self::Server(e.server),
            ApiError::Validation(e) => Self::Validation(e),
            ApiError::Connect(e) => Self::Connect(e),
            ApiError::ConnectionLost(e) => Self::ConnectionLost(e),
            ApiError::Timeout(e) => Self::Timeout(e),
            ApiError::Protocol(e) => Self::Protocol(e),
            ApiError::ClientClosed(e) => Self::ClientClosed(e),
            ApiError::Aborted(e) => Self::Aborted(e),
            ApiError::IndefiniteAppend {
                final_attempt_error,
            } => (*final_attempt_error).into(),
            #[cfg(feature = "_hidden")]
            ApiError::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

/// Errors returned by unary read and tail-check operations.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// A non-2xx HTTP response from the server.
    #[error(transparent)]
    Server(#[from] ServerError),
    /// The requested read position has not been written.
    #[error(transparent)]
    ReadUnwritten(#[from] ReadUnwrittenError),
    /// Input validation failed.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Failed to establish a connection or `connection_timeout` elapsed.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// A request or connection broke, or a response ended prematurely.
    #[error(transparent)]
    ConnectionLost(#[from] ConnectionLostError),
    /// The request timed out.
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    /// A successful response violated protocol checks.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// A call was made on a closed client.
    #[error(transparent)]
    ClientClosed(#[from] ClientClosedError),
    /// An in-flight read was aborted.
    #[error(transparent)]
    Aborted(#[from] AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(crate::types::AccessTokenProviderError),
}

impl ReadError {
    /// Whether retrying the operation may succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Server(e) => e.is_retryable(),
            Self::ReadUnwritten(e) => e.is_retryable(),
            Self::Validation(_) => false,
            Self::Connect(e) => e.is_retryable(),
            Self::ConnectionLost(e) => e.is_retryable(),
            Self::Timeout(e) => e.is_retryable(),
            Self::Protocol(e) => e.is_retryable(),
            Self::ClientClosed(e) => e.is_retryable(),
            Self::Aborted(e) => e.is_retryable(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => e.is_retryable(),
        }
    }

    /// Whether the failed attempt certainly had no side effects (always `true` for reads).
    pub fn has_no_side_effects(&self) -> bool {
        true
    }

    /// Return the underlying [`ServerError`], including for [`ReadUnwritten`](Self::ReadUnwritten).
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            Self::ReadUnwritten(e) => Some(&e.server),
            _ => None,
        }
    }
}

impl From<ReadError> for S2Error {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::Server(e) => Self::Server(e.into_read_only()),
            ReadError::ReadUnwritten(e) => Self::ReadUnwritten(e),
            ReadError::Validation(e) => Self::Validation(e),
            ReadError::Connect(e) => Self::Connect(e.into_read_only()),
            ReadError::ConnectionLost(e) => Self::ConnectionLost(e.into_read_only()),
            ReadError::Timeout(e) => Self::Timeout(e.into_read_only()),
            ReadError::Protocol(e) => Self::Protocol(e.into_read_only()),
            ReadError::ClientClosed(e) => Self::ClientClosed(e),
            ReadError::Aborted(e) => Self::Aborted(e.into_read_only()),
            #[cfg(feature = "_hidden")]
            ReadError::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

impl From<ApiError> for ReadError {
    fn from(error: ApiError) -> Self {
        let error = error.into_read_only();
        match error {
            ApiError::Server(e) => Self::Server(e),
            ApiError::ReadUnwritten(e) => Self::ReadUnwritten(e),
            ApiError::SeqNumMismatch(e) => Self::Server(e.server),
            ApiError::FencingTokenMismatch(e) => Self::Server(e.server),
            ApiError::Validation(e) => Self::Validation(e),
            ApiError::Connect(e) => Self::Connect(e),
            ApiError::ConnectionLost(e) => Self::ConnectionLost(e),
            ApiError::Timeout(e) => Self::Timeout(e),
            ApiError::Protocol(e) => Self::Protocol(e),
            ApiError::ClientClosed(e) => Self::ClientClosed(e),
            ApiError::Aborted(e) => Self::Aborted(e),
            ApiError::IndefiniteAppend {
                final_attempt_error,
            } => (*final_attempt_error).into(),
            #[cfg(feature = "_hidden")]
            ApiError::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

/// Errors returned by unary append operations.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AppendError {
    /// A non-2xx HTTP response from the server.
    #[error(transparent)]
    Server(#[from] ServerError),
    /// `match_seq_num` did not match the stream's next sequence number.
    #[error(transparent)]
    SeqNumMismatch(#[from] SeqNumMismatchError),
    /// `fencing_token` did not match the stream's current fencing token.
    #[error(transparent)]
    FencingTokenMismatch(#[from] FencingTokenMismatchError),
    /// The final attempt failed definitively, but an earlier attempt may have taken effect.
    #[error(transparent)]
    IndefiniteAppend(#[from] IndefiniteAppendError<Self>),
    /// Input validation failed.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Failed to establish a connection or `connection_timeout` elapsed.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// A request or connection broke, or a response ended prematurely.
    #[error(transparent)]
    ConnectionLost(#[from] ConnectionLostError),
    /// The request timed out.
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    /// A successful response violated protocol checks.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// A call was made on a closed client.
    #[error(transparent)]
    ClientClosed(#[from] ClientClosedError),
    /// An in-flight append was aborted.
    #[error(transparent)]
    Aborted(#[from] AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(crate::types::AccessTokenProviderError),
}

impl AppendError {
    /// Whether retrying the operation may succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Server(e) => e.is_retryable(),
            Self::SeqNumMismatch(e) => e.is_retryable(),
            Self::FencingTokenMismatch(e) => e.is_retryable(),
            Self::IndefiniteAppend(e) => e.is_retryable(),
            Self::Validation(_) => false,
            Self::Connect(e) => e.is_retryable(),
            Self::ConnectionLost(e) => e.is_retryable(),
            Self::Timeout(e) => e.is_retryable(),
            Self::Protocol(e) => e.is_retryable(),
            Self::ClientClosed(e) => e.is_retryable(),
            Self::Aborted(e) => e.is_retryable(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => e.is_retryable(),
        }
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Server(e) => e.has_no_side_effects(),
            Self::SeqNumMismatch(e) => e.has_no_side_effects(),
            Self::FencingTokenMismatch(e) => e.has_no_side_effects(),
            Self::IndefiniteAppend(e) => e.has_no_side_effects(),
            Self::Validation(_) => true,
            Self::Connect(e) => e.has_no_side_effects(),
            Self::ConnectionLost(e) => e.has_no_side_effects(),
            Self::Timeout(e) => e.has_no_side_effects(),
            Self::Protocol(e) => e.has_no_side_effects(),
            Self::ClientClosed(e) => e.has_no_side_effects(),
            Self::Aborted(e) => e.has_no_side_effects(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(_) => true,
        }
    }

    /// Return the underlying [`ServerError`] for direct server errors (including `412` mismatches).
    ///
    /// Returns `None` for [`IndefiniteAppend`](Self::IndefiniteAppend); inspect
    /// [`final_attempt_error`](Self::final_attempt_error) instead.
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            Self::SeqNumMismatch(e) => Some(&e.server),
            Self::FencingTokenMismatch(e) => Some(&e.server),
            _ => None,
        }
    }

    /// Return the final attempt's error if this is [`IndefiniteAppend`](Self::IndefiniteAppend).
    pub fn final_attempt_error(&self) -> Option<&Self> {
        match self {
            Self::IndefiniteAppend(e) => Some(e.final_attempt_error()),
            _ => None,
        }
    }
}

impl From<AppendError> for S2Error {
    fn from(error: AppendError) -> Self {
        match error {
            AppendError::Server(e) => Self::Server(e),
            AppendError::SeqNumMismatch(e) => Self::SeqNumMismatch(e),
            AppendError::FencingTokenMismatch(e) => Self::FencingTokenMismatch(e),
            AppendError::IndefiniteAppend(e) => Self::IndefiniteAppend(e.map(S2Error::from)),
            AppendError::Validation(e) => Self::Validation(e),
            AppendError::Connect(e) => Self::Connect(e),
            AppendError::ConnectionLost(e) => Self::ConnectionLost(e),
            AppendError::Timeout(e) => Self::Timeout(e),
            AppendError::Protocol(e) => Self::Protocol(e),
            AppendError::ClientClosed(e) => Self::ClientClosed(e),
            AppendError::Aborted(e) => Self::Aborted(e),
            #[cfg(feature = "_hidden")]
            AppendError::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

impl From<ApiError> for AppendError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::Server(e) => Self::Server(e),
            ApiError::SeqNumMismatch(e) => Self::SeqNumMismatch(e),
            ApiError::FencingTokenMismatch(e) => Self::FencingTokenMismatch(e),
            ApiError::ReadUnwritten(e) => Self::Server(e.server),
            ApiError::IndefiniteAppend {
                final_attempt_error,
            } => Self::IndefiniteAppend(IndefiniteAppendError::new((*final_attempt_error).into())),
            ApiError::Validation(e) => Self::Validation(e),
            ApiError::Connect(e) => Self::Connect(e),
            ApiError::ConnectionLost(e) => Self::ConnectionLost(e),
            ApiError::Timeout(e) => Self::Timeout(e),
            ApiError::Protocol(e) => Self::Protocol(e),
            ApiError::ClientClosed(e) => Self::ClientClosed(e),
            ApiError::Aborted(e) => Self::Aborted(e),
            #[cfg(feature = "_hidden")]
            ApiError::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

/// Errors returned by [`AppendSession`](crate::append_session::AppendSession) and
/// [`Producer`](crate::producer::Producer).
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AppendSessionError {
    /// A non-2xx HTTP response from the server (including session terminal frames).
    #[error(transparent)]
    Server(#[from] ServerError),
    /// `match_seq_num` did not match the stream's next sequence number.
    #[error(transparent)]
    SeqNumMismatch(#[from] SeqNumMismatchError),
    /// `fencing_token` did not match the stream's current fencing token.
    #[error(transparent)]
    FencingTokenMismatch(#[from] FencingTokenMismatchError),
    /// The final attempt failed definitively, but an earlier attempt may have taken effect.
    #[error(transparent)]
    IndefiniteAppend(#[from] IndefiniteAppendError<Self>),
    /// The session closed or began closing before handling the call.
    #[error(transparent)]
    SessionClosed(#[from] SessionClosedError<Self>),
    /// Input validation failed.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Failed to establish a connection or `connection_timeout` elapsed.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// The session stream or connection broke, or ended prematurely with unacked batches.
    #[error(transparent)]
    ConnectionLost(#[from] ConnectionLostError),
    /// Request or acknowledgement timeout elapsed.
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    /// A response or session frame violated protocol checks.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// A call was made on a closed client.
    #[error(transparent)]
    ClientClosed(#[from] ClientClosedError),
    /// The session was aborted (dropped or client closed).
    #[error(transparent)]
    Aborted(#[from] AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(crate::types::AccessTokenProviderError),
}

impl AppendSessionError {
    /// Whether retrying the operation may succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Server(e) => e.is_retryable(),
            Self::SeqNumMismatch(e) => e.is_retryable(),
            Self::FencingTokenMismatch(e) => e.is_retryable(),
            Self::IndefiniteAppend(e) => e.is_retryable(),
            Self::SessionClosed(e) => e.is_retryable(),
            Self::Validation(_) => false,
            Self::Connect(e) => e.is_retryable(),
            Self::ConnectionLost(e) => e.is_retryable(),
            Self::Timeout(e) => e.is_retryable(),
            Self::Protocol(e) => e.is_retryable(),
            Self::ClientClosed(e) => e.is_retryable(),
            Self::Aborted(e) => e.is_retryable(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => e.is_retryable(),
        }
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Server(e) => e.has_no_side_effects(),
            Self::SeqNumMismatch(e) => e.has_no_side_effects(),
            Self::FencingTokenMismatch(e) => e.has_no_side_effects(),
            Self::IndefiniteAppend(e) => e.has_no_side_effects(),
            Self::SessionClosed(e) => e.has_no_side_effects(),
            Self::Validation(_) => true,
            Self::Connect(e) => e.has_no_side_effects(),
            Self::ConnectionLost(e) => e.has_no_side_effects(),
            Self::Timeout(e) => e.has_no_side_effects(),
            Self::Protocol(e) => e.has_no_side_effects(),
            Self::ClientClosed(e) => e.has_no_side_effects(),
            Self::Aborted(e) => e.has_no_side_effects(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(_) => true,
        }
    }

    /// Return the underlying [`ServerError`] for direct server errors (including `412` mismatches).
    ///
    /// Wrapper errors ([`IndefiniteAppend`](Self::IndefiniteAppend) and
    /// [`SessionClosed`](Self::SessionClosed)) return `None`.
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            Self::SeqNumMismatch(e) => Some(&e.server),
            Self::FencingTokenMismatch(e) => Some(&e.server),
            _ => None,
        }
    }

    /// Return the final attempt's error if this is [`IndefiniteAppend`](Self::IndefiniteAppend).
    pub fn final_attempt_error(&self) -> Option<&Self> {
        match self {
            Self::IndefiniteAppend(e) => Some(e.final_attempt_error()),
            _ => None,
        }
    }

    /// Return the session failure if this is [`SessionClosed`](Self::SessionClosed).
    pub fn failure(&self) -> Option<&Self> {
        match self {
            Self::SessionClosed(e) => e.failure(),
            _ => None,
        }
    }

    pub(crate) fn is_authentication_error(&self) -> bool {
        matches!(self, Self::Server(e) if e.is_authentication_error())
    }

    pub(crate) fn is_server_draining(&self) -> bool {
        matches!(self, Self::Server(e) if e.is_server_draining())
    }

    pub(crate) fn with_context(self, context: &ErrorContext) -> Self {
        match self {
            Self::Server(e) => Self::Server(e.with_context(context)),
            Self::SeqNumMismatch(e) => Self::SeqNumMismatch(e.with_context(context)),
            Self::FencingTokenMismatch(e) => Self::FencingTokenMismatch(e.with_context(context)),
            Self::IndefiniteAppend(e) => Self::IndefiniteAppend(e.map(|i| i.with_context(context))),
            Self::SessionClosed(mut e) => {
                e.context.merge_missing(context);
                Self::SessionClosed(e)
            }
            Self::Validation(e) => Self::Validation(e),
            Self::Connect(e) => Self::Connect(e.with_context(context)),
            Self::ConnectionLost(e) => Self::ConnectionLost(e.with_context(context)),
            Self::Timeout(e) => Self::Timeout(e.with_context(context)),
            Self::Protocol(e) => Self::Protocol(e.with_context(context)),
            Self::ClientClosed(e) => Self::ClientClosed(e.with_context(context)),
            Self::Aborted(e) => Self::Aborted(e.with_context(context)),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

impl AppendRetryError for AppendSessionError {
    fn has_no_side_effects(&self) -> bool {
        Self::has_no_side_effects(self)
    }

    fn into_indefinite_failure(self) -> Self {
        Self::IndefiniteAppend(IndefiniteAppendError::new(self))
    }
}

impl From<AppendError> for AppendSessionError {
    fn from(error: AppendError) -> Self {
        match error {
            AppendError::Server(e) => Self::Server(e),
            AppendError::SeqNumMismatch(e) => Self::SeqNumMismatch(e),
            AppendError::FencingTokenMismatch(e) => Self::FencingTokenMismatch(e),
            AppendError::IndefiniteAppend(e) => {
                Self::IndefiniteAppend(e.map(AppendSessionError::from))
            }
            AppendError::Validation(e) => Self::Validation(e),
            AppendError::Connect(e) => Self::Connect(e),
            AppendError::ConnectionLost(e) => Self::ConnectionLost(e),
            AppendError::Timeout(e) => Self::Timeout(e),
            AppendError::Protocol(e) => Self::Protocol(e),
            AppendError::ClientClosed(e) => Self::ClientClosed(e),
            AppendError::Aborted(e) => Self::Aborted(e),
            #[cfg(feature = "_hidden")]
            AppendError::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

impl From<AppendSessionError> for S2Error {
    fn from(error: AppendSessionError) -> Self {
        match error {
            AppendSessionError::Server(e) => Self::Server(e),
            AppendSessionError::SeqNumMismatch(e) => Self::SeqNumMismatch(e),
            AppendSessionError::FencingTokenMismatch(e) => Self::FencingTokenMismatch(e),
            AppendSessionError::IndefiniteAppend(e) => Self::IndefiniteAppend(e.map(S2Error::from)),
            AppendSessionError::SessionClosed(e) => Self::SessionClosed(e.map(S2Error::from)),
            AppendSessionError::Validation(e) => Self::Validation(e),
            AppendSessionError::Connect(e) => Self::Connect(e),
            AppendSessionError::ConnectionLost(e) => Self::ConnectionLost(e),
            AppendSessionError::Timeout(e) => Self::Timeout(e),
            AppendSessionError::Protocol(e) => Self::Protocol(e),
            AppendSessionError::ClientClosed(e) => Self::ClientClosed(e),
            AppendSessionError::Aborted(e) => Self::Aborted(e),
            #[cfg(feature = "_hidden")]
            AppendSessionError::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

impl From<ApiError> for AppendSessionError {
    fn from(error: ApiError) -> Self {
        AppendError::from(error).into()
    }
}

/// Errors returned by [`ReadSession`](crate::read_session::ReadSession) and its
/// [`caught_up`](crate::read_session::ReadSession::caught_up) future.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ReadSessionError {
    /// A non-2xx HTTP response from the server (including session terminal frames).
    #[error(transparent)]
    Server(#[from] ServerError),
    /// The requested read position has not been written.
    #[error(transparent)]
    ReadUnwritten(#[from] ReadUnwrittenError),
    /// The session closed before handling the call or catching up.
    #[error(transparent)]
    SessionClosed(#[from] SessionClosedError<Self>),
    /// Input validation failed.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Failed to establish a connection or `connection_timeout` elapsed.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// The session stream or connection broke, or ended prematurely.
    #[error(transparent)]
    ConnectionLost(#[from] ConnectionLostError),
    /// Request or heartbeat timeout elapsed.
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    /// A response or session frame violated protocol checks.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// A call was made on a closed client.
    #[error(transparent)]
    ClientClosed(#[from] ClientClosedError),
    /// The session was aborted (for example by client `close()`).
    #[error(transparent)]
    Aborted(#[from] AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(crate::types::AccessTokenProviderError),
}

impl ReadSessionError {
    /// Whether retrying the operation may succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Server(e) => e.is_retryable(),
            Self::ReadUnwritten(e) => e.is_retryable(),
            Self::SessionClosed(e) => e.is_retryable(),
            Self::Validation(_) => false,
            Self::Connect(e) => e.is_retryable(),
            Self::ConnectionLost(e) => e.is_retryable(),
            Self::Timeout(e) => e.is_retryable(),
            Self::Protocol(e) => e.is_retryable(),
            Self::ClientClosed(e) => e.is_retryable(),
            Self::Aborted(e) => e.is_retryable(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => e.is_retryable(),
        }
    }

    /// Whether the failed attempt certainly had no side effects (always `true` for reads).
    pub fn has_no_side_effects(&self) -> bool {
        true
    }

    /// Return the underlying [`ServerError`], including for [`ReadUnwritten`](Self::ReadUnwritten).
    ///
    /// Returns `None` for [`SessionClosed`](Self::SessionClosed); inspect
    /// [`failure`](Self::failure) instead.
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            Self::ReadUnwritten(e) => Some(&e.server),
            _ => None,
        }
    }

    /// Return the session failure if this is [`SessionClosed`](Self::SessionClosed).
    pub fn failure(&self) -> Option<&Self> {
        match self {
            Self::SessionClosed(e) => e.failure(),
            _ => None,
        }
    }

    pub(crate) fn with_context(self, context: &ErrorContext) -> Self {
        let context = context.clone().into_read_only();
        match self {
            Self::Server(e) => Self::Server(e.with_context(&context)),
            Self::ReadUnwritten(e) => Self::ReadUnwritten(e.with_context(&context)),
            Self::SessionClosed(mut e) => {
                e.context.merge_missing(&context);
                Self::SessionClosed(e)
            }
            Self::Validation(e) => Self::Validation(e),
            Self::Connect(e) => Self::Connect(e.with_context(&context)),
            Self::ConnectionLost(e) => Self::ConnectionLost(e.with_context(&context)),
            Self::Timeout(e) => Self::Timeout(e.with_context(&context)),
            Self::Protocol(e) => Self::Protocol(e.with_context(&context)),
            Self::ClientClosed(e) => Self::ClientClosed(e.with_context(&context)),
            Self::Aborted(e) => Self::Aborted(e.with_context(&context)),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

impl From<ReadError> for ReadSessionError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::Server(e) => Self::Server(e.into_read_only()),
            ReadError::ReadUnwritten(e) => Self::ReadUnwritten(e),
            ReadError::Validation(e) => Self::Validation(e),
            ReadError::Connect(e) => Self::Connect(e.into_read_only()),
            ReadError::ConnectionLost(e) => Self::ConnectionLost(e.into_read_only()),
            ReadError::Timeout(e) => Self::Timeout(e.into_read_only()),
            ReadError::Protocol(e) => Self::Protocol(e.into_read_only()),
            ReadError::ClientClosed(e) => Self::ClientClosed(e),
            ReadError::Aborted(e) => Self::Aborted(e.into_read_only()),
            #[cfg(feature = "_hidden")]
            ReadError::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

impl From<ReadSessionError> for S2Error {
    fn from(error: ReadSessionError) -> Self {
        match error {
            ReadSessionError::Server(e) => Self::Server(e.into_read_only()),
            ReadSessionError::ReadUnwritten(e) => Self::ReadUnwritten(e),
            ReadSessionError::SessionClosed(e) => Self::SessionClosed(e.map(S2Error::from)),
            ReadSessionError::Validation(e) => Self::Validation(e),
            ReadSessionError::Connect(e) => Self::Connect(e.into_read_only()),
            ReadSessionError::ConnectionLost(e) => Self::ConnectionLost(e.into_read_only()),
            ReadSessionError::Timeout(e) => Self::Timeout(e.into_read_only()),
            ReadSessionError::Protocol(e) => Self::Protocol(e.into_read_only()),
            ReadSessionError::ClientClosed(e) => Self::ClientClosed(e),
            ReadSessionError::Aborted(e) => Self::Aborted(e.into_read_only()),
            #[cfg(feature = "_hidden")]
            ReadSessionError::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
        }
    }
}

impl From<ApiError> for ReadSessionError {
    fn from(error: ApiError) -> Self {
        ReadError::from(error).into()
    }
}

pub(crate) fn server_error_is_retryable(status: StatusCode, code: Option<&str>) -> bool {
    if status == StatusCode::PRECONDITION_FAILED {
        return false;
    }
    if let Some(known) = code.and_then(|c| c.parse::<ErrorCode>().ok())
        && known.status() == status
    {
        return known.is_retryable();
    }
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

pub(crate) fn server_error_has_no_side_effects(status: StatusCode, code: Option<&str>) -> bool {
    if status == StatusCode::PRECONDITION_FAILED {
        return true;
    }
    code.and_then(|c| c.parse::<ErrorCode>().ok())
        .is_some_and(|known| known.status() == status && known.has_no_side_effects())
}

pub(crate) fn classify_http_error(err: client::HttpError, context: ErrorContext) -> ApiError {
    let err_msg = err.to_string();
    match err {
        client::HttpError::Send(ref send_err) if send_err.is_connect() => {
            ApiError::Connect(ConnectError::new(err_msg, context))
        }
        client::HttpError::Timeout => {
            ApiError::Timeout(TimeoutError::new("request timed out", context))
        }
        client::HttpError::ClientClosed => ApiError::ClientClosed(ClientClosedError::new(context)),
        client::HttpError::Aborted => {
            ApiError::Aborted(AbortedError::new("client closed", context))
        }
        client::HttpError::Send(_) | client::HttpError::Receive(_) => {
            if let Some(hyper_err) = source_err::<hyper::Error>(&err) {
                let detail = format!("{hyper_err} -> {err_msg}");
                if hyper_err.is_parse() || hyper_err.is_user() {
                    return ApiError::Protocol(ProtocolError::new(detail, context));
                }
                if source_err::<h2::Error>(&err)
                    .is_some_and(|e| e.reason() == Some(h2::Reason::REFUSED_STREAM))
                {
                    return ApiError::ConnectionLost(ConnectionLostError::new(
                        detail, true, context,
                    ));
                }
                return ApiError::ConnectionLost(ConnectionLostError::new(detail, false, context));
            }
            if source_err::<h2::Error>(&err)
                .is_some_and(|e| e.reason() == Some(h2::Reason::REFUSED_STREAM))
            {
                return ApiError::ConnectionLost(ConnectionLostError::new(err_msg, true, context));
            }
            ApiError::ConnectionLost(ConnectionLostError::new(err_msg, false, context))
        }
        client::HttpError::RequestBuild(message) => ApiError::Protocol(ProtocolError::new(
            format!("request build: {message}"),
            context,
        )),
        client::HttpError::RequestCompression(message) => ApiError::Protocol(ProtocolError::new(
            format!("request compression: {message}"),
            context,
        )),
        client::HttpError::ResponseCompression(message) => ApiError::Protocol(ProtocolError::new(
            format!("response compression: {message}"),
            context,
        )),
        client::HttpError::ResponseDecode(error) => ApiError::Protocol(ProtocolError::new(
            format!("response decode: {error}"),
            context,
        )),
    }
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

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    fn response(status: StatusCode, code: Option<&str>) -> ServerError {
        ServerError::new_for_test(status, code, "test")
    }

    // spec: r1 E2, E4a
    #[test]
    fn error_response_preserves_raw_and_known_codes() {
        let known = response(StatusCode::NOT_FOUND, Some("basin_not_found"));
        assert_eq!(known.code.as_deref(), Some("basin_not_found"));
        assert_eq!(known.message, "test");
        assert_eq!(known.known_code(), Some(ErrorCode::BasinNotFound));
        assert!(known.to_string().contains("basin_not_found"));

        let unknown = response(
            StatusCode::BAD_REQUEST,
            Some("introduced_by_a_newer_server"),
        );
        assert_eq!(unknown.known_code(), None);
        assert_eq!(
            unknown.code.as_deref(),
            Some("introduced_by_a_newer_server")
        );
    }

    // spec: r1 E4b
    #[test]
    fn server_classification_falls_back_to_status_on_status_mismatch() {
        let mismatch = response(StatusCode::INTERNAL_SERVER_ERROR, Some("rate_limited"));
        assert!(mismatch.is_retryable());
        assert!(!mismatch.has_no_side_effects());

        let non_retryable_status = response(StatusCode::BAD_REQUEST, Some("unavailable"));
        assert!(!non_retryable_status.is_retryable());
        assert!(!non_retryable_status.has_no_side_effects());
    }

    // spec: r1 E4c, E4e
    #[test]
    fn unknown_codes_and_412_classification() {
        let unknown = response(StatusCode::SERVICE_UNAVAILABLE, Some("future_server_error"));
        assert!(unknown.is_retryable());
        assert!(!unknown.has_no_side_effects());

        let plain_412 = ServerError::from_response(
            StatusCode::PRECONDITION_FAILED,
            b"",
            ErrorContext::default(),
        );
        assert_eq!(plain_412.code, None);
        assert_eq!(plain_412.message, "412");
        assert!(!plain_412.is_retryable());
        assert!(plain_412.has_no_side_effects());
    }

    // spec: r1 E3
    #[test]
    fn http_error_classification_matches_e3() {
        assert!(matches!(
            classify_http_error(
                client::HttpError::RequestBuild("bad request".to_owned()),
                ErrorContext::default()
            ),
            ApiError::Protocol(ProtocolError { message, .. }) if message.contains("bad request")
        ));
        assert!(matches!(
            classify_http_error(
                client::HttpError::ResponseCompression("corrupt".to_owned()),
                ErrorContext::default()
            ),
            ApiError::Protocol(ProtocolError { message, .. }) if message.contains("corrupt")
        ));
        let json_error = serde_json::from_slice::<serde_json::Value>(b"{")
            .expect_err("invalid JSON should fail");
        assert!(matches!(
            classify_http_error(
                client::HttpError::ResponseDecode(json_error),
                ErrorContext::default()
            ),
            ApiError::Protocol(_)
        ));
        assert!(matches!(
            classify_http_error(client::HttpError::Timeout, ErrorContext::default()),
            ApiError::Timeout(_)
        ));
    }

    // spec: r1 E1, E5a, E5b, E6, E7
    #[test]
    fn wrappers_hide_inner_server_error_and_expose_source_and_context() {
        let ctx = ErrorContext::stream("append", "my-basin", "my-stream", false).with_attempts(3);
        let inner = AppendError::SeqNumMismatch(SeqNumMismatchError::new(
            42,
            ServerError::from_response(
                StatusCode::PRECONDITION_FAILED,
                br#"{"seq_num_mismatch":42}"#,
                ctx.clone(),
            ),
        ));
        assert!(inner.server_error().is_some());
        assert!(inner.has_no_side_effects());
        assert!(!inner.is_retryable());
        let inner_msg = inner.to_string();
        assert!(inner_msg.contains("append"), "{inner_msg}");
        assert!(inner_msg.contains("my-basin"), "{inner_msg}");
        assert!(inner_msg.contains("my-stream"), "{inner_msg}");
        assert!(inner_msg.contains("3 attempts"), "{inner_msg}");

        let wrapped = AppendError::IndefiniteAppend(IndefiniteAppendError::new(inner));
        assert!(wrapped.server_error().is_none());
        assert!(!wrapped.has_no_side_effects());
        assert!(!wrapped.is_retryable());
        assert!(matches!(
            wrapped.final_attempt_error(),
            Some(AppendError::SeqNumMismatch(e)) if e.assignable_seq_num == 42
        ));
        let source = wrapped
            .source()
            .expect("source set")
            .downcast_ref::<AppendError>()
            .expect("source downcasts directly to AppendError");
        assert!(matches!(
            source,
            AppendError::SeqNumMismatch(e) if e.assignable_seq_num == 42
        ));

        let s2_err: S2Error = wrapped.into();
        assert!(s2_err.server_error().is_none());
        assert!(!s2_err.has_no_side_effects());
        assert!(matches!(
            s2_err.final_attempt_error(),
            Some(S2Error::SeqNumMismatch(e)) if e.assignable_seq_num == 42
        ));
        assert!(
            s2_err
                .source()
                .expect("S2Error source set")
                .downcast_ref::<S2Error>()
                .is_some()
        );

        let closed_clean =
            AppendSessionError::SessionClosed(SessionClosedError::new(None, ctx.clone()));
        assert!(closed_clean.has_no_side_effects());
        assert!(!closed_clean.is_retryable());
        assert!(closed_clean.failure().is_none());
        assert!(closed_clean.source().is_none());
        assert!(closed_clean.to_string().contains("my-basin"));

        let session_failure =
            AppendSessionError::Server(response(StatusCode::FORBIDDEN, Some("permission_denied")));
        let closed_failed =
            AppendSessionError::SessionClosed(SessionClosedError::new(Some(session_failure), ctx));
        assert!(closed_failed.has_no_side_effects());
        assert!(!closed_failed.is_retryable());
        assert!(closed_failed.server_error().is_none());
        assert!(closed_failed.failure().is_some());
        assert!(closed_failed.to_string().contains("permission_denied"));
        assert!(
            closed_failed
                .source()
                .expect("SessionClosed source set")
                .downcast_ref::<AppendSessionError>()
                .is_some()
        );
    }

    // spec: r1 E1, E3
    #[test]
    fn read_errors_stay_definite_when_converted_to_s2_error() {
        let timeout = ReadError::Timeout(TimeoutError::new("timed out", ErrorContext::default()));
        assert!(timeout.is_retryable());
        assert!(timeout.has_no_side_effects());
        let s2_err: S2Error = timeout.into();
        assert!(s2_err.is_retryable());
        assert!(s2_err.has_no_side_effects());
    }
}
