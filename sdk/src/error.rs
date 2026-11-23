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
use s2_api::v1::stream::{TailResponse, s2s::TerminalMessage};
pub use s2_common::ValidationError;

use crate::{
    client,
    types::{FencingToken, StreamPosition},
};

/// Borrowed operation metadata kept on the stack during calls so the success path allocates
/// nothing; converted into an [`ErrorContext`] only when an error actually occurs (`E7`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct OpScope<'a> {
    pub operation: &'static str,
    pub basin: Option<&'a str>,
    pub stream: Option<&'a str>,
    pub read_only: bool,
}

impl<'a> OpScope<'a> {
    pub(crate) const fn account(operation: &'static str, read_only: bool) -> Self {
        Self {
            operation,
            basin: None,
            stream: None,
            read_only,
        }
    }

    pub(crate) const fn basin(operation: &'static str, basin: &'a str, read_only: bool) -> Self {
        Self {
            operation,
            basin: Some(basin),
            stream: None,
            read_only,
        }
    }

    pub(crate) const fn stream(
        operation: &'static str,
        basin: &'a str,
        stream: &'a str,
        read_only: bool,
    ) -> Self {
        Self {
            operation,
            basin: Some(basin),
            stream: Some(stream),
            read_only,
        }
    }

    pub(crate) fn context(self, attempts: u32) -> ErrorContext {
        ErrorContext(Some(Arc::new(ErrorContextInner {
            operation: Some(self.operation),
            basin: self.basin.map(str::to_owned),
            stream: self.stream.map(str::to_owned),
            attempts,
            read_only: self.read_only,
        })))
    }
}

/// Context attached to SDK errors for diagnostic display (`E7`) and read-only classification.
///
/// Stored behind an `Option<Arc<...>>` so error values stay compact on the stack and `Clone` is
/// O(1) without heap allocation on the default path.
#[derive(Debug, Clone, Default)]
pub(crate) struct ErrorContext(Option<Arc<ErrorContextInner>>);

#[derive(Debug, Clone, Default)]
struct ErrorContextInner {
    operation: Option<&'static str>,
    basin: Option<String>,
    stream: Option<String>,
    attempts: u32,
    read_only: bool,
}

impl ErrorContext {
    pub(crate) fn stream(
        operation: &'static str,
        basin: &str,
        stream: &str,
        read_only: bool,
    ) -> Self {
        OpScope::stream(operation, basin, stream, read_only).context(1)
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
        if self
            .0
            .as_ref()
            .is_none_or(|inner| inner.attempts != attempts)
        {
            self.inner_mut().attempts = attempts;
        }
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
        let Some(self_inner) = self.0.as_deref() else {
            self.0 = other.0.clone();
            return;
        };
        let needs_update = (self_inner.operation.is_none() && other_inner.operation.is_some())
            || (self_inner.basin.is_none() && other_inner.basin.is_some())
            || (self_inner.stream.is_none() && other_inner.stream.is_some())
            || (self_inner.attempts <= 1 && other_inner.attempts > 1)
            || (!self_inner.read_only && other_inner.read_only);
        if !needs_update {
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
}

#[derive(serde::Deserialize)]
struct ServerErrorBody {
    code: String,
    message: String,
}

#[derive(serde::Deserialize)]
struct AppendConditionFailedBody {
    seq_num_mismatch: Option<u64>,
    fencing_token_mismatch: Option<String>,
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
            _ => status.as_str().to_owned(),
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

    /// Return the server error code when it is recognized by this SDK version **and** paired with
    /// the HTTP status defined for it.
    ///
    /// The raw [`code`](Self::code) remains available so callers can preserve and report codes
    /// introduced by newer servers or returned with unexpected statuses.
    pub fn known_code(&self) -> Option<ErrorCode> {
        self.code
            .as_deref()
            .and_then(|c| c.parse::<ErrorCode>().ok())
            .filter(|known| known.status() == self.status)
    }

    /// Whether retrying the request may succeed.
    pub fn is_retryable(&self) -> bool {
        if self.status == StatusCode::PRECONDITION_FAILED {
            return false;
        }
        if let Some(known) = self.known_code() {
            return known.is_retryable();
        }
        matches!(
            self.status,
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::INTERNAL_SERVER_ERROR
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        )
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        self.context.is_read_only()
            || self.status == StatusCode::PRECONDITION_FAILED
            || self
                .known_code()
                .is_some_and(ErrorCode::has_no_side_effects)
    }

    pub(crate) fn is_authentication_error(&self) -> bool {
        self.known_code() == Some(ErrorCode::Authn)
    }

    pub(crate) fn is_server_draining(&self) -> bool {
        self.known_code() == Some(ErrorCode::ServerDraining)
    }

    pub(crate) fn is_hot_server(&self) -> bool {
        self.known_code() == Some(ErrorCode::HotServer)
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
                    None if self.0.message == self.0.status.as_str() => {
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

macro_rules! define_message_error {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            field_doc: $field_doc:literal,
            prefix: $prefix:literal,
            retryable: $retryable:expr,
            retryable_doc: $retryable_doc:literal,
            no_side_effects: |$self_ident:ident| $no_side_effects:expr,
            no_side_effects_doc: $no_side_effects_doc:literal,
            $(into_read_only: $into_ro:ident,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        #[non_exhaustive]
        pub struct $name {
            #[doc = $field_doc]
            pub message: String,
            pub(crate) context: ErrorContext,
        }

        impl $name {
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

            $(
                pub(crate) fn $into_ro(mut self) -> Self {
                    self.context.set_read_only();
                    self
                }
            )?

            #[doc = $retryable_doc]
            pub fn is_retryable(&self) -> bool {
                $retryable
            }

            #[doc = $no_side_effects_doc]
            pub fn has_no_side_effects(&self) -> bool {
                let $self_ident = self;
                $no_side_effects
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.context
                    .format_with(f, format_args!("{}: {}", $prefix, self.message))
            }
        }

        impl std::error::Error for $name {}
    };
}

define_message_error! {
    /// Failed to establish a connection, or `connection_timeout` elapsed.
    pub struct ConnectError {
        field_doc: "Diagnostic detail describing the connection failure.",
        prefix: "connect",
        retryable: true,
        retryable_doc: "Whether retrying the request may succeed (always `true`).",
        no_side_effects: |_this| true,
        no_side_effects_doc: "Whether the failed attempt certainly had no side effects (always `true`).",
    }
}

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

define_message_error! {
    /// A request, acknowledgement, or read-session heartbeat timed out.
    pub struct TimeoutError {
        field_doc: "Diagnostic detail identifying which timer expired.",
        prefix: "timeout",
        retryable: true,
        retryable_doc: "Whether retrying the request may succeed (always `true`).",
        no_side_effects: |this| this.context.is_read_only(),
        no_side_effects_doc: "Whether the failed attempt certainly had no side effects.",
        into_read_only: into_read_only,
    }
}

define_message_error! {
    /// A successful response or session message could not be decoded or violated an SDK check.
    pub struct ProtocolError {
        field_doc: "Diagnostic detail describing the protocol failure.",
        prefix: "protocol",
        retryable: false,
        retryable_doc: "Whether retrying the request may succeed (always `false`).",
        no_side_effects: |this| this.context.is_read_only(),
        no_side_effects_doc: "Whether the failed attempt certainly had no side effects.",
        into_read_only: into_read_only,
    }
}

/// A call was made on a client after `close()`.
#[derive(Debug, Clone)]
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

define_message_error! {
    /// A session was aborted, a call was canceled, or a unary call was in flight when the client
    /// closed.
    pub struct AbortedError {
        field_doc: "Diagnostic detail describing why the operation was aborted.",
        prefix: "aborted",
        retryable: false,
        retryable_doc: "Whether retrying the request may succeed (always `false`).",
        no_side_effects: |this| this.context.is_read_only(),
        no_side_effects_doc: "Whether the failed attempt certainly had no side effects.",
        into_read_only: into_read_only,
    }
}

/// A definite final error on an append followed an earlier attempt that may have taken effect,
/// making the overall append indeterminate.
#[derive(Debug, Clone)]
pub struct IndefiniteAppendError<E> {
    final_attempt_error: Box<E>,
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

macro_rules! impl_indefinite_is_retryable {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl IndefiniteAppendError<$ty> {
                /// Whether retrying the underlying error may succeed.
                pub fn is_retryable(&self) -> bool {
                    self.final_attempt_error.is_retryable()
                }
            }
        )+
    };
}

impl_indefinite_is_retryable!(AppendError, AppendSessionError, S2Error);

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
pub struct SessionClosedError<E> {
    failure: Option<Box<E>>,
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
            Some(failure) => write!(f, "session closed: {failure}"),
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

macro_rules! delegate_is_retryable {
    ($self:expr, [$($variant:ident),* $(,)?]) => {
        match $self {
            $(Self::$variant(e) => e.is_retryable(),)*
            Self::Validation(_) => false,
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => e.is_retryable(),
        }
    };
}

macro_rules! delegate_has_no_side_effects {
    ($self:expr, [$($variant:ident),* $(,)?]) => {
        match $self {
            $(Self::$variant(e) => e.has_no_side_effects(),)*
            Self::Validation(_) => true,
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(_) => true,
        }
    };
}

macro_rules! impl_error_upcast {
    (
        $src:ident => $dst:ident {
            direct: [$($direct:ident),* $(,)?],
            read_only: [$($ro:ident),* $(,)?],
            mapped: [$($mapped:ident),* $(,)?],
        }
    ) => {
        impl From<$src> for $dst {
            fn from(error: $src) -> Self {
                match error {
                    $($src::$direct(e) => Self::$direct(e),)*
                    $($src::$ro(e) => Self::$ro(e.into_read_only()),)*
                    $($src::$mapped(e) => Self::$mapped(e.map($dst::from)),)*
                    #[cfg(feature = "_hidden")]
                    $src::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
                }
            }
        }
    };
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
        delegate_is_retryable!(
            self,
            [
                Server,
                SeqNumMismatch,
                FencingTokenMismatch,
                ReadUnwritten,
                IndefiniteAppend,
                SessionClosed,
                Connect,
                ConnectionLost,
                Timeout,
                Protocol,
                ClientClosed,
                Aborted,
            ]
        )
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        delegate_has_no_side_effects!(
            self,
            [
                Server,
                SeqNumMismatch,
                FencingTokenMismatch,
                ReadUnwritten,
                IndefiniteAppend,
                SessionClosed,
                Connect,
                ConnectionLost,
                Timeout,
                Protocol,
                ClientClosed,
                Aborted,
            ]
        )
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

/// Errors returned by account, basin, stream-management, and metrics operations.
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
        delegate_is_retryable!(
            self,
            [
                Server,
                Connect,
                ConnectionLost,
                Timeout,
                Protocol,
                ClientClosed,
                Aborted,
            ]
        )
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        delegate_has_no_side_effects!(
            self,
            [
                Server,
                Connect,
                ConnectionLost,
                Timeout,
                Protocol,
                ClientClosed,
                Aborted,
            ]
        )
    }

    /// Return the server error, if present.
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            _ => None,
        }
    }
}

impl_error_upcast!(RequestError => S2Error {
    direct: [Server, Validation, Connect, ConnectionLost, Timeout, Protocol, ClientClosed, Aborted],
    read_only: [],
    mapped: [],
});

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
        delegate_is_retryable!(
            self,
            [
                Server,
                ReadUnwritten,
                Connect,
                ConnectionLost,
                Timeout,
                Protocol,
                ClientClosed,
                Aborted,
            ]
        )
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

impl_error_upcast!(ReadError => S2Error {
    direct: [ReadUnwritten, Validation, Connect, ClientClosed],
    read_only: [Server, ConnectionLost, Timeout, Protocol, Aborted],
    mapped: [],
});

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
        delegate_is_retryable!(
            self,
            [
                Server,
                SeqNumMismatch,
                FencingTokenMismatch,
                IndefiniteAppend,
                Connect,
                ConnectionLost,
                Timeout,
                Protocol,
                ClientClosed,
                Aborted,
            ]
        )
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        delegate_has_no_side_effects!(
            self,
            [
                Server,
                SeqNumMismatch,
                FencingTokenMismatch,
                IndefiniteAppend,
                Connect,
                ConnectionLost,
                Timeout,
                Protocol,
                ClientClosed,
                Aborted,
            ]
        )
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

impl_error_upcast!(AppendError => S2Error {
    direct: [Server, SeqNumMismatch, FencingTokenMismatch, Validation, Connect, ConnectionLost, Timeout, Protocol, ClientClosed, Aborted],
    read_only: [],
    mapped: [IndefiniteAppend],
});

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
        delegate_is_retryable!(
            self,
            [
                Server,
                SeqNumMismatch,
                FencingTokenMismatch,
                IndefiniteAppend,
                SessionClosed,
                Connect,
                ConnectionLost,
                Timeout,
                Protocol,
                ClientClosed,
                Aborted,
            ]
        )
    }

    /// Whether the failed attempt certainly had no side effects.
    pub fn has_no_side_effects(&self) -> bool {
        delegate_has_no_side_effects!(
            self,
            [
                Server,
                SeqNumMismatch,
                FencingTokenMismatch,
                IndefiniteAppend,
                SessionClosed,
                Connect,
                ConnectionLost,
                Timeout,
                Protocol,
                ClientClosed,
                Aborted,
            ]
        )
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

impl_error_upcast!(AppendError => AppendSessionError {
    direct: [Server, SeqNumMismatch, FencingTokenMismatch, Validation, Connect, ConnectionLost, Timeout, Protocol, ClientClosed, Aborted],
    read_only: [],
    mapped: [IndefiniteAppend],
});

impl_error_upcast!(AppendSessionError => S2Error {
    direct: [Server, SeqNumMismatch, FencingTokenMismatch, Validation, Connect, ConnectionLost, Timeout, Protocol, ClientClosed, Aborted],
    read_only: [],
    mapped: [IndefiniteAppend, SessionClosed],
});

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
        delegate_is_retryable!(
            self,
            [
                Server,
                ReadUnwritten,
                SessionClosed,
                Connect,
                ConnectionLost,
                Timeout,
                Protocol,
                ClientClosed,
                Aborted,
            ]
        )
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

    pub(crate) fn is_server_draining(&self) -> bool {
        matches!(self, Self::Server(e) if e.is_server_draining())
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

impl_error_upcast!(ReadError => ReadSessionError {
    direct: [ReadUnwritten, Validation, Connect, ClientClosed],
    read_only: [Server, ConnectionLost, Timeout, Protocol, Aborted],
    mapped: [],
});

impl_error_upcast!(ReadSessionError => S2Error {
    direct: [ReadUnwritten, Validation, Connect, ClientClosed],
    read_only: [Server, ConnectionLost, Timeout, Protocol, Aborted],
    mapped: [SessionClosed],
});

/// Internal transport-layer error abstraction implemented directly by the five public operation
/// error enums, allowing `api.rs` unary and streaming paths to construct the exact return type
/// without an intermediate `ApiError` wrapper.
pub(crate) trait TransportError:
    Sized
    + fmt::Display
    + From<ServerError>
    + From<ValidationError>
    + From<ConnectError>
    + From<ConnectionLostError>
    + From<TimeoutError>
    + From<ProtocolError>
    + From<ClientClosedError>
    + From<AbortedError>
{
    fn from_http(err: client::HttpError, context: ErrorContext) -> Self {
        classify_http_error(err, context)
    }

    fn from_http_response(status: StatusCode, body: &[u8], context: ErrorContext) -> Self;

    fn from_terminal_message(msg: TerminalMessage, context: ErrorContext) -> Self {
        let status = match StatusCode::from_u16(msg.status) {
            Ok(status) if (300..600).contains(&status.as_u16()) => status,
            Ok(status) => {
                return ProtocolError::new(
                    format!("unexpected non-error status code in terminal frame: {status}"),
                    context,
                )
                .into();
            }
            Err(err) => {
                return ProtocolError::new(
                    format!("invalid status code in terminal frame: {err}"),
                    context,
                )
                .into();
            }
        };
        Self::from_http_response(status, &msg.body, context)
    }

    #[cfg(feature = "_hidden")]
    fn from_access_token_provider(err: crate::types::AccessTokenProviderError) -> Self;

    fn is_retryable(&self) -> bool;

    fn has_no_side_effects(&self) -> bool;

    fn server_error(&self) -> Option<&ServerError>;

    fn connection_lost_mut(&mut self) -> Option<&mut ConnectionLostError> {
        None
    }

    fn mark_unsent_connection_lost(mut self, unsent: bool) -> Self {
        if unsent && let Some(conn_lost) = self.connection_lost_mut() {
            conn_lost.no_side_effects = true;
        }
        self
    }

    fn is_authentication_error(&self) -> bool {
        self.server_error()
            .is_some_and(ServerError::is_authentication_error)
    }

    fn should_retire_connection(&self) -> bool {
        self.server_error()
            .is_some_and(ServerError::should_retire_connection)
    }

    fn with_prior_uncertainty(self, _prior_uncertainty: bool) -> Self {
        self
    }
}

fn parse_append_response<E>(status: StatusCode, body: &[u8], context: ErrorContext) -> E
where
    E: From<ServerError> + From<SeqNumMismatchError> + From<FencingTokenMismatchError>,
{
    if status == StatusCode::PRECONDITION_FAILED
        && let Ok(parsed) = serde_json::from_slice::<AppendConditionFailedBody>(body)
    {
        match (parsed.seq_num_mismatch, parsed.fencing_token_mismatch) {
            (Some(assignable_seq_num), None) => {
                let server = ServerError::from_response(status, body, context);
                return SeqNumMismatchError::new(assignable_seq_num, server).into();
            }
            (None, Some(token)) => {
                let server = ServerError::from_response(status, body, context);
                return FencingTokenMismatchError::new(FencingToken::from_server(token), server)
                    .into();
            }
            _ => {}
        }
    }
    ServerError::from_response(status, body, context).into()
}

fn parse_read_response<E>(status: StatusCode, body: &[u8], context: ErrorContext) -> E
where
    E: From<ServerError> + From<ReadUnwrittenError>,
{
    let context = context.into_read_only();
    if status == StatusCode::RANGE_NOT_SATISFIABLE
        && let Ok(tail) = serde_json::from_slice::<TailResponse>(body)
    {
        let server = ServerError::from_response(status, body, context);
        return ReadUnwrittenError::new(tail.tail.into(), server).into();
    }
    ServerError::from_response(status, body, context).into()
}

macro_rules! impl_transport_error {
    (
        $ty:ident,
        from_http_response: $from_resp:expr
        $(, read_only: $ro:tt)?
        $(, unsent_conn_lost: $unsent:tt)?
        $(, prior_uncertainty: $prior:tt)?
        $(,)?
    ) => {
        impl TransportError for $ty {
            $(
                impl_transport_error!(@read_only $ro);
            )?

            fn from_http_response(status: StatusCode, body: &[u8], context: ErrorContext) -> Self {
                ($from_resp)(status, body, context)
            }

            #[cfg(feature = "_hidden")]
            fn from_access_token_provider(err: crate::types::AccessTokenProviderError) -> Self {
                Self::AccessTokenProvider(err)
            }

            fn is_retryable(&self) -> bool {
                Self::is_retryable(self)
            }

            fn has_no_side_effects(&self) -> bool {
                Self::has_no_side_effects(self)
            }

            fn server_error(&self) -> Option<&ServerError> {
                Self::server_error(self)
            }

            $(
                impl_transport_error!(@unsent $unsent);
            )?

            $(
                impl_transport_error!(@prior $prior);
            )?
        }
    };
    (@read_only true) => {
        fn from_http(err: client::HttpError, context: ErrorContext) -> Self {
            classify_http_error(err, context.into_read_only())
        }
    };
    (@unsent true) => {
        fn connection_lost_mut(&mut self) -> Option<&mut ConnectionLostError> {
            match self {
                Self::ConnectionLost(e) => Some(e),
                _ => None,
            }
        }
    };
    (@prior true) => {
        fn with_prior_uncertainty(self, prior_uncertainty: bool) -> Self {
            if prior_uncertainty && self.has_no_side_effects() {
                Self::IndefiniteAppend(IndefiniteAppendError::new(self))
            } else {
                self
            }
        }
    };
}

impl_transport_error!(
    RequestError,
    from_http_response: |status, body, ctx| RequestError::Server(ServerError::from_response(status, body, ctx)),
    unsent_conn_lost: true,
);
impl_transport_error!(
    ReadError,
    from_http_response: parse_read_response,
    read_only: true,
);
impl_transport_error!(
    ReadSessionError,
    from_http_response: parse_read_response,
    read_only: true,
);
impl_transport_error!(
    AppendError,
    from_http_response: parse_append_response,
    unsent_conn_lost: true,
    prior_uncertainty: true,
);
impl_transport_error!(
    AppendSessionError,
    from_http_response: parse_append_response,
    unsent_conn_lost: true,
    prior_uncertainty: true,
);

pub(crate) fn classify_http_error<E: TransportError>(
    err: client::HttpError,
    context: ErrorContext,
) -> E {
    match err {
        client::HttpError::Connect(message) => ConnectError::new(message, context).into(),
        client::HttpError::Timeout => TimeoutError::new("request timed out", context).into(),
        client::HttpError::Closed => AbortedError::new("client closed", context).into(),
        client::HttpError::Transport(hyper_err) => {
            let detail = client::format_error_chain(&hyper_err);
            if hyper_err.is_parse() {
                return ProtocolError::new(detail, context).into();
            }
            let refused = source_err::<h2::Error>(&hyper_err)
                .is_some_and(|e| e.reason() == Some(h2::Reason::REFUSED_STREAM));
            ConnectionLostError::new(detail, refused, context).into()
        }
        client::HttpError::RequestBuild(message) => {
            ProtocolError::new(format!("request build: {message}"), context).into()
        }
        client::HttpError::RequestCompression(message) => {
            ProtocolError::new(format!("request compression: {message}"), context).into()
        }
        client::HttpError::ResponseCompression(message) => {
            ProtocolError::new(format!("response compression: {message}"), context).into()
        }
        client::HttpError::ResponseTooLarge(limit) => {
            ProtocolError::new(format!("response exceeded {limit} byte limit"), context).into()
        }
        client::HttpError::ResponseDecode(error) => {
            ProtocolError::new(format!("response decode: {error}"), context).into()
        }
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
        assert_eq!(mismatch.known_code(), None);
        assert!(mismatch.is_retryable());
        assert!(!mismatch.has_no_side_effects());

        let non_retryable_status = response(StatusCode::BAD_REQUEST, Some("unavailable"));
        assert_eq!(non_retryable_status.known_code(), None);
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
            classify_http_error::<RequestError>(
                client::HttpError::Connect("dns failed".to_owned()),
                ErrorContext::default()
            ),
            RequestError::Connect(ConnectError { message, .. }) if message.contains("dns failed")
        ));
        assert!(matches!(
            classify_http_error::<RequestError>(
                client::HttpError::RequestBuild("bad request".to_owned()),
                ErrorContext::default()
            ),
            RequestError::Protocol(ProtocolError { message, .. }) if message.contains("bad request")
        ));
        assert!(matches!(
            classify_http_error::<RequestError>(
                client::HttpError::ResponseCompression("corrupt".to_owned()),
                ErrorContext::default()
            ),
            RequestError::Protocol(ProtocolError { message, .. }) if message.contains("corrupt")
        ));
        assert!(matches!(
            classify_http_error::<RequestError>(
                client::HttpError::ResponseTooLarge(1024),
                ErrorContext::default()
            ),
            RequestError::Protocol(ProtocolError { message, .. }) if message.contains("1024")
        ));
        let json_error = serde_json::from_slice::<serde_json::Value>(b"{")
            .expect_err("invalid JSON should fail");
        assert!(matches!(
            classify_http_error::<RequestError>(
                client::HttpError::ResponseDecode(json_error),
                ErrorContext::default()
            ),
            RequestError::Protocol(_)
        ));
        assert!(matches!(
            classify_http_error::<RequestError>(
                client::HttpError::Timeout,
                ErrorContext::default()
            ),
            RequestError::Timeout(_)
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

    // spec: r1 E4
    #[test]
    fn validation_error_exposes_e4_predicates() {
        let err = ValidationError::from("invalid input");
        assert_eq!(err.message(), "invalid input");
        assert!(!err.is_retryable());
        assert!(err.has_no_side_effects());
    }

    // spec: r1 E3, T9
    #[tokio::test]
    async fn hyper_dispatch_gone_maps_to_connection_lost_not_protocol() {
        #[derive(Clone, Default)]
        struct DropRequestTaskExecutor(Arc<std::sync::atomic::AtomicUsize>);
        impl<F> hyper::rt::Executor<F> for DropRequestTaskExecutor
        where
            F: std::future::Future + Send + 'static,
            F::Output: Send + 'static,
        {
            fn execute(&self, fut: F) {
                // Allow hyper's initial h2 connection task to run, then drop the per-request
                // task to simulate runtime teardown / dispatch drop (`User::DispatchGone`).
                if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    tokio::spawn(fut);
                } else {
                    drop(fut);
                }
            }
        }

        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let _conn = h2::server::handshake(server_io).await;
            std::future::pending::<()>().await;
        });
        let (mut sender, mut conn) = hyper::client::conn::http2::handshake(
            DropRequestTaskExecutor::default(),
            hyper_util::rt::TokioIo::new(client_io),
        )
        .await
        .unwrap();
        let req = http::Request::builder()
            .uri("http://localhost/test")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp_fut = sender.send_request(req);
        let hyper_err = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::select! {
                res = resp_fut => res.unwrap_err(),
                res = &mut conn => panic!("conn exited before request errored: {res:?}"),
            }
        })
        .await
        .expect("hyper_dispatch_gone test timed out");
        assert!(
            hyper_err.is_user(),
            "expected hyper User::DispatchGone (`is_user() == true`), got {hyper_err:?}"
        );
        let classified = classify_http_error::<RequestError>(
            client::HttpError::Transport(hyper_err),
            ErrorContext::default(),
        );
        assert!(
            matches!(classified, RequestError::ConnectionLost(_)),
            "expected ConnectionLostError, got {classified:?}"
        );
        assert!(classified.is_retryable());
        server_task.abort();
    }

    #[rstest::rstest]
    #[case(StatusCode::FORBIDDEN, "permission_denied", false, false)]
    #[case(StatusCode::FORBIDDEN, "permission_denied", true, true)]
    #[case(StatusCode::SERVICE_UNAVAILABLE, "unavailable", false, false)]
    #[case(StatusCode::SERVICE_UNAVAILABLE, "unavailable", true, false)]
    #[case(StatusCode::TOO_MANY_REQUESTS, "rate_limited", true, true)]
    #[test]
    fn unary_append_failure_preserves_uncertainty_and_final_error(
        #[case] status: StatusCode,
        #[case] code: &str,
        #[case] prior_uncertainty: bool,
        #[case] wrapped: bool,
    ) {
        let error = AppendError::Server(response(status, Some(code)))
            .with_prior_uncertainty(prior_uncertainty);
        assert_eq!(matches!(error, AppendError::IndefiniteAppend(_)), wrapped);
        if wrapped {
            assert!(error.server_error().is_none());
            assert!(!error.has_no_side_effects());
            let latest = error
                .source()
                .unwrap()
                .downcast_ref::<AppendError>()
                .unwrap();
            assert!(latest.has_no_side_effects());
            let server = latest.server_error().unwrap();
            assert_eq!(
                (server.status, server.code.as_deref()),
                (status, Some(code))
            );
            assert_eq!(server.message, "test");
            assert_eq!(error.is_retryable(), server.is_retryable());
            assert_eq!(
                error.to_string(),
                format!(
                    "append may have taken effect in an earlier attempt; final attempt failed: {latest}"
                )
            );
        } else {
            let server = error.server_error().unwrap();
            assert_eq!(
                (server.status, server.code.as_deref()),
                (status, Some(code))
            );
            assert_eq!(server.message, "test");
            assert_eq!(error.is_retryable(), server.is_retryable());
            assert_eq!(error.has_no_side_effects(), server.has_no_side_effects());
        }
    }

    #[rstest::rstest]
    #[case::condition_failed(
        AppendError::from_http_response(
            StatusCode::PRECONDITION_FAILED,
            br#"{"seq_num_mismatch":42}"#,
            ErrorContext::default(),
        ),
        "assignable_seq_num=42"
    )]
    #[case::unrecognized_condition(
        AppendError::from_terminal_message(
            TerminalMessage {
                status: 412,
                body: bytes::Bytes::from_static(br#"{"some_future_mismatch":7}"#),
            },
            ErrorContext::default(),
        ),
        r#"{"some_future_mismatch":7}"#
    )]
    #[case::invalid_access_token(
        AppendError::Validation(ValidationError("invalid access token: invalid header".to_owned())),
        "invalid access token: invalid header"
    )]
    #[test]
    fn unary_append_wraps_definite_terminal_errors(
        #[case] error: AppendError,
        #[case] expected_substr: &str,
    ) {
        assert!(error.has_no_side_effects());
        let error = error.with_prior_uncertainty(true);
        assert!(matches!(error, AppendError::IndefiniteAppend(_)));
        assert!(!error.has_no_side_effects());
        assert!(!error.is_retryable());
        assert!(error.server_error().is_none());
        let latest = error
            .source()
            .unwrap()
            .downcast_ref::<AppendError>()
            .unwrap();
        assert!(latest.has_no_side_effects());
        assert!(
            latest.to_string().contains(expected_substr),
            "got: {latest}"
        );
    }
}
