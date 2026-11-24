//! Errors returned by the SDK.
//!
//! Client construction and retry overrides (`S2::new`, `S2::from_env`, `with_retry`) return
//! [`ValidationError`], and synchronous session openers (`append_session`, `producer`,
//! `read_session`, `read_batch_session`) return [`ClientClosedError`]. Every other operation
//! returns the narrowest error enum for its surface ([`RequestError`], [`ReadError`],
//! [`AppendError`], [`AppendSessionError`], or [`ReadSessionError`]), and every operation error
//! converts into the catch-all [`S2Error`].
//!
//! Every error exposes [`is_retryable`](S2Error::is_retryable) (whether repeating the operation may
//! succeed) and [`has_no_side_effects`](S2Error::has_no_side_effects) (whether the failed attempt
//! certainly had no side effects).

use std::{fmt, sync::Arc};

pub use http::StatusCode;
pub use s2_api::v1::error::ErrorCode;
use s2_api::v1::stream::{TailResponse, s2s::TerminalMessage};
/// Input or configuration validation error.
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

    fn is_read_only(&self) -> bool {
        self.0.as_ref().is_some_and(|inner| inner.read_only)
    }

    fn set_read_only(&mut self) {
        self.set_read_only_flag(true);
    }

    fn set_read_only_flag(&mut self, read_only: bool) {
        if self.is_read_only() != read_only {
            self.inner_mut().read_only = read_only;
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

    fn merge_missing(&mut self, other: &ErrorContext) {
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

    fn format_with(&self, f: &mut fmt::Formatter<'_>, detail: impl fmt::Display) -> fmt::Result {
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

    pub(crate) fn format_validation(&self, detail: impl fmt::Display) -> ValidationError {
        struct ContextDisplay<'a, D>(&'a ErrorContext, D);
        impl<D: fmt::Display> fmt::Display for ContextDisplay<'_, D> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.format_with(f, &self.1)
            }
        }
        ValidationError(ContextDisplay(self, detail).to_string())
    }

    fn debug_fields(&self, ds: &mut fmt::DebugStruct<'_, '_>) {
        if let Some(inner) = self.0.as_deref() {
            if let Some(op) = inner.operation {
                ds.field("operation", &op);
            }
            if let Some(basin) = inner.basin.as_deref() {
                ds.field("basin", &basin);
            }
            if let Some(stream) = inner.stream.as_deref() {
                ds.field("stream", &stream);
            }
            if inner.attempts > 1 {
                ds.field("attempts", &inner.attempts);
            }
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
#[derive(Clone)]
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

impl fmt::Debug for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("ServerError");
        ds.field("status", &self.status)
            .field("code", &self.code)
            .field("message", &self.message)
            .field("has_no_side_effects", &self.has_no_side_effects());
        self.context.debug_fields(&mut ds);
        ds.finish()
    }
}

impl ServerError {
    /// Construct a [`ServerError`] with the given HTTP status and message.
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code: None,
            message: message.into(),
            context: ErrorContext::default(),
        }
    }

    /// Attach a structured server error code to this error.
    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

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
    #[must_use]
    pub fn known_code(&self) -> Option<ErrorCode> {
        self.code
            .as_deref()
            .and_then(|c| c.parse::<ErrorCode>().ok())
            .filter(|known| known.status() == self.status)
    }

    /// Whether this server error has the given recognized [`ErrorCode`] (paired with its defined
    /// HTTP status).
    #[must_use]
    pub fn has_error_code(&self, code: ErrorCode) -> bool {
        self.known_code() == Some(code)
    }

    /// Whether retrying the request may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
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
    #[must_use]
    pub fn has_no_side_effects(&self) -> bool {
        self.context.is_read_only()
            || self.status == StatusCode::PRECONDITION_FAILED
            || self
                .known_code()
                .is_some_and(ErrorCode::has_no_side_effects)
    }

    fn is_authentication_error(&self) -> bool {
        self.has_error_code(ErrorCode::Authn)
    }

    fn is_server_draining(&self) -> bool {
        self.has_error_code(ErrorCode::ServerDraining)
    }

    fn is_hot_server(&self) -> bool {
        self.has_error_code(ErrorCode::HotServer)
    }

    fn should_retire_connection(&self) -> bool {
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
#[derive(Clone)]
#[non_exhaustive]
pub struct SeqNumMismatchError {
    /// The sequence number the stream will assign next.
    pub assignable_seq_num: u64,
    server: Box<ServerError>,
}

impl fmt::Debug for SeqNumMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("SeqNumMismatchError");
        ds.field("assignable_seq_num", &self.assignable_seq_num)
            .field("status", &self.server.status);
        self.server.context.debug_fields(&mut ds);
        ds.finish()
    }
}

impl SeqNumMismatchError {
    /// Construct a [`SeqNumMismatchError`] for the given next assignable sequence number.
    ///
    /// Attaches a default HTTP `412` [`ServerError`]. Intended for building fixtures in
    /// downstream tests.
    #[must_use]
    pub fn new(assignable_seq_num: u64) -> Self {
        Self::from_server(
            assignable_seq_num,
            ServerError::new(
                StatusCode::PRECONDITION_FAILED,
                format!("sequence number mismatch (assignable_seq_num={assignable_seq_num})"),
            ),
        )
    }

    pub(crate) fn from_server(assignable_seq_num: u64, server: ServerError) -> Self {
        Self {
            assignable_seq_num,
            server: Box::new(server),
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.server.context.merge_missing(context);
        self
    }

    /// Return the underlying HTTP `412` [`ServerError`].
    #[must_use]
    pub fn server_error(&self) -> &ServerError {
        &self.server
    }

    /// Whether retrying the request may succeed (always `false`).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects (always `true`).
    #[must_use]
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
#[derive(Clone)]
#[non_exhaustive]
pub struct FencingTokenMismatchError {
    /// The stream's current fencing token.
    pub current_fencing_token: FencingToken,
    server: Box<ServerError>,
}

impl fmt::Debug for FencingTokenMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("FencingTokenMismatchError");
        ds.field("current_fencing_token", &self.current_fencing_token)
            .field("status", &self.server.status);
        self.server.context.debug_fields(&mut ds);
        ds.finish()
    }
}

impl FencingTokenMismatchError {
    /// Construct a [`FencingTokenMismatchError`] for the given current fencing token.
    ///
    /// Attaches a default HTTP `412` [`ServerError`]. Intended for building fixtures in
    /// downstream tests.
    #[must_use]
    pub fn new(current_fencing_token: FencingToken) -> Self {
        let server = ServerError::new(
            StatusCode::PRECONDITION_FAILED,
            format!(
                "fencing token mismatch (current_fencing_token={:?})",
                &*current_fencing_token
            ),
        );
        Self::from_server(current_fencing_token, server)
    }

    pub(crate) fn from_server(current_fencing_token: FencingToken, server: ServerError) -> Self {
        Self {
            current_fencing_token,
            server: Box::new(server),
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.server.context.merge_missing(context);
        self
    }

    /// Return the underlying HTTP `412` [`ServerError`].
    #[must_use]
    pub fn server_error(&self) -> &ServerError {
        &self.server
    }

    /// Whether retrying the request may succeed (always `false`).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects (always `true`).
    #[must_use]
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
#[derive(Clone)]
#[non_exhaustive]
pub struct ReadUnwrittenError {
    /// The stream's current tail position.
    pub tail: StreamPosition,
    server: Box<ServerError>,
}

impl fmt::Debug for ReadUnwrittenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("ReadUnwrittenError");
        ds.field("tail", &self.tail)
            .field("status", &self.server.status);
        self.server.context.debug_fields(&mut ds);
        ds.finish()
    }
}

impl ReadUnwrittenError {
    /// Construct a [`ReadUnwrittenError`] for the given stream tail position.
    ///
    /// Attaches a default HTTP `416` [`ServerError`]. Intended for building fixtures in
    /// downstream tests.
    #[must_use]
    pub fn new(tail: StreamPosition) -> Self {
        Self::from_server(
            tail,
            ServerError::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                format!("read from unwritten position (tail={tail})"),
            ),
        )
    }

    pub(crate) fn from_server(tail: StreamPosition, server: ServerError) -> Self {
        Self {
            tail,
            server: Box::new(server.into_read_only()),
        }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.server.context.merge_missing(context);
        self
    }

    /// Return the underlying HTTP `416` [`ServerError`].
    #[must_use]
    pub fn server_error(&self) -> &ServerError {
        &self.server
    }

    /// Whether retrying the request may succeed (always `false`).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects (always `true`).
    #[must_use]
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
            debug_no_side_effects: $debug_nse:expr,
            $(into_read_only: $into_ro:ident,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone)]
        #[non_exhaustive]
        pub struct $name {
            #[doc = $field_doc]
            pub message: String,
            pub(crate) context: ErrorContext,
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut ds = f.debug_struct(stringify!($name));
                ds.field("message", &self.message);
                if $debug_nse {
                    ds.field("has_no_side_effects", &self.has_no_side_effects());
                }
                self.context.debug_fields(&mut ds);
                ds.finish()
            }
        }

        impl $name {
            /// Construct this error with the given diagnostic message.
            ///
            /// Intended for building fixtures in downstream tests.
            #[must_use]
            pub fn new(message: impl Into<String>) -> Self {
                Self::new_with_context(message, ErrorContext::default())
            }

            pub(crate) fn new_with_context(
                message: impl Into<String>,
                context: ErrorContext,
            ) -> Self {
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
                /// Mark whether the failure occurred on a read-only operation with no side effects.
                ///
                /// Intended for building fixtures in downstream tests.
                #[must_use]
                pub fn with_no_side_effects(mut self, no_side_effects: bool) -> Self {
                    self.context.set_read_only_flag(no_side_effects);
                    self
                }

                pub(crate) fn $into_ro(mut self) -> Self {
                    self.context.set_read_only();
                    self
                }
            )?

            #[doc = $retryable_doc]
            #[must_use]
            pub fn is_retryable(&self) -> bool {
                $retryable
            }

            #[doc = $no_side_effects_doc]
            #[must_use]
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
        debug_no_side_effects: false,
    }
}

/// A request or connection broke, or a response ended prematurely.
#[derive(Clone)]
#[non_exhaustive]
pub struct ConnectionLostError {
    /// Diagnostic detail describing the transport failure.
    pub message: String,
    pub(crate) no_side_effects: bool,
    pub(crate) context: ErrorContext,
}

impl fmt::Debug for ConnectionLostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("ConnectionLostError");
        ds.field("message", &self.message)
            .field("has_no_side_effects", &self.has_no_side_effects());
        self.context.debug_fields(&mut ds);
        ds.finish()
    }
}

impl ConnectionLostError {
    /// Construct a [`ConnectionLostError`] with the given diagnostic message.
    ///
    /// Defaults [`has_no_side_effects`](Self::has_no_side_effects) to `false` (indefinite); call
    /// [`with_no_side_effects`](Self::with_no_side_effects) to mark an unsent or server-refused
    /// failure as definite. Intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self::new_with_context(message, false, ErrorContext::default())
    }

    /// Mark whether the connection failure occurred before any side effects were possible.
    #[must_use]
    pub fn with_no_side_effects(mut self, no_side_effects: bool) -> Self {
        self.no_side_effects = no_side_effects;
        if !no_side_effects {
            self.context.set_read_only_flag(false);
        }
        self
    }

    pub(crate) fn new_with_context(
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
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        true
    }

    /// Whether the failed attempt certainly had no side effects.
    ///
    /// True for read-only operations, when nothing unacked was sent before the connection broke,
    /// or when the server reported the stream unprocessed (such as HTTP/2 `REFUSED_STREAM`).
    #[must_use]
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
        debug_no_side_effects: true,
        into_read_only: into_read_only,
    }
}

/// A successful response or session message could not be decoded or violated an SDK check.
#[derive(Clone)]
#[non_exhaustive]
pub struct ProtocolError {
    /// Diagnostic detail describing the protocol failure.
    pub message: String,
    pub(crate) no_side_effects: bool,
    pub(crate) context: ErrorContext,
}

impl fmt::Debug for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("ProtocolError");
        ds.field("message", &self.message)
            .field("has_no_side_effects", &self.has_no_side_effects());
        self.context.debug_fields(&mut ds);
        ds.finish()
    }
}

impl ProtocolError {
    /// Construct a [`ProtocolError`] with the given diagnostic message.
    ///
    /// Defaults [`has_no_side_effects`](Self::has_no_side_effects) to `false` (indefinite); call
    /// [`with_no_side_effects`](Self::with_no_side_effects) to mark a local pre-send failure as
    /// definite. Intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self::new_with_context(message, ErrorContext::default())
    }

    /// Mark whether the protocol failure occurred before any side effects were possible.
    #[must_use]
    pub fn with_no_side_effects(mut self, no_side_effects: bool) -> Self {
        self.no_side_effects = no_side_effects;
        if !no_side_effects {
            self.context.set_read_only_flag(false);
        }
        self
    }

    pub(crate) fn new_with_context(message: impl Into<String>, context: ErrorContext) -> Self {
        Self {
            message: message.into(),
            no_side_effects: false,
            context,
        }
    }

    /// Construct a protocol error that occurred strictly before any bytes could be sent
    /// (such as local frame encoding on `submit()`), guaranteeing no side effects (`Terms`/`E3`).
    pub(crate) fn new_definite(message: impl Into<String>, context: ErrorContext) -> Self {
        Self {
            message: message.into(),
            no_side_effects: true,
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
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects.
    #[must_use]
    pub fn has_no_side_effects(&self) -> bool {
        self.no_side_effects || self.context.is_read_only()
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
#[derive(Clone)]
pub struct ClientClosedError {
    pub(crate) context: ErrorContext,
}

impl fmt::Debug for ClientClosedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("ClientClosedError");
        self.context.debug_fields(&mut ds);
        ds.finish()
    }
}

impl Default for ClientClosedError {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientClosedError {
    /// Construct a [`ClientClosedError`].
    ///
    /// Intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_context(ErrorContext::default())
    }

    pub(crate) fn new_with_context(context: ErrorContext) -> Self {
        Self { context }
    }

    pub(crate) fn with_context(mut self, context: &ErrorContext) -> Self {
        self.context.merge_missing(context);
        self
    }

    /// Whether retrying the request may succeed (always `false`).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects (always `true`).
    #[must_use]
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
        debug_no_side_effects: true,
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
    /// Construct an [`IndefiniteAppendError`] wrapping the final attempt's definite error.
    ///
    /// Intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(final_attempt_error: E) -> Self {
        Self {
            final_attempt_error: Box::new(final_attempt_error),
        }
    }

    /// Return the definite error returned by the final attempt.
    #[must_use]
    pub fn final_attempt_error(&self) -> &E {
        &self.final_attempt_error
    }

    /// Consume this wrapper and return the definite error returned by the final attempt.
    #[must_use]
    pub fn into_final_attempt_error(self) -> E {
        *self.final_attempt_error
    }

    /// Whether the append certainly had no side effects (always `false`).
    #[must_use]
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
                #[must_use]
                pub fn is_retryable(&self) -> bool {
                    self.final_attempt_error.is_retryable()
                }
            }
        )+
    };
}

impl_indefinite_is_retryable!(AppendError, AppendSessionError, S2Error);

impl From<IndefiniteAppendError<AppendError>> for S2Error {
    fn from(error: IndefiniteAppendError<AppendError>) -> Self {
        Self::IndefiniteAppend(error.map(S2Error::from))
    }
}

impl From<IndefiniteAppendError<AppendSessionError>> for S2Error {
    fn from(error: IndefiniteAppendError<AppendSessionError>) -> Self {
        Self::IndefiniteAppend(error.map(S2Error::from))
    }
}

impl From<IndefiniteAppendError<AppendError>> for AppendSessionError {
    fn from(error: IndefiniteAppendError<AppendError>) -> Self {
        Self::IndefiniteAppend(error.map(AppendSessionError::from))
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
#[derive(Clone)]
pub struct SessionClosedError<E> {
    failure: Option<Box<E>>,
    pub(crate) context: ErrorContext,
}

impl<E: fmt::Debug> fmt::Debug for SessionClosedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("SessionClosedError");
        ds.field("failure", &self.failure);
        if self.failure.is_none() {
            self.context.debug_fields(&mut ds);
        }
        ds.finish()
    }
}

impl<E> SessionClosedError<E> {
    /// Construct a [`SessionClosedError`] with an optional underlying session failure.
    ///
    /// Pass `None` for a clean close or `Some(failure)` when the session closed due to an error.
    /// Intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(failure: Option<E>) -> Self {
        Self::new_with_context(failure, ErrorContext::default())
    }

    pub(crate) fn new_with_context(failure: Option<E>, context: ErrorContext) -> Self {
        Self {
            failure: failure.map(Box::new),
            context,
        }
    }

    /// Return the session's failure, if it closed due to an error.
    #[must_use]
    pub fn failure(&self) -> Option<&E> {
        self.failure.as_deref()
    }

    /// Consume this wrapper and return the session's failure, if any.
    #[must_use]
    pub fn into_failure(self) -> Option<E> {
        self.failure.map(|e| *e)
    }

    /// Whether retrying the operation on this closed session may succeed (always `false`).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the rejected call certainly had no side effects (always `true`).
    #[must_use]
    pub fn has_no_side_effects(&self) -> bool {
        true
    }

    pub(crate) fn map<U>(self, f: impl FnOnce(E) -> U) -> SessionClosedError<U> {
        SessionClosedError {
            failure: self.failure.map(|e| Box::new(f(*e))),
            context: self.context,
        }
    }

    pub(crate) fn with_context(
        mut self,
        context: &ErrorContext,
        map_failure: impl FnOnce(E, &ErrorContext) -> E,
    ) -> Self {
        self.context.merge_missing(context);
        self.failure = self
            .failure
            .map(|failure| Box::new(map_failure(*failure, context)));
        self
    }
}

impl From<SessionClosedError<AppendSessionError>> for S2Error {
    fn from(error: SessionClosedError<AppendSessionError>) -> Self {
        Self::SessionClosed(error.map(S2Error::from))
    }
}

impl From<SessionClosedError<ReadSessionError>> for S2Error {
    fn from(error: SessionClosedError<ReadSessionError>) -> Self {
        Self::SessionClosed(error.map(S2Error::from))
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
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => e.is_retryable(),
        }
    };
}

macro_rules! delegate_has_no_side_effects {
    ($self:expr, [$($variant:ident),* $(,)?]) => {
        match $self {
            $(Self::$variant(e) => e.has_no_side_effects(),)*
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(_) => true,
        }
    };
}

macro_rules! impl_read_only_from {
    ($dst:ident { $($variant:ident($ty:ty)),* $(,)? }) => {
        $(
            impl From<$ty> for $dst {
                fn from(error: $ty) -> Self {
                    Self::$variant(error.into_read_only())
                }
            }
        )*
    };
}

// Both `impl_read_only_from!` and `read_only` arms below mark read-origin leaf errors as
// definite: `From<Leaf>` covers SDK/builder conversions, while `read_only` covers values
// constructed directly via public tuple variants (e.g.
// `ReadError::Timeout(TimeoutError::new(..))`).
macro_rules! impl_error_upcast {
    (
        $src:ident => $dst:ident {
            direct: [$($direct:ident),* $(,)?],
            $(read_only: [$($ro:ident),* $(,)?],)?
            mapped: [$($mapped:ident),* $(,)?],
        }
    ) => {
        impl From<$src> for $dst {
            fn from(error: $src) -> Self {
                match error {
                    $($src::$direct(e) => Self::$direct(e),)*
                    $($($src::$ro(e) => Self::$ro(e.into_read_only()),)*)?
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
    AccessTokenProvider(#[source] crate::types::AccessTokenProviderError),
}

impl S2Error {
    /// Whether retrying the operation may succeed.
    #[must_use]
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
                Validation,
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
    #[must_use]
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
                Validation,
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
    #[must_use]
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            Self::SeqNumMismatch(e) => Some(&e.server),
            Self::FencingTokenMismatch(e) => Some(&e.server),
            Self::ReadUnwritten(e) => Some(&e.server),
            _ => None,
        }
    }

    /// Return the recognized server [`ErrorCode`] if this is a direct server error with a known
    /// code paired with its defined HTTP status.
    #[must_use]
    pub fn known_code(&self) -> Option<ErrorCode> {
        self.server_error().and_then(ServerError::known_code)
    }

    /// Whether this is a direct server error matching `code` (paired with its defined HTTP status).
    #[must_use]
    pub fn has_error_code(&self, code: ErrorCode) -> bool {
        self.known_code() == Some(code)
    }

    /// Return the final attempt's error if this is [`IndefiniteAppend`](Self::IndefiniteAppend).
    #[must_use]
    pub fn final_attempt_error(&self) -> Option<&Self> {
        match self {
            Self::IndefiniteAppend(e) => Some(e.final_attempt_error()),
            _ => None,
        }
    }

    /// Return the session failure if this is [`SessionClosed`](Self::SessionClosed).
    #[must_use]
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
    /// The in-flight request was aborted (for example by client `close()`).
    #[error(transparent)]
    Aborted(#[from] AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(#[source] crate::types::AccessTokenProviderError),
}

impl RequestError {
    /// Whether retrying the operation may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        delegate_is_retryable!(
            self,
            [
                Server,
                Validation,
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
    #[must_use]
    pub fn has_no_side_effects(&self) -> bool {
        delegate_has_no_side_effects!(
            self,
            [
                Server,
                Validation,
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
    #[must_use]
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            _ => None,
        }
    }

    /// Return the recognized server [`ErrorCode`] if this is a server error with a known code
    /// paired with its defined HTTP status.
    #[must_use]
    pub fn known_code(&self) -> Option<ErrorCode> {
        self.server_error().and_then(ServerError::known_code)
    }

    /// Whether this is a server error matching `code` (paired with its defined HTTP status).
    #[must_use]
    pub fn has_error_code(&self, code: ErrorCode) -> bool {
        self.known_code() == Some(code)
    }
}

impl_error_upcast!(RequestError => S2Error {
    direct: [Server, Validation, Connect, ConnectionLost, Timeout, Protocol, ClientClosed, Aborted],
    mapped: [],
});

/// Errors returned by unary read and tail-check operations.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// A non-2xx HTTP response from the server.
    #[error(transparent)]
    Server(ServerError),
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
    ConnectionLost(ConnectionLostError),
    /// The request timed out.
    #[error(transparent)]
    Timeout(TimeoutError),
    /// A successful response violated protocol checks.
    #[error(transparent)]
    Protocol(ProtocolError),
    /// A call was made on a closed client.
    #[error(transparent)]
    ClientClosed(#[from] ClientClosedError),
    /// The in-flight read was aborted (for example by client `close()`).
    #[error(transparent)]
    Aborted(AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(#[source] crate::types::AccessTokenProviderError),
}

impl_read_only_from!(ReadError {
    Server(ServerError),
    ConnectionLost(ConnectionLostError),
    Timeout(TimeoutError),
    Protocol(ProtocolError),
    Aborted(AbortedError),
});

impl ReadError {
    /// Whether retrying the operation may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        delegate_is_retryable!(
            self,
            [
                Server,
                ReadUnwritten,
                Validation,
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
    #[must_use]
    pub fn has_no_side_effects(&self) -> bool {
        true
    }

    /// Return the underlying [`ServerError`], including for [`ReadUnwritten`](Self::ReadUnwritten).
    #[must_use]
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            Self::ReadUnwritten(e) => Some(&e.server),
            _ => None,
        }
    }

    /// Return the recognized server [`ErrorCode`] if this is a server error with a known code
    /// paired with its defined HTTP status.
    #[must_use]
    pub fn known_code(&self) -> Option<ErrorCode> {
        self.server_error().and_then(ServerError::known_code)
    }

    /// Whether this is a server error matching `code` (paired with its defined HTTP status).
    #[must_use]
    pub fn has_error_code(&self, code: ErrorCode) -> bool {
        self.known_code() == Some(code)
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
    /// The in-flight append was aborted (for example by client `close()`).
    #[error(transparent)]
    Aborted(#[from] AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(#[source] crate::types::AccessTokenProviderError),
}

impl AppendError {
    /// Whether retrying the operation may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        delegate_is_retryable!(
            self,
            [
                Server,
                SeqNumMismatch,
                FencingTokenMismatch,
                IndefiniteAppend,
                Validation,
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
    #[must_use]
    pub fn has_no_side_effects(&self) -> bool {
        delegate_has_no_side_effects!(
            self,
            [
                Server,
                SeqNumMismatch,
                FencingTokenMismatch,
                IndefiniteAppend,
                Validation,
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
    #[must_use]
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            Self::SeqNumMismatch(e) => Some(&e.server),
            Self::FencingTokenMismatch(e) => Some(&e.server),
            _ => None,
        }
    }

    /// Return the recognized server [`ErrorCode`] if this is a direct server error with a known
    /// code paired with its defined HTTP status.
    #[must_use]
    pub fn known_code(&self) -> Option<ErrorCode> {
        self.server_error().and_then(ServerError::known_code)
    }

    /// Whether this is a direct server error matching `code` (paired with its defined HTTP status).
    #[must_use]
    pub fn has_error_code(&self, code: ErrorCode) -> bool {
        self.known_code() == Some(code)
    }

    /// Return the final attempt's error if this is [`IndefiniteAppend`](Self::IndefiniteAppend).
    #[must_use]
    pub fn final_attempt_error(&self) -> Option<&Self> {
        match self {
            Self::IndefiniteAppend(e) => Some(e.final_attempt_error()),
            _ => None,
        }
    }
}

impl_error_upcast!(AppendError => S2Error {
    direct: [Server, SeqNumMismatch, FencingTokenMismatch, Validation, Connect, ConnectionLost, Timeout, Protocol, ClientClosed, Aborted],
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
    /// The session closed or began closing before handling the call, or closed without sending
    /// this batch (including batches queued behind a definite rejection).
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
    /// The session was aborted (dropped, explicitly aborted, or client closed).
    #[error(transparent)]
    Aborted(#[from] AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(#[source] crate::types::AccessTokenProviderError),
}

impl AppendSessionError {
    /// Whether retrying the operation may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        delegate_is_retryable!(
            self,
            [
                Server,
                SeqNumMismatch,
                FencingTokenMismatch,
                IndefiniteAppend,
                SessionClosed,
                Validation,
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
    #[must_use]
    pub fn has_no_side_effects(&self) -> bool {
        delegate_has_no_side_effects!(
            self,
            [
                Server,
                SeqNumMismatch,
                FencingTokenMismatch,
                IndefiniteAppend,
                SessionClosed,
                Validation,
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
    #[must_use]
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            Self::SeqNumMismatch(e) => Some(&e.server),
            Self::FencingTokenMismatch(e) => Some(&e.server),
            _ => None,
        }
    }

    /// Return the recognized server [`ErrorCode`] if this is a direct server error with a known
    /// code paired with its defined HTTP status.
    #[must_use]
    pub fn known_code(&self) -> Option<ErrorCode> {
        self.server_error().and_then(ServerError::known_code)
    }

    /// Whether this is a direct server error matching `code` (paired with its defined HTTP status).
    #[must_use]
    pub fn has_error_code(&self, code: ErrorCode) -> bool {
        self.known_code() == Some(code)
    }

    /// Return the final attempt's error if this is [`IndefiniteAppend`](Self::IndefiniteAppend).
    #[must_use]
    pub fn final_attempt_error(&self) -> Option<&Self> {
        match self {
            Self::IndefiniteAppend(e) => Some(e.final_attempt_error()),
            _ => None,
        }
    }

    /// Return the session failure if this is [`SessionClosed`](Self::SessionClosed).
    #[must_use]
    pub fn failure(&self) -> Option<&Self> {
        match self {
            Self::SessionClosed(e) => e.failure(),
            _ => None,
        }
    }

    pub(crate) fn with_context(self, context: &ErrorContext) -> Self {
        match self {
            Self::Server(e) => Self::Server(e.with_context(context)),
            Self::SeqNumMismatch(e) => Self::SeqNumMismatch(e.with_context(context)),
            Self::FencingTokenMismatch(e) => Self::FencingTokenMismatch(e.with_context(context)),
            Self::IndefiniteAppend(e) => Self::IndefiniteAppend(e.map(|i| i.with_context(context))),
            Self::SessionClosed(e) => {
                Self::SessionClosed(e.with_context(context, Self::with_context))
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
    mapped: [IndefiniteAppend],
});

impl_error_upcast!(AppendSessionError => S2Error {
    direct: [Server, SeqNumMismatch, FencingTokenMismatch, Validation, Connect, ConnectionLost, Timeout, Protocol, ClientClosed, Aborted],
    mapped: [IndefiniteAppend, SessionClosed],
});

/// Errors returned by [`ReadSession`](crate::read_session::ReadSession),
/// [`ReadBatchSession`](crate::read_session::ReadBatchSession), and their
/// [`caught_up`](crate::read_session::ReadSession::caught_up) future.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ReadSessionError {
    /// A non-2xx HTTP response from the server (including session terminal frames).
    #[error(transparent)]
    Server(ServerError),
    /// The requested read position has not been written.
    #[error(transparent)]
    ReadUnwritten(#[from] ReadUnwrittenError),
    /// The session closed cleanly before catching up (surfaced by `caught_up()`).
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
    ConnectionLost(ConnectionLostError),
    /// Request or heartbeat timeout elapsed.
    #[error(transparent)]
    Timeout(TimeoutError),
    /// A response or session frame violated protocol checks.
    #[error(transparent)]
    Protocol(ProtocolError),
    /// A call was made on a closed client.
    #[error(transparent)]
    ClientClosed(#[from] ClientClosedError),
    /// The session was aborted (for example by client `close()`).
    #[error(transparent)]
    Aborted(AbortedError),
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(#[source] crate::types::AccessTokenProviderError),
}

impl_read_only_from!(ReadSessionError {
    Server(ServerError),
    ConnectionLost(ConnectionLostError),
    Timeout(TimeoutError),
    Protocol(ProtocolError),
    Aborted(AbortedError),
});

impl ReadSessionError {
    /// Whether retrying the operation may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        delegate_is_retryable!(
            self,
            [
                Server,
                ReadUnwritten,
                SessionClosed,
                Validation,
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
    #[must_use]
    pub fn has_no_side_effects(&self) -> bool {
        true
    }

    /// Return the underlying [`ServerError`], including for [`ReadUnwritten`](Self::ReadUnwritten).
    ///
    /// Returns `None` for [`SessionClosed`](Self::SessionClosed); inspect
    /// [`failure`](Self::failure) instead.
    #[must_use]
    pub fn server_error(&self) -> Option<&ServerError> {
        match self {
            Self::Server(e) => Some(e),
            Self::ReadUnwritten(e) => Some(&e.server),
            _ => None,
        }
    }

    /// Return the recognized server [`ErrorCode`] if this is a direct server error with a known
    /// code paired with its defined HTTP status.
    #[must_use]
    pub fn known_code(&self) -> Option<ErrorCode> {
        self.server_error().and_then(ServerError::known_code)
    }

    /// Whether this is a direct server error matching `code` (paired with its defined HTTP status).
    #[must_use]
    pub fn has_error_code(&self, code: ErrorCode) -> bool {
        self.known_code() == Some(code)
    }

    /// Return the session failure if this is [`SessionClosed`](Self::SessionClosed).
    #[must_use]
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
            Self::SessionClosed(e) => {
                Self::SessionClosed(e.with_context(&context, Self::with_context))
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
                return ProtocolError::new_with_context(
                    format!("unexpected non-error status code in terminal frame: {status}"),
                    context,
                )
                .into();
            }
            Err(err) => {
                return ProtocolError::new_with_context(
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

    fn is_server_draining(&self) -> bool {
        self.server_error()
            .is_some_and(ServerError::is_server_draining)
    }

    fn is_retryable_or_auth_refresh(&self, refreshes_tokens: bool) -> bool {
        self.is_retryable() || (refreshes_tokens && self.is_authentication_error())
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
                return SeqNumMismatchError::from_server(assignable_seq_num, server).into();
            }
            (None, Some(token)) => {
                let server = ServerError::from_response(status, body, context);
                return FencingTokenMismatchError::from_server(
                    FencingToken::from_server(token),
                    server,
                )
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
        return ReadUnwrittenError::from_server(StreamPosition::from_api(tail.tail), server).into();
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
        client::HttpError::Connect(message) => {
            ConnectError::new_with_context(message, context).into()
        }
        client::HttpError::Timeout => {
            TimeoutError::new_with_context("request timed out", context).into()
        }
        client::HttpError::Closed => {
            AbortedError::new_with_context("client closed", context).into()
        }
        client::HttpError::Transport(hyper_err) => {
            let detail = client::format_error_chain(&hyper_err);
            if hyper_err.is_parse() {
                return ProtocolError::new_with_context(detail, context).into();
            }
            let refused = find_source_err::<h2::Error>(&hyper_err)
                .is_some_and(|e| e.is_reset() && e.reason() == Some(h2::Reason::REFUSED_STREAM));
            ConnectionLostError::new_with_context(detail, refused, context).into()
        }
        client::HttpError::RequestBuild(message) => {
            ProtocolError::new_definite(format!("request build: {message}"), context).into()
        }
        client::HttpError::RequestCompression(message) => {
            ProtocolError::new_definite(format!("request compression: {message}"), context).into()
        }
        client::HttpError::ResponseCompression(message) => {
            ProtocolError::new_with_context(format!("response compression: {message}"), context)
                .into()
        }
        client::HttpError::ResponseTooLarge(limit) => ProtocolError::new_with_context(
            format!("response exceeded {limit} byte limit"),
            context,
        )
        .into(),
        client::HttpError::ResponseDecode(error) => {
            ProtocolError::new_with_context(format!("response decode: {error}"), context).into()
        }
    }
}

pub(crate) fn find_source_err<'a, T: std::error::Error + 'static>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a T> {
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
        let err = ServerError::new(status, "test");
        match code {
            Some(code) => err.with_code(code),
            None => err,
        }
    }

    // spec: r1 E3
    #[test]
    fn http_error_protocol_variants_classify_as_protocol() {
        let json_error = serde_json::from_slice::<serde_json::Value>(b"{")
            .expect_err("invalid JSON should fail");
        for (err, substr) in [
            (
                client::HttpError::RequestBuild("bad request".to_owned()),
                "bad request",
            ),
            (
                client::HttpError::ResponseCompression("corrupt".to_owned()),
                "corrupt",
            ),
            (client::HttpError::ResponseTooLarge(1024), "1024"),
            (client::HttpError::ResponseDecode(json_error), ""),
        ] {
            assert!(matches!(
                classify_http_error::<RequestError>(err, ErrorContext::default()),
                RequestError::Protocol(ProtocolError { message, .. }) if message.contains(substr)
            ));
        }
    }

    // spec: r1 E1, E5, E5a, E5b, E6
    #[test]
    fn wrapper_upcast_clean_close_and_retryable_indefinite_append() {
        let ctx = ErrorContext::stream("append", "my-basin", "my-stream", false);

        // Retryable definite error (`429 rate_limited`) wrapped in IndefiniteAppend preserves
        // `is_retryable() == true` while turning `has_no_side_effects()` to `false`, and preserves
        // `final_attempt_error()` / `source()` across `AppendError -> S2Error` upcast.
        let wrapped = AppendError::Server(response(
            StatusCode::TOO_MANY_REQUESTS,
            Some("rate_limited"),
        ))
        .with_prior_uncertainty(true);
        assert!(matches!(wrapped, AppendError::IndefiniteAppend(_)));
        assert!(wrapped.is_retryable());
        assert!(!wrapped.has_no_side_effects());
        assert!(wrapped.server_error().is_none());

        let s2_err: S2Error = wrapped.into();
        assert!(s2_err.is_retryable());
        assert!(!s2_err.has_no_side_effects());
        assert!(s2_err.server_error().is_none());
        assert!(matches!(
            s2_err.final_attempt_error(),
            Some(S2Error::Server(e)) if e.known_code() == Some(ErrorCode::RateLimited)
        ));
        assert!(
            s2_err
                .source()
                .expect("S2Error source set")
                .downcast_ref::<S2Error>()
                .is_some()
        );

        // Clean SessionClosed(None) has no source and formats with context.
        let closed_clean =
            AppendSessionError::SessionClosed(SessionClosedError::new_with_context(None, ctx));
        assert!(closed_clean.has_no_side_effects());
        assert!(!closed_clean.is_retryable());
        assert!(closed_clean.failure().is_none());
        assert!(closed_clean.source().is_none());
        assert!(closed_clean.to_string().contains("my-basin"));
    }

    // spec: r1 E1, E3
    #[test]
    fn read_errors_stay_definite_when_converted_to_s2_error() {
        let timeout = ReadError::Timeout(TimeoutError::new("timed out"));
        assert!(timeout.is_retryable());
        assert!(timeout.has_no_side_effects());
        let s2_err: S2Error = timeout.into();
        assert!(s2_err.is_retryable());
        assert!(s2_err.has_no_side_effects());
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

    #[test]
    fn pre_send_request_build_and_compression_errors_are_definite() {
        let ctx = ErrorContext::stream("append", "b", "s", false);
        for err in [
            client::HttpError::RequestBuild("bad header".into()),
            client::HttpError::RequestCompression("zstd failed".into()),
        ] {
            let classified = classify_http_error::<AppendError>(err, ctx.clone());
            assert!(matches!(classified, AppendError::Protocol(_)));
            assert!(classified.has_no_side_effects());
            assert!(!classified.is_retryable());
        }
    }
}
