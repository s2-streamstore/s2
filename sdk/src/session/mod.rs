pub mod append;
pub mod read;

pub(crate) use append::{
    AppendPermit, AppendPermits, AppendSessionInternal, BatchSubmitTicket, SessionLifecycle,
    validate_reserve_bytes,
};
pub use append::{AppendSession, AppendSessionConfig};
pub use read::{ReadBatchSession, ReadSession, ReadSessionConfig};
pub(crate) use read::{open_read_batch_session, open_read_session};

/// Pre-encoded per-stream options sent as request headers on every (re)connect of a session.
#[derive(Debug, Clone, Default)]
pub(crate) struct StreamHeaders {
    /// `s2-encryption-key`
    pub encryption: Option<http::HeaderValue>,
    /// `s2-stream-config`
    pub stream_config: Option<http::HeaderValue>,
}
