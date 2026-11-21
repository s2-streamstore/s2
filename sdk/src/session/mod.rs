pub mod append;
pub mod read;

pub(crate) use append::{
    AppendPermit, AppendPermits, AppendSessionInternal, BatchSubmitTicket, SessionLifecycle,
    validate_reserve_bytes,
};
pub use append::{AppendSession, AppendSessionConfig};
pub use read::ReadSession;
pub(crate) use read::read_session;

/// Per-stream options sent as request headers on every (re)connect of a session.
#[derive(Debug, Clone, Default)]
pub(crate) struct StreamHeaders {
    /// `s2-encryption-key`
    pub encryption: Option<crate::types::EncryptionKey>,
    /// `s2-stream-config`
    pub stream_config: Option<s2_api::v1::config::StreamConfig>,
}
