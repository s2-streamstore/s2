pub mod append;
pub mod read;

pub(crate) use append::{
    AppendPermit, AppendPermits, AppendSession, AppendSessionConfig, AppendSessionCore,
    BatchSubmitTicket, FinishOnDrop, SessionAbort, SessionLifecycle, SubmitTicket,
    validate_max_unacked_bytes, validate_reserve_bytes,
};
pub(crate) use read::{ReadBatchSession, ReadSession, ReadSessionConfig};

/// Pre-encoded per-stream options sent as request headers on unary stream calls and every
/// (re)connect of a session.
#[derive(Debug, Clone, Default)]
pub(crate) struct StreamHeaders {
    /// `s2-encryption-key`
    pub encryption: Option<http::HeaderValue>,
    /// `s2-stream-config`
    pub stream_config: Option<http::HeaderValue>,
}

impl StreamHeaders {
    pub(crate) fn apply(&self, request: &mut crate::client::Request) {
        if let Some(ref value) = self.encryption {
            request.headers_mut().insert(
                s2_common::encryption::S2_ENCRYPTION_KEY_HEADER.clone(),
                value.clone(),
            );
        }
        if let Some(ref value) = self.stream_config {
            request.headers_mut().insert(
                s2_api::v1::config::STREAM_CONFIG_HEADER.clone(),
                value.clone(),
            );
        }
    }
}
