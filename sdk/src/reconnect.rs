use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Shortest gap between acting on reconnect advice within one session.
///
/// A reconnect can land back on the same draining server, which advises again
/// immediately. Without a floor on the gap, that becomes a reconnect loop for
/// as long as the server takes to go away.
pub(crate) const MIN_ADVISED_RECONNECT_GAP: Duration = Duration::from_secs(2);

/// An atomic flag tracking whether the server has advised reconnecting on this
/// connection. Set by the response decoder when a frame carries the
/// reconnect-advised bit, checked by the session loops.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReconnectAdvice(Arc<AtomicBool>);

impl ReconnectAdvice {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn is_advised(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub(crate) fn advise(&self) {
        self.0.store(true, Ordering::Release);
    }
}
