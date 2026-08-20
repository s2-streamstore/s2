use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Max consecutive advised reconnects before delaying the next one.
pub(crate) const MAX_IMMEDIATE_ADVISED_RECONNECTS: usize = 3;

/// Delay applied past [`MAX_IMMEDIATE_ADVISED_RECONNECTS`].
pub(crate) const ADVISED_RECONNECT_DELAY: Duration = Duration::from_millis(100);

/// Gap after which advice starts a fresh streak rather than continuing one.
pub(crate) const ADVICE_STREAK_WINDOW: Duration = Duration::from_secs(10);

/// An atomic flag tracking whether the server has advised reconnecting on this
/// connection. Set by the response decoder when a frame carries the
/// reconnect-advised bit, checked by the session loops.
#[derive(Clone, Default)]
pub(crate) struct ReconnectAdvice(Arc<AtomicBool>);

impl ReconnectAdvice {
    pub(crate) fn is_advised(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub(crate) fn advise(&self) {
        self.0.store(true, Ordering::Release);
    }
}
