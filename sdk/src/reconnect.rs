use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Consecutive advised reconnects tolerated before pacing them.
///
/// A server only sets the advice bit on frames it is already sending, so a
/// session that reconnects normally makes progress every cycle. Repeated
/// advice without progress means load balancing has not yet stopped routing to
/// the draining server, and spinning would only add load.
pub(crate) const MAX_IMMEDIATE_ADVISED_RECONNECTS: usize = 3;

/// Delay applied once advised reconnects stop making progress.
pub(crate) const ADVISED_RECONNECT_DELAY: Duration = Duration::from_millis(100);

/// A shared flag recording whether the server advised reconnecting.
///
/// A server that is about to terminate sets the reconnect-advised bit on the
/// regular S2S frames it sends. The flag is per-connection: a session creates a
/// fresh handle for each attempt, the response decoder sets it, and the session
/// loop finishes the current connection cleanly before reconnecting.
///
/// This is advice, not an error. Acting on it moves the session to a healthy
/// server while the draining one is still serving, so no append becomes
/// ambiguous and no read has to be resumed from a failure.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReconnectAdvice(Arc<AtomicBool>);

impl ReconnectAdvice {
    /// Create a handle for a single connection attempt.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns `true` once the server has advised reconnecting.
    pub(crate) fn is_advised(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Record that the server advised reconnecting.
    pub(crate) fn advise(&self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advice_starts_unset() {
        assert!(!ReconnectAdvice::new().is_advised());
    }

    #[test]
    fn advice_is_shared_and_sticky() {
        let advice = ReconnectAdvice::new();
        let observer = advice.clone();
        advice.advise();
        advice.advise();
        assert!(observer.is_advised());
    }
}
