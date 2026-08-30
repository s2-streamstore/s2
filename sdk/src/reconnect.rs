use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::time::Instant;

/// Advised reconnects to attempt before staying on.
pub(crate) const MAX_ADVISED_RECONNECTS: usize = 1;

/// Gap after which the attempt count resets.
pub(crate) const ADVISED_RECONNECT_IDLE: Duration = Duration::from_secs(10);

/// Advised reconnects attempted lately.
#[derive(Clone, Copy, Default)]
pub(crate) struct AdvisedReconnects {
    count: usize,
    last: Option<Instant>,
}

impl AdvisedReconnects {
    pub(crate) fn record(&mut self) {
        if !self.is_recent() {
            self.count = 0;
        }
        self.last = Some(Instant::now());
        self.count += 1;
    }

    /// Whether to act on advice, or stay until the server ends the connection.
    pub(crate) fn should_reconnect(&self) -> bool {
        !self.is_recent() || self.count < MAX_ADVISED_RECONNECTS
    }

    pub(crate) fn count(&self) -> usize {
        self.count
    }

    fn is_recent(&self) -> bool {
        self.last
            .is_some_and(|at| at.elapsed() <= ADVISED_RECONNECT_IDLE)
    }
}

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
