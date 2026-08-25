use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::client::PoisonHandle;

/// Max consecutive advised reconnects before delaying the next one.
pub(crate) const MAX_IMMEDIATE_ADVISED_RECONNECTS: usize = 3;

/// Delay applied past [`MAX_IMMEDIATE_ADVISED_RECONNECTS`].
pub(crate) const ADVISED_RECONNECT_DELAY: Duration = Duration::from_millis(100);

/// If no reconnect advice arrives for this long, the consecutive count resets.
pub(crate) const ADVISED_RECONNECT_IDLE: Duration = Duration::from_secs(10);

/// An atomic flag tracking whether the server has advised reconnecting on this
/// connection. Set by the response decoder when a frame carries the
/// reconnect-advised bit, checked by the session loops.
///
/// Also carries the [`PoisonHandle`] for the pooled connection the session is
/// served on, captured once the response is established — the same role as
/// `hyper_util`'s `capture_connection`. The first advice poisons the
/// connection immediately, so pool hygiene does not depend on how (or whether)
/// the session acts on the advice: no new request reuses a connection to a
/// draining server even if the session is closing or already satisfied.
#[derive(Clone, Default)]
pub(crate) struct ReconnectAdvice(Arc<Inner>);

#[derive(Default)]
struct Inner {
    advised: AtomicBool,
    poison: OnceLock<PoisonHandle>,
}

impl ReconnectAdvice {
    pub(crate) fn is_advised(&self) -> bool {
        self.0.advised.load(Ordering::Acquire)
    }

    pub(crate) fn advise(&self) {
        // The advice bit repeats on every frame while the server drains; only
        // the first one poisons the pooled connection.
        if !self.0.advised.swap(true, Ordering::AcqRel)
            && let Some(poison) = self.0.poison.get()
        {
            poison.poison();
        }
    }

    /// Capture the poison handle for the pooled connection serving this
    /// session, once known.
    pub(crate) fn capture_connection(&self, poison: Option<PoisonHandle>) {
        if let Some(poison) = poison {
            let _ = self.0.poison.set(poison);
        }
    }
}
