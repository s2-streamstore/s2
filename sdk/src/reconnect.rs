use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::client::ConnectionId;

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
/// Also carries the identity of the pooled connection the session is served
/// on, bound once the response is established, so that acting on the advice
/// can rotate just that connection.
#[derive(Clone, Default)]
pub(crate) struct ReconnectAdvice(Arc<Inner>);

#[derive(Default)]
struct Inner {
    advised: AtomicBool,
    connection: OnceLock<ConnectionId>,
}

impl ReconnectAdvice {
    pub(crate) fn is_advised(&self) -> bool {
        self.0.advised.load(Ordering::Acquire)
    }

    pub(crate) fn advise(&self) {
        self.0.advised.store(true, Ordering::Release);
    }

    /// Capture which pooled connection serves this session, once known —
    /// the same role as `hyper_util`'s `capture_connection`.
    pub(crate) fn capture_connection(&self, connection: Option<ConnectionId>) {
        if let Some(connection) = connection {
            let _ = self.0.connection.set(connection);
        }
    }

    /// The pooled connection this session is served on, if bound.
    pub(crate) fn connection(&self) -> Option<ConnectionId> {
        self.0.connection.get().copied()
    }
}
