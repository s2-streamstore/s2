use std::time::Duration;

use tokio::time::Instant;

/// Minimum cooldown between advised reconnects (`T6a`).
const ADVISED_RECONNECT_COOLDOWN: Duration = Duration::from_secs(60);

/// Tracks advised reconnect cooldown so a session acts on server reconnect advice
/// at most once per cooldown window and stays put if advised again sooner (`T6a`).
#[derive(Clone, Default)]
pub(crate) struct AdvisedReconnects {
    last: Option<Instant>,
    total_reconnects: u64,
}

impl AdvisedReconnects {
    pub(crate) fn record(&mut self) {
        self.last = Some(Instant::now());
        self.total_reconnects = self.total_reconnects.saturating_add(1);
    }

    /// Whether to act on advice, or stay until the server ends the connection.
    pub(crate) fn should_reconnect(&self) -> bool {
        self.last
            .is_none_or(|at| at.elapsed() >= ADVISED_RECONNECT_COOLDOWN)
    }

    pub(crate) fn total(&self) -> u64 {
        self.total_reconnects
    }
}
