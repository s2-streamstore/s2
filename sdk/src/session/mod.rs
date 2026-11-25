use std::task::Waker;

pub mod append;
pub mod read;

pub(crate) use append::{
    AppendPermit, AppendPermits, AppendSession, AppendSessionConfig, AppendSessionCore,
    BatchSubmitTicket, LifecycleWake, SessionAbort, SessionLifecycle, send_oneshot_isolated,
    validate_max_unacked_bytes, validate_reserve_bytes,
};
pub(crate) use read::{ReadBatchSession, ReadSession, ReadSessionConfig};

/// Fixed-index slab of registered [`Waker`] slots with O(1) slot reuse.
///
/// Callers MUST clone and drop [`Waker`] values strictly outside any mutex guarding this slab so
/// custom waker hooks cannot re-enter the lock and deadlock.
pub(crate) struct WaiterSlab {
    slots: Vec<Option<Waker>>,
    free: Vec<usize>,
}

impl WaiterSlab {
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    pub(crate) fn will_wake(&self, idx: usize, waker: &Waker) -> bool {
        self.slots
            .get(idx)
            .and_then(Option::as_ref)
            .is_some_and(|w| w.will_wake(waker))
    }

    pub(crate) fn insert(&mut self, waker: Waker) -> usize {
        if let Some(idx) = self.free.pop() {
            self.slots[idx] = Some(waker);
            idx
        } else {
            let idx = self.slots.len();
            self.slots.push(Some(waker));
            idx
        }
    }

    /// Replace slot `idx` with `waker` only if `!will_wake`, returning either the displaced waker
    /// or the unused `waker` so the caller can drop it outside the lock.
    pub(crate) fn replace_if_changed(&mut self, idx: usize, waker: Waker) -> Option<Waker> {
        let slot = &mut self.slots[idx];
        if slot.as_ref().is_some_and(|w| w.will_wake(&waker)) {
            Some(waker)
        } else {
            slot.replace(waker)
        }
    }

    pub(crate) fn remove(&mut self, idx: usize) -> Option<Waker> {
        if idx < self.slots.len() {
            let waker = self.slots[idx].take();
            self.free.push(idx);
            waker
        } else {
            None
        }
    }

    pub(crate) fn take_all(&mut self) -> Vec<Option<Waker>> {
        self.free.clear();
        std::mem::take(&mut self.slots)
    }

    pub(crate) fn into_wakers(self) -> impl Iterator<Item = Waker> {
        self.slots.into_iter().flatten()
    }
}

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
    pub(crate) fn apply(
        &self,
        request: &mut crate::client::Request,
    ) -> Result<(), crate::client::HttpError> {
        if let Some(ref value) = self.encryption {
            request
                .headers_mut()
                .try_insert(
                    s2_common::encryption::S2_ENCRYPTION_KEY_HEADER.clone(),
                    value.clone(),
                )
                .map_err(|e| crate::client::HttpError::RequestBuild(e.to_string()))?;
        }
        if let Some(ref value) = self.stream_config {
            request
                .headers_mut()
                .try_insert(
                    s2_api::v1::config::STREAM_CONFIG_HEADER.clone(),
                    value.clone(),
                )
                .map_err(|e| crate::client::HttpError::RequestBuild(e.to_string()))?;
        }
        Ok(())
    }
}
