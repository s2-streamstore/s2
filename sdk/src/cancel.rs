use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Context,
};

use tokio_util::sync::{WaitForCancellationFuture, WaitForCancellationFutureOwned};

struct CancelFlag {
    cancelled: AtomicBool,
    parent: Option<Arc<CancelFlag>>,
}

impl CancelFlag {
    fn is_cancelled(&self) -> bool {
        let mut cur = Some(self);
        while let Some(node) = cur {
            if node.cancelled.load(Ordering::Acquire) {
                return true;
            }
            cur = node.parent.as_deref();
        }
        false
    }
}

/// Wrapper around [`tokio_util::sync::CancellationToken`] with a lock-free `is_cancelled()` fast
/// path (`tokio_util`'s `is_cancelled()` acquires an internal `std::sync::Mutex` shared across all
/// sessions on a client).
#[derive(Clone)]
pub(crate) struct CancellationToken {
    inner: tokio_util::sync::CancellationToken,
    flag: Arc<CancelFlag>,
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancellationToken")
            .field("is_cancelled", &self.is_cancelled())
            .finish()
    }
}

impl CancellationToken {
    pub(crate) fn new() -> Self {
        Self {
            inner: tokio_util::sync::CancellationToken::new(),
            flag: Arc::new(CancelFlag {
                cancelled: AtomicBool::new(false),
                parent: None,
            }),
        }
    }

    pub(crate) fn cancel(&self) {
        // Store `Release` before cancelling `inner` so any task woken by `cancelled()` /
        // `cancelled_owned()` is guaranteed to observe `is_cancelled() == true`. Note that this
        // guarantee is one-way: a caller observing `is_cancelled() == true` may momentarily poll
        // `cancelled()` as `Pending` until `inner.cancel()` finishes.
        self.flag.cancelled.store(true, Ordering::Release);
        self.inner.cancel();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.flag.is_cancelled()
    }

    pub(crate) fn child_token(&self) -> Self {
        // If already cancelled, create a detached flag so child tokens do not retain parent
        // chains or walk ancestors on `is_cancelled()`, matching `tokio_util`.
        let cancelled = self.is_cancelled();
        Self {
            inner: self.inner.child_token(),
            flag: Arc::new(CancelFlag {
                cancelled: AtomicBool::new(cancelled),
                parent: (!cancelled).then(|| self.flag.clone()),
            }),
        }
    }

    pub(crate) fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.inner.cancelled()
    }

    pub(crate) fn cancelled_owned(self) -> WaitForCancellationFutureOwned {
        self.inner.cancelled_owned()
    }
}

/// Lazily-allocated shutdown waiter for polling a [`CancellationToken`] inside manual `Future` /
/// `Stream` implementations.
#[derive(Default)]
pub(crate) struct ShutdownWait {
    wait: Option<Pin<Box<WaitForCancellationFutureOwned>>>,
}

impl ShutdownWait {
    /// Register `cx` with `token` if not yet cancelled, returning `true` once cancellation has
    /// fired.
    pub(crate) fn poll(&mut self, token: &CancellationToken, cx: &mut Context<'_>) -> bool {
        if token.is_cancelled() {
            return true;
        }
        self.wait
            .get_or_insert_with(|| Box::pin(token.clone().cancelled_owned()))
            .as_mut()
            .poll(cx)
            .is_ready()
    }

    #[cfg(test)]
    pub(crate) fn is_armed(&self) -> bool {
        self.wait.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_token_propagates_parent_to_children_lock_free() {
        let root = CancellationToken::new();
        let child = root.child_token();
        let grandchild = child.child_token();
        let sibling = root.child_token();

        assert!(!root.is_cancelled());
        assert!(!child.is_cancelled());
        assert!(!grandchild.is_cancelled());
        assert!(!sibling.is_cancelled());

        // Cancelling a child does not cancel its parent or sibling, but does cancel descendants.
        child.cancel();
        assert!(!root.is_cancelled());
        assert!(child.is_cancelled());
        assert!(grandchild.is_cancelled());
        assert!(!sibling.is_cancelled());

        // Cancelling the root wakes waiting children and makes `is_cancelled()` true immediately.
        let wait_sibling = sibling.clone().cancelled_owned();
        root.cancel();
        wait_sibling.await;
        assert!(root.is_cancelled());
        assert!(sibling.is_cancelled());

        // Child tokens created from an already-cancelled token are immediately cancelled and
        // detached from the parent flag chain.
        let post_cancel_child = root.child_token();
        assert!(post_cancel_child.is_cancelled());
        assert!(post_cancel_child.flag.parent.is_none());
        post_cancel_child.cancelled().await;
    }
}
