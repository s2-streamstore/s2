use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use http_body::{Body, Frame};
use pin_project_lite::pin_project;

/// An atomic flag that tracks whether any body frame has been yielded.
///
/// When used with [`RequestFrameMonitorBody`], the signal is set to `true`
/// the first time `poll_frame()` produces a frame. At error time, an unset
/// signal proves the request data never left the process, making retry safe.
#[derive(Debug, Clone)]
pub struct FrameSignal(Arc<AtomicBool>);

impl FrameSignal {
    /// Create a new unsignalled [`FrameSignal`].
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Returns `true` if the signal has been set.
    pub fn is_signalled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Reset the signal to unsignalled.
    pub fn reset(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Set the signal to signalled.
    pub fn signal(&self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Default for FrameSignal {
    fn default() -> Self {
        Self::new()
    }
}

pin_project! {
    /// A body wrapper that signals a [`FrameSignal`] when a frame is yielded.
    ///
    /// Wraps any `B: http_body::Body` and delegates all operations to the inner
    /// body. On each successful `poll_frame()` that yields a frame, the
    /// associated [`FrameSignal`] is set to signalled.
    pub struct RequestFrameMonitorBody<B> {
        #[pin]
        inner: B,
        signal: FrameSignal,
    }
}

impl<B> RequestFrameMonitorBody<B> {
    /// Wrap an inner body with frame monitoring.
    pub fn new(inner: B, signal: FrameSignal) -> Self {
        Self { inner, signal }
    }
}

impl<B> Body for RequestFrameMonitorBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let poll = this.inner.poll_frame(cx);
        if let std::task::Poll::Ready(Some(Ok(_))) = &poll {
            this.signal.signal();
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full};

    use super::*;

    #[test]
    fn signal_starts_unsignalled() {
        let signal = FrameSignal::new();
        assert!(!signal.is_signalled());
    }

    #[test]
    fn signal_round_trip() {
        let signal = FrameSignal::new();
        signal.signal();
        assert!(signal.is_signalled());
        signal.reset();
        assert!(!signal.is_signalled());
    }

    #[test]
    fn clone_shares_state() {
        let a = FrameSignal::new();
        let b = a.clone();
        a.signal();
        assert!(b.is_signalled());
    }

    #[tokio::test]
    async fn empty_body_does_not_signal() {
        let signal = FrameSignal::new();
        let body = RequestFrameMonitorBody::new(Empty::<Bytes>::new(), signal.clone());
        let collected = body.collect().await.unwrap();
        assert!(collected.to_bytes().is_empty());
        assert!(!signal.is_signalled());
    }

    #[tokio::test]
    async fn full_body_signals_on_frame() {
        let signal = FrameSignal::new();
        let body = RequestFrameMonitorBody::new(Full::new(Bytes::from("hello")), signal.clone());
        let collected = body.collect().await.unwrap();
        assert_eq!(collected.to_bytes().as_ref(), b"hello");
        assert!(signal.is_signalled());
    }

    #[tokio::test]
    async fn reset_between_attempts() {
        let signal = FrameSignal::new();

        // First attempt: signal gets set.
        let body = RequestFrameMonitorBody::new(Full::new(Bytes::from("data")), signal.clone());
        body.collect().await.unwrap();
        assert!(signal.is_signalled());

        // Reset before retry.
        signal.reset();
        assert!(!signal.is_signalled());

        // Second attempt with empty body: stays unsignalled.
        let body = RequestFrameMonitorBody::new(Empty::<Bytes>::new(), signal.clone());
        body.collect().await.unwrap();
        assert!(!signal.is_signalled());
    }
}
