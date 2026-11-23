use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll},
};

use http_body::{Body, Frame};
use pin_project_lite::pin_project;

use crate::client::BoxError;

const UNSENT: u8 = 0;
const SENT: u8 = 1;
const STOPPED_UNSENT: u8 = 2;
const STOPPED_SENT: u8 = 3;

fn attempt_ended_error() -> BoxError {
    Box::new(io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "attempt ended",
    ))
}

/// Race-free atomic gate tracking whether a unary request body has yielded any frame (`Terms:
/// Sent`, `T10`).
///
/// Paired with [`RequestFrameMonitorBody`], the first yielded frame transitions `UNSENT -> SENT`.
/// Calling [`stop`](Self::stop) when an attempt ends atomically seals the gate: if the state was
/// still `UNSENT`, it transitions to `STOPPED_UNSENT` and any subsequent body poll fails with
/// `ConnectionAborted` without yielding a frame, guaranteeing that an attempt classified as unsent
/// can never send bytes afterward.
#[derive(Debug, Clone)]
pub(crate) struct FrameSignal(Arc<AtomicU8>);

impl FrameSignal {
    /// Create a new unsent [`FrameSignal`].
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicU8::new(UNSENT)))
    }

    /// Returns `true` if at least one body frame passed the gate.
    pub(crate) fn is_signalled(&self) -> bool {
        matches!(self.0.load(Ordering::Acquire), SENT | STOPPED_SENT)
    }

    fn is_stopped(&self) -> bool {
        matches!(
            self.0.load(Ordering::Acquire),
            STOPPED_UNSENT | STOPPED_SENT
        )
    }

    /// Atomically allow a frame to be yielded, marking the request as sent.
    ///
    /// Returns `false` if the attempt has already been stopped.
    pub(crate) fn try_mark_sent(&self) -> bool {
        loop {
            match self.0.load(Ordering::Acquire) {
                UNSENT => {
                    if self
                        .0
                        .compare_exchange(UNSENT, SENT, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return true;
                    }
                }
                SENT => return true,
                STOPPED_UNSENT | STOPPED_SENT => return false,
                _ => unreachable!("invalid FrameSignal state"),
            }
        }
    }

    /// Stop the attempt so no further frames can be yielded.
    ///
    /// Returns `true` if and only if no frame was ever yielded before stopping.
    pub(crate) fn stop(&self) -> bool {
        loop {
            match self.0.load(Ordering::Acquire) {
                UNSENT => {
                    if self
                        .0
                        .compare_exchange(
                            UNSENT,
                            STOPPED_UNSENT,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                SENT => {
                    if self
                        .0
                        .compare_exchange(SENT, STOPPED_SENT, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return false;
                    }
                }
                STOPPED_UNSENT => return true,
                STOPPED_SENT => return false,
                _ => unreachable!("invalid FrameSignal state"),
            }
        }
    }
}

pin_project! {
    /// A body wrapper that gates frame emission through a [`FrameSignal`].
    ///
    /// Wraps a non-empty `B: http_body::Body` and delegates all operations to the inner body while
    /// the attempt is active. Once [`FrameSignal::stop`] is called, any further `poll_frame()`
    /// fails immediately without yielding frames.
    ///
    /// Note: an empty body yields no frames and therefore never signals; callers must only
    /// rely on `signal.stop() == true` as proof of an unsent request when the request has
    /// a non-empty body (such as JSON or protobuf payloads).
    pub(crate) struct RequestFrameMonitorBody<B> {
        #[pin]
        inner: B,
        signal: FrameSignal,
    }
}

impl<B> RequestFrameMonitorBody<B> {
    /// Wrap an inner body with frame monitoring and stop gating.
    pub(crate) fn new(inner: B, signal: FrameSignal) -> Self {
        Self { inner, signal }
    }
}

impl<B> Body for RequestFrameMonitorBody<B>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        if this.signal.is_stopped() {
            return Poll::Ready(Some(Err(attempt_ended_error())));
        }
        match this.inner.poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                if this.signal.is_stopped() {
                    Poll::Ready(Some(Err(attempt_ended_error())))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Ready(Some(Ok(frame))) => {
                if this.signal.try_mark_sent() {
                    Poll::Ready(Some(Ok(frame)))
                } else {
                    Poll::Ready(Some(Err(attempt_ended_error())))
                }
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err.into()))),
        }
    }

    fn is_end_stream(&self) -> bool {
        !self.signal.is_stopped() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full, StreamBody};

    use super::*;

    #[tokio::test]
    async fn monitor_body_signals_only_when_frame_yielded() {
        let empty_signal = FrameSignal::new();
        let empty = RequestFrameMonitorBody::new(Empty::<Bytes>::new(), empty_signal.clone());
        assert!(empty.collect().await.unwrap().to_bytes().is_empty());
        assert!(!empty_signal.is_signalled());

        let full_signal = FrameSignal::new();
        let full =
            RequestFrameMonitorBody::new(Full::new(Bytes::from("hello")), full_signal.clone());
        assert_eq!(full.collect().await.unwrap().to_bytes().as_ref(), b"hello");
        assert!(full_signal.is_signalled());
        assert!(!full_signal.stop());
    }

    // spec: r1 T10
    #[tokio::test]
    async fn stop_before_poll_blocks_body_and_preserves_unsent_state() {
        let signal = FrameSignal::new();
        let mut body =
            RequestFrameMonitorBody::new(Full::new(Bytes::from_static(b"payload")), signal.clone());

        assert!(signal.stop(), "stopped before any poll must report unsent");
        assert!(!signal.is_signalled());
        assert!(!body.is_end_stream());

        let err = body
            .frame()
            .await
            .expect("must yield abort error")
            .expect_err("stopped body must never yield data");
        assert!(err.to_string().contains("attempt ended"), "{err}");
        assert!(
            !signal.is_signalled(),
            "late poll after stop must never flip unsent to sent"
        );
    }

    // spec: r1 T10
    #[tokio::test]
    async fn stop_after_first_frame_blocks_subsequent_frames_and_preserves_sent_state() {
        let signal = FrameSignal::new();
        let stream = StreamBody::new(futures_util::stream::iter([
            Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"chunk-1"))),
            Ok(Frame::data(Bytes::from_static(b"chunk-2"))),
        ]));
        let mut body = RequestFrameMonitorBody::new(stream, signal.clone());

        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first.as_ref(), b"chunk-1");
        assert!(signal.is_signalled());

        assert!(!signal.stop(), "already sent must report was_unsent=false");
        assert!(signal.is_signalled());

        let err = body
            .frame()
            .await
            .expect("must yield abort error on next frame")
            .expect_err("stopped body must not yield chunk-2");
        assert!(err.to_string().contains("attempt ended"), "{err}");
        assert!(signal.is_signalled());
    }
}
