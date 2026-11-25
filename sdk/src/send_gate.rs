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
const SENT_BIT: u8 = 0b01;
const STOPPED_BIT: u8 = 0b10;

pub(crate) fn attempt_ended_io_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "attempt ended")
}

fn attempt_ended_error() -> BoxError {
    Box::new(attempt_ended_io_error())
}

/// Race-free atomic gate tracking whether a unary request body has yielded any frame (`Terms:
/// Sent`, `T10`).
///
/// Paired with [`GatedRequestBody`], the first yielded frame transitions `UNSENT -> SENT`.
/// Calling [`stop`](Self::stop) when an attempt ends atomically seals the gate: if the state was
/// still `UNSENT`, it transitions to `STOPPED_UNSENT` and any subsequent body poll fails with
/// `ConnectionAborted` without yielding a frame, guaranteeing that an attempt classified as unsent
/// can never send bytes afterward.
#[derive(Debug, Clone)]
pub(crate) struct SendGate(Arc<AtomicU8>);

impl SendGate {
    /// Create a new unsent [`SendGate`].
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicU8::new(UNSENT)))
    }

    /// Returns `true` if at least one body frame passed the gate.
    pub(crate) fn was_sent(&self) -> bool {
        (self.0.load(Ordering::Acquire) & SENT_BIT) != 0
    }

    fn is_stopped(&self) -> bool {
        (self.0.load(Ordering::Acquire) & STOPPED_BIT) != 0
    }

    /// Atomically allow a frame to be yielded, marking the request as sent.
    ///
    /// Returns `false` if the attempt has already been stopped.
    pub(crate) fn try_mark_sent(&self) -> bool {
        match self
            .0
            .compare_exchange(UNSENT, SENT_BIT, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) | Err(SENT_BIT) => true,
            Err(_) => false,
        }
    }

    /// Stop the attempt so no further frames can be yielded.
    ///
    /// Returns `true` if and only if no frame was ever yielded before stopping.
    pub(crate) fn stop(&self) -> bool {
        (self.0.fetch_or(STOPPED_BIT, Ordering::AcqRel) & SENT_BIT) == 0
    }
}

pin_project! {
    /// A body wrapper that gates frame emission through a [`SendGate`].
    ///
    /// Wraps a non-empty `B: http_body::Body` and delegates all operations to the inner body while
    /// the attempt is active. Once [`SendGate::stop`] is called, any further `poll_frame()`
    /// fails immediately without yielding frames.
    ///
    /// Note: an empty body yields no frames and therefore never marks sent; callers must only
    /// rely on `gate.stop() == true` as proof of an unsent request when the request has
    /// a non-empty body (such as JSON or protobuf payloads).
    pub(crate) struct GatedRequestBody<B> {
        #[pin]
        inner: B,
        gate: SendGate,
    }
}

impl<B> GatedRequestBody<B> {
    /// Wrap an inner body with frame monitoring and stop gating.
    pub(crate) fn new(inner: B, gate: SendGate) -> Self {
        Self { inner, gate }
    }
}

impl<B> Body for GatedRequestBody<B>
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
        if this.gate.is_stopped() {
            return Poll::Ready(Some(Err(attempt_ended_error())));
        }
        match this.inner.poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                if this.gate.is_stopped() {
                    Poll::Ready(Some(Err(attempt_ended_error())))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Ready(Some(Ok(frame))) => {
                if this.gate.try_mark_sent() {
                    Poll::Ready(Some(Ok(frame)))
                } else {
                    Poll::Ready(Some(Err(attempt_ended_error())))
                }
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err.into()))),
        }
    }

    fn is_end_stream(&self) -> bool {
        !self.gate.is_stopped() && self.inner.is_end_stream()
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
    async fn gated_body_marks_sent_only_when_frame_yielded() {
        let empty_gate = SendGate::new();
        let empty = GatedRequestBody::new(Empty::<Bytes>::new(), empty_gate.clone());
        assert!(empty.collect().await.unwrap().to_bytes().is_empty());
        assert!(!empty_gate.was_sent());

        let full_gate = SendGate::new();
        let full = GatedRequestBody::new(Full::new(Bytes::from("hello")), full_gate.clone());
        assert_eq!(full.collect().await.unwrap().to_bytes().as_ref(), b"hello");
        assert!(full_gate.was_sent());
        assert!(!full_gate.stop());
    }

    // spec: r1 T10
    #[tokio::test]
    async fn stop_before_poll_blocks_body_and_preserves_unsent_state() {
        let gate = SendGate::new();
        let mut body =
            GatedRequestBody::new(Full::new(Bytes::from_static(b"payload")), gate.clone());

        assert!(gate.stop(), "stopped before any poll must report unsent");
        assert!(!gate.was_sent());
        assert!(!body.is_end_stream());

        let err = body
            .frame()
            .await
            .expect("must yield abort error")
            .expect_err("stopped body must never yield data");
        assert!(err.to_string().contains("attempt ended"), "{err}");
        assert!(
            !gate.was_sent(),
            "late poll after stop must never flip unsent to sent"
        );
    }

    // spec: r1 T10
    #[tokio::test]
    async fn stop_after_first_frame_blocks_subsequent_frames_and_preserves_sent_state() {
        let gate = SendGate::new();
        let stream = StreamBody::new(futures_util::stream::iter([
            Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"chunk-1"))),
            Ok(Frame::data(Bytes::from_static(b"chunk-2"))),
        ]));
        let mut body = GatedRequestBody::new(stream, gate.clone());

        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first.as_ref(), b"chunk-1");
        assert!(gate.was_sent());

        assert!(!gate.stop(), "already sent must report was_unsent=false");
        assert!(gate.was_sent());

        let err = body
            .frame()
            .await
            .expect("must yield abort error on next frame")
            .expect_err("stopped body must not yield chunk-2");
        assert!(err.to_string().contains("attempt ended"), "{err}");
        assert!(gate.was_sent());
    }
}
