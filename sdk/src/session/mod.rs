pub mod append;
pub mod read;

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

pub(crate) use append::{
    AppendPermit, AppendPermits, AppendSession, AppendSessionConfig, AppendSessionCore,
    BatchSubmitTicket, SessionLifecycle, validate_reserve_bytes,
};
pub(crate) use read::{ReadBatchSession, ReadSession, ReadSessionConfig};
use tokio::sync::oneshot;

use crate::{
    error::{AbortedError, AppendSessionError, ErrorContext},
    types::{ONE_MIB, ValidationError},
};

/// Ensures a session's [`SessionLifecycle`] reaches `Closed` with an [`AbortedError`] if its
/// background task panics or is externally cancelled before finishing normally.
pub(crate) struct FinishOnDrop {
    lifecycle: Arc<SessionLifecycle>,
    context: ErrorContext,
    msg: &'static str,
}

impl FinishOnDrop {
    pub(crate) fn new(
        lifecycle: Arc<SessionLifecycle>,
        context: ErrorContext,
        msg: &'static str,
    ) -> Self {
        Self {
            lifecycle,
            context,
            msg,
        }
    }
}

impl Drop for FinishOnDrop {
    fn drop(&mut self) {
        if !self.lifecycle.is_closed() {
            self.lifecycle
                .finish(Err(AppendSessionError::Aborted(AbortedError::new(
                    self.msg,
                    self.context.clone(),
                ))));
        }
    }
}

/// Pre-encoded per-stream options sent as request headers on every (re)connect of a session.
#[derive(Debug, Clone, Default)]
pub(crate) struct StreamHeaders {
    /// `s2-encryption-key`
    pub encryption: Option<http::HeaderValue>,
    /// `s2-stream-config`
    pub stream_config: Option<http::HeaderValue>,
}

pub(crate) fn validate_max_unacked_bytes(max_unacked_bytes: u32) -> Result<u32, ValidationError> {
    if max_unacked_bytes < ONE_MIB {
        return Err(format!("max_unacked_bytes must be at least {ONE_MIB}").into());
    }
    Ok(max_unacked_bytes)
}

pub(crate) struct SubmitTicket<T> {
    rx: oneshot::Receiver<Result<T, AppendSessionError>>,
    lifecycle: Arc<SessionLifecycle>,
    context: ErrorContext,
    dropped_msg: &'static str,
}

impl<T> SubmitTicket<T> {
    pub(crate) fn new(
        rx: oneshot::Receiver<Result<T, AppendSessionError>>,
        lifecycle: Arc<SessionLifecycle>,
        context: ErrorContext,
        dropped_msg: &'static str,
    ) -> Self {
        Self {
            rx,
            lifecycle,
            context,
            dropped_msg,
        }
    }
}

impl<T> Future for SubmitTicket<T> {
    type Output = Result<T, AppendSessionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(res)) => Poll::Ready(res),
            Poll::Ready(Err(_)) => {
                Poll::Ready(Err(self.lifecycle.terminal_err().unwrap_or_else(|| {
                    AppendSessionError::Aborted(AbortedError::new(
                        self.dropped_msg,
                        self.context.clone(),
                    ))
                })))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
