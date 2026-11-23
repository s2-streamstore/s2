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
use futures_core::FusedFuture;
pub(crate) use read::{ReadBatchSession, ReadSession, ReadSessionConfig};
use tokio::sync::oneshot;

use crate::{
    error::{AbortedError, AppendSessionError, ErrorContext, ValidationError},
    types::ONE_MIB,
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
            self.lifecycle.finish(Err(AppendSessionError::Aborted(
                AbortedError::new_with_context(self.msg, self.context.clone()),
            )));
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

pub(crate) fn validate_max_unacked_bytes(
    max_unacked_bytes: usize,
) -> Result<usize, ValidationError> {
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
    outcome: Option<Result<T, AppendSessionError>>,
    done: bool,
}

impl<T: Clone> SubmitTicket<T> {
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
            outcome: None,
            done: false,
        }
    }

    fn closed_err(&self) -> AppendSessionError {
        self.lifecycle.terminal_err().unwrap_or_else(|| {
            AppendSessionError::Aborted(AbortedError::new_with_context(
                self.dropped_msg,
                self.context.clone(),
            ))
        })
    }

    pub(crate) fn try_ack(&mut self) -> Option<Result<T, AppendSessionError>> {
        if self.done {
            return None;
        }
        match self.rx.try_recv() {
            Ok(res) => {
                self.done = true;
                self.outcome = Some(res.clone());
                Some(res)
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                let res = Err(self.closed_err());
                self.done = true;
                self.outcome = Some(res.clone());
                Some(res)
            }
            Err(oneshot::error::TryRecvError::Empty) => None,
        }
    }
}

impl<T: Clone + Unpin> Future for SubmitTicket<T> {
    type Output = Result<T, AppendSessionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(res) = self.outcome.clone() {
            self.done = true;
            return Poll::Ready(res);
        }
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(res)) => {
                self.done = true;
                self.outcome = Some(res.clone());
                Poll::Ready(res)
            }
            Poll::Ready(Err(_)) => {
                let res = Err(self.closed_err());
                self.done = true;
                self.outcome = Some(res.clone());
                Poll::Ready(res)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: Clone + Unpin> FusedFuture for SubmitTicket<T> {
    fn is_terminated(&self) -> bool {
        self.done
    }
}
