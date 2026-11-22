use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
    time::Duration,
};

use futures_core::Stream;
use futures_util::{
    StreamExt,
    future::{FutureExt, Shared},
};
use http::StatusCode;
use s2_api::v1::stream::{ReadEnd, ReadStart};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, timeout},
};
use tokio_util::task::AbortOnDropHandle;
use tracing::debug;

use crate::{
    api::{ApiError, BasinClient, Streaming, retry_builder},
    client::ShutdownSignal,
    error::{
        AbortedError, ConnectionLostError, ErrorContext, ProtocolError, ReadSessionError,
        SessionClosedError, TimeoutError,
    },
    reconnect::{AdvisedReconnects, ReconnectAdvice},
    retry::RetryBackoff,
    session::StreamHeaders,
    types::{
        AccessTokenMode, MeteredBytes, ReadBatch, ReadInput, SequencedRecord, StreamName,
        StreamPosition,
    },
};

/// Retry policy for a continuous read session.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum ReadSessionRetryPolicy {
    /// Stop after the retry budget configured by [`RetryConfig`](crate::types::RetryConfig) is
    /// exhausted.
    #[default]
    Budgeted,
    /// Keep retrying retryable failures after the configured retry budget is exhausted.
    ///
    /// This also applies to the initial attempt, so iteration may remain pending through
    /// retryable failures until it connects or the session is dropped or aborted.
    Unbounded,
}

/// Configuration for a continuous read session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadSessionConfig {
    retry_policy: ReadSessionRetryPolicy,
}

impl ReadSessionConfig {
    /// Create a new [`ReadSessionConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the configured retry policy.
    pub fn retry_policy(&self) -> ReadSessionRetryPolicy {
        self.retry_policy
    }

    /// Set the policy for retrying retryable failures.
    ///
    /// Clean stream ends and non-retryable failures always terminate the session.
    ///
    /// Defaults to [`ReadSessionRetryPolicy::Budgeted`].
    pub fn with_retry_policy(self, retry_policy: ReadSessionRetryPolicy) -> Self {
        Self { retry_policy }
    }
}

/// The server heartbeats a tailing read session at a randomized gap of at most
/// 15 seconds (<https://s2.dev/docs/api/protocol#data-flow>), plus some buffer (`T7d`).
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, thiserror::Error)]
enum ReadSessionFailure {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    HeartbeatTimeout(#[from] TimeoutError),
}

impl ReadSessionFailure {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Api(err) => err.is_retryable(),
            Self::HeartbeatTimeout(_) => true,
        }
    }

    fn is_authentication_error(&self) -> bool {
        matches!(self, Self::Api(error) if error.is_authentication_error())
    }

    fn is_server_draining(&self) -> bool {
        matches!(self, Self::Api(error) if error.is_server_draining())
    }

    /// If this failure is an HTTP `416` (`Range Not Satisfiable`), returns `Some(tail)` where
    /// `tail` is `Some(pos)` for typed `ReadUnwritten` and `None` for plain `416`.
    fn range_not_satisfiable_tail(&self) -> Option<Option<StreamPosition>> {
        match self {
            Self::Api(ApiError::ReadUnwritten(err)) => Some(Some(err.tail)),
            Self::Api(ApiError::Server(err)) if err.status == StatusCode::RANGE_NOT_SATISFIABLE => {
                Some(None)
            }
            _ => None,
        }
    }

    fn into_error(self, context: &ErrorContext) -> ReadSessionError {
        match self {
            Self::Api(error) => ReadSessionError::from(error).with_context(context),
            Self::HeartbeatTimeout(error) => ReadSessionError::Timeout(error).with_context(context),
        }
    }
}

type CaughtUpResult = Result<StreamPosition, ReadSessionError>;

type SharedShutdown = Shared<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>;

#[derive(Clone)]
enum CaughtUpFuture {
    Pending {
        rx: Shared<oneshot::Receiver<CaughtUpResult>>,
        shutdown: SharedShutdown,
        context: ErrorContext,
    },
    Ready(CaughtUpResult),
}

impl Future for CaughtUpFuture {
    type Output = CaughtUpResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Pending {
                rx,
                shutdown,
                context,
            } => {
                // Poll `rx` first so a caught-up value resolved before client close is preserved
                // (`R8a`), then fall back to client shutdown (`C12`) even if the driver already
                // exited while records remained buffered.
                match Pin::new(rx).poll(cx) {
                    Poll::Ready(Ok(result)) => Poll::Ready(result),
                    Poll::Ready(Err(_)) => Poll::Ready(Err(ReadSessionError::SessionClosed(
                        SessionClosedError::new(None, context.clone()),
                    ))),
                    Poll::Pending => match Pin::new(shutdown).poll(cx) {
                        Poll::Ready(()) => Poll::Ready(Err(ReadSessionError::Aborted(
                            AbortedError::new("client closed", context.clone()),
                        ))),
                        Poll::Pending => Poll::Pending,
                    },
                }
            }
            Self::Ready(result) => Poll::Ready(result.clone()),
        }
    }
}

/// Future returned by [`ReadSession::caught_up`], [`ReadBatchSession::caught_up`], and
/// [`ReadSessionState::caught_up`] (`R8`).
///
/// Resolves to the stream tail position when the session is caught up, or fails with the session's
/// terminal error (or [`SessionClosedError`] if the session closes cleanly before catching up).
#[derive(Clone)]
pub struct CaughtUp(CaughtUpFuture);

impl fmt::Debug for CaughtUp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaughtUp").finish_non_exhaustive()
    }
}

impl Future for CaughtUp {
    type Output = Result<StreamPosition, ReadSessionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

fn pending_catch_up(
    shutdown: SharedShutdown,
    context: ErrorContext,
) -> (oneshot::Sender<CaughtUpResult>, CaughtUpFuture) {
    let (tx, rx) = oneshot::channel();
    (
        tx,
        CaughtUpFuture::Pending {
            rx: rx.shared(),
            shutdown,
            context,
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestState {
    Connecting,
    Open,
    CleanStop,
    Ended,
}

struct ReadStateInner {
    next_seq_num: Option<u64>,
    last_observed_tail: Option<StreamPosition>,
    request_state: RequestState,
    latest_request_tail: Option<StreamPosition>,
    caught_up_tail: Option<StreamPosition>,
    caught_up_tx: Option<oneshot::Sender<CaughtUpResult>>,
    caught_up_future: CaughtUpFuture,
    shutdown_shared: SharedShutdown,
    context: ErrorContext,
}

impl ReadStateInner {
    fn new(
        initial_next_seq_num: Option<u64>,
        shutdown_shared: SharedShutdown,
        context: ErrorContext,
    ) -> Self {
        let (tx, future) = pending_catch_up(shutdown_shared.clone(), context.clone());
        Self {
            next_seq_num: initial_next_seq_num,
            last_observed_tail: None,
            request_state: RequestState::Connecting,
            latest_request_tail: None,
            caught_up_tail: None,
            caught_up_tx: Some(tx),
            caught_up_future: future,
            shutdown_shared,
            context,
        }
    }

    fn compute_caught_up_tail(&self) -> Option<StreamPosition> {
        if !matches!(
            self.request_state,
            RequestState::Open | RequestState::CleanStop
        ) {
            return None;
        }
        let next = self.next_seq_num?;
        let tail = self.latest_request_tail?;
        (tail.seq_num == next).then_some(tail)
    }

    fn recompute_caught_up(&mut self) {
        if self.request_state == RequestState::Ended {
            return;
        }
        match self.compute_caught_up_tail() {
            Some(tail) => {
                if self.caught_up_tail != Some(tail) {
                    self.caught_up_tail = Some(tail);
                    if let Some(tx) = self.caught_up_tx.take() {
                        let _ = tx.send(Ok(tail));
                    } else {
                        self.caught_up_future = CaughtUpFuture::Ready(Ok(tail));
                    }
                }
            }
            None => {
                if self.caught_up_tail.take().is_some() {
                    let (tx, future) =
                        pending_catch_up(self.shutdown_shared.clone(), self.context.clone());
                    self.caught_up_tx = Some(tx);
                    self.caught_up_future = future;
                }
            }
        }
    }

    fn update_observed_tail(&mut self, candidate: StreamPosition) {
        match self.last_observed_tail {
            Some(prev) => {
                if candidate.seq_num > prev.seq_num
                    || (candidate.seq_num == prev.seq_num && candidate.timestamp >= prev.timestamp)
                {
                    self.last_observed_tail = Some(candidate);
                }
            }
            None => {
                self.last_observed_tail = Some(candidate);
            }
        }
    }

    fn on_message_fetched(
        &mut self,
        first_record_seq: Option<u64>,
        tail: Option<StreamPosition>,
    ) -> bool {
        if self.request_state == RequestState::Ended {
            return false;
        }
        self.request_state = RequestState::Open;
        self.latest_request_tail = tail;
        if let Some(tail) = tail {
            self.update_observed_tail(tail);
        }
        if self.next_seq_num.is_none() {
            self.next_seq_num = first_record_seq.or_else(|| tail.map(|t| t.seq_num));
        }
        self.recompute_caught_up();
        // Returns true if this was a heartbeat and `next_seq_num` is already at `tail.seq_num`,
        // meaning there are no earlier undelivered records waiting to advance past.
        first_record_seq.is_none() && tail.is_some_and(|t| self.next_seq_num == Some(t.seq_num))
    }

    fn on_disconnected(&mut self) {
        if self.request_state == RequestState::Ended {
            return;
        }
        self.request_state = RequestState::Connecting;
        self.latest_request_tail = None;
        self.recompute_caught_up();
    }

    fn on_clean_stop(&mut self, tail: Option<StreamPosition>) {
        if self.request_state == RequestState::Ended {
            return;
        }
        self.request_state = RequestState::CleanStop;
        if let Some(tail) = tail {
            self.latest_request_tail = Some(tail);
            self.update_observed_tail(tail);
        }
        self.recompute_caught_up();
    }

    fn on_record_delivered(&mut self, seq_num: u64) {
        self.next_seq_num = Some(seq_num.saturating_add(1));
        if self.request_state != RequestState::Ended {
            self.recompute_caught_up();
        }
    }

    fn on_heartbeat_delivered(&mut self, tail: StreamPosition) {
        if self.request_state == RequestState::Ended {
            return;
        }
        self.update_observed_tail(tail);
        self.next_seq_num = Some(
            self.next_seq_num
                .map_or(tail.seq_num, |prev| prev.max(tail.seq_num)),
        );
        self.recompute_caught_up();
    }

    fn on_ended(&mut self, error: Option<ReadSessionError>) {
        if self.request_state == RequestState::Ended {
            return;
        }
        self.request_state = RequestState::Ended;
        self.latest_request_tail = None;
        self.caught_up_tail = None;

        let terminal_err = error.unwrap_or_else(|| {
            ReadSessionError::SessionClosed(SessionClosedError::new(None, self.context.clone()))
        });
        if let Some(tx) = self.caught_up_tx.take() {
            let _ = tx.send(Err(terminal_err.clone()));
        }
        // Any future handed out *before* ending retains its resolved tail (`R8a`).
        // Subsequent `caught_up()` calls after the session ends see the terminal error (`R8d`).
        self.caught_up_future = CaughtUpFuture::Ready(Err(terminal_err));
    }
}

/// Concurrently accessible read-session progress state (`R6c`, `R7`, `R8`).
///
/// Cloneable handle to observe [`next_seq_num`](Self::next_seq_num),
/// [`last_observed_tail`](Self::last_observed_tail), [`is_caught_up`](Self::is_caught_up), and
/// [`caught_up`](Self::caught_up) from another task while a single consumer iterates the
/// [`ReadSession`] or [`ReadBatchSession`]. None of its methods block.
#[derive(Clone)]
pub struct ReadSessionState {
    inner: Arc<StdMutex<ReadStateInner>>,
    shutdown: ShutdownSignal,
}

impl fmt::Debug for ReadSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        let caught_up = !self.shutdown.is_closed() && inner.caught_up_tail.is_some();
        f.debug_struct("ReadSessionState")
            .field("next_seq_num", &inner.next_seq_num)
            .field("last_observed_tail", &inner.last_observed_tail)
            .field("is_caught_up", &caught_up)
            .finish()
    }
}

impl ReadSessionState {
    fn new(
        initial_next_seq_num: Option<u64>,
        shutdown: ShutdownSignal,
        context: ErrorContext,
    ) -> Self {
        let shutdown_shared = shutdown.cancelled().shared();
        Self {
            inner: Arc::new(StdMutex::new(ReadStateInner::new(
                initial_next_seq_num,
                shutdown_shared,
                context,
            ))),
            shutdown,
        }
    }

    /// Return the sequence number of the next record the session will deliver (`R7a`).
    ///
    /// An unclamped `ReadFrom::SeqNum` start is known immediately; any other start returns `None`
    /// until resolved by the first server response. Updated before each record (or batch) is
    /// handed to the caller, and advances on heartbeats. Retained after iteration ends.
    pub fn next_seq_num(&self) -> Option<u64> {
        self.inner.lock().unwrap().next_seq_num
    }

    /// Return the latest stream tail reported by the server (`R7b`).
    ///
    /// Never moves backward, persists across retries/handovers, and is retained after iteration
    /// ends.
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.inner.lock().unwrap().last_observed_tail
    }

    /// Return whether the active request is open and its most recent server message reported a
    /// tail equal to [`next_seq_num`](Self::next_seq_num) (`R7c`).
    ///
    /// Returns `false` while reconnecting or once iteration has ended.
    pub fn is_caught_up(&self) -> bool {
        !self.shutdown.is_closed() && self.inner.lock().unwrap().caught_up_tail.is_some()
    }

    /// Return a future that resolves to the tail position once the session is caught up (`R8`).
    ///
    /// Resolves immediately if currently caught up, or the next time the session becomes caught
    /// up. Once resolved, its value never changes. Does not drive reading — continue polling the
    /// session while awaiting it. Remains pending across retries and handovers. Fails with the
    /// session's failure, or [`SessionClosedError`] if the session closes cleanly before catching
    /// up.
    pub fn caught_up(&self) -> CaughtUp {
        let mut inner = self.inner.lock().unwrap();
        if self.shutdown.is_closed() && inner.request_state != RequestState::Ended {
            let err = ReadSessionError::Aborted(AbortedError::new(
                "client closed",
                inner.context.clone(),
            ));
            inner.on_ended(Some(err));
        }
        CaughtUp(inner.caught_up_future.clone())
    }

    fn on_message_fetched(
        &self,
        first_record_seq: Option<u64>,
        tail: Option<StreamPosition>,
    ) -> bool {
        self.inner
            .lock()
            .unwrap()
            .on_message_fetched(first_record_seq, tail)
    }

    fn on_disconnected(&self) {
        self.inner.lock().unwrap().on_disconnected();
    }

    fn on_clean_stop(&self, tail: Option<StreamPosition>) {
        self.inner.lock().unwrap().on_clean_stop(tail);
    }

    fn on_record_delivered(&self, seq_num: u64) {
        self.inner.lock().unwrap().on_record_delivered(seq_num);
    }

    fn on_heartbeat_delivered(&self, tail: StreamPosition) {
        self.inner.lock().unwrap().on_heartbeat_delivered(tail);
    }

    fn on_ended(&self, error: Option<ReadSessionError>) {
        self.inner.lock().unwrap().on_ended(error);
    }

    fn on_aborted(&self, err: AbortedError) {
        self.on_ended(Some(ReadSessionError::Aborted(err)));
    }
}

enum DriverEvent {
    Batch(ReadBatch),
    Heartbeat(StreamPosition),
    CleanEnd,
    Error(ReadSessionError),
}

struct ReadSessionCore {
    rx: mpsc::Receiver<DriverEvent>,
    state: ReadSessionState,
    shutdown: ShutdownSignal,
    shutdown_fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    context: ErrorContext,
    terminated: bool,
    _driver: AbortOnDropHandle<()>,
}

impl ReadSessionCore {
    fn open(
        client: BasinClient,
        name: StreamName,
        headers: StreamHeaders,
        input: ReadInput,
        config: ReadSessionConfig,
        op_name: &'static str,
    ) -> Self {
        let context = ErrorContext::stream(op_name, client.name.as_ref(), name.as_ref(), true);
        let shutdown = client.shutdown_signal();
        let (start, end, _) = input.into_api_parts();
        let initial_next_seq_num = if start.clamp == Some(true) {
            None
        } else {
            start.seq_num
        };
        let state = ReadSessionState::new(initial_next_seq_num, shutdown.clone(), context.clone());

        // Bounded capacity 1 enforces `R6b` (at most 1 batch decoded ahead of the batch currently
        // being delivered) and lets `T7d` pause the heartbeat timer while the caller has not yet
        // consumed buffered records.
        let (tx, rx) = mpsc::channel(1);
        let driver = tokio::spawn(run_read_driver(
            client,
            name,
            headers,
            start,
            end,
            config.retry_policy,
            state.clone(),
            tx,
            shutdown.clone(),
            context.clone(),
        ));

        Self {
            rx,
            state,
            shutdown_fut: shutdown.cancelled(),
            shutdown,
            context,
            terminated: false,
            _driver: AbortOnDropHandle::new(driver),
        }
    }

    fn abort_now(&mut self) -> ReadSessionError {
        self.terminated = true;
        self.rx.close();
        let err =
            ReadSessionError::Aborted(AbortedError::new("client closed", self.context.clone()));
        self.state.on_ended(Some(err.clone()));
        err
    }

    fn poll_abort(&mut self, cx: &mut Context<'_>) -> Option<ReadSessionError> {
        if self.shutdown.is_closed() || self.shutdown_fut.as_mut().poll(cx).is_ready() {
            Some(self.abort_now())
        } else {
            None
        }
    }
}

impl Drop for ReadSessionCore {
    fn drop(&mut self) {
        self.state.on_ended(None);
    }
}

/// A continuous stream of sequenced records (`R5`–`R11`).
///
/// Yields individual [`SequencedRecord`]s in sequence-number order. Dropping the session closes it
/// immediately (`R9b`). Use [`state`](Self::state) to observe progress concurrently from other
/// tasks (`R6c`).
pub struct ReadSession {
    core: ReadSessionCore,
    current_batch: VecDeque<SequencedRecord>,
}

impl fmt::Debug for ReadSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadSession")
            .field("state", &self.core.state)
            .finish_non_exhaustive()
    }
}

impl ReadSession {
    /// Return the next sequenced record from the session, or `None` when the session ends cleanly.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe and can be used inside [`tokio::select!`].
    pub async fn next(&mut self) -> Option<Result<SequencedRecord, ReadSessionError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    /// Return a cloneable handle to this session's concurrent progress state (`R6c`).
    pub fn state(&self) -> ReadSessionState {
        self.core.state.clone()
    }

    /// Return the sequence number of the next record this session will deliver (`R7a`).
    pub fn next_seq_num(&self) -> Option<u64> {
        self.core.state.next_seq_num()
    }

    /// Return the latest stream tail reported by the server (`R7b`).
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether all records through the active request's latest reported tail have been
    /// delivered (`R7c`).
    pub fn is_caught_up(&self) -> bool {
        self.core.state.is_caught_up()
    }

    /// Return a future for the current or next caught-up tail (`R8`).
    pub fn caught_up(&self) -> CaughtUp {
        self.core.state.caught_up()
    }
}

impl Stream for ReadSession {
    type Item = Result<SequencedRecord, ReadSessionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.core.terminated {
            return Poll::Ready(None);
        }
        // R9d / C12: client close aborts immediately, dropping fetched-but-undelivered records.
        if this.core.shutdown.is_closed() {
            this.current_batch.clear();
            return Poll::Ready(Some(Err(this.core.abort_now())));
        }

        if let Some(record) = this.current_batch.pop_front() {
            this.core.state.on_record_delivered(record.seq_num);
            return Poll::Ready(Some(Ok(record)));
        }

        loop {
            if let Some(err) = this.core.poll_abort(cx) {
                this.current_batch.clear();
                return Poll::Ready(Some(Err(err)));
            }
            match this.core.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(DriverEvent::Batch(batch))) => {
                    this.current_batch = batch.records.into();
                    if let Some(record) = this.current_batch.pop_front() {
                        this.core.state.on_record_delivered(record.seq_num);
                        return Poll::Ready(Some(Ok(record)));
                    }
                }
                Poll::Ready(Some(DriverEvent::Heartbeat(tail))) => {
                    this.core.state.on_heartbeat_delivered(tail);
                }
                Poll::Ready(Some(DriverEvent::CleanEnd)) | Poll::Ready(None) => {
                    this.core.terminated = true;
                    this.core.state.on_ended(None);
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(DriverEvent::Error(err))) => {
                    this.core.terminated = true;
                    this.core.state.on_ended(Some(err.clone()));
                    return Poll::Ready(Some(Err(err)));
                }
            }
        }
    }
}

/// A continuous stream of non-empty read batches (`R6a`).
///
/// Delivers each server batch whole, skips empty heartbeat frames while updating session state,
/// and follows all read-session rules per batch. Dropping the session closes it immediately
/// (`R9b`).
pub struct ReadBatchSession {
    core: ReadSessionCore,
}

impl fmt::Debug for ReadBatchSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadBatchSession")
            .field("state", &self.core.state)
            .finish_non_exhaustive()
    }
}

impl ReadBatchSession {
    /// Return the next non-empty batch from the session, or `None` when the session ends cleanly.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe and can be used inside [`tokio::select!`].
    pub async fn next(&mut self) -> Option<Result<ReadBatch, ReadSessionError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    /// Return a cloneable handle to this session's concurrent progress state (`R6c`).
    pub fn state(&self) -> ReadSessionState {
        self.core.state.clone()
    }

    /// Return the sequence number of the next record this session will deliver (`R7a`).
    pub fn next_seq_num(&self) -> Option<u64> {
        self.core.state.next_seq_num()
    }

    /// Return the latest stream tail reported by the server (`R7b`).
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether all records through the active request's latest reported tail have been
    /// delivered (`R7c`).
    pub fn is_caught_up(&self) -> bool {
        self.core.state.is_caught_up()
    }

    /// Return a future for the current or next caught-up tail (`R8`).
    pub fn caught_up(&self) -> CaughtUp {
        self.core.state.caught_up()
    }
}

impl Stream for ReadBatchSession {
    type Item = Result<ReadBatch, ReadSessionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.core.terminated {
            return Poll::Ready(None);
        }
        loop {
            if let Some(err) = this.core.poll_abort(cx) {
                return Poll::Ready(Some(Err(err)));
            }
            match this.core.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(DriverEvent::Batch(batch))) => {
                    let Some(last) = batch.records.last() else {
                        continue;
                    };
                    this.core.state.on_record_delivered(last.seq_num);
                    return Poll::Ready(Some(Ok(batch)));
                }
                Poll::Ready(Some(DriverEvent::Heartbeat(tail))) => {
                    this.core.state.on_heartbeat_delivered(tail);
                }
                Poll::Ready(Some(DriverEvent::CleanEnd)) | Poll::Ready(None) => {
                    this.core.terminated = true;
                    this.core.state.on_ended(None);
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(DriverEvent::Error(err))) => {
                    this.core.terminated = true;
                    this.core.state.on_ended(Some(err.clone()));
                    return Poll::Ready(Some(Err(err)));
                }
            }
        }
    }
}

pub(crate) fn open_read_session(
    client: BasinClient,
    name: StreamName,
    headers: StreamHeaders,
    input: ReadInput,
    config: ReadSessionConfig,
) -> ReadSession {
    ReadSession {
        core: ReadSessionCore::open(client, name, headers, input, config, "read_session"),
        current_batch: VecDeque::new(),
    }
}

pub(crate) fn open_read_batch_session(
    client: BasinClient,
    name: StreamName,
    headers: StreamHeaders,
    input: ReadInput,
    config: ReadSessionConfig,
) -> ReadBatchSession {
    ReadBatchSession {
        core: ReadSessionCore::open(client, name, headers, input, config, "read_batch_session"),
    }
}

type AttemptStream = Streaming<s2_api::v1::stream::proto::ReadBatch>;

#[allow(clippy::too_many_arguments)]
async fn run_read_driver(
    client: BasinClient,
    name: StreamName,
    headers: StreamHeaders,
    mut start: ReadStart,
    mut end: ReadEnd,
    retry_policy: ReadSessionRetryPolicy,
    state: ReadSessionState,
    tx: mpsc::Sender<DriverEvent>,
    shutdown: ShutdownSignal,
    context: ErrorContext,
) {
    let mut retry_backoff = retry_builder(&client.config.retry).build();
    let access_token_mode = client.config.access_token.mode();
    let baseline_wait = end.wait;
    let has_stop_option =
        end.count.is_some() || end.bytes.is_some() || end.until.is_some() || end.wait.is_some();

    let mut idle_since: Option<Instant> = None;
    let mut fetched_any_record = false;
    let mut has_received_response = false;
    let mut advised_reconnects = AdvisedReconnects::default();

    let mut active: Option<(AttemptStream, ReconnectAdvice, bool)> = None;
    let mut attempts: u32 = 0;
    let mut made_progress_in_attempt = false;
    let mut fetched_record_in_attempt = false;
    let mut last_fetched_seq: Option<u64> = None;

    loop {
        if shutdown.is_closed() {
            state.on_aborted(AbortedError::new("client closed", context.clone()));
            return;
        }
        if tx.is_closed() {
            return;
        }

        if active.is_none() {
            end.wait = remaining_wait(baseline_wait, idle_since);
            let attempt_num = retry_backoff.used().saturating_add(1);
            let reconnect = ReconnectAdvice::default();

            let open_res = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    state.on_aborted(AbortedError::new("client closed", context.clone()));
                    return;
                }
                _ = tx.closed() => return,
                res = client.read_session(
                    &name,
                    start.clone(),
                    end.clone(),
                    headers.encryption.as_ref(),
                    headers.stream_config.as_ref(),
                    reconnect.clone(),
                    attempt_num,
                ) => res,
            };

            if shutdown.is_closed() {
                state.on_aborted(AbortedError::new("client closed", context.clone()));
                return;
            }

            match open_res {
                Ok(batches) => {
                    active = Some((batches, reconnect, false));
                    made_progress_in_attempt = false;
                    fetched_record_in_attempt = false;
                }
                Err(api_err) => {
                    let err = ReadSessionFailure::Api(api_err);
                    // R11d: once the start has been resolved by a prior response, a resumed
                    // request with no wait remaining that receives 416 with `tail >= resume` has
                    // reached the tail on a stop condition.
                    if let Some(tail) = r11d_stop_tail(has_received_response, &start, &end, &err) {
                        state.on_clean_stop(tail);
                        if let Some(tail) = tail
                            && !state.is_caught_up()
                        {
                            send_terminal_event(
                                &tx,
                                &shutdown,
                                &state,
                                &context,
                                DriverEvent::Heartbeat(tail),
                            )
                            .await;
                        }
                        send_terminal_event(
                            &tx,
                            &shutdown,
                            &state,
                            &context,
                            DriverEvent::CleanEnd,
                        )
                        .await;
                        return;
                    }

                    attempts = attempts.saturating_add(1);
                    if let Some(backoff) =
                        retry_delay(&err, &mut retry_backoff, retry_policy, access_token_mode)
                    {
                        if sleep_or_stop(backoff, &shutdown, &tx, &state, &context).await {
                            return;
                        }
                        continue;
                    }
                    let final_err = err.into_error(&context.clone().with_attempts(attempts));
                    send_terminal_event(
                        &tx,
                        &shutdown,
                        &state,
                        &context,
                        DriverEvent::Error(final_err),
                    )
                    .await;
                    return;
                }
            }
        }

        // R6b + T7d: wait for channel capacity BEFORE reading the next message so we decode at
        // most 1 batch ahead and do not count caller backpressure against the heartbeat timeout.
        let permit = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                drop(active);
                state.on_aborted(AbortedError::new("client closed", context.clone()));
                return;
            }
            res = tx.reserve() => match res {
                Ok(permit) => permit,
                Err(_) => return,
            },
        };

        let (batches, reconnect, declined_advice) =
            active.as_mut().expect("active stream must be Some");
        let next_res = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                drop(permit);
                drop(active);
                state.on_aborted(AbortedError::new("client closed", context.clone()));
                return;
            }
            _ = tx.closed() => return,
            res = timeout(HEARTBEAT_TIMEOUT, batches.next()) => res,
        };

        if shutdown.is_closed() {
            drop(permit);
            drop(active);
            state.on_aborted(AbortedError::new("client closed", context.clone()));
            return;
        }

        let item = match next_res {
            Ok(Some(Ok(raw_batch))) => Ok(Some(ReadBatch::from_api(raw_batch))),
            Ok(Some(Err(api_err))) => Err(ReadSessionFailure::Api(api_err)),
            Ok(None) => Ok(None),
            Err(_) => Err(ReadSessionFailure::HeartbeatTimeout(TimeoutError::new(
                "heartbeat timeout",
                context.clone(),
            ))),
        };

        match item {
            Ok(Some(batch)) => {
                // R6: verify records arrive in strictly increasing seq_num order.
                match validate_read_batch_order(&batch, last_fetched_seq, &context) {
                    Ok(new_last) => last_fetched_seq = new_last,
                    Err(err) => {
                        drop(active);
                        state.on_disconnected();
                        permit.send(DriverEvent::Error(err));
                        return;
                    }
                }

                made_progress_in_attempt = true;
                has_received_response = true;
                if retry_backoff.used() > 0 {
                    retry_backoff.reset();
                }
                attempts = 0;

                // R11c: restart idle clock only when a record is fetched; if no record has been
                // fetched yet, start the clock the first time we learn we are at the tail.
                // Heartbeats never restart this clock.
                if !batch.records.is_empty() {
                    fetched_any_record = true;
                    fetched_record_in_attempt = true;
                    idle_since = Some(Instant::now());
                } else if !fetched_any_record && batch.tail.is_some() {
                    idle_since.get_or_insert_with(Instant::now);
                }

                update_resume_start(&mut start, &batch);
                if let Some(count) = end.count.as_mut() {
                    *count = count.saturating_sub(batch.records.len() as u64);
                }
                if let Some(bytes) = end.bytes.as_mut() {
                    *bytes = bytes.saturating_sub(
                        batch
                            .records
                            .iter()
                            .map(|r| r.metered_bytes() as u64)
                            .sum::<u64>(),
                    );
                }

                let first_record_seq = batch.records.first().map(|r| r.seq_num);
                let tail = batch.tail;
                let heartbeat_already_at_tail = state.on_message_fetched(first_record_seq, tail);

                if !batch.records.is_empty() {
                    permit.send(DriverEvent::Batch(batch));
                } else if let Some(tail) = tail
                    && !heartbeat_already_at_tail
                {
                    permit.send(DriverEvent::Heartbeat(tail));
                } else {
                    drop(permit);
                }

                // T6a: act on reconnect advice immediately (at most once every 60s).
                if reconnect.is_advised() && !*declined_advice {
                    if advised_reconnects.should_reconnect() {
                        active = None;
                        if read_limits_exhausted(&end) {
                            state.on_clean_stop(None);
                            send_terminal_event(
                                &tx,
                                &shutdown,
                                &state,
                                &context,
                                DriverEvent::CleanEnd,
                            )
                            .await;
                            return;
                        }
                        advised_reconnects.record();
                        debug!(
                            next_seq_num = ?start.seq_num,
                            advised_reconnects = advised_reconnects.count(),
                            "reconnecting read session on server advice"
                        );
                        state.on_disconnected();
                        continue;
                    }
                    *declined_advice = true;
                }
            }
            Ok(None) => {
                // T9 / R9a: clean EOF ends iteration cleanly ONLY when a stop option was set;
                // otherwise it is a ConnectionLostError and retried per retry_policy.
                active = None;
                if has_stop_option {
                    // R11c: if this attempt ran with a reduced `wait` budget and fetched new
                    // records (restarting the idle clock), reconnect with the refreshed wait
                    // rather than stopping prematurely when the server's shorter timer expires.
                    if fetched_record_in_attempt
                        && !read_limits_exhausted(&end)
                        && let (Some(base_w), Some(sent_w)) = (baseline_wait, end.wait)
                        && sent_w < base_w
                        && remaining_wait(baseline_wait, idle_since).is_some_and(|w| w > 0)
                    {
                        drop(permit);
                        state.on_disconnected();
                        continue;
                    }
                    state.on_clean_stop(None);
                    permit.send(DriverEvent::CleanEnd);
                    return;
                }
                let err =
                    ReadSessionFailure::Api(ApiError::ConnectionLost(ConnectionLostError::new(
                        "read stream ended cleanly without a stop condition",
                        true,
                        context.clone(),
                    )));
                state.on_disconnected();
                attempts = attempts.saturating_add(1);
                if let Some(backoff) =
                    retry_delay(&err, &mut retry_backoff, retry_policy, access_token_mode)
                {
                    drop(permit);
                    if sleep_or_stop(backoff, &shutdown, &tx, &state, &context).await {
                        return;
                    }
                    continue;
                }
                let final_err = err.into_error(&context.clone().with_attempts(attempts));
                permit.send(DriverEvent::Error(final_err));
                return;
            }
            Err(err) => {
                // T10: drop underlying attempt stream immediately.
                active = None;

                // R11d: 416 on a resumed request with no remaining wait is a clean stop unless the
                // reported tail regressed below our resume position.
                if let Some(tail) = r11d_stop_tail(has_received_response, &start, &end, &err) {
                    state.on_clean_stop(tail);
                    if let Some(tail) = tail
                        && !state.is_caught_up()
                    {
                        permit.send(DriverEvent::Heartbeat(tail));
                        send_terminal_event(
                            &tx,
                            &shutdown,
                            &state,
                            &context,
                            DriverEvent::CleanEnd,
                        )
                        .await;
                    } else {
                        permit.send(DriverEvent::CleanEnd);
                    }
                    return;
                }

                // If `count` or `bytes` is already exhausted after receiving data, all requested
                // records have been fetched; end cleanly rather than reconnecting with
                // count=0/bytes=0.
                if has_received_response && read_limits_exhausted(&end) {
                    state.on_clean_stop(None);
                    permit.send(DriverEvent::CleanEnd);
                    return;
                }

                state.on_disconnected();

                if err.is_server_draining() && made_progress_in_attempt {
                    drop(permit);
                    debug!(
                        next_seq_num = ?start.seq_num,
                        "reconnecting read session while server drains"
                    );
                    continue;
                }

                attempts = attempts.saturating_add(1);
                if let Some(backoff) =
                    retry_delay(&err, &mut retry_backoff, retry_policy, access_token_mode)
                {
                    drop(permit);
                    if sleep_or_stop(backoff, &shutdown, &tx, &state, &context).await {
                        return;
                    }
                    continue;
                }

                let final_err = err.into_error(&context.clone().with_attempts(attempts));
                permit.send(DriverEvent::Error(final_err));
                return;
            }
        }
    }
}

/// Check whether an error is a clean `R11d` stop condition (resumed request with no remaining
/// `wait` receiving `416` whose tail has not regressed below `start.seq_num`).
fn r11d_stop_tail(
    has_received_response: bool,
    start: &ReadStart,
    end: &ReadEnd,
    err: &ReadSessionFailure,
) -> Option<Option<StreamPosition>> {
    if !has_received_response || !has_no_wait_remaining(end) {
        return None;
    }
    let tail = err.range_not_satisfiable_tail()?;
    if let (Some(tail_pos), Some(resume_seq)) = (tail, start.seq_num)
        && tail_pos.seq_num < resume_seq
    {
        return None;
    }
    Some(tail)
}

async fn send_terminal_event(
    tx: &mpsc::Sender<DriverEvent>,
    shutdown: &ShutdownSignal,
    state: &ReadSessionState,
    context: &ErrorContext,
    event: DriverEvent,
) {
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => {
            state.on_aborted(AbortedError::new("client closed", context.clone()));
        }
        _ = tx.send(event) => {}
    }
}

/// Sleep for retry backoff while racing client shutdown and consumer drop.
/// Returns `true` if the driver should terminate.
async fn sleep_or_stop(
    backoff: Duration,
    shutdown: &ShutdownSignal,
    tx: &mpsc::Sender<DriverEvent>,
    state: &ReadSessionState,
    context: &ErrorContext,
) -> bool {
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => {
            state.on_aborted(AbortedError::new("client closed", context.clone()));
            true
        }
        _ = tx.closed() => true,
        _ = tokio::time::sleep(backoff) => false,
    }
}

fn validate_read_batch_order(
    batch: &ReadBatch,
    last_fetched_seq: Option<u64>,
    context: &ErrorContext,
) -> Result<Option<u64>, ReadSessionError> {
    let mut prev = last_fetched_seq;
    for record in &batch.records {
        if let Some(prev_seq) = prev
            && record.seq_num <= prev_seq
        {
            return Err(ReadSessionError::Protocol(ProtocolError::new(
                format!(
                    "read batch contained out-of-order or duplicate seq_num {} after {}",
                    record.seq_num, prev_seq
                ),
                context.clone(),
            )));
        }
        prev = Some(record.seq_num);
    }
    Ok(prev)
}

fn next_seq_num_after_batch(batch: &ReadBatch) -> Option<u64> {
    batch
        .records
        .last()
        .map(|record| record.seq_num.saturating_add(1))
        .or_else(|| batch.tail.as_ref().map(|tail| tail.seq_num))
}

/// Advance the absolute start used when reconnecting the read session (`R11b`).
///
/// Once the first response resolves the start (by record or heartbeat), subsequent attempts
/// resume strictly by `seq_num` without re-evaluating `timestamp`, `tail_offset`, or `clamp`.
fn update_resume_start(start: &mut ReadStart, batch: &ReadBatch) {
    if let Some(seq_num) = next_seq_num_after_batch(batch) {
        *start = ReadStart {
            seq_num: Some(seq_num),
            timestamp: None,
            tail_offset: None,
            clamp: None,
        };
    }
}

/// Whether the read's `count` or `bytes` limit has been used up.
fn read_limits_exhausted(end: &ReadEnd) -> bool {
    end.count == Some(0) || end.bytes == Some(0)
}

/// Whether a resumed request has no `wait` remaining (`R11d`).
fn has_no_wait_remaining(end: &ReadEnd) -> bool {
    match end.wait {
        Some(0) => true,
        Some(_) => false,
        None => end.count.is_some() || end.bytes.is_some() || end.until.is_some(),
    }
}

/// Compute the remaining wait budget for a resumed request (`R11c`), rounding up to whole seconds.
fn remaining_wait(baseline_wait: Option<u32>, idle_since: Option<Instant>) -> Option<u32> {
    baseline_wait.map(|w| match idle_since {
        Some(since) => {
            let baseline = Duration::from_secs(u64::from(w));
            let rem = baseline.saturating_sub(since.elapsed());
            let secs = rem.as_secs() + u64::from(rem.subsec_nanos() > 0);
            secs.min(u64::from(u32::MAX)) as u32
        }
        None => w,
    })
}

fn retry_delay(
    err: &ReadSessionFailure,
    backoffs: &mut RetryBackoff,
    retry_policy: ReadSessionRetryPolicy,
    access_token_mode: AccessTokenMode,
) -> Option<Duration> {
    let is_retryable =
        err.is_retryable() || (access_token_mode.is_refreshable() && err.is_authentication_error());
    if !is_retryable {
        debug!(
            %err,
            is_retryable = false,
            retries_exhausted = backoffs.is_exhausted(),
            "not retrying read session"
        );
        return None;
    }

    let backoff = match retry_policy {
        ReadSessionRetryPolicy::Budgeted => backoffs.next(),
        ReadSessionRetryPolicy::Unbounded => Some(backoffs.next_or_max()),
    };
    if let Some(backoff) = backoff {
        debug!(
            %err,
            ?backoff,
            ?retry_policy,
            num_retries_remaining = backoffs.remaining(),
            "retrying read session"
        );
        Some(backoff)
    } else {
        debug!(
            %err,
            is_retryable,
            retries_exhausted = backoffs.is_exhausted(),
            "not retrying read session"
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::poll;

    use super::*;
    use crate::{error::ReadUnwrittenError, types::Header};

    fn position(seq_num: u64) -> StreamPosition {
        StreamPosition {
            seq_num,
            timestamp: seq_num,
        }
    }

    fn record(seq_num: u64, command: bool) -> SequencedRecord {
        SequencedRecord {
            seq_num,
            timestamp: seq_num,
            body: Bytes::new(),
            headers: if command {
                vec![Header::new("", "fence")]
            } else {
                Vec::new()
            },
        }
    }

    fn batch(records: Vec<SequencedRecord>, tail: Option<StreamPosition>) -> ReadBatch {
        ReadBatch { records, tail }
    }

    // spec: r1 R11b
    #[test]
    fn empty_tail_anchors_relative_resume_start_and_clears_clamp() {
        let mut start = ReadStart {
            seq_num: None,
            timestamp: None,
            tail_offset: Some(0),
            clamp: Some(true),
        };

        update_resume_start(&mut start, &batch(Vec::new(), Some(position(42))));

        assert_eq!(start.seq_num, Some(42));
        assert_eq!(start.timestamp, None);
        assert_eq!(start.tail_offset, None);
        assert_eq!(start.clamp, None);
    }

    // spec: r1 R11d
    #[test]
    fn r11d_rejects_416_when_tail_regressed_below_resume_seq_num() {
        let start = ReadStart {
            seq_num: Some(10),
            timestamp: None,
            tail_offset: None,
            clamp: None,
        };
        let end = ReadEnd {
            count: Some(5),
            bytes: None,
            until: None,
            wait: None,
        };
        let server_416 = || {
            crate::error::ServerError::new_for_test(StatusCode::RANGE_NOT_SATISFIABLE, None, "416")
        };

        let at_tail = ReadSessionFailure::Api(ApiError::ReadUnwritten(ReadUnwrittenError::new(
            position(10),
            server_416(),
        )));
        assert_eq!(
            r11d_stop_tail(true, &start, &end, &at_tail),
            Some(Some(position(10)))
        );

        let trimmed_past = ReadSessionFailure::Api(ApiError::ReadUnwritten(
            ReadUnwrittenError::new(position(15), server_416()),
        ));
        assert_eq!(
            r11d_stop_tail(true, &start, &end, &trimmed_past),
            Some(Some(position(15)))
        );

        let recreated_lower = ReadSessionFailure::Api(ApiError::ReadUnwritten(
            ReadUnwrittenError::new(position(3), server_416()),
        ));
        assert_eq!(r11d_stop_tail(true, &start, &end, &recreated_lower), None);
    }

    // spec: r1 R11c
    #[tokio::test(start_paused = true)]
    async fn remaining_wait_rounds_up_to_whole_seconds() {
        let start = Instant::now();
        assert_eq!(remaining_wait(Some(10), None), Some(10));
        assert_eq!(remaining_wait(Some(10), Some(start)), Some(10));

        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(remaining_wait(Some(10), Some(start)), Some(10));

        tokio::time::advance(Duration::from_millis(999)).await;
        assert_eq!(remaining_wait(Some(10), Some(start)), Some(9));

        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(remaining_wait(Some(10), Some(start)), Some(9));

        tokio::time::advance(Duration::from_millis(8_998)).await;
        assert_eq!(remaining_wait(Some(10), Some(start)), Some(1));

        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(remaining_wait(Some(10), Some(start)), Some(0));

        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(remaining_wait(Some(10), Some(start)), Some(0));
    }

    fn test_session_parts(
        initial_next_seq_num: Option<u64>,
    ) -> (
        ReadSession,
        mpsc::Sender<DriverEvent>,
        ReadSessionState,
        ShutdownSignal,
    ) {
        let context = ErrorContext::default().into_read_only();
        let shutdown = ShutdownSignal::new();
        let state = ReadSessionState::new(initial_next_seq_num, shutdown.clone(), context.clone());
        let (tx, rx) = mpsc::channel(4);
        let driver = tokio::spawn(std::future::pending::<()>());
        let session = ReadSession {
            core: ReadSessionCore {
                rx,
                state: state.clone(),
                shutdown_fut: shutdown.cancelled(),
                shutdown: shutdown.clone(),
                context,
                terminated: false,
                _driver: AbortOnDropHandle::new(driver),
            },
            current_batch: VecDeque::new(),
        };
        (session, tx, state, shutdown)
    }

    #[tokio::test]
    async fn spec_r7_example_walkthrough() {
        let (mut session, tx, state, _shutdown) = test_session_parts(Some(0));

        // Step 1: Opened; nothing fetched yet
        assert_eq!(session.next_seq_num(), Some(0));
        assert_eq!(session.last_observed_tail(), None);
        assert!(!session.is_caught_up());
        let cu1 = session.caught_up();

        // Step 2: Records 0-4 fetched with tail 5; record 0 delivered
        let b = batch(
            (0..5).map(|i| record(i, false)).collect(),
            Some(position(5)),
        );
        state.on_message_fetched(Some(0), Some(position(5)));
        tx.send(DriverEvent::Batch(b)).await.unwrap();

        let r0 = session.next().await.unwrap().unwrap();
        assert_eq!(r0.seq_num, 0);
        assert_eq!(session.next_seq_num(), Some(1));
        assert_eq!(session.last_observed_tail(), Some(position(5)));
        assert!(!session.is_caught_up());

        // Step 3: Records 1-4 delivered
        for expected in 1..5 {
            let rec = session.next().await.unwrap().unwrap();
            assert_eq!(rec.seq_num, expected);
        }
        assert_eq!(session.next_seq_num(), Some(5));
        assert_eq!(session.last_observed_tail(), Some(position(5)));
        assert!(session.is_caught_up());
        assert_eq!(cu1.await.unwrap(), position(5));

        // Step 4: Heartbeat received with tail 5
        assert!(state.on_message_fetched(None, Some(position(5))));
        assert_eq!(session.next_seq_num(), Some(5));
        assert_eq!(session.last_observed_tail(), Some(position(5)));
        assert!(session.is_caught_up());

        // Step 5: Record 5 fetched with tail 6 (before delivery)
        let b5 = batch(vec![record(5, false)], Some(position(6)));
        state.on_message_fetched(Some(5), Some(position(6)));
        tx.send(DriverEvent::Batch(b5)).await.unwrap();
        assert_eq!(session.next_seq_num(), Some(5));
        assert_eq!(session.last_observed_tail(), Some(position(6)));
        assert!(!session.is_caught_up());

        // Step 6: Record 5 delivered
        let r5 = session.next().await.unwrap().unwrap();
        assert_eq!(r5.seq_num, 5);
        assert_eq!(session.next_seq_num(), Some(6));
        assert_eq!(session.last_observed_tail(), Some(position(6)));
        assert!(session.is_caught_up());

        // Step 7: Active request breaks
        state.on_disconnected();
        assert_eq!(session.next_seq_num(), Some(6));
        assert_eq!(session.last_observed_tail(), Some(position(6)));
        assert!(!session.is_caught_up());
        let cu2 = session.caught_up();

        // Step 8: Reconnected; heartbeat received with tail 6
        assert!(state.on_message_fetched(None, Some(position(6))));
        assert_eq!(session.next_seq_num(), Some(6));
        assert_eq!(session.last_observed_tail(), Some(position(6)));
        assert!(session.is_caught_up());
        assert_eq!(cu2.await.unwrap(), position(6));
    }

    #[tokio::test]
    async fn clean_stop_final_record_catches_up_then_iteration_end_resets_is_caught_up() {
        let (mut session, tx, state, _shutdown) = test_session_parts(Some(0));
        let cu = session.caught_up();

        let b = batch(vec![record(0, false), record(1, false)], Some(position(2)));
        state.on_message_fetched(Some(0), Some(position(2)));
        tx.send(DriverEvent::Batch(b)).await.unwrap();
        state.on_clean_stop(None);
        tx.send(DriverEvent::CleanEnd).await.unwrap();

        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert!(!session.is_caught_up());

        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 1);
        assert!(session.is_caught_up());
        assert_eq!(cu.await.unwrap(), position(2));
        let cu_while_caught = session.caught_up();

        assert!(session.next().await.is_none());
        assert!(!session.is_caught_up());
        assert_eq!(session.next_seq_num(), Some(2));
        assert_eq!(session.last_observed_tail(), Some(position(2)));
        assert_eq!(cu_while_caught.await.unwrap(), position(2));
        assert!(matches!(
            session.caught_up().await,
            Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
        ));
    }

    #[tokio::test]
    async fn heartbeat_after_trimmed_gap_advances_next_seq_num_on_delivery() {
        let (mut session, tx, state, _shutdown) = test_session_parts(Some(0));
        let cu = session.caught_up();

        let b = batch(vec![record(0, false)], None);
        state.on_message_fetched(Some(0), None);
        tx.send(DriverEvent::Batch(b)).await.unwrap();

        assert!(!state.on_message_fetched(None, Some(position(5))));
        tx.send(DriverEvent::Heartbeat(position(5))).await.unwrap();

        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert_eq!(session.next_seq_num(), Some(1));
        assert!(!session.is_caught_up());

        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);

        assert_eq!(session.next_seq_num(), Some(5));
        assert!(session.is_caught_up());
        assert_eq!(cu.await.unwrap(), position(5));
    }

    #[tokio::test]
    async fn clean_end_without_catching_up_rejects_wait() {
        let (mut session, tx, state, _shutdown) = test_session_parts(None);
        let cu = session.caught_up();
        state.on_clean_stop(None);
        tx.send(DriverEvent::CleanEnd).await.unwrap();

        assert!(session.next().await.is_none());
        assert!(matches!(
            cu.await,
            Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
        ));
    }

    #[tokio::test]
    async fn read_error_rejects_wait_and_preserves_prior_resolved_future() {
        let (mut session, tx, state, _shutdown) = test_session_parts(Some(0));

        state.on_message_fetched(Some(0), Some(position(1)));
        tx.send(DriverEvent::Batch(batch(
            vec![record(0, false)],
            Some(position(1)),
        )))
        .await
        .unwrap();

        session.next().await.unwrap().unwrap();
        assert!(session.is_caught_up());
        let resolved_cu = session.caught_up();

        state.on_disconnected();
        assert!(!session.is_caught_up());
        let pending_cu = session.caught_up();

        tx.send(DriverEvent::Error(ReadSessionError::Timeout(
            TimeoutError::new(
                "heartbeat timeout",
                ErrorContext::default().into_read_only(),
            ),
        )))
        .await
        .unwrap();

        let err = session.next().await.unwrap().unwrap_err();
        assert!(matches!(err, ReadSessionError::Timeout(_)));
        assert!(!session.is_caught_up());
        assert_eq!(resolved_cu.await.unwrap(), position(1));
        assert!(matches!(
            pending_cu.await,
            Err(ReadSessionError::Timeout(_))
        ));
        assert!(matches!(
            session.caught_up().await,
            Err(ReadSessionError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn dropping_session_rejects_wait() {
        let cu = {
            let (session, _tx, _state, _shutdown) = test_session_parts(None);
            session.caught_up()
        };

        assert!(matches!(
            cu.await,
            Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
        ));
    }

    #[tokio::test]
    async fn client_shutdown_wakes_caught_up_even_when_driver_exited() {
        let (session, tx, state, shutdown) = test_session_parts(Some(0));
        let cu = session.caught_up();
        // Simulate driver pushing a batch and CleanEnd, then exiting before consumer polls.
        state.on_message_fetched(Some(0), Some(position(1)));
        tx.send(DriverEvent::Batch(batch(
            vec![record(0, false)],
            Some(position(1)),
        )))
        .await
        .unwrap();
        state.on_clean_stop(None);
        tx.send(DriverEvent::CleanEnd).await.unwrap();
        drop(tx);

        // Client closes without polling `session`; pending `caught_up()` must wake immediately.
        shutdown.close();
        assert!(!session.is_caught_up());
        assert!(matches!(cu.await, Err(ReadSessionError::Aborted(_))));
        assert!(matches!(
            session.caught_up().await,
            Err(ReadSessionError::Aborted(_))
        ));
    }

    #[test]
    fn validate_read_batch_order_rejects_duplicate_and_backward_seq_nums() {
        let ctx = ErrorContext::default().into_read_only();
        let b1 = batch(vec![record(0, false), record(2, false)], None);
        let last = validate_read_batch_order(&b1, None, &ctx).unwrap();
        assert_eq!(last, Some(2));

        let dup = batch(vec![record(2, false)], None);
        assert!(matches!(
            validate_read_batch_order(&dup, last, &ctx),
            Err(ReadSessionError::Protocol(_))
        ));

        let backward_within = batch(vec![record(5, false), record(4, false)], None);
        assert!(matches!(
            validate_read_batch_order(&backward_within, last, &ctx),
            Err(ReadSessionError::Protocol(_))
        ));
    }
}
