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
use s2_api::v1::stream::{ReadEnd, ReadStart, proto};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, timeout},
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, debug, debug_span};

use crate::{
    api::{BasinClient, Streaming},
    client::CancellationToken,
    error::{
        AbortedError, ConnectionLostError, ErrorContext, ProtocolError, ReadSessionError,
        SessionClosedError, TimeoutError, TransportError,
    },
    reconnect::AdvisedReconnects,
    retry::RetryBackoff,
    session::StreamHeaders,
    types::{MeteredBytes, ReadBatch, ReadInput, SequencedRecord, StreamName, StreamPosition},
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
#[must_use]
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

type CaughtUpResult = Result<StreamPosition, ReadSessionError>;

#[derive(Clone)]
enum CaughtUpFuture {
    Pending(Shared<oneshot::Receiver<CaughtUpResult>>),
    Ready(CaughtUpResult),
}

impl Future for CaughtUpFuture {
    type Output = CaughtUpResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Pending(rx) => match Pin::new(rx).poll(cx) {
                Poll::Ready(Ok(result)) => Poll::Ready(result),
                Poll::Ready(Err(_)) => {
                    unreachable!("ReadSessionCore::drop resolves every pending CaughtUp")
                }
                Poll::Pending => Poll::Pending,
            },
            Self::Ready(result) => Poll::Ready(result.clone()),
        }
    }
}

/// Future returned by [`ReadSession::caught_up`], [`ReadBatchSession::caught_up`], and
/// [`ReadSessionState::caught_up`].
///
/// Resolves to the stream tail position when the session is caught up, or fails with the session's
/// terminal error (or [`SessionClosedError`] if the session closes cleanly before catching up).
#[derive(Clone)]
#[must_use = "futures do nothing unless `.await`ed or polled"]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestPhase {
    Connecting,
    Open { latest_tail: Option<StreamPosition> },
    Ended,
}

enum CatchUpSlot {
    Pending {
        tx: oneshot::Sender<CaughtUpResult>,
        future: CaughtUpFuture,
    },
    CaughtUp {
        tail: StreamPosition,
        future: CaughtUpFuture,
    },
    Ended(ReadSessionError),
}

impl CatchUpSlot {
    fn pending() -> Self {
        let (tx, rx) = oneshot::channel();
        Self::Pending {
            tx,
            future: CaughtUpFuture::Pending(rx.shared()),
        }
    }

    fn is_caught_up(&self) -> bool {
        matches!(self, Self::CaughtUp { .. })
    }

    fn future(&self) -> CaughtUpFuture {
        match self {
            Self::Pending { future, .. } | Self::CaughtUp { future, .. } => future.clone(),
            Self::Ended(err) => CaughtUpFuture::Ready(Err(err.clone())),
        }
    }
}

struct ReadStateInner {
    next_seq_num: Option<u64>,
    last_observed_tail: Option<StreamPosition>,
    phase: RequestPhase,
    catch_up: CatchUpSlot,
    context: ErrorContext,
}

impl ReadStateInner {
    fn new(initial_next_seq_num: Option<u64>, context: ErrorContext) -> Self {
        Self {
            next_seq_num: initial_next_seq_num,
            last_observed_tail: None,
            phase: RequestPhase::Connecting,
            catch_up: CatchUpSlot::pending(),
            context,
        }
    }

    fn compute_caught_up_tail(&self) -> Option<StreamPosition> {
        let RequestPhase::Open {
            latest_tail: Some(tail),
        } = self.phase
        else {
            return None;
        };
        (self.next_seq_num == Some(tail.seq_num)).then_some(tail)
    }

    fn recompute_caught_up(&mut self) {
        if self.phase == RequestPhase::Ended {
            return;
        }
        match self.compute_caught_up_tail() {
            Some(tail) => {
                if !matches!(self.catch_up, CatchUpSlot::CaughtUp { tail: prev, .. } if prev == tail)
                {
                    let prev = std::mem::replace(
                        &mut self.catch_up,
                        CatchUpSlot::CaughtUp {
                            tail,
                            future: CaughtUpFuture::Ready(Ok(tail)),
                        },
                    );
                    if let CatchUpSlot::Pending { tx, .. } = prev {
                        let _ = tx.send(Ok(tail));
                    }
                }
            }
            None => {
                if self.catch_up.is_caught_up() {
                    self.catch_up = CatchUpSlot::pending();
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
        if self.phase == RequestPhase::Ended {
            return false;
        }
        self.phase = RequestPhase::Open { latest_tail: tail };
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
        if self.phase == RequestPhase::Ended {
            return;
        }
        self.phase = RequestPhase::Connecting;
        self.recompute_caught_up();
    }

    fn on_clean_stop(&mut self, tail: Option<StreamPosition>) {
        if self.phase == RequestPhase::Ended {
            return;
        }
        let latest_tail = tail.or(match self.phase {
            RequestPhase::Open { latest_tail } => latest_tail,
            RequestPhase::Connecting | RequestPhase::Ended => None,
        });
        self.phase = RequestPhase::Open { latest_tail };
        if let Some(tail) = tail {
            self.update_observed_tail(tail);
        }
        self.recompute_caught_up();
    }

    fn on_record_delivered(&mut self, seq_num: u64) {
        self.next_seq_num = Some(seq_num.saturating_add(1));
        if self.phase != RequestPhase::Ended {
            self.recompute_caught_up();
        }
    }

    fn on_heartbeat_delivered(&mut self, tail: StreamPosition) {
        if self.phase == RequestPhase::Ended {
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
        if self.phase == RequestPhase::Ended {
            return;
        }
        self.phase = RequestPhase::Ended;

        let terminal_err = error.unwrap_or_else(|| {
            ReadSessionError::SessionClosed(SessionClosedError::new(None, self.context.clone()))
        });
        // Any future handed out *before* ending retains its resolved tail (`R8a`).
        // Subsequent `caught_up()` calls after the session ends see the terminal error (`R8d`).
        let prev = std::mem::replace(&mut self.catch_up, CatchUpSlot::Ended(terminal_err.clone()));
        if let CatchUpSlot::Pending { tx, .. } = prev {
            let _ = tx.send(Err(terminal_err));
        }
    }
}

/// Concurrently accessible read-session progress state.
///
/// Cloneable handle to observe [`next_seq_num`](Self::next_seq_num),
/// [`last_observed_tail`](Self::last_observed_tail), [`is_caught_up`](Self::is_caught_up), and
/// [`caught_up`](Self::caught_up) from another task while a single consumer iterates the
/// [`ReadSession`] or [`ReadBatchSession`]. None of its methods block.
#[derive(Clone)]
pub struct ReadSessionState {
    inner: Arc<StdMutex<ReadStateInner>>,
    shutdown: CancellationToken,
}

impl fmt::Debug for ReadSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        let caught_up = !self.shutdown.is_cancelled() && inner.catch_up.is_caught_up();
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
        shutdown: CancellationToken,
        context: ErrorContext,
    ) -> Self {
        Self {
            inner: Arc::new(StdMutex::new(ReadStateInner::new(
                initial_next_seq_num,
                context,
            ))),
            shutdown,
        }
    }

    /// Return the sequence number of the next record the session will deliver.
    ///
    /// An unclamped `ReadStart::SeqNum` start is known immediately; any other start returns `None`
    /// until resolved by the first server response. Updated before each record (or batch) is
    /// handed to the caller, and advances on heartbeats. Retained after iteration ends.
    pub fn next_seq_num(&self) -> Option<u64> {
        self.inner.lock().unwrap().next_seq_num
    }

    /// Return the latest stream tail reported by the server.
    ///
    /// Never moves backward, persists across retries and handovers, and is retained after
    /// iteration ends.
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.inner.lock().unwrap().last_observed_tail
    }

    /// Return whether the active request is open and its most recent server message reported a
    /// tail equal to [`next_seq_num`](Self::next_seq_num).
    ///
    /// Returns `false` while reconnecting or once iteration has ended.
    pub fn is_caught_up(&self) -> bool {
        !self.shutdown.is_cancelled() && self.inner.lock().unwrap().catch_up.is_caught_up()
    }

    /// Return a future that resolves to the tail position once the session is caught up.
    ///
    /// Resolves immediately if currently caught up, or the next time the session becomes caught
    /// up. Once resolved, its value never changes. Does not drive reading — continue polling the
    /// session while awaiting it. Remains pending across retries and handovers. Fails with the
    /// session's failure, or [`SessionClosedError`] if the session closes cleanly before catching
    /// up.
    pub fn caught_up(&self) -> CaughtUp {
        let mut inner = self.inner.lock().unwrap();
        if self.shutdown.is_cancelled() && inner.phase != RequestPhase::Ended {
            let err = ReadSessionError::Aborted(AbortedError::new(
                "client closed",
                inner.context.clone(),
            ));
            inner.on_ended(Some(err));
        }
        CaughtUp(inner.catch_up.future())
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
    shutdown: CancellationToken,
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
        let basin = client.name.clone();
        let context = ErrorContext::stream(op_name, basin.as_ref(), name.as_ref(), true);
        let shutdown = client.shutdown_token();
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
        let span = debug_span!("read_session", op = op_name, basin = %basin, stream = %name);
        let driver = ReadDriver::new(
            client,
            name,
            headers,
            start,
            end,
            config.retry_policy,
            op_name,
            state.clone(),
            tx,
            shutdown.clone(),
            context.clone(),
        );
        let handle = tokio::spawn(driver.run().instrument(span));

        Self {
            rx,
            state,
            shutdown,
            context,
            terminated: false,
            _driver: AbortOnDropHandle::new(handle),
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

    fn poll_next_batch(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<ReadBatch, ReadSessionError>>> {
        if self.terminated {
            return Poll::Ready(None);
        }
        loop {
            // `ReadDriver` wakes `self.rx` by dropping `tx` upon `shutdown.cancelled()`, so
            // checking `is_cancelled()` here handles both immediate and parked aborts (`C12`).
            if self.shutdown.is_cancelled() {
                return Poll::Ready(Some(Err(self.abort_now())));
            }
            match self.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(DriverEvent::Batch(batch))) => {
                    if !batch.records.is_empty() {
                        return Poll::Ready(Some(Ok(batch)));
                    }
                }
                Poll::Ready(Some(DriverEvent::Heartbeat(tail))) => {
                    self.state.on_heartbeat_delivered(tail);
                }
                Poll::Ready(Some(DriverEvent::CleanEnd)) | Poll::Ready(None) => {
                    if self.shutdown.is_cancelled() {
                        return Poll::Ready(Some(Err(self.abort_now())));
                    }
                    self.terminated = true;
                    self.rx.close();
                    self.state.on_ended(None);
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(DriverEvent::Error(err))) => {
                    self.terminated = true;
                    self.rx.close();
                    self.state.on_ended(Some(err.clone()));
                    return Poll::Ready(Some(Err(err)));
                }
            }
        }
    }
}

impl Drop for ReadSessionCore {
    fn drop(&mut self) {
        if self.shutdown.is_cancelled() {
            self.state
                .on_aborted(AbortedError::new("client closed", self.context.clone()));
        } else {
            self.state.on_ended(None);
        }
    }
}

/// A continuous stream of sequenced records.
///
/// Yields individual [`SequencedRecord`]s in sequence-number order. Dropping the session closes it
/// immediately. Use [`state`](Self::state) to observe progress concurrently from other tasks.
#[must_use = "sessions do nothing unless polled"]
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
    pub(crate) fn open(
        client: BasinClient,
        name: StreamName,
        headers: StreamHeaders,
        input: ReadInput,
        config: ReadSessionConfig,
    ) -> Self {
        Self {
            core: ReadSessionCore::open(client, name, headers, input, config, "read_session"),
            current_batch: VecDeque::new(),
        }
    }

    /// Return the next sequenced record from the session, or `None` when the session ends cleanly.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe and can be used inside [`tokio::select!`].
    pub async fn next(&mut self) -> Option<Result<SequencedRecord, ReadSessionError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    /// Return a cloneable handle to this session's concurrent progress state.
    pub fn state(&self) -> ReadSessionState {
        self.core.state.clone()
    }

    /// Return the sequence number of the next record this session will deliver.
    pub fn next_seq_num(&self) -> Option<u64> {
        self.core.state.next_seq_num()
    }

    /// Return the latest stream tail reported by the server.
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether all records through the active request's latest reported tail have been
    /// delivered.
    pub fn is_caught_up(&self) -> bool {
        self.core.state.is_caught_up()
    }

    /// Return a future for the current or next caught-up tail.
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
        if this.core.shutdown.is_cancelled() {
            this.current_batch.clear();
            return Poll::Ready(Some(Err(this.core.abort_now())));
        }

        if let Some(record) = this.current_batch.pop_front() {
            this.core.state.on_record_delivered(record.seq_num);
            return Poll::Ready(Some(Ok(record)));
        }

        match this.core.poll_next_batch(cx) {
            Poll::Ready(Some(Ok(batch))) => {
                this.current_batch = batch.records.into();
                let record = this
                    .current_batch
                    .pop_front()
                    .expect("poll_next_batch filters empty batches");
                this.core.state.on_record_delivered(record.seq_num);
                Poll::Ready(Some(Ok(record)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A continuous stream of non-empty read batches.
///
/// Delivers each server batch whole, skips empty heartbeat frames while updating session state,
/// and follows all read-session rules per batch. Dropping the session closes it immediately.
#[must_use = "sessions do nothing unless polled"]
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
    pub(crate) fn open(
        client: BasinClient,
        name: StreamName,
        headers: StreamHeaders,
        input: ReadInput,
        config: ReadSessionConfig,
    ) -> Self {
        Self {
            core: ReadSessionCore::open(client, name, headers, input, config, "read_batch_session"),
        }
    }

    /// Return the next non-empty batch from the session, or `None` when the session ends cleanly.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe and can be used inside [`tokio::select!`].
    pub async fn next(&mut self) -> Option<Result<ReadBatch, ReadSessionError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    /// Return a cloneable handle to this session's concurrent progress state.
    pub fn state(&self) -> ReadSessionState {
        self.core.state.clone()
    }

    /// Return the sequence number of the next record this session will deliver.
    pub fn next_seq_num(&self) -> Option<u64> {
        self.core.state.next_seq_num()
    }

    /// Return the latest stream tail reported by the server.
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether all records through the active request's latest reported tail have been
    /// delivered.
    pub fn is_caught_up(&self) -> bool {
        self.core.state.is_caught_up()
    }

    /// Return a future for the current or next caught-up tail.
    pub fn caught_up(&self) -> CaughtUp {
        self.core.state.caught_up()
    }
}

impl Stream for ReadBatchSession {
    type Item = Result<ReadBatch, ReadSessionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.core.poll_next_batch(cx) {
            Poll::Ready(Some(Ok(batch))) => {
                let last = batch
                    .records
                    .last()
                    .expect("poll_next_batch filters empty batches");
                this.core.state.on_record_delivered(last.seq_num);
                Poll::Ready(Some(Ok(batch)))
            }
            other => other,
        }
    }
}

struct ActiveAttempt {
    stream: Streaming<proto::ReadBatch, ReadSessionError>,
    made_progress: bool,
    fetched_record: bool,
}

struct ReadDriver {
    client: BasinClient,
    name: StreamName,
    headers: StreamHeaders,
    start: ReadStart,
    end: ReadEnd,
    baseline_wait: Option<u32>,
    has_stop_option: bool,
    retry_policy: ReadSessionRetryPolicy,
    refreshes_tokens: bool,
    op_name: &'static str,
    state: ReadSessionState,
    tx: mpsc::Sender<DriverEvent>,
    shutdown: CancellationToken,
    context: ErrorContext,
    retry_backoff: RetryBackoff,
    advised_reconnects: AdvisedReconnects,
    idle_since: Option<Instant>,
    has_received_response: bool,
    last_fetched_seq: Option<u64>,
    active: Option<ActiveAttempt>,
}

impl ReadDriver {
    #[allow(clippy::too_many_arguments)]
    fn new(
        client: BasinClient,
        name: StreamName,
        headers: StreamHeaders,
        start: ReadStart,
        end: ReadEnd,
        retry_policy: ReadSessionRetryPolicy,
        op_name: &'static str,
        state: ReadSessionState,
        tx: mpsc::Sender<DriverEvent>,
        shutdown: CancellationToken,
        context: ErrorContext,
    ) -> Self {
        let retry_backoff = RetryBackoff::from_config(&client.base().retry_config());
        let refreshes_tokens = client.base().refreshes_tokens();
        let baseline_wait = end.wait;
        let has_stop_option =
            end.count.is_some() || end.bytes.is_some() || end.until.is_some() || end.wait.is_some();
        Self {
            client,
            name,
            headers,
            start,
            end,
            baseline_wait,
            has_stop_option,
            retry_policy,
            refreshes_tokens,
            op_name,
            state,
            tx,
            shutdown,
            context,
            retry_backoff,
            advised_reconnects: AdvisedReconnects::default(),
            idle_since: None,
            has_received_response: false,
            last_fetched_seq: None,
            active: None,
        }
    }

    fn abort(&mut self) {
        self.active = None;
        debug!("aborting read session on client close");
        self.state
            .on_aborted(AbortedError::new("client closed", self.context.clone()));
    }

    /// Enqueue a terminal event and stay parked until the consumer consumes it (closing `rx`) or
    /// the client shuts down, so any pending `caught_up()` future still wakes immediately on
    /// `S2::close()` while records or a terminal event sit buffered (`C12`, `R8d`).
    async fn send_terminal_event(&mut self, event: DriverEvent) {
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => {
                self.abort();
                return;
            }
            res = self.tx.send(event) => {
                if res.is_err() {
                    return;
                }
            }
        }
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => self.abort(),
            _ = self.tx.closed() => {}
        }
    }

    /// Sleep for retry backoff while racing client shutdown and consumer drop.
    /// Returns `true` if the driver should terminate.
    async fn sleep_or_stop(&mut self, backoff: Duration) -> bool {
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => {
                self.abort();
                true
            }
            _ = self.tx.closed() => true,
            _ = tokio::time::sleep(backoff) => false,
        }
    }

    async fn finish_resumed_unwritten_stop(&mut self, tail: Option<StreamPosition>) {
        debug!(?tail, "read session reached tail on resumed stop condition");
        self.state.on_clean_stop(tail);
        if let Some(tail) = tail.filter(|_| !self.state.is_caught_up()) {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => {
                    self.abort();
                    return;
                }
                res = self.tx.send(DriverEvent::Heartbeat(tail)) => {
                    if res.is_err() {
                        return;
                    }
                }
            }
        }
        self.send_terminal_event(DriverEvent::CleanEnd).await;
    }

    /// Retry `err` according to `retry_policy`, or deliver the terminal error to the consumer.
    /// Returns `true` if the driver should continue retrying, or `false` to exit.
    async fn retry_or_fail(&mut self, err: ReadSessionError) -> bool {
        let attempts = self.retry_backoff.attempt_number();
        if let Some(backoff) = retry_delay(
            &err,
            &mut self.retry_backoff,
            self.retry_policy,
            self.refreshes_tokens,
        ) {
            return !self.sleep_or_stop(backoff).await;
        }
        let final_err = err.with_context(&self.context.clone().with_attempts(attempts));
        self.send_terminal_event(DriverEvent::Error(final_err))
            .await;
        false
    }

    async fn run(mut self) {
        loop {
            if self.shutdown.is_cancelled() {
                self.abort();
                return;
            }
            if self.tx.is_closed() {
                return;
            }

            if self.active.is_none() {
                self.end.wait = remaining_wait(self.baseline_wait, self.idle_since);
                let attempt_num = self.retry_backoff.attempt_number();
                debug!(
                    attempt = attempt_num,
                    resume_seq_num = ?self.start.seq_num,
                    "opening read session request"
                );

                let open_res = tokio::select! {
                    biased;
                    _ = self.shutdown.cancelled() => {
                        self.abort();
                        return;
                    }
                    _ = self.tx.closed() => return,
                    res = self.client.read_session(
                        self.op_name,
                        &self.name,
                        self.start.clone(),
                        self.end.clone(),
                        &self.headers,
                        attempt_num,
                    ) => res,
                };

                if self.shutdown.is_cancelled() {
                    self.abort();
                    return;
                }

                match open_res {
                    Ok(stream) => {
                        self.active = Some(ActiveAttempt {
                            stream,
                            made_progress: false,
                            fetched_record: false,
                        });
                    }
                    Err(err) => {
                        // R11d: once the start has been resolved by a prior response, a resumed
                        // request with no wait remaining that receives 416 with `tail >= resume`
                        // has reached the tail on a stop condition.
                        if let Some(tail) = resumed_unwritten_stop_tail(
                            self.has_received_response,
                            &self.start,
                            &self.end,
                            &err,
                        ) {
                            self.finish_resumed_unwritten_stop(tail).await;
                            return;
                        }
                        if self.retry_or_fail(err).await {
                            continue;
                        }
                        return;
                    }
                }
            }

            // R6b + T7d: wait for channel capacity BEFORE reading the next message so we decode at
            // most 1 batch ahead and do not count caller backpressure against the heartbeat
            // timeout.
            let tx = self.tx.clone();
            let permit = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => {
                    self.abort();
                    return;
                }
                res = tx.reserve() => match res {
                    Ok(permit) => permit,
                    Err(_) => return,
                },
            };

            let Some(next_res) = ({
                let attempt = self.active.as_mut().expect("active stream must be Some");
                tokio::select! {
                    biased;
                    _ = self.shutdown.cancelled() => None,
                    _ = self.tx.closed() => return,
                    res = timeout(HEARTBEAT_TIMEOUT, attempt.stream.next()) => Some(res),
                }
            }) else {
                drop(permit);
                self.abort();
                return;
            };

            if self.shutdown.is_cancelled() {
                drop(permit);
                self.abort();
                return;
            }

            let item = match next_res {
                Ok(Some(Ok(frame))) => {
                    Ok(Some((ReadBatch::from(frame.msg), frame.reconnect_advised)))
                }
                Ok(Some(Err(err))) => Err(err),
                Ok(None) => Ok(None),
                Err(_) => {
                    if let Some(active) = self.active.as_ref() {
                        active.stream.poison_connection();
                    }
                    Err(ReadSessionError::Timeout(TimeoutError::new(
                        "heartbeat timeout",
                        self.context.clone(),
                    )))
                }
            };

            match item {
                Ok(Some((batch, reconnect_advised))) => {
                    // R6: verify records arrive in strictly increasing seq_num order.
                    match validate_read_batch_order(&batch, self.last_fetched_seq, &self.context) {
                        Ok(new_last) => self.last_fetched_seq = new_last,
                        Err(err) => {
                            drop(permit);
                            self.active = None;
                            self.state.on_disconnected();
                            self.send_terminal_event(DriverEvent::Error(err)).await;
                            return;
                        }
                    }

                    let attempt = self.active.as_mut().expect("active stream must be Some");
                    attempt.made_progress = true;
                    self.has_received_response = true;
                    self.retry_backoff.reset();

                    // R11c: restart idle clock only when a record is fetched; if no record has
                    // been fetched yet, start the clock the first time we learn we are at the tail.
                    // Heartbeats never restart this clock.
                    if !batch.records.is_empty() {
                        attempt.fetched_record = true;
                        self.idle_since = Some(Instant::now());
                    } else if self.last_fetched_seq.is_none() && batch.tail.is_some() {
                        self.idle_since.get_or_insert_with(Instant::now);
                    }

                    update_resume_start(&mut self.start, &batch);
                    if let Some(count) = self.end.count.as_mut() {
                        *count = count.saturating_sub(batch.records.len() as u64);
                    }
                    if let Some(bytes) = self.end.bytes.as_mut() {
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
                    let heartbeat_already_at_tail =
                        self.state.on_message_fetched(first_record_seq, tail);

                    if !batch.records.is_empty() {
                        permit.send(DriverEvent::Batch(batch));
                    } else if let Some(tail) = tail
                        && !heartbeat_already_at_tail
                    {
                        permit.send(DriverEvent::Heartbeat(tail));
                    } else {
                        drop(permit);
                    }

                    // T6a: act on reconnect advice immediately (at most once per cooldown window).
                    if reconnect_advised && self.advised_reconnects.should_reconnect() {
                        self.active = None;
                        if read_limits_exhausted(&self.end) {
                            debug!("read session limits exhausted on advised reconnect");
                            self.state.on_clean_stop(None);
                            self.send_terminal_event(DriverEvent::CleanEnd).await;
                            return;
                        }
                        self.advised_reconnects.record();
                        debug!(
                            next_seq_num = ?self.start.seq_num,
                            advised_reconnects = self.advised_reconnects.total(),
                            "reconnecting read session on server advice"
                        );
                        self.state.on_disconnected();
                    }
                }
                Ok(None) => {
                    drop(permit);
                    // T9 / R9a: clean EOF ends iteration cleanly ONLY when a stop option was set;
                    // otherwise it is a ConnectionLostError and retried per retry_policy.
                    let fetched_record = self.active.take().is_some_and(|a| a.fetched_record);
                    if self.has_stop_option {
                        // R11c: if this attempt ran with a reduced `wait` budget and fetched new
                        // records (restarting the idle clock), reconnect with the refreshed wait
                        // rather than stopping prematurely when the server's shorter timer expires.
                        if fetched_record
                            && !read_limits_exhausted(&self.end)
                            && let (Some(base_w), Some(sent_w)) =
                                (self.baseline_wait, self.end.wait)
                            && sent_w < base_w
                            && remaining_wait(self.baseline_wait, self.idle_since)
                                .is_some_and(|w| w > 0)
                        {
                            self.state.on_disconnected();
                            continue;
                        }
                        debug!("read session ended cleanly on stop condition");
                        self.state.on_clean_stop(None);
                        self.send_terminal_event(DriverEvent::CleanEnd).await;
                        return;
                    }
                    let err = ReadSessionError::ConnectionLost(ConnectionLostError::new(
                        "read stream ended cleanly without a stop condition",
                        true,
                        self.context.clone(),
                    ));
                    self.state.on_disconnected();
                    if self.retry_or_fail(err).await {
                        continue;
                    }
                    return;
                }
                Err(err) => {
                    drop(permit);
                    // T10: drop underlying attempt stream immediately.
                    let made_progress = self.active.take().is_some_and(|a| a.made_progress);

                    // R11d: 416 on a resumed request with no remaining wait is a clean stop unless
                    // the reported tail regressed below our resume position.
                    if let Some(tail) = resumed_unwritten_stop_tail(
                        self.has_received_response,
                        &self.start,
                        &self.end,
                        &err,
                    ) {
                        self.finish_resumed_unwritten_stop(tail).await;
                        return;
                    }

                    // If `count` or `bytes` is already exhausted after receiving data, all
                    // requested records have been fetched; end cleanly rather than reconnecting
                    // with count=0/bytes=0.
                    if self.has_received_response && read_limits_exhausted(&self.end) {
                        debug!("read session limits exhausted after stream error");
                        self.state.on_clean_stop(None);
                        self.send_terminal_event(DriverEvent::CleanEnd).await;
                        return;
                    }

                    self.state.on_disconnected();

                    if err.is_server_draining() && made_progress {
                        debug!(
                            next_seq_num = ?self.start.seq_num,
                            "reconnecting read session while server drains"
                        );
                        continue;
                    }

                    if self.retry_or_fail(err).await {
                        continue;
                    }
                    return;
                }
            }
        }
    }
}

/// If `err` is an HTTP `416` (`Range Not Satisfiable`), return `Some(tail)` where `tail` is
/// `Some(pos)` for typed `ReadUnwritten` and `None` for plain `416`.
fn range_not_satisfiable_tail(err: &ReadSessionError) -> Option<Option<StreamPosition>> {
    match err {
        ReadSessionError::ReadUnwritten(e) => Some(Some(e.tail)),
        ReadSessionError::Server(e) if e.status == StatusCode::RANGE_NOT_SATISFIABLE => Some(None),
        _ => None,
    }
}

/// Check whether an error is a clean `R11d` stop condition (resumed request with no remaining
/// `wait` receiving `416` whose tail has not regressed below `start.seq_num`).
fn resumed_unwritten_stop_tail(
    has_received_response: bool,
    start: &ReadStart,
    end: &ReadEnd,
    err: &ReadSessionError,
) -> Option<Option<StreamPosition>> {
    if !has_received_response || !has_no_wait_remaining(end) {
        return None;
    }
    let tail = range_not_satisfiable_tail(err)?;
    if let (Some(tail_pos), Some(resume_seq)) = (tail, start.seq_num)
        && tail_pos.seq_num < resume_seq
    {
        return None;
    }
    Some(tail)
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
    err: &ReadSessionError,
    backoffs: &mut RetryBackoff,
    retry_policy: ReadSessionRetryPolicy,
    refreshes_tokens: bool,
) -> Option<Duration> {
    let is_retryable = err.is_retryable() || (refreshes_tokens && err.is_authentication_error());
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
        ReadSessionRetryPolicy::Unbounded => Some(backoffs.next_unbounded()),
    };
    if let Some(backoff) = backoff {
        let retries_remaining = match retry_policy {
            ReadSessionRetryPolicy::Budgeted => Some(backoffs.remaining()),
            ReadSessionRetryPolicy::Unbounded => None,
        };
        debug!(
            %err,
            ?backoff,
            ?retry_policy,
            ?retries_remaining,
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
    fn resumed_unwritten_rejects_416_when_tail_regressed_below_resume_seq_num() {
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

        let at_tail =
            ReadSessionError::ReadUnwritten(ReadUnwrittenError::new(position(10), server_416()));
        assert_eq!(
            resumed_unwritten_stop_tail(true, &start, &end, &at_tail),
            Some(Some(position(10)))
        );

        let trimmed_past =
            ReadSessionError::ReadUnwritten(ReadUnwrittenError::new(position(15), server_416()));
        assert_eq!(
            resumed_unwritten_stop_tail(true, &start, &end, &trimmed_past),
            Some(Some(position(15)))
        );

        let recreated_lower =
            ReadSessionError::ReadUnwritten(ReadUnwrittenError::new(position(3), server_416()));
        assert_eq!(
            resumed_unwritten_stop_tail(true, &start, &end, &recreated_lower),
            None
        );
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
        CancellationToken,
    ) {
        let context = ErrorContext::default().into_read_only();
        let shutdown = CancellationToken::new();
        let state = ReadSessionState::new(initial_next_seq_num, shutdown.clone(), context.clone());
        let (tx, rx) = mpsc::channel(4);
        let driver_shutdown = shutdown.clone();
        let driver_state = state.clone();
        let driver_ctx = context.clone();
        let driver = tokio::spawn(async move {
            driver_shutdown.cancelled().await;
            driver_state.on_aborted(AbortedError::new("client closed", driver_ctx));
        });
        let session = ReadSession {
            core: ReadSessionCore {
                rx,
                state: state.clone(),
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
    async fn dropping_session_after_client_shutdown_reports_aborted() {
        let (session, _tx, state, shutdown) = test_session_parts(None);
        let cu = session.caught_up();
        shutdown.cancel();
        drop(session);

        assert!(matches!(cu.await, Err(ReadSessionError::Aborted(_))));
        assert!(matches!(
            state.caught_up().await,
            Err(ReadSessionError::Aborted(_))
        ));
    }

    #[tokio::test]
    async fn client_shutdown_wakes_caught_up_while_terminal_event_is_buffered() {
        let (session, tx, state, shutdown) = test_session_parts(Some(0));
        let cu = session.caught_up();
        // Simulate driver pushing a batch and CleanEnd, then parking until rx closes.
        state.on_message_fetched(Some(0), Some(position(1)));
        tx.send(DriverEvent::Batch(batch(
            vec![record(0, false)],
            Some(position(1)),
        )))
        .await
        .unwrap();
        state.on_clean_stop(None);
        tx.send(DriverEvent::CleanEnd).await.unwrap();

        // Client closes without polling `session`; pending `caught_up()` must wake immediately.
        shutdown.cancel();
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
