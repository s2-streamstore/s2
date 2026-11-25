use std::{
    fmt,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
    time::Duration,
};

use futures_core::{FusedFuture, FusedStream, Stream};
use futures_util::future::{FutureExt, Shared};
use http::StatusCode;
use s2_api::v1::stream::{ReadEnd, ReadStart, proto};
use tokio::{
    sync::oneshot,
    time::{Instant, Sleep},
};
use tokio_util::sync::WaitForCancellationFutureOwned;
use tracing::{Instrument, Span, debug, debug_span};

use crate::{
    api::{BasinClient, Streaming},
    client::CancellationToken,
    error::{
        AbortedError, ConnectionLostError, ErrorContext, ProtocolError, ReadSessionError,
        SessionClosedError, TimeoutError, TransportError, ValidationError,
    },
    reconnect::AdvisedReconnects,
    retry::RetryBackoff,
    session::StreamHeaders,
    types::{BasinName, ReadBatch, ReadInput, SequencedRecord, StreamName, StreamPosition},
};

/// Retry policy for a continuous read session.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Hash)]
pub enum ReadSessionRetryPolicy {
    /// Stop after the retry budget configured by [`RetryConfig`](crate::types::RetryConfig) is
    /// exhausted.
    #[default]
    Budgeted,
    /// Keep retrying retryable failures after the configured retry budget is exhausted.
    ///
    /// This also applies to the initial attempt, so iteration may remain pending through
    /// retryable failures until it connects, the session is dropped, or
    /// [`S2::close`](crate::S2::close) is called.
    ///
    /// Retries are silent to the caller and logged only at `debug` level. If your application
    /// needs per-outage error callbacks or disconnected/unhealthy status reporting, prefer
    /// [`Budgeted`](Self::Budgeted) inside an outer reconnect loop that resumes from
    /// [`ReadSession::next_seq_num`] (or [`ReadBatchSession::next_seq_num`]).
    Unbounded,
}

impl ReadSessionRetryPolicy {
    /// Return the setting name of this retry policy.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Budgeted => "budgeted",
            Self::Unbounded => "unbounded",
        }
    }
}

impl AsRef<str> for ReadSessionRetryPolicy {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for ReadSessionRetryPolicy {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "budgeted" => Ok(Self::Budgeted),
            "unbounded" => Ok(Self::Unbounded),
            _ => Err(ValidationError(format!(
                "invalid read session retry policy `{s}`: expected `budgeted` or `unbounded`"
            ))),
        }
    }
}

impl fmt::Display for ReadSessionRetryPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration for a continuous read session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
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
    #[must_use]
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

/// Future returned by [`ReadSession::caught_up`], [`ReadBatchSession::caught_up`], and
/// [`ReadSessionState::caught_up`].
///
/// Resolves to the stream tail position when the session is caught up, or fails with the session's
/// terminal error (or [`SessionClosedError`] if the session closes cleanly before catching up).
///
/// **Important:** Does not drive reading — continue polling the session concurrently (for example
/// via [`ReadSession::next`] in another task or `tokio::select!`) while awaiting this future, even
/// on an empty stream. Calling [`S2::close`](crate::S2::close) or dropping the session still
/// fails a pending `CaughtUp` future immediately even when no task is polling the session.
///
/// Once resolved, its value never changes, and re-polling returns the same outcome without
/// panicking.
#[must_use = "futures do nothing unless `.await`ed or polled"]
pub struct CaughtUp {
    inner: CaughtUpFuture,
    state: ReadSessionState,
    shutdown_wait: Option<Pin<Box<WaitForCancellationFutureOwned>>>,
    done: bool,
}

impl Clone for CaughtUp {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            state: self.state.clone(),
            shutdown_wait: None,
            done: false,
        }
    }
}

impl fmt::Debug for CaughtUp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaughtUp").finish_non_exhaustive()
    }
}

impl Future for CaughtUp {
    type Output = Result<StreamPosition, ReadSessionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        match &mut this.inner {
            CaughtUpFuture::Ready(result) => {
                this.done = true;
                Poll::Ready(result.clone())
            }
            CaughtUpFuture::Pending(rx) => {
                // Always check the shared catch-up slot first so an already-resolved tail (`R8a`)
                // or already-locked close reason (`R9`) is never overwritten by a later client
                // shutdown.
                if let Poll::Ready(res) = Pin::new(&mut *rx).poll(cx) {
                    let result = res.expect(
                        "ReadSessionCore::drop resolves every pending CaughtUp before dropping tx",
                    );
                    this.inner = CaughtUpFuture::Ready(result.clone());
                    this.shutdown_wait = None;
                    this.done = true;
                    return Poll::Ready(result);
                }

                // R8d / R9d / C12: observe client shutdown immediately even when no task is
                // polling the pull-driven session.
                let shutdown_fired = if this.state.shutdown.is_cancelled() {
                    true
                } else {
                    let wait = this.shutdown_wait.get_or_insert_with(|| {
                        Box::pin(this.state.shutdown.clone().cancelled_owned())
                    });
                    wait.as_mut().poll(cx).is_ready()
                };

                if !shutdown_fired {
                    return Poll::Pending;
                }

                // Commit abort if no close reason locked in first; either way, every `Pending`
                // slot is guaranteed resolved once `closed.is_some()`.
                {
                    let mut inner = this.state.inner.lock().unwrap();
                    if inner.closed.is_none() {
                        let err =
                            AbortedError::new_with_context("client closed", inner.context.clone());
                        inner.on_aborted(err);
                    }
                }

                match Pin::new(&mut *rx).poll(cx) {
                    Poll::Ready(Ok(result)) => {
                        this.inner = CaughtUpFuture::Ready(result.clone());
                        this.shutdown_wait = None;
                        this.done = true;
                        Poll::Ready(result)
                    }
                    Poll::Ready(Err(_)) => {
                        unreachable!("ReadSessionCore::drop resolves every pending CaughtUp")
                    }
                    Poll::Pending => {
                        unreachable!("committing abort resolves every pending CaughtUp slot")
                    }
                }
            }
        }
    }
}

impl FusedFuture for CaughtUp {
    fn is_terminated(&self) -> bool {
        self.done
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

#[derive(Debug, Clone)]
enum TerminalClose {
    Clean,
    Error(ReadSessionError),
}

struct ReadStateInner {
    next_seq_num: Option<u64>,
    last_observed_tail: Option<StreamPosition>,
    phase: RequestPhase,
    catch_up: CatchUpSlot,
    /// Locked-in session close reason (`R9`). Once set, later aborts or closes have no effect.
    /// When `Clean` is reached while already caught up, `phase` stays `Open` until iteration
    /// returns `None` so `is_caught_up()` stays `true` per `R7c`.
    closed: Option<TerminalClose>,
    context: ErrorContext,
}

impl ReadStateInner {
    fn new(initial_next_seq_num: Option<u64>, context: ErrorContext) -> Self {
        Self {
            next_seq_num: initial_next_seq_num,
            last_observed_tail: None,
            phase: RequestPhase::Connecting,
            catch_up: CatchUpSlot::pending(),
            closed: None,
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

    fn apply_clean_close(&mut self) {
        if self.closed.is_some() {
            return;
        }
        self.closed = Some(TerminalClose::Clean);
        if !self.catch_up.is_caught_up() {
            self.on_ended(None);
        }
    }

    /// Record a freshly decoded non-empty batch together with immediate delivery of its first
    /// record (record view) or entire batch (batch view).
    fn on_batch_decoded_and_delivered(
        &mut self,
        tail: Option<StreamPosition>,
        delivered_last_seq: u64,
        disconnected_for_advice: bool,
        finished_stop: bool,
    ) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        if let Some(tail) = tail {
            self.update_observed_tail(tail);
        }
        self.phase = if disconnected_for_advice {
            RequestPhase::Connecting
        } else {
            RequestPhase::Open { latest_tail: tail }
        };
        self.next_seq_num = Some(delivered_last_seq.saturating_add(1));
        self.recompute_caught_up();
        if finished_stop {
            self.apply_clean_close();
        }
    }

    /// Record delivery of a subsequent record from the current batch.
    fn on_record_delivered(&mut self, seq_num: u64, finished_stop: bool) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        self.next_seq_num = Some(seq_num.saturating_add(1));
        self.recompute_caught_up();
        if finished_stop {
            self.apply_clean_close();
        }
    }

    /// Record a decoded heartbeat (`records` empty, `tail` present). Because reading is
    /// pull-driven (`R6b`), no records remain undelivered when a heartbeat is decoded.
    fn on_heartbeat(&mut self, tail: StreamPosition, disconnected_for_advice: bool) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        self.update_observed_tail(tail);
        self.next_seq_num = Some(
            self.next_seq_num
                .map_or(tail.seq_num, |prev| prev.max(tail.seq_num)),
        );
        self.phase = RequestPhase::Open {
            latest_tail: Some(tail),
        };
        self.recompute_caught_up();
        if disconnected_for_advice {
            self.phase = RequestPhase::Connecting;
            self.recompute_caught_up();
        }
    }

    fn on_disconnected(&mut self) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        self.phase = RequestPhase::Connecting;
        self.recompute_caught_up();
    }

    /// Finalize a clean stop when iteration is returning end-of-stream (`R9a`, `R11d`).
    fn on_clean_end_now(&mut self, tail: Option<StreamPosition>) {
        if self.closed.is_none() {
            if let Some(tail) = tail {
                self.update_observed_tail(tail);
                self.next_seq_num = Some(
                    self.next_seq_num
                        .map_or(tail.seq_num, |prev| prev.max(tail.seq_num)),
                );
                self.phase = RequestPhase::Open {
                    latest_tail: Some(tail),
                };
                self.recompute_caught_up();
            }
            self.closed = Some(TerminalClose::Clean);
        }
        self.on_ended(None);
    }

    /// Finalize a terminal failure (`R9c`).
    fn on_terminal_error(&mut self, err: ReadSessionError) {
        if self.closed.is_some() || self.phase == RequestPhase::Ended {
            return;
        }
        self.closed = Some(TerminalClose::Error(err.clone()));
        self.on_ended(Some(err));
    }

    fn on_aborted(&mut self, err: AbortedError) -> bool {
        if self.closed.is_some() || self.phase == RequestPhase::Ended {
            return false;
        }
        let err = ReadSessionError::Aborted(err);
        self.closed = Some(TerminalClose::Error(err.clone()));
        self.on_ended(Some(err));
        true
    }

    fn on_ended(&mut self, error: Option<ReadSessionError>) {
        if self.phase == RequestPhase::Ended {
            return;
        }
        self.phase = RequestPhase::Ended;

        let terminal_err = error.unwrap_or_else(|| {
            ReadSessionError::SessionClosed(SessionClosedError::new_with_context(
                None,
                self.context.clone(),
            ))
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
        let aborted_before_close = self.shutdown.is_cancelled() && inner.closed.is_none();
        let caught_up = !aborted_before_close && inner.catch_up.is_caught_up();
        f.debug_struct("ReadSessionState")
            .field("next_seq_num", &inner.next_seq_num)
            .field("last_observed_tail", &inner.last_observed_tail)
            .field("is_caught_up", &caught_up)
            .finish_non_exhaustive()
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
    /// until resolved by the first decoded server message. Updated before each record (or batch)
    /// is handed to the caller, and advances on heartbeats. Retained after iteration ends.
    #[must_use]
    pub fn next_seq_num(&self) -> Option<u64> {
        self.inner.lock().unwrap().next_seq_num
    }

    /// Return the latest stream tail observed from a decoded server message.
    ///
    /// Never moves backward, persists across retries and handovers, and is retained after
    /// iteration ends.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.inner.lock().unwrap().last_observed_tail
    }

    /// Return whether the session is open with an active request whose most recent decoded
    /// message reported a tail equal to [`next_seq_num`](Self::next_seq_num).
    ///
    /// Returns `false` while reconnecting, after [`S2::close`](crate::S2::close) or session drop,
    /// or once iteration has ended.
    #[must_use]
    pub fn is_caught_up(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        let aborted_before_close = self.shutdown.is_cancelled() && inner.closed.is_none();
        !aborted_before_close && inner.catch_up.is_caught_up()
    }

    /// Return a future that resolves to the tail position once the session is caught up.
    ///
    /// Resolves immediately if currently caught up, or the next time the session becomes caught
    /// up. Once resolved, its value never changes. Does not drive reading — continue polling the
    /// session while awaiting it (even on an empty stream). Remains pending across retries and
    /// handovers. Fails immediately on session close or [`S2::close`](crate::S2::close), even when
    /// no task is polling the session.
    pub fn caught_up(&self) -> CaughtUp {
        let mut inner = self.inner.lock().unwrap();
        if self.shutdown.is_cancelled() && inner.closed.is_none() {
            let err = AbortedError::new_with_context("client closed", inner.context.clone());
            inner.on_aborted(err);
        }
        CaughtUp {
            inner: inner.catch_up.future(),
            state: self.clone(),
            shutdown_wait: None,
            done: false,
        }
    }

    fn on_batch_decoded_and_delivered(
        &self,
        tail: Option<StreamPosition>,
        delivered_last_seq: u64,
        disconnected_for_advice: bool,
        finished_stop: bool,
    ) {
        self.inner.lock().unwrap().on_batch_decoded_and_delivered(
            tail,
            delivered_last_seq,
            disconnected_for_advice,
            finished_stop,
        );
    }

    fn on_record_delivered(&self, seq_num: u64, finished_stop: bool) {
        self.inner
            .lock()
            .unwrap()
            .on_record_delivered(seq_num, finished_stop);
    }

    fn on_heartbeat(&self, tail: StreamPosition, disconnected_for_advice: bool) {
        self.inner
            .lock()
            .unwrap()
            .on_heartbeat(tail, disconnected_for_advice);
    }

    fn on_disconnected(&self) {
        self.inner.lock().unwrap().on_disconnected();
    }

    fn on_clean_end_now(&self, tail: Option<StreamPosition>) {
        self.inner.lock().unwrap().on_clean_end_now(tail);
    }

    fn on_terminal_error(&self, err: ReadSessionError) {
        self.inner.lock().unwrap().on_terminal_error(err);
    }
}

struct ActiveAttempt {
    stream: Streaming<proto::ReadBatch, ReadSessionError>,
    made_progress: bool,
    fetched_record: bool,
    last_chunks_received: u64,
}

type OpenAttemptFuture = Pin<
    Box<
        dyn Future<Output = Result<Streaming<proto::ReadBatch, ReadSessionError>, ReadSessionError>>
            + Send,
    >,
>;

enum DriverPhase {
    Idle,
    Opening(OpenAttemptFuture),
    Active(ActiveAttempt),
    Backoff(Pin<Box<Sleep>>),
}

struct HeartbeatTimer {
    remaining: Duration,
    wait_started_at: Option<Instant>,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl HeartbeatTimer {
    fn new() -> Self {
        Self {
            remaining: HEARTBEAT_TIMEOUT,
            wait_started_at: None,
            sleep: None,
        }
    }

    fn reset(&mut self) {
        self.remaining = HEARTBEAT_TIMEOUT;
        self.wait_started_at = None;
        self.sleep = None;
    }

    fn pause(&mut self) {
        if let Some(started) = self.wait_started_at.take() {
            self.remaining = self.remaining.saturating_sub(started.elapsed());
        }
        self.sleep = None;
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.remaining.is_zero() {
            return Poll::Ready(());
        }
        if self.wait_started_at.is_none() {
            let now = Instant::now();
            self.wait_started_at = Some(now);
            let deadline = now + self.remaining;
            self.sleep = Some(Box::pin(tokio::time::sleep_until(deadline)));
        }
        self.sleep
            .as_mut()
            .expect("sleep initialized above")
            .as_mut()
            .poll(cx)
    }
}

struct DecodedBatch {
    batch: ReadBatch,
    limits_exhausted: bool,
    disconnected_for_advice: bool,
}

enum BatchStep {
    Yield(DecodedBatch),
    Continue,
    Error(ReadSessionError),
}

struct ReadSessionCore {
    basin: BasinName,
    stream: StreamName,
    client: BasinClient,
    headers: StreamHeaders,
    start: ReadStart,
    end: ReadEnd,
    baseline_wait: Option<u32>,
    has_stop_option: bool,
    retry_policy: ReadSessionRetryPolicy,
    refreshes_tokens: bool,
    op_name: &'static str,
    span: Span,
    state: ReadSessionState,
    shutdown: CancellationToken,
    shutdown_wait: Option<Pin<Box<WaitForCancellationFutureOwned>>>,
    context: ErrorContext,
    retry_backoff: RetryBackoff,
    advised_reconnects: AdvisedReconnects,
    idle_since: Option<Instant>,
    has_received_response: bool,
    last_fetched_seq: Option<u64>,
    phase: DriverPhase,
    heartbeat: HeartbeatTimer,
    /// True once remaining `count` or `bytes` hit 0 on the batch currently being delivered
    /// (`R11c`).
    stop_after_current_batch: bool,
    /// True once no more items will be produced (subsequent polls yield `None`).
    exhausted: bool,
    /// True once `Stream::poll_next` has returned `Poll::Ready(None)` (`FusedStream` contract).
    terminated: bool,
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
        let retry_backoff = RetryBackoff::from_config(&client.base().retry_config());
        let refreshes_tokens = client.base().refreshes_tokens();
        let (start, end, _) = input.into_api_parts();
        let baseline_wait = end.wait;
        let has_stop_option =
            end.count.is_some() || end.bytes.is_some() || end.until.is_some() || end.wait.is_some();
        let initial_next_seq_num = if start.clamp == Some(true) {
            None
        } else {
            start.seq_num
        };
        let state = ReadSessionState::new(initial_next_seq_num, shutdown.clone(), context.clone());
        let span = debug_span!("read_session", op = op_name, basin = %basin, stream = %name);

        Self {
            basin,
            stream: name,
            client,
            headers,
            start,
            end,
            baseline_wait,
            has_stop_option,
            retry_policy: config.retry_policy,
            refreshes_tokens,
            op_name,
            span,
            state,
            shutdown,
            shutdown_wait: None,
            context,
            retry_backoff,
            advised_reconnects: AdvisedReconnects::default(),
            idle_since: None,
            has_received_response: false,
            last_fetched_seq: None,
            phase: DriverPhase::Idle,
            heartbeat: HeartbeatTimer::new(),
            stop_after_current_batch: false,
            exhausted: false,
            terminated: false,
        }
    }

    fn pause_heartbeat_timer(&mut self) {
        self.heartbeat.pause();
    }

    fn finalize_closed(&mut self, closed: TerminalClose) -> Option<ReadSessionError> {
        self.exhausted = true;
        self.phase = DriverPhase::Idle;
        self.heartbeat.reset();
        self.shutdown_wait = None;
        match closed {
            TerminalClose::Clean => {
                self.terminated = true;
                self.state.inner.lock().unwrap().on_ended(None);
                None
            }
            TerminalClose::Error(err) => {
                self.state.inner.lock().unwrap().on_ended(Some(err.clone()));
                Some(err)
            }
        }
    }

    /// If the session has already closed (`R9`) or client shutdown (`C12`/`R9d`) is active,
    /// finalize and return `Some(None)` on clean close or `Some(Some(err))` on error.
    fn take_closed_or_abort(&mut self) -> Option<Option<ReadSessionError>> {
        let closed = {
            let mut inner = self.state.inner.lock().unwrap();
            if inner.closed.is_none() && self.shutdown.is_cancelled() {
                let err = AbortedError::new_with_context("client closed", self.context.clone());
                inner.on_aborted(err);
            }
            inner.closed.clone()
        };
        closed.map(|c| self.finalize_closed(c))
    }

    /// Register `cx` with the client shutdown token before returning `Poll::Pending`, or abort
    /// immediately if `S2::close()` already fired.
    fn pending_or_abort(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<DecodedBatch, ReadSessionError>>> {
        let fired = if self.shutdown.is_cancelled() {
            true
        } else {
            let wait = self
                .shutdown_wait
                .get_or_insert_with(|| Box::pin(self.shutdown.clone().cancelled_owned()));
            wait.as_mut().poll(cx).is_ready()
        };
        if fired && let Some(outcome) = self.take_closed_or_abort() {
            return Poll::Ready(outcome.map(Err));
        }
        Poll::Pending
    }

    fn start_open_attempt(&mut self) {
        self.end.wait = remaining_wait(self.baseline_wait, self.idle_since);
        let attempt_num = self.retry_backoff.attempt_number();
        debug!(
            attempt = attempt_num,
            next_seq_num = ?self.start.seq_num,
            "opening read session request"
        );
        let client = self.client.clone();
        let name = self.stream.clone();
        let headers = self.headers.clone();
        let start = self.start.clone();
        let end = self.end.clone();
        let op_name = self.op_name;
        let fut = async move {
            client
                .read_session(op_name, &name, start, end, &headers, attempt_num)
                .await
        }
        .instrument(self.span.clone());
        self.phase = DriverPhase::Opening(Box::pin(fut));
    }

    fn finish_clean_end_now(
        &mut self,
        tail: Option<StreamPosition>,
    ) -> Option<Result<DecodedBatch, ReadSessionError>> {
        self.exhausted = true;
        self.terminated = true;
        self.phase = DriverPhase::Idle;
        self.heartbeat.reset();
        self.shutdown_wait = None;
        self.state.on_clean_end_now(tail);
        None
    }

    fn finish_terminal_error(&mut self, err: ReadSessionError) -> ReadSessionError {
        self.exhausted = true;
        self.phase = DriverPhase::Idle;
        self.heartbeat.reset();
        self.shutdown_wait = None;
        self.state.on_terminal_error(err.clone());
        err
    }

    /// Schedule retry backoff on `err`, or lock in and return the terminal error.
    fn schedule_retry_or_fail(&mut self, err: ReadSessionError) -> Option<ReadSessionError> {
        let attempts = self.retry_backoff.attempt_number();
        let err = err.with_context(&self.context.clone().with_attempts(attempts));
        if let Some(backoff) = retry_delay(
            &err,
            attempts,
            &mut self.retry_backoff,
            self.retry_policy,
            self.refreshes_tokens,
        ) {
            self.phase = DriverPhase::Backoff(Box::pin(tokio::time::sleep(backoff)));
            None
        } else {
            Some(self.finish_terminal_error(err))
        }
    }

    fn handle_decoded_batch(&mut self, batch: ReadBatch, reconnect_advised: bool) -> BatchStep {
        // R6: verify records arrive in strictly increasing seq_num order and have a representable
        // successor `next_seq_num` (`R7a`).
        match validate_read_batch_order(&batch, self.last_fetched_seq, &self.context) {
            Ok(new_last) => self.last_fetched_seq = new_last,
            Err(err) => {
                self.phase = DriverPhase::Idle;
                self.heartbeat.reset();
                self.state.on_disconnected();
                return BatchStep::Error(self.finish_terminal_error(err));
            }
        }

        // T5a: only a non-empty batch or a heartbeat (carrying a tail) counts as progress and
        // resets the retry budget; ignore malformed empty frames.
        let has_records = !batch.records.is_empty();
        let has_tail = batch.tail.is_some();
        let is_progress = has_records || has_tail;

        if !is_progress {
            return BatchStep::Continue;
        }

        self.heartbeat.reset();
        if let DriverPhase::Active(attempt) = &mut self.phase {
            attempt.made_progress = true;
            if has_records {
                attempt.fetched_record = true;
            }
        }
        self.has_received_response = true;
        self.retry_backoff.reset();

        // R11c: restart idle clock only when a record is fetched; if no record has been fetched
        // yet, start the clock the first time we learn we are at the tail. Heartbeats never
        // restart this clock.
        if has_records {
            self.idle_since = Some(Instant::now());
        } else if self.last_fetched_seq.is_none() && has_tail {
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

        let limits_exhausted = has_records && read_limits_exhausted(&self.end);
        let mut disconnected_for_advice = false;

        if limits_exhausted {
            // R11c / T10: stop condition met; end the underlying request immediately without
            // waiting for trailing EOF or opening another request.
            debug!("read session count/bytes limit exhausted");
            self.phase = DriverPhase::Idle;
        } else if reconnect_advised && self.advised_reconnects.should_reconnect() {
            // T6a / T10: end the advised attempt immediately (releasing the retiring server) and
            // open the replacement request on the next transport pull (immediately for a
            // heartbeat, since iteration keeps pulling).
            self.phase = DriverPhase::Idle;
            self.advised_reconnects.record();
            disconnected_for_advice = true;
            debug!(
                next_seq_num = ?self.start.seq_num,
                advised_reconnects = self.advised_reconnects.total(),
                "reconnecting read session on server advice"
            );
        }

        if has_records {
            BatchStep::Yield(DecodedBatch {
                batch,
                limits_exhausted,
                disconnected_for_advice,
            })
        } else if let Some(tail) = batch.tail {
            self.state.on_heartbeat(tail, disconnected_for_advice);
            BatchStep::Continue
        } else {
            BatchStep::Continue
        }
    }

    fn handle_eof(
        &mut self,
        fetched_record: bool,
    ) -> Option<Option<Result<DecodedBatch, ReadSessionError>>> {
        // T9 / R9a: clean EOF ends iteration cleanly ONLY when a stop option was set; otherwise it
        // is a ConnectionLostError and retried per retry_policy.
        if self.has_stop_option {
            // R11c: if this attempt ran with a reduced `wait` budget and fetched new records
            // (restarting the idle clock), reconnect with the refreshed wait rather than stopping
            // prematurely when the server's shorter timer expires.
            if fetched_record
                && !read_limits_exhausted(&self.end)
                && let (Some(base_w), Some(sent_w)) = (self.baseline_wait, self.end.wait)
                && sent_w < base_w
                && remaining_wait(self.baseline_wait, self.idle_since).is_some_and(|w| w > 0)
            {
                self.state.on_disconnected();
                return None;
            }
            debug!("read session ended cleanly on stop condition");
            return Some(self.finish_clean_end_now(None));
        }
        let err = ReadSessionError::ConnectionLost(ConnectionLostError::new_with_context(
            "read stream ended cleanly without a stop condition",
            true,
            self.context.clone(),
        ));
        self.state.on_disconnected();
        self.schedule_retry_or_fail(err).map(|e| Some(Err(e)))
    }

    fn handle_stream_error(
        &mut self,
        err: ReadSessionError,
        made_progress: bool,
    ) -> Option<Option<Result<DecodedBatch, ReadSessionError>>> {
        // R11d: 416 on a resumed request with no remaining wait is a clean stop unless the
        // reported tail regressed below our resume position.
        if let Some(tail) =
            resumed_unwritten_stop_tail(self.has_received_response, &self.start, &self.end, &err)
        {
            debug!(?tail, "read session reached tail on resumed stop condition");
            return Some(self.finish_clean_end_now(tail));
        }

        // If `count` or `bytes` is already exhausted after receiving data, end cleanly rather than
        // reconnecting with count=0/bytes=0.
        if self.has_received_response && read_limits_exhausted(&self.end) {
            debug!("read session limits exhausted after stream error");
            return Some(self.finish_clean_end_now(None));
        }

        self.state.on_disconnected();

        if err.is_server_draining() && made_progress {
            debug!(
                next_seq_num = ?self.start.seq_num,
                "reconnecting read session while server drains"
            );
            return None;
        }

        self.schedule_retry_or_fail(err).map(|e| Some(Err(e)))
    }

    fn poll_next_batch(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<DecodedBatch, ReadSessionError>>> {
        if self.exhausted {
            self.terminated = true;
            return Poll::Ready(None);
        }
        let _entered = self.span.clone().entered();
        loop {
            if let Some(outcome) = self.take_closed_or_abort() {
                return Poll::Ready(outcome.map(Err));
            }

            match &mut self.phase {
                DriverPhase::Idle => {
                    self.start_open_attempt();
                }
                DriverPhase::Opening(fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return self.pending_or_abort(cx),
                    Poll::Ready(res) => {
                        self.phase = DriverPhase::Idle;
                        if self.shutdown.is_cancelled()
                            && let Some(outcome) = self.take_closed_or_abort()
                        {
                            return Poll::Ready(outcome.map(Err));
                        }
                        match res {
                            Ok(stream) => {
                                self.heartbeat.reset();
                                let last_chunks_received = stream.chunks_received();
                                self.phase = DriverPhase::Active(ActiveAttempt {
                                    stream,
                                    made_progress: false,
                                    fetched_record: false,
                                    last_chunks_received,
                                });
                            }
                            Err(err) => {
                                if let Some(tail) = resumed_unwritten_stop_tail(
                                    self.has_received_response,
                                    &self.start,
                                    &self.end,
                                    &err,
                                ) {
                                    debug!(
                                        ?tail,
                                        "read session reached tail on resumed stop condition"
                                    );
                                    return Poll::Ready(self.finish_clean_end_now(tail));
                                }
                                if let Some(terminal_err) = self.schedule_retry_or_fail(err) {
                                    return Poll::Ready(Some(Err(terminal_err)));
                                }
                            }
                        }
                    }
                },
                DriverPhase::Backoff(sleep) => match sleep.as_mut().poll(cx) {
                    Poll::Pending => return self.pending_or_abort(cx),
                    Poll::Ready(()) => {
                        self.phase = DriverPhase::Idle;
                    }
                },
                DriverPhase::Active(attempt) => {
                    // T7d: always poll the transport BEFORE checking the heartbeat timer so any
                    // messages already buffered by HTTP/2 are read before timing out.
                    match Pin::new(&mut attempt.stream).poll_next(cx) {
                        Poll::Ready(Some(Ok(frame))) => {
                            attempt.last_chunks_received = attempt.stream.chunks_received();
                            let batch = ReadBatch::from_proto(frame.msg);
                            let reconnect_advised = frame.reconnect_advised;
                            match self.handle_decoded_batch(batch, reconnect_advised) {
                                BatchStep::Yield(decoded) => return Poll::Ready(Some(Ok(decoded))),
                                BatchStep::Continue => {}
                                BatchStep::Error(err) => return Poll::Ready(Some(Err(err))),
                            }
                        }
                        Poll::Ready(Some(Err(err))) => {
                            let made_progress = attempt.made_progress;
                            self.phase = DriverPhase::Idle;
                            self.heartbeat.reset();
                            if let Some(result) = self.handle_stream_error(err, made_progress) {
                                return Poll::Ready(result);
                            }
                        }
                        Poll::Ready(None) => {
                            let fetched_record = attempt.fetched_record;
                            self.phase = DriverPhase::Idle;
                            self.heartbeat.reset();
                            if let Some(result) = self.handle_eof(fetched_record) {
                                return Poll::Ready(result);
                            }
                        }
                        Poll::Pending => {
                            let chunks_now = attempt.stream.chunks_received();
                            if chunks_now != attempt.last_chunks_received {
                                // Forward transport byte progress on an incomplete (e.g.
                                // flow-controlled) frame counts as liveness so resuming a parked
                                // session mid-frame does not falsely time out (`T7d`).
                                attempt.last_chunks_received = chunks_now;
                                self.heartbeat.reset();
                            }
                            match self.heartbeat.poll(cx) {
                                Poll::Pending => return self.pending_or_abort(cx),
                                Poll::Ready(()) => {
                                    let made_progress = attempt.made_progress;
                                    attempt.stream.retire_connection();
                                    self.phase = DriverPhase::Idle;
                                    self.heartbeat.reset();
                                    let err =
                                        ReadSessionError::Timeout(TimeoutError::new_with_context(
                                            "heartbeat timeout",
                                            self.context.clone(),
                                        ));
                                    if let Some(result) =
                                        self.handle_stream_error(err, made_progress)
                                    {
                                        return Poll::Ready(result);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Drop for ReadSessionCore {
    fn drop(&mut self) {
        let mut inner = self.state.inner.lock().unwrap();
        if inner.closed.is_none() {
            if self.shutdown.is_cancelled() {
                let err = AbortedError::new_with_context("client closed", self.context.clone());
                inner.on_aborted(err);
            } else {
                inner.closed = Some(TerminalClose::Clean);
                inner.on_ended(None);
            }
        } else {
            inner.on_ended(None);
        }
    }
}

/// Drop guard pausing the pull-driven `T7d` heartbeat countdown if a caller cancels `next()`.
struct PauseHeartbeatOnDrop<'a, T>(&'a mut T, fn(&mut T));

impl<T> Drop for PauseHeartbeatOnDrop<'_, T> {
    fn drop(&mut self) {
        (self.1)(self.0);
    }
}

/// A continuous stream of sequenced records.
///
/// Pull-driven: opening sends no request, and the session decodes zero batches ahead of the batch
/// currently being delivered, relying on transport flow control for network read-ahead. Yields
/// individual [`SequencedRecord`]s in sequence-number order. Dropping the session closes it
/// immediately. Use [`state`](Self::state) to observe progress concurrently from other tasks.
#[must_use = "read sessions close immediately when dropped"]
pub struct ReadSession {
    core: ReadSessionCore,
    current_batch: std::vec::IntoIter<SequencedRecord>,
}

impl fmt::Debug for ReadSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadSession")
            .field("basin", &self.core.basin)
            .field("stream", &self.core.stream)
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
            current_batch: Vec::new().into_iter(),
        }
    }

    /// Return the next sequenced record from the session, or `None` when the session ends cleanly.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe and can be used inside [`tokio::select!`]. Dropping the
    /// returned future pauses the heartbeat wait timer without losing buffered records or closing
    /// the session.
    pub async fn next(&mut self) -> Option<Result<SequencedRecord, ReadSessionError>> {
        let guard = PauseHeartbeatOnDrop(self, |s| s.core.pause_heartbeat_timer());
        std::future::poll_fn(|cx| Pin::new(&mut *guard.0).poll_next(cx)).await
    }

    /// Return a cloneable handle to this session's concurrent progress state.
    #[must_use]
    pub fn state(&self) -> ReadSessionState {
        self.core.state.clone()
    }

    /// Return the sequence number of the next record this session will deliver.
    #[must_use]
    pub fn next_seq_num(&self) -> Option<u64> {
        self.core.state.next_seq_num()
    }

    /// Return the latest stream tail observed from a decoded server message.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether the session is open with an active request whose most recent decoded
    /// message reported a tail equal to [`next_seq_num`](Self::next_seq_num).
    #[must_use]
    pub fn is_caught_up(&self) -> bool {
        self.core.state.is_caught_up()
    }

    /// Return a future for the current or next caught-up tail.
    ///
    /// **Important:** Does not drive reading — continue polling [`next`](Self::next) concurrently
    /// while awaiting this future (even on an empty stream), or it will remain pending
    /// indefinitely. See [`ReadSessionState::caught_up`] for full details.
    pub fn caught_up(&self) -> CaughtUp {
        self.core.state.caught_up()
    }
}

impl Stream for ReadSession {
    type Item = Result<SequencedRecord, ReadSessionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.core.exhausted {
            this.core.terminated = true;
            return Poll::Ready(None);
        }
        // R9 / R9d / C12: if already closed or aborted by client close, finalize immediately
        // (dropping any buffered records on abort, and ignoring late aborts after R9a/R9c close).
        if let Some(outcome) = this.core.take_closed_or_abort() {
            this.current_batch = Vec::new().into_iter();
            return Poll::Ready(outcome.map(Err));
        }

        if let Some(record) = this.current_batch.next() {
            let finished_stop = this.core.stop_after_current_batch && this.current_batch.len() == 0;
            this.core
                .state
                .on_record_delivered(record.seq_num, finished_stop);
            return Poll::Ready(Some(Ok(record)));
        }

        match this.core.poll_next_batch(cx) {
            Poll::Ready(Some(Ok(decoded))) => {
                let tail = decoded.batch.tail;
                let mut iter = decoded.batch.records.into_iter();
                let record = iter
                    .next()
                    .expect("poll_next_batch only yields non-empty batches");
                this.current_batch = iter;
                this.core.stop_after_current_batch = decoded.limits_exhausted;
                let finished_stop = decoded.limits_exhausted && this.current_batch.len() == 0;
                this.core.state.on_batch_decoded_and_delivered(
                    tail,
                    record.seq_num,
                    decoded.disconnected_for_advice,
                    finished_stop,
                );
                Poll::Ready(Some(Ok(record)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl FusedStream for ReadSession {
    fn is_terminated(&self) -> bool {
        self.core.terminated
    }
}

/// A continuous stream of non-empty read batches.
///
/// Pull-driven: opening sends no request, and the session decodes zero batches ahead, relying on
/// transport flow control for network read-ahead. Delivers each server batch whole, skips empty
/// heartbeat frames while updating session state, and follows all read-session rules per batch.
/// Dropping the session closes it immediately.
#[must_use = "read sessions close immediately when dropped"]
pub struct ReadBatchSession {
    core: ReadSessionCore,
}

impl fmt::Debug for ReadBatchSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadBatchSession")
            .field("basin", &self.core.basin)
            .field("stream", &self.core.stream)
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
    /// This method is cancel safe and can be used inside [`tokio::select!`]. Dropping the
    /// returned future pauses the heartbeat wait timer without losing buffered records or closing
    /// the session.
    pub async fn next(&mut self) -> Option<Result<ReadBatch, ReadSessionError>> {
        let guard = PauseHeartbeatOnDrop(self, |s| s.core.pause_heartbeat_timer());
        std::future::poll_fn(|cx| Pin::new(&mut *guard.0).poll_next(cx)).await
    }

    /// Return a cloneable handle to this session's concurrent progress state.
    #[must_use]
    pub fn state(&self) -> ReadSessionState {
        self.core.state.clone()
    }

    /// Return the sequence number of the next record this session will deliver.
    #[must_use]
    pub fn next_seq_num(&self) -> Option<u64> {
        self.core.state.next_seq_num()
    }

    /// Return the latest stream tail observed from a decoded server message.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether the session is open with an active request whose most recent decoded
    /// message reported a tail equal to [`next_seq_num`](Self::next_seq_num).
    #[must_use]
    pub fn is_caught_up(&self) -> bool {
        self.core.state.is_caught_up()
    }

    /// Return a future for the current or next caught-up tail.
    ///
    /// **Important:** Does not drive reading — continue polling [`next`](Self::next) concurrently
    /// while awaiting this future (even on an empty stream), or it will remain pending
    /// indefinitely. See [`ReadSessionState::caught_up`] for full details.
    pub fn caught_up(&self) -> CaughtUp {
        self.core.state.caught_up()
    }
}

impl Stream for ReadBatchSession {
    type Item = Result<ReadBatch, ReadSessionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.core.poll_next_batch(cx) {
            Poll::Ready(Some(Ok(decoded))) => {
                let tail = decoded.batch.tail;
                let last_seq = decoded
                    .batch
                    .records
                    .last()
                    .expect("poll_next_batch only yields non-empty batches")
                    .seq_num;
                this.core.state.on_batch_decoded_and_delivered(
                    tail,
                    last_seq,
                    decoded.disconnected_for_advice,
                    decoded.limits_exhausted,
                );
                Poll::Ready(Some(Ok(decoded.batch)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl FusedStream for ReadBatchSession {
    fn is_terminated(&self) -> bool {
        self.core.terminated
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
            return Err(ReadSessionError::Protocol(ProtocolError::new_with_context(
                format!(
                    "read batch contained out-of-order or duplicate seq_num {} after {}",
                    record.seq_num, prev_seq
                ),
                context.clone(),
            )));
        }
        if record.seq_num.checked_add(1).is_none() {
            return Err(ReadSessionError::Protocol(ProtocolError::new_with_context(
                "read batch record seq_num u64::MAX has no representable successor",
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
    attempt: u32,
    backoffs: &mut RetryBackoff,
    retry_policy: ReadSessionRetryPolicy,
    refreshes_tokens: bool,
) -> Option<Duration> {
    let is_retryable = err.is_retryable_or_auth_refresh(refreshes_tokens);
    if !is_retryable {
        debug!(
            err = %err,
            attempt,
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
            err = %err,
            attempt,
            delay = ?backoff,
            ?retry_policy,
            ?retries_remaining,
            "retrying read session"
        );
        Some(backoff)
    } else {
        debug!(
            err = %err,
            attempt,
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
    use tokio::sync::mpsc;

    use super::*;
    use crate::{
        api::{BaseClient, S2sFrame},
        types::{RetryConfig, S2Config, S2Endpoints},
    };

    fn position(seq_num: u64) -> StreamPosition {
        StreamPosition {
            seq_num,
            timestamp: seq_num,
        }
    }

    fn record(seq_num: u64) -> SequencedRecord {
        SequencedRecord {
            seq_num,
            timestamp: seq_num,
            body: Bytes::new(),
            headers: Vec::new(),
        }
    }

    fn proto_batch(seq_nums: &[u64], tail: Option<u64>) -> proto::ReadBatch {
        proto::ReadBatch {
            records: seq_nums
                .iter()
                .map(|&seq_num| proto::SequencedRecord {
                    seq_num,
                    timestamp: seq_num,
                    headers: Vec::new(),
                    body: Bytes::new(),
                })
                .collect(),
            tail: tail.map(|seq_num| proto::StreamPosition {
                seq_num,
                timestamp: seq_num,
            }),
        }
    }

    fn batch(records: Vec<SequencedRecord>, tail: Option<StreamPosition>) -> ReadBatch {
        ReadBatch { records, tail }
    }

    type FrameTx = mpsc::UnboundedSender<Result<S2sFrame<proto::ReadBatch>, ReadSessionError>>;

    fn test_session_with_active_stream(
        input: ReadInput,
    ) -> (ReadSession, FrameTx, ReadSessionState, CancellationToken) {
        let config = S2Config::new("test-token")
            .with_endpoints(S2Endpoints::for_endpoint("http://127.0.0.1:1").unwrap())
            .with_retry(RetryConfig::new().with_max_attempts(1).unwrap());
        let base = BaseClient::init(&config).unwrap();
        let basin = BasinClient::init(
            "test-basin".parse().unwrap(),
            &config.endpoints,
            base.clone(),
        );
        let mut session = ReadSession::open(
            basin,
            "test-stream".parse().unwrap(),
            StreamHeaders::default(),
            input,
            ReadSessionConfig::default(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stream = Streaming::from_stream_for_test(futures_util::stream::poll_fn(move |cx| {
            rx.poll_recv(cx)
        }));
        session.core.phase = DriverPhase::Active(ActiveAttempt {
            stream,
            made_progress: false,
            fetched_record: false,
            last_chunks_received: 0,
        });
        let state = session.state();
        let shutdown = session.core.shutdown.clone();
        (session, tx, state, shutdown)
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

    #[tokio::test]
    async fn clean_stop_final_record_catches_up_then_iteration_end_resets_is_caught_up() {
        let (mut session, tx, _state, _shutdown) = test_session_with_active_stream(
            ReadInput::new()
                .with_start(crate::types::ReadStart::SeqNum(0))
                .with_count(2),
        );
        let cu = session.caught_up();

        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0, 1], Some(2)),
            reconnect_advised: false,
        }))
        .unwrap();
        drop(tx);

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
    async fn heartbeat_after_trimmed_gap_advances_next_seq_num_on_pull() {
        let (mut session, tx, _state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );
        let cu = session.caught_up();

        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], None),
            reconnect_advised: false,
        }))
        .unwrap();
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[], Some(5)),
            reconnect_advised: false,
        }))
        .unwrap();

        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert_eq!(session.next_seq_num(), Some(1));
        assert!(!session.is_caught_up());
        // R6b: heartbeat has not been decoded ahead yet!
        assert_eq!(session.last_observed_tail(), None);

        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);

        assert_eq!(session.next_seq_num(), Some(5));
        assert!(session.is_caught_up());
        assert_eq!(cu.await.unwrap(), position(5));
    }

    #[tokio::test]
    async fn clean_stop_after_heartbeat_preserves_progress_and_catch_up() {
        let (mut session, tx, _state, _shutdown) = test_session_with_active_stream(
            ReadInput::new()
                .with_start(crate::types::ReadStart::SeqNum(0))
                .with_wait_secs(5),
        );
        let cu = session.caught_up();

        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[], Some(5)),
            reconnect_advised: false,
        }))
        .unwrap();
        drop(tx);

        assert!(session.next().await.is_none());
        assert_eq!(session.next_seq_num(), Some(5));
        assert_eq!(session.last_observed_tail(), Some(position(5)));
        assert!(!session.is_caught_up());
        assert_eq!(cu.await.unwrap(), position(5));
        assert!(matches!(
            session.caught_up().await,
            Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
        ));
    }

    #[tokio::test]
    async fn terminal_error_after_heartbeat_preserves_next_seq_num() {
        let (mut session, tx, _state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );
        let cu = session.caught_up();

        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[], Some(5)),
            reconnect_advised: false,
        }))
        .unwrap();
        tx.send(Err(ReadSessionError::Timeout(
            TimeoutError::new_with_context(
                "heartbeat timeout",
                ErrorContext::default().into_read_only(),
            ),
        )))
        .unwrap();

        let delivered_err = session.next().await.unwrap().unwrap_err();
        assert!(matches!(delivered_err, ReadSessionError::Timeout(_)));
        assert_eq!(session.next_seq_num(), Some(5));
        assert_eq!(session.last_observed_tail(), Some(position(5)));
        assert!(!session.is_caught_up());
        // Heartbeat caught the session up to 5 before the subsequent error arrived (`R8a`).
        assert_eq!(cu.await.unwrap(), position(5));
        assert!(matches!(
            session.caught_up().await,
            Err(ReadSessionError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn clean_end_without_catching_up_rejects_wait() {
        let (mut session, tx, _state, _shutdown) =
            test_session_with_active_stream(ReadInput::new().with_count(1));
        let cu = session.caught_up();
        drop(tx);

        assert!(session.next().await.is_none());
        assert!(matches!(
            cu.await,
            Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
        ));
    }

    #[tokio::test]
    async fn read_error_rejects_wait_and_preserves_prior_resolved_future() {
        let (mut session, tx, _state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );

        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();

        session.next().await.unwrap().unwrap();
        assert!(session.is_caught_up());
        let resolved_cu = session.caught_up();

        session.core.state.on_disconnected();
        assert!(!session.is_caught_up());
        let pending_cu = session.caught_up();

        tx.send(Err(ReadSessionError::Timeout(
            TimeoutError::new_with_context(
                "heartbeat timeout",
                ErrorContext::default().into_read_only(),
            ),
        )))
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
            let (session, _tx, _state, _shutdown) =
                test_session_with_active_stream(ReadInput::new());
            session.caught_up()
        };

        assert!(matches!(
            cu.await,
            Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
        ));
    }

    #[tokio::test]
    async fn client_shutdown_wakes_parked_caught_up_immediately_without_polling_session() {
        let (mut session, _tx, state, shutdown) = test_session_with_active_stream(ReadInput::new());
        let cu = state.caught_up();

        // Park `session` (never poll `session.next()`), then trigger client shutdown!
        shutdown.cancel();

        // R8d / R9d / C12: pending CaughtUp wakes immediately with AbortedError!
        let cu_err = tokio::time::timeout(Duration::from_secs(1), cu)
            .await
            .expect("parked CaughtUp must wake immediately on client close")
            .unwrap_err();
        assert!(matches!(cu_err, ReadSessionError::Aborted(_)), "{cu_err:?}");
        assert!(!state.is_caught_up());
        assert!(matches!(
            state.caught_up().await,
            Err(ReadSessionError::Aborted(_))
        ));

        // Subsequent next() yields AbortedError once, then None.
        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::Aborted(_)))
        ));
        assert!(session.next().await.is_none());
    }

    #[tokio::test]
    async fn dropping_session_after_client_shutdown_reports_aborted() {
        let (session, _tx, state, shutdown) = test_session_with_active_stream(ReadInput::new());
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
    async fn caught_up_fused_and_repoll_after_resolution_does_not_panic() {
        use futures_core::FusedFuture as _;

        let (mut session, tx, _state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );
        let mut cu = session.caught_up();
        assert!(!cu.is_terminated());
        assert!(poll!(Pin::new(&mut cu)).is_pending());

        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);

        let first = poll!(Pin::new(&mut cu));
        assert!(matches!(first, Poll::Ready(Ok(pos)) if pos == position(1)));
        assert!(cu.is_terminated());

        // Re-polling a resolved CaughtUp future returns the cached result rather than panicking.
        let second = poll!(Pin::new(&mut cu));
        assert!(matches!(second, Poll::Ready(Ok(pos)) if pos == position(1)));
        assert!(cu.is_terminated());

        // Cloning a resolved CaughtUp resets termination so the clone can be polled once.
        let mut cloned = cu.clone();
        assert!(!cloned.is_terminated());
        assert!(matches!(
            poll!(Pin::new(&mut cloned)),
            Poll::Ready(Ok(pos)) if pos == position(1)
        ));
        assert!(cloned.is_terminated());
    }

    #[test]
    fn validate_read_batch_order_rejects_duplicate_and_backward_seq_nums() {
        let ctx = ErrorContext::default().into_read_only();
        let b1 = batch(vec![record(0), record(2)], None);
        let last = validate_read_batch_order(&b1, None, &ctx).unwrap();
        assert_eq!(last, Some(2));

        let dup = batch(vec![record(2)], None);
        assert!(matches!(
            validate_read_batch_order(&dup, last, &ctx),
            Err(ReadSessionError::Protocol(_))
        ));

        let backward_within = batch(vec![record(5), record(4)], None);
        assert!(matches!(
            validate_read_batch_order(&backward_within, last, &ctx),
            Err(ReadSessionError::Protocol(_))
        ));
    }

    // spec: r1 R5
    #[test]
    fn opening_read_session_outside_tokio_runtime_does_not_panic() {
        let config = S2Config::new("test-token")
            .with_endpoints(S2Endpoints::for_endpoint("http://127.0.0.1:1").unwrap());
        let s2 = crate::S2::new(config).unwrap();
        let stream = s2
            .basin("test-basin".parse().unwrap())
            .stream("test-stream".parse().unwrap());
        let _rs = stream
            .read_session(ReadInput::new(), ReadSessionConfig::default())
            .unwrap();
        let _rbs = stream
            .read_batch_session(ReadInput::new(), ReadSessionConfig::default())
            .unwrap();
    }
}
