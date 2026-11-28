use std::{
    fmt,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::{Arc, Mutex as StdMutex, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use futures_core::{FusedFuture, FusedStream, Stream};
use s2_api::v1::stream::{ReadEnd, ReadStart, proto};
use tokio::{
    sync::{Notify, futures::OwnedNotified},
    time::{Instant, Sleep},
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, Span, debug, debug_span};

use crate::{
    api::{BasinClient, Streaming},
    cancel::{CancellationToken, ShutdownWait},
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

struct CaughtUpSignal {
    result: OnceLock<CaughtUpResult>,
    notify: Arc<Notify>,
}

impl CaughtUpSignal {
    fn new() -> Self {
        Self {
            result: OnceLock::new(),
            notify: Arc::new(Notify::new()),
        }
    }

    fn get(&self) -> Option<&CaughtUpResult> {
        self.result.get()
    }

    /// Store `result` if unset, returning `Some(notify)` so callers wake waiters *after* dropping
    /// the outer `ReadSessionState` lock (preventing deadlocks if a custom waker inspects state).
    #[must_use]
    fn set_result(&self, result: CaughtUpResult) -> Option<Arc<Notify>> {
        self.result.set(result).ok().map(|()| self.notify.clone())
    }
}

/// Zero-lock `Sync` wrapper around a `Send` value accessed exclusively via `&mut self`.
///
/// Uses [`StdMutex::get_mut`] solely to opt into `Sync` (`Mutex<T>: Sync` for `T: Send`) without
/// ever locking at runtime or adding an external crate dependency.
#[derive(Default)]
struct SyncCell<T>(StdMutex<T>);

impl<T> SyncCell<T> {
    fn new(value: T) -> Self {
        Self(StdMutex::new(value))
    }

    fn get_mut(&mut self) -> &mut T {
        self.0.get_mut().expect("SyncCell mutex is never locked")
    }
}

#[derive(Default)]
struct CaughtUpWaits {
    notified: Option<Pin<Box<OwnedNotified>>>,
    shutdown: ShutdownWait,
}

enum CaughtUpInner {
    Pending {
        signal: Arc<CaughtUpSignal>,
        state: ReadSessionState,
        waits: SyncCell<CaughtUpWaits>,
    },
    Ready(CaughtUpResult),
}

/// Future returned by [`ReadSession::caught_up`], [`ReadBatchSession::caught_up`], and
/// [`ReadSessionState::caught_up`].
///
/// Resolves immediately to [`ReadSessionState::last_observed_tail`] if
/// [`ReadSessionState::is_caught_up`] is `true` (even after the session closes), or the next time
/// it becomes `true`. If an open, non-caught-up session closes or aborts while this future is
/// pending (or is already closed while not caught up), it fails with the session's failure (or
/// [`SessionClosedError`] if the session closed cleanly or was dropped).
///
/// **Important:** Does not drive reading — continue polling the session concurrently (for example
/// via [`ReadSession::next`] in another task or `tokio::select!`) while awaiting this future, even
/// on an empty stream. Calling [`S2::close`](crate::S2::close) or dropping an open, non-caught-up
/// session still fails a pending `CaughtUp` future immediately even when no task is polling the
/// session.
///
/// Once resolved, its value never changes, and re-polling returns the same outcome without
/// panicking.
#[must_use = "futures do nothing unless `.await`ed or polled"]
pub struct CaughtUp {
    inner: CaughtUpInner,
    done: bool,
}

impl Clone for CaughtUp {
    fn clone(&self) -> Self {
        let inner = match &self.inner {
            CaughtUpInner::Ready(result) => CaughtUpInner::Ready(result.clone()),
            CaughtUpInner::Pending { signal, state, .. } => match signal.get() {
                Some(result) => CaughtUpInner::Ready(result.clone()),
                None => CaughtUpInner::Pending {
                    signal: signal.clone(),
                    state: state.clone(),
                    waits: SyncCell::default(),
                },
            },
        };
        Self { inner, done: false }
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
        let resolved = match &mut this.inner {
            CaughtUpInner::Ready(result) => {
                this.done = true;
                return Poll::Ready(result.clone());
            }
            CaughtUpInner::Pending {
                signal,
                state,
                waits,
            } => {
                let waits = waits.get_mut();

                // Always check the catch-up signal first so an already-resolved tail (`R8a`) or
                // already-locked close reason (`R9`) is never overwritten by a later client
                // shutdown.
                if let Some(result) = signal.get() {
                    result.clone()
                } else {
                    // Register `cx` with the signal before re-checking `signal.get()` so a
                    // concurrent resolution cannot slip between the check and registration.
                    let notified = waits
                        .notified
                        .get_or_insert_with(|| Box::pin(signal.notify.clone().notified_owned()));
                    let _ = notified.as_mut().poll(cx);

                    if let Some(result) = signal.get() {
                        result.clone()
                    } else if !waits.shutdown.poll(&state.shutdown, cx) {
                        // R8d / R9d / C12: observe client shutdown immediately even when no task
                        // is polling the on-demand session.
                        return Poll::Pending;
                    } else {
                        // `update` folds `shutdown.is_cancelled()` into `abort_for_client_close`
                        // and settles any pending waiter before returning.
                        state.update(|_| ());
                        signal
                            .get()
                            .expect("shutdown update resolves every pending CaughtUpSignal")
                            .clone()
                    }
                }
            }
        };
        this.inner = CaughtUpInner::Ready(resolved.clone());
        this.done = true;
        Poll::Ready(resolved)
    }
}

impl FusedFuture for CaughtUp {
    fn is_terminated(&self) -> bool {
        self.done
    }
}

#[derive(Debug, Clone)]
enum TerminalClose {
    Clean,
    Error(ReadSessionError),
}

impl TerminalClose {
    /// Convert a finalized session close into the next `Stream::poll_next` item (`None` for a
    /// clean end, `Some(Err(err))` for a terminal error).
    fn into_stream_item<T>(self) -> Option<Result<T, ReadSessionError>> {
        match self {
            Self::Clean => None,
            Self::Error(err) => Some(Err(err)),
        }
    }
}

struct ReadStateInner {
    next_seq_num: Option<u64>,
    last_observed_tail: Option<StreamPosition>,
    /// `tail.seq_num` carried by the latest valid received batch or heartbeat (`None` initially or
    /// when the latest valid batch omitted `tail`).
    latest_message_tail_seq: Option<u64>,
    /// Pending `caught_up()` waiter; lazily allocated on demand. Invariant outside the lock:
    /// `Some` implies `caught_up_outcome().is_none()`.
    waiter: Option<Arc<CaughtUpSignal>>,
    /// Locked-in session close reason (`R9`). Once set, later closes or aborts have no effect.
    closed: Option<TerminalClose>,
    context: ErrorContext,
    /// Current retry attempt number (`E7`), updated on each attempt start and reset to `1` on
    /// `T5a` progress so aborts from parked observers carry the accurate attempt count.
    attempts: u32,
}

impl ReadStateInner {
    fn new(initial_next_seq_num: Option<u64>, context: ErrorContext) -> Self {
        Self {
            next_seq_num: initial_next_seq_num,
            last_observed_tail: None,
            latest_message_tail_seq: None,
            waiter: None,
            closed: None,
            context,
            attempts: 1,
        }
    }

    fn current_context(&self) -> ErrorContext {
        self.context.clone().with_attempts(self.attempts)
    }

    fn caught_up_tail(&self) -> Option<StreamPosition> {
        let tail_seq = self.latest_message_tail_seq?;
        self.last_observed_tail
            .filter(|_| self.next_seq_num == Some(tail_seq))
    }

    fn is_caught_up(&self) -> bool {
        self.caught_up_tail().is_some()
    }

    fn caught_up_outcome(&self) -> Option<CaughtUpResult> {
        if let Some(tail) = self.caught_up_tail() {
            return Some(Ok(tail));
        }
        self.closed.as_ref().map(|close| match close {
            TerminalClose::Error(err) => Err(err.clone()),
            TerminalClose::Clean => Err(ReadSessionError::SessionClosed(
                SessionClosedError::new_with_context(None, self.context.clone()),
            )),
        })
    }

    fn update_observed_tail(&mut self, candidate: StreamPosition) {
        if self.last_observed_tail.is_none_or(|prev| {
            (candidate.seq_num, candidate.timestamp) >= (prev.seq_num, prev.timestamp)
        }) {
            self.last_observed_tail = Some(candidate);
        }
    }

    /// Lock in the session's close reason (`R9`), returning the winning reason. Preserves `R7`
    /// state and any caught-up status; `ReadSessionState::update` settles any pending waiter.
    fn close_with(&mut self, close: TerminalClose) -> TerminalClose {
        self.closed.get_or_insert(close).clone()
    }

    /// Record a freshly decoded valid server message (heartbeat or batch together with delivery of
    /// its first record / whole batch).
    fn on_message(&mut self, tail: Option<StreamPosition>, next_seq_num: u64) {
        self.attempts = 1;
        if let Some(tail) = tail {
            self.update_observed_tail(tail);
        }
        self.latest_message_tail_seq = tail.map(|t| t.seq_num);
        self.next_seq_num = Some(next_seq_num);
    }

    /// Record delivery of a subsequent record from the current batch.
    fn on_record_delivered(&mut self, seq_num: u64) {
        self.next_seq_num = Some(seq_num + 1);
    }

    fn abort_for_client_close(&mut self) {
        if self.closed.is_none() {
            let close = TerminalClose::Error(ReadSessionError::Aborted(
                AbortedError::new_with_context("client closed", self.current_context()),
            ));
            self.closed = Some(close);
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
        let caught_up = inner.is_caught_up();
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
    /// until resolved by the first valid received server message. Updated before each record (or
    /// batch) is handed to the caller, and advances on heartbeats. Retained after the session
    /// closes.
    #[must_use]
    pub fn next_seq_num(&self) -> Option<u64> {
        self.inner.lock().unwrap().next_seq_num
    }

    /// Return the highest stream tail observed from a valid received server message as of the last
    /// pull.
    ///
    /// Because reading is on-demand, this does not reflect newer appends while the session is
    /// parked; use [`S2Stream::check_tail`](crate::S2Stream::check_tail) for a fresh stream tail.
    /// Ordered by `(seq_num, timestamp)`, persists across attempts, and is retained after the
    /// session closes.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.inner.lock().unwrap().last_observed_tail
    }

    /// Return whether the latest valid received message (as of the last pull) reported a tail
    /// equal to [`next_seq_num`](Self::next_seq_num).
    ///
    /// Because reading is on-demand, this is not a live lag or liveness check while the session is
    /// parked; use [`S2Stream::check_tail`](crate::S2Stream::check_tail) for a fresh stream tail.
    /// Preserved across disconnects, retries, handovers, and session close; returns `true` if and
    /// only if [`caught_up`](Self::caught_up) resolves immediately to
    /// [`last_observed_tail`](Self::last_observed_tail).
    #[must_use]
    pub fn is_caught_up(&self) -> bool {
        self.inner.lock().unwrap().is_caught_up()
    }

    /// Return a future that resolves to [`last_observed_tail`](Self::last_observed_tail) once the
    /// session is caught up.
    ///
    /// Resolves immediately if [`is_caught_up`](Self::is_caught_up) is `true` (even after the
    /// session closes), or the next time it becomes `true`. Once resolved, its value never
    /// changes. Does not drive reading — continue polling the session while awaiting it (even on
    /// an empty stream). Remains pending across retries, handovers, and continuations. If an open,
    /// non-caught-up session closes or is aborted (including via [`S2::close`](crate::S2::close)
    /// while parked), pending and subsequent futures fail immediately.
    pub fn caught_up(&self) -> CaughtUp {
        let inner = self.update(|inner| match inner.caught_up_outcome() {
            Some(result) => CaughtUpInner::Ready(result),
            None => {
                let signal = inner
                    .waiter
                    .get_or_insert_with(|| Arc::new(CaughtUpSignal::new()))
                    .clone();
                CaughtUpInner::Pending {
                    signal,
                    state: self.clone(),
                    waits: SyncCell::default(),
                }
            }
        });
        CaughtUp { inner, done: false }
    }

    /// Lock state, fold in any pending client shutdown (`R9d`), apply `f`, settle any pending
    /// `caught_up()` waiter, and dispatch its wakeup strictly *after* releasing the lock.
    fn update<R>(&self, f: impl FnOnce(&mut ReadStateInner) -> R) -> R {
        let (out, notify) = {
            let mut inner = self.inner.lock().unwrap();
            if self.shutdown.is_cancelled() {
                inner.abort_for_client_close();
            }
            let out = f(&mut inner);
            let notify = if inner.waiter.is_some() {
                inner
                    .caught_up_outcome()
                    .and_then(|outcome| inner.waiter.take()?.set_result(outcome))
            } else {
                None
            };
            (out, notify)
        };
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
        out
    }

    fn set_attempt(&self, attempts: u32) {
        self.inner.lock().unwrap().attempts = attempts;
    }

    fn validation_bounds(&self) -> (Option<u64>, Option<u64>) {
        let inner = self.inner.lock().unwrap();
        (
            inner.next_seq_num,
            inner.last_observed_tail.map(|t| t.seq_num),
        )
    }
}

struct ActiveAttempt {
    stream: Streaming<proto::ReadBatch, ReadSessionError>,
    made_progress: bool,
    fetched_record: bool,
    last_chunks_received: u64,
    heartbeat_deadline: Option<Instant>,
}

impl ActiveAttempt {
    fn new(stream: Streaming<proto::ReadBatch, ReadSessionError>) -> Self {
        let last_chunks_received = stream.chunks_received();
        Self {
            stream,
            made_progress: false,
            fetched_record: false,
            last_chunks_received,
            heartbeat_deadline: None,
        }
    }

    fn record_chunk_progress(&mut self) {
        let chunks_now = self.stream.chunks_received();
        if chunks_now != self.last_chunks_received {
            self.last_chunks_received = chunks_now;
            self.heartbeat_deadline = None;
        }
    }
}

type OpenAttemptHandle =
    AbortOnDropHandle<Result<Streaming<proto::ReadBatch, ReadSessionError>, ReadSessionError>>;

/// Cap timer delays at ~30 years (matching Tokio's internal `safe_delay`) so extreme caller
/// retry delays (such as `Duration::MAX`) never overflow `Instant + Duration` or Tokio's
/// millisecond tick conversion.
const MAX_TIMER_DELAY: Duration = Duration::from_secs(86_400 * 365 * 30);

fn deadline_after(duration: Duration) -> Option<Instant> {
    Instant::now().checked_add(duration.min(MAX_TIMER_DELAY))
}

enum DriverPhase {
    Idle,
    Opening(OpenAttemptHandle),
    Active(ActiveAttempt),
    Backoff(Option<Instant>),
}

/// Reusable lazily-boxed Tokio [`Sleep`] shared by retry backoff and `T7d` heartbeat waits.
///
/// Boxing keeps [`ReadSession`] and [`ReadBatchSession`] `Unpin` (since `Sleep` is `!Unpin`),
/// while reusing a single allocation via [`Sleep::reset`] avoids per-wait heap churn and avoids
/// taking Tokio's timer-driver lock on every batch or chunk arrival. Trade-off: clearing
/// `heartbeat_deadline` on progress leaves the prior timer entry in Tokio's wheel until it is
/// next extended, dropped on close/drop, or expires once (at most one harmless stray wake if the
/// session parks immediately after receiving a frame).
#[derive(Default)]
struct ReusableSleep {
    sleep: Option<(tokio::runtime::Id, Pin<Box<Sleep>>)>,
}

impl ReusableSleep {
    fn poll_until(&mut self, deadline: Instant, cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= deadline {
            return Poll::Ready(());
        }
        let runtime_id = tokio::runtime::Handle::current().id();
        if self.sleep.as_ref().is_some_and(|(id, _)| *id != runtime_id) {
            self.sleep = None;
        }
        let (_, sleep) = self
            .sleep
            .get_or_insert_with(|| (runtime_id, Box::pin(tokio::time::sleep_until(deadline))));
        if sleep.deadline() != deadline {
            sleep.as_mut().reset(deadline);
        }
        sleep.as_mut().poll(cx)
    }
}

struct DecodedBatch {
    batch: ReadBatch,
    last_seq_num: u64,
    /// Whether remaining `count` or `bytes` reached `0` (`R10c`), locking in clean close (`R9a`)
    /// once the batch's final record is delivered.
    close_clean: bool,
}

struct PollTransport {
    phase: DriverPhase,
    sleep: ReusableSleep,
    shutdown: ShutdownWait,
}

impl PollTransport {
    fn new() -> Self {
        Self {
            phase: DriverPhase::Idle,
            sleep: ReusableSleep::default(),
            shutdown: ShutdownWait::default(),
        }
    }
}

/// Live client and transport resources owned while a read session is open. Dropped atomically when
/// [`StreamLifecycle`] leaves [`StreamLifecycle::Active`] so retained finished sessions never pin
/// the HTTP/2 pool, timer wheel, or shutdown waiter list (`C12`).
struct ActiveTransport {
    client: BasinClient,
    transport: SyncCell<PollTransport>,
}

enum StreamLifecycle {
    Active(Box<ActiveTransport>),
    /// Terminal item already returned (error or limit-exhausting final record/batch); next poll
    /// emits `None` and transitions to `Terminated`.
    PendingEof,
    /// `None` has been returned (`FusedStream::is_terminated() == true`).
    Terminated,
}

struct ReadSessionCore {
    basin: BasinName,
    stream: StreamName,
    headers: StreamHeaders,
    start: ReadStart,
    end: ReadEnd,
    baseline_wait: Option<u32>,
    retry_policy: ReadSessionRetryPolicy,
    refreshes_tokens: bool,
    op_name: &'static str,
    span: Span,
    state: ReadSessionState,
    context: ErrorContext,
    retry_backoff: RetryBackoff,
    advised_reconnects: AdvisedReconnects,
    idle_since: Option<Instant>,
    lifecycle: StreamLifecycle,
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
        debug_assert!(!read_limits_exhausted(&end));
        let baseline_wait = end.wait;
        let initial_next_seq_num = if start.clamp == Some(true) {
            None
        } else {
            start.seq_num
        };
        let state = ReadSessionState::new(initial_next_seq_num, shutdown, context.clone());
        let span = debug_span!("read_session", op = op_name, basin = %basin, stream = %name);

        Self {
            basin,
            stream: name,
            headers,
            start,
            end,
            baseline_wait,
            retry_policy: config.retry_policy,
            refreshes_tokens,
            op_name,
            span,
            state,
            context,
            retry_backoff,
            advised_reconnects: AdvisedReconnects::default(),
            idle_since: None,
            lifecycle: StreamLifecycle::Active(Box::new(ActiveTransport {
                client,
                transport: SyncCell::new(PollTransport::new()),
            })),
        }
    }

    fn has_stop_option(&self) -> bool {
        self.end.count.is_some()
            || self.end.bytes.is_some()
            || self.end.until.is_some()
            || self.baseline_wait.is_some()
    }

    fn active_mut(&mut self) -> &mut ActiveTransport {
        match &mut self.lifecycle {
            StreamLifecycle::Active(active) => active,
            StreamLifecycle::PendingEof | StreamLifecycle::Terminated => {
                unreachable!("active read session transport accessed after end")
            }
        }
    }

    fn transport_mut(&mut self) -> &mut PollTransport {
        self.active_mut().transport.get_mut()
    }

    #[cfg(test)]
    fn is_active(&self) -> bool {
        matches!(self.lifecycle, StreamLifecycle::Active(_))
    }

    fn poll_if_ended(&mut self) -> bool {
        match self.lifecycle {
            StreamLifecycle::Active(_) => false,
            StreamLifecycle::PendingEof => {
                self.lifecycle = StreamLifecycle::Terminated;
                true
            }
            StreamLifecycle::Terminated => true,
        }
    }

    fn is_terminated(&self) -> bool {
        matches!(self.lifecycle, StreamLifecycle::Terminated)
    }

    /// Drop live client/transport resources and transition lifecycle according to `closed` (`C12`).
    fn release_with(&mut self, closed: TerminalClose) -> TerminalClose {
        self.lifecycle = match &closed {
            TerminalClose::Clean => StreamLifecycle::Terminated,
            TerminalClose::Error(_) => StreamLifecycle::PendingEof,
        };
        closed
    }

    /// Commit a terminal close under a single state lock, respecting any prior close/abort,
    /// and release live client/transport resources afterward outside the lock (`C12`).
    fn finish_session(&mut self, close: TerminalClose) -> TerminalClose {
        let closed = self.state.update(|inner| inner.close_with(close));
        self.release_with(closed)
    }

    /// Apply `f` if the session is open and not aborted; otherwise finalize and return the
    /// committed terminal close reason under a single state lock.
    fn transact(&mut self, f: impl FnOnce(&mut ReadStateInner)) -> Result<(), TerminalClose> {
        let res = self.state.update(|inner| match &inner.closed {
            Some(closed) => Err(closed.clone()),
            None => {
                f(inner);
                Ok(())
            }
        });
        res.map_err(|closed| self.release_with(closed))
    }

    fn commit_delivered(
        &mut self,
        close_clean: bool,
        f: impl FnOnce(&mut ReadStateInner),
    ) -> Result<(), TerminalClose> {
        self.transact(|inner| {
            f(inner);
            if close_clean {
                inner.close_with(TerminalClose::Clean);
            }
        })?;
        if close_clean {
            // Close reason is now locked in (`R9`), so drop live transport/client immediately;
            // the next pull returns `None` directly while preserving `FusedStream::is_terminated`.
            self.lifecycle = StreamLifecycle::PendingEof;
        }
        Ok(())
    }

    /// Finalize after observing client shutdown (`C12`/`R9d`).
    fn abort_now(&mut self) -> TerminalClose {
        let closed = self.state.update(|inner| {
            inner
                .closed
                .clone()
                .expect("abort_now requires shutdown to be cancelled")
        });
        self.release_with(closed)
    }

    fn abort_if_shutdown(&mut self) -> Result<(), TerminalClose> {
        if self.state.shutdown.is_cancelled() {
            return Err(self.abort_now());
        }
        Ok(())
    }

    /// Register `cx` with the client shutdown token before returning `Poll::Pending`, or abort
    /// immediately if `S2::close()` already fired.
    fn pending_or_abort(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<DecodedBatch, TerminalClose>> {
        let StreamLifecycle::Active(active) = &mut self.lifecycle else {
            unreachable!("pending_or_abort called after session ended");
        };
        if active
            .transport
            .get_mut()
            .shutdown
            .poll(&self.state.shutdown, cx)
        {
            return Poll::Ready(Err(self.abort_now()));
        }
        Poll::Pending
    }

    fn start_open_attempt(&mut self) {
        self.end.wait = remaining_wait(self.baseline_wait, self.idle_since);
        let attempt_num = self.retry_backoff.attempt_number();
        self.state.set_attempt(attempt_num);
        debug!(
            attempt = attempt_num,
            next_seq_num = ?self.start.seq_num,
            "opening read session request"
        );
        let name = self.stream.clone();
        let headers = self.headers.clone();
        let start = self.start.clone();
        let end = self.end.clone();
        let op_name = self.op_name;
        let span = self.span.clone();
        let active = self.active_mut();
        let client = active.client.clone();
        let fut = async move {
            client
                .read_session(op_name, &name, start, end, &headers, attempt_num)
                .await
        }
        .instrument(span);
        // Spawn the opening request behind `AbortOnDropHandle` so `T7a`/`T7b` (`connection_timeout`
        // and `request_timeout` until `200` headers or full non-2xx error body) settle in real time
        // even if the caller parks while `Opening`, while keeping body decoding, heartbeats, and
        // retries on-demand (`R6b`) and aborting immediately if the session drops.
        active.transport.get_mut().phase =
            DriverPhase::Opening(AbortOnDropHandle::new(tokio::spawn(fut)));
    }

    /// Schedule retry backoff on `err`, or lock in and return the terminal close reason.
    fn schedule_retry_or_fail(&mut self, err: ReadSessionError) -> Result<(), TerminalClose> {
        let attempts = self.retry_backoff.attempt_number();
        let err = err.with_context(&self.context.clone().with_attempts(attempts));
        if let Some(backoff) = retry_delay(
            &err,
            attempts,
            &mut self.retry_backoff,
            self.retry_policy,
            self.refreshes_tokens,
        ) {
            self.transport_mut().phase = DriverPhase::Backoff(deadline_after(backoff));
            Ok(())
        } else {
            Err(self.finish_session(TerminalClose::Error(err)))
        }
    }

    fn maybe_handover(&mut self, reconnect_advised: bool) {
        if reconnect_advised && self.advised_reconnects.should_reconnect() {
            // T6a / T10: end the advised attempt immediately (releasing the retiring server) and
            // open the replacement request on the next transport pull (immediately for a
            // heartbeat, since iteration keeps pulling).
            self.transport_mut().phase = DriverPhase::Idle;
            self.advised_reconnects.record();
            debug!(
                next_seq_num = ?self.start.seq_num,
                advised_reconnects = self.advised_reconnects.total(),
                "reconnecting read session on server advice"
            );
        }
    }

    fn handle_decoded_batch(
        &mut self,
        batch: ReadBatch,
        reconnect_advised: bool,
    ) -> Result<Option<DecodedBatch>, TerminalClose> {
        // R6 / R7a / R7b / E7: reject invalid batches atomically without delivering records or
        // updating session state.
        let attempts = self.retry_backoff.attempt_number();
        let (known_next_seq_num, last_observed_tail_seq) = self.state.validation_bounds();
        let validated = match validate_read_batch(batch, known_next_seq_num, last_observed_tail_seq)
        {
            Ok(msg) => msg,
            Err(msg) => {
                let err = ReadSessionError::Protocol(ProtocolError::new_with_context(
                    msg,
                    self.context.clone().with_attempts(attempts),
                ));
                return Err(self.finish_session(TerminalClose::Error(err)));
            }
        };

        // T5a: every valid message is a non-empty batch or a heartbeat carrying a tail, so it
        // counts as progress and resets the retry budget.
        let has_records = matches!(validated, ValidatedMessage::Records { .. });
        if let DriverPhase::Active(attempt) = &mut self.transport_mut().phase {
            attempt.heartbeat_deadline = None;
            attempt.made_progress = true;
            attempt.fetched_record |= has_records;
        }
        self.retry_backoff.reset();

        match validated {
            ValidatedMessage::Heartbeat(tail) => {
                // R10d: start idle clock on the first heartbeat if unset, but never restart it.
                self.idle_since.get_or_insert_with(Instant::now);
                set_resume_seq_num(&mut self.start, tail.seq_num);
                self.maybe_handover(reconnect_advised);
                self.transact(|inner| inner.on_message(Some(tail), tail.seq_num))?;
                Ok(None)
            }
            ValidatedMessage::Records {
                batch,
                last_seq_num,
            } => {
                // R10d: fetching records restarts the idle clock.
                self.idle_since = Some(Instant::now());
                set_resume_seq_num(&mut self.start, last_seq_num + 1);
                if let Some(count) = self.end.count.as_mut() {
                    *count = count.saturating_sub(batch.records.len() as u64);
                }
                if let Some(bytes) = self.end.bytes.as_mut() {
                    *bytes = bytes.saturating_sub(batch.metered_bytes() as u64);
                }
                let close_clean = read_limits_exhausted(&self.end);
                if close_clean {
                    // R10c / T10: stop condition met; end the underlying request immediately
                    // without waiting for trailing EOF or opening another request.
                    debug!("read session count/bytes limit exhausted");
                    self.transport_mut().phase = DriverPhase::Idle;
                } else {
                    self.maybe_handover(reconnect_advised);
                }
                Ok(Some(DecodedBatch {
                    batch,
                    last_seq_num,
                    close_clean,
                }))
            }
        }
    }

    fn handle_eof(&mut self, fetched_record: bool) -> Result<(), TerminalClose> {
        // T9 / R9a: clean EOF ends iteration cleanly ONLY when a stop option was set; otherwise it
        // is a ConnectionLostError and retried per retry_policy.
        if self.has_stop_option() {
            debug_assert!(!read_limits_exhausted(&self.end));
            // R10d: if this attempt ran with a reduced `wait` budget, fetched new records
            // (restarting the idle clock), and ended cleanly while caught up (`is_caught_up`),
            // continue with the refreshed wait rather than stopping prematurely when the server's
            // shorter timer expires. Requiring `is_caught_up` avoids an unnecessary follow-up
            // request on pre-tail `until` or partial-`bytes` cutoffs.
            if fetched_record
                && self.state.is_caught_up()
                && let (Some(base_w), Some(sent_w)) = (self.baseline_wait, self.end.wait)
                && sent_w < base_w
                && remaining_wait(self.baseline_wait, self.idle_since).is_some_and(|w| w > 0)
            {
                return Ok(());
            }
            debug!("read session ended cleanly on stop condition");
            return Err(self.finish_session(TerminalClose::Clean));
        }
        let err = ReadSessionError::ConnectionLost(ConnectionLostError::new_with_context(
            "read stream ended cleanly without a stop condition",
            true,
            self.context.clone(),
        ));
        self.schedule_retry_or_fail(err)
    }

    fn handle_stream_error(
        &mut self,
        err: ReadSessionError,
        made_progress: bool,
    ) -> Result<(), TerminalClose> {
        if err.is_server_draining() && made_progress {
            debug!(
                next_seq_num = ?self.start.seq_num,
                "reconnecting read session while server drains"
            );
            return Ok(());
        }

        self.schedule_retry_or_fail(err)
    }

    fn poll_next_batch(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<DecodedBatch, TerminalClose>> {
        let _entered = self.span.clone().entered();
        loop {
            // Fast path: while `lifecycle` is `Active`, `inner.closed` can only be set by
            // `S2::close()` (`shutdown.is_cancelled()`), avoiding a state-lock on steady polls.
            self.abort_if_shutdown()?;

            let PollTransport { phase, sleep, .. } = self.transport_mut();

            match phase {
                DriverPhase::Idle => {
                    self.start_open_attempt();
                }
                DriverPhase::Opening(handle) => match Pin::new(handle).poll(cx) {
                    Poll::Pending => return self.pending_or_abort(cx),
                    Poll::Ready(join_res) => {
                        *phase = DriverPhase::Idle;
                        self.abort_if_shutdown()?;
                        let res = match join_res {
                            Ok(res) => res,
                            Err(err) if err.is_panic() => {
                                std::panic::resume_unwind(err.into_panic())
                            }
                            // A non-panic `JoinError` means the spawning Tokio runtime shut down
                            // while opening; surface a non-retryable abort rather than retrying.
                            Err(_) => {
                                Err(ReadSessionError::Aborted(AbortedError::new_with_context(
                                    "read session open task cancelled",
                                    self.context
                                        .clone()
                                        .with_attempts(self.retry_backoff.attempt_number()),
                                )))
                            }
                        };
                        match res {
                            Ok(stream) => {
                                self.transport_mut().phase =
                                    DriverPhase::Active(ActiveAttempt::new(stream));
                            }
                            Err(err) => self.schedule_retry_or_fail(err)?,
                        }
                    }
                },
                DriverPhase::Backoff(deadline) => match deadline {
                    Some(deadline) => match sleep.poll_until(*deadline, cx) {
                        Poll::Pending => return self.pending_or_abort(cx),
                        Poll::Ready(()) => *phase = DriverPhase::Idle,
                    },
                    None => return self.pending_or_abort(cx),
                },
                DriverPhase::Active(attempt) => {
                    // T7d: always poll the transport BEFORE checking the heartbeat timer so any
                    // messages already buffered by HTTP/2 are read before timing out.
                    match Pin::new(&mut attempt.stream).poll_next(cx) {
                        Poll::Ready(Some(Ok(frame))) => {
                            attempt.record_chunk_progress();
                            let batch = ReadBatch::from_proto(frame.msg);
                            let reconnect_advised = frame.reconnect_advised;
                            if let Some(decoded) =
                                self.handle_decoded_batch(batch, reconnect_advised)?
                            {
                                return Poll::Ready(Ok(decoded));
                            }
                        }
                        Poll::Ready(Some(Err(err))) => {
                            let made_progress = attempt.made_progress;
                            *phase = DriverPhase::Idle;
                            self.handle_stream_error(err, made_progress)?;
                        }
                        Poll::Ready(None) => {
                            let fetched_record = attempt.fetched_record;
                            *phase = DriverPhase::Idle;
                            self.handle_eof(fetched_record)?;
                        }
                        Poll::Pending => {
                            // Forward transport byte progress on an incomplete (e.g.
                            // flow-controlled) frame counts as liveness so resuming a parked
                            // session mid-frame does not falsely time out (`T7d`).
                            attempt.record_chunk_progress();
                            let deadline = *attempt
                                .heartbeat_deadline
                                .get_or_insert_with(|| Instant::now() + HEARTBEAT_TIMEOUT);
                            match sleep.poll_until(deadline, cx) {
                                Poll::Pending => return self.pending_or_abort(cx),
                                Poll::Ready(()) => {
                                    attempt.stream.retire_connection();
                                    *phase = DriverPhase::Idle;
                                    let err =
                                        ReadSessionError::Timeout(TimeoutError::new_with_context(
                                            "heartbeat timeout",
                                            self.context.clone(),
                                        ));
                                    self.schedule_retry_or_fail(err)?;
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
        if matches!(self.lifecycle, StreamLifecycle::Active(_)) {
            self.state.update(|inner| {
                inner.close_with(TerminalClose::Clean);
            });
        }
    }
}

struct BufferedBatch {
    records: std::vec::IntoIter<SequencedRecord>,
    /// Whether delivering the final buffered record locks in clean close (`R9a`/`R10c`).
    close_clean: bool,
}

impl BufferedBatch {
    fn pop(&mut self) -> Option<(SequencedRecord, bool)> {
        let record = self.records.next()?;
        Some((record, self.records.len() == 0 && self.close_clean))
    }

    fn is_empty(&self) -> bool {
        self.records.len() == 0
    }
}

/// A continuous stream of sequenced records.
///
/// Reads on demand with no session-level read-ahead: opening sends no request, and the session
/// decodes zero batches ahead of the batch currently being delivered, relying on transport flow
/// control for byte-level network read-ahead. Yields individual [`SequencedRecord`]s in
/// sequence-number order. Dropping the session closes it immediately. Use [`state`](Self::state)
/// to observe progress concurrently from other tasks.
///
/// Both [`next`](Self::next) and [`Stream::poll_next`](futures_core::Stream::poll_next) are
/// cancel safe and have identical behavior.
#[must_use = "read sessions close immediately when dropped"]
pub struct ReadSession {
    core: ReadSessionCore,
    buffered: Option<BufferedBatch>,
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
            buffered: None,
        }
    }

    /// Return the next sequenced record from the session, or `None` when the session ends cleanly.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe and can be used inside [`tokio::select!`]. Dropping the
    /// returned future does not lose buffered records or close the session.
    ///
    /// # Panics
    ///
    /// Panics if polled outside the context of a Tokio runtime.
    pub async fn next(&mut self) -> Option<Result<SequencedRecord, ReadSessionError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
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

    /// Return the highest stream tail observed from a valid received server message as of the last
    /// pull.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether the latest valid received message (as of the last pull) reported a tail
    /// equal to [`next_seq_num`](Self::next_seq_num).
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

/// Polling [`Stream`] directly requires an active Tokio runtime and behaves identically to
/// [`ReadSession::next`].
impl Stream for ReadSession {
    type Item = Result<SequencedRecord, ReadSessionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.core.poll_if_ended() {
            return Poll::Ready(None);
        }

        let (mut buffered, fresh_tail) = match this.buffered.take() {
            Some(buffered) => (buffered, None),
            None => match this.core.poll_next_batch(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(closed)) => return Poll::Ready(closed.into_stream_item()),
                Poll::Ready(Ok(decoded)) => (
                    BufferedBatch {
                        records: decoded.batch.records.into_iter(),
                        close_clean: decoded.close_clean,
                    },
                    Some(decoded.batch.tail),
                ),
            },
        };

        let (record, close_clean) = buffered.pop().expect("buffered batch is always non-empty");
        let res = match fresh_tail {
            Some(tail) => this.core.commit_delivered(close_clean, |inner| {
                inner.on_message(tail, record.seq_num + 1)
            }),
            None => this.core.commit_delivered(close_clean, |inner| {
                inner.on_record_delivered(record.seq_num)
            }),
        };
        if let Err(closed) = res {
            return Poll::Ready(closed.into_stream_item());
        }
        if !buffered.is_empty() {
            this.buffered = Some(buffered);
        }
        Poll::Ready(Some(Ok(record)))
    }
}

impl FusedStream for ReadSession {
    fn is_terminated(&self) -> bool {
        self.core.is_terminated()
    }
}

/// A continuous stream of non-empty read batches.
///
/// Reads on demand with no session-level read-ahead: opening sends no request, and the session
/// decodes zero batches ahead, relying on transport flow control for byte-level network
/// read-ahead. Delivers each server batch whole, skips empty heartbeat frames while updating
/// session state, and follows all read-session rules per batch. Dropping the session closes it
/// immediately.
///
/// Both [`next`](Self::next) and [`Stream::poll_next`](futures_core::Stream::poll_next) are
/// cancel safe and have identical behavior.
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
    /// returned future does not lose buffered records or close the session.
    ///
    /// # Panics
    ///
    /// Panics if polled outside the context of a Tokio runtime.
    pub async fn next(&mut self) -> Option<Result<ReadBatch, ReadSessionError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
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

    /// Return the highest stream tail observed from a valid received server message as of the last
    /// pull.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether the latest valid received message (as of the last pull) reported a tail
    /// equal to [`next_seq_num`](Self::next_seq_num).
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

/// Polling [`Stream`] directly requires an active Tokio runtime and behaves identically to
/// [`ReadBatchSession::next`].
impl Stream for ReadBatchSession {
    type Item = Result<ReadBatch, ReadSessionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.core.poll_if_ended() {
            return Poll::Ready(None);
        }
        match this.core.poll_next_batch(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(closed)) => Poll::Ready(closed.into_stream_item()),
            Poll::Ready(Ok(decoded)) => {
                if let Err(closed) = this.core.commit_delivered(decoded.close_clean, |inner| {
                    inner.on_message(decoded.batch.tail, decoded.last_seq_num + 1);
                }) {
                    return Poll::Ready(closed.into_stream_item());
                }
                Poll::Ready(Some(Ok(decoded.batch)))
            }
        }
    }
}

impl FusedStream for ReadBatchSession {
    fn is_terminated(&self) -> bool {
        self.core.is_terminated()
    }
}

enum ValidatedMessage {
    Heartbeat(StreamPosition),
    Records { batch: ReadBatch, last_seq_num: u64 },
}

fn validate_read_batch(
    batch: ReadBatch,
    known_next_seq_num: Option<u64>,
    last_observed_tail_seq: Option<u64>,
) -> Result<ValidatedMessage, String> {
    if batch.records.is_empty() && batch.tail.is_none() {
        return Err("read batch was empty with no tail".to_owned());
    }

    if let (Some(tail), Some(prev_tail_seq)) = (batch.tail, last_observed_tail_seq)
        && tail.seq_num < prev_tail_seq
    {
        return Err(format!(
            "read batch tail seq_num {} regressed below last observed tail {}",
            tail.seq_num, prev_tail_seq
        ));
    }

    let Some(first) = batch.records.first() else {
        let tail = batch.tail.expect("empty batch without tail rejected above");
        if let Some(next_seq) = known_next_seq_num
            && tail.seq_num < next_seq
        {
            return Err(format!(
                "read heartbeat tail seq_num {} is below next_seq_num {}",
                tail.seq_num, next_seq
            ));
        }
        return Ok(ValidatedMessage::Heartbeat(tail));
    };

    if let Some(next_seq) = known_next_seq_num
        && first.seq_num < next_seq
    {
        return Err(format!(
            "read batch contained seq_num {} below resolved cursor {}",
            first.seq_num, next_seq
        ));
    }

    for pair in batch.records.windows(2) {
        if pair[1].seq_num <= pair[0].seq_num {
            return Err(format!(
                "read batch contained out-of-order or duplicate seq_num {} after {}",
                pair[1].seq_num, pair[0].seq_num
            ));
        }
    }

    let last_seq_num = batch.records.last().expect("non-empty batch").seq_num;
    if last_seq_num == u64::MAX {
        return Err("read batch record seq_num u64::MAX has no representable successor".to_owned());
    }
    if let Some(tail) = batch.tail
        && tail.seq_num <= last_seq_num
    {
        return Err(format!(
            "read batch tail seq_num {} is not greater than last record seq_num {}",
            tail.seq_num, last_seq_num
        ));
    }
    Ok(ValidatedMessage::Records {
        batch,
        last_seq_num,
    })
}

/// Advance the absolute start used when reconnecting the read session (`R10b`).
///
/// Once the first valid record batch or heartbeat resolves the start, subsequent attempts resume
/// strictly by monotonic `seq_num` without re-evaluating `timestamp`, `tail_offset`, or `clamp`.
fn set_resume_seq_num(start: &mut ReadStart, seq_num: u64) {
    *start = ReadStart {
        seq_num: Some(seq_num),
        timestamp: None,
        tail_offset: None,
        clamp: None,
    };
}

/// Whether the read's `count` or `bytes` limit has been used up (`R10c`).
fn read_limits_exhausted(end: &ReadEnd) -> bool {
    end.count == Some(0) || end.bytes == Some(0)
}

/// Compute the remaining wait budget for a resumed request (`R10d`), rounding up to whole seconds.
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

    fn test_basin_client(retry: RetryConfig) -> BasinClient {
        let config = S2Config::new("test-token")
            .with_endpoints(S2Endpoints::for_endpoint("http://127.0.0.1:1").unwrap())
            .with_retry(retry);
        let base = BaseClient::init(&config).unwrap();
        BasinClient::init("test-basin".parse().unwrap(), &config.endpoints, base)
    }

    fn attach_test_stream(
        core: &mut ReadSessionCore,
    ) -> (FrameTx, Arc<std::sync::atomic::AtomicU64>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let chunks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let stream = Streaming::from_stream_with_chunks_for_test(
            futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx)),
            chunks.clone(),
        );
        core.transport_mut().phase = DriverPhase::Active(ActiveAttempt::new(stream));
        (tx, chunks)
    }

    fn test_session_with_retry(
        input: ReadInput,
        retry: RetryConfig,
    ) -> (
        ReadSession,
        FrameTx,
        Arc<std::sync::atomic::AtomicU64>,
        ReadSessionState,
        CancellationToken,
    ) {
        let mut session = ReadSession::open(
            test_basin_client(retry),
            "test-stream".parse().unwrap(),
            StreamHeaders::default(),
            input,
            ReadSessionConfig::default(),
        );
        let (tx, chunks) = attach_test_stream(&mut session.core);
        let state = session.state();
        let shutdown = session.core.state.shutdown.clone();
        (session, tx, chunks, state, shutdown)
    }

    fn test_session_with_active_stream(
        input: ReadInput,
    ) -> (ReadSession, FrameTx, ReadSessionState, CancellationToken) {
        let (session, tx, _chunks, state, shutdown) =
            test_session_with_retry(input, RetryConfig::new().with_max_attempts(1));
        (session, tx, state, shutdown)
    }

    // spec: r1 R10d
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
    async fn clean_stop_final_record_catches_up_and_preserves_is_caught_up_after_end() {
        let (mut session, tx, _state, _shutdown) = test_session_with_active_stream(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)).with_count(2),
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
        assert!(session.is_caught_up());
        assert!(!session.core.is_active());
        assert_eq!(session.next_seq_num(), Some(2));
        assert_eq!(session.last_observed_tail(), Some(position(2)));
        assert_eq!(cu_while_caught.await.unwrap(), position(2));
        assert_eq!(session.caught_up().await.unwrap(), position(2));
    }

    #[tokio::test]
    async fn heartbeat_after_trimmed_gap_advances_next_seq_num_on_pull() {
        let (mut session, tx, _state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));
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
            ReadInput::new(crate::types::ReadStart::SeqNum(0)).with_wait_secs(5),
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
        assert!(session.is_caught_up());
        assert_eq!(cu.await.unwrap(), position(5));
        assert_eq!(session.caught_up().await.unwrap(), position(5));
    }

    #[tokio::test]
    async fn terminal_error_after_heartbeat_preserves_next_seq_num_and_catch_up() {
        let (mut session, tx, _state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));
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
        assert!(session.is_caught_up());
        // Heartbeat caught the session up to 5 before the subsequent error arrived (`R7c`/`R8`).
        assert_eq!(cu.await.unwrap(), position(5));
        assert_eq!(session.caught_up().await.unwrap(), position(5));
    }

    #[tokio::test]
    async fn clean_end_without_catching_up_rejects_wait() {
        let (mut session, tx, _state, _shutdown) = test_session_with_active_stream(
            ReadInput::new(crate::types::ReadStart::TAIL).with_count(1),
        );
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
        let (mut session, tx, _state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));

        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();

        session.next().await.unwrap().unwrap();
        assert!(session.is_caught_up());
        let resolved_cu = session.caught_up();

        // A non-tailing batch clears is_caught_up so a new caught_up() future is pending.
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[1], None),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 1);
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
                test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::TAIL));
            session.caught_up()
        };

        assert!(matches!(
            cu.await,
            Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
        ));
    }

    #[tokio::test]
    async fn client_shutdown_wakes_parked_caught_up_immediately_without_polling_session() {
        let (mut session, _tx, state, shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::TAIL));
        let cu1 = state.caught_up();
        let cu2 = cu1.clone();

        // Poll both clones until genuinely parked on the shutdown cancellation future before
        // calling `shutdown.cancel()` (and never poll `session.next()`).
        let polled1 = Arc::new(Notify::new());
        let polled2 = Arc::new(Notify::new());
        let task1 = tokio::spawn({
            let polled = polled1.clone();
            async move {
                let mut cu = Box::pin(cu1);
                assert!(poll!(cu.as_mut()).is_pending());
                polled.notify_one();
                cu.await
            }
        });
        let task2 = tokio::spawn({
            let polled = polled2.clone();
            async move {
                let mut cu = Box::pin(cu2);
                assert!(poll!(cu.as_mut()).is_pending());
                polled.notify_one();
                cu.await
            }
        });
        polled1.notified().await;
        polled2.notified().await;
        tokio::task::yield_now().await;

        shutdown.cancel();

        // R8d / R9d / C12: already-parked CaughtUp clones both wake immediately with AbortedError!
        for task in [task1, task2] {
            let cu_err = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("parked CaughtUp must wake immediately on client close")
                .unwrap()
                .unwrap_err();
            assert!(matches!(cu_err, ReadSessionError::Aborted(_)), "{cu_err:?}");
        }
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
    async fn concurrent_abort_wins_over_clean_end_terminal_error_and_record_delivery() {
        // 1. Clean end cannot mask an Aborted close already committed by a concurrent CaughtUp.
        let (mut session, _tx, state, shutdown) = test_session_with_active_stream(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)).with_count(2),
        );
        shutdown.cancel();
        assert!(matches!(
            state.caught_up().await,
            Err(ReadSessionError::Aborted(_))
        ));
        assert!(matches!(
            session.core.finish_session(TerminalClose::Clean),
            TerminalClose::Error(ReadSessionError::Aborted(_))
        ));
        assert!(session.next().await.is_none());

        // 2. Terminal error cannot overwrite an Aborted close already committed concurrently.
        let (mut session, _tx, state, shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));
        shutdown.cancel();
        assert!(matches!(
            state.caught_up().await,
            Err(ReadSessionError::Aborted(_))
        ));
        let timeout_err = ReadSessionError::Timeout(TimeoutError::new_with_context(
            "heartbeat timeout",
            ErrorContext::default().into_read_only(),
        ));
        assert!(matches!(
            session
                .core
                .finish_session(TerminalClose::Error(timeout_err)),
            TerminalClose::Error(ReadSessionError::Aborted(_))
        ));
        assert!(session.next().await.is_none());

        // 3. Record/batch delivery rejects and leaves next_seq_num untouched once aborted.
        let (mut session, _tx, state, shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));
        shutdown.cancel();
        assert!(matches!(
            session
                .core
                .commit_delivered(false, |inner| inner.on_record_delivered(0)),
            Err(TerminalClose::Error(ReadSessionError::Aborted(_)))
        ));
        assert!(matches!(
            session
                .core
                .commit_delivered(false, |inner| inner.on_message(Some(position(1)), 1)),
            Err(TerminalClose::Error(ReadSessionError::Aborted(_)))
        ));
        assert_eq!(state.next_seq_num(), Some(0));
    }

    #[tokio::test]
    async fn exhausted_delivery_immediately_releases_transport_and_client() {
        let (mut session, tx, _state, _shutdown) = test_session_with_active_stream(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)).with_count(1),
        );

        // First poll parks on the active stream, arming both the heartbeat timer and shutdown
        // waiter on `PollTransport`.
        assert!(futures_util::poll!(std::pin::pin!(session.next())).is_pending());
        {
            let transport = session.core.transport_mut();
            assert!(transport.sleep.sleep.is_some());
            assert!(transport.shutdown.is_armed());
        }

        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();

        let rec = session.next().await.unwrap().unwrap();
        assert_eq!(rec.seq_num, 0);

        // Immediately after delivering the count-exhausting record (before the trailing `next()`),
        // leaving `StreamLifecycle::Active` drops client, phase, timer, and shutdown waiter
        // structurally, while `FusedStream::is_terminated()` stays `false` until `None` is yielded.
        assert!(!session.core.is_active());
        assert!(!session.is_terminated());

        assert!(session.next().await.is_none());
        assert!(session.is_terminated());
    }

    #[tokio::test]
    async fn dropping_session_after_client_shutdown_reports_aborted() {
        let (session, _tx, state, shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::TAIL));
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

        let (mut session, tx, _state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));
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

    fn test_batch_session_with_active_stream(
        input: ReadInput,
    ) -> (
        ReadBatchSession,
        FrameTx,
        ReadSessionState,
        CancellationToken,
    ) {
        let mut session = ReadBatchSession::open(
            test_basin_client(RetryConfig::new().with_max_attempts(1)),
            "test-stream".parse().unwrap(),
            StreamHeaders::default(),
            input,
            ReadSessionConfig::default(),
        );
        let (tx, _chunks) = attach_test_stream(&mut session.core);
        let state = session.state();
        let shutdown = session.core.state.shutdown.clone();
        (session, tx, state, shutdown)
    }

    #[test]
    fn validate_read_batch_rejects_invalid_batches_and_heartbeats() {
        assert!(matches!(
            validate_read_batch(batch(vec![record(0), record(2)], None), None, None),
            Ok(ValidatedMessage::Records {
                last_seq_num: 2,
                ..
            })
        ));
        assert!(matches!(
            validate_read_batch(batch(vec![], Some(position(5))), Some(5), Some(5)),
            Ok(ValidatedMessage::Heartbeat(pos)) if pos == position(5)
        ));

        assert!(validate_read_batch(batch(vec![record(2)], None), Some(3), None).is_err());
        assert!(
            validate_read_batch(batch(vec![record(5), record(4)], None), Some(3), None).is_err()
        );
        assert!(validate_read_batch(batch(vec![], None), Some(0), None).is_err());
        assert!(
            validate_read_batch(batch(vec![record(3)], Some(position(4))), Some(3), Some(5))
                .is_err()
        );
        assert!(validate_read_batch(batch(vec![], Some(position(2))), Some(3), None).is_err());
        assert!(validate_read_batch(batch(vec![], Some(position(4))), Some(3), Some(5)).is_err());
        assert!(validate_read_batch(batch(vec![], Some(position(6))), Some(7), Some(5)).is_err());
    }

    #[tokio::test]
    async fn caught_up_waker_reading_state_synchronously_does_not_deadlock() {
        use std::{
            sync::atomic::{AtomicUsize, Ordering},
            task::{Wake, Waker},
        };

        struct InspectingWaker {
            state: ReadSessionState,
            wakes: AtomicUsize,
        }

        impl Wake for InspectingWaker {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.wakes.fetch_add(1, Ordering::SeqCst);
                // Re-entering all ReadSessionState accessors inside wake() must never deadlock.
                let _ = self.state.next_seq_num();
                let _ = self.state.last_observed_tail();
                let _ = self.state.is_caught_up();
                drop(self.state.caught_up());
            }
        }

        // 1. Catch-up transition wakes outside ReadSessionState lock.
        let (mut session, tx, state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));
        let mut cu = state.caught_up();
        let inspector = Arc::new(InspectingWaker {
            state: state.clone(),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(inspector.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut cu).poll(&mut cx).is_pending());

        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert!(inspector.wakes.load(Ordering::SeqCst) >= 1);
        assert_eq!(cu.await.unwrap(), position(1));

        // 2. Drop transition wakes outside ReadSessionState lock.
        let (session, _tx, state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::TAIL));
        let mut cu = state.caught_up();
        let inspector = Arc::new(InspectingWaker {
            state: state.clone(),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(inspector.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut cu).poll(&mut cx).is_pending());
        drop(session);
        assert!(inspector.wakes.load(Ordering::SeqCst) >= 1);
        assert!(matches!(cu.await, Err(ReadSessionError::SessionClosed(_))));
    }

    // spec: r1 R6, R6a, R7a, R7b, R9c
    #[tokio::test]
    async fn invalid_batch_is_rejected_atomically_in_record_and_batch_views() {
        // Record view rejects `[7, u64::MAX]` (with tail) atomically: delivers no records,
        // preserves `next_seq_num` and `last_observed_tail`, releases `client`, fails `caught_up`
        // and iteration once with `ProtocolError`, then yields `None`.
        let (mut session, tx, state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(7)));
        let cu = state.caught_up();
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[7, u64::MAX], Some(u64::MAX)),
            reconnect_advised: false,
        }))
        .unwrap();

        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::Protocol(_)))
        ));
        assert!(!session.core.is_active());
        assert_eq!(state.next_seq_num(), Some(7));
        assert_eq!(state.last_observed_tail(), None);
        assert!(!state.is_caught_up());
        assert!(matches!(cu.await, Err(ReadSessionError::Protocol(_))));
        assert!(session.next().await.is_none());

        // Record view also rejects an out-of-order batch `[7, 8, 5]` with a tail atomically
        // without delivering `[7, 8]` or recording the corrupt batch's tail.
        let (mut session, tx, state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(7)));
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[7, 8, 5], Some(20)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::Protocol(_)))
        ));
        assert_eq!(state.next_seq_num(), Some(7));
        assert_eq!(state.last_observed_tail(), None);
        assert!(session.next().await.is_none());

        // Batch view rejects `[7, u64::MAX]` with a tail identically (`R6`/`R6a`).
        let (mut batch_sess, batch_tx, batch_state, _shutdown) =
            test_batch_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(
                7,
            )));
        batch_tx
            .send(Ok(S2sFrame {
                msg: proto_batch(&[7, u64::MAX], Some(u64::MAX)),
                reconnect_advised: false,
            }))
            .unwrap();
        assert!(matches!(
            batch_sess.next().await,
            Some(Err(ReadSessionError::Protocol(_)))
        ));
        assert!(!batch_sess.core.is_active());
        assert_eq!(batch_state.next_seq_num(), Some(7));
        assert_eq!(batch_state.last_observed_tail(), None);
        assert!(batch_sess.next().await.is_none());

        // Both views atomically reject a non-empty batch whose `tail.seq_num <=
        // last_record.seq_num` (such as `[0, 1, 2]` with `tail = 1` or `tail = 2`) without
        // mid-batch catch-up (`R6`).
        for bad_tail in [1, 2] {
            let (mut session, tx, state, _shutdown) =
                test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));
            let cu = state.caught_up();
            tx.send(Ok(S2sFrame {
                msg: proto_batch(&[0, 1, 2], Some(bad_tail)),
                reconnect_advised: true,
            }))
            .unwrap();
            assert!(matches!(
                session.next().await,
                Some(Err(ReadSessionError::Protocol(_)))
            ));
            assert_eq!(state.next_seq_num(), Some(0));
            assert_eq!(state.last_observed_tail(), None);
            assert!(!state.is_caught_up());
            assert!(matches!(cu.await, Err(ReadSessionError::Protocol(_))));
            assert!(session.next().await.is_none());

            let (mut batch_sess, batch_tx, batch_state, _shutdown) =
                test_batch_session_with_active_stream(ReadInput::new(
                    crate::types::ReadStart::SeqNum(0),
                ));
            batch_tx
                .send(Ok(S2sFrame {
                    msg: proto_batch(&[0, 1, 2], Some(bad_tail)),
                    reconnect_advised: true,
                }))
                .unwrap();
            assert!(matches!(
                batch_sess.next().await,
                Some(Err(ReadSessionError::Protocol(_)))
            ));
            assert_eq!(batch_state.next_seq_num(), Some(0));
            assert_eq!(batch_state.last_observed_tail(), None);
            assert!(batch_sess.next().await.is_none());
        }
    }

    // spec: r1 R6, R7c, R9c
    #[tokio::test]
    async fn empty_frame_without_tail_fails_atomically_preserving_caught_up_state() {
        let (mut session, tx, state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert!(state.is_caught_up());
        assert_eq!(state.last_observed_tail(), Some(position(1)));

        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[], None),
            reconnect_advised: false,
        }))
        .unwrap();
        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::Protocol(_)))
        ));
        assert!(session.next().await.is_none());

        assert!(state.is_caught_up());
        assert_eq!(state.next_seq_num(), Some(1));
        assert_eq!(state.last_observed_tail(), Some(position(1)));
        assert_eq!(state.caught_up().await.unwrap(), position(1));
    }

    // spec: r1 R6, R7a, R7b, R10b
    #[tokio::test]
    async fn regressing_heartbeat_fails_atomically_without_rewinding_cursor_or_state() {
        let (mut session, tx, state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::TailOffset(0)));
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[], Some(12)),
            reconnect_advised: false,
        }))
        .unwrap();
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[], Some(8)),
            reconnect_advised: false,
        }))
        .unwrap();

        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::Protocol(_)))
        ));
        assert!(!session.core.is_active());
        assert_eq!(state.next_seq_num(), Some(12));
        assert_eq!(session.core.start.seq_num, Some(12));
        assert_eq!(state.last_observed_tail(), Some(position(12)));
        assert!(state.is_caught_up());
        assert_eq!(state.caught_up().await.unwrap(), position(12));
        assert!(session.next().await.is_none());
    }

    // spec: r1 T7d, T5a
    #[tokio::test(start_paused = true)]
    async fn partial_chunk_progress_resets_heartbeat_timer_without_resetting_retry_budget() {
        use std::sync::atomic::Ordering;

        let (mut session, _tx, chunks, _state, _shutdown) = test_session_with_retry(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)),
            RetryConfig::new().with_max_attempts(2),
        );
        // Simulate one failed attempt already consumed so retry budget is on attempt 2.
        assert!(session.core.retry_backoff.next().is_some());
        assert_eq!(session.core.retry_backoff.attempt_number(), 2);

        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());

        // Advance 15s, then record partial transport chunk progress without completing a frame.
        tokio::time::advance(Duration::from_secs(15)).await;
        assert!(poll!(next.as_mut()).is_pending());
        chunks.fetch_add(1, Ordering::Relaxed);
        assert!(poll!(next.as_mut()).is_pending());

        // Advance another 15s (30s total, but only 15s since bytes arrived) -> must NOT time out!
        tokio::time::advance(Duration::from_secs(15)).await;
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);

        // Retry budget was NOT reset by partial-frame bytes (`T5a`).
        assert_eq!(session.core.retry_backoff.attempt_number(), 2);
    }

    // spec: r1 T9
    #[tokio::test]
    async fn initial_request_terminal_416_after_record_surfaces_read_unwritten_error() {
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)).with_count(10),
        );

        // Initial request delivers record 0, then emits terminal 416 -> surfaces ReadUnwrittenError
        // while preserving prior caught-up state (`T9`/`R7`/`R9c`).
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();
        tx.send(Err(ReadSessionError::ReadUnwritten(
            crate::error::ReadUnwrittenError::new(position(1)),
        )))
        .unwrap();

        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::ReadUnwritten(ref e))) if e.tail == position(1)
        ));
        assert_eq!(state.next_seq_num(), Some(1));
        assert!(state.is_caught_up());
        assert_eq!(state.caught_up().await.unwrap(), position(1));
        assert!(session.next().await.is_none());
    }

    // spec: r1 C12, R9a, R9c
    #[tokio::test]
    async fn client_is_released_immediately_on_final_ok_when_close_locks_in() {
        // 1. Uncaught-up count=1 (ReadSession): client released immediately upon returning record
        //    0.
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)).with_count(1),
        );
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(5)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert!(!session.core.is_active());
        assert!(!state.is_caught_up());
        assert!(session.next().await.is_none());

        // 2. Caught-up count=1 (ReadSession): client released immediately, while `is_caught_up`
        //    remains true even after trailing `None` (`R7c`/`R9a`).
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)).with_count(1),
        );
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert!(!session.core.is_active());
        assert!(state.is_caught_up());
        assert!(session.next().await.is_none());
        assert!(state.is_caught_up());
        assert_eq!(state.caught_up().await.unwrap(), position(1));

        // 3. ReadBatchSession count=1: client released immediately on returning the final batch.
        let (mut batch_sess, batch_tx, _state, _shutdown) = test_batch_session_with_active_stream(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)).with_count(1),
        );
        batch_tx
            .send(Ok(S2sFrame {
                msg: proto_batch(&[0], Some(5)),
                reconnect_advised: false,
            }))
            .unwrap();
        assert_eq!(batch_sess.next().await.unwrap().unwrap().records.len(), 1);
        assert!(!batch_sess.core.is_active());
        assert!(batch_sess.next().await.is_none());
    }

    // spec: r1 T7d
    #[tokio::test(start_paused = true)]
    async fn t7d_deterministic_buffered_frame_partial_chunk_and_fragmented_wait() {
        use std::sync::atomic::Ordering;

        let make_session = || {
            let (session, tx, chunks, _state, _shutdown) = test_session_with_retry(
                ReadInput::new(crate::types::ReadStart::SeqNum(0)),
                RetryConfig::new().with_max_attempts(1),
            );
            (session, tx, chunks)
        };

        // 1. Raw StreamExt::next arms deadline, then a buffered frame arrives before resume past
        //    20s -> resuming delivers the buffered frame before timing out.
        {
            use futures_util::StreamExt;
            let (mut session, tx, chunks) = make_session();
            let mut pending = Box::pin(StreamExt::next(&mut session));
            assert!(poll!(pending.as_mut()).is_pending());
            drop(pending);

            chunks.fetch_add(1, Ordering::Relaxed);
            tx.send(Ok(S2sFrame {
                msg: proto_batch(&[0], Some(1)),
                reconnect_advised: false,
            }))
            .unwrap();
            tokio::time::advance(Duration::from_secs(30)).await;
            assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        }

        // 2. Raw StreamExt::next arms deadline, then partial-frame bytes arrive (chunks_received
        //    increments without completing a frame) before resume past 20s -> resets timer instead
        //    of timing out, then completes the frame.
        {
            use futures_util::StreamExt;
            let (mut session, tx, chunks) = make_session();
            let mut pending = Box::pin(StreamExt::next(&mut session));
            assert!(poll!(pending.as_mut()).is_pending());
            drop(pending);

            chunks.fetch_add(1, Ordering::Relaxed);
            tokio::time::advance(Duration::from_secs(30)).await;
            {
                let mut resumed = Box::pin(StreamExt::next(&mut session));
                assert!(poll!(resumed.as_mut()).is_pending());
                drop(resumed);
            }
            chunks.fetch_add(1, Ordering::Relaxed);
            tx.send(Ok(S2sFrame {
                msg: proto_batch(&[0], Some(1)),
                reconnect_advised: false,
            }))
            .unwrap();
            assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        }

        // 3. Continuously pending fragmented frame: chunk progress every 12s stays alive past 20s,
        //    then 21s of silence mid-frame fails with TimeoutError.
        {
            let (mut session, tx, chunks) = make_session();
            let mut next = Box::pin(session.next());
            assert!(poll!(next.as_mut()).is_pending());
            tokio::time::advance(Duration::from_secs(12)).await;
            assert!(poll!(next.as_mut()).is_pending());
            chunks.fetch_add(1, Ordering::Relaxed);
            assert!(poll!(next.as_mut()).is_pending());
            tokio::time::advance(Duration::from_secs(12)).await;
            assert!(poll!(next.as_mut()).is_pending());
            chunks.fetch_add(1, Ordering::Relaxed);
            tx.send(Ok(S2sFrame {
                msg: proto_batch(&[0], Some(1)),
                reconnect_advised: false,
            }))
            .unwrap();
            assert_eq!(next.await.unwrap().unwrap().seq_num, 0);

            let mut stalled = Box::pin(session.next());
            assert!(poll!(stalled.as_mut()).is_pending());
            tokio::time::advance(Duration::from_secs(21)).await;
            assert!(matches!(
                stalled.await,
                Some(Err(ReadSessionError::Timeout(_)))
            ));
        }
        // 4. Parked between deliveries without waiting on the transport never arms the timer.
        {
            let (mut session, tx, chunks) = make_session();
            chunks.fetch_add(1, Ordering::Relaxed);
            tx.send(Ok(S2sFrame {
                msg: proto_batch(&[0], Some(1)),
                reconnect_advised: false,
            }))
            .unwrap();
            assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
            tokio::time::advance(Duration::from_secs(60)).await;
            let mut next = Box::pin(session.next());
            assert!(
                poll!(next.as_mut()).is_pending(),
                "T7d: timer must not be armed before waiting on the transport"
            );
            drop(next);
            // Once armed by a pending wait, >20s of true silence times out immediately on resume.
            tokio::time::advance(Duration::from_secs(21)).await;
            assert!(matches!(
                session.next().await,
                Some(Err(ReadSessionError::Timeout(_)))
            ));
        }
    }

    // spec: r1 R7, R7c, R9, R9a, T6a, T10
    #[tokio::test]
    async fn client_close_after_caught_up_r9a_and_advised_batch_preserve_caught_up() {
        // R7 / R7c / R9 / R9a: After caught-up R9a lock-in, S2::close() has no effect:
        // `is_caught_up` stays true, `caught_up()` keeps resolving to `last_observed_tail`, and
        // iteration returns `None`.
        let (mut session, tx, state, shutdown) = test_session_with_active_stream(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)).with_count(1),
        );
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert!(state.is_caught_up());
        let prior_cu = state.caught_up();

        shutdown.cancel();
        assert!(state.is_caught_up());
        assert_eq!(prior_cu.await.unwrap(), position(1));
        assert_eq!(state.caught_up().await.unwrap(), position(1));
        assert!(session.next().await.is_none());

        // T6a / T10 / R6a / R7c: A batch carrying `reconnect_advised` that reaches `tail`
        // resolves pending `caught_up()` and preserves `is_caught_up() == true` across handover
        // uniformly across batch view and record view (regardless of batch size).
        let (mut batch_sess, batch_tx, batch_state, _shutdown) =
            test_batch_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(
                0,
            )));
        let pending_cu = batch_state.caught_up();
        batch_tx
            .send(Ok(S2sFrame {
                msg: proto_batch(&[0, 1], Some(2)),
                reconnect_advised: true,
            }))
            .unwrap();
        assert_eq!(batch_sess.next().await.unwrap().unwrap().records.len(), 2);
        assert_eq!(pending_cu.await.unwrap(), position(2));
        assert!(batch_state.is_caught_up());
        assert_eq!(batch_state.caught_up().await.unwrap(), position(2));

        // Record view with a 2-record advised batch `[0, 1]` and tail `2`: record 0 does not yet
        // catch up; record 1 resolves pending `caught_up()` to `2` and preserves `is_caught_up`.
        let (mut rec_sess, rec_tx, rec_state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));
        let mut pending_cu = rec_state.caught_up();
        rec_tx
            .send(Ok(S2sFrame {
                msg: proto_batch(&[0, 1], Some(2)),
                reconnect_advised: true,
            }))
            .unwrap();
        assert_eq!(rec_sess.next().await.unwrap().unwrap().seq_num, 0);
        assert_eq!(rec_state.next_seq_num(), Some(1));
        assert!(!rec_state.is_caught_up());
        assert!(poll!(Pin::new(&mut pending_cu)).is_pending());
        // A waiter registered between record 0 and record 1 also resolves on record 1.
        let mid_batch_cu = rec_state.caught_up();
        assert_eq!(rec_sess.next().await.unwrap().unwrap().seq_num, 1);
        assert_eq!(rec_state.next_seq_num(), Some(2));
        assert_eq!(pending_cu.await.unwrap(), position(2));
        assert_eq!(mid_batch_cu.await.unwrap(), position(2));
        assert!(rec_state.is_caught_up());
        assert_eq!(rec_state.caught_up().await.unwrap(), position(2));

        // Record view with a 1-record advised batch `[0]` and tail `1` behaves identically.
        let (mut one_sess, one_tx, one_state, _shutdown) =
            test_session_with_active_stream(ReadInput::new(crate::types::ReadStart::SeqNum(0)));
        let pending_cu = one_state.caught_up();
        one_tx
            .send(Ok(S2sFrame {
                msg: proto_batch(&[0], Some(1)),
                reconnect_advised: true,
            }))
            .unwrap();
        assert_eq!(one_sess.next().await.unwrap().unwrap().seq_num, 0);
        assert_eq!(pending_cu.await.unwrap(), position(1));
        assert!(one_state.is_caught_up());
        assert_eq!(one_state.caught_up().await.unwrap(), position(1));
    }

    // spec: r1 T7d
    #[tokio::test(start_paused = true)]
    async fn reusable_sleep_reuses_single_allocation_across_heartbeat_and_backoff_and_clears_on_close()
     {
        let (mut session, tx, _chunks, _state, _shutdown) = test_session_with_retry(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)),
            RetryConfig::new()
                .with_max_attempts(2)
                .with_min_base_delay(Duration::from_millis(200))
                .with_max_base_delay(Duration::from_millis(200)),
        );

        // No Sleep is allocated until the session actually blocks.
        assert!(session.core.transport_mut().sleep.sleep.is_none());
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert!(session.core.transport_mut().sleep.sleep.is_none());

        // First Pending poll allocates a single Box<Sleep>.
        {
            let mut next = Box::pin(session.next());
            assert!(poll!(next.as_mut()).is_pending());
        }
        let sleep_addr = session
            .core
            .transport_mut()
            .sleep
            .sleep
            .as_ref()
            .expect("sleep allocated on first pending heartbeat")
            .1
            .as_ref()
            .get_ref() as *const Sleep as usize;

        // Progress clears the deadline without freeing the Sleep box; the next Pending poll reuses
        // the exact same allocation with an extended deadline.
        tokio::time::advance(Duration::from_secs(10)).await;
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[1], Some(2)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 1);
        assert!(matches!(
            &session.core.transport_mut().phase,
            DriverPhase::Active(attempt) if attempt.heartbeat_deadline.is_none()
        ));
        {
            let mut next = Box::pin(session.next());
            assert!(poll!(next.as_mut()).is_pending());
        }
        let reused_addr = session
            .core
            .transport_mut()
            .sleep
            .sleep
            .as_ref()
            .unwrap()
            .1
            .as_ref()
            .get_ref() as *const Sleep as usize;
        assert_eq!(reused_addr, sleep_addr);

        // Extended deadline does not fire at 15s (25s since start), then fires past 20s and enters
        // retry backoff reusing the same Sleep box.
        tokio::time::advance(Duration::from_secs(15)).await;
        {
            let mut next = Box::pin(session.next());
            assert!(poll!(next.as_mut()).is_pending());
        }
        tokio::time::advance(Duration::from_secs(6)).await;
        {
            let mut next = Box::pin(session.next());
            assert!(poll!(next.as_mut()).is_pending());
        }
        assert!(matches!(
            session.core.transport_mut().phase,
            DriverPhase::Backoff(_)
        ));
        let backoff_addr = session
            .core
            .transport_mut()
            .sleep
            .sleep
            .as_ref()
            .unwrap()
            .1
            .as_ref()
            .get_ref() as *const Sleep as usize;
        assert_eq!(backoff_addr, sleep_addr);

        // Closing the session drops the active transport (including the Sleep box) immediately.
        session.core.state.shutdown.cancel();
        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::Aborted(_)))
        ));
        assert!(!session.core.is_active());

        // Extreme retry backoff (`Duration::MAX`) must not panic when computing the deadline,
        // and still aborts cleanly on client close.
        let (mut max_session, max_tx, _chunks, _state, _shutdown) = test_session_with_retry(
            ReadInput::new(crate::types::ReadStart::SeqNum(0)),
            RetryConfig::new()
                .with_max_attempts(2)
                .with_min_base_delay(Duration::MAX)
                .with_max_base_delay(Duration::MAX),
        );
        max_tx
            .send(Err(ReadSessionError::ConnectionLost(
                ConnectionLostError::new_with_context(
                    "transient",
                    true,
                    ErrorContext::default().into_read_only(),
                ),
            )))
            .unwrap();
        {
            let mut next = Box::pin(max_session.next());
            assert!(poll!(next.as_mut()).is_pending());
        }
        assert!(matches!(
            max_session.core.transport_mut().phase,
            DriverPhase::Backoff(_)
        ));
        max_session.core.state.shutdown.cancel();
        assert!(matches!(
            max_session.next().await,
            Some(Err(ReadSessionError::Aborted(_)))
        ));
    }

    #[test]
    fn reusable_sleep_rebinds_when_moved_to_another_tokio_runtime() {
        let mut timer = ReusableSleep::default();

        let rt1 = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt1.block_on(async {
            let deadline = Instant::now() + Duration::from_secs(60);
            let mut wait = std::future::poll_fn(|cx| timer.poll_until(deadline, cx));
            assert!(poll!(Pin::new(&mut wait)).is_pending());
        });
        drop(rt1);

        let rt2 = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt2.block_on(async {
            let deadline = Instant::now() + Duration::from_millis(25);
            tokio::time::timeout(
                Duration::from_secs(1),
                std::future::poll_fn(|cx| timer.poll_until(deadline, cx)),
            )
            .await
            .expect("timer must rebind to the new Tokio runtime and wake cleanly");
        });
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
            .read_session(
                ReadInput::new(crate::types::ReadStart::TAIL),
                ReadSessionConfig::default(),
            )
            .unwrap();
        let _rbs = stream
            .read_batch_session(
                ReadInput::new(crate::types::ReadStart::TAIL),
                ReadSessionConfig::default(),
            )
            .unwrap();
    }
}
