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
use http::StatusCode;
use s2_api::v1::stream::{ReadEnd, ReadStart, proto};
use tokio::{
    sync::{Notify, futures::OwnedNotified},
    time::{Instant, Sleep},
};
use tokio_util::{sync::WaitForCancellationFutureOwned, task::AbortOnDropHandle};
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

#[derive(Default)]
#[must_use = "pending catch-up wake must be dispatched after releasing the state lock"]
struct PendingWake(Option<Arc<Notify>>);

impl PendingWake {
    fn set(&mut self, notify: Option<Arc<Notify>>) {
        if let Some(notify) = notify {
            debug_assert!(self.0.is_none());
            self.0 = Some(notify);
        }
    }

    fn wake(self) {
        if let Some(notify) = self.0 {
            notify.notify_waiters();
        }
    }
}

#[derive(Clone)]
enum CaughtUpFuture {
    Pending(Arc<CaughtUpSignal>),
    Ready(CaughtUpResult),
}

#[derive(Default)]
struct CaughtUpWaits {
    notified: Option<Pin<Box<OwnedNotified>>>,
    shutdown_wait: Option<Pin<Box<WaitForCancellationFutureOwned>>>,
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
    /// Wrapped in `StdMutex` solely to preserve `Sync` (`Mutex<T>: Sync` for `T: Send`).
    /// Accessed exclusively via `get_mut()` inside `Future::poll` with zero runtime locking.
    waits: StdMutex<CaughtUpWaits>,
    done: bool,
}

impl Clone for CaughtUp {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            state: self.state.clone(),
            waits: StdMutex::new(CaughtUpWaits::default()),
            done: false,
        }
    }
}

impl fmt::Debug for CaughtUp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaughtUp").finish_non_exhaustive()
    }
}

impl CaughtUp {
    fn finish_ready(
        waits: &mut CaughtUpWaits,
        done: &mut bool,
        result: &CaughtUpResult,
    ) -> Poll<CaughtUpResult> {
        *waits = CaughtUpWaits::default();
        *done = true;
        Poll::Ready(result.clone())
    }
}

impl Future for CaughtUp {
    type Output = Result<StreamPosition, ReadSessionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        match &this.inner {
            CaughtUpFuture::Ready(result) => {
                this.done = true;
                Poll::Ready(result.clone())
            }
            CaughtUpFuture::Pending(signal) => {
                let waits = this
                    .waits
                    .get_mut()
                    .expect("CaughtUp waits mutex is never locked");

                // Always check the catch-up signal first so an already-resolved tail (`R8a`) or
                // already-locked close reason (`R9`) is never overwritten by a later client
                // shutdown.
                if let Some(result) = signal.get() {
                    return Self::finish_ready(waits, &mut this.done, result);
                }

                // Register `cx` with the signal before re-checking `signal.get()` so a concurrent
                // `resolve()` cannot slip between the check and registration.
                let notified = waits
                    .notified
                    .get_or_insert_with(|| Box::pin(signal.notify.clone().notified_owned()));
                let _ = notified.as_mut().poll(cx);

                if let Some(result) = signal.get() {
                    return Self::finish_ready(waits, &mut this.done, result);
                }

                // R8d / R9d / C12: observe client shutdown immediately even when no task is
                // polling the on-demand session.
                let shutdown_fired = if this.state.shutdown.is_cancelled() {
                    true
                } else {
                    let wait = waits.shutdown_wait.get_or_insert_with(|| {
                        Box::pin(this.state.shutdown.clone().cancelled_owned())
                    });
                    wait.as_mut().poll(cx).is_ready()
                };

                if !shutdown_fired {
                    return Poll::Pending;
                }

                // Commit abort if no close reason locked in first; once `closed.is_some()`, every
                // `Pending` signal handed out by this session has been resolved.
                this.state
                    .update(|inner, wake| inner.abort_for_client_close(wake));

                if let Some(result) = signal.get() {
                    Self::finish_ready(waits, &mut this.done, result)
                } else {
                    waits.shutdown_wait = None;
                    Poll::Pending
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
    /// Lazily allocated on the first `caught_up()` call while pending so sessions that never await
    /// `caught_up()` avoid allocating `CaughtUpSignal`/`Notify` on init or tailing batches.
    Pending(Option<Arc<CaughtUpSignal>>),
    CaughtUp(StreamPosition),
    Ended(ReadSessionError),
}

impl CatchUpSlot {
    fn pending() -> Self {
        Self::Pending(None)
    }

    fn is_caught_up(&self) -> bool {
        matches!(self, Self::CaughtUp(_))
    }

    fn future(&mut self) -> CaughtUpFuture {
        match self {
            Self::Pending(slot) => {
                let signal = slot.get_or_insert_with(|| Arc::new(CaughtUpSignal::new()));
                CaughtUpFuture::Pending(signal.clone())
            }
            Self::CaughtUp(tail) => CaughtUpFuture::Ready(Ok(*tail)),
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
    /// Current retry attempt number (`E7`), updated on each attempt start and reset to `1` on
    /// `T5a` progress so aborts from parked observers carry the accurate attempt count.
    attempts: u32,
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
            attempts: 1,
        }
    }

    fn current_context(&self) -> ErrorContext {
        self.context.clone().with_attempts(self.attempts)
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

    fn recompute_caught_up(&mut self, wake: &mut PendingWake) {
        if self.phase == RequestPhase::Ended {
            return;
        }
        match self.compute_caught_up_tail() {
            Some(tail) => {
                if !matches!(self.catch_up, CatchUpSlot::CaughtUp(prev) if prev == tail) {
                    let prev = std::mem::replace(&mut self.catch_up, CatchUpSlot::CaughtUp(tail));
                    if let CatchUpSlot::Pending(Some(signal)) = prev {
                        wake.set(signal.set_result(Ok(tail)));
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

    fn lock_in_clean_close(&mut self, wake: &mut PendingWake) {
        if self.closed.is_some() {
            return;
        }
        self.closed = Some(TerminalClose::Clean);
        if !self.catch_up.is_caught_up() {
            self.on_ended(None, wake);
        }
    }

    fn finish_batch_action(&mut self, after_batch: AfterBatch, wake: &mut PendingWake) {
        match after_batch {
            AfterBatch::None => {}
            AfterBatch::CloseClean => self.lock_in_clean_close(wake),
            AfterBatch::Disconnect => {
                self.phase = RequestPhase::Connecting;
                self.recompute_caught_up(wake);
            }
        }
    }

    /// Record a freshly decoded non-empty batch together with immediate delivery of its first
    /// record (record view) or entire batch (batch view).
    fn on_batch_decoded_and_delivered(
        &mut self,
        tail: Option<StreamPosition>,
        delivered_last_seq: u64,
        after_batch: AfterBatch,
        wake: &mut PendingWake,
    ) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        self.attempts = 1;
        if let Some(tail) = tail {
            self.update_observed_tail(tail);
        }
        self.phase = RequestPhase::Open { latest_tail: tail };
        self.next_seq_num = Some(delivered_last_seq.saturating_add(1));
        self.recompute_caught_up(wake);
        self.finish_batch_action(after_batch, wake);
    }

    /// Record delivery of a subsequent record from the current batch.
    fn on_record_delivered(
        &mut self,
        seq_num: u64,
        after_batch: AfterBatch,
        wake: &mut PendingWake,
    ) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        self.next_seq_num = Some(seq_num.saturating_add(1));
        self.recompute_caught_up(wake);
        self.finish_batch_action(after_batch, wake);
    }

    /// Record a decoded heartbeat (`records` empty, `tail` present). Because reading is on-demand
    /// (`R6b`), no records remain undelivered when a heartbeat is decoded.
    fn on_heartbeat(
        &mut self,
        tail: StreamPosition,
        disconnected_for_advice: bool,
        wake: &mut PendingWake,
    ) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        self.attempts = 1;
        self.update_observed_tail(tail);
        self.next_seq_num = Some(
            self.next_seq_num
                .map_or(tail.seq_num, |prev| prev.max(tail.seq_num)),
        );
        self.phase = RequestPhase::Open {
            latest_tail: Some(tail),
        };
        self.recompute_caught_up(wake);
        if disconnected_for_advice {
            self.phase = RequestPhase::Connecting;
            self.recompute_caught_up(wake);
        }
    }

    /// Record an empty regular message carrying neither records nor a tail (`R7c`): clears the
    /// active request's latest tail so `is_caught_up()` reflects the most recent decoded message,
    /// while preserving `last_observed_tail` and `next_seq_num`.
    fn on_empty_frame_without_tail(&mut self, wake: &mut PendingWake) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        if matches!(self.phase, RequestPhase::Open { .. }) {
            self.phase = RequestPhase::Open { latest_tail: None };
            self.recompute_caught_up(wake);
        }
    }

    fn on_disconnected(&mut self, wake: &mut PendingWake) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        self.phase = RequestPhase::Connecting;
        self.recompute_caught_up(wake);
    }

    /// Apply a clean stop when iteration is returning end-of-stream (`R9a`, `R11d`).
    fn on_clean_end_now(&mut self, tail: Option<StreamPosition>, wake: &mut PendingWake) {
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
                self.recompute_caught_up(wake);
            }
            self.closed = Some(TerminalClose::Clean);
        }
    }

    fn abort_for_client_close(&mut self, wake: &mut PendingWake) {
        match &self.closed {
            Some(TerminalClose::Clean) => {
                // Keep the locked-in clean outcome (`R9`), but end caught-up observation
                // immediately on client close (`R7`/`R7c`).
                self.on_ended(None, wake);
            }
            Some(TerminalClose::Error(_)) => {}
            None => {
                if self.phase == RequestPhase::Ended {
                    return;
                }
                let err = ReadSessionError::Aborted(AbortedError::new_with_context(
                    "client closed",
                    self.current_context(),
                ));
                self.closed = Some(TerminalClose::Error(err.clone()));
                self.on_ended(Some(err), wake);
            }
        }
    }

    fn lock_in_abort_if_cancelled(
        &mut self,
        shutdown: &CancellationToken,
        wake: &mut PendingWake,
    ) -> Option<TerminalClose> {
        if shutdown.is_cancelled() {
            self.abort_for_client_close(wake);
        }
        self.closed.clone()
    }

    fn end_with_close(&mut self, close: &TerminalClose, wake: &mut PendingWake) {
        self.on_ended(
            match close {
                TerminalClose::Clean => None,
                TerminalClose::Error(err) => Some(err.clone()),
            },
            wake,
        );
    }

    fn on_ended(&mut self, error: Option<ReadSessionError>, wake: &mut PendingWake) {
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
        if let CatchUpSlot::Pending(Some(signal)) = prev {
            wake.set(signal.set_result(Err(terminal_err)));
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

    /// Return the latest stream tail observed from a decoded server message as of the last pull.
    ///
    /// Because reading is on-demand, this does not reflect newer appends while the session is
    /// parked; use [`S2Stream::check_tail`](crate::S2Stream::check_tail) for a fresh stream tail.
    /// Never moves backward, persists across retries and handovers, and is retained after
    /// iteration ends.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.inner.lock().unwrap().last_observed_tail
    }

    /// Return whether the session is open with an active request whose most recent decoded
    /// message (as of the last pull) reported a tail equal to [`next_seq_num`](Self::next_seq_num).
    ///
    /// Because reading is on-demand, this is not a live lag or liveness check while the session is
    /// parked; use [`S2Stream::check_tail`](crate::S2Stream::check_tail) for a fresh stream tail.
    /// Returns `false` while reconnecting, after [`S2::close`](crate::S2::close) or session drop,
    /// or once iteration has ended.
    #[must_use]
    pub fn is_caught_up(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        !self.shutdown.is_cancelled() && inner.catch_up.is_caught_up()
    }

    /// Return a future that resolves to the tail position once the session is caught up.
    ///
    /// Resolves immediately if currently caught up, or the next time the session becomes caught
    /// up. Once resolved, its value never changes. Does not drive reading — continue polling the
    /// session while awaiting it (even on an empty stream). Remains pending across retries and
    /// handovers. Fails immediately on session close or [`S2::close`](crate::S2::close), even when
    /// no task is polling the session.
    pub fn caught_up(&self) -> CaughtUp {
        let future = self.update(|inner, wake| {
            if self.shutdown.is_cancelled() {
                inner.abort_for_client_close(wake);
            }
            inner.catch_up.future()
        });
        CaughtUp {
            inner: future,
            state: self.clone(),
            waits: StdMutex::new(CaughtUpWaits::default()),
            done: false,
        }
    }

    fn update<R>(&self, f: impl FnOnce(&mut ReadStateInner, &mut PendingWake) -> R) -> R {
        let mut wake = PendingWake::default();
        let out = {
            let mut inner = self.inner.lock().unwrap();
            f(&mut inner, &mut wake)
        };
        wake.wake();
        out
    }

    fn set_attempt(&self, attempts: u32) {
        self.inner.lock().unwrap().attempts = attempts;
    }

    fn on_disconnected(&self) {
        self.update(|inner, wake| inner.on_disconnected(wake));
    }
}

/// Immutable snapshot of per-attempt parameters captured when opening each request (`R11d`).
#[derive(Clone, Copy)]
struct AttemptSnapshot {
    /// Whether the session had already resolved its start before *this* request was opened.
    was_resumed: bool,
    /// Absolute `seq_num` sent on *this* request (compared against `416` wire tail per `R11d`).
    sent_seq_num: Option<u64>,
    /// Whether *this* request was sent with no `wait` remaining (`R11d`).
    no_wait_remaining: bool,
}

struct ActiveAttempt {
    stream: Streaming<proto::ReadBatch, ReadSessionError>,
    snapshot: AttemptSnapshot,
    made_progress: bool,
    fetched_record: bool,
    last_chunks_received: u64,
}

impl ActiveAttempt {
    fn record_chunk_progress(&mut self, heartbeat_deadline: &mut Option<Instant>) {
        let chunks_now = self.stream.chunks_received();
        if chunks_now != self.last_chunks_received {
            self.last_chunks_received = chunks_now;
            *heartbeat_deadline = None;
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
    Opening {
        handle: OpenAttemptHandle,
        snapshot: AttemptSnapshot,
    },
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
    sleep: Option<Pin<Box<Sleep>>>,
}

impl ReusableSleep {
    fn poll_until(&mut self, deadline: Instant, cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= deadline {
            return Poll::Ready(());
        }
        let sleep = self
            .sleep
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        if sleep.deadline() != deadline {
            sleep.as_mut().reset(deadline);
        }
        sleep.as_mut().poll(cx)
    }

    fn clear(&mut self) {
        self.sleep = None;
    }
}

/// Transition applied once the final record of a decoded batch has been delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterBatch {
    None,
    /// Remaining `count` or `bytes` reached `0` (`R11c`): lock in clean close (`R9a`).
    CloseClean,
    /// `T6a` reconnect advice acted on: transition to `Connecting` after delivering the batch so
    /// its tail still resolves pending `caught_up()` uniformly across views and batch sizes.
    Disconnect,
}

struct DecodedBatch {
    batch: ReadBatch,
    after_batch: AfterBatch,
}

enum DriverStep {
    Continue,
    Done(Option<Result<DecodedBatch, ReadSessionError>>),
}

enum BatchStep {
    Yield(DecodedBatch),
    Continue,
    Done(Option<Result<DecodedBatch, ReadSessionError>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamLifecycle {
    Active,
    /// Terminal error already returned; next poll emits `None` and transitions to `Terminated`.
    PendingEof,
    /// `None` has been returned (`FusedStream::is_terminated() == true`).
    Terminated,
}

struct PollTransport {
    phase: DriverPhase,
    heartbeat_deadline: Option<Instant>,
    sleep: ReusableSleep,
    shutdown_wait: Option<Pin<Box<WaitForCancellationFutureOwned>>>,
}

impl PollTransport {
    fn new() -> Self {
        Self {
            phase: DriverPhase::Idle,
            heartbeat_deadline: None,
            sleep: ReusableSleep::default(),
            shutdown_wait: None,
        }
    }

    fn reset_to_idle(&mut self) {
        self.phase = DriverPhase::Idle;
        self.heartbeat_deadline = None;
        self.sleep.clear();
        self.shutdown_wait = None;
    }
}

struct ReadSessionCore {
    basin: BasinName,
    stream: StreamName,
    /// Released once the session can no longer open new requests so a retained finished session
    /// does not keep the underlying client / HTTP/2 connection pool alive (`C12`).
    client: Option<BasinClient>,
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
    context: ErrorContext,
    retry_backoff: RetryBackoff,
    advised_reconnects: AdvisedReconnects,
    idle_since: Option<Instant>,
    has_received_response: bool,
    last_fetched_seq: Option<u64>,
    /// Non-`Sync` on-demand transport state wrapped in `StdMutex` solely to keep `ReadSession`
    /// and `ReadBatchSession` `Sync` (`Mutex<T>: Sync` for `T: Send`). Accessed exclusively via
    /// `get_mut()` on `&mut self`, so polling incurs zero runtime locking.
    transport: StdMutex<PollTransport>,
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
        let baseline_wait = end.wait;
        let has_stop_option =
            end.count.is_some() || end.bytes.is_some() || end.until.is_some() || end.wait.is_some();
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
            client: Some(client),
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
            context,
            retry_backoff,
            advised_reconnects: AdvisedReconnects::default(),
            idle_since: None,
            has_received_response: false,
            last_fetched_seq: None,
            transport: StdMutex::new(PollTransport::new()),
            lifecycle: StreamLifecycle::Active,
        }
    }

    fn transport_mut(&mut self) -> &mut PollTransport {
        self.transport
            .get_mut()
            .expect("read transport mutex is never locked")
    }

    fn poll_if_ended(&mut self) -> bool {
        match self.lifecycle {
            StreamLifecycle::Active => false,
            StreamLifecycle::PendingEof => {
                self.lifecycle = StreamLifecycle::Terminated;
                true
            }
            StreamLifecycle::Terminated => true,
        }
    }

    fn is_terminated(&self) -> bool {
        self.lifecycle == StreamLifecycle::Terminated
    }

    /// Tear down local transport/client state after `inner.closed` and `RequestPhase::Ended` have
    /// already been committed under the state lock (`C12`).
    fn finish_already_closed(&mut self, closed: TerminalClose) -> Option<ReadSessionError> {
        self.transport_mut().reset_to_idle();
        self.client = None;
        match closed {
            TerminalClose::Clean => {
                self.lifecycle = StreamLifecycle::Terminated;
                None
            }
            TerminalClose::Error(err) => {
                self.lifecycle = StreamLifecycle::PendingEof;
                Some(err)
            }
        }
    }

    /// Commit a terminal transition under a single state lock, respecting any prior close/abort,
    /// and release `BasinClient` afterward outside the lock (`C12`).
    fn finish_session(
        &mut self,
        f: impl FnOnce(&mut ReadStateInner, &mut PendingWake) -> TerminalClose,
    ) -> Option<ReadSessionError> {
        let closed = self.state.update(|inner, wake| {
            let closed = if let Some(closed) =
                inner.lock_in_abort_if_cancelled(&self.state.shutdown, wake)
            {
                closed
            } else {
                f(inner, wake)
            };
            inner.end_with_close(&closed, wake);
            closed
        });
        self.finish_already_closed(closed)
    }

    /// Apply `f` if the session is open and not aborted; otherwise finalize and return the
    /// committed terminal outcome under a single state lock.
    fn update_open_or_finish(
        &mut self,
        f: impl FnOnce(&mut ReadStateInner, &mut PendingWake),
    ) -> Result<(), Option<ReadSessionError>> {
        let closed = self.state.update(|inner, wake| {
            if let Some(closed) = inner.lock_in_abort_if_cancelled(&self.state.shutdown, wake) {
                inner.end_with_close(&closed, wake);
                Some(closed)
            } else {
                f(inner, wake);
                None
            }
        });
        match closed {
            Some(closed) => Err(self.finish_already_closed(closed)),
            None => Ok(()),
        }
    }

    fn commit_record_delivered(
        &mut self,
        seq_num: u64,
        after_batch: AfterBatch,
    ) -> Result<(), Option<ReadSessionError>> {
        self.update_open_or_finish(|inner, wake| {
            inner.on_record_delivered(seq_num, after_batch, wake);
        })?;
        if after_batch == AfterBatch::CloseClean {
            // Close reason is now locked in (`R9`), so no further request can open and dropping
            // the last `BasinClient` cannot alter `ReadSessionState`.
            self.client = None;
        }
        Ok(())
    }

    fn commit_batch_delivered(
        &mut self,
        tail: Option<StreamPosition>,
        delivered_last_seq: u64,
        after_batch: AfterBatch,
    ) -> Result<(), Option<ReadSessionError>> {
        self.update_open_or_finish(|inner, wake| {
            inner.on_batch_decoded_and_delivered(tail, delivered_last_seq, after_batch, wake);
        })?;
        if after_batch == AfterBatch::CloseClean {
            self.client = None;
        }
        Ok(())
    }

    /// If the session has already closed (`R9`) or client shutdown (`C12`/`R9d`) is active,
    /// finalize under a single lock and return `Some(None)` on clean close or `Some(Some(err))`.
    fn take_closed_or_abort(&mut self) -> Option<Option<ReadSessionError>> {
        let closed = self.state.update(|inner, wake| {
            let closed = inner.lock_in_abort_if_cancelled(&self.state.shutdown, wake)?;
            inner.end_with_close(&closed, wake);
            Some(closed)
        })?;
        Some(self.finish_already_closed(closed))
    }

    /// Register `cx` with the client shutdown token before returning `Poll::Pending`, or abort
    /// immediately if `S2::close()` already fired.
    fn pending_or_abort(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<DecodedBatch, ReadSessionError>>> {
        let fired = if self.state.shutdown.is_cancelled() {
            true
        } else {
            let shutdown = self.state.shutdown.clone();
            let wait = self
                .transport_mut()
                .shutdown_wait
                .get_or_insert_with(|| Box::pin(shutdown.cancelled_owned()));
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
        self.state.set_attempt(attempt_num);
        let snapshot = AttemptSnapshot {
            was_resumed: self.has_received_response,
            sent_seq_num: self.start.seq_num,
            no_wait_remaining: has_no_wait_remaining(&self.end),
        };
        debug!(
            attempt = attempt_num,
            next_seq_num = ?self.start.seq_num,
            "opening read session request"
        );
        let client = self
            .client
            .clone()
            .expect("active read session holds BasinClient");
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
        // Spawn the opening request behind `AbortOnDropHandle` so `T7a`/`T7b` (`connection_timeout`
        // and `request_timeout` until `200` headers or full non-2xx error body) settle in real time
        // even if the caller parks while `Opening`, while keeping body decoding, heartbeats, and
        // retries on-demand (`R6b`) and aborting immediately if the session drops.
        self.transport_mut().phase = DriverPhase::Opening {
            handle: AbortOnDropHandle::new(tokio::spawn(fut)),
            snapshot,
        };
    }

    fn finish_clean_end_now(
        &mut self,
        tail: Option<StreamPosition>,
    ) -> Option<Result<DecodedBatch, ReadSessionError>> {
        self.finish_session(|inner, wake| {
            inner.on_clean_end_now(tail, wake);
            TerminalClose::Clean
        })
        .map(Err)
    }

    fn finish_terminal_error(
        &mut self,
        err: ReadSessionError,
    ) -> Option<Result<DecodedBatch, ReadSessionError>> {
        self.finish_session(|inner, _wake| {
            inner.closed = Some(TerminalClose::Error(err.clone()));
            TerminalClose::Error(err)
        })
        .map(Err)
    }

    /// Schedule retry backoff on `err`, or lock in and return the terminal poll result.
    fn schedule_retry_or_fail(&mut self, err: ReadSessionError) -> DriverStep {
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
            DriverStep::Continue
        } else {
            DriverStep::Done(self.finish_terminal_error(err))
        }
    }

    /// Handle a regular frame carrying neither records nor a tail (`T5a`, `T6a`, `R7c`).
    fn handle_empty_frame(&mut self, reconnect_advised: bool, made_progress: bool) -> BatchStep {
        // T6 / T6a: even if an empty frame carries no progress, still honor reconnect advice so
        // the retiring request is closed; only grant a free handover if this attempt already made
        // progress earlier, otherwise count the move as a retry (`T1`/`T3`).
        if reconnect_advised && self.advised_reconnects.should_reconnect() {
            let transport = self.transport_mut();
            transport.phase = DriverPhase::Idle;
            transport.heartbeat_deadline = None;
            self.advised_reconnects.record();
            self.state.on_disconnected();
            debug!(
                next_seq_num = ?self.start.seq_num,
                made_progress,
                advised_reconnects = self.advised_reconnects.total(),
                "reconnecting read session on server advice from empty frame"
            );
            if !made_progress {
                let err = ReadSessionError::ConnectionLost(ConnectionLostError::new_with_context(
                    "server advised reconnect before stream progress",
                    true,
                    self.context.clone(),
                ));
                if let DriverStep::Done(done) = self.schedule_retry_or_fail(err) {
                    return BatchStep::Done(done);
                }
            }
        } else if let Err(outcome) =
            self.update_open_or_finish(|inner, wake| inner.on_empty_frame_without_tail(wake))
        {
            return BatchStep::Done(outcome.map(Err));
        }
        BatchStep::Continue
    }

    fn handle_decoded_batch(
        &mut self,
        batch: ReadBatch,
        reconnect_advised: bool,
        made_progress: bool,
    ) -> BatchStep {
        // R6 / R7a / E7: reject any batch containing a non-increasing seq_num, a seq_num below
        // the resolved cursor, or an unrepresentable successor atomically without delivering any
        // of its records or updating session state.
        let attempts = self.retry_backoff.attempt_number();
        let min_next_seq_num = if self.has_received_response || self.start.clamp != Some(true) {
            self.start.seq_num
        } else {
            None
        };
        self.last_fetched_seq = match validate_read_batch_order(
            &batch,
            self.last_fetched_seq,
            min_next_seq_num,
            &self.context,
            attempts,
        ) {
            Ok(last_seq) => last_seq,
            Err(err) => return BatchStep::Done(self.finish_terminal_error(err)),
        };

        // T5a: only a non-empty batch or a heartbeat (carrying a tail) counts as progress and
        // resets the retry budget.
        let has_records = !batch.records.is_empty();
        let has_tail = batch.tail.is_some();
        if !has_records && !has_tail {
            return self.handle_empty_frame(reconnect_advised, made_progress);
        }

        {
            let transport = self.transport_mut();
            transport.heartbeat_deadline = None;
            if let DriverPhase::Active(attempt) = &mut transport.phase {
                attempt.made_progress = true;
                if has_records {
                    attempt.fetched_record = true;
                }
            }
        }
        let had_response = self.has_received_response;
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

        update_resume_start(&mut self.start, &batch, had_response);
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
        let after_batch = if limits_exhausted {
            // R11c / T10: stop condition met; end the underlying request immediately without
            // waiting for trailing EOF or opening another request.
            debug!("read session count/bytes limit exhausted");
            self.transport_mut().phase = DriverPhase::Idle;
            AfterBatch::CloseClean
        } else if reconnect_advised && self.advised_reconnects.should_reconnect() {
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
            AfterBatch::Disconnect
        } else {
            AfterBatch::None
        };

        if has_records {
            BatchStep::Yield(DecodedBatch { batch, after_batch })
        } else if let Some(tail) = batch.tail {
            if let Err(outcome) = self.update_open_or_finish(|inner, wake| {
                inner.on_heartbeat(tail, after_batch == AfterBatch::Disconnect, wake);
            }) {
                return BatchStep::Done(outcome.map(Err));
            }
            BatchStep::Continue
        } else {
            BatchStep::Continue
        }
    }

    fn handle_eof(&mut self, fetched_record: bool) -> DriverStep {
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
                return DriverStep::Continue;
            }
            debug!("read session ended cleanly on stop condition");
            return DriverStep::Done(self.finish_clean_end_now(None));
        }
        let err = ReadSessionError::ConnectionLost(ConnectionLostError::new_with_context(
            "read stream ended cleanly without a stop condition",
            true,
            self.context.clone(),
        ));
        self.state.on_disconnected();
        self.schedule_retry_or_fail(err)
    }

    fn handle_stream_error(
        &mut self,
        err: ReadSessionError,
        made_progress: bool,
        snapshot: AttemptSnapshot,
    ) -> DriverStep {
        // R11d: 416 on a resumed request with no remaining wait is a clean stop unless the
        // reported tail regressed below the sequence number sent on that request.
        if let Some(tail) = resumed_unwritten_stop_tail(snapshot, &err) {
            debug!(?tail, "read session reached tail on resumed stop condition");
            return DriverStep::Done(self.finish_clean_end_now(tail));
        }

        // If `count` or `bytes` is already exhausted after receiving data, end cleanly rather than
        // reconnecting with count=0/bytes=0.
        if self.has_received_response && read_limits_exhausted(&self.end) {
            debug!("read session limits exhausted after stream error");
            return DriverStep::Done(self.finish_clean_end_now(None));
        }

        self.state.on_disconnected();

        if err.is_server_draining() && made_progress {
            debug!(
                next_seq_num = ?self.start.seq_num,
                "reconnecting read session while server drains"
            );
            return DriverStep::Continue;
        }

        self.schedule_retry_or_fail(err)
    }

    fn poll_next_batch(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<DecodedBatch, ReadSessionError>>> {
        if self.poll_if_ended() {
            return Poll::Ready(None);
        }
        let _entered = self.span.clone().entered();
        loop {
            // Fast path: while `lifecycle == Active`, `inner.closed` can only be set by
            // `AfterBatch::CloseClean` (which clears `self.client = None`) or `S2::close()`
            // (`shutdown.is_cancelled()`), so steady-state polls avoid locking `state.inner`.
            if (self.client.is_none() || self.state.shutdown.is_cancelled())
                && let Some(outcome) = self.take_closed_or_abort()
            {
                return Poll::Ready(outcome.map(Err));
            }

            let PollTransport {
                phase,
                heartbeat_deadline,
                sleep,
                ..
            } = self
                .transport
                .get_mut()
                .expect("read transport mutex is never locked");

            match phase {
                DriverPhase::Idle => {
                    self.start_open_attempt();
                }
                DriverPhase::Opening { handle, snapshot } => match Pin::new(handle).poll(cx) {
                    Poll::Pending => return self.pending_or_abort(cx),
                    Poll::Ready(join_res) => {
                        let snapshot = *snapshot;
                        *phase = DriverPhase::Idle;
                        if self.state.shutdown.is_cancelled()
                            && let Some(outcome) = self.take_closed_or_abort()
                        {
                            return Poll::Ready(outcome.map(Err));
                        }
                        let res = match join_res {
                            Ok(res) => res,
                            Err(err) if err.is_panic() => {
                                std::panic::resume_unwind(err.into_panic())
                            }
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
                                let transport = self.transport_mut();
                                transport.heartbeat_deadline = None;
                                let last_chunks_received = stream.chunks_received();
                                transport.phase = DriverPhase::Active(ActiveAttempt {
                                    stream,
                                    snapshot,
                                    made_progress: false,
                                    fetched_record: false,
                                    last_chunks_received,
                                });
                            }
                            Err(err) => {
                                if let Some(tail) = resumed_unwritten_stop_tail(snapshot, &err) {
                                    debug!(
                                        ?tail,
                                        "read session reached tail on resumed stop condition"
                                    );
                                    return Poll::Ready(self.finish_clean_end_now(tail));
                                }
                                if let DriverStep::Done(done) = self.schedule_retry_or_fail(err) {
                                    return Poll::Ready(done);
                                }
                            }
                        }
                    }
                },
                DriverPhase::Backoff(deadline) => match deadline {
                    Some(deadline) => match sleep.poll_until(*deadline, cx) {
                        Poll::Pending => return self.pending_or_abort(cx),
                        Poll::Ready(()) => {
                            *phase = DriverPhase::Idle;
                        }
                    },
                    None => return self.pending_or_abort(cx),
                },
                DriverPhase::Active(attempt) => {
                    // T7d: always poll the transport BEFORE checking the heartbeat timer so any
                    // messages already buffered by HTTP/2 are read before timing out.
                    match Pin::new(&mut attempt.stream).poll_next(cx) {
                        Poll::Ready(Some(Ok(frame))) => {
                            attempt.record_chunk_progress(heartbeat_deadline);
                            let made_progress = attempt.made_progress;
                            let batch = ReadBatch::from_proto(frame.msg);
                            let reconnect_advised = frame.reconnect_advised;
                            match self.handle_decoded_batch(batch, reconnect_advised, made_progress)
                            {
                                BatchStep::Yield(decoded) => return Poll::Ready(Some(Ok(decoded))),
                                BatchStep::Continue => {}
                                BatchStep::Done(done) => return Poll::Ready(done),
                            }
                        }
                        Poll::Ready(Some(Err(err))) => {
                            let made_progress = attempt.made_progress;
                            let snapshot = attempt.snapshot;
                            *phase = DriverPhase::Idle;
                            *heartbeat_deadline = None;
                            if let DriverStep::Done(result) =
                                self.handle_stream_error(err, made_progress, snapshot)
                            {
                                return Poll::Ready(result);
                            }
                        }
                        Poll::Ready(None) => {
                            let fetched_record = attempt.fetched_record;
                            *phase = DriverPhase::Idle;
                            *heartbeat_deadline = None;
                            if let DriverStep::Done(result) = self.handle_eof(fetched_record) {
                                return Poll::Ready(result);
                            }
                        }
                        Poll::Pending => {
                            // Forward transport byte progress on an incomplete (e.g.
                            // flow-controlled) frame counts as liveness so resuming a parked
                            // session mid-frame does not falsely time out (`T7d`).
                            attempt.record_chunk_progress(heartbeat_deadline);
                            let deadline = *heartbeat_deadline
                                .get_or_insert_with(|| Instant::now() + HEARTBEAT_TIMEOUT);
                            match sleep.poll_until(deadline, cx) {
                                Poll::Pending => return self.pending_or_abort(cx),
                                Poll::Ready(()) => {
                                    let made_progress = attempt.made_progress;
                                    let snapshot = attempt.snapshot;
                                    attempt.stream.retire_connection();
                                    *phase = DriverPhase::Idle;
                                    *heartbeat_deadline = None;
                                    let err =
                                        ReadSessionError::Timeout(TimeoutError::new_with_context(
                                            "heartbeat timeout",
                                            self.context.clone(),
                                        ));
                                    if let DriverStep::Done(result) =
                                        self.handle_stream_error(err, made_progress, snapshot)
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
        self.state.update(|inner, wake| {
            if inner.closed.is_none() {
                if self.state.shutdown.is_cancelled() {
                    inner.abort_for_client_close(wake);
                } else {
                    inner.closed = Some(TerminalClose::Clean);
                    inner.on_ended(None, wake);
                }
            } else {
                inner.on_ended(None, wake);
            }
        });
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
    current_batch: std::vec::IntoIter<SequencedRecord>,
    /// Transition to apply once the final buffered record of `current_batch` is delivered.
    after_current_batch: AfterBatch,
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
            after_current_batch: AfterBatch::None,
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

    /// Return the latest stream tail observed from a decoded server message as of the last pull.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether the session is open with an active request whose most recent decoded
    /// message (as of the last pull) reported a tail equal to [`next_seq_num`](Self::next_seq_num).
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

        if let Some(record) = this.current_batch.next() {
            let after_batch = if this.current_batch.len() == 0 {
                std::mem::replace(&mut this.after_current_batch, AfterBatch::None)
            } else {
                AfterBatch::None
            };
            if let Err(outcome) = this
                .core
                .commit_record_delivered(record.seq_num, after_batch)
            {
                this.current_batch = Vec::new().into_iter();
                this.after_current_batch = AfterBatch::None;
                return Poll::Ready(outcome.map(Err));
            }
            return Poll::Ready(Some(Ok(record)));
        }

        match this.core.poll_next_batch(cx) {
            Poll::Ready(Some(Ok(decoded))) => {
                let tail = decoded.batch.tail;
                let mut iter = decoded.batch.records.into_iter();
                let record = iter
                    .next()
                    .expect("poll_next_batch only yields non-empty batches");
                let is_last = iter.len() == 0;
                let after_this = if is_last {
                    decoded.after_batch
                } else {
                    AfterBatch::None
                };
                if let Err(outcome) =
                    this.core
                        .commit_batch_delivered(tail, record.seq_num, after_this)
                {
                    return Poll::Ready(outcome.map(Err));
                }
                this.current_batch = iter;
                this.after_current_batch = if is_last {
                    AfterBatch::None
                } else {
                    decoded.after_batch
                };
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

    /// Return the latest stream tail observed from a decoded server message as of the last pull.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether the session is open with an active request whose most recent decoded
    /// message (as of the last pull) reported a tail equal to [`next_seq_num`](Self::next_seq_num).
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
        match this.core.poll_next_batch(cx) {
            Poll::Ready(Some(Ok(decoded))) => {
                let tail = decoded.batch.tail;
                let last_seq = decoded
                    .batch
                    .records
                    .last()
                    .expect("poll_next_batch only yields non-empty batches")
                    .seq_num;
                if let Err(outcome) =
                    this.core
                        .commit_batch_delivered(tail, last_seq, decoded.after_batch)
                {
                    return Poll::Ready(outcome.map(Err));
                }
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
        self.core.is_terminated()
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
/// `wait` receiving `416` whose tail has not regressed below the `seq_num` sent on that request).
fn resumed_unwritten_stop_tail(
    snapshot: AttemptSnapshot,
    err: &ReadSessionError,
) -> Option<Option<StreamPosition>> {
    if !snapshot.was_resumed || !snapshot.no_wait_remaining {
        return None;
    }
    let tail = range_not_satisfiable_tail(err)?;
    if let (Some(tail_pos), Some(sent_seq)) = (tail, snapshot.sent_seq_num)
        && tail_pos.seq_num < sent_seq
    {
        return None;
    }
    Some(tail)
}

fn validate_read_batch_order(
    batch: &ReadBatch,
    last_fetched_seq: Option<u64>,
    min_next_seq_num: Option<u64>,
    context: &ErrorContext,
    attempts: u32,
) -> Result<Option<u64>, ReadSessionError> {
    let mut prev = last_fetched_seq;
    for record in &batch.records {
        if let Some(min_seq) = min_next_seq_num
            && record.seq_num < min_seq
        {
            return Err(ReadSessionError::Protocol(ProtocolError::new_with_context(
                format!(
                    "read batch contained seq_num {} below resolved cursor {}",
                    record.seq_num, min_seq
                ),
                context.clone().with_attempts(attempts),
            )));
        }
        if let Some(prev_seq) = prev
            && record.seq_num <= prev_seq
        {
            return Err(ReadSessionError::Protocol(ProtocolError::new_with_context(
                format!(
                    "read batch contained out-of-order or duplicate seq_num {} after {}",
                    record.seq_num, prev_seq
                ),
                context.clone().with_attempts(attempts),
            )));
        }
        if record.seq_num.checked_add(1).is_none() {
            return Err(ReadSessionError::Protocol(ProtocolError::new_with_context(
                "read batch record seq_num u64::MAX has no representable successor",
                context.clone().with_attempts(attempts),
            )));
        }
        prev = Some(record.seq_num);
    }
    if let (Some(last_record), Some(tail)) = (batch.records.last(), batch.tail)
        && tail.seq_num <= last_record.seq_num
    {
        return Err(ReadSessionError::Protocol(ProtocolError::new_with_context(
            format!(
                "read batch tail seq_num {} is not greater than last record seq_num {}",
                tail.seq_num, last_record.seq_num
            ),
            context.clone().with_attempts(attempts),
        )));
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
/// resume strictly by monotonic `seq_num` without re-evaluating `timestamp`, `tail_offset`, or
/// `clamp`.
fn update_resume_start(start: &mut ReadStart, batch: &ReadBatch, had_response: bool) {
    if let Some(candidate) = next_seq_num_after_batch(batch) {
        let seq_num = if had_response || start.clamp != Some(true) {
            start.seq_num.map_or(candidate, |prev| prev.max(candidate))
        } else {
            candidate
        };
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
            .with_retry(RetryConfig::new().with_max_attempts(1));
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
        let snapshot = AttemptSnapshot {
            was_resumed: false,
            sent_seq_num: session.core.start.seq_num,
            no_wait_remaining: has_no_wait_remaining(&session.core.end),
        };
        session.core.transport_mut().phase = DriverPhase::Active(ActiveAttempt {
            stream,
            snapshot,
            made_progress: false,
            fetched_record: false,
            last_chunks_received: 0,
        });
        let state = session.state();
        let shutdown = session.core.state.shutdown.clone();
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
        assert!(session.core.client.is_none());
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
            ReadInput::new()
                .with_start(crate::types::ReadStart::SeqNum(0))
                .with_count(2),
        );
        shutdown.cancel();
        assert!(matches!(
            state.caught_up().await,
            Err(ReadSessionError::Aborted(_))
        ));
        assert!(matches!(
            session.core.finish_clean_end_now(None),
            Some(Err(ReadSessionError::Aborted(_)))
        ));
        assert!(session.next().await.is_none());

        // 2. Terminal error cannot overwrite an Aborted close already committed concurrently.
        let (mut session, _tx, state, shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );
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
            session.core.finish_terminal_error(timeout_err),
            Some(Err(ReadSessionError::Aborted(_)))
        ));
        assert!(session.next().await.is_none());

        // 3. Record/batch delivery rejects and leaves next_seq_num untouched once aborted.
        let (mut session, _tx, state, shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );
        shutdown.cancel();
        assert!(matches!(
            session.core.commit_record_delivered(0, AfterBatch::None),
            Err(Some(ReadSessionError::Aborted(_)))
        ));
        assert!(matches!(
            session
                .core
                .commit_batch_delivered(Some(position(1)), 0, AfterBatch::None),
            Err(Some(ReadSessionError::Aborted(_)))
        ));
        assert_eq!(state.next_seq_num(), Some(0));
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

    fn test_batch_session_with_active_stream(
        input: ReadInput,
    ) -> (
        ReadBatchSession,
        FrameTx,
        ReadSessionState,
        CancellationToken,
    ) {
        let config = S2Config::new("test-token")
            .with_endpoints(S2Endpoints::for_endpoint("http://127.0.0.1:1").unwrap())
            .with_retry(RetryConfig::new().with_max_attempts(1));
        let base = BaseClient::init(&config).unwrap();
        let basin = BasinClient::init(
            "test-basin".parse().unwrap(),
            &config.endpoints,
            base.clone(),
        );
        let mut session = ReadBatchSession::open(
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
        let snapshot = AttemptSnapshot {
            was_resumed: false,
            sent_seq_num: session.core.start.seq_num,
            no_wait_remaining: has_no_wait_remaining(&session.core.end),
        };
        session.core.transport_mut().phase = DriverPhase::Active(ActiveAttempt {
            stream,
            snapshot,
            made_progress: false,
            fetched_record: false,
            last_chunks_received: 0,
        });
        let state = session.state();
        let shutdown = session.core.state.shutdown.clone();
        (session, tx, state, shutdown)
    }

    #[test]
    fn validate_read_batch_order_rejects_duplicate_and_backward_seq_nums() {
        let ctx = ErrorContext::stream("read_session", "b", "s", true);
        let b1 = batch(vec![record(0), record(2)], None);
        let last = validate_read_batch_order(&b1, None, None, &ctx, 1).unwrap();
        assert_eq!(last, Some(2));

        let dup = batch(vec![record(2)], None);
        assert!(matches!(
            validate_read_batch_order(&dup, last, Some(3), &ctx, 1),
            Err(ReadSessionError::Protocol(_))
        ));

        let backward_within = batch(vec![record(5), record(4)], None);
        assert!(matches!(
            validate_read_batch_order(&backward_within, last, Some(3), &ctx, 2),
            Err(ReadSessionError::Protocol(err)) if err.to_string().contains("after 2 attempts")
        ));
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
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );
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
        let (session, _tx, state, _shutdown) = test_session_with_active_stream(ReadInput::new());
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
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(7)),
        );
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
        assert!(session.core.client.is_none());
        assert_eq!(state.next_seq_num(), Some(7));
        assert_eq!(state.last_observed_tail(), None);
        assert!(!state.is_caught_up());
        assert!(matches!(cu.await, Err(ReadSessionError::Protocol(_))));
        assert!(session.next().await.is_none());

        // Record view also rejects an out-of-order batch `[7, 8, 5]` with a tail atomically
        // without delivering `[7, 8]` or recording the corrupt batch's tail.
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(7)),
        );
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
            test_batch_session_with_active_stream(
                ReadInput::new().with_start(crate::types::ReadStart::SeqNum(7)),
            );
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
        assert!(batch_sess.core.client.is_none());
        assert_eq!(batch_state.next_seq_num(), Some(7));
        assert_eq!(batch_state.last_observed_tail(), None);
        assert!(batch_sess.next().await.is_none());

        // Both views atomically reject a non-empty batch whose `tail.seq_num <=
        // last_record.seq_num` (such as `[0, 1, 2]` with `tail = 1` or `tail = 2`) without
        // mid-batch catch-up (`R6`).
        for bad_tail in [1, 2] {
            let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
                ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
            );
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
                test_batch_session_with_active_stream(
                    ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
                );
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

    // spec: r1 R7c, T5a
    #[tokio::test]
    async fn empty_frame_without_tail_clears_is_caught_up_without_losing_observed_tail() {
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );
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
        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);

        assert!(!state.is_caught_up());
        assert_eq!(state.next_seq_num(), Some(1));
        assert_eq!(state.last_observed_tail(), Some(position(1)));
    }

    // spec: r1 R7a, R11b
    #[tokio::test]
    async fn regressing_heartbeat_does_not_rewind_resume_cursor_or_public_checkpoint() {
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::TailOffset(0)),
        );
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

        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);

        assert_eq!(state.next_seq_num(), Some(12));
        assert_eq!(session.core.start.seq_num, Some(12));
        assert_eq!(state.last_observed_tail(), Some(position(12)));
        assert!(!state.is_caught_up());

        // Even without a reconnect, a subsequent record below the resolved cursor 12 fails with
        // ProtocolError rather than rewinding next_seq_num.
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[8], Some(9)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::Protocol(_)))
        ));
        assert!(session.core.client.is_none());
        assert_eq!(state.next_seq_num(), Some(12));
    }

    // spec: r1 T7d, T5a
    #[tokio::test(start_paused = true)]
    async fn empty_frame_with_chunk_progress_resets_heartbeat_timer_without_resetting_retry_budget()
    {
        use std::sync::atomic::{AtomicU64, Ordering};

        let config = S2Config::new("test-token")
            .with_endpoints(S2Endpoints::for_endpoint("http://127.0.0.1:1").unwrap())
            .with_retry(RetryConfig::new().with_max_attempts(2));
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
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        );
        // Simulate one failed attempt already consumed so retry budget is on attempt 2.
        assert!(session.core.retry_backoff.next().is_some());
        assert_eq!(session.core.retry_backoff.attempt_number(), 2);

        let (tx, mut rx) = mpsc::unbounded_channel();
        let chunks = Arc::new(AtomicU64::new(0));
        let stream = Streaming::from_stream_with_chunks_for_test(
            futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx)),
            chunks.clone(),
        );
        let snapshot = AttemptSnapshot {
            was_resumed: false,
            sent_seq_num: session.core.start.seq_num,
            no_wait_remaining: has_no_wait_remaining(&session.core.end),
        };
        session.core.transport_mut().phase = DriverPhase::Active(ActiveAttempt {
            stream,
            snapshot,
            made_progress: false,
            fetched_record: false,
            last_chunks_received: 0,
        });

        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());

        // Advance 15s, then deliver an empty frame whose transport chunk incremented `chunks`.
        tokio::time::advance(Duration::from_secs(15)).await;
        assert!(poll!(next.as_mut()).is_pending());
        chunks.fetch_add(1, Ordering::Relaxed);
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[], None),
            reconnect_advised: false,
        }))
        .unwrap();
        assert!(poll!(next.as_mut()).is_pending());

        // Advance another 15s (30s total, but only 15s since bytes arrived) -> must NOT time out!
        tokio::time::advance(Duration::from_secs(15)).await;
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);

        // Retry budget was NOT reset by the empty frame (`T5a`).
        assert_eq!(session.core.retry_backoff.attempt_number(), 2);
    }

    // spec: r1 R11d, T9
    #[tokio::test]
    async fn initial_request_terminal_416_after_record_surfaces_read_unwritten_error() {
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new()
                .with_start(crate::types::ReadStart::SeqNum(0))
                .with_count(10),
        );

        // Initial request delivers record 0 (setting has_received_response=true and advancing
        // self.start to 1), then emits terminal 416 on the SAME initial request -> MUST NOT be
        // misclassified as a resumed R11d clean stop!
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
        assert!(session.next().await.is_none());
    }

    // spec: r1 C12, R9a, R9c
    #[tokio::test]
    async fn client_is_released_immediately_on_final_ok_when_close_locks_in() {
        // 1. Uncaught-up count=1 (ReadSession): client released immediately upon returning record
        //    0.
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new()
                .with_start(crate::types::ReadStart::SeqNum(0))
                .with_count(1),
        );
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(5)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert!(session.core.client.is_none());
        assert!(!state.is_caught_up());
        assert!(session.next().await.is_none());

        // 2. Caught-up count=1 (ReadSession): client released immediately, while `is_caught_up`
        //    stays true until trailing `None` (`R7c`).
        let (mut session, tx, state, _shutdown) = test_session_with_active_stream(
            ReadInput::new()
                .with_start(crate::types::ReadStart::SeqNum(0))
                .with_count(1),
        );
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[0], Some(1)),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
        assert!(session.core.client.is_none());
        assert!(state.is_caught_up());
        assert!(session.next().await.is_none());
        assert!(!state.is_caught_up());

        // 3. ReadBatchSession count=1: client released immediately on returning the final batch.
        let (mut batch_sess, batch_tx, _state, _shutdown) = test_batch_session_with_active_stream(
            ReadInput::new()
                .with_start(crate::types::ReadStart::SeqNum(0))
                .with_count(1),
        );
        batch_tx
            .send(Ok(S2sFrame {
                msg: proto_batch(&[0], Some(5)),
                reconnect_advised: false,
            }))
            .unwrap();
        assert_eq!(batch_sess.next().await.unwrap().unwrap().records.len(), 1);
        assert!(batch_sess.core.client.is_none());
        assert!(batch_sess.next().await.is_none());
    }

    // spec: r1 T7d
    #[tokio::test(start_paused = true)]
    async fn t7d_deterministic_buffered_frame_partial_chunk_and_fragmented_wait() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let make_session = || {
            let config = S2Config::new("test-token")
                .with_endpoints(S2Endpoints::for_endpoint("http://127.0.0.1:1").unwrap())
                .with_retry(RetryConfig::new().with_max_attempts(1));
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
                ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
                ReadSessionConfig::default(),
            );
            let (tx, mut rx) = mpsc::unbounded_channel();
            let chunks = Arc::new(AtomicU64::new(0));
            let stream = Streaming::from_stream_with_chunks_for_test(
                futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx)),
                chunks.clone(),
            );
            let snapshot = AttemptSnapshot {
                was_resumed: false,
                sent_seq_num: Some(0),
                no_wait_remaining: false,
            };
            session.core.transport_mut().phase = DriverPhase::Active(ActiveAttempt {
                stream,
                snapshot,
                made_progress: false,
                fetched_record: false,
                last_chunks_received: 0,
            });
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
    async fn client_close_after_caught_up_r9a_clears_is_caught_up_and_advised_batch_resolves_caught_up()
     {
        // S1: After caught-up R9a lock-in, S2::close() ends caught-up observation immediately
        // while keeping the clean outcome (`None` on iteration, SessionClosedError on new
        // caught_up(), prior resolved caught_up() retained).
        let (mut session, tx, state, shutdown) = test_session_with_active_stream(
            ReadInput::new()
                .with_start(crate::types::ReadStart::SeqNum(0))
                .with_count(1),
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
        assert!(!state.is_caught_up());
        assert_eq!(prior_cu.await.unwrap(), position(1));
        assert!(matches!(
            state.caught_up().await,
            Err(ReadSessionError::SessionClosed(_))
        ));
        assert!(session.next().await.is_none());

        // T6a / T10 / R6a: A batch carrying `reconnect_advised` that reaches `tail` resolves
        // pending `caught_up()` uniformly across batch view and record view (regardless of batch
        // size), then transitions to `Connecting` so `is_caught_up()` is false.
        let (mut batch_sess, batch_tx, batch_state, _shutdown) =
            test_batch_session_with_active_stream(
                ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
            );
        let pending_cu = batch_state.caught_up();
        batch_tx
            .send(Ok(S2sFrame {
                msg: proto_batch(&[0, 1], Some(2)),
                reconnect_advised: true,
            }))
            .unwrap();
        assert_eq!(batch_sess.next().await.unwrap().unwrap().records.len(), 2);
        assert_eq!(pending_cu.await.unwrap(), position(2));
        assert!(!batch_state.is_caught_up());

        // Record view with a 2-record advised batch `[0, 1]` and tail `2`: record 0 does not yet
        // catch up; record 1 resolves pending `caught_up()` to `2` and then drops `is_caught_up`.
        let (mut rec_sess, rec_tx, rec_state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );
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
        assert!(!rec_state.is_caught_up());
        let mut post_handover_cu = rec_state.caught_up();
        assert!(poll!(Pin::new(&mut post_handover_cu)).is_pending());

        // Record view with a 1-record advised batch `[0]` and tail `1` behaves identically.
        let (mut one_sess, one_tx, one_state, _shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );
        let pending_cu = one_state.caught_up();
        one_tx
            .send(Ok(S2sFrame {
                msg: proto_batch(&[0], Some(1)),
                reconnect_advised: true,
            }))
            .unwrap();
        assert_eq!(one_sess.next().await.unwrap().unwrap().seq_num, 0);
        assert_eq!(pending_cu.await.unwrap(), position(1));
        assert!(!one_state.is_caught_up());
    }

    // spec: r1 T7d
    #[tokio::test(start_paused = true)]
    async fn reusable_sleep_reuses_single_allocation_across_heartbeat_and_backoff_and_clears_on_close()
     {
        let config = S2Config::new("test-token")
            .with_endpoints(S2Endpoints::for_endpoint("http://127.0.0.1:1").unwrap())
            .with_retry(
                RetryConfig::new()
                    .with_max_attempts(2)
                    .with_min_base_delay(Duration::from_millis(200))
                    .with_max_base_delay(Duration::from_millis(200)),
            );
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
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stream = Streaming::from_stream_for_test(futures_util::stream::poll_fn(move |cx| {
            rx.poll_recv(cx)
        }));
        let snapshot = AttemptSnapshot {
            was_resumed: false,
            sent_seq_num: Some(0),
            no_wait_remaining: false,
        };
        session.core.transport_mut().phase = DriverPhase::Active(ActiveAttempt {
            stream,
            snapshot,
            made_progress: false,
            fetched_record: false,
            last_chunks_received: 0,
        });

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
        assert!(session.core.transport_mut().heartbeat_deadline.is_none());
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
            .as_ref()
            .get_ref() as *const Sleep as usize;
        assert_eq!(backoff_addr, sleep_addr);

        // Closing the session clears and drops the Sleep box immediately.
        session.core.state.shutdown.cancel();
        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::Aborted(_)))
        ));
        assert!(session.core.transport_mut().sleep.sleep.is_none());

        // Extreme retry backoff (`Duration::MAX`) must not panic when computing the deadline,
        // and still aborts cleanly on client close.
        let max_delay_cfg = S2Config::new("test-token")
            .with_endpoints(S2Endpoints::for_endpoint("http://127.0.0.1:1").unwrap())
            .with_retry(
                RetryConfig::new()
                    .with_max_attempts(2)
                    .with_min_base_delay(Duration::MAX)
                    .with_max_base_delay(Duration::MAX),
            );
        let max_base = BaseClient::init(&max_delay_cfg).unwrap();
        let max_basin = BasinClient::init(
            "test-basin".parse().unwrap(),
            &max_delay_cfg.endpoints,
            max_base,
        );
        let mut max_session = ReadSession::open(
            max_basin,
            "test-stream".parse().unwrap(),
            StreamHeaders::default(),
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        );
        let (max_tx, mut max_rx) = mpsc::unbounded_channel();
        let max_stream =
            Streaming::from_stream_for_test(futures_util::stream::poll_fn(move |cx| {
                max_rx.poll_recv(cx)
            }));
        max_session.core.transport_mut().phase = DriverPhase::Active(ActiveAttempt {
            stream: max_stream,
            snapshot: AttemptSnapshot {
                was_resumed: false,
                sent_seq_num: Some(0),
                no_wait_remaining: false,
            },
            made_progress: false,
            fetched_record: false,
            last_chunks_received: 0,
        });
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
