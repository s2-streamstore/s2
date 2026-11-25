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
use http::StatusCode;
use s2_api::v1::stream::{ReadEnd, ReadStart, proto};
use tokio::{
    sync::{Notify, futures::OwnedNotified},
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

struct CaughtUpSignal {
    result: StdMutex<Option<CaughtUpResult>>,
    notify: Arc<Notify>,
}

impl CaughtUpSignal {
    fn new() -> Self {
        Self {
            result: StdMutex::new(None),
            notify: Arc::new(Notify::new()),
        }
    }

    fn get(&self) -> Option<CaughtUpResult> {
        self.result.lock().unwrap().clone()
    }

    /// Store `result` if unset, returning `Some(notify)` so callers wake waiters *after* dropping
    /// the outer `ReadSessionState` lock (preventing deadlocks if a custom waker inspects state).
    #[must_use]
    fn set_result(&self, result: CaughtUpResult) -> Option<Arc<Notify>> {
        let mut guard = self.result.lock().unwrap();
        if guard.is_none() {
            *guard = Some(result);
            Some(self.notify.clone())
        } else {
            None
        }
    }
}

#[derive(Default)]
#[must_use = "pending catch-up wakes must be dispatched after releasing the state lock"]
struct PendingWakes {
    first: Option<Arc<Notify>>,
    second: Option<Arc<Notify>>,
}

impl PendingWakes {
    fn push(&mut self, notify: Option<Arc<Notify>>) {
        let Some(notify) = notify else {
            return;
        };
        if self.first.is_none() {
            self.first = Some(notify);
        } else {
            debug_assert!(self.second.is_none());
            self.second = Some(notify);
        }
    }

    fn wake(self) {
        if let Some(notify) = self.first {
            notify.notify_waiters();
        }
        if let Some(notify) = self.second {
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
                // Always check the catch-up signal first so an already-resolved tail (`R8a`) or
                // already-locked close reason (`R9`) is never overwritten by a later client
                // shutdown.
                if let Some(result) = signal.get() {
                    this.inner = CaughtUpFuture::Ready(result.clone());
                    *this
                        .waits
                        .get_mut()
                        .expect("CaughtUp waits mutex is never locked") = CaughtUpWaits::default();
                    this.done = true;
                    return Poll::Ready(result);
                }

                let waits = this
                    .waits
                    .get_mut()
                    .expect("CaughtUp waits mutex is never locked");

                // Register `cx` with the signal before re-checking `signal.get()` so a concurrent
                // `resolve()` cannot slip between the check and registration.
                let notified = waits
                    .notified
                    .get_or_insert_with(|| Box::pin(signal.notify.clone().notified_owned()));
                let _ = notified.as_mut().poll(cx);

                if let Some(result) = signal.get() {
                    this.inner = CaughtUpFuture::Ready(result.clone());
                    *waits = CaughtUpWaits::default();
                    this.done = true;
                    return Poll::Ready(result);
                }

                // R8d / R9d / C12: observe client shutdown immediately even when no task is
                // polling the pull-driven session.
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
                let mut wakes = PendingWakes::default();
                {
                    let mut inner = this.state.inner.lock().unwrap();
                    if inner.closed.is_none() {
                        let err =
                            AbortedError::new_with_context("client closed", inner.context.clone());
                        inner.on_aborted(err, &mut wakes);
                    }
                }
                wakes.wake();

                if let Some(result) = signal.get() {
                    this.inner = CaughtUpFuture::Ready(result.clone());
                    *waits = CaughtUpWaits::default();
                    this.done = true;
                    Poll::Ready(result)
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
    Pending(Arc<CaughtUpSignal>),
    CaughtUp(StreamPosition),
    Ended(ReadSessionError),
}

impl CatchUpSlot {
    fn pending() -> Self {
        Self::Pending(Arc::new(CaughtUpSignal::new()))
    }

    fn is_caught_up(&self) -> bool {
        matches!(self, Self::CaughtUp(_))
    }

    fn future(&self) -> CaughtUpFuture {
        match self {
            Self::Pending(signal) => CaughtUpFuture::Pending(signal.clone()),
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

    fn recompute_caught_up(&mut self, wakes: &mut PendingWakes) {
        if self.phase == RequestPhase::Ended {
            return;
        }
        match self.compute_caught_up_tail() {
            Some(tail) => {
                if !matches!(self.catch_up, CatchUpSlot::CaughtUp(prev) if prev == tail) {
                    let prev = std::mem::replace(&mut self.catch_up, CatchUpSlot::CaughtUp(tail));
                    if let CatchUpSlot::Pending(signal) = prev {
                        wakes.push(signal.set_result(Ok(tail)));
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

    fn apply_close(&mut self, close: TerminalClose, wakes: &mut PendingWakes) {
        if self.closed.is_some() {
            return;
        }
        match close {
            TerminalClose::Clean => {
                self.closed = Some(TerminalClose::Clean);
                if !self.catch_up.is_caught_up() {
                    self.on_ended(None, wakes);
                }
            }
            TerminalClose::Error(err) => {
                self.closed = Some(TerminalClose::Error(err.clone()));
                self.on_ended(Some(err), wakes);
            }
        }
    }

    /// Record a freshly decoded non-empty batch together with immediate delivery of its first
    /// record (record view) or entire batch (batch view).
    fn on_batch_decoded_and_delivered(
        &mut self,
        tail: Option<StreamPosition>,
        delivered_last_seq: u64,
        disconnected: bool,
        lock_in_close: Option<TerminalClose>,
        wakes: &mut PendingWakes,
    ) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        if let Some(tail) = tail {
            self.update_observed_tail(tail);
        }
        self.phase = if disconnected {
            RequestPhase::Connecting
        } else {
            RequestPhase::Open { latest_tail: tail }
        };
        self.next_seq_num = Some(delivered_last_seq.saturating_add(1));
        self.recompute_caught_up(wakes);
        if let Some(close) = lock_in_close {
            self.apply_close(close, wakes);
        }
    }

    /// Record delivery of a subsequent record from the current batch.
    fn on_record_delivered(
        &mut self,
        seq_num: u64,
        lock_in_close: Option<TerminalClose>,
        wakes: &mut PendingWakes,
    ) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        self.next_seq_num = Some(seq_num.saturating_add(1));
        self.recompute_caught_up(wakes);
        if let Some(close) = lock_in_close {
            self.apply_close(close, wakes);
        }
    }

    /// Record a decoded heartbeat (`records` empty, `tail` present). Because reading is
    /// pull-driven (`R6b`), no records remain undelivered when a heartbeat is decoded.
    fn on_heartbeat(
        &mut self,
        tail: StreamPosition,
        disconnected_for_advice: bool,
        wakes: &mut PendingWakes,
    ) {
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
        self.recompute_caught_up(wakes);
        if disconnected_for_advice {
            self.phase = RequestPhase::Connecting;
            self.recompute_caught_up(wakes);
        }
    }

    /// Record an empty regular message carrying neither records nor a tail (`R7c`): clears the
    /// active request's latest tail so `is_caught_up()` reflects the most recent decoded message,
    /// while preserving `last_observed_tail` and `next_seq_num`.
    fn on_empty_frame_without_tail(&mut self, wakes: &mut PendingWakes) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        if matches!(self.phase, RequestPhase::Open { .. }) {
            self.phase = RequestPhase::Open { latest_tail: None };
            self.recompute_caught_up(wakes);
        }
    }

    fn on_disconnected(&mut self, wakes: &mut PendingWakes) {
        if self.phase == RequestPhase::Ended || self.closed.is_some() {
            return;
        }
        self.phase = RequestPhase::Connecting;
        self.recompute_caught_up(wakes);
    }

    /// Finalize a clean stop when iteration is returning end-of-stream (`R9a`, `R11d`).
    fn on_clean_end_now(&mut self, tail: Option<StreamPosition>, wakes: &mut PendingWakes) {
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
                self.recompute_caught_up(wakes);
            }
            self.closed = Some(TerminalClose::Clean);
        }
        self.on_ended(None, wakes);
    }

    /// Finalize a terminal failure (`R9c`).
    fn on_terminal_error(&mut self, err: ReadSessionError, wakes: &mut PendingWakes) {
        if self.closed.is_some() || self.phase == RequestPhase::Ended {
            return;
        }
        self.closed = Some(TerminalClose::Error(err.clone()));
        self.on_ended(Some(err), wakes);
    }

    fn on_aborted(&mut self, err: AbortedError, wakes: &mut PendingWakes) -> bool {
        if self.closed.is_some() || self.phase == RequestPhase::Ended {
            return false;
        }
        let err = ReadSessionError::Aborted(err);
        self.closed = Some(TerminalClose::Error(err.clone()));
        self.on_ended(Some(err), wakes);
        true
    }

    fn lock_in_abort_if_cancelled(
        &mut self,
        shutdown: &CancellationToken,
        wakes: &mut PendingWakes,
    ) -> Option<TerminalClose> {
        if self.closed.is_none() && shutdown.is_cancelled() {
            let err = AbortedError::new_with_context("client closed", self.context.clone());
            self.on_aborted(err, wakes);
        }
        self.closed.clone()
    }

    fn on_ended(&mut self, error: Option<ReadSessionError>, wakes: &mut PendingWakes) {
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
        if let CatchUpSlot::Pending(signal) = prev {
            wakes.push(signal.set_result(Err(terminal_err)));
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
        let mut wakes = PendingWakes::default();
        let future = {
            let mut inner = self.inner.lock().unwrap();
            if self.shutdown.is_cancelled() && inner.closed.is_none() {
                let err = AbortedError::new_with_context("client closed", inner.context.clone());
                inner.on_aborted(err, &mut wakes);
            }
            inner.catch_up.future()
        };
        wakes.wake();
        CaughtUp {
            inner: future,
            state: self.clone(),
            waits: StdMutex::new(CaughtUpWaits::default()),
            done: false,
        }
    }

    fn closed_or_abort(&self) -> Option<TerminalClose> {
        let mut wakes = PendingWakes::default();
        let closed = {
            let mut inner = self.inner.lock().unwrap();
            inner.lock_in_abort_if_cancelled(&self.shutdown, &mut wakes)
        };
        wakes.wake();
        closed
    }

    fn on_batch_decoded_and_delivered(
        &self,
        tail: Option<StreamPosition>,
        delivered_last_seq: u64,
        disconnected: bool,
        lock_in_close: Option<TerminalClose>,
    ) -> Result<(), TerminalClose> {
        let mut wakes = PendingWakes::default();
        let res = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(closed) = inner.lock_in_abort_if_cancelled(&self.shutdown, &mut wakes) {
                Err(closed)
            } else {
                inner.on_batch_decoded_and_delivered(
                    tail,
                    delivered_last_seq,
                    disconnected,
                    lock_in_close,
                    &mut wakes,
                );
                Ok(())
            }
        };
        wakes.wake();
        res
    }

    fn on_record_delivered(
        &self,
        seq_num: u64,
        lock_in_close: Option<TerminalClose>,
    ) -> Result<(), TerminalClose> {
        let mut wakes = PendingWakes::default();
        let res = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(closed) = inner.lock_in_abort_if_cancelled(&self.shutdown, &mut wakes) {
                Err(closed)
            } else {
                inner.on_record_delivered(seq_num, lock_in_close, &mut wakes);
                Ok(())
            }
        };
        wakes.wake();
        res
    }

    fn on_heartbeat(
        &self,
        tail: StreamPosition,
        disconnected_for_advice: bool,
    ) -> Result<(), TerminalClose> {
        let mut wakes = PendingWakes::default();
        let res = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(closed) = inner.lock_in_abort_if_cancelled(&self.shutdown, &mut wakes) {
                Err(closed)
            } else {
                inner.on_heartbeat(tail, disconnected_for_advice, &mut wakes);
                Ok(())
            }
        };
        wakes.wake();
        res
    }

    fn on_empty_frame_without_tail(&self) -> Result<(), TerminalClose> {
        let mut wakes = PendingWakes::default();
        let res = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(closed) = inner.lock_in_abort_if_cancelled(&self.shutdown, &mut wakes) {
                Err(closed)
            } else {
                inner.on_empty_frame_without_tail(&mut wakes);
                Ok(())
            }
        };
        wakes.wake();
        res
    }

    fn on_disconnected(&self) {
        let mut wakes = PendingWakes::default();
        {
            self.inner.lock().unwrap().on_disconnected(&mut wakes);
        }
        wakes.wake();
    }

    fn on_clean_end_now(&self, tail: Option<StreamPosition>) -> TerminalClose {
        let mut wakes = PendingWakes::default();
        let closed = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(closed) = inner.lock_in_abort_if_cancelled(&self.shutdown, &mut wakes) {
                inner.on_ended(
                    match &closed {
                        TerminalClose::Clean => None,
                        TerminalClose::Error(err) => Some(err.clone()),
                    },
                    &mut wakes,
                );
                closed
            } else {
                inner.on_clean_end_now(tail, &mut wakes);
                TerminalClose::Clean
            }
        };
        wakes.wake();
        closed
    }

    fn on_terminal_error(&self, err: ReadSessionError) -> TerminalClose {
        let mut wakes = PendingWakes::default();
        let closed = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(closed) = inner.lock_in_abort_if_cancelled(&self.shutdown, &mut wakes) {
                inner.on_ended(
                    match &closed {
                        TerminalClose::Clean => None,
                        TerminalClose::Error(err) => Some(err.clone()),
                    },
                    &mut wakes,
                );
                closed
            } else {
                inner.on_terminal_error(err.clone(), &mut wakes);
                TerminalClose::Error(err)
            }
        };
        wakes.wake();
        closed
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
    /// Close reason to lock in once the final record of `batch` has been delivered (`R9a` when
    /// remaining `count`/`bytes` hit 0, or `R9c` after a valid prefix before a mid-batch
    /// `ProtocolError` in record iteration).
    close_after_batch: Option<TerminalClose>,
    disconnected: bool,
}

enum BatchStep {
    Yield(DecodedBatch),
    Continue,
    Done(Option<Result<DecodedBatch, ReadSessionError>>),
}

struct PollTransport {
    phase: DriverPhase,
    heartbeat: HeartbeatTimer,
    shutdown_wait: Option<Pin<Box<WaitForCancellationFutureOwned>>>,
}

impl PollTransport {
    fn new() -> Self {
        Self {
            phase: DriverPhase::Idle,
            heartbeat: HeartbeatTimer::new(),
            shutdown_wait: None,
        }
    }

    fn reset_to_idle(&mut self) {
        self.phase = DriverPhase::Idle;
        self.heartbeat.reset();
        self.shutdown_wait = None;
    }
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
    deliver_valid_prefix: bool,
    span: Span,
    state: ReadSessionState,
    shutdown: CancellationToken,
    context: ErrorContext,
    retry_backoff: RetryBackoff,
    advised_reconnects: AdvisedReconnects,
    idle_since: Option<Instant>,
    has_received_response: bool,
    last_fetched_seq: Option<u64>,
    /// Non-`Sync` pull-driven transport state wrapped in `StdMutex` solely to keep `ReadSession`
    /// and `ReadBatchSession` `Sync` (`Mutex<T>: Sync` for `T: Send`). Accessed exclusively via
    /// `get_mut()` on `&mut self`, so polling incurs zero runtime locking.
    transport: StdMutex<PollTransport>,
    /// Close reason to lock in once the final record of `current_batch` has been delivered
    /// (`R9a` for exhausted `count`/`bytes`, or `R9c` for a deferred mid-batch `ProtocolError`).
    close_after_current_batch: Option<TerminalClose>,
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
        deliver_valid_prefix: bool,
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
            deliver_valid_prefix,
            span,
            state,
            shutdown,
            context,
            retry_backoff,
            advised_reconnects: AdvisedReconnects::default(),
            idle_since: None,
            has_received_response: false,
            last_fetched_seq: None,
            transport: StdMutex::new(PollTransport::new()),
            close_after_current_batch: None,
            exhausted: false,
            terminated: false,
        }
    }

    fn transport_mut(&mut self) -> &mut PollTransport {
        self.transport
            .get_mut()
            .expect("read transport mutex is never locked")
    }

    fn pause_heartbeat_timer(&mut self) {
        self.transport_mut().heartbeat.pause();
    }

    fn finalize_closed(&mut self, closed: TerminalClose) -> Option<ReadSessionError> {
        self.exhausted = true;
        self.close_after_current_batch = None;
        self.transport_mut().reset_to_idle();
        let mut wakes = PendingWakes::default();
        let out = {
            let mut inner = self.state.inner.lock().unwrap();
            match closed {
                TerminalClose::Clean => {
                    self.terminated = true;
                    inner.on_ended(None, &mut wakes);
                    None
                }
                TerminalClose::Error(err) => {
                    inner.on_ended(Some(err.clone()), &mut wakes);
                    Some(err)
                }
            }
        };
        wakes.wake();
        out
    }

    /// If the session has already closed (`R9`) or client shutdown (`C12`/`R9d`) is active,
    /// finalize and return `Some(None)` on clean close or `Some(Some(err))` on error.
    fn take_closed_or_abort(&mut self) -> Option<Option<ReadSessionError>> {
        self.state
            .closed_or_abort()
            .map(|c| self.finalize_closed(c))
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
            let shutdown = self.shutdown.clone();
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
        self.transport_mut().phase = DriverPhase::Opening(Box::pin(fut));
    }

    fn finish_clean_end_now(
        &mut self,
        tail: Option<StreamPosition>,
    ) -> Option<Result<DecodedBatch, ReadSessionError>> {
        let closed = self.state.on_clean_end_now(tail);
        self.finalize_closed(closed).map(Err)
    }

    fn finish_terminal_error(
        &mut self,
        err: ReadSessionError,
    ) -> Option<Result<DecodedBatch, ReadSessionError>> {
        let closed = self.state.on_terminal_error(err);
        self.finalize_closed(closed).map(Err)
    }

    /// Schedule retry backoff on `err`, or lock in and return the terminal poll result.
    fn schedule_retry_or_fail(
        &mut self,
        err: ReadSessionError,
    ) -> Option<Option<Result<DecodedBatch, ReadSessionError>>> {
        let attempts = self.retry_backoff.attempt_number();
        let err = err.with_context(&self.context.clone().with_attempts(attempts));
        if let Some(backoff) = retry_delay(
            &err,
            attempts,
            &mut self.retry_backoff,
            self.retry_policy,
            self.refreshes_tokens,
        ) {
            self.transport_mut().phase =
                DriverPhase::Backoff(Box::pin(tokio::time::sleep(backoff)));
            None
        } else {
            Some(self.finish_terminal_error(err))
        }
    }

    fn handle_decoded_batch(&mut self, mut batch: ReadBatch, reconnect_advised: bool) -> BatchStep {
        // R6 / R7a / E7: verify records arrive in strictly increasing seq_num order at or above
        // the resolved cursor, with representable successor `next_seq_num`, annotating the active
        // attempt count on any ProtocolError.
        let attempts = self.retry_backoff.attempt_number();
        let attempt_ctx = self.context.clone().with_attempts(attempts);
        let min_next_seq_num = if self.has_received_response || self.start.clamp != Some(true) {
            self.start.seq_num
        } else {
            None
        };
        let validation = validate_read_batch_order(
            &batch,
            self.last_fetched_seq,
            min_next_seq_num,
            &attempt_ctx,
        );
        if let Some(err) = validation.error {
            let transport = self.transport_mut();
            transport.phase = DriverPhase::Idle;
            transport.heartbeat.reset();
            if !self.deliver_valid_prefix || validation.valid_len == 0 {
                self.state.on_disconnected();
                return BatchStep::Done(self.finish_terminal_error(err));
            }
            // R6a / R9c: in record iteration, deliver the valid record prefix before failing with
            // ProtocolError, without trusting the corrupt batch's tail.
            batch.records.truncate(validation.valid_len);
            batch.tail = None;
            self.last_fetched_seq = validation.last_valid_seq;
            self.has_received_response = true;
            return BatchStep::Yield(DecodedBatch {
                batch,
                close_after_batch: Some(TerminalClose::Error(err)),
                disconnected: true,
            });
        }
        self.last_fetched_seq = validation.last_valid_seq;

        // T5a: only a non-empty batch or a heartbeat (carrying a tail) counts as progress and
        // resets the retry budget.
        let has_records = !batch.records.is_empty();
        let has_tail = batch.tail.is_some();
        let is_progress = has_records || has_tail;

        if !is_progress {
            // T6 / T6a: even if an empty frame carries no progress, still honor reconnect advice
            // so the retiring request is closed; only grant a free handover if this attempt
            // already made progress earlier, otherwise count the move as a retry (`T1`/`T3`).
            if reconnect_advised && self.advised_reconnects.should_reconnect() {
                let made_progress = matches!(
                    &self.transport_mut().phase,
                    DriverPhase::Active(attempt) if attempt.made_progress
                );
                let transport = self.transport_mut();
                transport.phase = DriverPhase::Idle;
                transport.heartbeat.reset();
                self.advised_reconnects.record();
                self.state.on_disconnected();
                debug!(
                    next_seq_num = ?self.start.seq_num,
                    made_progress,
                    advised_reconnects = self.advised_reconnects.total(),
                    "reconnecting read session on server advice from empty frame"
                );
                if !made_progress {
                    let err =
                        ReadSessionError::ConnectionLost(ConnectionLostError::new_with_context(
                            "server advised reconnect before stream progress",
                            true,
                            self.context.clone(),
                        ));
                    if let Some(done) = self.schedule_retry_or_fail(err) {
                        return BatchStep::Done(done);
                    }
                }
            } else if let Err(closed) = self.state.on_empty_frame_without_tail() {
                return BatchStep::Done(self.finalize_closed(closed).map(Err));
            }
            return BatchStep::Continue;
        }

        {
            let transport = self.transport_mut();
            transport.heartbeat.reset();
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
        let mut disconnected_for_advice = false;

        if limits_exhausted {
            // R11c / T10: stop condition met; end the underlying request immediately without
            // waiting for trailing EOF or opening another request.
            debug!("read session count/bytes limit exhausted");
            self.transport_mut().phase = DriverPhase::Idle;
        } else if reconnect_advised && self.advised_reconnects.should_reconnect() {
            // T6a / T10: end the advised attempt immediately (releasing the retiring server) and
            // open the replacement request on the next transport pull (immediately for a
            // heartbeat, since iteration keeps pulling).
            self.transport_mut().phase = DriverPhase::Idle;
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
                close_after_batch: limits_exhausted.then_some(TerminalClose::Clean),
                disconnected: disconnected_for_advice,
            })
        } else if let Some(tail) = batch.tail {
            if let Err(closed) = self.state.on_heartbeat(tail, disconnected_for_advice) {
                return BatchStep::Done(self.finalize_closed(closed).map(Err));
            }
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
        self.schedule_retry_or_fail(err)
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

        self.schedule_retry_or_fail(err)
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

            let PollTransport {
                phase, heartbeat, ..
            } = self
                .transport
                .get_mut()
                .expect("read transport mutex is never locked");

            match phase {
                DriverPhase::Idle => {
                    self.start_open_attempt();
                }
                DriverPhase::Opening(fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return self.pending_or_abort(cx),
                    Poll::Ready(res) => {
                        *phase = DriverPhase::Idle;
                        if self.shutdown.is_cancelled()
                            && let Some(outcome) = self.take_closed_or_abort()
                        {
                            return Poll::Ready(outcome.map(Err));
                        }
                        match res {
                            Ok(stream) => {
                                let transport = self.transport_mut();
                                transport.heartbeat.reset();
                                let last_chunks_received = stream.chunks_received();
                                transport.phase = DriverPhase::Active(ActiveAttempt {
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
                                if let Some(done) = self.schedule_retry_or_fail(err) {
                                    return Poll::Ready(done);
                                }
                            }
                        }
                    }
                },
                DriverPhase::Backoff(sleep) => match sleep.as_mut().poll(cx) {
                    Poll::Pending => return self.pending_or_abort(cx),
                    Poll::Ready(()) => {
                        *phase = DriverPhase::Idle;
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
                                BatchStep::Done(done) => return Poll::Ready(done),
                            }
                        }
                        Poll::Ready(Some(Err(err))) => {
                            let made_progress = attempt.made_progress;
                            *phase = DriverPhase::Idle;
                            heartbeat.reset();
                            if let Some(result) = self.handle_stream_error(err, made_progress) {
                                return Poll::Ready(result);
                            }
                        }
                        Poll::Ready(None) => {
                            let fetched_record = attempt.fetched_record;
                            *phase = DriverPhase::Idle;
                            heartbeat.reset();
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
                                heartbeat.reset();
                            }
                            match heartbeat.poll(cx) {
                                Poll::Pending => return self.pending_or_abort(cx),
                                Poll::Ready(()) => {
                                    let made_progress = attempt.made_progress;
                                    attempt.stream.retire_connection();
                                    *phase = DriverPhase::Idle;
                                    heartbeat.reset();
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
        let mut wakes = PendingWakes::default();
        {
            let mut inner = self.state.inner.lock().unwrap();
            if inner.closed.is_none() {
                if self.shutdown.is_cancelled() {
                    let err = AbortedError::new_with_context("client closed", self.context.clone());
                    inner.on_aborted(err, &mut wakes);
                } else {
                    inner.closed = Some(TerminalClose::Clean);
                    inner.on_ended(None, &mut wakes);
                }
            } else {
                inner.on_ended(None, &mut wakes);
            }
        }
        wakes.wake();
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
///
/// Prefer the inherent [`next`](Self::next) method when canceling pending waits (such as in
/// [`tokio::select!`] or timeouts): dropping `next()` pauses the 20 s heartbeat timer across idle
/// gaps, whereas driving [`Stream::poll_next`](futures_core::Stream::poll_next) directly (for
/// example via `StreamExt::next()`) has no drop hook for abandoned pending polls, so an armed
/// heartbeat deadline continues running until the next poll completes (while still draining any
/// already-buffered transport messages or bytes first).
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
            core: ReadSessionCore::open(client, name, headers, input, config, "read_session", true),
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

/// Note: polling [`Stream`] directly (for example via `StreamExt::next()`) has no cancellation
/// callback if a pending poll is dropped, so an already-armed heartbeat deadline continues running
/// until the next poll completes (while still draining already-buffered transport messages or
/// bytes first). Prefer [`ReadSession::next`] when canceling pending reads in `select!` or
/// timeouts.
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
            let lock_in_close = if this.current_batch.len() == 0 {
                this.core.close_after_current_batch.take()
            } else {
                None
            };
            if let Err(closed) = this
                .core
                .state
                .on_record_delivered(record.seq_num, lock_in_close)
            {
                this.current_batch = Vec::new().into_iter();
                this.core.close_after_current_batch = None;
                return Poll::Ready(this.core.finalize_closed(closed).map(Err));
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
                let (lock_in_close, remaining_close) = if iter.len() == 0 {
                    (decoded.close_after_batch, None)
                } else {
                    (None, decoded.close_after_batch)
                };
                if let Err(closed) = this.core.state.on_batch_decoded_and_delivered(
                    tail,
                    record.seq_num,
                    decoded.disconnected,
                    lock_in_close,
                ) {
                    return Poll::Ready(this.core.finalize_closed(closed).map(Err));
                }
                this.current_batch = iter;
                this.core.close_after_current_batch = remaining_close;
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
///
/// Prefer the inherent [`next`](Self::next) method when canceling pending waits (such as in
/// [`tokio::select!`] or timeouts): dropping `next()` pauses the 20 s heartbeat timer across idle
/// gaps, whereas driving [`Stream::poll_next`](futures_core::Stream::poll_next) directly (for
/// example via `StreamExt::next()`) has no drop hook for abandoned pending polls, so an armed
/// heartbeat deadline continues running until the next poll completes (while still draining any
/// already-buffered transport messages or bytes first).
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
            core: ReadSessionCore::open(
                client,
                name,
                headers,
                input,
                config,
                "read_batch_session",
                false,
            ),
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

/// Note: polling [`Stream`] directly (for example via `StreamExt::next()`) has no cancellation
/// callback if a pending poll is dropped, so an already-armed heartbeat deadline continues running
/// until the next poll completes (while still draining already-buffered transport messages or
/// bytes first). Prefer [`ReadBatchSession::next`] when canceling pending reads in `select!` or
/// timeouts.
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
                if let Err(closed) = this.core.state.on_batch_decoded_and_delivered(
                    tail,
                    last_seq,
                    decoded.disconnected,
                    decoded.close_after_batch,
                ) {
                    return Poll::Ready(this.core.finalize_closed(closed).map(Err));
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

struct BatchOrderValidation {
    valid_len: usize,
    last_valid_seq: Option<u64>,
    error: Option<ReadSessionError>,
}

fn validate_read_batch_order(
    batch: &ReadBatch,
    last_fetched_seq: Option<u64>,
    min_next_seq_num: Option<u64>,
    context: &ErrorContext,
) -> BatchOrderValidation {
    let mut prev = last_fetched_seq;
    for (idx, record) in batch.records.iter().enumerate() {
        if let Some(min_seq) = min_next_seq_num
            && record.seq_num < min_seq
        {
            return BatchOrderValidation {
                valid_len: idx,
                last_valid_seq: prev,
                error: Some(ReadSessionError::Protocol(ProtocolError::new_with_context(
                    format!(
                        "read batch contained seq_num {} below resolved cursor {}",
                        record.seq_num, min_seq
                    ),
                    context.clone(),
                ))),
            };
        }
        if let Some(prev_seq) = prev
            && record.seq_num <= prev_seq
        {
            return BatchOrderValidation {
                valid_len: idx,
                last_valid_seq: prev,
                error: Some(ReadSessionError::Protocol(ProtocolError::new_with_context(
                    format!(
                        "read batch contained out-of-order or duplicate seq_num {} after {}",
                        record.seq_num, prev_seq
                    ),
                    context.clone(),
                ))),
            };
        }
        if record.seq_num.checked_add(1).is_none() {
            return BatchOrderValidation {
                valid_len: idx,
                last_valid_seq: prev,
                error: Some(ReadSessionError::Protocol(ProtocolError::new_with_context(
                    "read batch record seq_num u64::MAX has no representable successor",
                    context.clone(),
                ))),
            };
        }
        prev = Some(record.seq_num);
    }
    BatchOrderValidation {
        valid_len: batch.records.len(),
        last_valid_seq: prev,
        error: None,
    }
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
        session.core.transport_mut().phase = DriverPhase::Active(ActiveAttempt {
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
        let (_session, _tx, state, shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(0)),
        );
        shutdown.cancel();
        assert!(matches!(
            state.on_record_delivered(0, None),
            Err(TerminalClose::Error(ReadSessionError::Aborted(_)))
        ));
        assert!(matches!(
            state.on_batch_decoded_and_delivered(Some(position(1)), 0, false, None),
            Err(TerminalClose::Error(ReadSessionError::Aborted(_)))
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
        session.core.transport_mut().phase = DriverPhase::Active(ActiveAttempt {
            stream,
            made_progress: false,
            fetched_record: false,
            last_chunks_received: 0,
        });
        let state = session.state();
        let shutdown = session.core.shutdown.clone();
        (session, tx, state, shutdown)
    }

    #[test]
    fn validate_read_batch_order_rejects_duplicate_and_backward_seq_nums() {
        let ctx = ErrorContext::default().into_read_only();
        let b1 = batch(vec![record(0), record(2)], None);
        let res = validate_read_batch_order(&b1, None, None, &ctx);
        assert!(res.error.is_none());
        assert_eq!(res.valid_len, 2);
        assert_eq!(res.last_valid_seq, Some(2));

        let dup = batch(vec![record(2)], None);
        let res_dup = validate_read_batch_order(&dup, res.last_valid_seq, Some(3), &ctx);
        assert_eq!(res_dup.valid_len, 0);
        assert!(matches!(res_dup.error, Some(ReadSessionError::Protocol(_))));

        let backward_within = batch(vec![record(5), record(4)], None);
        let res_back =
            validate_read_batch_order(&backward_within, res.last_valid_seq, Some(3), &ctx);
        assert_eq!(res_back.valid_len, 1);
        assert_eq!(res_back.last_valid_seq, Some(5));
        assert!(matches!(
            res_back.error,
            Some(ReadSessionError::Protocol(_))
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

    // spec: r1 R6a, R7a, R9c
    #[tokio::test]
    async fn mixed_valid_and_invalid_batch_delivers_valid_prefix_in_record_view_and_rejects_atomically_in_batch_view()
     {
        // Record view delivers valid prefix `[7]`, updates `next_seq_num` to `8`, then yields
        // ProtocolError once, then None — and locks in R9c so late shutdown does not mask it.
        let (mut session, tx, state, shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(7)),
        );
        let cu = state.caught_up();
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[7, u64::MAX], Some(u64::MAX)),
            reconnect_advised: false,
        }))
        .unwrap();

        let rec = session.next().await.unwrap().unwrap();
        assert_eq!(rec.seq_num, 7);
        assert_eq!(state.next_seq_num(), Some(8));
        assert!(!state.is_caught_up());
        assert_eq!(state.last_observed_tail(), None);
        assert!(matches!(cu.await, Err(ReadSessionError::Protocol(_))));

        // Late shutdown after R9c locked in on final valid prefix record has no effect.
        shutdown.cancel();
        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::Protocol(_)))
        ));
        assert!(session.next().await.is_none());

        // Multi-record valid prefix `[7, 8]` before backward `5`: aborting after record `7`
        // drops record `8` and wins with AbortedError (`R9d`).
        let (mut session, tx, state, shutdown) = test_session_with_active_stream(
            ReadInput::new().with_start(crate::types::ReadStart::SeqNum(7)),
        );
        tx.send(Ok(S2sFrame {
            msg: proto_batch(&[7, 8, 5], None),
            reconnect_advised: false,
        }))
        .unwrap();
        assert_eq!(session.next().await.unwrap().unwrap().seq_num, 7);
        assert_eq!(state.next_seq_num(), Some(8));
        shutdown.cancel();
        assert!(matches!(
            session.next().await,
            Some(Err(ReadSessionError::Aborted(_)))
        ));
        assert!(session.next().await.is_none());

        // Batch view rejects `[7, u64::MAX]` atomically without delivering `7` (`R6a`).
        let (mut batch_sess, batch_tx, batch_state, _shutdown) =
            test_batch_session_with_active_stream(
                ReadInput::new().with_start(crate::types::ReadStart::SeqNum(7)),
            );
        batch_tx
            .send(Ok(S2sFrame {
                msg: proto_batch(&[7, u64::MAX], None),
                reconnect_advised: false,
            }))
            .unwrap();
        assert!(matches!(
            batch_sess.next().await,
            Some(Err(ReadSessionError::Protocol(_)))
        ));
        assert_eq!(batch_state.next_seq_num(), Some(7));
        assert!(batch_sess.next().await.is_none());
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
        assert_eq!(state.next_seq_num(), Some(12));
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
