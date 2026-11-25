use std::{
    fmt,
    future::Future,
    ops::ControlFlow,
    pin::{Pin, pin},
    str::FromStr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures_core::{FusedFuture, FusedStream, Stream};
use futures_util::{
    StreamExt,
    future::{FutureExt, Shared},
};
use http::StatusCode;
use s2_api::v1::stream::{ReadEnd, ReadStart, proto};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, Sleep},
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, debug, debug_span};

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

impl Future for CaughtUpFuture {
    type Output = CaughtUpResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Pending(rx) => match Pin::new(rx).poll(cx) {
                Poll::Ready(Ok(result)) => {
                    *self = Self::Ready(result.clone());
                    Poll::Ready(result)
                }
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
///
/// **Important:** Does not drive reading — continue polling the session concurrently (for example
/// via [`ReadSession::next`] in another task or `tokio::select!`) while awaiting this future.
///
/// Once resolved, its value never changes, and re-polling returns the same outcome without
/// panicking.
#[must_use = "futures do nothing unless `.await`ed or polled"]
pub struct CaughtUp {
    inner: CaughtUpFuture,
    done: bool,
}

impl Clone for CaughtUp {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
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
        match Pin::new(&mut self.inner).poll(cx) {
            Poll::Ready(res) => {
                self.done = true;
                Poll::Ready(res)
            }
            Poll::Pending => Poll::Pending,
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
        waiter: Option<(oneshot::Sender<CaughtUpResult>, CaughtUpFuture)>,
    },
    CaughtUp {
        tail: StreamPosition,
        future: CaughtUpFuture,
    },
    Ended(ReadSessionError),
}

impl CatchUpSlot {
    fn pending() -> Self {
        Self::Pending { waiter: None }
    }

    fn is_caught_up(&self) -> bool {
        matches!(self, Self::CaughtUp { .. })
    }

    fn future(&mut self) -> CaughtUpFuture {
        match self {
            Self::Pending { waiter } => {
                let (_, future) = waiter.get_or_insert_with(|| {
                    let (tx, rx) = oneshot::channel();
                    (tx, CaughtUpFuture::Pending(rx.shared()))
                });
                future.clone()
            }
            Self::CaughtUp { future, .. } => future.clone(),
            Self::Ended(err) => CaughtUpFuture::Ready(Err(err.clone())),
        }
    }
}

#[derive(Debug, Clone)]
enum TerminalClose {
    Clean,
    Error(ReadSessionError),
}

enum PendingClose {
    Clean { final_tail: Option<StreamPosition> },
    Error(ReadSessionError),
}

/// Deferred oneshot wake for a pending [`CaughtUp`] waiter, always fired AFTER releasing
/// `ReadStateShared::inner` so custom wakers reading session state cannot deadlock on re-entry.
#[must_use]
struct CatchUpWake(Option<(oneshot::Sender<CaughtUpResult>, CaughtUpResult)>);

impl CatchUpWake {
    const NONE: Self = Self(None);

    fn or(self, other: Self) -> Self {
        match (self.0, other.0) {
            (Some(first), None) => Self(Some(first)),
            (None, second) => Self(second),
            (Some(first), Some(_)) => {
                debug_assert!(
                    false,
                    "at most one pending caught_up waiter per lock acquisition"
                );
                Self(Some(first))
            }
        }
    }

    fn fire(self) {
        if let Some((tx, res)) = self.0 {
            let _ = tx.send(res);
        }
    }
}

struct ReadStateShared {
    inner: StdMutex<ReadStateInner>,
    /// Atomic mirror of `inner.closed.is_some()` for lock-free `take_closed_or_abort()`.
    closed: AtomicBool,
    /// Atomic mirror of `inner.catch_up.is_caught_up()`.
    caught_up: AtomicBool,
    /// Monotonic flag set once `next_seq_val` holds a valid sequence number.
    has_next_seq: AtomicBool,
    /// Single source of truth for `next_seq_num` once `has_next_seq` is true.
    next_seq_val: AtomicU64,
    /// Atomic mirror of `latest_tail.seq_num` while `phase == Open { latest_tail: Some(t) }`
    /// with `t.seq_num >= 1`, or `0` otherwise. Since any delivered record's successor
    /// `seq_num + 1` is `>= 1`, comparing `next_seq == latest_tail_seq` detects catch-up
    /// across the entire `u64` range.
    latest_tail_seq: AtomicU64,
}

impl ReadStateShared {
    fn new(initial_next_seq_num: Option<u64>, context: ErrorContext) -> Self {
        Self {
            inner: StdMutex::new(ReadStateInner::new(context)),
            closed: AtomicBool::new(false),
            caught_up: AtomicBool::new(false),
            has_next_seq: AtomicBool::new(initial_next_seq_num.is_some()),
            next_seq_val: AtomicU64::new(initial_next_seq_num.unwrap_or(0)),
            latest_tail_seq: AtomicU64::new(0),
        }
    }

    fn load_next_seq(&self) -> Option<u64> {
        if self.has_next_seq.load(Ordering::Acquire) {
            Some(self.next_seq_val.load(Ordering::SeqCst))
        } else {
            None
        }
    }

    fn store_next_seq(&self, seq: u64) {
        self.next_seq_val.store(seq, Ordering::SeqCst);
        if !self.has_next_seq.load(Ordering::Relaxed) {
            self.has_next_seq.store(true, Ordering::Release);
        }
    }

    fn set_phase(&self, inner: &mut ReadStateInner, phase: RequestPhase) {
        inner.phase = phase;
        let tail_seq = match phase {
            RequestPhase::Open {
                latest_tail: Some(tail),
            } => tail.seq_num,
            RequestPhase::Open { latest_tail: None }
            | RequestPhase::Connecting
            | RequestPhase::Ended => 0,
        };
        self.latest_tail_seq.store(tail_seq, Ordering::SeqCst);
    }

    fn set_closed(&self, inner: &mut ReadStateInner, closed: TerminalClose) {
        inner.closed = Some(closed);
        self.closed.store(true, Ordering::Release);
    }

    fn recompute_caught_up(&self, inner: &mut ReadStateInner) -> CatchUpWake {
        if inner.phase == RequestPhase::Ended {
            return CatchUpWake::NONE;
        }
        let caught_up_tail = match inner.phase {
            RequestPhase::Open {
                latest_tail: Some(tail),
            } => (self.load_next_seq() == Some(tail.seq_num)).then_some(tail),
            RequestPhase::Open { latest_tail: None }
            | RequestPhase::Connecting
            | RequestPhase::Ended => None,
        };
        match caught_up_tail {
            Some(tail) => {
                // Publish `caught_up = true` before waking `caught_up()` waiters so a caller
                // checking `is_caught_up()` immediately after `caught_up().await` cannot observe
                // `false` on a multi-threaded runtime.
                self.caught_up.store(true, Ordering::Release);
                if !matches!(inner.catch_up, CatchUpSlot::CaughtUp { tail: prev, .. } if prev == tail)
                {
                    let prev = std::mem::replace(
                        &mut inner.catch_up,
                        CatchUpSlot::CaughtUp {
                            tail,
                            future: CaughtUpFuture::Ready(Ok(tail)),
                        },
                    );
                    if let CatchUpSlot::Pending {
                        waiter: Some((tx, _)),
                    } = prev
                    {
                        return CatchUpWake(Some((tx, Ok(tail))));
                    }
                }
                CatchUpWake::NONE
            }
            None => {
                if inner.catch_up.is_caught_up() {
                    inner.catch_up = CatchUpSlot::pending();
                }
                self.caught_up.store(false, Ordering::Release);
                CatchUpWake::NONE
            }
        }
    }

    fn apply_heartbeat_tail(
        &self,
        inner: &mut ReadStateInner,
        tail: StreamPosition,
    ) -> CatchUpWake {
        if inner.phase == RequestPhase::Ended {
            return CatchUpWake::NONE;
        }
        inner.update_observed_tail(tail);
        let next = self
            .load_next_seq()
            .map_or(tail.seq_num, |prev| prev.max(tail.seq_num));
        self.store_next_seq(next);
        self.recompute_caught_up(inner)
    }

    fn apply_clean_close(
        &self,
        inner: &mut ReadStateInner,
        final_tail: Option<StreamPosition>,
    ) -> CatchUpWake {
        let mut wake = CatchUpWake::NONE;
        if let Some(tail) = final_tail {
            wake = wake.or(self.apply_heartbeat_tail(inner, tail));
        }
        self.set_closed(inner, TerminalClose::Clean);
        if !inner.catch_up.is_caught_up() {
            wake = wake.or(self.on_ended(inner, None));
        }
        wake
    }

    fn maybe_apply_pending_close(&self, inner: &mut ReadStateInner) -> CatchUpWake {
        if !inner.has_pending_deliveries()
            && inner.closed.is_none()
            && let Some(pending) = inner.pending_close.take()
        {
            match pending {
                PendingClose::Clean { final_tail } => self.apply_clean_close(inner, final_tail),
                PendingClose::Error(err) => {
                    self.set_closed(inner, TerminalClose::Error(err.clone()));
                    self.on_ended(inner, Some(err))
                }
            }
        } else {
            CatchUpWake::NONE
        }
    }

    fn on_ended(&self, inner: &mut ReadStateInner, error: Option<ReadSessionError>) -> CatchUpWake {
        if inner.phase == RequestPhase::Ended {
            return CatchUpWake::NONE;
        }
        self.set_phase(inner, RequestPhase::Ended);
        self.caught_up.store(false, Ordering::Release);

        let terminal_err = error.unwrap_or_else(|| {
            ReadSessionError::SessionClosed(SessionClosedError::new_with_context(
                None,
                inner.context.clone(),
            ))
        });
        // Any future handed out *before* ending retains its resolved tail (`R8a`).
        // Subsequent `caught_up()` calls after the session ends see the terminal error (`R8d`).
        let prev = std::mem::replace(
            &mut inner.catch_up,
            CatchUpSlot::Ended(terminal_err.clone()),
        );
        if let CatchUpSlot::Pending {
            waiter: Some((tx, _)),
        } = prev
        {
            CatchUpWake(Some((tx, Err(terminal_err))))
        } else {
            CatchUpWake::NONE
        }
    }

    fn on_aborted_locked(
        &self,
        inner: &mut ReadStateInner,
        err: AbortedError,
    ) -> (bool, CatchUpWake) {
        if inner.closed.is_some() || inner.phase == RequestPhase::Ended {
            return (false, CatchUpWake::NONE);
        }
        inner.pending_heartbeats = 0;
        inner.pending_close = None;
        let err = ReadSessionError::Aborted(err);
        self.set_closed(inner, TerminalClose::Error(err.clone()));
        let wake = self.on_ended(inner, Some(err));
        (true, wake)
    }
}

struct ReadStateInner {
    last_observed_tail: Option<StreamPosition>,
    phase: RequestPhase,
    catch_up: CatchUpSlot,
    buffered_records: usize,
    pending_heartbeats: usize,
    pending_close: Option<PendingClose>,
    /// Locked-in session close reason (`R9`). Once set, later aborts or closes have no effect.
    /// When `Clean` is reached while already caught up, `phase` stays `Open` until iteration
    /// returns `None` so `is_caught_up()` stays `true` per `R7c` without racing the driver.
    closed: Option<TerminalClose>,
    context: ErrorContext,
}

impl ReadStateInner {
    fn new(context: ErrorContext) -> Self {
        Self {
            last_observed_tail: None,
            phase: RequestPhase::Connecting,
            catch_up: CatchUpSlot::pending(),
            buffered_records: 0,
            pending_heartbeats: 0,
            pending_close: None,
            closed: None,
            context,
        }
    }

    fn has_pending_deliveries(&self) -> bool {
        self.buffered_records > 0 || self.pending_heartbeats > 0
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
}

/// Concurrently accessible read-session progress state.
///
/// Cloneable handle to observe [`next_seq_num`](Self::next_seq_num),
/// [`last_observed_tail`](Self::last_observed_tail), [`is_caught_up`](Self::is_caught_up), and
/// [`caught_up`](Self::caught_up) from another task while a single consumer iterates the
/// [`ReadSession`] or [`ReadBatchSession`]. None of its methods block.
#[derive(Clone)]
pub struct ReadSessionState {
    shared: Arc<ReadStateShared>,
    shutdown: CancellationToken,
}

impl fmt::Debug for ReadSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.shared.inner.lock().unwrap();
        let aborted_before_close = self.shutdown.is_cancelled() && inner.closed.is_none();
        let caught_up = !aborted_before_close && inner.catch_up.is_caught_up();
        f.debug_struct("ReadSessionState")
            .field("next_seq_num", &self.shared.load_next_seq())
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
            shared: Arc::new(ReadStateShared::new(initial_next_seq_num, context)),
            shutdown,
        }
    }

    /// Return the sequence number of the next record the session will deliver.
    ///
    /// An unclamped `ReadStart::SeqNum` start is known immediately; any other start returns `None`
    /// until resolved by the first server response. Updated before each record (or batch) is
    /// handed to the caller, and advances on heartbeats. Retained after iteration ends.
    #[must_use]
    pub fn next_seq_num(&self) -> Option<u64> {
        self.shared.load_next_seq()
    }

    /// Return the latest stream tail reported by the server.
    ///
    /// Never moves backward, persists across retries and handovers, and is retained after
    /// iteration ends.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.shared.inner.lock().unwrap().last_observed_tail
    }

    /// Return whether the active request is open and its most recent server message reported a
    /// tail equal to [`next_seq_num`](Self::next_seq_num).
    ///
    /// Returns `false` while reconnecting or once iteration has ended.
    #[must_use]
    pub fn is_caught_up(&self) -> bool {
        if !self.shared.caught_up.load(Ordering::Acquire) {
            return false;
        }
        if !self.shutdown.is_cancelled() {
            return true;
        }
        let inner = self.shared.inner.lock().unwrap();
        let aborted_before_close = self.shutdown.is_cancelled() && inner.closed.is_none();
        !aborted_before_close && inner.catch_up.is_caught_up()
    }

    /// Return a future that resolves to the tail position once the session is caught up.
    ///
    /// Resolves immediately if currently caught up, or the next time the session becomes caught
    /// up. Once resolved, its value never changes. Does not drive reading — continue polling the
    /// session while awaiting it. Remains pending across retries and handovers. Fails with the
    /// session's failure, or [`SessionClosedError`] if the session closes cleanly before catching
    /// up.
    pub fn caught_up(&self) -> CaughtUp {
        let (future, wake) = {
            let mut inner = self.shared.inner.lock().unwrap();
            let wake = if self.shutdown.is_cancelled() && inner.closed.is_none() {
                let err = AbortedError::new_with_context("client closed", inner.context.clone());
                self.shared.on_aborted_locked(&mut inner, err).1
            } else {
                CatchUpWake::NONE
            };
            (inner.catch_up.future(), wake)
        };
        wake.fire();
        CaughtUp {
            inner: future,
            done: false,
        }
    }

    fn is_closed_fast(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    fn on_message_fetched(
        &self,
        first_record_seq: Option<u64>,
        tail: Option<StreamPosition>,
        record_count: usize,
    ) -> bool {
        let (heartbeat_already_at_tail, wake) = {
            let mut inner = self.shared.inner.lock().unwrap();
            if inner.phase == RequestPhase::Ended || inner.closed.is_some() {
                return true;
            }
            inner.buffered_records = inner.buffered_records.saturating_add(record_count);
            self.shared
                .set_phase(&mut inner, RequestPhase::Open { latest_tail: tail });
            if let Some(tail) = tail {
                inner.update_observed_tail(tail);
            }
            if self.shared.load_next_seq().is_none()
                && let Some(seq) = first_record_seq.or_else(|| tail.map(|t| t.seq_num))
            {
                self.shared.store_next_seq(seq);
            }
            let wake = self.shared.recompute_caught_up(&mut inner);
            // Returns true if this was a heartbeat and `next_seq_num` is already at `tail.seq_num`,
            // meaning there are no earlier undelivered records waiting to advance past.
            let heartbeat_already_at_tail = first_record_seq.is_none()
                && tail.is_some_and(|t| self.shared.load_next_seq() == Some(t.seq_num));
            if first_record_seq.is_none() && tail.is_some() && !heartbeat_already_at_tail {
                inner.pending_heartbeats = inner.pending_heartbeats.saturating_add(1);
            }
            (heartbeat_already_at_tail, wake)
        };
        wake.fire();
        heartbeat_already_at_tail
    }

    fn on_disconnected(&self) {
        let wake = {
            let mut inner = self.shared.inner.lock().unwrap();
            if inner.phase == RequestPhase::Ended || inner.closed.is_some() {
                return;
            }
            self.shared.set_phase(&mut inner, RequestPhase::Connecting);
            self.shared.recompute_caught_up(&mut inner)
        };
        wake.fire();
    }

    fn on_clean_stop(&self, tail: Option<StreamPosition>) -> bool {
        let (closed, wake) = {
            let mut inner = self.shared.inner.lock().unwrap();
            if inner.closed.is_some() || inner.phase == RequestPhase::Ended {
                return true;
            }
            let latest_tail = tail.or(match inner.phase {
                RequestPhase::Open { latest_tail } => latest_tail,
                RequestPhase::Connecting | RequestPhase::Ended => None,
            });
            self.shared
                .set_phase(&mut inner, RequestPhase::Open { latest_tail });
            if let Some(tail) = tail {
                inner.update_observed_tail(tail);
            }
            if !inner.has_pending_deliveries() {
                let wake = self.shared.apply_clean_close(&mut inner, tail);
                (true, wake)
            } else {
                inner.pending_close = Some(PendingClose::Clean { final_tail: tail });
                let wake = self.shared.recompute_caught_up(&mut inner);
                (false, wake)
            }
        };
        wake.fire();
        closed
    }

    fn on_terminal_error(&self, err: ReadSessionError) -> bool {
        let (closed, wake) = {
            let mut inner = self.shared.inner.lock().unwrap();
            if inner.closed.is_some() || inner.phase == RequestPhase::Ended {
                return true;
            }
            if !inner.has_pending_deliveries() {
                self.shared
                    .set_closed(&mut inner, TerminalClose::Error(err.clone()));
                let wake = self.shared.on_ended(&mut inner, Some(err));
                (true, wake)
            } else {
                inner.pending_close = Some(PendingClose::Error(err));
                (false, CatchUpWake::NONE)
            }
        };
        wake.fire();
        closed
    }

    fn on_records_delivered(&self, last_seq_num: u64, count: usize) {
        let wake = {
            let mut inner = self.shared.inner.lock().unwrap();
            self.shared.store_next_seq(last_seq_num.saturating_add(1));
            inner.buffered_records = inner.buffered_records.saturating_sub(count);
            let mut wake = CatchUpWake::NONE;
            if inner.phase != RequestPhase::Ended {
                wake = wake.or(self.shared.recompute_caught_up(&mut inner));
            }
            wake.or(self.shared.maybe_apply_pending_close(&mut inner))
        };
        wake.fire();
    }

    fn on_heartbeat_delivered(&self, tail: StreamPosition) {
        let wake = {
            let mut inner = self.shared.inner.lock().unwrap();
            inner.pending_heartbeats = inner.pending_heartbeats.saturating_sub(1);
            let wake = self.shared.apply_heartbeat_tail(&mut inner, tail);
            wake.or(self.shared.maybe_apply_pending_close(&mut inner))
        };
        wake.fire();
    }

    fn on_aborted(&self, err: AbortedError) -> bool {
        let (aborted, wake) = {
            let mut inner = self
                .shared
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.shared.inner.clear_poison();
            self.shared.on_aborted_locked(&mut inner, err)
        };
        wake.fire();
        aborted
    }
}

enum DriverEvent {
    Batch(ReadBatch),
    Heartbeat(StreamPosition),
    CleanEnd,
    Error(ReadSessionError),
}

struct ReadSessionCore {
    basin: BasinName,
    stream: StreamName,
    rx: mpsc::Receiver<DriverEvent>,
    state: ReadSessionState,
    shutdown: CancellationToken,
    context: ErrorContext,
    /// True once no more items will be produced (subsequent polls yield `None`).
    exhausted: bool,
    /// True once `Stream::poll_next` has returned `Poll::Ready(None)` (`FusedStream` contract).
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
            name.clone(),
            headers,
            start,
            end,
            config.retry_policy,
            op_name,
            state.clone(),
            shutdown.clone(),
            context.clone(),
        );
        let handle = tokio::spawn(driver.run(tx).instrument(span));

        Self {
            basin,
            stream: name,
            rx,
            state,
            shutdown,
            context,
            exhausted: false,
            terminated: false,
            _driver: AbortOnDropHandle::new(handle),
        }
    }

    fn finalize_closed(&mut self, closed: TerminalClose) -> Option<ReadSessionError> {
        self.exhausted = true;
        self.rx.close();
        let (res, wake) = {
            let mut inner = self.state.shared.inner.lock().unwrap();
            match closed {
                TerminalClose::Clean => {
                    self.terminated = true;
                    let wake = self.state.shared.on_ended(&mut inner, None);
                    (None, wake)
                }
                TerminalClose::Error(err) => {
                    let wake = self.state.shared.on_ended(&mut inner, Some(err.clone()));
                    (Some(err), wake)
                }
            }
        };
        wake.fire();
        res
    }

    /// If the session has already closed (`R9`) or client shutdown (`C12`/`R9d`) is active,
    /// finalize and return `Some(None)` on clean close or `Some(Some(err))` on error.
    fn take_closed_or_abort(&mut self) -> Option<Option<ReadSessionError>> {
        if !self.state.is_closed_fast() && !self.shutdown.is_cancelled() {
            return None;
        }
        let (closed, wake) = {
            let mut inner = self.state.shared.inner.lock().unwrap();
            let wake = if inner.closed.is_none() && self.shutdown.is_cancelled() {
                let err = AbortedError::new_with_context("client closed", self.context.clone());
                self.state.shared.on_aborted_locked(&mut inner, err).1
            } else {
                CatchUpWake::NONE
            };
            (inner.closed.clone(), wake)
        };
        wake.fire();
        closed.map(|c| self.finalize_closed(c))
    }

    fn poll_next_batch(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<ReadBatch, ReadSessionError>>> {
        if self.exhausted {
            self.terminated = true;
            return Poll::Ready(None);
        }
        loop {
            if let Some(outcome) = self.take_closed_or_abort() {
                return Poll::Ready(outcome.map(Err));
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
                Poll::Ready(Some(DriverEvent::CleanEnd)) => {
                    let (closed, wake) = {
                        let mut inner = self.state.shared.inner.lock().unwrap();
                        let wake = if inner.closed.is_none() {
                            if self.shutdown.is_cancelled() {
                                let err = AbortedError::new_with_context(
                                    "client closed",
                                    self.context.clone(),
                                );
                                self.state.shared.on_aborted_locked(&mut inner, err).1
                            } else {
                                self.state
                                    .shared
                                    .set_closed(&mut inner, TerminalClose::Clean);
                                CatchUpWake::NONE
                            }
                        } else {
                            CatchUpWake::NONE
                        };
                        (inner.closed.clone().expect("closed set above"), wake)
                    };
                    wake.fire();
                    return Poll::Ready(self.finalize_closed(closed).map(Err));
                }
                Poll::Ready(None) => {
                    if let Some(outcome) = self.take_closed_or_abort() {
                        return Poll::Ready(outcome.map(Err));
                    }
                    let err = ReadSessionError::Aborted(AbortedError::new_with_context(
                        "read session task ended unexpectedly",
                        self.context.clone(),
                    ));
                    let wake = {
                        let mut inner = self.state.shared.inner.lock().unwrap();
                        self.state
                            .shared
                            .set_closed(&mut inner, TerminalClose::Error(err.clone()));
                        self.state.shared.on_ended(&mut inner, Some(err.clone()))
                    };
                    wake.fire();
                    self.exhausted = true;
                    self.rx.close();
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Ready(Some(DriverEvent::Error(err))) => {
                    let closed = {
                        let mut inner = self.state.shared.inner.lock().unwrap();
                        if inner.closed.is_none() {
                            self.state
                                .shared
                                .set_closed(&mut inner, TerminalClose::Error(err.clone()));
                        }
                        inner.closed.clone().expect("closed set above")
                    };
                    return Poll::Ready(self.finalize_closed(closed).map(Err));
                }
            }
        }
    }
}

impl Drop for ReadSessionCore {
    fn drop(&mut self) {
        let wake = {
            let mut inner = self
                .state
                .shared
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.state.shared.inner.clear_poison();
            if inner.closed.is_none() {
                inner.pending_heartbeats = 0;
                inner.pending_close = None;
                if self.shutdown.is_cancelled() {
                    let err = AbortedError::new_with_context("client closed", self.context.clone());
                    self.state.shared.on_aborted_locked(&mut inner, err).1
                } else {
                    self.state
                        .shared
                        .set_closed(&mut inner, TerminalClose::Clean);
                    self.state.shared.on_ended(&mut inner, None)
                }
            } else {
                self.state.shared.on_ended(&mut inner, None)
            }
        };
        wake.fire();
    }
}

/// A continuous stream of sequenced records.
///
/// Yields individual [`SequencedRecord`]s in sequence-number order. Dropping the session closes it
/// immediately. Use [`state`](Self::state) to observe progress concurrently from other tasks.
#[must_use = "read sessions close immediately when dropped"]
pub struct ReadSession {
    core: ReadSessionCore,
    current_batch: std::vec::IntoIter<SequencedRecord>,
    unflushed_delivered: usize,
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
            unflushed_delivered: 0,
        }
    }

    fn record_delivered(&mut self, seq_num: u64) {
        let next_seq = seq_num.saturating_add(1);
        if self.current_batch.len() > 0 {
            let shared = &self.core.state.shared;
            shared.store_next_seq(next_seq);
            // Valid server tails are monotonic and `>= delivered_end`, so a mid-batch record can
            // only transition `caught_up` from `false -> true` when `next_seq == latest_tail_seq`;
            // if already `caught_up` or matching tail, fall through to lock and update
            // `CatchUpSlot`.
            if shared.latest_tail_seq.load(Ordering::SeqCst) != next_seq
                && !shared.caught_up.load(Ordering::Acquire)
            {
                self.unflushed_delivered += 1;
                return;
            }
        }
        let count = self.unflushed_delivered + 1;
        self.unflushed_delivered = 0;
        self.core.state.on_records_delivered(seq_num, count);
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
    #[must_use]
    pub fn state(&self) -> ReadSessionState {
        self.core.state.clone()
    }

    /// Return the sequence number of the next record this session will deliver.
    #[must_use]
    pub fn next_seq_num(&self) -> Option<u64> {
        self.core.state.next_seq_num()
    }

    /// Return the latest stream tail reported by the server.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether all records through the active request's latest reported tail have been
    /// delivered.
    #[must_use]
    pub fn is_caught_up(&self) -> bool {
        self.core.state.is_caught_up()
    }

    /// Return a future for the current or next caught-up tail.
    ///
    /// **Important:** Does not drive reading — continue polling [`next`](Self::next) concurrently
    /// while awaiting this future, or it will remain pending indefinitely. See
    /// [`ReadSessionState::caught_up`] for full details.
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
            this.unflushed_delivered = 0;
            return Poll::Ready(outcome.map(Err));
        }

        if let Some(record) = this.current_batch.next() {
            this.record_delivered(record.seq_num);
            return Poll::Ready(Some(Ok(record)));
        }

        match this.core.poll_next_batch(cx) {
            Poll::Ready(Some(Ok(batch))) => {
                this.current_batch = batch.records.into_iter();
                let record = this
                    .current_batch
                    .next()
                    .expect("poll_next_batch filters empty batches");
                this.record_delivered(record.seq_num);
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
/// Delivers each server batch whole, skips empty heartbeat frames while updating session state,
/// and follows all read-session rules per batch. Dropping the session closes it immediately.
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
    /// This method is cancel safe and can be used inside [`tokio::select!`].
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

    /// Return the latest stream tail reported by the server.
    #[must_use]
    pub fn last_observed_tail(&self) -> Option<StreamPosition> {
        self.core.state.last_observed_tail()
    }

    /// Return whether all records through the active request's latest reported tail have been
    /// delivered.
    #[must_use]
    pub fn is_caught_up(&self) -> bool {
        self.core.state.is_caught_up()
    }

    /// Return a future for the current or next caught-up tail.
    ///
    /// **Important:** Does not drive reading — continue polling [`next`](Self::next) concurrently
    /// while awaiting this future, or it will remain pending indefinitely. See
    /// [`ReadSessionState::caught_up`] for full details.
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
                this.core
                    .state
                    .on_records_delivered(last.seq_num, batch.records.len());
                Poll::Ready(Some(Ok(batch)))
            }
            other => other,
        }
    }
}

impl FusedStream for ReadBatchSession {
    fn is_terminated(&self) -> bool {
        self.core.terminated
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
    shutdown: CancellationToken,
    context: ErrorContext,
    retry_backoff: RetryBackoff,
    advised_reconnects: AdvisedReconnects,
    idle_since: Option<Instant>,
    has_received_response: bool,
    last_fetched_seq: Option<u64>,
    active: Option<ActiveAttempt>,
}

impl Drop for ReadDriver {
    fn drop(&mut self) {
        // Ensures pending `CaughtUp` waiters wake with `AbortedError` if the driver task is
        // cancelled or dropped before its first poll (e.g. runtime shutdown) or panics before
        // recording a terminal state.
        self.state.on_aborted(AbortedError::new_with_context(
            "read session task ended unexpectedly",
            self.context.clone(),
        ));
    }
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
        self.state.on_aborted(AbortedError::new_with_context(
            "client closed",
            self.context.clone(),
        ));
    }

    /// Enqueue a terminal event. If buffered records or heartbeats remain (`!already_closed`),
    /// stay parked until the consumer consumes them (closing `rx`) or the client shuts down, so
    /// any pending `caught_up()` future still wakes immediately on `S2::close()` (`C12`, `R8d`,
    /// `R9`).
    async fn send_terminal_event(
        &mut self,
        tx: &mpsc::Sender<DriverEvent>,
        event: DriverEvent,
        already_closed: bool,
    ) {
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled(), if !already_closed => {
                self.abort();
                return;
            }
            res = tx.send(event) => {
                if res.is_err() {
                    return;
                }
            }
        }
        if already_closed {
            return;
        }
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => self.abort(),
            _ = tx.closed() => {}
        }
    }

    /// Sleep for retry backoff while racing client shutdown and consumer drop.
    /// Returns `true` if the driver should terminate.
    async fn sleep_or_stop(&mut self, tx: &mpsc::Sender<DriverEvent>, backoff: Duration) -> bool {
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => {
                self.abort();
                true
            }
            _ = tx.closed() => true,
            _ = tokio::time::sleep(backoff) => false,
        }
    }

    async fn finish_clean_stop(
        &mut self,
        tx: &mpsc::Sender<DriverEvent>,
        tail: Option<StreamPosition>,
    ) {
        let already_closed = self.state.on_clean_stop(tail);
        self.send_terminal_event(tx, DriverEvent::CleanEnd, already_closed)
            .await;
    }

    async fn finish_terminal_error(
        &mut self,
        tx: &mpsc::Sender<DriverEvent>,
        err: ReadSessionError,
    ) {
        let already_closed = self.state.on_terminal_error(err.clone());
        self.send_terminal_event(tx, DriverEvent::Error(err), already_closed)
            .await;
    }

    async fn finish_resumed_unwritten_stop(
        &mut self,
        tx: &mpsc::Sender<DriverEvent>,
        tail: Option<StreamPosition>,
    ) {
        debug!(?tail, "read session reached tail on resumed stop condition");
        self.finish_clean_stop(tx, tail).await;
    }

    /// Retry `err` according to `retry_policy`, or deliver the terminal error to the consumer.
    /// Returns `true` if the driver should continue retrying, or `false` to exit.
    async fn retry_or_fail(
        &mut self,
        tx: &mpsc::Sender<DriverEvent>,
        err: ReadSessionError,
    ) -> bool {
        let attempts = self.retry_backoff.attempt_number();
        let err = err.with_context(&self.context.clone().with_attempts(attempts));
        if let Some(backoff) = retry_delay(
            &err,
            attempts,
            &mut self.retry_backoff,
            self.retry_policy,
            self.refreshes_tokens,
        ) {
            return !self.sleep_or_stop(tx, backoff).await;
        }
        self.finish_terminal_error(tx, err).await;
        false
    }

    async fn open_attempt(&mut self, tx: &mpsc::Sender<DriverEvent>) -> ControlFlow<()> {
        self.end.wait = remaining_wait(self.baseline_wait, self.idle_since);
        let attempt_num = self.retry_backoff.attempt_number();
        debug!(
            attempt = attempt_num,
            next_seq_num = ?self.start.seq_num,
            "opening read session request"
        );

        let open_res = tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => {
                self.abort();
                return ControlFlow::Break(());
            }
            _ = tx.closed() => return ControlFlow::Break(()),
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
            return ControlFlow::Break(());
        }

        match open_res {
            Ok(stream) => {
                self.active = Some(ActiveAttempt {
                    stream,
                    made_progress: false,
                    fetched_record: false,
                });
                ControlFlow::Continue(())
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
                    self.finish_resumed_unwritten_stop(tx, tail).await;
                    return ControlFlow::Break(());
                }
                if self.retry_or_fail(tx, err).await {
                    ControlFlow::Continue(())
                } else {
                    ControlFlow::Break(())
                }
            }
        }
    }

    async fn recv_next_item<SF, CF>(
        &mut self,
        mut heartbeat_sleep: Pin<&mut Sleep>,
        mut shutdown_fut: Pin<&mut SF>,
        mut tx_closed_fut: Pin<&mut CF>,
    ) -> ControlFlow<(), Result<Option<(proto::ReadBatch, bool)>, ReadSessionError>>
    where
        SF: Future<Output = ()>,
        CF: Future<Output = ()>,
    {
        let deadline = Instant::now().checked_add(HEARTBEAT_TIMEOUT);
        let attempt = self.active.as_mut().expect("active stream must be Some");
        let item = loop {
            tokio::select! {
                biased;
                _ = shutdown_fut.as_mut() => {
                    self.abort();
                    return ControlFlow::Break(());
                }
                _ = tx_closed_fut.as_mut() => return ControlFlow::Break(()),
                res = attempt.stream.next() => break match res {
                    Some(Ok(frame)) => Ok(Some((frame.msg, frame.reconnect_advised))),
                    Some(Err(err)) => Err(err),
                    None => Ok(None),
                },
                _ = heartbeat_sleep.as_mut(), if deadline.is_some() => {
                    let target = deadline.expect("deadline is Some");
                    if Instant::now() < target {
                        heartbeat_sleep.as_mut().reset(target);
                        continue;
                    }
                    attempt.stream.retire_connection();
                    break Err(ReadSessionError::Timeout(TimeoutError::new_with_context(
                        "heartbeat timeout",
                        self.context.clone(),
                    )));
                }
            }
        };

        if self.shutdown.is_cancelled() {
            self.abort();
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(item)
    }

    async fn handle_batch(
        &mut self,
        tx: &mpsc::Sender<DriverEvent>,
        proto_batch: proto::ReadBatch,
        reconnect_advised: bool,
        permit: mpsc::Permit<'_, DriverEvent>,
    ) -> ControlFlow<()> {
        // R6: convert and verify records arrive in strictly increasing seq_num order in one pass.
        let compute_bytes = self.end.bytes.is_some();
        let (batch, batch_metered_bytes) = match convert_and_validate_read_batch(
            proto_batch,
            self.last_fetched_seq,
            compute_bytes,
            &self.context,
        ) {
            Ok((batch, new_last, metered_bytes)) => {
                self.last_fetched_seq = new_last;
                (batch, metered_bytes)
            }
            Err(err) => {
                drop(permit);
                self.active = None;
                self.state.on_disconnected();
                self.finish_terminal_error(tx, err).await;
                return ControlFlow::Break(());
            }
        };

        // T5a: only a non-empty batch or a heartbeat (carrying a tail) counts as
        // progress and resets the retry budget; ignore malformed empty frames.
        let has_records = !batch.records.is_empty();
        let has_tail = batch.tail.is_some();
        let is_progress = has_records || has_tail;

        if is_progress {
            let attempt = self.active.as_mut().expect("active stream must be Some");
            attempt.made_progress = true;
            self.has_received_response = true;
            self.retry_backoff.reset();

            // R11c: restart idle clock only when a record is fetched; if no record has
            // been fetched yet, start the clock the first time we learn we are at the
            // tail. Heartbeats never restart this clock. Only needed when `wait > 0`.
            if has_records {
                attempt.fetched_record = true;
                if self.baseline_wait.is_some_and(|w| w > 0) {
                    self.idle_since = Some(Instant::now());
                }
            } else if self.last_fetched_seq.is_none()
                && has_tail
                && self.baseline_wait.is_some_and(|w| w > 0)
            {
                self.idle_since.get_or_insert_with(Instant::now);
            }

            update_resume_start(&mut self.start, &batch);
            if let Some(count) = self.end.count.as_mut() {
                *count = count.saturating_sub(batch.records.len() as u64);
            }
            if let Some(bytes) = self.end.bytes.as_mut() {
                *bytes = bytes.saturating_sub(batch_metered_bytes);
            }

            let first_record_seq = batch.records.first().map(|r| r.seq_num);
            let tail = batch.tail;
            let heartbeat_already_at_tail =
                self.state
                    .on_message_fetched(first_record_seq, tail, batch.records.len());

            if has_records {
                permit.send(DriverEvent::Batch(batch));
                if read_limits_exhausted(&self.end) {
                    debug!("read session count/bytes limit exhausted");
                    self.active = None;
                    self.finish_clean_stop(tx, None).await;
                    return ControlFlow::Break(());
                }
            } else if let Some(tail) = tail
                && !heartbeat_already_at_tail
            {
                permit.send(DriverEvent::Heartbeat(tail));
            } else {
                drop(permit);
            }
        } else {
            drop(permit);
        }

        // T6a: act on reconnect advice immediately (at most once per cooldown window).
        if reconnect_advised && self.advised_reconnects.should_reconnect() {
            self.active = None;
            if read_limits_exhausted(&self.end) {
                debug!("read session limits exhausted on advised reconnect");
                self.finish_clean_stop(tx, None).await;
                return ControlFlow::Break(());
            }
            self.advised_reconnects.record();
            debug!(
                next_seq_num = ?self.start.seq_num,
                advised_reconnects = self.advised_reconnects.total(),
                "reconnecting read session on server advice"
            );
            self.state.on_disconnected();
        }
        ControlFlow::Continue(())
    }

    async fn handle_eof(&mut self, tx: &mpsc::Sender<DriverEvent>) -> ControlFlow<()> {
        // T9 / R9a: clean EOF ends iteration cleanly ONLY when a stop option was set;
        // otherwise it is a ConnectionLostError and retried per retry_policy.
        let fetched_record = self.active.take().is_some_and(|a| a.fetched_record);
        if self.has_stop_option {
            // R11c: if this attempt ran with a reduced `wait` budget and fetched new
            // records (restarting the idle clock), reconnect with the refreshed wait
            // rather than stopping prematurely when the server's shorter timer expires.
            if fetched_record
                && !read_limits_exhausted(&self.end)
                && let (Some(base_w), Some(sent_w)) = (self.baseline_wait, self.end.wait)
                && sent_w < base_w
                && remaining_wait(self.baseline_wait, self.idle_since).is_some_and(|w| w > 0)
            {
                self.state.on_disconnected();
                return ControlFlow::Continue(());
            }
            debug!("read session ended cleanly on stop condition");
            self.finish_clean_stop(tx, None).await;
            return ControlFlow::Break(());
        }
        let err = ReadSessionError::ConnectionLost(ConnectionLostError::new_with_context(
            "read stream ended cleanly without a stop condition",
            true,
            self.context.clone(),
        ));
        self.state.on_disconnected();
        if self.retry_or_fail(tx, err).await {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        }
    }

    async fn handle_stream_error(
        &mut self,
        tx: &mpsc::Sender<DriverEvent>,
        err: ReadSessionError,
    ) -> ControlFlow<()> {
        // T10: drop underlying attempt stream immediately.
        let made_progress = self.active.take().is_some_and(|a| a.made_progress);

        // R11d: 416 on a resumed request with no remaining wait is a clean stop unless
        // the reported tail regressed below our resume position.
        if let Some(tail) =
            resumed_unwritten_stop_tail(self.has_received_response, &self.start, &self.end, &err)
        {
            self.finish_resumed_unwritten_stop(tx, tail).await;
            return ControlFlow::Break(());
        }

        // If `count` or `bytes` is already exhausted after receiving data, all
        // requested records have been fetched; end cleanly rather than reconnecting
        // with count=0/bytes=0.
        if self.has_received_response && read_limits_exhausted(&self.end) {
            debug!("read session limits exhausted after stream error");
            self.finish_clean_stop(tx, None).await;
            return ControlFlow::Break(());
        }

        self.state.on_disconnected();

        if err.is_server_draining() && made_progress {
            debug!(
                next_seq_num = ?self.start.seq_num,
                "reconnecting read session while server drains"
            );
            return ControlFlow::Continue(());
        }

        if self.retry_or_fail(tx, err).await {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        }
    }

    async fn run(mut self, tx: mpsc::Sender<DriverEvent>) {
        let shutdown = self.shutdown.clone();
        let mut shutdown_fut = pin!(shutdown.cancelled());
        let tx_for_closed = tx.clone();
        let mut tx_closed_fut = pin!(tx_for_closed.closed());
        let mut heartbeat_sleep = pin!(tokio::time::sleep(HEARTBEAT_TIMEOUT));

        loop {
            if self.shutdown.is_cancelled() {
                self.abort();
                return;
            }
            if tx.is_closed() {
                return;
            }

            if self.active.is_none() {
                if self.open_attempt(&tx).await.is_break() {
                    return;
                }
                if self.active.is_none() {
                    continue;
                }
            }

            // R6b + T7d: wait for channel capacity BEFORE reading the next message so we decode at
            // most 1 batch ahead and do not count caller backpressure against the heartbeat
            // timeout. Fast-path `try_reserve()` avoids `select!` and `tx.clone()` when
            // uncontended.
            let permit = match tx.try_reserve() {
                Ok(permit) => permit,
                Err(mpsc::error::TrySendError::Closed(_)) => return,
                Err(mpsc::error::TrySendError::Full(())) => {
                    tokio::select! {
                        biased;
                        _ = shutdown_fut.as_mut() => {
                            self.abort();
                            return;
                        }
                        res = tx.reserve() => match res {
                            Ok(permit) => permit,
                            Err(_) => return,
                        },
                    }
                }
            };

            let item = match self
                .recv_next_item(
                    heartbeat_sleep.as_mut(),
                    shutdown_fut.as_mut(),
                    tx_closed_fut.as_mut(),
                )
                .await
            {
                ControlFlow::Continue(item) => item,
                ControlFlow::Break(()) => {
                    drop(permit);
                    return;
                }
            };

            let flow = match item {
                Ok(Some((batch, reconnect_advised))) => {
                    self.handle_batch(&tx, batch, reconnect_advised, permit)
                        .await
                }
                Ok(None) => {
                    drop(permit);
                    self.handle_eof(&tx).await
                }
                Err(err) => {
                    drop(permit);
                    self.handle_stream_error(&tx, err).await
                }
            };
            if flow.is_break() {
                return;
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

fn convert_and_validate_read_batch(
    proto_batch: proto::ReadBatch,
    last_fetched_seq: Option<u64>,
    compute_metered_bytes: bool,
    context: &ErrorContext,
) -> Result<(ReadBatch, Option<u64>, u64), ReadSessionError> {
    let mut prev = last_fetched_seq;
    let mut metered_bytes: u64 = 0;
    let mut records = Vec::with_capacity(proto_batch.records.len());
    for proto_rec in proto_batch.records {
        if let Some(prev_seq) = prev
            && proto_rec.seq_num <= prev_seq
        {
            return Err(ReadSessionError::Protocol(ProtocolError::new_with_context(
                format!(
                    "read batch contained out-of-order or duplicate seq_num {} after {}",
                    proto_rec.seq_num, prev_seq
                ),
                context.clone(),
            )));
        }
        if proto_rec.seq_num.checked_add(1).is_none() {
            return Err(ReadSessionError::Protocol(ProtocolError::new_with_context(
                "read batch record seq_num u64::MAX has no representable successor",
                context.clone(),
            )));
        }
        prev = Some(proto_rec.seq_num);
        let record = SequencedRecord::from_proto(proto_rec);
        if compute_metered_bytes {
            metered_bytes = metered_bytes.saturating_add(record.metered_bytes() as u64);
        }
        records.push(record);
    }
    let batch = ReadBatch {
        records,
        tail: proto_batch.tail.map(StreamPosition::from_proto),
    };
    Ok((batch, prev, metered_bytes))
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

    use super::*;

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

    fn batch(records: Vec<SequencedRecord>, tail: Option<StreamPosition>) -> ReadBatch {
        ReadBatch { records, tail }
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
        let driver = tokio::spawn(std::future::pending::<()>());
        let session = ReadSession {
            core: ReadSessionCore {
                basin: "test-basin".parse().unwrap(),
                stream: "test-stream".parse().unwrap(),
                rx,
                state: state.clone(),
                shutdown: shutdown.clone(),
                context,
                exhausted: false,
                terminated: false,
                _driver: AbortOnDropHandle::new(driver),
            },
            current_batch: Vec::new().into_iter(),
            unflushed_delivered: 0,
        };
        (session, tx, state, shutdown)
    }

    #[tokio::test]
    async fn clean_stop_final_record_catches_up_then_iteration_end_resets_is_caught_up() {
        let (mut session, tx, state, _shutdown) = test_session_parts(Some(0));
        let cu = session.caught_up();

        let b = batch(vec![record(0), record(1)], Some(position(2)));
        state.on_message_fetched(Some(0), Some(position(2)), 2);
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

        let b = batch(vec![record(0)], None);
        state.on_message_fetched(Some(0), None, 1);
        tx.send(DriverEvent::Batch(b)).await.unwrap();

        assert!(!state.on_message_fetched(None, Some(position(5)), 0));
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
    async fn clean_stop_racing_pending_heartbeat_preserves_progress_and_catch_up() {
        let (mut session, tx, state, _shutdown) = test_session_parts(Some(0));
        let cu = session.caught_up();

        // Driver fetches a heartbeat advancing past a trimmed gap and enqueues it.
        assert!(!state.on_message_fetched(None, Some(position(5)), 0));
        tx.send(DriverEvent::Heartbeat(position(5))).await.unwrap();

        // Simulate the driver observing clean EOF before the consumer delivers the heartbeat.
        assert!(!state.on_clean_stop(None));
        tx.send(DriverEvent::CleanEnd).await.unwrap();

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
    async fn terminal_error_racing_pending_heartbeat_preserves_next_seq_num() {
        let (mut session, tx, state, _shutdown) = test_session_parts(Some(0));
        let cu = session.caught_up();

        assert!(!state.on_message_fetched(None, Some(position(5)), 0));
        tx.send(DriverEvent::Heartbeat(position(5))).await.unwrap();

        let err = ReadSessionError::Timeout(TimeoutError::new_with_context(
            "heartbeat timeout",
            ErrorContext::default().into_read_only(),
        ));
        state.on_disconnected();
        assert!(!state.on_terminal_error(err.clone()));
        tx.send(DriverEvent::Error(err)).await.unwrap();

        let delivered_err = session.next().await.unwrap().unwrap_err();
        assert!(matches!(delivered_err, ReadSessionError::Timeout(_)));
        assert_eq!(session.next_seq_num(), Some(5));
        assert_eq!(session.last_observed_tail(), Some(position(5)));
        assert!(!session.is_caught_up());
        assert!(matches!(cu.await, Err(ReadSessionError::Timeout(_))));
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

        state.on_message_fetched(Some(0), Some(position(1)), 1);
        tx.send(DriverEvent::Batch(batch(
            vec![record(0)],
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
            TimeoutError::new_with_context(
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
    async fn caught_up_fused_and_repoll_after_resolution_does_not_panic() {
        use futures_core::FusedFuture as _;

        let (mut session, tx, state, _shutdown) = test_session_parts(Some(0));
        let mut cu = session.caught_up();
        assert!(!cu.is_terminated());
        assert!(poll!(Pin::new(&mut cu)).is_pending());

        state.on_message_fetched(Some(0), Some(position(1)), 1);
        tx.send(DriverEvent::Batch(batch(
            vec![record(0)],
            Some(position(1)),
        )))
        .await
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
        let proto_rec = |seq_num| proto::SequencedRecord {
            seq_num,
            timestamp: seq_num,
            headers: Vec::new(),
            body: Bytes::new(),
        };
        let b1 = proto::ReadBatch {
            records: vec![proto_rec(0), proto_rec(2)],
            tail: None,
        };
        let (_, last, _) = convert_and_validate_read_batch(b1, None, false, &ctx).unwrap();
        assert_eq!(last, Some(2));

        let dup = proto::ReadBatch {
            records: vec![proto_rec(2)],
            tail: None,
        };
        assert!(matches!(
            convert_and_validate_read_batch(dup, last, false, &ctx),
            Err(ReadSessionError::Protocol(_))
        ));

        let backward_within = proto::ReadBatch {
            records: vec![proto_rec(5), proto_rec(4)],
            tail: None,
        };
        assert!(matches!(
            convert_and_validate_read_batch(backward_within, last, false, &ctx),
            Err(ReadSessionError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn unexpected_driver_exit_surfaces_aborted_rather_than_clean_end() {
        let (mut session, tx, _state, _shutdown) = test_session_parts(Some(0));
        let cu = session.caught_up();
        drop(tx);

        assert!(!session.is_terminated());
        let err = session
            .next()
            .await
            .expect("must not appear as clean stop")
            .unwrap_err();
        assert!(matches!(err, ReadSessionError::Aborted(_)), "{err:?}");
        assert!(!session.is_terminated());
        assert!(session.next().await.is_none());
        assert!(session.is_terminated());
        assert!(matches!(cu.await, Err(ReadSessionError::Aborted(_))));
    }

    #[tokio::test]
    async fn mid_batch_record_delivery_and_interleaved_heartbeat_update_caught_up_accurately() {
        let (mut session, tx, state, _shutdown) = test_session_parts(Some(0));
        let mut cu = session.caught_up();

        // Simulate a fetched 3-record batch (seq 0, 1, 2) with tail=3.
        state.on_message_fetched(Some(0), Some(position(3)), 3);
        tx.send(DriverEvent::Batch(ReadBatch::new(
            vec![
                SequencedRecord::new(0, Bytes::from_static(b"a"), Vec::new(), 10),
                SequencedRecord::new(1, Bytes::from_static(b"b"), Vec::new(), 11),
                SequencedRecord::new(2, Bytes::from_static(b"c"), Vec::new(), 12),
            ],
            Some(position(3)),
        )))
        .await
        .unwrap();

        // Deliver record 0 (mid-batch lock-free path): next_seq advances to 1, still not caught up.
        let r0 = session.next().await.unwrap().unwrap();
        assert_eq!(r0.seq_num, 0);
        assert_eq!(state.next_seq_num(), Some(1));
        assert!(!state.is_caught_up());
        assert!(poll!(Pin::new(&mut cu)).is_pending());

        // Interleave a heartbeat advancing tail to 5 while records 1 & 2 are still buffered
        // locally.
        assert!(!state.on_message_fetched(None, Some(position(5)), 0));
        tx.send(DriverEvent::Heartbeat(position(5))).await.unwrap();

        // Deliver record 1 (mid-batch) and record 2 (end of batch -> flushes on_records_delivered).
        let r1 = session.next().await.unwrap().unwrap();
        assert_eq!(r1.seq_num, 1);
        assert_eq!(state.next_seq_num(), Some(2));
        assert!(!state.is_caught_up());

        let r2 = session.next().await.unwrap().unwrap();
        assert_eq!(r2.seq_num, 2);
        assert_eq!(state.next_seq_num(), Some(3));
        assert!(!state.is_caught_up());

        // Polling next consumes the queued Heartbeat(5) which advances next_seq to 5 and resolves
        // caught_up.
        state.on_clean_stop(Some(position(5)));
        tx.send(DriverEvent::CleanEnd).await.unwrap();
        assert!(session.next().await.is_none());
        assert_eq!(state.next_seq_num(), Some(5));
        assert_eq!(cu.await.unwrap(), position(5));
    }
}
