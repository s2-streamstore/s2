use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    pin::{Pin, pin},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_core::Stream;
use futures_util::{FutureExt, StreamExt};
use s2_api::v1::stream::{proto, s2s};
use tokio::{
    sync::{Notify, mpsc, oneshot, watch},
    time::{Instant, Sleep},
};
use tracing::{Instrument, debug, debug_span};

use crate::{
    api::{BasinClient, Streaming},
    batching::RECORD_BATCH_MIN,
    client::CancellationToken,
    error::{
        AbortedError, AppendSessionError, ConnectionLostError, ErrorContext, ProtocolError,
        SessionClosedError, TimeoutError, TransportError,
    },
    reconnect::AdvisedReconnects,
    retry::RetryBackoff,
    session::{FinishOnDrop, StreamHeaders, SubmitTicket, validate_max_unacked_bytes},
    types::{
        AppendAck, AppendInput, AppendRetryPolicy, BasinName, MeteredBytes, ONE_MIB, StreamConfig,
        StreamName, StreamPosition, ValidationError,
    },
};

/// Chunk size used when streaming encoded S2S frames into HTTP/2 DATA frames so wire-send
/// progress tracks HTTP/2 flow control (`T7c`, `T10`).
const FRAME_CHUNK_BYTES: usize = 16 * 1024;

/// A [`Future`] that resolves to an acknowledgement once the batch of records is appended.
pub struct BatchSubmitTicket(SubmitTicket<AppendAck>);

impl fmt::Debug for BatchSubmitTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BatchSubmitTicket").finish_non_exhaustive()
    }
}

impl Future for BatchSubmitTicket {
    type Output = Result<AppendAck, AppendSessionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
/// Configuration for an [`AppendSession`].
pub struct AppendSessionConfig {
    max_unacked_bytes: u32,
    max_unacked_batches: Option<u32>,
    stream_config: Option<StreamConfig>,
}

impl Default for AppendSessionConfig {
    fn default() -> Self {
        Self {
            max_unacked_bytes: 5 * ONE_MIB,
            max_unacked_batches: None,
            stream_config: None,
        }
    }
}

impl AppendSessionConfig {
    /// Create a new [`AppendSessionConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the limit on total metered bytes of unacknowledged [`AppendInput`]s held in memory.
    pub fn max_unacked_bytes(&self) -> u32 {
        self.max_unacked_bytes
    }

    /// Return the limit on number of unacknowledged [`AppendInput`]s held in memory, if set.
    pub fn max_unacked_batches(&self) -> Option<u32> {
        self.max_unacked_batches
    }

    /// Return the stream configuration to apply if the stream is created on append, if set.
    pub fn stream_config(&self) -> Option<&StreamConfig> {
        self.stream_config.as_ref()
    }

    /// Set the limit on total metered bytes of unacknowledged [`AppendInput`]s held in memory.
    ///
    /// **Note:** It must be at least `1MiB`.
    ///
    /// Defaults to `5MiB`.
    pub fn with_max_unacked_bytes(self, max_unacked_bytes: u32) -> Result<Self, ValidationError> {
        let max_unacked_bytes = validate_max_unacked_bytes(max_unacked_bytes)?;
        Ok(Self {
            max_unacked_bytes,
            ..self
        })
    }

    /// Set the limit on number of unacknowledged [`AppendInput`]s held in memory.
    ///
    /// **Note:** Must be at least `1`.
    ///
    /// Defaults to no limit.
    pub fn with_max_unacked_batches(
        self,
        max_unacked_batches: u32,
    ) -> Result<Self, ValidationError> {
        if max_unacked_batches == 0 {
            return Err("max_unacked_batches must be at least 1".into());
        }
        Ok(Self {
            max_unacked_batches: Some(max_unacked_batches),
            ..self
        })
    }

    /// Set the stream configuration to apply if the stream is created on append.
    ///
    /// Unset fields inherit the basin's default stream configuration. Ignored if the stream
    /// already exists.
    ///
    /// Defaults to `None`.
    pub fn with_stream_config(self, stream_config: StreamConfig) -> Self {
        Self {
            stream_config: Some(stream_config),
            ..self
        }
    }
}

#[derive(Clone)]
enum LifecycleState {
    Open,
    Closing { failure: Option<AppendSessionError> },
    Closed(Result<(), AppendSessionError>),
}

/// Shared lifecycle coordination for [`AppendSession`] and [`Producer`](crate::producer::Producer).
///
/// Guarantees:
/// - Transitions out of `Open` immediately when `close()` starts or when the session terminates,
///   waking any `reserve()`/`submit()` waiting on capacity (`A4c`).
/// - Repeated or concurrent `close(&self)` calls return the exact same `Result` (`A8a`).
/// - Dropping a `close(&self)` future cancels only that wait (`T8`).
pub(crate) struct SessionLifecycle {
    state: watch::Sender<LifecycleState>,
}

impl SessionLifecycle {
    pub(crate) fn new() -> Self {
        let (state, _) = watch::channel(LifecycleState::Open);
        Self { state }
    }

    pub(crate) fn is_closing_or_closed(&self) -> bool {
        !matches!(*self.state.borrow(), LifecycleState::Open)
    }

    pub(crate) fn is_closed(&self) -> bool {
        matches!(*self.state.borrow(), LifecycleState::Closed(_))
    }

    /// Transition `Open -> Closing { failure: None }`. Returns `true` if this call performed the
    /// transition.
    pub(crate) fn mark_closing(&self) -> bool {
        self.state.send_if_modified(|s| {
            if matches!(s, LifecycleState::Open) {
                *s = LifecycleState::Closing { failure: None };
                true
            } else {
                false
            }
        })
    }

    pub(crate) fn set_terminal_err(&self, err: AppendSessionError) {
        self.state.send_if_modified(|s| match s {
            LifecycleState::Open | LifecycleState::Closing { .. } => {
                *s = LifecycleState::Closing { failure: Some(err) };
                true
            }
            LifecycleState::Closed(_) => false,
        });
    }

    pub(crate) fn terminal_err(&self) -> Option<AppendSessionError> {
        match &*self.state.borrow() {
            LifecycleState::Open => None,
            LifecycleState::Closing { failure } => failure.clone(),
            LifecycleState::Closed(res) => res.as_ref().err().cloned(),
        }
    }

    pub(crate) fn session_closed_err(&self, context: &ErrorContext) -> AppendSessionError {
        AppendSessionError::SessionClosed(SessionClosedError::new(
            self.terminal_err(),
            context.clone(),
        ))
    }

    pub(crate) fn finish(&self, result: Result<(), AppendSessionError>) {
        self.state.send_if_modified(|s| {
            if matches!(s, LifecycleState::Closed(_)) {
                false
            } else {
                *s = LifecycleState::Closed(result);
                true
            }
        });
    }

    pub(crate) async fn wait_closing_or_closed(&self) {
        let mut rx = self.state.subscribe();
        let _ = rx.wait_for(|s| !matches!(s, LifecycleState::Open)).await;
    }

    pub(crate) async fn wait_closed(&self) -> Result<(), AppendSessionError> {
        let mut rx = self.state.subscribe();
        let guard = rx
            .wait_for(|s| matches!(s, LifecycleState::Closed(_)))
            .await
            .expect("watch sender owned by self");
        match &*guard {
            LifecycleState::Closed(res) => res.clone(),
            _ => unreachable!("wait_for guarantees Closed"),
        }
    }
}

/// Shared append-session core used by both [`AppendSession`] and
/// [`Producer`](crate::producer::Producer).
pub(crate) struct AppendSessionCore {
    basin: BasinName,
    stream: StreamName,
    compression: s2s::CompressionAlgorithm,
    /// Serializes command acceptance and `close()` initiation so every `submit()` returning `Ok`
    /// is ordered strictly before `Command::Close` in the unbounded channel (`A4c`, `A8a`).
    gate: Arc<StdMutex<()>>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    lifecycle: Arc<SessionLifecycle>,
    client_shutdown: CancellationToken,
    /// Child token of `client_shutdown`; cancelled on either client close or session drop/abort.
    abort: CancellationToken,
    unacked_batches: Arc<AtomicUsize>,
    dropped_abort_msg: &'static str,
    context: ErrorContext,
}

impl AppendSessionCore {
    pub(crate) fn new(
        client: BasinClient,
        stream: StreamName,
        headers: StreamHeaders,
        op: &'static str,
        dropped_abort_msg: &'static str,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let gate = Arc::new(StdMutex::new(()));
        let lifecycle = Arc::new(SessionLifecycle::new());
        let client_shutdown = client.shutdown_token();
        let abort = client_shutdown.child_token();
        let unacked_batches = Arc::new(AtomicUsize::new(0));
        let basin = client.name.clone();
        let compression: s2s::CompressionAlgorithm = client.config().compression.into();
        let context = ErrorContext::stream(op, basin.as_ref(), stream.as_ref(), false);

        let span = debug_span!("append_session", op, basin = %basin, stream = %stream);
        let task = AppendSessionTask {
            client,
            stream: stream.clone(),
            headers,
            op,
            gate: gate.clone(),
            lifecycle: lifecycle.clone(),
            client_shutdown: client_shutdown.clone(),
            abort: abort.clone(),
            dropped_abort_msg,
            context: context.clone(),
            state: SessionState {
                cmd_rx,
                inflight_appends: VecDeque::new(),
                closing: false,
                prev_ack_end: None,
                unacked_batches: unacked_batches.clone(),
            },
        };
        tokio::spawn(task.run().instrument(span));

        Self {
            basin,
            stream,
            compression,
            gate,
            cmd_tx,
            lifecycle,
            client_shutdown,
            abort,
            unacked_batches,
            dropped_abort_msg,
            context,
        }
    }

    pub(crate) fn lifecycle(&self) -> &Arc<SessionLifecycle> {
        &self.lifecycle
    }

    pub(crate) fn terminal_err(&self) -> Option<AppendSessionError> {
        self.lifecycle.terminal_err()
    }

    fn session_closed_err_on_submit(&self) -> AppendSessionError {
        let failure = self.lifecycle.terminal_err().or_else(|| {
            if self.unacked_batches.load(Ordering::Acquire) > 0 && self.abort.is_cancelled() {
                let reason = abort_reason_msg(&self.client_shutdown, self.dropped_abort_msg);
                Some(AppendSessionError::Aborted(AbortedError::new(
                    reason,
                    self.context.clone(),
                )))
            } else {
                None
            }
        });
        AppendSessionError::SessionClosed(SessionClosedError::new(failure, self.context.clone()))
    }

    pub(crate) fn submit(
        &self,
        input: AppendInput,
        permit: Option<AppendPermit>,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
        if self.lifecycle.is_closing_or_closed() || self.abort.is_cancelled() {
            return Err(self.session_closed_err_on_submit());
        }

        // Encode and compress on the caller task before taking the gate so the session task stays
        // focused on network I/O and state transitions.
        let record_count = input.records.len() as u64;
        let api_input: proto::AppendInput = input.into();
        let frame = s2s::SessionMessage::regular(self.compression, &api_input)
            .map_err(|err| {
                AppendSessionError::Protocol(ProtocolError::new(
                    format!("failed to encode append frame: {err}"),
                    self.context.clone(),
                ))
            })?
            .encode();

        let (ack_tx, ack_rx) = oneshot::channel();
        {
            let _gate = self.gate.lock().unwrap();
            if self.lifecycle.is_closing_or_closed() || self.abort.is_cancelled() {
                return Err(self.session_closed_err_on_submit());
            }
            if self
                .cmd_tx
                .send(Command::Submit {
                    frame,
                    record_count,
                    ack_tx,
                    permit,
                })
                .is_err()
            {
                return Err(self.session_closed_err_on_submit());
            }
            self.unacked_batches.fetch_add(1, Ordering::Release);
        }
        Ok(BatchSubmitTicket(SubmitTicket::new(
            ack_rx,
            self.lifecycle.clone(),
            self.context.clone(),
            self.dropped_abort_msg,
        )))
    }

    pub(crate) async fn close(&self) -> Result<(), AppendSessionError> {
        {
            let _gate = self.gate.lock().unwrap();
            if !self.abort.is_cancelled() && self.lifecycle.mark_closing() {
                let _ = self.cmd_tx.send(Command::Close);
            }
        }
        self.lifecycle.wait_closed().await
    }

    pub(crate) fn abort(&self) {
        if !self.lifecycle.is_closed() {
            self.abort.cancel();
        }
    }
}

impl Drop for AppendSessionCore {
    fn drop(&mut self) {
        self.abort();
    }
}

/// A session for high-throughput appending with backpressure control. It can be created from
/// [`append_session`](crate::S2Stream::append_session).
///
/// Supports pipelining multiple [`AppendInput`]s while preserving submission order. Opening a
/// session sends no request until the first batch is submitted.
#[must_use = "append sessions do nothing unless batches are submitted"]
pub struct AppendSession {
    core: Arc<AppendSessionCore>,
    permits: AppendPermits,
}

impl fmt::Debug for AppendSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppendSession")
            .field("basin", &self.core.basin)
            .field("stream", &self.core.stream)
            .field("unacked_bytes", &self.permits.in_flight_bytes())
            .field(
                "unacked_batches",
                &self.core.unacked_batches.load(Ordering::Relaxed),
            )
            .field(
                "closing_or_closed",
                &self.core.lifecycle.is_closing_or_closed(),
            )
            .finish_non_exhaustive()
    }
}

impl AppendSession {
    pub(crate) fn new(
        client: BasinClient,
        stream: StreamName,
        headers: StreamHeaders,
        config: AppendSessionConfig,
    ) -> Self {
        let permits = AppendPermits::new(config.max_unacked_batches, config.max_unacked_bytes);
        let core = Arc::new(AppendSessionCore::new(
            client,
            stream,
            headers,
            "append_session",
            "append session dropped without calling close",
        ));
        Self { core, permits }
    }

    /// Submit a batch of records for appending.
    ///
    /// Accepts an [`AppendInput`], [`AppendRecordBatch`](crate::types::AppendRecordBatch),
    /// [`AppendRecord`](crate::types::AppendRecord), or
    /// [`CommandRecord`](crate::types::CommandRecord).
    ///
    /// Internally, it waits on [`reserve`](Self::reserve), then submits using the permit.
    /// This provides backpressure when unacknowledged limits are reached.
    /// For explicit control, use [`reserve`](Self::reserve) followed by
    /// [`BatchSubmitPermit::submit`].
    ///
    /// **Note**: After all submits, call [`close`](Self::close) to ensure all batches are
    /// appended. Dropping the session without closing aborts it.
    pub async fn submit(
        &self,
        input: impl Into<AppendInput>,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
        let input = input.into();
        let bytes = input.records.metered_bytes() as u32;
        let permit = self.reserve(bytes).await?;
        permit.submit(input)
    }

    /// Reserve capacity for a batch of up to `bytes` metered bytes to be submitted.
    ///
    /// Useful in [`select!`](tokio::select) loops where you want to interleave submission with
    /// other async work. See [`submit`](Self::submit) for a simpler API.
    ///
    /// Capacity is granted FIFO. Validated before waiting; `bytes` must be between `8` and `1MiB`.
    /// If the session closes or begins closing while waiting, returns [`SessionClosedError`].
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. Dropping the future before completion accepts nothing and
    /// releases any partially acquired reservation.
    pub async fn reserve(&self, bytes: u32) -> Result<BatchSubmitPermit, AppendSessionError> {
        validate_reserve_bytes(bytes, ONE_MIB)?;

        self.check_open_for_reserve().await?;

        let append_permit = tokio::select! {
            biased;
            _ = self.core.lifecycle.wait_closing_or_closed() => {
                return Err(self.core.lifecycle.session_closed_err(&self.core.context));
            }
            permit = self.permits.acquire(bytes) => permit,
        };

        self.check_open_for_reserve().await?;

        Ok(BatchSubmitPermit {
            append_permit,
            reserved_bytes: bytes,
            core: self.core.clone(),
        })
    }

    async fn check_open_for_reserve(&self) -> Result<(), AppendSessionError> {
        if self.core.lifecycle.is_closing_or_closed() {
            return Err(self.core.lifecycle.session_closed_err(&self.core.context));
        }
        if self.core.abort.is_cancelled() {
            self.core.lifecycle.wait_closing_or_closed().await;
            return Err(self.core.lifecycle.session_closed_err(&self.core.context));
        }
        Ok(())
    }

    /// Close the session and wait for all accepted batches to reach an outcome.
    ///
    /// Calling `close()` stops accepting new submissions immediately and waits until all
    /// already-accepted batches settle. Repeated or concurrent calls to `close()` return the same
    /// result. Dropping a `close()` future cancels only the wait; dropping the [`AppendSession`]
    /// aborts it.
    pub async fn close(&self) -> Result<(), AppendSessionError> {
        self.core.close().await
    }
}

impl Drop for AppendSession {
    fn drop(&mut self) {
        self.core.abort();
    }
}

/// A permit to submit a batch after reserving capacity.
#[must_use = "a permit reserves session capacity; call `.submit(...)` to send the batch"]
pub struct BatchSubmitPermit {
    append_permit: AppendPermit,
    reserved_bytes: u32,
    core: Arc<AppendSessionCore>,
}

impl fmt::Debug for BatchSubmitPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BatchSubmitPermit")
            .field("reserved_bytes", &self.reserved_bytes)
            .finish_non_exhaustive()
    }
}

impl BatchSubmitPermit {
    /// Submit the batch using this permit.
    ///
    /// Fails with [`ValidationError`] (releasing the reservation and leaving the session open) if
    /// the batch's metered size exceeds the reserved bytes. Fails with [`SessionClosedError`] if
    /// the session closed or began closing after the permit was reserved.
    pub fn submit(
        mut self,
        input: impl Into<AppendInput>,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
        let input = input.into();
        let metered = input.records.metered_bytes();
        if metered > self.reserved_bytes as usize {
            return Err(AppendSessionError::Validation(ValidationError(format!(
                "batch size in metered bytes ({metered}) exceeds reserved capacity ({})",
                self.reserved_bytes
            ))));
        }

        // Release any unused over-reserved capacity immediately (`A4a`).
        self.append_permit.shrink(metered as u32);
        self.core.submit(input, Some(self.append_permit))
    }
}

pub(crate) fn validate_reserve_bytes(bytes: u32, max_bytes: u32) -> Result<(), AppendSessionError> {
    if (bytes as usize) < RECORD_BATCH_MIN.bytes {
        return Err(AppendSessionError::Validation(ValidationError(format!(
            "reserved bytes ({bytes}) must be at least {}",
            RECORD_BATCH_MIN.bytes
        ))));
    }
    if bytes > max_bytes {
        return Err(AppendSessionError::Validation(ValidationError(format!(
            "reserved bytes ({bytes}) exceeds maximum ({max_bytes})"
        ))));
    }
    Ok(())
}

struct PermitWaiter {
    id: u64,
    bytes: u32,
    granted: oneshot::Sender<()>,
}

struct PermitsState {
    available_batches: Option<u32>,
    total_bytes: u32,
    available_bytes: u32,
    next_waiter_id: u64,
    waiters: VecDeque<PermitWaiter>,
}

impl PermitsState {
    fn can_satisfy(&self, bytes: u32) -> bool {
        self.available_batches.is_none_or(|c| c >= 1) && self.available_bytes >= bytes
    }

    fn take(&mut self, bytes: u32) {
        if let Some(c) = self.available_batches.as_mut() {
            *c -= 1;
        }
        self.available_bytes -= bytes;
    }

    fn release(&mut self, bytes: u32) {
        if let Some(c) = self.available_batches.as_mut() {
            *c += 1;
        }
        self.available_bytes += bytes;
        self.grant_next();
    }

    fn grant_next(&mut self) {
        while let Some(front) = self.waiters.front() {
            if !self.can_satisfy(front.bytes) {
                break;
            }
            let waiter = self.waiters.pop_front().expect("checked front");
            self.take(waiter.bytes);
            if waiter.granted.send(()).is_err() {
                // Waiter was dropped concurrently; immediately refund and continue FIFO granting.
                if let Some(c) = self.available_batches.as_mut() {
                    *c += 1;
                }
                self.available_bytes += waiter.bytes;
            }
        }
    }
}

pub(crate) struct AppendPermit {
    inner: Arc<StdMutex<PermitsState>>,
    bytes: u32,
    has_batch_slot: bool,
}

impl fmt::Debug for AppendPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppendPermit")
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl AppendPermit {
    /// Release excess over-reserved byte capacity immediately once exact size is known.
    pub(crate) fn shrink(&mut self, new_bytes: u32) {
        if new_bytes < self.bytes {
            let excess = self.bytes - new_bytes;
            self.bytes = new_bytes;
            let mut state = self.inner.lock().unwrap();
            state.available_bytes += excess;
            state.grant_next();
        }
    }

    /// Merge another byte-only permit from the same pool into `self` without acquiring the mutex.
    pub(crate) fn merge(&mut self, mut other: AppendPermit) {
        debug_assert!(Arc::ptr_eq(&self.inner, &other.inner));
        debug_assert!(!self.has_batch_slot && !other.has_batch_slot);
        self.bytes = self
            .bytes
            .checked_add(other.bytes)
            .expect("merged permit bytes cannot exceed pool capacity");
        other.bytes = 0;
    }
}

impl Drop for AppendPermit {
    fn drop(&mut self) {
        if self.bytes == 0 && !self.has_batch_slot {
            return;
        }
        let mut state = self.inner.lock().unwrap();
        state.release(self.bytes);
    }
}

#[derive(Clone)]
pub(crate) struct AppendPermits {
    inner: Arc<StdMutex<PermitsState>>,
}

impl AppendPermits {
    pub(crate) fn new(count_permits: Option<u32>, bytes_permits: u32) -> Self {
        Self {
            inner: Arc::new(StdMutex::new(PermitsState {
                available_batches: count_permits,
                total_bytes: bytes_permits,
                available_bytes: bytes_permits,
                next_waiter_id: 0,
                waiters: VecDeque::new(),
            })),
        }
    }

    pub(crate) fn in_flight_bytes(&self) -> u32 {
        let state = self.inner.lock().unwrap();
        state.total_bytes - state.available_bytes
    }

    pub(crate) fn has_waiters(&self) -> bool {
        !self.inner.lock().unwrap().waiters.is_empty()
    }

    #[cfg(test)]
    fn try_acquire(&self, bytes: u32) -> Option<AppendPermit> {
        let mut state = self.inner.lock().unwrap();
        if state.waiters.is_empty() && state.can_satisfy(bytes) {
            let has_batch_slot = state.available_batches.is_some();
            state.take(bytes);
            Some(AppendPermit {
                inner: self.inner.clone(),
                bytes,
                has_batch_slot,
            })
        } else {
            None
        }
    }

    pub(crate) async fn acquire(&self, bytes: u32) -> AppendPermit {
        self.acquire_inner(bytes, None).await
    }

    /// Acquire capacity FIFO, notifying `on_wait` strictly after enqueueing this waiter so a
    /// woken consumer is guaranteed to observe `has_waiters() == true` (`A5a`).
    pub(crate) async fn acquire_notifying(&self, bytes: u32, on_wait: &Notify) -> AppendPermit {
        self.acquire_inner(bytes, Some(on_wait)).await
    }

    async fn acquire_inner(&self, bytes: u32, on_wait: Option<&Notify>) -> AppendPermit {
        struct AcquireGuard<'a> {
            inner: &'a StdMutex<PermitsState>,
            id: u64,
            bytes: u32,
            rx: oneshot::Receiver<()>,
            acquired: bool,
        }

        impl Drop for AcquireGuard<'_> {
            fn drop(&mut self) {
                if self.acquired {
                    return;
                }
                let mut state = self.inner.lock().unwrap();
                if let Some(pos) = state.waiters.iter().position(|w| w.id == self.id) {
                    state.waiters.remove(pos);
                    state.grant_next();
                } else if self.rx.try_recv().is_ok() {
                    // Grant raced with cancellation; refund immediately.
                    state.release(self.bytes);
                }
            }
        }

        let (has_batch_slot, mut guard) = {
            let mut state = self.inner.lock().unwrap();
            let has_batch_slot = state.available_batches.is_some();
            if state.waiters.is_empty() && state.can_satisfy(bytes) {
                state.take(bytes);
                return AppendPermit {
                    inner: self.inner.clone(),
                    bytes,
                    has_batch_slot,
                };
            }
            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let (tx, rx) = oneshot::channel();
            state.waiters.push_back(PermitWaiter {
                id,
                bytes,
                granted: tx,
            });
            (
                has_batch_slot,
                AcquireGuard {
                    inner: &self.inner,
                    id,
                    bytes,
                    rx,
                    acquired: false,
                },
            )
        };

        if let Some(notify) = on_wait {
            notify.notify_one();
        }

        (&mut guard.rx)
            .await
            .expect("permit waiter sender stays alive while AppendPermits is borrowed");
        guard.acquired = true;
        AppendPermit {
            inner: self.inner.clone(),
            bytes,
            has_batch_slot,
        }
    }
}

struct SessionState {
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    inflight_appends: VecDeque<InflightAppend>,
    closing: bool,
    prev_ack_end: Option<StreamPosition>,
    unacked_batches: Arc<AtomicUsize>,
}

impl SessionState {
    fn is_close_complete(&self) -> bool {
        self.closing && self.inflight_appends.is_empty()
    }

    fn push_submit(
        &mut self,
        frame: Bytes,
        record_count: u64,
        ack_tx: oneshot::Sender<Result<AppendAck, AppendSessionError>>,
        permit: Option<AppendPermit>,
    ) {
        debug_assert!(!self.closing, "gate orders all Submits before Close");
        self.inflight_appends.push_back(InflightAppend {
            frame,
            record_count,
            ack_tx,
            _permit: permit,
            sent_ever: false,
            prior_uncertainty: false,
            attempt_last_byte_rx: None,
        });
    }

    fn drain_queued_commands(&mut self) -> Vec<Command> {
        self.cmd_rx.close();
        let mut queued = Vec::new();
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            queued.push(cmd);
        }
        queued
    }
}

struct InflightAppend {
    /// Pre-encoded and compressed S2S frame; cloning on resend is O(1).
    frame: Bytes,
    record_count: u64,
    ack_tx: oneshot::Sender<Result<AppendAck, AppendSessionError>>,
    _permit: Option<AppendPermit>,
    sent_ever: bool,
    prior_uncertainty: bool,
    attempt_last_byte_rx: Option<oneshot::Receiver<Instant>>,
}

enum Command {
    Submit {
        frame: Bytes,
        record_count: u64,
        ack_tx: oneshot::Sender<Result<AppendAck, AppendSessionError>>,
        permit: Option<AppendPermit>,
    },
    Close,
}

/// Race-free gate between the session task and `AttemptBodyStream` (`Terms: Sent`, `T10`).
struct AttemptSendGate {
    stopped: bool,
    batches_started: usize,
}

impl AttemptSendGate {
    fn new() -> Arc<StdMutex<Self>> {
        Arc::new(StdMutex::new(Self {
            stopped: false,
            batches_started: 0,
        }))
    }

    fn stop(gate: &StdMutex<Self>) -> usize {
        let mut g = gate.lock().unwrap();
        g.stopped = true;
        g.batches_started
    }
}

struct OutboundBatch {
    remaining: Bytes,
    last_byte_tx: Option<oneshot::Sender<Instant>>,
}

impl OutboundBatch {
    fn next_chunk(&mut self) -> Bytes {
        let take_len = self.remaining.len().min(FRAME_CHUNK_BYTES);
        let chunk = self.remaining.split_to(take_len);
        if self.remaining.is_empty()
            && let Some(tx) = self.last_byte_tx.take()
        {
            let _ = tx.send(Instant::now());
        }
        chunk
    }
}

struct AttemptBodyStream {
    rx: mpsc::Receiver<OutboundBatch>,
    current: Option<OutboundBatch>,
    gate: Arc<StdMutex<AttemptSendGate>>,
    aborted: bool,
}

impl AttemptBodyStream {
    fn new(rx: mpsc::Receiver<OutboundBatch>, gate: Arc<StdMutex<AttemptSendGate>>) -> Self {
        Self {
            rx,
            current: None,
            gate,
            aborted: false,
        }
    }

    fn abort_err() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "attempt ended")
    }
}

impl Stream for AttemptBodyStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if this.aborted {
            return Poll::Ready(None);
        }

        if let Some(active) = this.current.as_mut() {
            if this.gate.lock().unwrap().stopped {
                this.current = None;
                this.aborted = true;
                return Poll::Ready(Some(Err(Self::abort_err())));
            }
            let chunk = active.next_chunk();
            if active.remaining.is_empty() {
                this.current = None;
            }
            return Poll::Ready(Some(Ok(chunk)));
        }

        match this.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                if this.gate.lock().unwrap().stopped {
                    this.aborted = true;
                    Poll::Ready(Some(Err(Self::abort_err())))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Ready(Some(mut batch)) => {
                {
                    let mut gate = this.gate.lock().unwrap();
                    if gate.stopped {
                        this.aborted = true;
                        return Poll::Ready(Some(Err(Self::abort_err())));
                    }
                    gate.batches_started += 1;
                }
                let chunk = batch.next_chunk();
                if !batch.remaining.is_empty() {
                    this.current = Some(batch);
                }
                Poll::Ready(Some(Ok(chunk)))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerKind {
    /// Waiting for the oldest sent batch to be acknowledged (`T7c`).
    Ack,
    /// Request body was dropped by hyper while waiting for a response error or EOF.
    BodyClosed,
}

enum AttemptResult {
    /// Everything accepted was acknowledged and the caller closed the session.
    Closed,
    /// Connection ended cleanly or broke while nothing was unacked (`A3`, `T9`).
    IdleEnded,
    /// Server advised reconnecting and all sent batches drained cleanly (`T6a`).
    ReconnectAdvised { made_progress: bool },
    /// Session was aborted (`C12`, `A8c`).
    Aborted(&'static str),
    /// Attempt failed with an error.
    Error {
        err: AppendSessionError,
        made_progress: bool,
        unacked_sent_in_attempt: usize,
    },
}

enum IdleWait {
    WorkReady,
    Closed,
    Aborted(&'static str),
}

struct AppendSessionTask {
    client: BasinClient,
    stream: StreamName,
    headers: StreamHeaders,
    op: &'static str,
    gate: Arc<StdMutex<()>>,
    lifecycle: Arc<SessionLifecycle>,
    client_shutdown: CancellationToken,
    abort: CancellationToken,
    dropped_abort_msg: &'static str,
    context: ErrorContext,
    state: SessionState,
}

impl AppendSessionTask {
    fn abort_reason_msg(&self) -> &'static str {
        abort_reason_msg(&self.client_shutdown, self.dropped_abort_msg)
    }

    fn check_abort(&self) -> Option<&'static str> {
        self.abort.is_cancelled().then(|| self.abort_reason_msg())
    }

    async fn run(mut self) {
        let _finish_guard = FinishOnDrop::new(
            self.lifecycle.clone(),
            self.context.clone(),
            self.dropped_abort_msg,
        );
        let refreshes_tokens = self.client.base().refreshes_tokens();
        let retry_config = self.client.base().retry_config();
        let mut retry_backoff = RetryBackoff::from_config(&retry_config);
        let mut advised_reconnects = AdvisedReconnects::default();

        loop {
            if let Some(reason) = self.check_abort() {
                self.abort_session(reason);
                return;
            }

            // Lazy open (A3, T6): do not open a request until we have a batch to send.
            if self.state.inflight_appends.is_empty() {
                if self.state.is_close_complete() {
                    self.finish_clean();
                    return;
                }
                match self.wait_for_work().await {
                    IdleWait::WorkReady => {}
                    IdleWait::Closed => {
                        self.finish_clean();
                        return;
                    }
                    IdleWait::Aborted(reason) => {
                        self.abort_session(reason);
                        return;
                    }
                }
            }

            let attempt_num = retry_backoff.attempt_number();
            debug!(
                attempt = attempt_num,
                inflight = self.state.inflight_appends.len(),
                "opening append session request"
            );
            let result = self.run_attempt(advised_reconnects, attempt_num).await;

            match result {
                AttemptResult::Closed => {
                    self.finish_clean();
                    return;
                }
                AttemptResult::IdleEnded => {
                    // T9 / A3: clean end or break while nothing is unacked is not an error and uses
                    // no budget. Reset retry state so earlier transient failures do not leak across
                    // an idle gap.
                    retry_backoff.reset();
                }
                AttemptResult::ReconnectAdvised { made_progress } => {
                    advised_reconnects.record();
                    if made_progress {
                        retry_backoff.reset();
                    }
                    debug!(
                        inflight_appends_len = self.state.inflight_appends.len(),
                        advised_reconnects = advised_reconnects.total(),
                        "reconnecting append session on server advice"
                    );
                }
                AttemptResult::Aborted(reason) => {
                    self.abort_session(reason);
                    return;
                }
                AttemptResult::Error {
                    mut err,
                    made_progress,
                    unacked_sent_in_attempt,
                } => {
                    if made_progress {
                        retry_backoff.reset();
                    }

                    if err.is_server_draining() && self.state.is_close_complete() {
                        self.finish_clean();
                        return;
                    }
                    if err.is_server_draining() && made_progress {
                        debug!(
                            inflight_appends_len = self.state.inflight_appends.len(),
                            "reconnecting append session while server drains"
                        );
                        continue;
                    }

                    // E3 / Terms: ConnectionLostError is definite if nothing unacked was sent in
                    // this attempt.
                    err = err.mark_unsent_connection_lost(unacked_sent_in_attempt == 0);

                    let attempts = retry_backoff.attempt_number();
                    let err = err.with_context(&self.context.clone().with_attempts(attempts));
                    let attempt_may_have_side_effects =
                        unacked_sent_in_attempt > 0 && !err.has_no_side_effects();

                    if is_safe_to_retry(
                        &err,
                        retry_config.append_retry_policy,
                        attempt_may_have_side_effects,
                        refreshes_tokens,
                    ) && let Some(backoff) = retry_backoff.next()
                    {
                        if attempt_may_have_side_effects {
                            for append in self
                                .state
                                .inflight_appends
                                .iter_mut()
                                .take(unacked_sent_in_attempt)
                            {
                                append.prior_uncertainty = true;
                            }
                        }
                        debug!(
                            %err,
                            attempt = attempts,
                            ?backoff,
                            num_retries_remaining = retry_backoff.remaining(),
                            "retrying append session"
                        );
                        if let Some(reason) = self.sleep_or_abort(backoff).await {
                            self.abort_session(reason);
                            return;
                        }
                    } else {
                        debug!(
                            %err,
                            attempt = attempts,
                            retries_exhausted = retry_backoff.is_exhausted(),
                            "not retrying append session"
                        );
                        self.settle_terminal_error(err, unacked_sent_in_attempt);
                        return;
                    }
                }
            }
        }
    }

    async fn wait_for_work(&mut self) -> IdleWait {
        tokio::select! {
            biased;
            _ = self.abort.cancelled() => IdleWait::Aborted(self.abort_reason_msg()),
            cmd = self.state.cmd_rx.recv() => match cmd {
                Some(Command::Submit {
                    frame,
                    record_count,
                    ack_tx,
                    permit,
                }) => {
                    self.state.push_submit(frame, record_count, ack_tx, permit);
                    IdleWait::WorkReady
                }
                Some(Command::Close) => {
                    self.state.closing = true;
                    IdleWait::Closed
                }
                None => IdleWait::Aborted(self.dropped_abort_msg),
            },
        }
    }

    async fn sleep_or_abort(&self, duration: Duration) -> Option<&'static str> {
        tokio::select! {
            biased;
            _ = self.abort.cancelled() => Some(self.abort_reason_msg()),
            _ = tokio::time::sleep(duration) => None,
        }
    }

    fn finish_clean(&mut self) {
        debug!("append session closed cleanly");
        let queued = {
            let _gate = self.gate.lock().unwrap();
            self.lifecycle.mark_closing();
            self.state.drain_queued_commands()
        };
        let closed_err =
            AppendSessionError::SessionClosed(SessionClosedError::new(None, self.context.clone()));
        for cmd in queued {
            if let Command::Submit { ack_tx, .. } = cmd {
                let _ = ack_tx.send(Err(closed_err.clone()));
            }
        }
        self.lifecycle.finish(Ok(()));
    }

    fn abort_session(&mut self, reason: &'static str) {
        let aborted = AppendSessionError::Aborted(AbortedError::new(reason, self.context.clone()));
        let (queued, has_pending_work) = {
            // Hold gate across checking pending work AND publishing terminal_err / closing so
            // concurrent reserve()/submit() callers never observe
            // `SessionClosedError { failure: None }` on an aborted session with pending work.
            let _gate = self.gate.lock().unwrap();
            let queued = self.state.drain_queued_commands();
            let has_pending_work = !self.state.inflight_appends.is_empty()
                || queued
                    .iter()
                    .any(|cmd| matches!(cmd, Command::Submit { .. }));
            if has_pending_work {
                self.lifecycle.set_terminal_err(aborted.clone());
            } else {
                self.lifecycle.mark_closing();
            }
            (queued, has_pending_work)
        };

        debug!(
            reason,
            has_pending_work,
            inflight_appends_len = self.state.inflight_appends.len(),
            "aborting append session"
        );

        if !has_pending_work {
            // A8c: aborting an idle append session loses nothing, so the close is clean.
            self.lifecycle.finish(Ok(()));
            return;
        }

        let unsent = AppendSessionError::SessionClosed(SessionClosedError::new(
            Some(aborted.clone()),
            self.context.clone(),
        ));

        for append in self.state.inflight_appends.drain(..) {
            let outcome = if append.sent_ever {
                aborted.clone()
            } else {
                unsent.clone()
            };
            let _ = append.ack_tx.send(Err(outcome));
        }

        for cmd in queued {
            if let Command::Submit { ack_tx, .. } = cmd {
                let _ = ack_tx.send(Err(unsent.clone()));
            }
        }

        self.lifecycle.finish(Err(aborted));
    }

    /// Settle all unacked and queued batches according to `A6a`, `A6b`, and `A9`.
    fn settle_terminal_error(
        &mut self,
        final_err: AppendSessionError,
        unacked_sent_in_attempt: usize,
    ) {
        let from_server = matches!(
            final_err,
            AppendSessionError::Server(_)
                | AppendSessionError::SeqNumMismatch(_)
                | AppendSessionError::FencingTokenMismatch(_)
        );
        let rejected =
            from_server && unacked_sent_in_attempt > 0 && !self.state.inflight_appends.is_empty();
        let rejected_definite = rejected && final_err.has_no_side_effects();

        // Batch `i == 0` when `rejected` always has `sent_ever == true` (since
        // `unacked_sent_in_attempt > 0`), so this predicate cleanly separates batches that receive
        // `SessionClosedError` from those that receive `final_err`.
        let gets_closed_err =
            |i: usize, append: &InflightAppend| (i > 0 && rejected_definite) || !append.sent_ever;

        // A6b / A9: determine whether any batch's outcome will be wrapped in IndefiniteAppendError.
        let any_batch_wrapped =
            self.state
                .inflight_appends
                .iter()
                .enumerate()
                .any(|(i, append)| {
                    append.prior_uncertainty
                        && (final_err.has_no_side_effects() || gets_closed_err(i, append))
                });

        // A9: session failure is final_err, wrapped in IndefiniteAppendError if final_err is
        // definite and any batch's outcome was wrapped.
        let session_failure = final_err.clone().with_prior_uncertainty(any_batch_wrapped);

        let queued = {
            let _gate = self.gate.lock().unwrap();
            self.lifecycle.set_terminal_err(session_failure.clone());
            self.state.drain_queued_commands()
        };
        let closed_err = AppendSessionError::SessionClosed(SessionClosedError::new(
            Some(session_failure.clone()),
            self.context.clone(),
        ));

        for (i, append) in self.state.inflight_appends.drain(..).enumerate() {
            let base = if gets_closed_err(i, &append) {
                closed_err.clone()
            } else {
                final_err.clone()
            };
            let _ = append
                .ack_tx
                .send(Err(base.with_prior_uncertainty(append.prior_uncertainty)));
        }

        for cmd in queued {
            if let Command::Submit { ack_tx, .. } = cmd {
                let _ = ack_tx.send(Err(closed_err.clone()));
            }
        }

        self.lifecycle.finish(Err(session_failure));
    }

    async fn run_attempt(
        &mut self,
        advised_reconnects: AdvisedReconnects,
        attempt: u32,
    ) -> AttemptResult {
        for append in &mut self.state.inflight_appends {
            append.attempt_last_byte_rx = None;
        }

        let send_gate = AttemptSendGate::new();
        let (input_tx, input_rx) = mpsc::channel::<OutboundBatch>(1);
        let body_stream = AttemptBodyStream::new(input_rx, send_gate.clone());

        let connect_fut =
            self.client
                .append_session(self.op, &self.stream, body_stream, &self.headers, attempt);

        let mut acks = tokio::select! {
            biased;
            _ = self.abort.cancelled() => {
                AttemptSendGate::stop(&send_gate);
                return AttemptResult::Aborted(self.abort_reason_msg());
            }
            res = connect_fut => match res {
                Ok(s) => s,
                Err(err) => {
                    AttemptSendGate::stop(&send_gate);
                    if let Some(reason) = self.check_abort() {
                        return AttemptResult::Aborted(reason);
                    }
                    return AttemptResult::Error {
                        err,
                        made_progress: false,
                        unacked_sent_in_attempt: 0,
                    };
                }
            }
        };

        let ack_timeout = self.client.base().request_timeout();
        let mut input_tx = Some(input_tx);
        let mut send_cursor: usize = 0;
        let mut acked_in_attempt: usize = 0;
        let mut draining_for_reconnect = false;

        let mut became_oldest_at: Option<Instant> =
            (!self.state.inflight_appends.is_empty()).then(Instant::now);
        let mut ack_timer = pin!(tokio::time::sleep(Duration::ZERO));
        let mut timer_kind: Option<TimerKind> = None;

        loop {
            if self.state.is_close_complete() {
                drop(input_tx);
                drop(acks);
                return AttemptResult::Closed;
            }

            if input_tx.is_none()
                && !draining_for_reconnect
                && self.state.inflight_appends.is_empty()
            {
                drop(acks);
                return AttemptResult::IdleEnded;
            }

            // Check if the oldest unacked batch already finished sending its last byte (e.g. while
            // pipelined behind an earlier batch), and arm the T7c timer immediately if so.
            refresh_oldest_timer(
                &mut self.state,
                became_oldest_at,
                ack_timeout,
                ack_timer.as_mut(),
                &mut timer_kind,
            );

            // If the request body was dropped by hyper while batches remain unacked (not an
            // advised drain), bound waiting for the server's response error or EOF.
            if input_tx.is_none()
                && !draining_for_reconnect
                && !self.state.inflight_appends.is_empty()
                && timer_kind.is_none()
            {
                arm_timer(
                    ack_timer.as_mut(),
                    &mut timer_kind,
                    TimerKind::BodyClosed,
                    Instant::now(),
                    ack_timeout,
                );
            }

            let can_send_more = input_tx.is_some()
                && !draining_for_reconnect
                && send_cursor < self.state.inflight_appends.len();
            let wait_oldest_last_byte = timer_kind.is_none()
                && self
                    .state
                    .inflight_appends
                    .front()
                    .is_some_and(|f| f.attempt_last_byte_rx.is_some());

            let mut drop_input_tx = false;

            tokio::select! {
                biased;

                // T10: process already-received acks first, in order.
                ack = acks.next() => {
                    match ack {
                        Some(Ok(frame)) => {
                            match process_proto_ack(
                                frame.msg,
                                &mut self.state,
                                send_cursor,
                                &self.context,
                            ) {
                                Ok(()) => {
                                    acked_in_attempt += 1;
                                    send_cursor = send_cursor.saturating_sub(1);
                                    timer_kind = None;
                                    became_oldest_at =
                                        (!self.state.inflight_appends.is_empty()).then(Instant::now);
                                    // T6a: Act on reconnect advice at most once per cooldown window
                                    // by half-closing and draining batches already sent on this
                                    // request.
                                    if frame.reconnect_advised
                                        && !draining_for_reconnect
                                        && advised_reconnects.should_reconnect()
                                    {
                                        draining_for_reconnect = true;
                                        drop_input_tx = true;
                                    }
                                    if draining_for_reconnect && send_cursor == 0 {
                                        drop(acks);
                                        return AttemptResult::ReconnectAdvised {
                                            made_progress: acked_in_attempt > 0,
                                        };
                                    }
                                }
                                Err(err) => {
                                    let unacked_sent = finish_attempt_gate(
                                        &send_gate,
                                        acked_in_attempt,
                                        &mut self.state,
                                    );
                                    return AttemptResult::Error {
                                        err,
                                        made_progress: acked_in_attempt > 0,
                                        unacked_sent_in_attempt: unacked_sent,
                                    };
                                }
                            }
                        }
                        Some(Err(err)) => {
                            let unacked_sent =
                                finish_attempt_gate(&send_gate, acked_in_attempt, &mut self.state);

                            if let Some(reason) = self.check_abort() {
                                return AttemptResult::Aborted(reason);
                            }

                            // T9 / A3: Connection break or retryable error while nothing is unacked
                            // is not a session error and uses no budget.
                            if self.state.inflight_appends.is_empty() && err.is_retryable() {
                                return AttemptResult::IdleEnded;
                            }

                            if draining_for_reconnect && err.is_server_draining() && unacked_sent == 0 {
                                return AttemptResult::ReconnectAdvised {
                                    made_progress: acked_in_attempt > 0,
                                };
                            }

                            return AttemptResult::Error {
                                err,
                                made_progress: acked_in_attempt > 0,
                                unacked_sent_in_attempt: unacked_sent,
                            };
                        }
                        None => {
                            let unacked_sent =
                                finish_attempt_gate(&send_gate, acked_in_attempt, &mut self.state);

                            if let Some(reason) = self.check_abort() {
                                return AttemptResult::Aborted(reason);
                            }

                            if draining_for_reconnect {
                                if unacked_sent == 0 {
                                    return AttemptResult::ReconnectAdvised {
                                        made_progress: acked_in_attempt > 0,
                                    };
                                }
                                return AttemptResult::Error {
                                    err: AppendSessionError::ConnectionLost(ConnectionLostError::new(
                                        "response stream closed early during reconnect drain",
                                        false,
                                        self.context.clone(),
                                    )),
                                    made_progress: acked_in_attempt > 0,
                                    unacked_sent_in_attempt: unacked_sent,
                                };
                            }

                            // T9: Clean end with nothing unacked -> no error, no budget used (A3).
                            if self.state.inflight_appends.is_empty() {
                                return if self.state.closing {
                                    AttemptResult::Closed
                                } else {
                                    AttemptResult::IdleEnded
                                };
                            }

                            // T9: Clean end with unacked batches -> ConnectionLostError.
                            return AttemptResult::Error {
                                err: AppendSessionError::ConnectionLost(ConnectionLostError::new(
                                    "response stream closed early while appends in flight",
                                    unacked_sent == 0,
                                    self.context.clone(),
                                )),
                                made_progress: acked_in_attempt > 0,
                                unacked_sent_in_attempt: unacked_sent,
                            };
                        }
                    }
                }

                _ = self.abort.cancelled() => {
                    drain_ready_acks(
                        &mut acks,
                        &mut self.state,
                        &mut acked_in_attempt,
                        &mut send_cursor,
                        &self.context,
                    );
                    finish_attempt_gate(&send_gate, acked_in_attempt, &mut self.state);
                    return AttemptResult::Aborted(self.abort_reason_msg());
                }

                _ = &mut ack_timer, if timer_kind.is_some() => {
                    acks.poison_connection();
                    let unacked_sent =
                        finish_attempt_gate(&send_gate, acked_in_attempt, &mut self.state);
                    if self.state.inflight_appends.is_empty() {
                        return AttemptResult::IdleEnded;
                    }
                    let err = match timer_kind.expect("timer_kind is Some") {
                        TimerKind::Ack => AppendSessionError::Timeout(TimeoutError::new(
                            "append acknowledgement timed out",
                            self.context.clone(),
                        )),
                        TimerKind::BodyClosed => {
                            AppendSessionError::ConnectionLost(ConnectionLostError::new(
                                "request body closed before response ended",
                                unacked_sent == 0,
                                self.context.clone(),
                            ))
                        }
                    };
                    return AttemptResult::Error {
                        err,
                        made_progress: acked_in_attempt > 0,
                        unacked_sent_in_attempt: unacked_sent,
                    };
                }

                sent_at = async {
                    self.state
                        .inflight_appends
                        .front_mut()
                        .expect("front exists")
                        .attempt_last_byte_rx
                        .as_mut()
                        .expect("rx exists")
                        .await
                }, if wait_oldest_last_byte => {
                    if let Some(front) = self.state.inflight_appends.front_mut() {
                        front.attempt_last_byte_rx = None;
                        let start = match sent_at {
                            Ok(sent_at) => became_oldest_at.map_or(sent_at, |b| b.max(sent_at)),
                            Err(_) => Instant::now(),
                        };
                        arm_timer(
                            ack_timer.as_mut(),
                            &mut timer_kind,
                            TimerKind::Ack,
                            start,
                            ack_timeout,
                        );
                    }
                }

                permit = async {
                    input_tx
                        .as_ref()
                        .expect("input_tx exists")
                        .reserve()
                        .await
                }, if can_send_more => {
                    match permit {
                        Ok(permit) => {
                            let append = &mut self.state.inflight_appends[send_cursor];
                            let (last_byte_tx, last_byte_rx) = oneshot::channel();
                            append.attempt_last_byte_rx = Some(last_byte_rx);
                            permit.send(OutboundBatch {
                                remaining: append.frame.clone(),
                                last_byte_tx: Some(last_byte_tx),
                            });
                            send_cursor += 1;
                        }
                        Err(_) => {
                            // Hyper dropped the request body stream (e.g. server replied with a
                            // terminal error or reset the stream). Stop sending and stay in the
                            // loop so `acks.next()` drains all buffered acks and surfaces the real
                            // terminal server error or EOF (`T10`, `A6a`). The next iteration arms
                            // `TimerKind::BodyClosed` if batches remain unacked.
                            drop_input_tx = true;
                        }
                    }
                }

                cmd = self.state.cmd_rx.recv() => {
                    match cmd {
                        Some(Command::Submit {
                            frame,
                            record_count,
                            ack_tx,
                            permit,
                        }) => {
                            let was_empty = self.state.inflight_appends.is_empty();
                            self.state.push_submit(frame, record_count, ack_tx, permit);
                            if was_empty {
                                became_oldest_at = Some(Instant::now());
                            }
                        }
                        Some(Command::Close) => {
                            self.state.closing = true;
                        }
                        None => {
                            drain_ready_acks(
                                &mut acks,
                                &mut self.state,
                                &mut acked_in_attempt,
                                &mut send_cursor,
                                &self.context,
                            );
                            finish_attempt_gate(&send_gate, acked_in_attempt, &mut self.state);
                            return AttemptResult::Aborted(self.dropped_abort_msg);
                        }
                    }
                }
            }

            if drop_input_tx {
                input_tx = None;
            }
        }
    }
}

fn abort_reason_msg(
    client_shutdown: &CancellationToken,
    dropped_abort_msg: &'static str,
) -> &'static str {
    if client_shutdown.is_cancelled() {
        "client closed"
    } else {
        dropped_abort_msg
    }
}

fn arm_timer(
    ack_timer: Pin<&mut Sleep>,
    timer_kind: &mut Option<TimerKind>,
    kind: TimerKind,
    start: Instant,
    ack_timeout: Duration,
) {
    ack_timer.reset(start + ack_timeout);
    *timer_kind = Some(kind);
}

fn refresh_oldest_timer(
    state: &mut SessionState,
    became_oldest_at: Option<Instant>,
    ack_timeout: Duration,
    ack_timer: Pin<&mut Sleep>,
    timer_kind: &mut Option<TimerKind>,
) {
    if timer_kind.is_some() {
        return;
    }
    let Some(front) = state.inflight_appends.front_mut() else {
        return;
    };
    let Some(rx) = front.attempt_last_byte_rx.as_mut() else {
        return;
    };
    match rx.try_recv() {
        Ok(sent_at) => {
            front.attempt_last_byte_rx = None;
            let start = became_oldest_at.map_or(sent_at, |b| b.max(sent_at));
            arm_timer(ack_timer, timer_kind, TimerKind::Ack, start, ack_timeout);
        }
        Err(oneshot::error::TryRecvError::Empty) => {}
        Err(oneshot::error::TryRecvError::Closed) => {
            front.attempt_last_byte_rx = None;
            arm_timer(
                ack_timer,
                timer_kind,
                TimerKind::Ack,
                Instant::now(),
                ack_timeout,
            );
        }
    }
}

fn finish_attempt_gate(
    send_gate: &StdMutex<AttemptSendGate>,
    acked_in_attempt: usize,
    state: &mut SessionState,
) -> usize {
    let batches_started = AttemptSendGate::stop(send_gate);
    let unacked_sent = batches_started
        .saturating_sub(acked_in_attempt)
        .min(state.inflight_appends.len());
    for append in state.inflight_appends.iter_mut().take(unacked_sent) {
        append.sent_ever = true;
    }
    unacked_sent
}

/// Drain any acks already buffered in `acks` before an abort ends the attempt (`T10`).
fn drain_ready_acks(
    acks: &mut Streaming<proto::AppendAck, AppendSessionError>,
    state: &mut SessionState,
    acked_in_attempt: &mut usize,
    send_cursor: &mut usize,
    context: &ErrorContext,
) {
    // Use `coop::unconstrained` so Tokio cooperative preemption cannot spuriously return
    // `Pending` and drop an already-buffered ack during abort (`T10`).
    while let Some(Some(Ok(frame))) = tokio::task::coop::unconstrained(acks.next()).now_or_never() {
        if process_proto_ack(frame.msg, state, *send_cursor, context).is_err() {
            break;
        }
        *acked_in_attempt += 1;
        *send_cursor = send_cursor.saturating_sub(1);
    }
}

fn process_proto_ack(
    proto_ack: proto::AppendAck,
    state: &mut SessionState,
    send_cursor: usize,
    context: &ErrorContext,
) -> Result<(), AppendSessionError> {
    if send_cursor == 0 {
        return Err(AppendSessionError::Protocol(ProtocolError::new(
            "received ack for a batch that was not sent on this attempt",
            context.clone(),
        )));
    }

    let Some(corresponding_append) = state.inflight_appends.front() else {
        return Err(AppendSessionError::Protocol(ProtocolError::new(
            "received ack without a corresponding append in flight",
            context.clone(),
        )));
    };

    let ack = AppendAck::try_from_proto(
        proto_ack,
        corresponding_append.record_count,
        context.clone(),
    )?;

    if state
        .prev_ack_end
        .is_some_and(|end| ack.start.seq_num < end.seq_num || ack.end.seq_num <= end.seq_num)
    {
        return Err(AppendSessionError::Protocol(ProtocolError::new(
            "ack range must not overlap or precede previous ack end",
            context.clone(),
        )));
    }

    let corresponding_append = state
        .inflight_appends
        .pop_front()
        .expect("inflight front was checked above");
    state.unacked_batches.fetch_sub(1, Ordering::Release);
    state.prev_ack_end = Some(ack.end);

    let _ = corresponding_append.ack_tx.send(Ok(ack));

    Ok(())
}

fn is_safe_to_retry(
    err: &AppendSessionError,
    policy: AppendRetryPolicy,
    attempt_may_have_side_effects: bool,
    refreshes_tokens: bool,
) -> bool {
    let policy_compliant = match policy {
        AppendRetryPolicy::All => true,
        AppendRetryPolicy::NoSideEffects => !attempt_may_have_side_effects,
    };
    policy_compliant && (err.is_retryable() || (refreshes_tokens && err.is_authentication_error()))
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        sync::{Arc, atomic::AtomicUsize},
    };

    use bytes::Bytes;
    use futures_util::poll;
    use http::StatusCode;
    use s2_api::v1::stream::proto;

    use super::{AppendSessionError, is_safe_to_retry};
    use crate::{
        error::{ErrorContext, ServerError, TimeoutError, TransportError},
        types::AppendRetryPolicy,
    };

    fn server_error(status: StatusCode, code: &str) -> AppendSessionError {
        AppendSessionError::Server(ServerError::new_for_test(status, Some(code), "test"))
    }

    #[rstest::rstest]
    #[case(StatusCode::FORBIDDEN, "permission_denied", false, false)]
    #[case(StatusCode::FORBIDDEN, "permission_denied", true, true)]
    #[case(StatusCode::SERVICE_UNAVAILABLE, "unavailable", false, false)]
    #[case(StatusCode::SERVICE_UNAVAILABLE, "unavailable", true, false)]
    #[case(StatusCode::TOO_MANY_REQUESTS, "rate_limited", true, true)]
    #[test]
    fn session_failure_preserves_uncertainty_and_latest_error(
        #[case] status: StatusCode,
        #[case] code: &str,
        #[case] prior_uncertainty: bool,
        #[case] wrapped: bool,
    ) {
        let latest = server_error(status, code);
        let error = latest.clone().with_prior_uncertainty(prior_uncertainty);
        assert_eq!(
            matches!(error, AppendSessionError::IndefiniteAppend(_)),
            wrapped
        );
        assert_eq!(error.is_retryable(), latest.is_retryable());
        assert_eq!(
            error.has_no_side_effects(),
            !wrapped && latest.has_no_side_effects()
        );
        if wrapped {
            assert!(error.server_error().is_none());
            let source = error
                .source()
                .unwrap()
                .downcast_ref::<AppendSessionError>()
                .unwrap();
            assert_eq!(source.to_string(), latest.to_string());
            assert!(source.has_no_side_effects());
            assert_eq!(source.server_error().unwrap().code.as_deref(), Some(code));
        } else {
            assert_eq!(error.server_error().unwrap().code.as_deref(), Some(code));
        }
    }

    #[test]
    fn safe_to_retry_session_all_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");
        let policy = AppendRetryPolicy::All;

        assert!(is_safe_to_retry(&retryable, policy, true, false));
        assert!(!is_safe_to_retry(&non_retryable, policy, true, false));

        let unauthorized = server_error(StatusCode::UNAUTHORIZED, "authn");
        assert!(is_safe_to_retry(&unauthorized, policy, true, true));
        assert!(!is_safe_to_retry(&unauthorized, policy, true, false));

        let unrelated_unauthorized = server_error(StatusCode::UNAUTHORIZED, "other");
        assert!(!is_safe_to_retry(
            &unrelated_unauthorized,
            policy,
            true,
            true
        ));
    }

    #[test]
    fn safe_to_retry_session_no_side_effects_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let no_side_effect = server_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        let policy = AppendRetryPolicy::NoSideEffects;

        // No possible side effects (e.g. nothing unacked sent, or definite error) -> safe.
        assert!(is_safe_to_retry(&retryable, policy, false, false));
        assert!(is_safe_to_retry(&no_side_effect, policy, false, false));

        // Possible side effects -> not safe under NoSideEffects.
        assert!(!is_safe_to_retry(&retryable, policy, true, false));
        assert!(!is_safe_to_retry(
            &AppendSessionError::Timeout(TimeoutError::new(
                "append acknowledgement timed out",
                ErrorContext::default(),
            )),
            policy,
            true,
            false,
        ));
    }

    #[tokio::test]
    async fn session_lifecycle_mark_closing_and_wait_closed_without_receivers() {
        use super::SessionLifecycle;

        let lifecycle = SessionLifecycle::new();
        // Calling mark_closing() with zero subscribers must still observe closed=true later.
        assert!(lifecycle.mark_closing());
        assert!(!lifecycle.mark_closing());
        assert!(lifecycle.is_closing_or_closed());
        lifecycle.wait_closing_or_closed().await;

        // Calling finish() before wait_closed() must resolve immediately without lost wakeup.
        lifecycle.finish(Ok(()));
        assert!(lifecycle.is_closed());
        assert!(lifecycle.wait_closed().await.is_ok());

        // Concurrent waiter started before finish() must wake with exact error, and
        // set_terminal_err can update a Closing error before finish() seals it.
        let lc2 = SessionLifecycle::new();
        let mut wait_fut = Box::pin(lc2.wait_closed());
        assert!(poll!(wait_fut.as_mut()).is_pending());

        lc2.set_terminal_err(server_error(StatusCode::BAD_REQUEST, "first"));
        lc2.set_terminal_err(server_error(StatusCode::FORBIDDEN, "permission_denied"));
        assert_eq!(
            lc2.terminal_err()
                .unwrap()
                .server_error()
                .unwrap()
                .code
                .as_deref(),
            Some("permission_denied")
        );

        lc2.finish(Err(server_error(
            StatusCode::FORBIDDEN,
            "permission_denied",
        )));
        let res = wait_fut.await;
        assert!(matches!(res, Err(AppendSessionError::Server(_))));
    }

    #[tokio::test]
    async fn append_permits_strict_joint_fifo_and_shrink_and_cancel() {
        use super::AppendPermits;

        let permits = AppendPermits::new(Some(2), 100);

        // Acquire 80 bytes (1 batch left, 20 bytes left).
        let mut p1 = permits.acquire(80).await;
        // A waiter needing 60 bytes blocks at the head of the FIFO queue.
        let mut large_fut = Box::pin(permits.acquire(60));
        assert!(poll!(large_fut.as_mut()).is_pending());

        // A small waiter needing 10 bytes MUST NOT jump ahead of the queued 60-byte waiter!
        assert!(permits.has_waiters());
        assert!(permits.try_acquire(10).is_none());

        // Shrinking p1 from 80 -> 20 releases 60 bytes (80 available) and immediately wakes
        // large_fut.
        p1.shrink(20);
        let p_large = large_fut.await;
        assert!(!permits.has_waiters());

        // Now 2 batches held (0 batch slots left) and 20 bytes left.
        // Queue a third waiter, cancel it, then drop p1 & p_large and ensure no leak.
        let mut cancel_fut = Box::pin(permits.acquire(10));
        assert!(poll!(cancel_fut.as_mut()).is_pending());
        assert!(permits.has_waiters());
        drop(cancel_fut);
        assert!(!permits.has_waiters());

        drop(p1);
        drop(p_large);
        let full = permits
            .try_acquire(100)
            .expect("all 100 bytes and batch slots should be restored");
        drop(full);
    }

    #[test]
    fn append_permit_merge_combines_bytes_without_leaking() {
        use super::AppendPermits;

        let permits = AppendPermits::new(None, 100);
        let mut p1 = permits.try_acquire(30).unwrap();
        let p2 = permits.try_acquire(40).unwrap();
        assert_eq!(permits.in_flight_bytes(), 70);

        p1.merge(p2);
        assert_eq!(permits.in_flight_bytes(), 70);

        drop(p1);
        assert_eq!(permits.in_flight_bytes(), 0);
        assert!(permits.try_acquire(100).is_some());
    }

    #[test]
    fn process_ack_preserves_inflight_batch_on_protocol_error() {
        use std::collections::VecDeque;

        use super::{InflightAppend, SessionState, process_proto_ack};

        let (_cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ack_tx, mut ack_rx) = tokio::sync::oneshot::channel();
        let unacked_batches = Arc::new(AtomicUsize::new(1));
        let mut state = SessionState {
            cmd_rx,
            inflight_appends: VecDeque::from([InflightAppend {
                frame: Bytes::new(),
                record_count: 1,
                ack_tx,
                _permit: None,
                sent_ever: true,
                prior_uncertainty: false,
                attempt_last_byte_rx: None,
            }]),
            closing: false,
            prev_ack_end: None,
            unacked_batches: unacked_batches.clone(),
        };
        let ctx = ErrorContext::default();
        let pos = |seq_num| {
            Some(proto::StreamPosition {
                seq_num,
                timestamp: 1,
            })
        };

        // send_cursor == 0 rejects unsolicited ack without popping inflight_appends.
        let ok_ack = proto::AppendAck {
            start: pos(0),
            end: pos(1),
            tail: pos(1),
        };
        let err = process_proto_ack(ok_ack, &mut state, 0, &ctx).unwrap_err();
        assert!(matches!(err, AppendSessionError::Protocol(_)));
        assert_eq!(state.inflight_appends.len(), 1);
        assert_eq!(
            unacked_batches.load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // Wrong record count (2 instead of 1) rejects without popping inflight_appends.
        let bad_ack = proto::AppendAck {
            start: pos(0),
            end: pos(2),
            tail: pos(2),
        };
        let err = process_proto_ack(bad_ack, &mut state, 1, &ctx).unwrap_err();
        assert!(matches!(err, AppendSessionError::Protocol(_)));
        assert_eq!(state.inflight_appends.len(), 1);
        assert!(ack_rx.try_recv().is_err());

        // Valid ack succeeds and delivers through ack_tx.
        process_proto_ack(ok_ack, &mut state, 1, &ctx).unwrap();
        assert!(state.inflight_appends.is_empty());
        assert_eq!(
            unacked_batches.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(ack_rx.try_recv().unwrap().is_ok());
    }
}
