use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    pin::{Pin, pin},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_core::{FusedFuture, Stream};
use futures_util::{FutureExt, StreamExt};
use s2_api::v1::stream::{proto, s2s};
use tokio::{
    sync::{Notify, mpsc, oneshot, watch},
    time::Instant,
};
use tracing::{Instrument, debug, debug_span};

use crate::{
    api::{BasinClient, Streaming},
    batching::RECORD_BATCH_MIN,
    client::CancellationToken,
    error::{
        AbortedError, AppendSessionError, ConnectionLostError, ErrorContext, ProtocolError,
        SessionClosedError, TimeoutError, TransportError, ValidationError,
    },
    reconnect::AdvisedReconnects,
    retry::RetryBackoff,
    send_gate::attempt_ended_io_error,
    session::StreamHeaders,
    types::{
        AppendAck, AppendInput, AppendRecord, AppendRetryPolicy, BasinName, ONE_MIB, StreamConfig,
        StreamName, StreamPosition, append_input_parts_encoded_len, encode_append_input_parts,
    },
};

/// Chunk size used when streaming encoded S2S frames into HTTP/2 DATA frames so wire-send
/// progress tracks HTTP/2 flow control (`T7c`, `T10`).
const FRAME_CHUNK_BYTES: usize = 16 * 1024;

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

/// A [`Future`] that resolves to an acknowledgement once the batch of records is appended.
///
/// Once resolved, re-polling returns the same outcome without panicking, and
/// [`try_ack`](Self::try_ack) returns `None`.
pub struct BatchSubmitTicket(SubmitTicket<AppendAck>);

impl BatchSubmitTicket {
    /// Poll the ticket without blocking, returning `Some` once the batch outcome is ready.
    ///
    /// Returns `None` if the batch is still in flight or if the outcome was already consumed.
    #[must_use]
    pub fn try_ack(&mut self) -> Option<Result<AppendAck, AppendSessionError>> {
        self.0.try_ack()
    }
}

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

impl FusedFuture for BatchSubmitTicket {
    fn is_terminated(&self) -> bool {
        self.0.is_terminated()
    }
}

/// Configuration for an [`AppendSession`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct AppendSessionConfig {
    max_unacked_bytes: usize,
    max_unacked_batches: Option<usize>,
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
    #[must_use]
    pub fn max_unacked_bytes(&self) -> usize {
        self.max_unacked_bytes
    }

    /// Return the limit on number of unacknowledged [`AppendInput`]s held in memory, if set.
    #[must_use]
    pub fn max_unacked_batches(&self) -> Option<usize> {
        self.max_unacked_batches
    }

    /// Return the stream configuration to apply if the stream is created on append, if set.
    #[must_use]
    pub fn stream_config(&self) -> Option<&StreamConfig> {
        self.stream_config.as_ref()
    }

    /// Set the limit on total metered bytes of unacknowledged [`AppendInput`]s held in memory.
    ///
    /// Defaults to `5 MiB`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `max_unacked_bytes` is less than `1 MiB`.
    pub fn with_max_unacked_bytes(self, max_unacked_bytes: usize) -> Result<Self, ValidationError> {
        let max_unacked_bytes = validate_max_unacked_bytes(max_unacked_bytes)?;
        Ok(Self {
            max_unacked_bytes,
            ..self
        })
    }

    /// Set the limit on number of unacknowledged [`AppendInput`]s held in memory.
    ///
    /// Defaults to no limit.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `max_unacked_batches` is `0`.
    pub fn with_max_unacked_batches(
        self,
        max_unacked_batches: usize,
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

const PHASE_OPEN: u8 = 0;
const PHASE_CLOSING_CLEAN: u8 = 1;
const PHASE_CLOSING_ERR: u8 = 2;
const PHASE_CLOSED_CLEAN: u8 = 3;
const PHASE_CLOSED_ERR: u8 = 4;

/// Shared lifecycle coordination for [`AppendSession`] and [`Producer`](crate::producer::Producer).
///
/// Guarantees:
/// - Transitions out of `Open` immediately when `close()` starts or when the session terminates,
///   waking any `reserve()`/`submit()` waiting on capacity (`A4c`).
/// - Repeated or concurrent `close(&self)` calls return the exact same `Result` (`A8a`).
/// - Dropping a `close(&self)` future cancels only that wait (`T8`).
pub(crate) struct SessionLifecycle {
    state: watch::Sender<LifecycleState>,
    phase: AtomicU8,
}

impl SessionLifecycle {
    pub(crate) fn new() -> Self {
        let (state, _) = watch::channel(LifecycleState::Open);
        Self {
            state,
            phase: AtomicU8::new(PHASE_OPEN),
        }
    }

    pub(crate) fn is_closing_or_closed(&self) -> bool {
        self.phase.load(Ordering::Acquire) != PHASE_OPEN
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.phase.load(Ordering::Acquire) >= PHASE_CLOSED_CLEAN
    }

    pub(crate) fn has_terminal_err(&self) -> bool {
        matches!(
            self.phase.load(Ordering::Acquire),
            PHASE_CLOSING_ERR | PHASE_CLOSED_ERR
        )
    }

    /// Transition `Open -> Closing { failure: None }`. Returns `true` if this call performed the
    /// transition.
    pub(crate) fn mark_closing(&self) -> bool {
        self.state.send_if_modified(|s| {
            if matches!(s, LifecycleState::Open) {
                *s = LifecycleState::Closing { failure: None };
                self.phase.store(PHASE_CLOSING_CLEAN, Ordering::Release);
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
                self.phase.store(PHASE_CLOSING_ERR, Ordering::Release);
                true
            }
            LifecycleState::Closed(_) => false,
        });
    }

    pub(crate) fn terminal_err(&self) -> Option<AppendSessionError> {
        if !self.has_terminal_err() {
            return None;
        }
        match &*self.state.borrow() {
            LifecycleState::Open => None,
            LifecycleState::Closing { failure } => failure.clone(),
            LifecycleState::Closed(res) => res.as_ref().err().cloned(),
        }
    }

    pub(crate) fn session_closed_err(&self, context: &ErrorContext) -> AppendSessionError {
        AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
            self.terminal_err(),
            context.clone(),
        ))
    }

    pub(crate) fn finish(&self, result: Result<(), AppendSessionError>) {
        self.state.send_if_modified(|s| {
            if matches!(s, LifecycleState::Closed(_)) {
                false
            } else {
                let phase = if result.is_ok() {
                    PHASE_CLOSED_CLEAN
                } else {
                    PHASE_CLOSED_ERR
                };
                *s = LifecycleState::Closed(result);
                self.phase.store(phase, Ordering::Release);
                true
            }
        });
    }

    pub(crate) async fn wait_closing_or_closed(&self) {
        if self.is_closing_or_closed() {
            return;
        }
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

/// Shared abort signal pairing a [`CancellationToken`] with an explicit-abort flag and its
/// diagnostic messages.
///
/// Supports parent/child cancellation between [`Producer`](crate::producer::Producer) and its
/// owned [`AppendSessionCore`].
#[derive(Clone)]
pub(crate) struct SessionAbort {
    client_shutdown: CancellationToken,
    token: CancellationToken,
    explicit: Arc<AtomicBool>,
    explicit_msg: &'static str,
    dropped_msg: &'static str,
}

impl SessionAbort {
    pub(crate) fn new(
        client_shutdown: CancellationToken,
        explicit_msg: &'static str,
        dropped_msg: &'static str,
    ) -> Self {
        let token = client_shutdown.child_token();
        Self {
            client_shutdown,
            token,
            explicit: Arc::new(AtomicBool::new(false)),
            explicit_msg,
            dropped_msg,
        }
    }

    pub(crate) fn child(&self) -> Self {
        Self {
            client_shutdown: self.client_shutdown.clone(),
            token: self.token.child_token(),
            explicit: self.explicit.clone(),
            explicit_msg: self.explicit_msg,
            dropped_msg: self.dropped_msg,
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    pub(crate) async fn cancelled(&self) {
        self.token.cancelled().await;
    }

    pub(crate) fn cancel_explicit(&self) {
        self.explicit.store(true, Ordering::Release);
        self.token.cancel();
    }

    pub(crate) fn cancel_dropped(&self) {
        self.token.cancel();
    }

    pub(crate) fn reason(&self) -> &'static str {
        if self.client_shutdown.is_cancelled() {
            "client closed"
        } else if self.explicit.load(Ordering::Acquire) {
            self.explicit_msg
        } else {
            self.dropped_msg
        }
    }

    pub(crate) fn dropped_msg(&self) -> &'static str {
        self.dropped_msg
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
    /// Cancelled on client close, parent abort, or session drop/abort.
    abort: SessionAbort,
    unacked_batches: Arc<AtomicUsize>,
    context: ErrorContext,
}

impl AppendSessionCore {
    pub(crate) fn new(
        client: BasinClient,
        stream: StreamName,
        headers: StreamHeaders,
        op: &'static str,
        explicit_abort_msg: &'static str,
        dropped_abort_msg: &'static str,
    ) -> Self {
        let abort = SessionAbort::new(
            client.shutdown_token(),
            explicit_abort_msg,
            dropped_abort_msg,
        );
        Self::new_with_abort(client, stream, headers, op, abort)
    }

    pub(crate) fn new_with_abort(
        client: BasinClient,
        stream: StreamName,
        headers: StreamHeaders,
        op: &'static str,
        abort: SessionAbort,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let gate = Arc::new(StdMutex::new(()));
        let lifecycle = Arc::new(SessionLifecycle::new());
        let unacked_batches = Arc::new(AtomicUsize::new(0));
        let basin = client.name.clone();
        let compression = client.base().compression().into_api();
        let context = ErrorContext::stream(op, basin.as_ref(), stream.as_ref(), false);

        let span = debug_span!("append_session", op, basin = %basin, stream = %stream);
        let task = AppendSessionTask {
            client,
            stream: stream.clone(),
            headers,
            op,
            gate: gate.clone(),
            lifecycle: lifecycle.clone(),
            abort: abort.clone(),
            context: context.clone(),
            state: SessionState {
                cmd_rx,
                inflight_appends: VecDeque::new(),
                closing: false,
                prev_ack_end: None,
                unacked_batches: unacked_batches.clone(),
            },
            active_attempt: None,
        };
        tokio::spawn(task.run().instrument(span));

        Self {
            basin,
            stream,
            compression,
            gate,
            cmd_tx,
            lifecycle,
            abort,
            unacked_batches,
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
                Some(AppendSessionError::Aborted(AbortedError::new_with_context(
                    self.abort.reason(),
                    self.context.clone(),
                )))
            } else {
                None
            }
        });
        AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
            failure,
            self.context.clone(),
        ))
    }

    pub(crate) fn submit(
        &self,
        input: AppendInput,
        permit: Option<AppendPermit>,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
        self.submit_parts(
            input.records(),
            input.match_seq_num(),
            input.fencing_token().map(AsRef::as_ref),
            permit,
        )
    }

    pub(crate) fn submit_parts(
        &self,
        records: &[AppendRecord],
        match_seq_num: Option<u64>,
        fencing_token: Option<&str>,
        permit: Option<AppendPermit>,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
        if self.lifecycle.is_closing_or_closed() || self.abort.is_cancelled() {
            return Err(self.session_closed_err_on_submit());
        }

        // Encode and compress on the caller task before taking the gate so the session task stays
        // focused on network I/O and state transitions.
        let record_count = records.len() as u64;
        let encoded_len = append_input_parts_encoded_len(records, match_seq_num, fencing_token);
        let frame = s2s::encode_regular_frame_with(self.compression, encoded_len, |buf| {
            encode_append_input_parts(records, match_seq_num, fencing_token, buf);
        })
        .map_err(|err| {
            AppendSessionError::Protocol(ProtocolError::new_definite(
                format!("failed to encode append frame: {err}"),
                self.context.clone(),
            ))
        })?;

        let (ack_tx, ack_rx) = oneshot::channel();
        {
            let _gate = self.gate.lock().unwrap();
            if self.lifecycle.is_closing_or_closed() || self.abort.is_cancelled() {
                return Err(self.session_closed_err_on_submit());
            }
            self.unacked_batches.fetch_add(1, Ordering::Release);
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
                self.unacked_batches.fetch_sub(1, Ordering::Release);
                return Err(self.session_closed_err_on_submit());
            }
        }
        Ok(BatchSubmitTicket(SubmitTicket::new(
            ack_rx,
            self.lifecycle.clone(),
            self.context.clone(),
            self.abort.dropped_msg(),
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

    pub(crate) fn abort_explicit(&self) {
        if !self.lifecycle.is_closed() {
            self.abort.cancel_explicit();
        }
    }

    pub(crate) fn abort_dropped(&self) {
        if !self.lifecycle.is_closed() {
            self.abort.cancel_dropped();
        }
    }
}

impl Drop for AppendSessionCore {
    fn drop(&mut self) {
        self.abort_dropped();
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
            "append session aborted",
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
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe while waiting for capacity. Dropping the future before it
    /// resolves accepts nothing and releases any partially acquired reservation.
    pub async fn submit(
        &self,
        input: impl Into<AppendInput>,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
        let input = input.into();
        input
            .validate_for_write()
            .map_err(|e| self.core.context.format_validation(e))?;
        let bytes = input.metered_bytes();
        let append_permit = self.acquire_permit(bytes).await?;
        self.core.submit(input, Some(append_permit))
    }

    /// Reserve capacity for a batch of up to `bytes` metered bytes to be submitted.
    ///
    /// Useful in [`select!`](tokio::select) loops where you want to interleave submission with
    /// other async work. See [`submit`](Self::submit) for a simpler API.
    ///
    /// Capacity is granted FIFO. Validated before waiting; `bytes` must be between `8` and `1 MiB`.
    /// If the session closes or begins closing while waiting, returns [`SessionClosedError`].
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. Dropping the future before completion accepts nothing and
    /// releases any partially acquired reservation.
    pub async fn reserve(&self, bytes: usize) -> Result<BatchSubmitPermit, AppendSessionError> {
        validate_reserve_bytes(bytes, ONE_MIB, &self.core.context)?;
        let append_permit = self.acquire_permit(bytes).await?;

        Ok(BatchSubmitPermit {
            append_permit,
            reserved_bytes: bytes,
            core: self.core.clone(),
        })
    }

    async fn acquire_permit(&self, bytes: usize) -> Result<AppendPermit, AppendSessionError> {
        self.check_open_for_reserve().await?;

        if let Some(permit) = self.permits.try_acquire(bytes) {
            self.check_open_for_reserve().await?;
            return Ok(permit);
        }

        let append_permit = tokio::select! {
            biased;
            _ = self.core.lifecycle.wait_closing_or_closed() => {
                return Err(self.core.lifecycle.session_closed_err(&self.core.context));
            }
            permit = self.permits.acquire(bytes) => permit,
        };

        self.check_open_for_reserve().await?;
        Ok(append_permit)
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

    /// Return the number of metered bytes currently reserved or awaiting acknowledgement.
    ///
    /// Includes bytes held by outstanding [`BatchSubmitPermit`]s as well as submitted batches that
    /// have not yet settled. Returns to `0` once all permits and batches have settled.
    #[must_use]
    pub fn unacked_bytes(&self) -> usize {
        self.permits.in_flight_bytes()
    }

    /// Return the number of submitted batches currently awaiting an outcome.
    ///
    /// Incremented when a batch is accepted and decremented whenever it settles (acknowledged,
    /// failed, or aborted), returning to `0` once all submitted batches have settled.
    #[must_use]
    pub fn unacked_batches(&self) -> usize {
        self.core.unacked_batches.load(Ordering::Acquire)
    }

    /// Close the session and wait for all accepted batches to reach an outcome.
    ///
    /// Calling `close()` stops accepting new submissions immediately and waits until all
    /// already-accepted batches settle. Repeated or concurrent calls to `close()` return the same
    /// result.
    ///
    /// # Cancel safety
    ///
    /// Dropping a `close()` future cancels only the wait; the session continues closing in the
    /// background. Dropping the [`AppendSession`] itself aborts it.
    pub async fn close(&self) -> Result<(), AppendSessionError> {
        self.core.close().await
    }

    /// Immediately abort the session without waiting for unacknowledged batches.
    ///
    /// Equivalent to dropping the session early while keeping the handle alive (for example, when
    /// the handle is shared behind an `Arc`). Already-sent unacknowledged batches fail with
    /// [`AbortedError`], and unsent batches fail with [`SessionClosedError`]. Calling `abort()`
    /// after the session has already closed is a no-op.
    pub fn abort(&self) {
        self.core.abort_explicit();
    }
}

impl Drop for AppendSession {
    fn drop(&mut self) {
        self.core.abort_dropped();
    }
}

/// A permit to submit a batch after reserving capacity.
#[must_use = "a permit reserves session capacity; call `.submit(...)` to send the batch"]
pub struct BatchSubmitPermit {
    append_permit: AppendPermit,
    reserved_bytes: usize,
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
    /// Return the number of metered bytes reserved by this permit.
    #[must_use]
    pub fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    /// Submit the batch using this permit.
    ///
    /// Any excess reserved capacity above the batch's actual metered byte size is released
    /// immediately so waiting callers can proceed.
    ///
    /// Fails with [`ValidationError`] (releasing the reservation and leaving the session open) if
    /// the batch's metered size exceeds the reserved bytes. Fails with [`SessionClosedError`] if
    /// the session closed or began closing after the permit was reserved.
    pub fn submit(
        self,
        input: impl Into<AppendInput>,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
        let input = input.into();
        input
            .validate_for_write()
            .map_err(|e| self.core.context.format_validation(e))?;
        let metered = input.metered_bytes();
        self.submit_validated(input, metered)
    }

    fn submit_validated(
        mut self,
        input: AppendInput,
        metered: usize,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
        if metered > self.reserved_bytes {
            return Err(AppendSessionError::Validation(
                self.core.context.format_validation(format!(
                    "batch size in metered bytes ({metered}) exceeds reserved capacity ({})",
                    self.reserved_bytes
                )),
            ));
        }

        // Release any unused over-reserved capacity immediately (`A4a`).
        self.append_permit.shrink(metered);
        self.core.submit(input, Some(self.append_permit))
    }
}

pub(crate) fn validate_reserve_bytes(
    bytes: usize,
    max_bytes: usize,
    context: &ErrorContext,
) -> Result<(), AppendSessionError> {
    if bytes < RECORD_BATCH_MIN.bytes {
        return Err(AppendSessionError::Validation(context.format_validation(
            format!(
                "reserved bytes ({bytes}) must be at least {}",
                RECORD_BATCH_MIN.bytes
            ),
        )));
    }
    if bytes > max_bytes {
        return Err(AppendSessionError::Validation(context.format_validation(
            format!("reserved bytes ({bytes}) exceeds maximum ({max_bytes})"),
        )));
    }
    Ok(())
}

struct PermitWaiter {
    id: u64,
    bytes: usize,
    granted: oneshot::Sender<()>,
}

struct PermitsState {
    available_batches: Option<usize>,
    total_bytes: usize,
    available_bytes: usize,
    next_waiter_id: u64,
    waiters: VecDeque<PermitWaiter>,
}

impl PermitsState {
    fn can_satisfy(&self, bytes: usize) -> bool {
        self.available_batches.is_none_or(|c| c >= 1) && self.available_bytes >= bytes
    }

    fn take(&mut self, bytes: usize) {
        if let Some(c) = self.available_batches.as_mut() {
            *c -= 1;
        }
        self.available_bytes -= bytes;
    }

    fn release(&mut self, bytes: usize, has_waiters: &AtomicBool) {
        if let Some(c) = self.available_batches.as_mut() {
            *c += 1;
        }
        self.available_bytes += bytes;
        self.grant_next(has_waiters);
    }

    fn grant_next(&mut self, has_waiters: &AtomicBool) {
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
        if self.waiters.is_empty() {
            has_waiters.store(false, Ordering::Release);
        }
    }
}

struct PermitsInner {
    state: StdMutex<PermitsState>,
    has_waiters: AtomicBool,
}

pub(crate) struct AppendPermit {
    inner: Arc<PermitsInner>,
    bytes: usize,
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
    pub(crate) fn shrink(&mut self, new_bytes: usize) {
        if new_bytes < self.bytes {
            let excess = self.bytes - new_bytes;
            self.bytes = new_bytes;
            let mut state = self.inner.state.lock().unwrap();
            state.available_bytes += excess;
            state.grant_next(&self.inner.has_waiters);
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
        let mut state = self.inner.state.lock().unwrap();
        state.release(self.bytes, &self.inner.has_waiters);
    }
}

#[derive(Clone)]
pub(crate) struct AppendPermits {
    inner: Arc<PermitsInner>,
}

impl AppendPermits {
    pub(crate) fn new(count_permits: Option<usize>, bytes_permits: usize) -> Self {
        Self {
            inner: Arc::new(PermitsInner {
                state: StdMutex::new(PermitsState {
                    available_batches: count_permits,
                    total_bytes: bytes_permits,
                    available_bytes: bytes_permits,
                    next_waiter_id: 0,
                    waiters: VecDeque::new(),
                }),
                has_waiters: AtomicBool::new(false),
            }),
        }
    }

    pub(crate) fn in_flight_bytes(&self) -> usize {
        let state = self.inner.state.lock().unwrap();
        state.total_bytes - state.available_bytes
    }

    pub(crate) fn has_waiters(&self) -> bool {
        self.inner.has_waiters.load(Ordering::Acquire)
    }

    pub(crate) fn try_acquire(&self, bytes: usize) -> Option<AppendPermit> {
        let mut state = self.inner.state.lock().unwrap();
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

    pub(crate) async fn acquire(&self, bytes: usize) -> AppendPermit {
        self.acquire_inner(bytes, None).await
    }

    /// Acquire capacity FIFO, notifying `on_wait` strictly after enqueueing the first waiter
    /// (`0 -> 1`) so a woken consumer is guaranteed to observe `has_waiters() == true` (`A5a`).
    pub(crate) async fn acquire_notifying(&self, bytes: usize, on_wait: &Notify) -> AppendPermit {
        self.acquire_inner(bytes, Some(on_wait)).await
    }

    async fn acquire_inner(&self, bytes: usize, on_wait: Option<&Notify>) -> AppendPermit {
        struct AcquireGuard<'a> {
            inner: &'a PermitsInner,
            id: u64,
            bytes: usize,
            rx: oneshot::Receiver<()>,
            acquired: bool,
        }

        impl Drop for AcquireGuard<'_> {
            fn drop(&mut self) {
                if self.acquired {
                    return;
                }
                let mut state = self.inner.state.lock().unwrap();
                if let Some(pos) = state.waiters.iter().position(|w| w.id == self.id) {
                    state.waiters.remove(pos);
                    state.grant_next(&self.inner.has_waiters);
                } else if self.rx.try_recv().is_ok() {
                    // Grant raced with cancellation; refund immediately.
                    state.release(self.bytes, &self.inner.has_waiters);
                }
            }
        }

        let (has_batch_slot, was_empty, mut guard) = {
            let mut state = self.inner.state.lock().unwrap();
            let has_batch_slot = state.available_batches.is_some();
            if state.waiters.is_empty() && state.can_satisfy(bytes) {
                state.take(bytes);
                return AppendPermit {
                    inner: self.inner.clone(),
                    bytes,
                    has_batch_slot,
                };
            }
            let was_empty = state.waiters.is_empty();
            let id = state.next_waiter_id;
            state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
            let (tx, rx) = oneshot::channel();
            state.waiters.push_back(PermitWaiter {
                id,
                bytes,
                granted: tx,
            });
            if was_empty {
                self.inner.has_waiters.store(true, Ordering::Release);
            }
            (
                has_batch_slot,
                was_empty,
                AcquireGuard {
                    inner: &self.inner,
                    id,
                    bytes,
                    rx,
                    acquired: false,
                },
            )
        };

        if was_empty && let Some(notify) = on_wait {
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

const GATE_STOPPED: u64 = 1 << 63;
const GATE_DRAINING: u64 = 1 << 62;
const GATE_COUNT_MASK: u64 = (1 << 62) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateState {
    Open,
    Draining,
    Stopped,
}

struct FinishLog {
    base_idx: usize,
    times_ns: VecDeque<u64>,
}

/// Shared lock-free gate and lazy timeout telemetry between `AppendSessionTask::run_attempt` and
/// `AttemptBodyStream` (`Terms: Sent`, `T6a`, `T7c`, `T10`).
struct AttemptSync {
    epoch: Instant,
    /// Bit 63: STOPPED, Bit 62: DRAINING, Bits 0..62: `batches_started`.
    gate: AtomicU64,
    /// Latest chunk write progress in nanoseconds since `epoch`.
    last_write_progress_ns: AtomicU64,
    /// `0` while body stream is alive; `elapsed_nanos + 1` once dropped by hyper.
    body_dropped_at_ns: AtomicU64,
    /// Per-batch last-byte handoff timestamps (nanos since `epoch`), indexed by attempt batch idx.
    finish_log: StdMutex<FinishLog>,
}

impl AttemptSync {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            epoch: Instant::now(),
            gate: AtomicU64::new(0),
            last_write_progress_ns: AtomicU64::new(0),
            body_dropped_at_ns: AtomicU64::new(0),
            finish_log: StdMutex::new(FinishLog {
                base_idx: 0,
                times_ns: VecDeque::new(),
            }),
        })
    }

    fn elapsed_ns(&self) -> u64 {
        self.epoch.elapsed().as_nanos().min((u64::MAX - 1) as u128) as u64
    }

    fn stop(&self) -> usize {
        (self.gate.fetch_or(GATE_STOPPED, Ordering::AcqRel) & GATE_COUNT_MASK) as usize
    }

    fn start_draining(&self) -> usize {
        (self.gate.fetch_or(GATE_DRAINING, Ordering::AcqRel) & GATE_COUNT_MASK) as usize
    }

    fn batches_started(&self) -> usize {
        (self.gate.load(Ordering::Acquire) & GATE_COUNT_MASK) as usize
    }

    fn is_stopped(&self) -> bool {
        (self.gate.load(Ordering::Acquire) & GATE_STOPPED) != 0
    }

    fn check_before_recv(&self) -> GateState {
        let v = self.gate.load(Ordering::Acquire);
        if v & GATE_STOPPED != 0 {
            GateState::Stopped
        } else if v & GATE_DRAINING != 0 {
            GateState::Draining
        } else {
            GateState::Open
        }
    }

    fn try_start_batch(&self) -> GateState {
        let mut cur = self.gate.load(Ordering::Acquire);
        loop {
            if cur & GATE_STOPPED != 0 {
                return GateState::Stopped;
            }
            if cur & GATE_DRAINING != 0 {
                return GateState::Draining;
            }
            debug_assert!((cur & GATE_COUNT_MASK) < GATE_COUNT_MASK);
            match self
                .gate
                .compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return GateState::Open,
                Err(actual) => cur = actual,
            }
        }
    }

    fn record_write_progress(&self) {
        self.last_write_progress_ns
            .store(self.elapsed_ns(), Ordering::Release);
    }

    fn last_write_progress(&self) -> Instant {
        let ns = self.last_write_progress_ns.load(Ordering::Acquire);
        self.epoch + Duration::from_nanos(ns)
    }

    fn record_batch_finished(&self) {
        let ns = self.elapsed_ns();
        self.finish_log.lock().unwrap().times_ns.push_back(ns);
    }

    fn finish_time(&self, batch_idx: usize) -> Option<Instant> {
        let log = self.finish_log.lock().unwrap();
        let offset = batch_idx.checked_sub(log.base_idx)?;
        let ns = *log.times_ns.get(offset)?;
        Some(self.epoch + Duration::from_nanos(ns))
    }

    fn prune_finished(&self, acked_in_attempt: usize) {
        let mut log = self.finish_log.lock().unwrap();
        let drop_count = acked_in_attempt
            .saturating_sub(log.base_idx)
            .min(log.times_ns.len());
        if drop_count > 0 {
            log.times_ns.drain(..drop_count);
            log.base_idx += drop_count;
        }
    }

    fn mark_body_dropped(&self) {
        let encoded = self.elapsed_ns() + 1;
        let _ = self.body_dropped_at_ns.compare_exchange(
            0,
            encoded,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn body_dropped_at(&self) -> Option<Instant> {
        let encoded = self.body_dropped_at_ns.load(Ordering::Acquire);
        if encoded == 0 {
            None
        } else {
            Some(self.epoch + Duration::from_nanos(encoded - 1))
        }
    }
}

struct AttemptBodyStream {
    rx: mpsc::Receiver<Bytes>,
    current: Option<Bytes>,
    sync: Arc<AttemptSync>,
    aborted: bool,
}

impl AttemptBodyStream {
    fn new(rx: mpsc::Receiver<Bytes>, sync: Arc<AttemptSync>) -> Self {
        Self {
            rx,
            current: None,
            sync,
            aborted: false,
        }
    }

    fn take_chunk(sync: &AttemptSync, remaining: &mut Bytes) -> Bytes {
        let take_len = remaining.len().min(FRAME_CHUNK_BYTES);
        let chunk = remaining.split_to(take_len);
        if remaining.is_empty() {
            sync.record_batch_finished();
        } else {
            sync.record_write_progress();
        }
        chunk
    }
}

impl Drop for AttemptBodyStream {
    fn drop(&mut self) {
        self.sync.mark_body_dropped();
    }
}

impl Stream for AttemptBodyStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if this.aborted {
            return Poll::Ready(None);
        }

        if let Some(remaining) = this.current.as_mut() {
            if this.sync.is_stopped() {
                this.current = None;
                this.aborted = true;
                return Poll::Ready(Some(Err(attempt_ended_io_error())));
            }
            let chunk = Self::take_chunk(&this.sync, remaining);
            if remaining.is_empty() {
                this.current = None;
            }
            return Poll::Ready(Some(Ok(chunk)));
        }

        match this.sync.check_before_recv() {
            GateState::Stopped => {
                this.aborted = true;
                return Poll::Ready(Some(Err(attempt_ended_io_error())));
            }
            GateState::Draining => return Poll::Ready(None),
            GateState::Open => {}
        }

        match this.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                if this.sync.is_stopped() {
                    this.aborted = true;
                    Poll::Ready(Some(Err(attempt_ended_io_error())))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Ready(Some(mut remaining)) => {
                match this.sync.try_start_batch() {
                    GateState::Stopped => {
                        this.aborted = true;
                        return Poll::Ready(Some(Err(attempt_ended_io_error())));
                    }
                    GateState::Draining => return Poll::Ready(None),
                    GateState::Open => {}
                }
                let chunk = Self::take_chunk(&this.sync, &mut remaining);
                if !remaining.is_empty() {
                    this.current = Some(remaining);
                }
                Poll::Ready(Some(Ok(chunk)))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerKind {
    /// Waiting for forward HTTP/2 write progress while uploading the oldest unacked batch.
    WriteStall,
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
    ReconnectAdvised,
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
    abort: SessionAbort,
    context: ErrorContext,
    state: SessionState,
    /// Tracks `(sync, acked_in_attempt)` while an attempt is active so abnormal drop/unwind can
    /// freeze `sync` and classify the sent prefix vs unsent tail accurately (`A6a`, `A8c`).
    active_attempt: Option<(Arc<AttemptSync>, usize)>,
}

impl Drop for AppendSessionTask {
    fn drop(&mut self) {
        if self.lifecycle.is_closed() {
            return;
        }
        if let Some((sync, acked_in_attempt)) = self.active_attempt.take() {
            finish_attempt_gate(&sync, acked_in_attempt, &mut self.state);
        }
        let explicit_abort = self.abort.is_cancelled();
        let reason = if explicit_abort {
            self.abort.reason()
        } else {
            self.abort.dropped_msg()
        };
        let aborted = AppendSessionError::Aborted(AbortedError::new_with_context(
            reason,
            self.context.clone(),
        ));
        let (queued, has_pending_work, existing_err) = {
            let _gate = self
                .gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.gate.clear_poison();
            let queued = self.state.drain_queued_commands();
            let has_pending_work = !self.state.inflight_appends.is_empty()
                || queued
                    .iter()
                    .any(|cmd| matches!(cmd, Command::Submit { .. }));
            let existing_err = self.lifecycle.terminal_err();
            if let Some(err) = existing_err.as_ref() {
                self.lifecycle.set_terminal_err(err.clone());
            } else if has_pending_work || !explicit_abort {
                self.lifecycle.set_terminal_err(aborted.clone());
            } else {
                self.lifecycle.mark_closing();
            }
            (queued, has_pending_work, existing_err)
        };

        if !has_pending_work && explicit_abort && existing_err.is_none() {
            // A8c: explicitly aborting an idle append session loses nothing, so the close is clean.
            self.lifecycle.finish(Ok(()));
            return;
        }

        let err = existing_err.unwrap_or(aborted);
        let unsent = AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
            Some(err.clone()),
            self.context.clone(),
        ));

        for append in self.state.inflight_appends.drain(..) {
            let outcome = if append.sent_ever {
                err.clone()
            } else {
                unsent.clone()
            };
            drop(append._permit);
            self.state.unacked_batches.fetch_sub(1, Ordering::Release);
            let _ = append.ack_tx.send(Err(outcome));
        }
        for cmd in queued {
            if let Command::Submit { ack_tx, permit, .. } = cmd {
                drop(permit);
                self.state.unacked_batches.fetch_sub(1, Ordering::Release);
                let _ = ack_tx.send(Err(unsent.clone()));
            }
        }
        self.lifecycle.finish(Err(err));
    }
}

impl AppendSessionTask {
    fn check_abort(&self) -> Option<&'static str> {
        self.abort.is_cancelled().then(|| self.abort.reason())
    }

    async fn run(mut self) {
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
            let result = self.run_attempt(&mut advised_reconnects, attempt_num).await;

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
                AttemptResult::ReconnectAdvised => {
                    retry_backoff.reset();
                    debug!(
                        inflight = self.state.inflight_appends.len(),
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
                            inflight = self.state.inflight_appends.len(),
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

                    if should_retry_append_session(
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
                            err = %err,
                            attempt = attempts,
                            delay = ?backoff,
                            retries_remaining = retry_backoff.remaining(),
                            "retrying append session"
                        );
                        if let Some(reason) = self.sleep_or_abort(backoff).await {
                            self.abort_session(reason);
                            return;
                        }
                    } else {
                        debug!(
                            err = %err,
                            attempt = attempts,
                            is_retryable = err.is_retryable(),
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
            _ = self.abort.cancelled() => IdleWait::Aborted(self.abort.reason()),
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
                None => IdleWait::Aborted(self.abort.dropped_msg()),
            },
        }
    }

    async fn sleep_or_abort(&self, duration: Duration) -> Option<&'static str> {
        tokio::select! {
            biased;
            _ = self.abort.cancelled() => Some(self.abort.reason()),
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
        let closed_err = AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
            None,
            self.context.clone(),
        ));
        for cmd in queued {
            if let Command::Submit { ack_tx, permit, .. } = cmd {
                drop(permit);
                self.state.unacked_batches.fetch_sub(1, Ordering::Release);
                let _ = ack_tx.send(Err(closed_err.clone()));
            }
        }
        debug_assert_eq!(self.state.unacked_batches.load(Ordering::Acquire), 0);
        self.lifecycle.finish(Ok(()));
    }

    fn abort_session(&mut self, reason: &'static str) {
        let aborted = AppendSessionError::Aborted(AbortedError::new_with_context(
            reason,
            self.context.clone(),
        ));
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
            inflight = self.state.inflight_appends.len(),
            "aborting append session"
        );

        if !has_pending_work {
            // A8c: aborting an idle append session loses nothing, so the close is clean.
            debug_assert_eq!(self.state.unacked_batches.load(Ordering::Acquire), 0);
            self.lifecycle.finish(Ok(()));
            return;
        }

        let unsent = AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
            Some(aborted.clone()),
            self.context.clone(),
        ));

        for append in self.state.inflight_appends.drain(..) {
            let InflightAppend {
                ack_tx,
                _permit,
                sent_ever,
                ..
            } = append;
            let outcome = if sent_ever {
                aborted.clone()
            } else {
                unsent.clone()
            };
            drop(_permit);
            self.state.unacked_batches.fetch_sub(1, Ordering::Release);
            let _ = ack_tx.send(Err(outcome));
        }

        for cmd in queued {
            if let Command::Submit { ack_tx, permit, .. } = cmd {
                drop(permit);
                self.state.unacked_batches.fetch_sub(1, Ordering::Release);
                let _ = ack_tx.send(Err(unsent.clone()));
            }
        }

        debug_assert_eq!(self.state.unacked_batches.load(Ordering::Acquire), 0);
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
        let closed_err = AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
            Some(session_failure.clone()),
            self.context.clone(),
        ));

        for (i, append) in self.state.inflight_appends.drain(..).enumerate() {
            let base = if gets_closed_err(i, &append) {
                closed_err.clone()
            } else {
                final_err.clone()
            };
            let InflightAppend {
                ack_tx,
                _permit,
                prior_uncertainty,
                ..
            } = append;
            drop(_permit);
            self.state.unacked_batches.fetch_sub(1, Ordering::Release);
            let _ = ack_tx.send(Err(base.with_prior_uncertainty(prior_uncertainty)));
        }

        for cmd in queued {
            if let Command::Submit { ack_tx, permit, .. } = cmd {
                drop(permit);
                self.state.unacked_batches.fetch_sub(1, Ordering::Release);
                let _ = ack_tx.send(Err(closed_err.clone()));
            }
        }

        debug_assert_eq!(self.state.unacked_batches.load(Ordering::Acquire), 0);
        self.lifecycle.finish(Err(session_failure));
    }

    async fn run_attempt(
        &mut self,
        advised_reconnects: &mut AdvisedReconnects,
        attempt: u32,
    ) -> AttemptResult {
        /// Owns the body channel sender alongside its `AttemptSync` so any abnormal drop/unwind
        /// calls `sync.stop()` STRICTLY BEFORE dropping `tx` (preventing `AttemptBodyStream` from
        /// observing a closed channel while the gate is still open).
        struct AttemptSender {
            tx: Option<mpsc::Sender<Bytes>>,
            sync: Option<Arc<AttemptSync>>,
        }
        impl AttemptSender {
            fn new(tx: mpsc::Sender<Bytes>, sync: Arc<AttemptSync>) -> Self {
                Self {
                    tx: Some(tx),
                    sync: Some(sync),
                }
            }
            fn as_ref(&self) -> Option<&mpsc::Sender<Bytes>> {
                self.tx.as_ref()
            }
            fn is_some(&self) -> bool {
                self.tx.is_some()
            }
            fn is_none(&self) -> bool {
                self.tx.is_none()
            }
            fn close_clean(&mut self) {
                self.tx = None;
            }
            fn disarm(&mut self) {
                self.sync = None;
            }
        }
        impl Drop for AttemptSender {
            fn drop(&mut self) {
                if let Some(sync) = self.sync.take() {
                    sync.stop();
                }
                self.tx = None;
            }
        }

        let sync = AttemptSync::new();
        self.active_attempt = Some((sync.clone(), 0));
        let (tx, input_rx) = mpsc::channel::<Bytes>(16);
        let mut input_tx = AttemptSender::new(tx, sync.clone());
        let body_stream = AttemptBodyStream::new(input_rx, sync.clone());

        let abort = self.abort.clone();
        let mut abort_fut = pin!(abort.cancelled());

        let connect_fut =
            self.client
                .append_session(self.op, &self.stream, body_stream, &self.headers, attempt);

        let mut acks = tokio::select! {
            biased;
            _ = abort_fut.as_mut() => {
                sync.stop();
                self.active_attempt = None;
                return AttemptResult::Aborted(self.abort.reason());
            }
            res = connect_fut => match res {
                Ok(s) => s,
                Err(err) => {
                    sync.stop();
                    self.active_attempt = None;
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
        let mut send_cursor: usize = 0;
        let mut acked_in_attempt: usize = 0;
        let mut draining_for_reconnect = false;

        let mut became_oldest_at: Option<Instant> =
            (!self.state.inflight_appends.is_empty()).then(Instant::now);
        let mut ack_timer = pin!(tokio::time::sleep(Duration::ZERO));
        let mut ack_timer_armed = false;

        loop {
            if self.state.is_close_complete() {
                self.active_attempt = None;
                input_tx.disarm();
                input_tx.close_clean();
                drop(acks);
                return AttemptResult::Closed;
            }

            // Check abort BEFORE handing any unsent frames to `AttemptBodyStream` so an
            // already-aborted session cannot start transmitting an unsent batch (`A8c`).
            if let Some(reason) = self.check_abort() {
                self.active_attempt = None;
                abort_attempt(
                    &mut acks,
                    &mut self.state,
                    &sync,
                    &mut acked_in_attempt,
                    &mut send_cursor,
                    &self.context,
                );
                return AttemptResult::Aborted(reason);
            }

            // Eagerly enqueue ready frames into the bounded body channel without entering
            // `select!` when slots are available.
            if !draining_for_reconnect && let Some(tx) = input_tx.as_ref() {
                let mut closed = false;
                while send_cursor < self.state.inflight_appends.len() {
                    if let Some(reason) = self.check_abort() {
                        self.active_attempt = None;
                        abort_attempt(
                            &mut acks,
                            &mut self.state,
                            &sync,
                            &mut acked_in_attempt,
                            &mut send_cursor,
                            &self.context,
                        );
                        return AttemptResult::Aborted(reason);
                    }
                    let frame = self.state.inflight_appends[send_cursor].frame.clone();
                    match tx.try_send(frame) {
                        Ok(()) => send_cursor += 1,
                        Err(mpsc::error::TrySendError::Full(_)) => break,
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            closed = true;
                            break;
                        }
                    }
                }
                if closed {
                    input_tx.close_clean();
                }
            }

            if input_tx.is_none()
                && !draining_for_reconnect
                && self.state.inflight_appends.is_empty()
            {
                self.active_attempt = None;
                input_tx.disarm();
                drop(acks);
                return AttemptResult::IdleEnded;
            }

            // Lazily arm the watchdog timer once; while healthy traffic flows, it is never
            // reset per batch or per chunk and only recomputed if the old deadline fires (`T7c`).
            if !self.state.inflight_appends.is_empty()
                && !ack_timer_armed
                && let Some(deadline) = became_oldest_at
                    .unwrap_or_else(Instant::now)
                    .checked_add(ack_timeout)
            {
                ack_timer.as_mut().reset(deadline);
                ack_timer_armed = true;
            }

            let can_send_more = input_tx.is_some()
                && !draining_for_reconnect
                && send_cursor < self.state.inflight_appends.len();
            let timer_active = ack_timer_armed && !self.state.inflight_appends.is_empty();

            let mut drop_input_tx = false;
            let mut reconnect_advised_done = false;

            tokio::select! {
                biased;

                // T10: process already-received acks first, in order.
                ack = acks.next() => {
                    match ack {
                        Some(Ok(frame)) => {
                            let batches_started = if self.abort.is_cancelled() {
                                sync.stop()
                            } else {
                                sync.batches_started()
                            };
                            let sent_unacked = batches_started.saturating_sub(acked_in_attempt);
                            match process_proto_ack(
                                frame.msg,
                                &mut self.state,
                                sent_unacked,
                                &self.context,
                            ) {
                                Ok(()) => {
                                    acked_in_attempt += 1;
                                    if let Some((_, tracked_acked)) = self.active_attempt.as_mut() {
                                        *tracked_acked = acked_in_attempt;
                                    }
                                    send_cursor = send_cursor.saturating_sub(1);
                                    if acked_in_attempt.is_multiple_of(64) {
                                        sync.prune_finished(acked_in_attempt);
                                    }
                                    became_oldest_at =
                                        (!self.state.inflight_appends.is_empty()).then(Instant::now);
                                    // T6a: Act on reconnect advice at most once per cooldown window
                                    // by stopping new batches from starting, finishing any
                                    // already-started batch, half-closing, and draining acks for
                                    // started batches only.
                                    if frame.reconnect_advised
                                        && !draining_for_reconnect
                                        && advised_reconnects.should_reconnect()
                                    {
                                        draining_for_reconnect = true;
                                        advised_reconnects.record();
                                        sync.start_draining();
                                        drop_input_tx = true;
                                    }
                                    if draining_for_reconnect
                                        && !self.abort.is_cancelled()
                                        && sync.batches_started() <= acked_in_attempt
                                    {
                                        reconnect_advised_done = true;
                                    }
                                }
                                Err(err) => {
                                    self.active_attempt = None;
                                    let unacked_sent = finish_attempt_gate(
                                        &sync,
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
                            self.active_attempt = None;
                            let unacked_sent =
                                finish_attempt_gate(&sync, acked_in_attempt, &mut self.state);

                            if let Some(reason) = self.check_abort() {
                                return AttemptResult::Aborted(reason);
                            }

                            // T9 / A3: Connection break or retryable error while nothing is unacked
                            // is not a session error and uses no budget.
                            if self.state.inflight_appends.is_empty() && err.is_retryable() {
                                return AttemptResult::IdleEnded;
                            }

                            if draining_for_reconnect && err.is_server_draining() && unacked_sent == 0 {
                                return AttemptResult::ReconnectAdvised;
                            }

                            return AttemptResult::Error {
                                err,
                                made_progress: acked_in_attempt > 0,
                                unacked_sent_in_attempt: unacked_sent,
                            };
                        }
                        None => {
                            self.active_attempt = None;
                            let unacked_sent =
                                finish_attempt_gate(&sync, acked_in_attempt, &mut self.state);

                            if let Some(reason) = self.check_abort() {
                                return AttemptResult::Aborted(reason);
                            }

                            if draining_for_reconnect {
                                if unacked_sent == 0 {
                                    return AttemptResult::ReconnectAdvised;
                                }
                                return AttemptResult::Error {
                                    err: AppendSessionError::ConnectionLost(ConnectionLostError::new_with_context(
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
                                err: AppendSessionError::ConnectionLost(ConnectionLostError::new_with_context(
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

                _ = abort_fut.as_mut() => {
                    self.active_attempt = None;
                    abort_attempt(
                        &mut acks,
                        &mut self.state,
                        &sync,
                        &mut acked_in_attempt,
                        &mut send_cursor,
                        &self.context,
                    );
                    return AttemptResult::Aborted(self.abort.reason());
                }

                _ = &mut ack_timer, if timer_active => {
                    ack_timer_armed = false;
                    let now = Instant::now();
                    let (kind, start) = if let Some(sent_at) = sync.finish_time(acked_in_attempt) {
                        (
                            TimerKind::Ack,
                            became_oldest_at.map_or(sent_at, |b| b.max(sent_at)),
                        )
                    } else if let Some(dropped_at) = sync.body_dropped_at() {
                        (
                            TimerKind::BodyClosed,
                            became_oldest_at.map_or(dropped_at, |b| b.max(dropped_at)),
                        )
                    } else {
                        let progress_at = sync.last_write_progress();
                        (
                            TimerKind::WriteStall,
                            became_oldest_at.map_or(progress_at, |b| b.max(progress_at)),
                        )
                    };

                    match start.checked_add(ack_timeout) {
                        Some(deadline) if deadline > now => {
                            ack_timer.as_mut().reset(deadline);
                            ack_timer_armed = true;
                            continue;
                        }
                        None => continue,
                        Some(_) => {}
                    }

                    acks.retire_connection();
                    self.active_attempt = None;
                    let unacked_sent =
                        finish_attempt_gate(&sync, acked_in_attempt, &mut self.state);
                    if self.state.inflight_appends.is_empty() {
                        return AttemptResult::IdleEnded;
                    }
                    let err = match kind {
                        TimerKind::WriteStall => AppendSessionError::Timeout(TimeoutError::new_with_context(
                            "append write timed out",
                            self.context.clone(),
                        )),
                        TimerKind::Ack => AppendSessionError::Timeout(TimeoutError::new_with_context(
                            "append acknowledgement timed out",
                            self.context.clone(),
                        )),
                        TimerKind::BodyClosed => {
                            AppendSessionError::ConnectionLost(ConnectionLostError::new_with_context(
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

                permit = async {
                    input_tx
                        .as_ref()
                        .expect("input_tx exists")
                        .reserve()
                        .await
                }, if can_send_more => {
                    match permit {
                        Ok(permit) => {
                            let frame = self.state.inflight_appends[send_cursor].frame.clone();
                            permit.send(frame);
                            send_cursor += 1;
                        }
                        Err(_) => {
                            // Hyper dropped the request body stream (e.g. server replied with a
                            // terminal error or reset the stream). Stop sending and stay in the
                            // loop so `acks.next()` drains all buffered acks and surfaces the real
                            // terminal server error or EOF (`T10`, `A6a`).
                            drop_input_tx = true;
                        }
                    }
                }

                cmd = self.state.cmd_rx.recv() => {
                    let mut first = cmd;
                    for remaining in (0..32).rev() {
                        match first {
                            Some(Command::Submit {
                                frame,
                                record_count,
                                ack_tx,
                                permit,
                            }) => {
                                let was_empty = self.state.inflight_appends.is_empty();
                                self.state.push_submit(frame, record_count, ack_tx, permit);
                                if was_empty {
                                    let now = Instant::now();
                                    became_oldest_at = Some(now);
                                    if ack_timer_armed && ack_timer.deadline() <= now {
                                        ack_timer_armed = false;
                                    }
                                }
                            }
                            Some(Command::Close) => {
                                self.state.closing = true;
                                break;
                            }
                            None => {
                                self.active_attempt = None;
                                abort_attempt(
                                    &mut acks,
                                    &mut self.state,
                                    &sync,
                                    &mut acked_in_attempt,
                                    &mut send_cursor,
                                    &self.context,
                                );
                                return AttemptResult::Aborted(self.abort.dropped_msg());
                            }
                        }
                        if remaining == 0 {
                            break;
                        }
                        match self.state.cmd_rx.try_recv() {
                            Ok(next) => first = Some(next),
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => first = None,
                        }
                    }
                }
            }

            if reconnect_advised_done {
                self.active_attempt = None;
                input_tx.disarm();
                input_tx.close_clean();
                drop(acks);
                return AttemptResult::ReconnectAdvised;
            }
            if drop_input_tx {
                input_tx.close_clean();
            }
        }
    }
}

fn finish_attempt_gate(
    sync: &AttemptSync,
    acked_in_attempt: usize,
    state: &mut SessionState,
) -> usize {
    let batches_started = sync.stop();
    let unacked_sent = batches_started
        .saturating_sub(acked_in_attempt)
        .min(state.inflight_appends.len());
    for append in state.inflight_appends.iter_mut().take(unacked_sent) {
        append.sent_ever = true;
    }
    unacked_sent
}

/// Stop the attempt gate immediately so `AttemptBodyStream` cannot start any unsent batch queued
/// in the body channel, then drain any already-buffered acks against the frozen started count and
/// classify the remaining unacked batches (`A8c`, `T10`).
fn abort_attempt(
    acks: &mut Streaming<proto::AppendAck, AppendSessionError>,
    state: &mut SessionState,
    sync: &AttemptSync,
    acked_in_attempt: &mut usize,
    send_cursor: &mut usize,
    context: &ErrorContext,
) {
    let batches_started = sync.stop();
    // Use `coop::unconstrained` so Tokio cooperative preemption cannot spuriously return
    // `Pending` and drop an already-buffered ack during abort (`T10`).
    while let Some(Some(Ok(frame))) = tokio::task::coop::unconstrained(acks.next()).now_or_never() {
        let sent_unacked = batches_started.saturating_sub(*acked_in_attempt);
        if process_proto_ack(frame.msg, state, sent_unacked, context).is_err() {
            break;
        }
        *acked_in_attempt += 1;
        *send_cursor = send_cursor.saturating_sub(1);
    }
    let unacked_sent = batches_started
        .saturating_sub(*acked_in_attempt)
        .min(state.inflight_appends.len());
    for append in state.inflight_appends.iter_mut().take(unacked_sent) {
        append.sent_ever = true;
    }
}

fn process_proto_ack(
    proto_ack: proto::AppendAck,
    state: &mut SessionState,
    sent_unacked: usize,
    context: &ErrorContext,
) -> Result<(), AppendSessionError> {
    if sent_unacked == 0 {
        return Err(AppendSessionError::Protocol(
            ProtocolError::new_with_context(
                "received ack for a batch that was not sent on this attempt",
                context.clone(),
            ),
        ));
    }

    let Some(corresponding_append) = state.inflight_appends.front() else {
        return Err(AppendSessionError::Protocol(
            ProtocolError::new_with_context(
                "received ack without a corresponding append in flight",
                context.clone(),
            ),
        ));
    };

    let ack = AppendAck::try_from_proto(proto_ack, corresponding_append.record_count)
        .map_err(|e| e.with_context(context))?;

    if state
        .prev_ack_end
        .is_some_and(|end| ack.start.seq_num < end.seq_num || ack.end.seq_num <= end.seq_num)
    {
        return Err(AppendSessionError::Protocol(
            ProtocolError::new_with_context(
                "ack range must not overlap or precede previous ack end",
                context.clone(),
            ),
        ));
    }

    let InflightAppend {
        ack_tx, _permit, ..
    } = state
        .inflight_appends
        .pop_front()
        .expect("inflight front was checked above");
    // Release capacity and decrement unacked_batches BEFORE waking the ticket so callers checking
    // `unacked_bytes()` / `unacked_batches()` immediately after `ticket.await` observe settled
    // counts without racing.
    drop(_permit);
    state.unacked_batches.fetch_sub(1, Ordering::Release);
    state.prev_ack_end = Some(ack.end);

    let _ = ack_tx.send(Ok(ack));

    Ok(())
}

fn should_retry_append_session(
    err: &AppendSessionError,
    policy: AppendRetryPolicy,
    attempt_may_have_side_effects: bool,
    refreshes_tokens: bool,
) -> bool {
    let policy_compliant = match policy {
        AppendRetryPolicy::All => true,
        AppendRetryPolicy::NoSideEffects => !attempt_may_have_side_effects,
    };
    policy_compliant && err.is_retryable_or_auth_refresh(refreshes_tokens)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use bytes::Bytes;
    use futures_util::poll;
    use http::StatusCode;
    use s2_api::v1::stream::proto;

    use super::{AppendSessionError, should_retry_append_session};
    use crate::{
        error::{ErrorContext, ServerError},
        types::{AppendRetryPolicy, StreamPosition},
    };

    fn server_error(status: StatusCode, code: &str) -> AppendSessionError {
        AppendSessionError::Server(ServerError::new(status, "test").with_code(code))
    }

    #[test]
    fn safe_to_retry_session_policies() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");
        let authn = server_error(StatusCode::UNAUTHORIZED, "authn");
        let other_401 = server_error(StatusCode::UNAUTHORIZED, "other");

        assert!(should_retry_append_session(
            &retryable,
            AppendRetryPolicy::All,
            true,
            false
        ));
        assert!(!should_retry_append_session(
            &non_retryable,
            AppendRetryPolicy::All,
            true,
            false
        ));
        assert!(should_retry_append_session(
            &authn,
            AppendRetryPolicy::All,
            true,
            true
        ));
        assert!(!should_retry_append_session(
            &authn,
            AppendRetryPolicy::All,
            true,
            false
        ));
        assert!(!should_retry_append_session(
            &other_401,
            AppendRetryPolicy::All,
            true,
            true
        ));

        assert!(should_retry_append_session(
            &retryable,
            AppendRetryPolicy::NoSideEffects,
            false,
            false
        ));
        assert!(!should_retry_append_session(
            &retryable,
            AppendRetryPolicy::NoSideEffects,
            true,
            false
        ));
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

    // spec: r1 A1
    #[test]
    fn process_ack_rejects_unsolicited_and_overlapping_acks() {
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
            }]),
            closing: false,
            prev_ack_end: Some(StreamPosition {
                seq_num: 5,
                timestamp: 1,
            }),
            unacked_batches: unacked_batches.clone(),
        };
        let ctx = ErrorContext::default();
        let pos = |seq_num| {
            Some(proto::StreamPosition {
                seq_num,
                timestamp: 1,
            })
        };

        // Unsent (sent_unacked == 0) rejects unsolicited ack without popping inflight_appends.
        let valid_ack = proto::AppendAck {
            start: pos(5),
            end: pos(6),
            tail: pos(6),
        };
        assert!(matches!(
            process_proto_ack(valid_ack, &mut state, 0, &ctx),
            Err(AppendSessionError::Protocol(_))
        ));
        assert_eq!(state.inflight_appends.len(), 1);
        assert_eq!(unacked_batches.load(Ordering::Relaxed), 1);

        // Overlapping ack (`start.seq_num < prev_ack_end.seq_num`) rejects without popping.
        let overlapping = proto::AppendAck {
            start: pos(4),
            end: pos(5),
            tail: pos(5),
        };
        assert!(matches!(
            process_proto_ack(overlapping, &mut state, 1, &ctx),
            Err(AppendSessionError::Protocol(_))
        ));
        assert_eq!(state.inflight_appends.len(), 1);
        assert!(ack_rx.try_recv().is_err());
    }

    // spec: r1 T6a
    #[tokio::test]
    async fn attempt_body_stream_draining_finishes_active_batch_and_skips_queued_batch() {
        use futures_util::StreamExt;

        use super::{AttemptBodyStream, AttemptSync, FRAME_CHUNK_BYTES};

        let sync = AttemptSync::new();
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        let mut stream = AttemptBodyStream::new(rx, sync.clone());

        // Enqueue a 2-chunk batch and a 2nd queued batch.
        tx.send(Bytes::from(vec![0xAA; FRAME_CHUNK_BYTES + 16]))
            .await
            .unwrap();
        tx.send(Bytes::from_static(b"queued-second-batch"))
            .await
            .unwrap();

        // First chunk starts batch 1.
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.len(), FRAME_CHUNK_BYTES);
        assert_eq!(sync.batches_started(), 1);
        assert!(sync.finish_time(0).is_none());

        // Reconnect advice begins draining before batch 1 finishes and while batch 2 sits queued.
        assert_eq!(sync.start_draining(), 1);
        drop(tx);

        // Batch 1 finishes cleanly...
        let rest = stream.next().await.unwrap().unwrap();
        assert_eq!(rest.len(), 16);
        assert!(sync.finish_time(0).is_some());

        // ...then the stream half-closes cleanly WITHOUT pulling batch 2!
        assert!(stream.next().await.is_none());
        assert_eq!(sync.batches_started(), 1);
        assert!(sync.finish_time(1).is_none());
    }

    #[test]
    fn attempt_sync_finish_time_after_prune_and_gate_transitions() {
        use super::{AttemptSync, GateState};

        let sync = AttemptSync::new();
        for i in 0..100usize {
            assert_eq!(sync.try_start_batch(), GateState::Open);
            assert_eq!(sync.batches_started(), i + 1);
            sync.record_batch_finished();
        }
        // Prune past the 64-entry compaction threshold and verify lookup indexing remains exact.
        sync.prune_finished(70);
        assert!(sync.finish_time(0).is_none());
        assert!(sync.finish_time(69).is_none());
        let t70 = sync.finish_time(70).expect("index 70 retained");
        let t99 = sync.finish_time(99).expect("index 99 retained");
        assert!(t99 >= t70);
        assert!(sync.finish_time(100).is_none());

        assert_eq!(sync.start_draining(), 100);
        assert_eq!(sync.try_start_batch(), GateState::Draining);
        assert_eq!(sync.batches_started(), 100);

        assert_eq!(sync.stop(), 100);
        assert!(sync.is_stopped());
        assert_eq!(sync.try_start_batch(), GateState::Stopped);
        assert_eq!(sync.batches_started(), 100);
    }
}
