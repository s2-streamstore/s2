use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_core::Stream;
use futures_util::{FutureExt, StreamExt};
use s2_api::v1::stream::s2s;
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::{Instant, Sleep},
};
use tracing::debug;

use crate::{
    api::{BasinClient, Streaming, retry_builder},
    batching::RECORD_BATCH_MIN,
    client::ShutdownSignal,
    error::{
        AbortedError, AppendSessionError, ConnectionLostError, ErrorContext, ProtocolError,
        SessionClosedError, TimeoutError,
    },
    reconnect::{AdvisedReconnects, ReconnectAdvice},
    retry::{AppendRetryError, RetryBackoffBuilder},
    session::StreamHeaders,
    types::{
        AccessTokenMode, AppendAck, AppendInput, AppendRetryPolicy, MeteredBytes, ONE_MIB,
        StreamConfig, StreamName, StreamPosition, ValidationError,
    },
};

/// Chunk size used when streaming encoded S2S frames into HTTP/2 DATA frames so wire-send
/// progress tracks HTTP/2 flow control (`T7c`, `T10`).
const FRAME_CHUNK_BYTES: usize = 16 * 1024;

/// A [`Future`] that resolves to an acknowledgement once the batch of records is appended.
pub struct BatchSubmitTicket {
    rx: oneshot::Receiver<Result<AppendAck, AppendSessionError>>,
    lifecycle: Arc<SessionLifecycle>,
    context: ErrorContext,
}

impl fmt::Debug for BatchSubmitTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BatchSubmitTicket").finish_non_exhaustive()
    }
}

impl Future for BatchSubmitTicket {
    type Output = Result<AppendAck, AppendSessionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(res)) => Poll::Ready(res),
            Poll::Ready(Err(_)) => {
                Poll::Ready(Err(self.lifecycle.terminal_err().unwrap_or_else(|| {
                    AppendSessionError::Aborted(AbortedError::new(
                        "append session dropped without calling close",
                        self.context.clone(),
                    ))
                })))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Clone)]
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

    /// Set the limit on total metered bytes of unacknowledged [`AppendInput`]s held in memory.
    ///
    /// **Note:** It must be at least `1MiB`.
    ///
    /// Defaults to `5MiB`.
    pub fn with_max_unacked_bytes(self, max_unacked_bytes: u32) -> Result<Self, ValidationError> {
        if max_unacked_bytes < ONE_MIB {
            return Err(format!("max_unacked_bytes must be at least {ONE_MIB}").into());
        }
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

    pub(crate) fn stream_config(&self) -> Option<&StreamConfig> {
        self.stream_config.as_ref()
    }
}

/// Shared lifecycle coordination for [`AppendSession`] and [`Producer`](crate::producer::Producer).
///
/// Guarantees:
/// - `closing_or_closed` flips immediately when `close()` starts or when the session terminates,
///   waking any `reserve()`/`submit()` waiting on capacity (`A4c`).
/// - Repeated or concurrent `close(&self)` calls return the exact same `Result` (`A8a`).
/// - Dropping a `close(&self)` future cancels only that wait (`T8`).
pub(crate) struct SessionLifecycle {
    closing: AtomicBool,
    closing_watch: watch::Sender<bool>,
    terminal_err: OnceLock<AppendSessionError>,
    close_result: watch::Sender<Option<Result<(), AppendSessionError>>>,
}

impl SessionLifecycle {
    pub(crate) fn new() -> Self {
        let (closing_watch, _) = watch::channel(false);
        let (close_result, _) = watch::channel(None);
        Self {
            closing: AtomicBool::new(false),
            closing_watch,
            terminal_err: OnceLock::new(),
            close_result,
        }
    }

    pub(crate) fn is_closing_or_closed(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.close_result.borrow().is_some()
    }

    pub(crate) fn mark_closing(&self) {
        self.closing.store(true, Ordering::Release);
        self.closing_watch.send_replace(true);
    }

    pub(crate) fn set_terminal_err(&self, err: AppendSessionError) {
        let _ = self.terminal_err.set(err);
        self.mark_closing();
    }

    pub(crate) fn terminal_err(&self) -> Option<AppendSessionError> {
        self.terminal_err.get().cloned()
    }

    pub(crate) fn session_closed_err(&self, context: &ErrorContext) -> AppendSessionError {
        AppendSessionError::SessionClosed(SessionClosedError::new(
            self.terminal_err(),
            context.clone(),
        ))
    }

    pub(crate) fn finish(&self, result: Result<(), AppendSessionError>) {
        if let Err(err) = &result {
            let _ = self.terminal_err.set(err.clone());
        }
        self.mark_closing();
        self.close_result.send_if_modified(|slot| {
            if slot.is_none() {
                *slot = Some(result);
                true
            } else {
                false
            }
        });
    }

    pub(crate) fn wait_closing_or_closed(
        &self,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let mut rx = self.closing_watch.subscribe();
        Box::pin(async move {
            if *rx.borrow_and_update() {
                return;
            }
            let _ = rx.wait_for(|closed| *closed).await;
        })
    }

    pub(crate) async fn wait_closed(&self) -> Result<(), AppendSessionError> {
        let mut rx = self.close_result.subscribe();
        if let Some(result) = rx.borrow_and_update().clone() {
            return result;
        }
        match rx.wait_for(|slot| slot.is_some()).await {
            Ok(guard) => guard.clone().expect("wait_for guarantees Some"),
            Err(_) => self.close_result.borrow().clone().unwrap_or(Ok(())),
        }
    }
}

/// Serializes command acceptance and `close()` initiation so every `submit()` returning `Ok` is
/// ordered strictly before `Command::Close` in the unbounded channel (`A4c`, `A8a`).
struct AcceptanceGate {
    closing: bool,
}

/// A session for high-throughput appending with backpressure control. It can be created from
/// [`append_session`](crate::S2Stream::append_session).
///
/// Supports pipelining multiple [`AppendInput`]s while preserving submission order. Opening a
/// session sends no request until the first batch is submitted.
pub struct AppendSession {
    gate: Arc<StdMutex<AcceptanceGate>>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    permits: AppendPermits,
    lifecycle: Arc<SessionLifecycle>,
    client_shutdown: ShutdownSignal,
    abort_signal: ShutdownSignal,
    context: ErrorContext,
}

impl fmt::Debug for AppendSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppendSession")
            .field("closing_or_closed", &self.lifecycle.is_closing_or_closed())
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
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let permits = AppendPermits::new(config.max_unacked_batches, config.max_unacked_bytes);
        let retry_builder = retry_builder(&client.config.retry);
        let gate = Arc::new(StdMutex::new(AcceptanceGate { closing: false }));
        let lifecycle = Arc::new(SessionLifecycle::new());
        let client_shutdown = client.shutdown_signal();
        let abort_signal = ShutdownSignal::new();
        let context = ErrorContext::stream(
            "append_session",
            client.name.as_ref(),
            stream.as_ref(),
            false,
        );
        tokio::spawn(run_session_with_retry(
            client,
            stream,
            headers,
            cmd_rx,
            retry_builder,
            gate.clone(),
            lifecycle.clone(),
            abort_signal.clone(),
            "append session dropped without calling close",
            context.clone(),
        ));
        Self {
            gate,
            cmd_tx,
            permits,
            lifecycle,
            client_shutdown,
            abort_signal,
            context,
        }
    }

    /// Submit a batch of records for appending.
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
        input: AppendInput,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
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

        if self.lifecycle.is_closing_or_closed() {
            return Err(self.lifecycle.session_closed_err(&self.context));
        }
        if self.client_shutdown.is_closed() || self.abort_signal.is_closed() {
            self.lifecycle.wait_closing_or_closed().await;
            return Err(self.lifecycle.session_closed_err(&self.context));
        }

        let closing_fut = self.lifecycle.wait_closing_or_closed();
        let append_permit = tokio::select! {
            biased;
            _ = closing_fut => {
                return Err(self.lifecycle.session_closed_err(&self.context));
            }
            permit = self.permits.acquire(bytes) => permit,
        };

        if self.lifecycle.is_closing_or_closed() {
            return Err(self.lifecycle.session_closed_err(&self.context));
        }
        if self.client_shutdown.is_closed() || self.abort_signal.is_closed() {
            self.lifecycle.wait_closing_or_closed().await;
            return Err(self.lifecycle.session_closed_err(&self.context));
        }

        Ok(BatchSubmitPermit {
            append_permit,
            reserved_bytes: bytes,
            gate: self.gate.clone(),
            cmd_tx: self.cmd_tx.clone(),
            lifecycle: self.lifecycle.clone(),
            client_shutdown: self.client_shutdown.clone(),
            abort_signal: self.abort_signal.clone(),
            context: self.context.clone(),
        })
    }

    /// Close the session and wait for all accepted batches to reach an outcome.
    ///
    /// Calling `close()` stops accepting new submissions immediately and waits until all
    /// already-accepted batches settle. Repeated or concurrent calls to `close()` return the same
    /// result. Dropping a `close()` future cancels only the wait; dropping the [`AppendSession`]
    /// aborts it.
    pub async fn close(&self) -> Result<(), AppendSessionError> {
        self.initiate_close();
        self.lifecycle.wait_closed().await
    }

    fn initiate_close(&self) {
        let mut gate = self.gate.lock().unwrap();
        if !gate.closing {
            gate.closing = true;
            self.lifecycle.mark_closing();
            let _ = self.cmd_tx.send(Command::Close);
        }
    }
}

impl Drop for AppendSession {
    fn drop(&mut self) {
        if !self.lifecycle.is_closed() {
            self.abort_signal.close();
        }
    }
}

/// A permit to submit a batch after reserving capacity.
pub struct BatchSubmitPermit {
    append_permit: AppendPermit,
    reserved_bytes: u32,
    gate: Arc<StdMutex<AcceptanceGate>>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    lifecycle: Arc<SessionLifecycle>,
    client_shutdown: ShutdownSignal,
    abort_signal: ShutdownSignal,
    context: ErrorContext,
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
    pub fn submit(mut self, input: AppendInput) -> Result<BatchSubmitTicket, AppendSessionError> {
        let metered = input.records.metered_bytes();
        if metered > self.reserved_bytes as usize {
            return Err(AppendSessionError::Validation(ValidationError(format!(
                "batch size in metered bytes ({metered}) exceeds reserved capacity ({})",
                self.reserved_bytes
            ))));
        }

        // Release any unused over-reserved capacity immediately (`A4a`).
        self.append_permit.shrink(metered as u32);

        let (ack_tx, ack_rx) = oneshot::channel();
        {
            let gate = self.gate.lock().unwrap();
            if gate.closing
                || self.lifecycle.is_closing_or_closed()
                || self.client_shutdown.is_closed()
                || self.abort_signal.is_closed()
            {
                return Err(self.lifecycle.session_closed_err(&self.context));
            }
            if self
                .cmd_tx
                .send(Command::Submit {
                    input,
                    ack_tx,
                    permit: Some(self.append_permit),
                })
                .is_err()
            {
                return Err(self.lifecycle.session_closed_err(&self.context));
            }
        }

        Ok(BatchSubmitTicket {
            rx: ack_rx,
            lifecycle: self.lifecycle,
            context: self.context,
        })
    }
}

pub(crate) struct AppendSessionInternal {
    gate: Arc<StdMutex<AcceptanceGate>>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    lifecycle: Arc<SessionLifecycle>,
    abort_signal: ShutdownSignal,
    context: ErrorContext,
}

impl AppendSessionInternal {
    pub(crate) fn new(client: BasinClient, stream: StreamName, headers: StreamHeaders) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let retry_builder = retry_builder(&client.config.retry);
        let gate = Arc::new(StdMutex::new(AcceptanceGate { closing: false }));
        let lifecycle = Arc::new(SessionLifecycle::new());
        let abort_signal = ShutdownSignal::new();
        let context =
            ErrorContext::stream("producer", client.name.as_ref(), stream.as_ref(), false);
        tokio::spawn(run_session_with_retry(
            client,
            stream,
            headers,
            cmd_rx,
            retry_builder,
            gate.clone(),
            lifecycle.clone(),
            abort_signal.clone(),
            "producer dropped without calling close",
            context.clone(),
        ));
        Self {
            gate,
            cmd_tx,
            lifecycle,
            abort_signal,
            context,
        }
    }

    pub(crate) fn terminal_err(&self) -> Option<AppendSessionError> {
        self.lifecycle.terminal_err()
    }

    pub(crate) fn submit(
        &self,
        input: AppendInput,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        {
            let gate = self.gate.lock().unwrap();
            if gate.closing || self.lifecycle.is_closing_or_closed() {
                return Err(self.lifecycle.session_closed_err(&self.context));
            }
            if self
                .cmd_tx
                .send(Command::Submit {
                    input,
                    ack_tx,
                    permit: None,
                })
                .is_err()
            {
                return Err(self.lifecycle.session_closed_err(&self.context));
            }
        }
        Ok(BatchSubmitTicket {
            rx: ack_rx,
            lifecycle: self.lifecycle.clone(),
            context: self.context.clone(),
        })
    }

    pub(crate) async fn close(&self) -> Result<(), AppendSessionError> {
        {
            let mut gate = self.gate.lock().unwrap();
            if !gate.closing {
                gate.closing = true;
                self.lifecycle.mark_closing();
                let _ = self.cmd_tx.send(Command::Close);
            }
        }
        self.lifecycle.wait_closed().await
    }

    pub(crate) fn abort(&self) {
        if !self.lifecycle.is_closed() {
            self.abort_signal.close();
        }
    }
}

impl Drop for AppendSessionInternal {
    fn drop(&mut self) {
        self.abort();
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
}

impl Drop for AppendPermit {
    fn drop(&mut self) {
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
                available_bytes: bytes_permits,
                next_waiter_id: 0,
                waiters: VecDeque::new(),
            })),
        }
    }

    pub(crate) fn try_acquire(&self, bytes: u32) -> Option<AppendPermit> {
        let mut state = self.inner.lock().unwrap();
        if state.waiters.is_empty() && state.can_satisfy(bytes) {
            state.take(bytes);
            Some(AppendPermit {
                inner: self.inner.clone(),
                bytes,
            })
        } else {
            None
        }
    }

    pub(crate) async fn acquire(&self, bytes: u32) -> AppendPermit {
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

        let mut guard = {
            let mut state = self.inner.lock().unwrap();
            if state.waiters.is_empty() && state.can_satisfy(bytes) {
                state.take(bytes);
                return AppendPermit {
                    inner: self.inner.clone(),
                    bytes,
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
            AcquireGuard {
                inner: &self.inner,
                id,
                bytes,
                rx,
                acquired: false,
            }
        };

        let _ = (&mut guard.rx).await;
        guard.acquired = true;
        AppendPermit {
            inner: self.inner.clone(),
            bytes,
        }
    }
}

struct SessionState {
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    inflight_appends: VecDeque<InflightAppend>,
    inflight_bytes: usize,
    closing: bool,
    total_records: u64,
    total_acked_records: u64,
    prev_ack_end: Option<StreamPosition>,
}

impl SessionState {
    fn is_close_complete(&self) -> bool {
        self.closing && self.inflight_appends.is_empty()
    }

    fn push_submit(
        &mut self,
        input: AppendInput,
        ack_tx: oneshot::Sender<Result<AppendAck, AppendSessionError>>,
        permit: Option<AppendPermit>,
        context: &ErrorContext,
    ) {
        if self.closing {
            let _ = ack_tx.send(Err(AppendSessionError::SessionClosed(
                SessionClosedError::new(None, context.clone()),
            )));
            return;
        }
        let input_metered_bytes = input.records.metered_bytes();
        self.total_records = self
            .total_records
            .saturating_add(input.records.len() as u64);
        self.inflight_bytes += input_metered_bytes;
        self.inflight_appends.push_back(InflightAppend {
            input,
            input_metered_bytes,
            ack_tx,
            _permit: permit,
            sent_ever: false,
            prior_uncertainty: false,
            attempt_last_byte_rx: None,
            attempt_last_byte_at: None,
        });
    }
}

struct InflightAppend {
    input: AppendInput,
    input_metered_bytes: usize,
    ack_tx: oneshot::Sender<Result<AppendAck, AppendSessionError>>,
    _permit: Option<AppendPermit>,
    sent_ever: bool,
    prior_uncertainty: bool,
    attempt_last_byte_rx: Option<oneshot::Receiver<Instant>>,
    attempt_last_byte_at: Option<Instant>,
}

#[allow(clippy::large_enum_variant)]
enum Command {
    Submit {
        input: AppendInput,
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
    frame: Bytes,
    last_byte_tx: Option<oneshot::Sender<Instant>>,
}

struct ActiveOutbound {
    remaining: Bytes,
    last_byte_tx: Option<oneshot::Sender<Instant>>,
}

struct AttemptBodyStream {
    rx: mpsc::Receiver<OutboundBatch>,
    current: Option<ActiveOutbound>,
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
            {
                let gate = this.gate.lock().unwrap();
                if gate.stopped {
                    this.current = None;
                    this.aborted = true;
                    return Poll::Ready(Some(Err(Self::abort_err())));
                }
            }
            let take_len = active.remaining.len().min(FRAME_CHUNK_BYTES);
            let chunk = active.remaining.split_to(take_len);
            if active.remaining.is_empty() {
                if let Some(tx) = active.last_byte_tx.take() {
                    let _ = tx.send(Instant::now());
                }
                this.current = None;
            }
            return Poll::Ready(Some(Ok(chunk)));
        }

        {
            let gate = this.gate.lock().unwrap();
            if gate.stopped {
                this.aborted = true;
                return Poll::Ready(Some(Err(Self::abort_err())));
            }
        }

        match this.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(mut batch)) => {
                {
                    let mut gate = this.gate.lock().unwrap();
                    if gate.stopped {
                        this.aborted = true;
                        return Poll::Ready(Some(Err(Self::abort_err())));
                    }
                    gate.batches_started += 1;
                }
                let take_len = batch.frame.len().min(FRAME_CHUNK_BYTES);
                let chunk = batch.frame.split_to(take_len);
                if batch.frame.is_empty() {
                    if let Some(tx) = batch.last_byte_tx.take() {
                        let _ = tx.send(Instant::now());
                    }
                } else {
                    this.current = Some(ActiveOutbound {
                        remaining: batch.frame,
                        last_byte_tx: batch.last_byte_tx,
                    });
                }
                Poll::Ready(Some(Ok(chunk)))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AbortReason {
    ClientClosed,
    SessionDropped(&'static str),
}

impl AbortReason {
    fn message(self) -> &'static str {
        match self {
            Self::ClientClosed => "client closed",
            Self::SessionDropped(msg) => msg,
        }
    }
}

enum AttemptResult {
    /// Everything accepted was acknowledged and the caller closed the session.
    Closed,
    /// Connection ended cleanly or broke while nothing was unacked (`A3`, `T9`).
    IdleEnded,
    /// Server advised reconnecting and all sent batches drained cleanly (`T6a`).
    ReconnectAdvised { made_progress: bool },
    /// Session was aborted (`C12`, `A8c`).
    Aborted { reason: AbortReason },
    /// Attempt failed with an error.
    Error {
        err: AppendSessionError,
        made_progress: bool,
        unacked_sent_in_attempt: usize,
    },
}

#[allow(clippy::too_many_arguments)]
async fn run_session_with_retry(
    client: BasinClient,
    stream: StreamName,
    headers: StreamHeaders,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    retry_builder: RetryBackoffBuilder,
    gate: Arc<StdMutex<AcceptanceGate>>,
    lifecycle: Arc<SessionLifecycle>,
    abort_signal: ShutdownSignal,
    dropped_abort_msg: &'static str,
    context: ErrorContext,
) {
    let access_token_mode = client.config.access_token.mode();
    let client_shutdown = client.shutdown_signal();

    let mut state = SessionState {
        cmd_rx,
        inflight_appends: VecDeque::new(),
        inflight_bytes: 0,
        closing: false,
        total_records: 0,
        total_acked_records: 0,
        prev_ack_end: None,
    };
    let mut retry_backoff = retry_builder.build();
    let mut advised_reconnects = AdvisedReconnects::default();
    let mut attempts: u32 = 0;

    loop {
        if let Some(reason) = check_abort(&client_shutdown, &abort_signal, dropped_abort_msg) {
            abort_session(&mut state, &gate, &lifecycle, &context, reason);
            return;
        }

        // Lazy open (A3, T6): do not open a request until we have a batch to send.
        if state.inflight_appends.is_empty() {
            if state.is_close_complete() {
                finish_clean(&mut state, &gate, &lifecycle, &context);
                return;
            }
            match wait_for_work(
                &mut state,
                &client_shutdown,
                &abort_signal,
                dropped_abort_msg,
                &context,
            )
            .await
            {
                IdleWait::WorkReady => {}
                IdleWait::Closed => {
                    finish_clean(&mut state, &gate, &lifecycle, &context);
                    return;
                }
                IdleWait::Aborted(reason) => {
                    abort_session(&mut state, &gate, &lifecycle, &context, reason);
                    return;
                }
            }
        }

        let attempt_num = retry_backoff.used() + 1;
        let result = run_attempt(
            &client,
            &stream,
            &headers,
            &mut state,
            advised_reconnects,
            &client_shutdown,
            &abort_signal,
            dropped_abort_msg,
            &context,
            attempt_num,
        )
        .await;

        match result {
            AttemptResult::Closed => {
                finish_clean(&mut state, &gate, &lifecycle, &context);
                return;
            }
            AttemptResult::IdleEnded => {
                // T9 / A3: clean end or break while nothing is unacked is not an error and uses
                // no budget. Reset retry state so earlier transient failures do not leak across
                // an idle gap.
                retry_backoff.reset();
                attempts = 0;
                continue;
            }
            AttemptResult::ReconnectAdvised { made_progress } => {
                advised_reconnects.record();
                if made_progress {
                    retry_backoff.reset();
                    attempts = 0;
                    debug!(
                        inflight_appends_len = state.inflight_appends.len(),
                        advised_reconnects = advised_reconnects.count(),
                        "reconnecting append session on server advice"
                    );
                } else if let Some(backoff) = retry_backoff.next() {
                    if let Some(reason) =
                        sleep_or_abort(backoff, &client_shutdown, &abort_signal, dropped_abort_msg)
                            .await
                    {
                        abort_session(&mut state, &gate, &lifecycle, &context, reason);
                        return;
                    }
                } else {
                    attempts += 1;
                    let attempt_ctx = context.clone().with_attempts(attempts);
                    let err = AppendSessionError::ConnectionLost(ConnectionLostError::new(
                        "server repeatedly advised reconnecting without progress",
                        true,
                        attempt_ctx,
                    ));
                    settle_terminal_error(&mut state, &gate, &lifecycle, &context, err, 0);
                    return;
                }
            }
            AttemptResult::Aborted { reason } => {
                abort_session(&mut state, &gate, &lifecycle, &context, reason);
                return;
            }
            AttemptResult::Error {
                mut err,
                made_progress,
                unacked_sent_in_attempt,
            } => {
                if made_progress {
                    retry_backoff.reset();
                    attempts = 0;
                }

                if err.is_server_draining() && state.is_close_complete() {
                    finish_clean(&mut state, &gate, &lifecycle, &context);
                    return;
                }
                if err.is_server_draining() && made_progress {
                    debug!(
                        inflight_appends_len = state.inflight_appends.len(),
                        "reconnecting append session while server drains"
                    );
                    continue;
                }

                // E3 / Terms: ConnectionLostError is definite if nothing unacked was sent in this
                // attempt.
                if unacked_sent_in_attempt == 0
                    && let AppendSessionError::ConnectionLost(conn_lost) = err
                {
                    err = AppendSessionError::ConnectionLost(conn_lost.with_no_side_effects(true));
                }

                attempts += 1;
                let attempt_ctx = context.clone().with_attempts(attempts);
                let err = err.with_context(&attempt_ctx);
                let attempt_may_have_side_effects =
                    unacked_sent_in_attempt > 0 && !err.has_no_side_effects();

                if is_safe_to_retry(
                    &err,
                    client.config.retry.append_retry_policy,
                    attempt_may_have_side_effects,
                    access_token_mode,
                ) && let Some(backoff) = retry_backoff.next()
                {
                    if attempt_may_have_side_effects {
                        for append in state
                            .inflight_appends
                            .iter_mut()
                            .take(unacked_sent_in_attempt)
                        {
                            append.prior_uncertainty = true;
                        }
                    }
                    debug!(
                        %err,
                        ?backoff,
                        num_retries_remaining = retry_backoff.remaining(),
                        "retrying append session"
                    );
                    if let Some(reason) =
                        sleep_or_abort(backoff, &client_shutdown, &abort_signal, dropped_abort_msg)
                            .await
                    {
                        abort_session(&mut state, &gate, &lifecycle, &context, reason);
                        return;
                    }
                } else {
                    debug!(
                        %err,
                        retries_exhausted = retry_backoff.is_exhausted(),
                        "not retrying append session"
                    );
                    settle_terminal_error(
                        &mut state,
                        &gate,
                        &lifecycle,
                        &context,
                        err,
                        unacked_sent_in_attempt,
                    );
                    return;
                }
            }
        }
    }
}

enum IdleWait {
    WorkReady,
    Closed,
    Aborted(AbortReason),
}

async fn wait_for_work(
    state: &mut SessionState,
    client_shutdown: &ShutdownSignal,
    abort_signal: &ShutdownSignal,
    dropped_abort_msg: &'static str,
    context: &ErrorContext,
) -> IdleWait {
    let mut client_closed = client_shutdown.cancelled();
    let mut dropped = abort_signal.cancelled();

    loop {
        tokio::select! {
            biased;
            _ = &mut client_closed => return IdleWait::Aborted(AbortReason::ClientClosed),
            _ = &mut dropped => return IdleWait::Aborted(AbortReason::SessionDropped(dropped_abort_msg)),
            cmd = state.cmd_rx.recv() => {
                match cmd {
                    Some(Command::Submit { input, ack_tx, permit }) => {
                        state.push_submit(input, ack_tx, permit, context);
                        if !state.inflight_appends.is_empty() {
                            return IdleWait::WorkReady;
                        }
                    }
                    Some(Command::Close) => {
                        state.closing = true;
                        return IdleWait::Closed;
                    }
                    None => {
                        return IdleWait::Aborted(AbortReason::SessionDropped(dropped_abort_msg));
                    }
                }
            }
        }
    }
}

fn check_abort(
    client_shutdown: &ShutdownSignal,
    abort_signal: &ShutdownSignal,
    dropped_abort_msg: &'static str,
) -> Option<AbortReason> {
    if client_shutdown.is_closed() {
        Some(AbortReason::ClientClosed)
    } else if abort_signal.is_closed() {
        Some(AbortReason::SessionDropped(dropped_abort_msg))
    } else {
        None
    }
}

async fn sleep_or_abort(
    duration: Duration,
    client_shutdown: &ShutdownSignal,
    abort_signal: &ShutdownSignal,
    dropped_abort_msg: &'static str,
) -> Option<AbortReason> {
    tokio::select! {
        biased;
        _ = client_shutdown.cancelled() => Some(AbortReason::ClientClosed),
        _ = abort_signal.cancelled() => Some(AbortReason::SessionDropped(dropped_abort_msg)),
        _ = tokio::time::sleep(duration) => None,
    }
}

fn drain_queued_commands(state: &mut SessionState) -> Vec<Command> {
    state.cmd_rx.close();
    let mut queued = Vec::new();
    while let Ok(cmd) = state.cmd_rx.try_recv() {
        queued.push(cmd);
    }
    queued
}

fn finish_clean(
    state: &mut SessionState,
    gate: &StdMutex<AcceptanceGate>,
    lifecycle: &SessionLifecycle,
    context: &ErrorContext,
) {
    {
        let mut g = gate.lock().unwrap();
        g.closing = true;
    }
    lifecycle.mark_closing();
    let closed_err =
        AppendSessionError::SessionClosed(SessionClosedError::new(None, context.clone()));
    for cmd in drain_queued_commands(state) {
        if let Command::Submit { ack_tx, .. } = cmd {
            let _ = ack_tx.send(Err(closed_err.clone()));
        }
    }
    lifecycle.finish(Ok(()));
}

fn abort_session(
    state: &mut SessionState,
    gate: &StdMutex<AcceptanceGate>,
    lifecycle: &SessionLifecycle,
    context: &ErrorContext,
    reason: AbortReason,
) {
    let aborted = AppendSessionError::Aborted(AbortedError::new(reason.message(), context.clone()));
    let (queued, has_pending_work) = {
        // Hold gate across checking pending work AND publishing terminal_err / closing so
        // concurrent reserve()/submit() callers never observe SessionClosedError { failure: None }
        // on an aborted session with pending work.
        let mut g = gate.lock().unwrap();
        g.closing = true;
        let queued = drain_queued_commands(state);
        let has_pending_work = !state.inflight_appends.is_empty()
            || queued
                .iter()
                .any(|cmd| matches!(cmd, Command::Submit { .. }));
        if has_pending_work {
            lifecycle.set_terminal_err(aborted.clone());
        } else {
            lifecycle.mark_closing();
        }
        (queued, has_pending_work)
    };

    if !has_pending_work {
        // A8c: aborting an idle append session loses nothing, so the close is clean.
        lifecycle.finish(Ok(()));
        return;
    }

    let unsent = AppendSessionError::SessionClosed(SessionClosedError::new(
        Some(aborted.clone()),
        context.clone(),
    ));

    for append in state.inflight_appends.drain(..) {
        let outcome = if append.sent_ever {
            aborted.clone()
        } else {
            unsent.clone()
        };
        let _ = append.ack_tx.send(Err(outcome));
    }
    state.inflight_bytes = 0;

    for cmd in queued {
        if let Command::Submit { ack_tx, .. } = cmd {
            let _ = ack_tx.send(Err(unsent.clone()));
        }
    }

    lifecycle.finish(Err(aborted));
}

/// Settle all unacked and queued batches according to `A6a`, `A6b`, and `A9`.
fn settle_terminal_error(
    state: &mut SessionState,
    gate: &StdMutex<AcceptanceGate>,
    lifecycle: &SessionLifecycle,
    context: &ErrorContext,
    final_err: AppendSessionError,
    unacked_sent_in_attempt: usize,
) {
    let from_server = matches!(
        final_err,
        AppendSessionError::Server(_)
            | AppendSessionError::SeqNumMismatch(_)
            | AppendSessionError::FencingTokenMismatch(_)
    );
    let rejected = from_server && unacked_sent_in_attempt > 0 && !state.inflight_appends.is_empty();
    let rejected_definite = rejected && final_err.has_no_side_effects();

    // A6b / A9: determine whether any batch's outcome will be wrapped in IndefiniteAppendError.
    let any_batch_wrapped = state
        .inflight_appends
        .iter()
        .enumerate()
        .any(|(i, append)| {
            if !append.prior_uncertainty {
                return false;
            }
            if i == 0 && rejected {
                final_err.has_no_side_effects()
            } else if (i > 0 && rejected_definite) || !append.sent_ever {
                true
            } else {
                final_err.has_no_side_effects()
            }
        });

    // A9: session failure is final_err, wrapped in IndefiniteAppendError if final_err is definite
    // and any batch's outcome was wrapped.
    let session_failure = if final_err.has_no_side_effects() && any_batch_wrapped {
        final_err.clone().into_indefinite_failure()
    } else {
        final_err.clone()
    };

    // Publish terminal error before setting gate.closing so concurrent reserve/submit callers
    // always observe the session failure on SessionClosedError.
    lifecycle.set_terminal_err(session_failure.clone());
    {
        let mut g = gate.lock().unwrap();
        g.closing = true;
    }
    let closed_err = AppendSessionError::SessionClosed(SessionClosedError::new(
        Some(session_failure.clone()),
        context.clone(),
    ));

    for (i, append) in state.inflight_appends.drain(..).enumerate() {
        let base_outcome = if i == 0 && rejected {
            final_err.clone()
        } else if (i > 0 && rejected_definite) || !append.sent_ever {
            closed_err.clone()
        } else {
            final_err.clone()
        };
        let outcome = base_outcome.with_prior_uncertainty(append.prior_uncertainty);
        let _ = append.ack_tx.send(Err(outcome));
    }
    state.inflight_bytes = 0;

    for cmd in drain_queued_commands(state) {
        if let Command::Submit { ack_tx, .. } = cmd {
            let _ = ack_tx.send(Err(closed_err.clone()));
        }
    }

    lifecycle.finish(Err(session_failure));
}

#[allow(clippy::too_many_arguments)]
async fn run_attempt(
    client: &BasinClient,
    stream: &StreamName,
    headers: &StreamHeaders,
    state: &mut SessionState,
    advised_reconnects: AdvisedReconnects,
    client_shutdown: &ShutdownSignal,
    abort_signal: &ShutdownSignal,
    dropped_abort_msg: &'static str,
    context: &ErrorContext,
    attempt: u32,
) -> AttemptResult {
    // Clear per-attempt wire-send state on all unacked batches.
    for append in &mut state.inflight_appends {
        append.attempt_last_byte_rx = None;
        append.attempt_last_byte_at = None;
    }

    let send_gate = AttemptSendGate::new();
    let reconnect = ReconnectAdvice::default();
    let (input_tx, input_rx) = mpsc::channel::<OutboundBatch>(1);
    let body_stream = AttemptBodyStream::new(input_rx, send_gate.clone());

    let connect_fut = client.append_session(
        stream,
        body_stream,
        headers.encryption.as_ref(),
        headers.stream_config.as_ref(),
        reconnect.clone(),
        attempt,
    );

    let mut client_closed_fut = client_shutdown.cancelled();
    let mut abort_fut = abort_signal.cancelled();

    let ack_stream = tokio::select! {
        biased;
        _ = &mut client_closed_fut => {
            AttemptSendGate::stop(&send_gate);
            return AttemptResult::Aborted { reason: AbortReason::ClientClosed };
        }
        _ = &mut abort_fut => {
            AttemptSendGate::stop(&send_gate);
            return AttemptResult::Aborted { reason: AbortReason::SessionDropped(dropped_abort_msg) };
        }
        res = connect_fut => match res {
            Ok(s) => s,
            Err(err) => {
                AttemptSendGate::stop(&send_gate);
                if let Some(reason) = check_abort(client_shutdown, abort_signal, dropped_abort_msg) {
                    return AttemptResult::Aborted { reason };
                }
                return AttemptResult::Error {
                    err: err.into(),
                    made_progress: false,
                    unacked_sent_in_attempt: 0,
                };
            }
        }
    };

    let ack_ctx = context.clone();
    let mut acks: Streaming<AppendAck> = Box::pin(ack_stream.map(move |ack| match ack {
        Ok(ack) => {
            AppendAck::try_from_proto(ack, ack_ctx.clone()).map_err(crate::api::ApiError::Protocol)
        }
        Err(err) => Err(err),
    }));

    let ack_timeout = client.config.request_timeout;
    let compression: s2s::CompressionAlgorithm = client.config.compression.into();
    let mut input_tx = Some(input_tx);
    let mut send_cursor: usize = 0;
    let mut acked_in_attempt: usize = 0;
    let mut draining_for_reconnect = false;
    let mut declined_advice = false;

    let mut became_oldest_at: Option<Instant> =
        (!state.inflight_appends.is_empty()).then(Instant::now);
    let ack_timer = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(ack_timer);
    let mut ack_timer_armed = false;

    loop {
        if state.is_close_complete() {
            finish_attempt_gate(&send_gate, acked_in_attempt, state);
            drop(input_tx);
            drop(acks);
            return AttemptResult::Closed;
        }

        // T6a: Act on reconnect advice once per 60s by half-closing and draining all batches
        // already sent on this request.
        if !draining_for_reconnect && reconnect.is_advised() && !declined_advice {
            if advised_reconnects.should_reconnect() {
                draining_for_reconnect = true;
                // Stop sending new batches on this request; half-close so the server acks
                // everything already pushed into `input_tx`.
                drop(input_tx.take());
                if send_cursor == 0 {
                    finish_attempt_gate(&send_gate, acked_in_attempt, state);
                    drop(acks);
                    return AttemptResult::ReconnectAdvised {
                        made_progress: acked_in_attempt > 0,
                    };
                }
            } else {
                declined_advice = true;
            }
        }

        // Check if oldest unacked batch already finished sending its last byte (e.g. while it was
        // pipelined behind an earlier batch), and arm the T7c timer immediately if so.
        refresh_oldest_timer(
            state,
            became_oldest_at,
            ack_timeout,
            ack_timer.as_mut(),
            &mut ack_timer_armed,
        );

        // If the request body was dropped by hyper (not an advised drain), bound waiting for the
        // server's response error or EOF.
        if input_tx.is_none() && !draining_for_reconnect && !ack_timer_armed {
            ack_timer.as_mut().reset(Instant::now() + ack_timeout);
            ack_timer_armed = true;
        }

        let can_send_more = input_tx.is_some()
            && !draining_for_reconnect
            && send_cursor < state.inflight_appends.len();
        let wait_oldest_last_byte = !ack_timer_armed
            && state
                .inflight_appends
                .front()
                .is_some_and(|f| f.attempt_last_byte_rx.is_some());

        let mut drop_input_tx = false;

        tokio::select! {
            biased;

            // T10: process already-received acks first, in order.
            ack = acks.next() => {
                match ack {
                    Some(Ok(ack)) => {
                        match process_ack(ack, state, send_cursor, context) {
                            Ok(()) => {
                                acked_in_attempt += 1;
                                send_cursor = send_cursor.saturating_sub(1);
                                ack_timer_armed = false;
                                became_oldest_at = (!state.inflight_appends.is_empty()).then(Instant::now);
                                if draining_for_reconnect && send_cursor == 0 {
                                    // All batches sent on the advised request are acked; reconnect
                                    // immediately rather than waiting indefinitely for server EOF.
                                    finish_attempt_gate(&send_gate, acked_in_attempt, state);
                                    drop(acks);
                                    return AttemptResult::ReconnectAdvised {
                                        made_progress: acked_in_attempt > 0,
                                    };
                                }
                            }
                            Err(err) => {
                                let unacked_sent = finish_attempt_gate(&send_gate, acked_in_attempt, state);
                                return AttemptResult::Error {
                                    err,
                                    made_progress: acked_in_attempt > 0,
                                    unacked_sent_in_attempt: unacked_sent,
                                };
                            }
                        }
                    }
                    Some(Err(api_err)) => {
                        let err: AppendSessionError = api_err.into();
                        let unacked_sent = finish_attempt_gate(&send_gate, acked_in_attempt, state);

                        if let Some(reason) = check_abort(client_shutdown, abort_signal, dropped_abort_msg) {
                            return AttemptResult::Aborted { reason };
                        }

                        // T9 / A3: Connection break or retryable error while nothing is unacked is
                        // not a session error and uses no budget.
                        if state.inflight_appends.is_empty()
                            && (matches!(err, AppendSessionError::ConnectionLost(_))
                                || err.is_retryable())
                        {
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
                        let unacked_sent = finish_attempt_gate(&send_gate, acked_in_attempt, state);

                        if let Some(reason) = check_abort(client_shutdown, abort_signal, dropped_abort_msg) {
                            return AttemptResult::Aborted { reason };
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
                                    context.clone(),
                                )),
                                made_progress: acked_in_attempt > 0,
                                unacked_sent_in_attempt: unacked_sent,
                            };
                        }

                        // T9: Clean end with nothing unacked -> no error, no budget used (A3).
                        if state.inflight_appends.is_empty() {
                            return if state.closing {
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
                                context.clone(),
                            )),
                            made_progress: acked_in_attempt > 0,
                            unacked_sent_in_attempt: unacked_sent,
                        };
                    }
                }
            }

            _ = &mut client_closed_fut => {
                drain_ready_acks(&mut acks, state, &mut acked_in_attempt, &mut send_cursor, context);
                finish_attempt_gate(&send_gate, acked_in_attempt, state);
                return AttemptResult::Aborted { reason: AbortReason::ClientClosed };
            }

            _ = &mut abort_fut => {
                drain_ready_acks(&mut acks, state, &mut acked_in_attempt, &mut send_cursor, context);
                finish_attempt_gate(&send_gate, acked_in_attempt, state);
                return AttemptResult::Aborted { reason: AbortReason::SessionDropped(dropped_abort_msg) };
            }

            _ = &mut ack_timer, if ack_timer_armed => {
                let unacked_sent = finish_attempt_gate(&send_gate, acked_in_attempt, state);
                return AttemptResult::Error {
                    err: AppendSessionError::Timeout(TimeoutError::new(
                        "append acknowledgement timed out",
                        context.clone(),
                    )),
                    made_progress: acked_in_attempt > 0,
                    unacked_sent_in_attempt: unacked_sent,
                };
            }

            sent_at = async {
                state
                    .inflight_appends
                    .front_mut()
                    .expect("front exists")
                    .attempt_last_byte_rx
                    .as_mut()
                    .expect("rx exists")
                    .await
            }, if wait_oldest_last_byte => {
                if let Some(front) = state.inflight_appends.front_mut() {
                    front.attempt_last_byte_rx = None;
                    match sent_at {
                        Ok(sent_at) => {
                            front.attempt_last_byte_at = Some(sent_at);
                            let start = became_oldest_at.map_or(sent_at, |b| b.max(sent_at));
                            ack_timer.as_mut().reset(start + ack_timeout);
                            ack_timer_armed = true;
                        }
                        Err(_) => {
                            // Body stream dropped before sending last byte; arm ack_timer so we
                            // stay bounded while `acks.next()` drains any server error or EOF.
                            ack_timer.as_mut().reset(Instant::now() + ack_timeout);
                            ack_timer_armed = true;
                        }
                    }
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
                        let append = &mut state.inflight_appends[send_cursor];
                        let api_input: s2_api::v1::stream::proto::AppendInput =
                            append.input.clone().into();
                        let encoded = match s2s::SessionMessage::regular(compression, &api_input) {
                            Ok(msg) => msg.encode(),
                            Err(err) => {
                                let unacked_sent =
                                    finish_attempt_gate(&send_gate, acked_in_attempt, state);
                                return AttemptResult::Error {
                                    err: AppendSessionError::Protocol(ProtocolError::new(
                                        format!("failed to encode append frame: {err}"),
                                        context.clone(),
                                    )),
                                    made_progress: acked_in_attempt > 0,
                                    unacked_sent_in_attempt: unacked_sent,
                                };
                            }
                        };
                        let (last_byte_tx, last_byte_rx) = oneshot::channel();
                        append.attempt_last_byte_rx = Some(last_byte_rx);
                        permit.send(OutboundBatch {
                            frame: encoded,
                            last_byte_tx: Some(last_byte_tx),
                        });
                        send_cursor += 1;
                    }
                    Err(_) => {
                        // Hyper dropped the request body stream (e.g. server replied with a
                        // terminal error or reset the stream). Stop sending and stay in the loop
                        // so `acks.next()` drains all buffered acks and surfaces the real
                        // terminal server error or EOF (`T10`, `A6a`).
                        drop_input_tx = true;
                        if !ack_timer_armed {
                            ack_timer.as_mut().reset(Instant::now() + ack_timeout);
                            ack_timer_armed = true;
                        }
                    }
                }
            }

            cmd = state.cmd_rx.recv() => {
                match cmd {
                    Some(Command::Submit { input, ack_tx, permit }) => {
                        let was_empty = state.inflight_appends.is_empty();
                        state.push_submit(input, ack_tx, permit, context);
                        if was_empty && !state.inflight_appends.is_empty() {
                            became_oldest_at = Some(Instant::now());
                        }
                    }
                    Some(Command::Close) => {
                        state.closing = true;
                    }
                    None => {
                        drain_ready_acks(&mut acks, state, &mut acked_in_attempt, &mut send_cursor, context);
                        finish_attempt_gate(&send_gate, acked_in_attempt, state);
                        return AttemptResult::Aborted { reason: AbortReason::SessionDropped(dropped_abort_msg) };
                    }
                }
            }
        }

        if drop_input_tx {
            input_tx = None;
        }
    }
}

fn refresh_oldest_timer(
    state: &mut SessionState,
    became_oldest_at: Option<Instant>,
    ack_timeout: Duration,
    mut ack_timer: Pin<&mut Sleep>,
    ack_timer_armed: &mut bool,
) {
    if *ack_timer_armed {
        return;
    }
    let Some(front) = state.inflight_appends.front_mut() else {
        return;
    };
    if front.attempt_last_byte_at.is_none()
        && let Some(rx) = front.attempt_last_byte_rx.as_mut()
    {
        match rx.try_recv() {
            Ok(sent_at) => {
                front.attempt_last_byte_at = Some(sent_at);
                front.attempt_last_byte_rx = None;
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
            Err(oneshot::error::TryRecvError::Closed) => {
                front.attempt_last_byte_rx = None;
                ack_timer.as_mut().reset(Instant::now() + ack_timeout);
                *ack_timer_armed = true;
                return;
            }
        }
    }
    if let Some(sent_at) = front.attempt_last_byte_at {
        let start = became_oldest_at.map_or(sent_at, |b| b.max(sent_at));
        ack_timer.as_mut().reset(start + ack_timeout);
        *ack_timer_armed = true;
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
    acks: &mut Streaming<AppendAck>,
    state: &mut SessionState,
    acked_in_attempt: &mut usize,
    send_cursor: &mut usize,
    context: &ErrorContext,
) {
    while let Some(Some(Ok(ack))) = acks.next().now_or_never() {
        if process_ack(ack, state, *send_cursor, context).is_err() {
            break;
        }
        *acked_in_attempt += 1;
        *send_cursor = send_cursor.saturating_sub(1);
    }
}

fn process_ack(
    ack: AppendAck,
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

    if state
        .prev_ack_end
        .is_some_and(|end| ack.start.seq_num < end.seq_num || ack.end.seq_num <= end.seq_num)
    {
        return Err(AppendSessionError::Protocol(ProtocolError::new(
            "ack range must not overlap or precede previous ack end",
            context.clone(),
        )));
    }

    let expected_records = corresponding_append.input.records.len() as u64;
    ack.validate_record_count(expected_records, context)
        .map_err(AppendSessionError::Protocol)?;
    let num_acked_records = ack.end.seq_num - ack.start.seq_num;

    let corresponding_append = state
        .inflight_appends
        .pop_front()
        .expect("inflight front was checked above");
    state.total_acked_records = state.total_acked_records.saturating_add(num_acked_records);
    state.inflight_bytes -= corresponding_append.input_metered_bytes;
    state.prev_ack_end = Some(ack.end);

    let _ = corresponding_append.ack_tx.send(Ok(ack));

    if state.inflight_appends.is_empty() {
        debug_assert_eq!(
            state.total_records, state.total_acked_records,
            "all records should be acked when inflight is empty"
        );
    }

    Ok(())
}

fn is_safe_to_retry(
    err: &AppendSessionError,
    policy: AppendRetryPolicy,
    attempt_may_have_side_effects: bool,
    access_token_mode: AccessTokenMode,
) -> bool {
    let policy_compliant = match policy {
        AppendRetryPolicy::All => true,
        AppendRetryPolicy::NoSideEffects => !attempt_may_have_side_effects,
    };
    policy_compliant
        && (err.is_retryable()
            || (access_token_mode.is_refreshable() && err.is_authentication_error()))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use http::StatusCode;

    use super::{AppendSessionError, is_safe_to_retry};
    use crate::{
        error::{ErrorContext, ServerError, TimeoutError},
        retry::AppendRetryError,
        types::{AccessTokenMode, AppendRetryPolicy},
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
        let static_mode = AccessTokenMode::Static;

        assert!(is_safe_to_retry(&retryable, policy, true, static_mode));
        assert!(!is_safe_to_retry(&non_retryable, policy, true, static_mode));

        let unauthorized = server_error(StatusCode::UNAUTHORIZED, "authn");
        #[cfg(feature = "_hidden")]
        assert!(is_safe_to_retry(
            &unauthorized,
            policy,
            true,
            AccessTokenMode::Refreshable,
        ));
        assert!(!is_safe_to_retry(&unauthorized, policy, true, static_mode));

        #[cfg(feature = "_hidden")]
        let unrelated_unauthorized = server_error(StatusCode::UNAUTHORIZED, "other");
        #[cfg(feature = "_hidden")]
        assert!(!is_safe_to_retry(
            &unrelated_unauthorized,
            policy,
            true,
            AccessTokenMode::Refreshable,
        ));
    }

    #[test]
    fn safe_to_retry_session_no_side_effects_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let no_side_effect = server_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        let policy = AppendRetryPolicy::NoSideEffects;
        let mode = AccessTokenMode::Static;

        // No possible side effects (e.g. nothing unacked sent, or definite error) -> safe.
        assert!(is_safe_to_retry(&retryable, policy, false, mode));
        assert!(is_safe_to_retry(&no_side_effect, policy, false, mode));

        // Possible side effects -> not safe under NoSideEffects.
        assert!(!is_safe_to_retry(&retryable, policy, true, mode));
        assert!(!is_safe_to_retry(
            &AppendSessionError::Timeout(TimeoutError::new(
                "append acknowledgement timed out",
                ErrorContext::default(),
            )),
            policy,
            true,
            mode,
        ));
    }

    #[tokio::test]
    async fn session_lifecycle_mark_closing_and_wait_closed_without_receivers() {
        use super::SessionLifecycle;

        let lifecycle = SessionLifecycle::new();
        // Calling mark_closing() with zero subscribers must still observe closed=true later.
        lifecycle.mark_closing();
        assert!(lifecycle.is_closing_or_closed());
        lifecycle.wait_closing_or_closed().await;

        // Calling finish() before wait_closed() must resolve immediately without lost wakeup.
        lifecycle.finish(Ok(()));
        assert!(lifecycle.is_closed());
        assert!(lifecycle.wait_closed().await.is_ok());

        // Concurrent waiter started before finish() must also wake with exact error.
        let lc2 = std::sync::Arc::new(SessionLifecycle::new());
        let lc2_clone = lc2.clone();
        let waiter = tokio::spawn(async move { lc2_clone.wait_closed().await });
        tokio::task::yield_now().await;
        lc2.finish(Err(server_error(
            StatusCode::FORBIDDEN,
            "permission_denied",
        )));
        let res = waiter.await.unwrap();
        assert!(matches!(res, Err(AppendSessionError::Server(_))));
    }

    #[tokio::test]
    async fn append_permits_strict_joint_fifo_and_shrink_and_cancel() {
        use super::AppendPermits;

        let permits = AppendPermits::new(Some(2), 100);

        // Acquire 80 bytes (1 batch left, 20 bytes left).
        let mut p1 = permits.acquire(80).await;
        // A waiter needing 60 bytes blocks at the head of the FIFO queue.
        let p_large_permits = permits.clone();
        let large_task = tokio::spawn(async move { p_large_permits.acquire(60).await });
        tokio::task::yield_now().await;

        // A small waiter needing 10 bytes MUST NOT jump ahead of the queued 60-byte waiter!
        assert!(permits.try_acquire(10).is_none());

        // Shrinking p1 from 80 -> 20 releases 60 bytes (80 available) and immediately wakes
        // large_task.
        p1.shrink(20);
        let p_large = tokio::time::timeout(std::time::Duration::from_secs(1), large_task)
            .await
            .expect("shrink should wake blocked FIFO waiter")
            .unwrap();

        // Now 2 batches held (0 batch slots left) and 20 bytes left.
        // Queue a third waiter, cancel it, then drop p1 & p_large and ensure no leak.
        let cancel_permits = permits.clone();
        let mut cancel_fut = Box::pin(cancel_permits.acquire(10));
        assert!(futures_util::FutureExt::now_or_never(&mut cancel_fut).is_none());
        drop(cancel_fut);

        drop(p1);
        drop(p_large);
        let full = permits
            .try_acquire(100)
            .expect("all 100 bytes and batch slots should be restored");
        drop(full);
    }

    #[test]
    fn process_ack_preserves_inflight_batch_on_protocol_error() {
        use std::collections::VecDeque;

        use super::{InflightAppend, SessionState, process_ack};
        use crate::types::{
            AppendAck, AppendInput, AppendRecord, AppendRecordBatch, StreamPosition,
        };

        let (_cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ack_tx, mut ack_rx) = tokio::sync::oneshot::channel();
        let batch = AppendRecordBatch::try_from_iter([AppendRecord::new("a").unwrap()]).unwrap();
        let input = AppendInput::new(batch);
        let mut state = SessionState {
            cmd_rx,
            inflight_appends: VecDeque::from([InflightAppend {
                input,
                input_metered_bytes: 9,
                ack_tx,
                _permit: None,
                sent_ever: true,
                prior_uncertainty: false,
                attempt_last_byte_rx: None,
                attempt_last_byte_at: None,
            }]),
            inflight_bytes: 9,
            closing: false,
            total_records: 1,
            total_acked_records: 0,
            prev_ack_end: None,
        };
        let ctx = ErrorContext::default();

        // send_cursor == 0 rejects unsolicited ack without popping inflight_appends.
        let ok_ack = AppendAck::new(
            StreamPosition::new(0, 1),
            StreamPosition::new(1, 1),
            StreamPosition::new(1, 1),
        );
        let err = process_ack(ok_ack.clone(), &mut state, 0, &ctx).unwrap_err();
        assert!(matches!(err, AppendSessionError::Protocol(_)));
        assert_eq!(state.inflight_appends.len(), 1);

        // Wrong record count (2 instead of 1) rejects without popping inflight_appends.
        let bad_ack = AppendAck::new(
            StreamPosition::new(0, 1),
            StreamPosition::new(2, 1),
            StreamPosition::new(2, 1),
        );
        let err = process_ack(bad_ack, &mut state, 1, &ctx).unwrap_err();
        assert!(matches!(err, AppendSessionError::Protocol(_)));
        assert_eq!(state.inflight_appends.len(), 1);
        assert!(ack_rx.try_recv().is_err());

        // Valid ack succeeds and delivers through ack_tx.
        process_ack(ok_ack, &mut state, 1, &ctx).unwrap();
        assert!(state.inflight_appends.is_empty());
        assert!(ack_rx.try_recv().unwrap().is_ok());
    }
}
