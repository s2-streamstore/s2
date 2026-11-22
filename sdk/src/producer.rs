//! High-level producer for appending individual records to streams.
//!
//! See [`Producer`].

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures_util::{StreamExt, stream::FuturesOrdered};
use s2_common::{caps::RECORD_BATCH_MAX, record::Metered};
use tokio::{
    sync::{Notify, mpsc, oneshot},
    time::{Instant, Sleep},
};

use crate::{
    api::BasinClient,
    batching::{
        MatchSeqState, batch_is_full, batch_would_overflow, validate_max_batch_bytes,
        validate_max_batch_records,
    },
    client::ShutdownSignal,
    error::{AbortedError, AppendSessionError, ErrorContext, SessionClosedError},
    session::{
        AppendPermit, AppendPermits, AppendSessionInternal, BatchSubmitTicket, SessionLifecycle,
        StreamHeaders, validate_reserve_bytes,
    },
    types::{
        AppendAck, AppendInput, AppendRecord, AppendRecordBatch, FencingToken, MeteredBytes,
        ONE_MIB, StreamConfig, StreamName, ValidationError,
    },
};

/// A [`Future`] that resolves to a [`RecordAck`] once the record is appended.
pub struct RecordSubmitTicket {
    rx: oneshot::Receiver<Result<RecordAck, AppendSessionError>>,
    lifecycle: Arc<SessionLifecycle>,
    context: ErrorContext,
}

impl fmt::Debug for RecordSubmitTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordSubmitTicket").finish_non_exhaustive()
    }
}

impl Future for RecordSubmitTicket {
    type Output = Result<RecordAck, AppendSessionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(res)) => Poll::Ready(res),
            Poll::Ready(Err(_)) => {
                Poll::Ready(Err(self.lifecycle.terminal_err().unwrap_or_else(|| {
                    AppendSessionError::Aborted(AbortedError::new(
                        "producer dropped without calling close",
                        self.context.clone(),
                    ))
                })))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Acknowledgement for an appended record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordAck {
    /// Sequence number assigned to the record.
    pub seq_num: u64,
    /// Acknowledgement for the containing batch.
    pub batch: AppendAck,
}

impl RecordAck {
    /// Construct an acknowledgement for an appended record.
    ///
    /// This is intended for building fixtures in downstream tests.
    pub fn new(seq_num: u64, batch: AppendAck) -> Self {
        Self { seq_num, batch }
    }
}

/// Configuration for a [`Producer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerConfig {
    max_unacked_bytes: u32,
    linger: Duration,
    max_batch_records: usize,
    max_batch_bytes: usize,
    fencing_token: Option<FencingToken>,
    match_seq_num: Option<u64>,
    stream_config: Option<StreamConfig>,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            max_unacked_bytes: 5 * ONE_MIB,
            linger: Duration::from_millis(5),
            max_batch_records: RECORD_BATCH_MAX.count,
            max_batch_bytes: RECORD_BATCH_MAX.bytes,
            fencing_token: None,
            match_seq_num: None,
            stream_config: None,
        }
    }
}

impl ProducerConfig {
    /// Create a new [`ProducerConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the limit on total metered bytes of unacknowledged [`AppendRecord`]s held in memory.
    pub fn max_unacked_bytes(&self) -> u32 {
        self.max_unacked_bytes
    }

    /// Return the configured linger duration.
    pub fn linger(&self) -> Duration {
        self.linger
    }

    /// Return the configured maximum records per batch.
    pub fn max_batch_records(&self) -> usize {
        self.max_batch_records
    }

    /// Return the configured maximum metered bytes per batch.
    pub fn max_batch_bytes(&self) -> usize {
        self.max_batch_bytes
    }

    /// Return the configured fencing token, if any.
    pub fn fencing_token(&self) -> Option<&FencingToken> {
        self.fencing_token.as_ref()
    }

    /// Return the configured starting `match_seq_num`, if any.
    pub fn match_seq_num(&self) -> Option<u64> {
        self.match_seq_num
    }

    /// Return the stream configuration to apply if the stream is created on append, if set.
    pub fn stream_config(&self) -> Option<&StreamConfig> {
        self.stream_config.as_ref()
    }

    /// Set the limit on total metered bytes of unacknowledged [`AppendRecord`]s held in memory.
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

    /// Set how long to wait after the first record in a batch arrives before flushing it.
    ///
    /// Defaults to `5ms`.
    pub fn with_linger(self, linger: Duration) -> Self {
        Self { linger, ..self }
    }

    /// Set the maximum number of records per batch.
    ///
    /// **Note:** Must be between `1` and `1000`.
    ///
    /// Defaults to `1000`.
    pub fn with_max_batch_records(self, max_batch_records: usize) -> Result<Self, ValidationError> {
        let max_batch_records = validate_max_batch_records(max_batch_records)?;
        Ok(Self {
            max_batch_records,
            ..self
        })
    }

    /// Set the maximum metered bytes per batch.
    ///
    /// **Note:** Must be between `8` bytes and `1MiB`.
    ///
    /// Defaults to `1MiB`.
    pub fn with_max_batch_bytes(self, max_batch_bytes: usize) -> Result<Self, ValidationError> {
        let max_batch_bytes = validate_max_batch_bytes(max_batch_bytes)?;
        Ok(Self {
            max_batch_bytes,
            ..self
        })
    }

    /// Set the fencing token for all [`AppendInput`]s.
    ///
    /// Defaults to `None`.
    pub fn with_fencing_token(self, fencing_token: FencingToken) -> Self {
        Self {
            fencing_token: Some(fencing_token),
            ..self
        }
    }

    /// Set the match sequence number for the initial [`AppendInput`]. It
    /// will be auto-incremented for subsequent ones.
    ///
    /// Defaults to `None`.
    pub fn with_match_seq_num(self, match_seq_num: u64) -> Self {
        Self {
            match_seq_num: Some(match_seq_num),
            ..self
        }
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

struct ProducerGate {
    closing: bool,
    match_seq: MatchSeqState,
    last_accepted_id: u64,
}

/// High-level interface for submitting individual [`AppendRecord`]s.
///
/// Handles batching of records into [`AppendInput`]s automatically based on [`ProducerConfig`],
/// and owns an internal append session. Opening a producer sends no request until the first batch
/// is ready.
pub struct Producer {
    gate: Arc<StdMutex<ProducerGate>>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    permits: AppendPermits,
    max_batch_bytes: usize,
    acked_through_id: Arc<AtomicU64>,
    lifecycle: Arc<SessionLifecycle>,
    session_lifecycle: Arc<SessionLifecycle>,
    client_shutdown: ShutdownSignal,
    abort_signal: ShutdownSignal,
    flush_partial_notify: Arc<Notify>,
    context: ErrorContext,
}

impl fmt::Debug for Producer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Producer")
            .field("max_batch_bytes", &self.max_batch_bytes)
            .field("closing_or_closed", &self.is_closing_or_closed())
            .finish_non_exhaustive()
    }
}

impl Producer {
    pub(crate) fn new(
        client: BasinClient,
        stream: StreamName,
        headers: StreamHeaders,
        config: ProducerConfig,
    ) -> Self {
        let context =
            ErrorContext::stream("producer", client.name.as_ref(), stream.as_ref(), false);
        let client_shutdown = client.shutdown_signal();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let permits = AppendPermits::new(None, config.max_unacked_bytes);
        let max_batch_bytes = config.max_batch_bytes;
        let gate = Arc::new(StdMutex::new(ProducerGate {
            closing: false,
            match_seq: MatchSeqState::from_option(config.match_seq_num),
            last_accepted_id: 0,
        }));
        let acked_through_id = Arc::new(AtomicU64::new(0));
        let lifecycle = Arc::new(SessionLifecycle::new());
        let abort_signal = ShutdownSignal::new();
        let flush_partial_notify = Arc::new(Notify::new());
        let session = AppendSessionInternal::new(client, stream, headers);
        let session_lifecycle = session.lifecycle().clone();
        let task = ProducerTask::new(
            session,
            config,
            cmd_rx,
            permits.clone(),
            gate.clone(),
            acked_through_id.clone(),
            lifecycle.clone(),
            client_shutdown.clone(),
            abort_signal.clone(),
            flush_partial_notify.clone(),
            context.clone(),
        );
        tokio::spawn(task.run());
        Self {
            gate,
            cmd_tx,
            permits,
            max_batch_bytes,
            acked_through_id,
            lifecycle,
            session_lifecycle,
            client_shutdown,
            abort_signal,
            flush_partial_notify,
            context,
        }
    }

    fn is_closing_or_closed(&self) -> bool {
        self.lifecycle.is_closing_or_closed() || self.session_lifecycle.is_closing_or_closed()
    }

    fn session_closed_err(&self) -> AppendSessionError {
        let failure = self
            .lifecycle
            .terminal_err()
            .or_else(|| self.session_lifecycle.terminal_err());
        AppendSessionError::SessionClosed(SessionClosedError::new(failure, self.context.clone()))
    }

    /// Submit a record for appending.
    ///
    /// Accepts an [`AppendRecord`] or [`CommandRecord`](crate::types::CommandRecord).
    ///
    /// Validates the record size against `max_batch_bytes` and `match_seq_num` bounds before
    /// waiting for capacity. Waits when the unacknowledged bytes limit is reached, providing
    /// backpressure. For explicit control, use [`reserve`](Self::reserve) followed by
    /// [`RecordSubmitPermit::submit`].
    ///
    /// Use [`flush`](Self::flush) to establish a non-terminal durability boundary, and call
    /// [`close`](Self::close) when finished to flush remaining records and release resources.
    pub async fn submit(
        &self,
        record: impl Into<AppendRecord>,
    ) -> Result<RecordSubmitTicket, AppendSessionError> {
        let record = record.into();
        let bytes = record.metered_bytes();
        if bytes > self.max_batch_bytes {
            return Err(AppendSessionError::Validation(ValidationError(format!(
                "record size in metered bytes ({bytes}) exceeds max_batch_bytes ({})",
                self.max_batch_bytes
            ))));
        }
        {
            let gate = self.gate.lock().unwrap();
            if gate.match_seq.is_exhausted() {
                return Err(AppendSessionError::Validation(ValidationError(
                    "match_seq_num overflow: batch end sequence number exceeds u64::MAX".into(),
                )));
            }
        }
        let permit = self.reserve(bytes as u32).await?;
        permit.submit(record)
    }

    /// Reserve capacity for a record of up to `bytes` metered bytes to be submitted.
    ///
    /// Useful in [`select!`](tokio::select) loops where you want to interleave submission with
    /// other async work. See [`submit`](Self::submit) for a simpler API.
    ///
    /// Capacity is granted FIFO. Validated before waiting; `bytes` must be between `8` and
    /// `max_batch_bytes`. If the producer closes or begins closing while waiting, returns
    /// [`SessionClosedError`].
    ///
    /// Reserving capacity does not order a record relative to [`flush`](Self::flush); the record
    /// is ordered when [`RecordSubmitPermit::submit`] is called.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. Dropping the future before completion accepts nothing.
    pub async fn reserve(&self, bytes: u32) -> Result<RecordSubmitPermit, AppendSessionError> {
        validate_reserve_bytes(bytes, self.max_batch_bytes as u32)?;

        if self.is_closing_or_closed() {
            return Err(self.session_closed_err());
        }
        if self.client_shutdown.is_closed() || self.abort_signal.is_closed() {
            self.lifecycle.wait_closing_or_closed().await;
            return Err(self.session_closed_err());
        }

        let append_permit = if let Some(permit) = self.permits.try_acquire(bytes) {
            permit
        } else {
            let closing_fut = self.lifecycle.wait_closing_or_closed();
            let session_closing_fut = self.session_lifecycle.wait_closing_or_closed();
            tokio::select! {
                biased;
                _ = closing_fut => {
                    return Err(self.session_closed_err());
                }
                _ = session_closing_fut => {
                    return Err(self.session_closed_err());
                }
                permit = self.permits.acquire_notifying(bytes, &self.flush_partial_notify) => permit,
            }
        };

        if self.is_closing_or_closed() {
            return Err(self.session_closed_err());
        }
        if self.client_shutdown.is_closed() || self.abort_signal.is_closed() {
            self.lifecycle.wait_closing_or_closed().await;
            return Err(self.session_closed_err());
        }

        Ok(RecordSubmitPermit {
            append_permit,
            reserved_bytes: bytes,
            max_batch_bytes: self.max_batch_bytes,
            gate: self.gate.clone(),
            cmd_tx: self.cmd_tx.clone(),
            lifecycle: self.lifecycle.clone(),
            session_lifecycle: self.session_lifecycle.clone(),
            client_shutdown: self.client_shutdown.clone(),
            abort_signal: self.abort_signal.clone(),
            context: self.context.clone(),
        })
    }

    /// Flush all records accepted before this call and wait for them to become durable.
    ///
    /// Immediately submits any partial batch without waiting for `linger`. Returns `Ok(())` once
    /// every record accepted before `flush()` began has been acknowledged, or fails with the
    /// session's failure if any covered record fails. A failure affecting only later records, or
    /// closing the producer, does not fail `flush()` once covered records succeed.
    pub async fn flush(&self) -> Result<(), AppendSessionError> {
        let flush_state = {
            // Hold gate across reading `last_accepted_id` and enqueueing `Command::Flush` so the
            // flush boundary linearizes strictly between earlier and later `Command::Submit`s (A7).
            let gate = self.gate.lock().unwrap();
            let target_id = gate.last_accepted_id;

            if self.acked_through_id.load(Ordering::Acquire) >= target_id {
                return Ok(());
            }

            if self.lifecycle.is_closed() {
                Err(target_id)
            } else {
                let (done_tx, done_rx) = oneshot::channel();
                if self
                    .cmd_tx
                    .send(Command::Flush { target_id, done_tx })
                    .is_err()
                {
                    Err(target_id)
                } else {
                    Ok((target_id, done_rx))
                }
            }
        };

        let (target_id, done_rx) = match flush_state {
            Ok(pair) => pair,
            Err(target_id) => return self.flush_result_after_close(target_id).await,
        };

        match done_rx.await {
            Ok(res) => res,
            Err(_) => self.flush_result_after_close(target_id).await,
        }
    }

    async fn flush_result_after_close(&self, target_id: u64) -> Result<(), AppendSessionError> {
        if self.acked_through_id.load(Ordering::Acquire) >= target_id {
            return Ok(());
        }
        let close_res = self.lifecycle.wait_closed().await;
        if self.acked_through_id.load(Ordering::Acquire) >= target_id {
            return Ok(());
        }
        match close_res {
            Err(err) => Err(err),
            Ok(()) => Err(AppendSessionError::Aborted(AbortedError::new(
                "producer closed before flush completed",
                self.context.clone(),
            ))),
        }
    }

    /// Close the producer, immediately submitting any partial batch and waiting for all accepted
    /// records to reach an outcome.
    ///
    /// Repeated or concurrent calls to `close()` return the same result. Dropping a `close()`
    /// future cancels only the wait; dropping the [`Producer`] aborts it and its owned append
    /// session.
    pub async fn close(&self) -> Result<(), AppendSessionError> {
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
}

impl Drop for Producer {
    fn drop(&mut self) {
        if !self.lifecycle.is_closed() {
            self.abort_signal.close();
        }
    }
}

/// A permit to submit a record after reserving capacity.
pub struct RecordSubmitPermit {
    append_permit: AppendPermit,
    reserved_bytes: u32,
    max_batch_bytes: usize,
    gate: Arc<StdMutex<ProducerGate>>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    lifecycle: Arc<SessionLifecycle>,
    session_lifecycle: Arc<SessionLifecycle>,
    client_shutdown: ShutdownSignal,
    abort_signal: ShutdownSignal,
    context: ErrorContext,
}

impl fmt::Debug for RecordSubmitPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordSubmitPermit")
            .field("reserved_bytes", &self.reserved_bytes)
            .finish_non_exhaustive()
    }
}

impl RecordSubmitPermit {
    fn session_closed_err(&self) -> AppendSessionError {
        let failure = self
            .lifecycle
            .terminal_err()
            .or_else(|| self.session_lifecycle.terminal_err());
        AppendSessionError::SessionClosed(SessionClosedError::new(failure, self.context.clone()))
    }

    /// Submit the record using this permit.
    ///
    /// Accepts an [`AppendRecord`] or [`CommandRecord`](crate::types::CommandRecord).
    ///
    /// Fails with [`ValidationError`] (releasing the reservation and leaving the producer open) if
    /// the record's metered size exceeds the reserved bytes or `max_batch_bytes`, or if advancing
    /// `match_seq_num` would overflow `u64`. Fails with [`SessionClosedError`] if the producer
    /// closed or began closing after the permit was reserved.
    pub fn submit(
        mut self,
        record: impl Into<AppendRecord>,
    ) -> Result<RecordSubmitTicket, AppendSessionError> {
        let record = record.into();
        let metered = record.metered_bytes();
        if metered > self.reserved_bytes as usize {
            return Err(AppendSessionError::Validation(ValidationError(format!(
                "record size in metered bytes ({metered}) exceeds reserved capacity ({})",
                self.reserved_bytes
            ))));
        }
        if metered > self.max_batch_bytes {
            return Err(AppendSessionError::Validation(ValidationError(format!(
                "record size in metered bytes ({metered}) exceeds max_batch_bytes ({})",
                self.max_batch_bytes
            ))));
        }

        // Release any unused over-reserved capacity immediately (`A4a`).
        self.append_permit.shrink(metered as u32);

        let (ack_tx, ack_rx) = oneshot::channel();
        {
            let mut gate = self.gate.lock().unwrap();
            if gate.match_seq.is_exhausted() {
                return Err(AppendSessionError::Validation(ValidationError(
                    "match_seq_num overflow: batch end sequence number exceeds u64::MAX".into(),
                )));
            }
            if gate.closing
                || self.lifecycle.is_closing_or_closed()
                || self.session_lifecycle.is_closing_or_closed()
                || self.client_shutdown.is_closed()
                || self.abort_signal.is_closed()
            {
                return Err(self.session_closed_err());
            }
            let match_seq_num = gate.match_seq.claim_next()?;
            let acceptance_id = gate.last_accepted_id + 1;
            if self
                .cmd_tx
                .send(Command::Submit {
                    record,
                    acceptance_id,
                    match_seq_num,
                    ack_tx,
                    permit: self.append_permit,
                })
                .is_err()
            {
                let failure = self
                    .lifecycle
                    .terminal_err()
                    .or_else(|| self.session_lifecycle.terminal_err());
                return Err(AppendSessionError::SessionClosed(SessionClosedError::new(
                    failure,
                    self.context,
                )));
            }
            gate.last_accepted_id = acceptance_id;
        }

        Ok(RecordSubmitTicket {
            rx: ack_rx,
            lifecycle: self.lifecycle,
            context: self.context,
        })
    }
}

struct ProducerTask {
    session: AppendSessionInternal,
    linger: Duration,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    permits: AppendPermits,
    gate: Arc<StdMutex<ProducerGate>>,
    acked_through_id: Arc<AtomicU64>,
    lifecycle: Arc<SessionLifecycle>,
    client_shutdown: ShutdownSignal,
    abort_signal: ShutdownSignal,
    flush_partial_notify: Arc<Notify>,
    context: ErrorContext,
    batcher: PartialBatch,
    linger_sleep: Option<Pin<Box<Sleep>>>,
    linger_deadline: Option<Instant>,
    pending_batch_acks: FuturesOrdered<PendingBatchAck>,
    pending_flushes: Vec<PendingFlush>,
}

impl ProducerTask {
    #[allow(clippy::too_many_arguments)]
    fn new(
        session: AppendSessionInternal,
        config: ProducerConfig,
        cmd_rx: mpsc::UnboundedReceiver<Command>,
        permits: AppendPermits,
        gate: Arc<StdMutex<ProducerGate>>,
        acked_through_id: Arc<AtomicU64>,
        lifecycle: Arc<SessionLifecycle>,
        client_shutdown: ShutdownSignal,
        abort_signal: ShutdownSignal,
        flush_partial_notify: Arc<Notify>,
        context: ErrorContext,
    ) -> Self {
        let batcher = PartialBatch::new(
            config.max_batch_records,
            config.max_batch_bytes,
            config.fencing_token,
        );
        Self {
            session,
            linger: config.linger,
            cmd_rx,
            permits,
            gate,
            acked_through_id,
            lifecycle,
            client_shutdown,
            abort_signal,
            flush_partial_notify,
            context,
            batcher,
            linger_sleep: None,
            linger_deadline: None,
            pending_batch_acks: FuturesOrdered::new(),
            pending_flushes: Vec::new(),
        }
    }

    fn arm_linger(&mut self) {
        if self.linger.is_zero() {
            return;
        }
        let Some(deadline) = Instant::now().checked_add(self.linger) else {
            return;
        };
        match self.linger_sleep.as_mut() {
            Some(sleep) => sleep.as_mut().reset(deadline),
            None => self.linger_sleep = Some(Box::pin(tokio::time::sleep_until(deadline))),
        }
        self.linger_deadline = Some(deadline);
    }

    /// Take the current partial batch and submit it to the owned session.
    /// Returns `Err(records)` if the owned session has already closed/failed.
    fn try_cut_and_submit(&mut self) -> Result<(), Vec<PendingRecordAck>> {
        self.linger_deadline = None;
        let Some((input, max_id, records)) = self.batcher.take() else {
            return Ok(());
        };
        match self.session.submit(input) {
            Ok(ticket) => {
                self.pending_batch_acks.push_back(PendingBatchAck {
                    ticket,
                    batch_max_id: max_id,
                    pending_record_acks: Some(records),
                });
                Ok(())
            }
            Err(_) => Err(records),
        }
    }

    /// Cut the partial batch when backpressure is waiting and no other batch is in flight (`A5a`).
    ///
    /// Keeping the check level-triggered on current state (`pending_batch_acks.is_empty() &&
    /// !batcher.is_empty() && permits.has_waiters()`) prevents lost wakeups while avoiding
    /// small-batch fragmentation when other batches are already in flight.
    fn should_flush_for_backpressure(&self) -> bool {
        self.pending_batch_acks.is_empty() && !self.batcher.is_empty() && self.permits.has_waiters()
    }

    fn publish_closing_from_session(&self) {
        if let Some(err) = self.session.terminal_err() {
            self.lifecycle.set_terminal_err(err);
        }
        let mut g = self.gate.lock().unwrap();
        g.closing = true;
        self.lifecycle.mark_closing();
    }

    async fn run(mut self) {
        let mut closing = false;
        let mut client_closed_fut = self.client_shutdown.cancelled();
        let mut abort_fut = self.abort_signal.cancelled();

        loop {
            if closing && self.batcher.is_empty() && self.pending_batch_acks.is_empty() {
                break;
            }

            // For positive linger, flush before pulling more commands if deadline already elapsed.
            if !self.batcher.is_empty()
                && !self.linger.is_zero()
                && self.linger_deadline.is_some_and(|d| Instant::now() >= d)
            {
                if let Err(unsubmitted) = self.try_cut_and_submit() {
                    self.terminate(unsubmitted).await;
                    return;
                }
                continue;
            }

            let linger_active = self.linger_deadline.is_some() && !self.batcher.is_empty();

            tokio::select! {
                biased;

                // Deliver completed batch outcomes strictly in submission order (A6d, A7).
                Some((batch_ack, batch_max_id, batch_record_acks)) = self.pending_batch_acks.next() => {
                    if batch_ack.is_err() {
                        // Publish terminal error and close acceptance gate BEFORE `dispatch_acks`
                        // drops permits and unblocks waiting `reserve()` callers (`A4c`, `A9`).
                        self.publish_closing_from_session();
                        dispatch_acks(batch_ack, batch_record_acks);
                        self.terminate(Vec::new()).await;
                        return;
                    }
                    dispatch_acks(batch_ack, batch_record_acks);
                    self.acked_through_id.store(batch_max_id, Ordering::Release);
                    resolve_satisfied_flushes(&mut self.pending_flushes, batch_max_id);
                    if self.should_flush_for_backpressure()
                        && let Err(unsubmitted) = self.try_cut_and_submit()
                    {
                        self.terminate(unsubmitted).await;
                        return;
                    }
                }

                _ = &mut client_closed_fut => {
                    self.abort("client closed").await;
                    return;
                }

                _ = &mut abort_fut => {
                    self.abort("producer dropped without calling close").await;
                    return;
                }

                _ = async {
                    self.linger_sleep.as_mut().expect("linger_sleep armed").as_mut().await
                }, if linger_active => {
                    if let Err(unsubmitted) = self.try_cut_and_submit() {
                        self.terminate(unsubmitted).await;
                        return;
                    }
                }

                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(Command::Submit {
                            record,
                            acceptance_id,
                            match_seq_num,
                            ack_tx,
                            permit,
                        }) => {
                            let record = Metered::from(record);
                            if !self.batcher.is_empty() && self.batcher.would_overflow(&record)
                                && let Err(unsubmitted) = self.try_cut_and_submit()
                            {
                                // Put current record into batcher so terminate settles
                                // `unsubmitted` first, then this record, in order.
                                self.batcher.push(
                                    record,
                                    acceptance_id,
                                    match_seq_num,
                                    PendingRecordAck { ack_tx, _permit: permit },
                                );
                                self.terminate(unsubmitted).await;
                                return;
                            }

                            let was_empty = self.batcher.is_empty();
                            self.batcher.push(
                                record,
                                acceptance_id,
                                match_seq_num,
                                PendingRecordAck { ack_tx, _permit: permit },
                            );

                            if self.batcher.is_full() || self.should_flush_for_backpressure() {
                                if let Err(unsubmitted) = self.try_cut_and_submit() {
                                    self.terminate(unsubmitted).await;
                                    return;
                                }
                            } else if was_empty {
                                self.arm_linger();
                            }
                        }
                        Some(Command::Flush { target_id, done_tx }) => {
                            if self.acked_through_id.load(Ordering::Acquire) >= target_id {
                                let _ = done_tx.send(Ok(()));
                                continue;
                            }
                            self.pending_flushes.push(PendingFlush { target_id, done_tx });
                            if !self.batcher.is_empty()
                                && let Err(unsubmitted) = self.try_cut_and_submit()
                            {
                                self.terminate(unsubmitted).await;
                                return;
                            }
                        }
                        Some(Command::Close) => {
                            closing = true;
                            if !self.batcher.is_empty()
                                && let Err(unsubmitted) = self.try_cut_and_submit()
                            {
                                self.terminate(unsubmitted).await;
                                return;
                            }
                        }
                        None => {
                            self.abort("producer dropped without calling close").await;
                            return;
                        }
                    }
                }

                // When `linger == 0`, coalesce any immediately-queued commands above, then submit
                // as soon as the command channel is drained without touching the timer wheel.
                _ = std::future::ready(()), if self.linger.is_zero() && !self.batcher.is_empty() => {
                    if let Err(unsubmitted) = self.try_cut_and_submit() {
                        self.terminate(unsubmitted).await;
                        return;
                    }
                }

                // Wake when a caller begins waiting on capacity (`A5a`).
                _ = self.flush_partial_notify.notified() => {
                    if self.should_flush_for_backpressure()
                        && let Err(unsubmitted) = self.try_cut_and_submit()
                    {
                        self.terminate(unsubmitted).await;
                        return;
                    }
                }
            }
        }

        self.finish_clean().await;
    }

    async fn finish_clean(mut self) {
        let session_close_res = self.session.close().await;
        {
            let mut g = self.gate.lock().unwrap();
            g.closing = true;
        }
        self.lifecycle.mark_closing();

        let acked = self.acked_through_id.load(Ordering::Acquire);
        for flush in self.pending_flushes.drain(..) {
            if acked >= flush.target_id {
                let _ = flush.done_tx.send(Ok(()));
            } else {
                let _ = flush.done_tx.send(session_close_res.clone());
            }
        }

        self.cmd_rx.close();
        let closed_err = AppendSessionError::SessionClosed(SessionClosedError::new(
            session_close_res.as_ref().err().cloned(),
            self.context.clone(),
        ));
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            match cmd {
                Command::Submit { ack_tx, .. } => {
                    let _ = ack_tx.send(Err(closed_err.clone()));
                }
                Command::Flush { target_id, done_tx } => {
                    if acked >= target_id {
                        let _ = done_tx.send(Ok(()));
                    } else {
                        let _ = done_tx.send(session_close_res.clone());
                    }
                }
                Command::Close => {}
            }
        }

        self.lifecycle.finish(session_close_res);
    }

    /// Settle all remaining batches using exact outcomes from the owned `AppendSession`
    /// (`A6d`, `A9`), then fail any records still being batched or queued with
    /// `SessionClosedError` (`A6a`).
    async fn terminate(mut self, unsubmitted: Vec<PendingRecordAck>) {
        self.publish_closing_from_session();

        // Drain every remaining batch already submitted to the owned session so every record
        // receives the exact outcome reported by AppendSession strictly in submission order (A6d).
        while let Some((batch_ack, batch_max_id, batch_records)) =
            self.pending_batch_acks.next().await
        {
            let ok = batch_ack.is_ok();
            dispatch_acks(batch_ack, batch_records);
            if ok {
                self.acked_through_id.store(batch_max_id, Ordering::Release);
                resolve_satisfied_flushes(&mut self.pending_flushes, batch_max_id);
            }
        }

        // Obtain the owned session's exact failure (A9).
        let session_failure = match self.session.close().await {
            Err(err) => err,
            Ok(()) => AppendSessionError::SessionClosed(SessionClosedError::new(
                None,
                self.context.clone(),
            )),
        };

        self.lifecycle.set_terminal_err(session_failure.clone());
        let unsent_err = AppendSessionError::SessionClosed(SessionClosedError::new(
            Some(session_failure.clone()),
            self.context.clone(),
        ));

        for pending in unsubmitted {
            let _ = pending.ack_tx.send(Err(unsent_err.clone()));
        }

        for pending in self.batcher.drain_acks() {
            let _ = pending.ack_tx.send(Err(unsent_err.clone()));
        }

        let acked = self.acked_through_id.load(Ordering::Acquire);
        for flush in self.pending_flushes.drain(..) {
            if acked >= flush.target_id {
                let _ = flush.done_tx.send(Ok(()));
            } else {
                let _ = flush.done_tx.send(Err(session_failure.clone()));
            }
        }

        self.cmd_rx.close();
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            match cmd {
                Command::Submit { ack_tx, .. } => {
                    let _ = ack_tx.send(Err(unsent_err.clone()));
                }
                Command::Flush { target_id, done_tx } => {
                    if acked >= target_id {
                        let _ = done_tx.send(Ok(()));
                    } else {
                        let _ = done_tx.send(Err(session_failure.clone()));
                    }
                }
                Command::Close => {}
            }
        }

        self.lifecycle.finish(Err(session_failure));
    }

    async fn abort(mut self, reason: &'static str) {
        let aborted = AppendSessionError::Aborted(AbortedError::new(reason, self.context.clone()));
        let queued_cmds = {
            let mut g = self.gate.lock().unwrap();
            g.closing = true;
            self.cmd_rx.close();
            let mut queued = Vec::new();
            while let Ok(cmd) = self.cmd_rx.try_recv() {
                queued.push(cmd);
            }
            let has_unsubmitted = !self.batcher.is_empty()
                || queued
                    .iter()
                    .any(|cmd| matches!(cmd, Command::Submit { .. }));
            if has_unsubmitted {
                // Publish failure before marking closing so waiting reserve()/submit() calls
                // observe `SessionClosedError { failure: Some(..) }` (`E6`).
                self.lifecycle.set_terminal_err(
                    self.session
                        .terminal_err()
                        .unwrap_or_else(|| aborted.clone()),
                );
            } else if self.pending_batch_acks.is_empty() {
                self.lifecycle.mark_closing();
            }
            queued
        };

        // Abort the owned AppendSession immediately (A3b, A8c) and forward its exact outcomes
        // (A6d).
        self.session.abort();
        while let Some((batch_ack, batch_max_id, batch_records)) =
            self.pending_batch_acks.next().await
        {
            let ok = batch_ack.is_ok();
            dispatch_acks(batch_ack, batch_records);
            if ok {
                self.acked_through_id.store(batch_max_id, Ordering::Release);
                resolve_satisfied_flushes(&mut self.pending_flushes, batch_max_id);
            }
        }
        let session_res = self.session.close().await;

        let unsubmitted_records = self.batcher.drain_acks();
        let has_queued_submits = queued_cmds
            .iter()
            .any(|cmd| matches!(cmd, Command::Submit { .. }));
        let has_unsubmitted = !unsubmitted_records.is_empty() || has_queued_submits;

        let final_result = match session_res {
            Err(session_err) => Err(session_err),
            Ok(()) if has_unsubmitted => Err(aborted),
            Ok(()) => Ok(()),
        };

        if let Err(err) = &final_result {
            self.lifecycle.set_terminal_err(err.clone());
        } else {
            self.lifecycle.mark_closing();
        }

        let unsent_err = AppendSessionError::SessionClosed(SessionClosedError::new(
            final_result.as_ref().err().cloned(),
            self.context.clone(),
        ));

        for pending in unsubmitted_records {
            let _ = pending.ack_tx.send(Err(unsent_err.clone()));
        }

        let acked = self.acked_through_id.load(Ordering::Acquire);
        for flush in self.pending_flushes.drain(..) {
            if acked >= flush.target_id {
                let _ = flush.done_tx.send(Ok(()));
            } else {
                let _ = flush.done_tx.send(final_result.clone());
            }
        }

        for cmd in queued_cmds {
            match cmd {
                Command::Submit { ack_tx, .. } => {
                    let _ = ack_tx.send(Err(unsent_err.clone()));
                }
                Command::Flush { target_id, done_tx } => {
                    if acked >= target_id {
                        let _ = done_tx.send(Ok(()));
                    } else {
                        let _ = done_tx.send(final_result.clone());
                    }
                }
                Command::Close => {}
            }
        }

        self.lifecycle.finish(final_result);
    }
}

struct PartialBatch {
    max_batch_records: usize,
    max_batch_bytes: usize,
    fencing_token: Option<FencingToken>,
    records: Metered<Vec<AppendRecord>>,
    batch_match_seq_num: Option<u64>,
    max_acceptance_id: u64,
    pending_acks: Vec<PendingRecordAck>,
}

impl PartialBatch {
    fn new(
        max_batch_records: usize,
        max_batch_bytes: usize,
        fencing_token: Option<FencingToken>,
    ) -> Self {
        Self {
            max_batch_records,
            max_batch_bytes,
            fencing_token,
            records: Metered::with_capacity(0),
            batch_match_seq_num: None,
            max_acceptance_id: 0,
            pending_acks: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn is_full(&self) -> bool {
        batch_is_full(&self.records, self.max_batch_records, self.max_batch_bytes)
    }

    fn would_overflow(&self, record: &Metered<AppendRecord>) -> bool {
        batch_would_overflow(
            &self.records,
            record,
            self.max_batch_records,
            self.max_batch_bytes,
        )
    }

    fn push(
        &mut self,
        record: Metered<AppendRecord>,
        acceptance_id: u64,
        match_seq_num: Option<u64>,
        ack: PendingRecordAck,
    ) {
        if self.records.is_empty() {
            self.batch_match_seq_num = match_seq_num;
        }
        self.records.push(record);
        self.max_acceptance_id = acceptance_id;
        self.pending_acks.push(ack);
    }

    fn take(&mut self) -> Option<(AppendInput, u64, Vec<PendingRecordAck>)> {
        if self.records.is_empty() {
            return None;
        }
        let records = std::mem::replace(&mut self.records, Metered::with_capacity(0));
        let match_seq_num = self.batch_match_seq_num.take();
        let max_id = self.max_acceptance_id;
        let pending_acks = std::mem::take(&mut self.pending_acks);
        let input = AppendInput {
            records: AppendRecordBatch::from(records),
            match_seq_num,
            fencing_token: self.fencing_token.clone(),
        };
        Some((input, max_id, pending_acks))
    }

    fn drain_acks(&mut self) -> Vec<PendingRecordAck> {
        self.records = Metered::with_capacity(0);
        self.batch_match_seq_num = None;
        std::mem::take(&mut self.pending_acks)
    }
}

enum Command {
    Submit {
        record: AppendRecord,
        acceptance_id: u64,
        match_seq_num: Option<u64>,
        ack_tx: oneshot::Sender<Result<RecordAck, AppendSessionError>>,
        permit: AppendPermit,
    },
    Flush {
        target_id: u64,
        done_tx: oneshot::Sender<Result<(), AppendSessionError>>,
    },
    Close,
}

struct PendingFlush {
    target_id: u64,
    done_tx: oneshot::Sender<Result<(), AppendSessionError>>,
}

struct PendingRecordAck {
    ack_tx: oneshot::Sender<Result<RecordAck, AppendSessionError>>,
    _permit: AppendPermit,
}

struct PendingBatchAck {
    ticket: BatchSubmitTicket,
    batch_max_id: u64,
    pending_record_acks: Option<Vec<PendingRecordAck>>,
}

impl Future for PendingBatchAck {
    type Output = (
        Result<AppendAck, AppendSessionError>,
        u64,
        Vec<PendingRecordAck>,
    );

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.ticket).poll(cx) {
            Poll::Ready(batch_ack) => Poll::Ready((
                batch_ack,
                self.batch_max_id,
                self.pending_record_acks
                    .take()
                    .expect("pending_record_acks should not be None"),
            )),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn dispatch_acks(
    batch_ack: Result<AppendAck, AppendSessionError>,
    pending_record_acks: Vec<PendingRecordAck>,
) {
    match batch_ack {
        Ok(batch_ack) => {
            for (offset, pending) in pending_record_acks.into_iter().enumerate() {
                let seq_num = batch_ack.start.seq_num + offset as u64;
                let _ = pending.ack_tx.send(Ok(RecordAck {
                    seq_num,
                    batch: batch_ack.clone(),
                }));
            }
        }
        Err(err) => {
            for pending in pending_record_acks {
                let _ = pending.ack_tx.send(Err(err.clone()));
            }
        }
    }
}

fn resolve_satisfied_flushes(pending_flushes: &mut Vec<PendingFlush>, acked_through_id: u64) {
    let mut i = 0;
    while i < pending_flushes.len() {
        if pending_flushes[i].target_id <= acked_through_id {
            let flush = pending_flushes.swap_remove(i);
            let _ = flush.done_tx.send(Ok(()));
        } else {
            i += 1;
        }
    }
}
