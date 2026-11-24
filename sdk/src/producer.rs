//! High-level producer for appending individual records to streams.
//!
//! See [`Producer`].

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures_core::FusedFuture;
use futures_util::{StreamExt, stream::FuturesOrdered};
use tokio::sync::{Notify, mpsc, oneshot};
use tracing::{Instrument, debug, debug_span};

use crate::{
    api::BasinClient,
    batching::{
        BatchAccumulator, Linger, MatchSeqState, validate_max_batch_bytes,
        validate_max_batch_records, validate_record_size,
    },
    client::CancellationToken,
    error::{AbortedError, AppendSessionError, ErrorContext, SessionClosedError, ValidationError},
    session::{
        AppendPermit, AppendPermits, AppendSessionCore, BatchSubmitTicket, FinishOnDrop,
        SessionLifecycle, StreamHeaders, SubmitTicket, validate_max_unacked_bytes,
        validate_reserve_bytes,
    },
    types::{
        AppendAck, AppendInput, AppendRecord, BasinName, FencingToken, ONE_MIB, RECORD_BATCH_MAX,
        StreamConfig, StreamName,
    },
};

const EXPLICIT_ABORT_MSG: &str = "producer aborted";
const DROPPED_ABORT_MSG: &str = "producer dropped without calling close";

type RecordAckTx = oneshot::Sender<Result<RecordAck, AppendSessionError>>;

/// A [`Future`] that resolves to a [`RecordAck`] once the record is appended.
pub struct RecordSubmitTicket(SubmitTicket<RecordAck>);

impl RecordSubmitTicket {
    /// Poll the ticket without blocking, returning `Some` once the record outcome is ready.
    ///
    /// Returns `None` if the record is still in flight or if the outcome was already consumed.
    #[must_use]
    pub fn try_ack(&mut self) -> Option<Result<RecordAck, AppendSessionError>> {
        self.0.try_ack()
    }
}

impl fmt::Debug for RecordSubmitTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordSubmitTicket").finish_non_exhaustive()
    }
}

impl Future for RecordSubmitTicket {
    type Output = Result<RecordAck, AppendSessionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl FusedFuture for RecordSubmitTicket {
    fn is_terminated(&self) -> bool {
        self.0.is_terminated()
    }
}

/// Acknowledgement for an appended record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    #[must_use]
    pub fn new(seq_num: u64, batch: AppendAck) -> Self {
        Self { seq_num, batch }
    }
}

/// Configuration for a [`Producer`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct ProducerConfig {
    max_unacked_bytes: usize,
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
    #[must_use]
    pub fn max_unacked_bytes(&self) -> usize {
        self.max_unacked_bytes
    }

    /// Return the configured linger duration.
    #[must_use]
    pub fn linger(&self) -> Duration {
        self.linger
    }

    /// Return the configured maximum records per batch.
    #[must_use]
    pub fn max_batch_records(&self) -> usize {
        self.max_batch_records
    }

    /// Return the configured maximum metered bytes per batch.
    #[must_use]
    pub fn max_batch_bytes(&self) -> usize {
        self.max_batch_bytes
    }

    /// Return the configured fencing token, if any.
    #[must_use]
    pub fn fencing_token(&self) -> Option<&FencingToken> {
        self.fencing_token.as_ref()
    }

    /// Return the configured starting `match_seq_num`, if any.
    #[must_use]
    pub fn match_seq_num(&self) -> Option<u64> {
        self.match_seq_num
    }

    /// Return the stream configuration to apply if the stream is created on append, if set.
    #[must_use]
    pub fn stream_config(&self) -> Option<&StreamConfig> {
        self.stream_config.as_ref()
    }

    /// Set the limit on total metered bytes of unacknowledged [`AppendRecord`]s held in memory.
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

    /// Set how long to wait after the first record in a batch arrives before flushing it.
    ///
    /// Defaults to `5ms`.
    pub fn with_linger(self, linger: Duration) -> Self {
        Self { linger, ..self }
    }

    /// Set the maximum number of records per batch.
    ///
    /// Defaults to `1000`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `max_batch_records` is outside `1..=1000`.
    pub fn with_max_batch_records(self, max_batch_records: usize) -> Result<Self, ValidationError> {
        let max_batch_records = validate_max_batch_records(max_batch_records)?;
        Ok(Self {
            max_batch_records,
            ..self
        })
    }

    /// Set the maximum metered bytes per batch.
    ///
    /// Defaults to `1 MiB`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `max_batch_bytes` is outside `8..=1_048_576`.
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
    match_seq: MatchSeqState,
    last_accepted_id: u64,
}

struct ProducerShared {
    basin: BasinName,
    stream: StreamName,
    gate: StdMutex<ProducerGate>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    permits: AppendPermits,
    max_batch_bytes: usize,
    fencing_token_len: usize,
    unacked_records: AtomicUsize,
    acked_through_id: AtomicU64,
    lifecycle: Arc<SessionLifecycle>,
    session_lifecycle: Arc<SessionLifecycle>,
    client_shutdown: CancellationToken,
    /// Child token of `client_shutdown`; cancelled on either client close or producer drop/abort.
    abort: CancellationToken,
    explicit_abort: AtomicBool,
    flush_partial_notify: Notify,
    context: ErrorContext,
}

impl ProducerShared {
    fn is_closing_or_closed(&self) -> bool {
        // Ignore a clean `session_lifecycle` close here: if `client.close()` aborts an idle owned
        // session while the producer still holds a partial batch, `ProducerTask` drives
        // `self.lifecycle` with `AbortedError` (`A8c`, `E6`).
        self.lifecycle.is_closing_or_closed() || self.session_lifecycle.terminal_err().is_some()
    }

    fn abort_reason(&self) -> &'static str {
        if self.client_shutdown.is_cancelled() {
            "client closed"
        } else if self.explicit_abort.load(Ordering::Acquire) {
            EXPLICIT_ABORT_MSG
        } else {
            DROPPED_ABORT_MSG
        }
    }

    fn session_closed_err(&self, has_unacked_work: bool) -> AppendSessionError {
        let failure = self
            .lifecycle
            .terminal_err()
            .or_else(|| self.session_lifecycle.terminal_err())
            .or_else(|| {
                (has_unacked_work && self.abort.is_cancelled()).then(|| {
                    AppendSessionError::Aborted(AbortedError::new_with_context(
                        self.abort_reason(),
                        self.context.clone(),
                    ))
                })
            });
        AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
            failure,
            self.context.clone(),
        ))
    }
}

/// High-level interface for submitting individual [`AppendRecord`]s.
///
/// Handles batching of records into [`AppendInput`]s automatically based on [`ProducerConfig`],
/// and owns an internal append session. Opening a producer sends no request until the first batch
/// is ready.
#[must_use = "producers do nothing unless records are submitted"]
pub struct Producer {
    shared: Arc<ProducerShared>,
}

impl fmt::Debug for Producer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Producer")
            .field("basin", &self.shared.basin)
            .field("stream", &self.shared.stream)
            .field("max_batch_bytes", &self.shared.max_batch_bytes)
            .field("unacked_bytes", &self.shared.permits.in_flight_bytes())
            .field(
                "unacked_records",
                &self.shared.unacked_records.load(Ordering::Relaxed),
            )
            .field(
                "acked_records",
                &self.shared.acked_through_id.load(Ordering::Relaxed),
            )
            .field("closing_or_closed", &self.shared.is_closing_or_closed())
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
        let basin = client.name.clone();
        let context = ErrorContext::stream("producer", basin.as_ref(), stream.as_ref(), false);
        let client_shutdown = client.shutdown_token();
        let abort = client_shutdown.child_token();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let permits = AppendPermits::new(None, config.max_unacked_bytes);
        let max_batch_bytes = config.max_batch_bytes;
        let fencing_token_len = config.fencing_token.as_ref().map_or(0, |t| t.len());
        let gate = StdMutex::new(ProducerGate {
            match_seq: MatchSeqState::from_option(config.match_seq_num),
            last_accepted_id: 0,
        });
        let lifecycle = Arc::new(SessionLifecycle::new());
        let session = AppendSessionCore::new(
            client,
            stream.clone(),
            headers,
            "producer",
            EXPLICIT_ABORT_MSG,
            DROPPED_ABORT_MSG,
        );
        let session_lifecycle = session.lifecycle().clone();

        let shared = Arc::new(ProducerShared {
            basin: basin.clone(),
            stream: stream.clone(),
            gate,
            cmd_tx,
            permits,
            max_batch_bytes,
            fencing_token_len,
            unacked_records: AtomicUsize::new(0),
            acked_through_id: AtomicU64::new(0),
            lifecycle,
            session_lifecycle,
            client_shutdown,
            abort,
            explicit_abort: AtomicBool::new(false),
            flush_partial_notify: Notify::new(),
            context,
        });

        let span = debug_span!("producer", basin = %basin, stream = %stream);
        let task = ProducerTask::new(shared.clone(), session, config, cmd_rx);
        tokio::spawn(task.run().instrument(span));
        Self { shared }
    }

    async fn check_open_for_reserve(&self) -> Result<(), AppendSessionError> {
        if self.shared.is_closing_or_closed() {
            return Err(self.shared.session_closed_err(false));
        }
        if self.shared.abort.is_cancelled() {
            self.shared.lifecycle.wait_closing_or_closed().await;
            return Err(self.shared.session_closed_err(false));
        }
        Ok(())
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
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe while waiting for capacity. Dropping the future before it
    /// resolves accepts nothing and releases any partially acquired reservation.
    pub async fn submit(
        &self,
        record: impl Into<AppendRecord>,
    ) -> Result<RecordSubmitTicket, AppendSessionError> {
        let record = record.into();
        FencingToken::validate_len(self.shared.fencing_token_len)
            .map_err(|e| self.shared.context.format_validation(e))?;
        record
            .validate_for_write()
            .map_err(|e| self.shared.context.format_validation(e))?;
        let bytes = record.metered_bytes();
        validate_record_size(bytes, self.shared.max_batch_bytes)
            .map_err(|e| self.shared.context.format_validation(e))?;
        self.shared
            .gate
            .lock()
            .unwrap()
            .match_seq
            .check_available()
            .map_err(|e| self.shared.context.format_validation(e))?;
        let permit = self.reserve(bytes).await?;
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
    pub async fn reserve(&self, bytes: usize) -> Result<RecordSubmitPermit, AppendSessionError> {
        validate_reserve_bytes(bytes, self.shared.max_batch_bytes, &self.shared.context)?;

        self.check_open_for_reserve().await?;

        let append_permit = tokio::select! {
            biased;
            _ = self.shared.lifecycle.wait_closing_or_closed() => {
                return Err(self.shared.session_closed_err(false));
            }
            permit = self
                .shared
                .permits
                .acquire_notifying(bytes, &self.shared.flush_partial_notify) => permit,
        };

        self.check_open_for_reserve().await?;

        Ok(RecordSubmitPermit {
            append_permit,
            reserved_bytes: bytes,
            shared: self.shared.clone(),
        })
    }

    /// Return the number of metered bytes currently reserved or awaiting acknowledgement.
    ///
    /// Includes bytes held by outstanding [`RecordSubmitPermit`]s as well as accepted records
    /// buffered in the current partial batch or in flight on the underlying session. Returns to `0`
    /// once all permits and records have settled.
    #[must_use]
    pub fn unacked_bytes(&self) -> usize {
        self.shared.permits.in_flight_bytes()
    }

    /// Return the number of accepted records currently awaiting an outcome.
    ///
    /// Incremented when a record is accepted and decremented whenever its batch settles
    /// (acknowledged, failed, or aborted), returning to `0` once all accepted records have settled.
    #[must_use]
    pub fn unacked_records(&self) -> usize {
        self.shared.unacked_records.load(Ordering::Acquire)
    }

    /// Return the cumulative number of records durably acknowledged by this producer.
    #[must_use]
    pub fn acked_records(&self) -> u64 {
        self.shared.acked_through_id.load(Ordering::Acquire)
    }

    /// Flush all records accepted before this call and wait for them to become durable.
    ///
    /// Immediately submits any partial batch without waiting for `linger`. Returns `Ok(())` once
    /// every record accepted before `flush()` began has been acknowledged, or fails with the
    /// session's failure if any covered record fails. A failure affecting only later records, or
    /// closing the producer, does not fail `flush()` once covered records succeed.
    ///
    /// # Cancel safety
    ///
    /// Dropping a `flush()` future cancels only the wait; the flush request remains submitted and
    /// accepted records continue draining in the background.
    pub async fn flush(&self) -> Result<(), AppendSessionError> {
        let flush_state = {
            // Hold gate across reading `last_accepted_id` and enqueueing `Command::Flush` so the
            // flush boundary linearizes strictly between earlier and later `Command::Submit`s
            // (`A7`) and arrives at the task in non-decreasing `target_id` order.
            let gate = self.shared.gate.lock().unwrap();
            let target_id = gate.last_accepted_id;

            if self.shared.acked_through_id.load(Ordering::Acquire) >= target_id {
                return Ok(());
            }

            if self.shared.lifecycle.is_closed() {
                Err(target_id)
            } else {
                let (done_tx, done_rx) = oneshot::channel();
                if self
                    .shared
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
        if self.shared.acked_through_id.load(Ordering::Acquire) >= target_id {
            return Ok(());
        }
        let close_res = self.shared.lifecycle.wait_closed().await;
        if self.shared.acked_through_id.load(Ordering::Acquire) >= target_id {
            return Ok(());
        }
        match close_res {
            Err(err) => Err(err),
            Ok(()) => {
                debug_assert!(
                    false,
                    "producer closed cleanly before accepted flush target was acked"
                );
                Err(AppendSessionError::Aborted(AbortedError::new_with_context(
                    "producer closed before flush completed",
                    self.shared.context.clone(),
                )))
            }
        }
    }

    /// Close the producer, immediately submitting any partial batch and waiting for all accepted
    /// records to reach an outcome.
    ///
    /// Repeated or concurrent calls to `close()` return the same result.
    ///
    /// # Cancel safety
    ///
    /// Dropping a `close()` future cancels only the wait; the producer continues closing in the
    /// background. Dropping the [`Producer`] itself aborts it and its owned append session.
    pub async fn close(&self) -> Result<(), AppendSessionError> {
        {
            let _gate = self.shared.gate.lock().unwrap();
            if !self.shared.abort.is_cancelled() && self.shared.lifecycle.mark_closing() {
                let _ = self.shared.cmd_tx.send(Command::Close);
            }
        }
        self.shared.lifecycle.wait_closed().await
    }

    /// Immediately abort the producer and its owned append session without waiting for buffered
    /// or in-flight records.
    ///
    /// Equivalent to dropping the producer early while keeping the handle alive (for example, when
    /// the handle is shared behind an `Arc`). Calling `abort()` after the producer has already
    /// closed is a no-op.
    pub fn abort(&self) {
        if !self.shared.lifecycle.is_closed() {
            self.shared.explicit_abort.store(true, Ordering::Release);
            self.shared.abort.cancel();
        }
    }
}

impl Drop for Producer {
    fn drop(&mut self) {
        if !self.shared.lifecycle.is_closed() {
            self.shared.abort.cancel();
        }
    }
}

/// A permit to submit a record after reserving capacity.
#[must_use = "a permit reserves producer capacity; call `.submit(...)` to enqueue the record"]
pub struct RecordSubmitPermit {
    append_permit: AppendPermit,
    reserved_bytes: usize,
    shared: Arc<ProducerShared>,
}

impl fmt::Debug for RecordSubmitPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordSubmitPermit")
            .field("reserved_bytes", &self.reserved_bytes)
            .finish_non_exhaustive()
    }
}

impl RecordSubmitPermit {
    /// Return the number of metered bytes reserved by this permit.
    #[must_use]
    pub fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    /// Submit the record using this permit.
    ///
    /// Accepts an [`AppendRecord`] or [`CommandRecord`](crate::types::CommandRecord). Any excess
    /// reserved capacity above the record's actual metered byte size is released immediately so
    /// waiting callers can proceed.
    ///
    /// Fails with [`ValidationError`] (releasing the reservation and leaving the producer open) if
    /// the record's metered size exceeds the reserved bytes or if advancing `match_seq_num` would
    /// overflow `u64`. Fails with [`SessionClosedError`] if the producer closed or began closing
    /// after the permit was reserved.
    pub fn submit(
        mut self,
        record: impl Into<AppendRecord>,
    ) -> Result<RecordSubmitTicket, AppendSessionError> {
        let record = record.into();
        FencingToken::validate_len(self.shared.fencing_token_len)
            .map_err(|e| self.shared.context.format_validation(e))?;
        record
            .validate_for_write()
            .map_err(|e| self.shared.context.format_validation(e))?;
        let metered = record.metered_bytes();
        if metered > self.reserved_bytes {
            return Err(AppendSessionError::Validation(
                self.shared.context.format_validation(format!(
                    "record size in metered bytes ({metered}) exceeds reserved capacity ({})",
                    self.reserved_bytes
                )),
            ));
        }

        // Release any unused over-reserved capacity immediately (`A4a`).
        self.append_permit.shrink(metered);

        let (ack_tx, ack_rx) = oneshot::channel();
        {
            let mut gate = self.shared.gate.lock().unwrap();
            gate.match_seq
                .check_available()
                .map_err(|e| self.shared.context.format_validation(e))?;
            let has_unacked_work =
                gate.last_accepted_id > self.shared.acked_through_id.load(Ordering::Acquire);
            if self.shared.is_closing_or_closed() || self.shared.abort.is_cancelled() {
                return Err(self.shared.session_closed_err(has_unacked_work));
            }
            let match_seq_num = gate
                .match_seq
                .claim_next()
                .map_err(|e| self.shared.context.format_validation(e))?;
            let acceptance_id = gate.last_accepted_id + 1;
            self.shared.unacked_records.fetch_add(1, Ordering::Release);
            if self
                .shared
                .cmd_tx
                .send(Command::Submit {
                    record,
                    record_bytes: metered,
                    acceptance_id,
                    match_seq_num,
                    ack_tx,
                    permit: self.append_permit,
                })
                .is_err()
            {
                self.shared.unacked_records.fetch_sub(1, Ordering::Release);
                return Err(self.shared.session_closed_err(has_unacked_work));
            }
            gate.last_accepted_id = acceptance_id;
        }

        Ok(RecordSubmitTicket(SubmitTicket::new(
            ack_rx,
            self.shared.lifecycle.clone(),
            self.shared.context.clone(),
            DROPPED_ABORT_MSG,
        )))
    }
}

struct UnsubmittedBatch {
    ack_txs: Vec<RecordAckTx>,
    _permit: AppendPermit,
}

struct ProducerTask {
    shared: Arc<ProducerShared>,
    session: AppendSessionCore,
    linger: Linger,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    partial_batch: PartialBatch,
    pending_batch_acks: FuturesOrdered<PendingBatchAck>,
    pending_flushes: VecDeque<PendingFlush>,
}

impl ProducerTask {
    fn new(
        shared: Arc<ProducerShared>,
        session: AppendSessionCore,
        config: ProducerConfig,
        cmd_rx: mpsc::UnboundedReceiver<Command>,
    ) -> Self {
        let partial_batch = PartialBatch::new(
            config.max_batch_records,
            config.max_batch_bytes,
            config.fencing_token,
        );
        Self {
            shared,
            session,
            linger: Linger::new(config.linger),
            cmd_rx,
            partial_batch,
            pending_batch_acks: FuturesOrdered::new(),
            pending_flushes: VecDeque::new(),
        }
    }

    /// Take the current partial batch and submit it to the owned session.
    /// Returns `Err(UnsubmittedBatch)` if the owned session has already closed/failed.
    fn try_cut_and_submit(&mut self) -> Result<(), UnsubmittedBatch> {
        self.linger.disarm();
        let Some((input, max_id, ack_txs, permit)) = self.partial_batch.take() else {
            return Ok(());
        };
        match self.session.submit(input, None) {
            Ok(ticket) => {
                self.pending_batch_acks.push_back(PendingBatchAck {
                    ticket,
                    batch_max_id: max_id,
                    ack_txs: Some(ack_txs),
                    permit: Some(permit),
                });
                Ok(())
            }
            Err(_) => Err(UnsubmittedBatch {
                ack_txs,
                _permit: permit,
            }),
        }
    }

    /// Cut the partial batch when backpressure is waiting and no other batch is in flight (`A5a`).
    ///
    /// Keeping the check level-triggered on current state (`pending_batch_acks.is_empty() &&
    /// !partial_batch.is_empty() && permits.has_waiters()`) prevents lost wakeups while avoiding
    /// small-batch fragmentation when other batches are already in flight.
    fn should_flush_for_backpressure(&self) -> bool {
        self.pending_batch_acks.is_empty()
            && !self.partial_batch.is_empty()
            && self.shared.permits.has_waiters()
    }

    fn publish_closing_from_session(&self, has_unsubmitted: bool) {
        let _gate = self.shared.gate.lock().unwrap();
        if let Some(err) = self.session.terminal_err() {
            self.shared.lifecycle.set_terminal_err(err);
        } else if has_unsubmitted && self.shared.abort.is_cancelled() {
            self.shared
                .lifecycle
                .set_terminal_err(AppendSessionError::Aborted(AbortedError::new_with_context(
                    self.shared.abort_reason(),
                    self.shared.context.clone(),
                )));
        } else if !self.shared.abort.is_cancelled() {
            self.shared.lifecycle.mark_closing();
        }
    }

    fn settle_batch_ack(
        &mut self,
        batch_ack: Result<AppendAck, AppendSessionError>,
        batch_max_id: u64,
        ack_txs: Vec<RecordAckTx>,
        batch_permit: AppendPermit,
    ) {
        let count = ack_txs.len();
        let ok = batch_ack.is_ok();
        // Release permit and update progress counters BEFORE waking tickets/flushes so callers
        // checking `unacked_bytes()` / `unacked_records()` / `acked_records()` immediately after
        // `ticket.await` or `flush().await` observe settled counts without racing.
        drop(batch_permit);
        self.shared
            .unacked_records
            .fetch_sub(count, Ordering::Release);
        if ok {
            self.shared
                .acked_through_id
                .store(batch_max_id, Ordering::Release);
        }
        dispatch_acks(batch_ack, ack_txs);
        if ok {
            resolve_satisfied_flushes(&mut self.pending_flushes, batch_max_id);
        }
    }

    async fn drain_pending_batch_acks(&mut self) {
        while let Some((batch_ack, batch_max_id, ack_txs, batch_permit)) =
            self.pending_batch_acks.next().await
        {
            self.settle_batch_ack(batch_ack, batch_max_id, ack_txs, batch_permit);
        }
    }

    fn settle_remaining(
        &mut self,
        unsubmitted: Option<UnsubmittedBatch>,
        queued_cmds: Vec<Command>,
        final_result: Result<(), AppendSessionError>,
    ) {
        if let Err(err) = &final_result {
            self.shared.lifecycle.set_terminal_err(err.clone());
        } else {
            self.shared.lifecycle.mark_closing();
        }

        let unsent_err = AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
            final_result.as_ref().err().cloned(),
            self.shared.context.clone(),
        ));

        if let Some(UnsubmittedBatch { ack_txs, _permit }) = unsubmitted {
            let count = ack_txs.len();
            drop(_permit);
            self.shared
                .unacked_records
                .fetch_sub(count, Ordering::Release);
            for ack_tx in ack_txs {
                let _ = ack_tx.send(Err(unsent_err.clone()));
            }
        }

        let partial_acks = self.partial_batch.drain_acks();
        if !partial_acks.is_empty() {
            self.shared
                .unacked_records
                .fetch_sub(partial_acks.len(), Ordering::Release);
            for ack_tx in partial_acks {
                let _ = ack_tx.send(Err(unsent_err.clone()));
            }
        }

        let acked = self.shared.acked_through_id.load(Ordering::Acquire);
        for flush in self.pending_flushes.drain(..) {
            let outcome = if acked >= flush.target_id {
                Ok(())
            } else {
                final_result.clone()
            };
            let _ = flush.done_tx.send(outcome);
        }

        for cmd in queued_cmds {
            match cmd {
                Command::Submit { ack_tx, permit, .. } => {
                    drop(permit);
                    self.shared.unacked_records.fetch_sub(1, Ordering::Release);
                    let _ = ack_tx.send(Err(unsent_err.clone()));
                }
                Command::Flush { target_id, done_tx } => {
                    let outcome = if acked >= target_id {
                        Ok(())
                    } else {
                        final_result.clone()
                    };
                    let _ = done_tx.send(outcome);
                }
                Command::Close => {}
            }
        }

        debug_assert_eq!(self.shared.unacked_records.load(Ordering::Acquire), 0);
        self.shared.lifecycle.finish(final_result);
    }

    async fn run(mut self) {
        let _finish_guard = FinishOnDrop::new(
            self.shared.lifecycle.clone(),
            self.shared.context.clone(),
            DROPPED_ABORT_MSG,
        );
        let mut closing = false;
        let abort = self.shared.abort.clone();

        loop {
            if closing && self.partial_batch.is_empty() && self.pending_batch_acks.is_empty() {
                break;
            }

            // For positive linger, flush before pulling more commands if deadline already elapsed.
            if !self.partial_batch.is_empty() && !self.linger.is_zero() && self.linger.elapsed() {
                if let Err(unsubmitted) = self.try_cut_and_submit() {
                    self.terminate(Some(unsubmitted)).await;
                    return;
                }
                continue;
            }

            let linger_active = !self.partial_batch.is_empty() && self.linger.prepare_sleep();

            tokio::select! {
                biased;

                // Deliver completed batch outcomes strictly in submission order (A6d, A7).
                Some((batch_ack, batch_max_id, ack_txs, batch_permit)) = self.pending_batch_acks.next() => {
                    if batch_ack.is_err() {
                        // Publish terminal error and close acceptance gate BEFORE dropping
                        // `batch_permit` and unblocking waiting `reserve()` callers (`A4c`, `A9`).
                        self.publish_closing_from_session(false);
                        self.settle_batch_ack(batch_ack, batch_max_id, ack_txs, batch_permit);
                        self.terminate(None).await;
                        return;
                    }
                    self.settle_batch_ack(batch_ack, batch_max_id, ack_txs, batch_permit);
                    if self.should_flush_for_backpressure() {
                        debug!("flushing partial batch early for backpressure waiter");
                        if let Err(unsubmitted) = self.try_cut_and_submit() {
                            self.terminate(Some(unsubmitted)).await;
                            return;
                        }
                    }
                }

                _ = abort.cancelled() => {
                    let reason = self.shared.abort_reason();
                    self.abort(reason).await;
                    return;
                }

                // A8b / A9: if the owned append session fails while no batch is in flight (for
                // example, a record is lingering in `partial_batch`), wake and settle immediately
                // rather than waiting out `linger`.
                _ = self.session.lifecycle().wait_closing_or_closed(), if !closing => {
                    self.terminate(None).await;
                    return;
                }

                _ = self.linger.wait(), if linger_active => {
                    if let Err(unsubmitted) = self.try_cut_and_submit() {
                        self.terminate(Some(unsubmitted)).await;
                        return;
                    }
                }

                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(Command::Submit {
                            record,
                            record_bytes,
                            acceptance_id,
                            match_seq_num,
                            ack_tx,
                            permit,
                        }) => {
                            if !self.partial_batch.is_empty()
                                && self.partial_batch.would_overflow(record_bytes)
                                && let Err(unsubmitted) = self.try_cut_and_submit()
                            {
                                // Put current record into partial_batch so terminate settles
                                // `unsubmitted` first, then this record, in order.
                                self.partial_batch.push(
                                    record,
                                    record_bytes,
                                    acceptance_id,
                                    match_seq_num,
                                    ack_tx,
                                    permit,
                                );
                                self.terminate(Some(unsubmitted)).await;
                                return;
                            }

                            let was_empty = self.partial_batch.is_empty();
                            self.partial_batch.push(
                                record,
                                record_bytes,
                                acceptance_id,
                                match_seq_num,
                                ack_tx,
                                permit,
                            );

                            if self.partial_batch.is_full() || self.should_flush_for_backpressure() {
                                if let Err(unsubmitted) = self.try_cut_and_submit() {
                                    self.terminate(Some(unsubmitted)).await;
                                    return;
                                }
                            } else if was_empty {
                                self.linger.arm_now();
                            }
                        }
                        Some(Command::Flush { target_id, done_tx }) => {
                            if self.shared.acked_through_id.load(Ordering::Acquire) >= target_id {
                                let _ = done_tx.send(Ok(()));
                                continue;
                            }
                            self.pending_flushes.push_back(PendingFlush { target_id, done_tx });
                            if !self.partial_batch.is_empty()
                                && let Err(unsubmitted) = self.try_cut_and_submit()
                            {
                                self.terminate(Some(unsubmitted)).await;
                                return;
                            }
                        }
                        Some(Command::Close) => {
                            closing = true;
                            if !self.partial_batch.is_empty()
                                && let Err(unsubmitted) = self.try_cut_and_submit()
                            {
                                self.terminate(Some(unsubmitted)).await;
                                return;
                            }
                        }
                        None => {
                            self.abort(DROPPED_ABORT_MSG).await;
                            return;
                        }
                    }
                }

                // When `linger == 0`, coalesce any immediately-queued commands above, then submit
                // as soon as the command channel is drained without touching the timer wheel.
                _ = std::future::ready(()), if self.linger.is_zero() && !self.partial_batch.is_empty() => {
                    if let Err(unsubmitted) = self.try_cut_and_submit() {
                        self.terminate(Some(unsubmitted)).await;
                        return;
                    }
                }

                // Wake when a caller begins waiting on capacity (`A5a`).
                _ = self.shared.flush_partial_notify.notified() => {
                    if self.should_flush_for_backpressure() {
                        debug!("flushing partial batch early for backpressure waiter");
                        if let Err(unsubmitted) = self.try_cut_and_submit() {
                            self.terminate(Some(unsubmitted)).await;
                            return;
                        }
                    }
                }
            }
        }

        self.finish_clean().await;
    }

    async fn finish_clean(mut self) {
        let session_close_res = self.session.close().await;
        let queued_cmds = {
            let _gate = self.shared.gate.lock().unwrap();
            self.shared.lifecycle.mark_closing();
            drain_queued_commands(&mut self.cmd_rx)
        };
        debug!(ok = session_close_res.is_ok(), "producer closed cleanly");
        self.settle_remaining(None, queued_cmds, session_close_res);
    }

    /// Settle all remaining batches using exact outcomes from the owned append session
    /// (`A6d`, `A9`), then fail any records still being batched or queued with
    /// `SessionClosedError` (`A6a`).
    async fn terminate(mut self, unsubmitted: Option<UnsubmittedBatch>) {
        self.publish_closing_from_session(unsubmitted.is_some());

        // Drain every remaining batch already submitted to the owned session so every record
        // receives the exact outcome reported by AppendSession strictly in submission order (A6d).
        self.drain_pending_batch_acks().await;

        // Obtain the owned session's exact failure (A9). If the owned session had nothing in
        // flight when an abort closed it cleanly, this producer still had unsubmitted work, so the
        // failure is `AbortedError` (`A8c`, `E6`).
        let session_failure = match self.session.close().await {
            Err(err) => err,
            Ok(()) => {
                debug_assert!(
                    self.shared.abort.is_cancelled(),
                    "owned session closed cleanly without abort while terminating producer"
                );
                AppendSessionError::Aborted(AbortedError::new_with_context(
                    self.shared.abort_reason(),
                    self.shared.context.clone(),
                ))
            }
        };

        debug!(%session_failure, "terminating producer on session failure");
        let queued_cmds = {
            let _gate = self.shared.gate.lock().unwrap();
            self.shared
                .lifecycle
                .set_terminal_err(session_failure.clone());
            drain_queued_commands(&mut self.cmd_rx)
        };
        self.settle_remaining(unsubmitted, queued_cmds, Err(session_failure));
    }

    async fn abort(mut self, reason: &'static str) {
        let aborted = AppendSessionError::Aborted(AbortedError::new_with_context(
            reason,
            self.shared.context.clone(),
        ));
        let queued_cmds = {
            let _gate = self.shared.gate.lock().unwrap();
            let queued = drain_queued_commands(&mut self.cmd_rx);
            let has_unsubmitted = !self.partial_batch.is_empty()
                || queued
                    .iter()
                    .any(|cmd| matches!(cmd, Command::Submit { .. }));
            if has_unsubmitted {
                // Publish failure before marking closing so waiting reserve()/submit() calls
                // observe `SessionClosedError { failure: Some(..) }` (`E6`).
                self.shared.lifecycle.set_terminal_err(
                    self.session
                        .terminal_err()
                        .unwrap_or_else(|| aborted.clone()),
                );
            } else if self.pending_batch_acks.is_empty() {
                self.shared.lifecycle.mark_closing();
            }
            queued
        };

        debug!(
            reason,
            pending_batches = self.pending_batch_acks.len(),
            partial_records = self.partial_batch.len(),
            "aborting producer"
        );

        // Abort the owned append session immediately (A3b, A8c) and forward its exact outcomes
        // (A6d).
        if self.shared.explicit_abort.load(Ordering::Acquire) {
            self.session.abort_explicit();
        } else {
            self.session.abort_dropped();
        }
        self.drain_pending_batch_acks().await;
        let session_res = self.session.close().await;

        let has_queued_submits = queued_cmds
            .iter()
            .any(|cmd| matches!(cmd, Command::Submit { .. }));
        let has_unsubmitted = !self.partial_batch.is_empty() || has_queued_submits;

        let final_result = match session_res {
            Err(session_err) => Err(session_err),
            Ok(()) if has_unsubmitted => Err(aborted),
            Ok(()) => Ok(()),
        };

        self.settle_remaining(None, queued_cmds, final_result);
    }
}

struct PartialBatch {
    acc: BatchAccumulator,
    max_acceptance_id: u64,
    permit: Option<AppendPermit>,
    ack_txs: Vec<RecordAckTx>,
}

impl PartialBatch {
    fn new(
        max_batch_records: usize,
        max_batch_bytes: usize,
        fencing_token: Option<FencingToken>,
    ) -> Self {
        Self {
            acc: BatchAccumulator::with_capacity(
                max_batch_records,
                max_batch_bytes,
                fencing_token,
                0,
            ),
            max_acceptance_id: 0,
            permit: None,
            ack_txs: Vec::new(),
        }
    }

    fn len(&self) -> usize {
        self.acc.len()
    }

    fn is_empty(&self) -> bool {
        self.acc.is_empty()
    }

    fn is_full(&self) -> bool {
        self.acc.is_full()
    }

    fn would_overflow(&self, record_bytes: usize) -> bool {
        self.acc.would_overflow(record_bytes)
    }

    fn push(
        &mut self,
        record: AppendRecord,
        record_bytes: usize,
        acceptance_id: u64,
        match_seq_num: Option<u64>,
        ack_tx: RecordAckTx,
        permit: AppendPermit,
    ) {
        self.acc.push(record, record_bytes, match_seq_num);
        self.max_acceptance_id = acceptance_id;
        match &mut self.permit {
            Some(existing) => existing.merge(permit),
            None => self.permit = Some(permit),
        }
        self.ack_txs.push(ack_tx);
    }

    fn take(&mut self) -> Option<(AppendInput, u64, Vec<RecordAckTx>, AppendPermit)> {
        if self.acc.is_empty() {
            return None;
        }
        let input = self.acc.take();
        let max_id = self.max_acceptance_id;
        let ack_txs = std::mem::take(&mut self.ack_txs);
        let permit = self
            .permit
            .take()
            .expect("non-empty PartialBatch must hold a permit");
        Some((input, max_id, ack_txs, permit))
    }

    fn drain_acks(&mut self) -> Vec<RecordAckTx> {
        self.acc.clear();
        self.permit = None;
        std::mem::take(&mut self.ack_txs)
    }
}

enum Command {
    Submit {
        record: AppendRecord,
        record_bytes: usize,
        acceptance_id: u64,
        match_seq_num: Option<u64>,
        ack_tx: RecordAckTx,
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

struct PendingBatchAck {
    ticket: BatchSubmitTicket,
    batch_max_id: u64,
    ack_txs: Option<Vec<RecordAckTx>>,
    permit: Option<AppendPermit>,
}

impl Future for PendingBatchAck {
    type Output = (
        Result<AppendAck, AppendSessionError>,
        u64,
        Vec<RecordAckTx>,
        AppendPermit,
    );

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.ticket).poll(cx) {
            Poll::Ready(batch_ack) => Poll::Ready((
                batch_ack,
                self.batch_max_id,
                self.ack_txs.take().expect("ack_txs should not be None"),
                self.permit.take().expect("permit should not be None"),
            )),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn dispatch_acks(batch_ack: Result<AppendAck, AppendSessionError>, ack_txs: Vec<RecordAckTx>) {
    match batch_ack {
        Ok(batch_ack) => {
            for (offset, ack_tx) in ack_txs.into_iter().enumerate() {
                let seq_num = batch_ack.start.seq_num + offset as u64;
                let _ = ack_tx.send(Ok(RecordAck {
                    seq_num,
                    batch: batch_ack.clone(),
                }));
            }
        }
        Err(err) => {
            for ack_tx in ack_txs {
                let _ = ack_tx.send(Err(err.clone()));
            }
        }
    }
}

fn drain_queued_commands(cmd_rx: &mut mpsc::UnboundedReceiver<Command>) -> Vec<Command> {
    cmd_rx.close();
    let mut queued = Vec::new();
    while let Ok(cmd) = cmd_rx.try_recv() {
        queued.push(cmd);
    }
    queued
}

fn resolve_satisfied_flushes(pending_flushes: &mut VecDeque<PendingFlush>, acked_through_id: u64) {
    while let Some(front) = pending_flushes.front() {
        if front.target_id <= acked_through_id {
            let flush = pending_flushes.pop_front().expect("checked front");
            let _ = flush.done_tx.send(Ok(()));
        } else {
            break;
        }
    }
}
