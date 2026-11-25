//! High-level producer for appending individual records to streams.
//!
//! See [`Producer`].

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    pin::{Pin, pin},
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use futures_core::FusedFuture;
use tokio::{
    sync::{Notify, mpsc, oneshot},
    time::Instant,
};
use tracing::{Instrument, debug, debug_span};

use crate::{
    api::BasinClient,
    batching::{
        Linger, MatchSeqState, validate_max_batch_bytes, validate_max_batch_records,
        validate_record_size,
    },
    error::{AbortedError, AppendSessionError, ErrorContext, SessionClosedError, ValidationError},
    session::{
        AppendPermit, AppendPermits, AppendSessionCore, BatchSubmitTicket, SessionAbort,
        SessionLifecycle, StreamHeaders, validate_max_unacked_bytes, validate_reserve_bytes,
    },
    types::{
        AppendAck, AppendRecord, BasinName, FencingToken, ONE_MIB, RECORD_BATCH_MAX, StreamConfig,
        StreamName,
    },
};

const EXPLICIT_ABORT_MSG: &str = "producer aborted";
const DROPPED_ABORT_MSG: &str = "producer dropped without calling close";

/// Per-batch shared outcome resolved once for all [`RecordSubmitTicket`]s belonging to a batch.
struct BatchOutcome {
    result: OnceLock<Result<AppendAck, AppendSessionError>>,
    waiters: StdMutex<Option<Vec<Option<Waker>>>>,
}

impl BatchOutcome {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            result: OnceLock::new(),
            waiters: StdMutex::new(Some(Vec::new())),
        })
    }

    fn resolve(&self, result: Result<AppendAck, AppendSessionError>) {
        let _ = self.result.set(result);
        let waiters = self.waiters.lock().unwrap().take();
        if let Some(waiters) = waiters {
            for waker in waiters.into_iter().flatten() {
                waker.wake();
            }
        }
    }
}

/// Panic-safe writer handle for a [`BatchOutcome`]. Owns the batch's `unacked_records`
/// accounting so success, failure, and implicit drop each decrement `unacked_records` exactly
/// once before publishing the outcome to waiting tickets.
struct BatchOutcomeWriter {
    outcome: Arc<BatchOutcome>,
    lifecycle: Arc<SessionLifecycle>,
    unacked_records: Arc<AtomicUsize>,
    record_count: usize,
    context: ErrorContext,
    resolved: bool,
}

impl BatchOutcomeWriter {
    fn new(
        lifecycle: Arc<SessionLifecycle>,
        unacked_records: Arc<AtomicUsize>,
        context: ErrorContext,
    ) -> (Self, Arc<BatchOutcome>) {
        let outcome = BatchOutcome::new();
        let writer = Self {
            outcome: outcome.clone(),
            lifecycle,
            unacked_records,
            record_count: 0,
            context,
            resolved: false,
        };
        (writer, outcome)
    }

    fn resolve(mut self, result: Result<AppendAck, AppendSessionError>) {
        self.resolved = true;
        if self.record_count > 0 {
            self.unacked_records
                .fetch_sub(self.record_count, Ordering::Release);
        }
        self.outcome.resolve(result);
    }
}

impl Drop for BatchOutcomeWriter {
    fn drop(&mut self) {
        if !self.resolved {
            self.resolved = true;
            if self.record_count > 0 {
                self.unacked_records
                    .fetch_sub(self.record_count, Ordering::Release);
            }
            let err = self.lifecycle.terminal_err().unwrap_or_else(|| {
                AppendSessionError::Aborted(AbortedError::new_with_context(
                    DROPPED_ABORT_MSG,
                    self.context.clone(),
                ))
            });
            self.outcome.resolve(Err(err));
        }
    }
}

/// A [`Future`] that resolves to a [`RecordAck`] once the record is appended.
///
/// Once resolved, re-polling returns the same outcome without panicking, and
/// [`try_ack`](Self::try_ack) returns `None`.
pub struct RecordSubmitTicket {
    outcome: Arc<BatchOutcome>,
    offset: u32,
    waker_slot: Option<usize>,
    done: bool,
}

fn map_record_outcome(
    result: &Result<AppendAck, AppendSessionError>,
    offset: u32,
) -> Result<RecordAck, AppendSessionError> {
    match result {
        Ok(batch) => Ok(RecordAck {
            seq_num: batch.start.seq_num + u64::from(offset),
            batch: batch.clone(),
        }),
        Err(err) => Err(err.clone()),
    }
}

impl RecordSubmitTicket {
    fn new(outcome: Arc<BatchOutcome>, offset: u32) -> Self {
        Self {
            outcome,
            offset,
            waker_slot: None,
            done: false,
        }
    }

    /// Poll the ticket without blocking, returning `Some` once the record outcome is ready.
    ///
    /// Returns `None` if the record is still in flight or if the outcome was already consumed.
    #[must_use]
    pub fn try_ack(&mut self) -> Option<Result<RecordAck, AppendSessionError>> {
        if self.done {
            return None;
        }
        let res = self.outcome.result.get()?;
        self.done = true;
        Some(map_record_outcome(res, self.offset))
    }
}

impl fmt::Debug for RecordSubmitTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordSubmitTicket").finish_non_exhaustive()
    }
}

impl Future for RecordSubmitTicket {
    type Output = Result<RecordAck, AppendSessionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(res) = this.outcome.result.get() {
            this.done = true;
            return Poll::Ready(map_record_outcome(res, this.offset));
        }
        let mut replaced_waker = None;
        {
            let mut waiters = this.outcome.waiters.lock().unwrap();
            if let Some(list) = waiters.as_mut() {
                match this.waker_slot {
                    Some(idx) => match &mut list[idx] {
                        Some(existing) if existing.will_wake(cx.waker()) => {}
                        slot => replaced_waker = slot.replace(cx.waker().clone()),
                    },
                    None => {
                        this.waker_slot = Some(list.len());
                        list.push(Some(cx.waker().clone()));
                    }
                }
                drop(waiters);
                drop(replaced_waker);
                return Poll::Pending;
            }
        }
        let res = this
            .outcome
            .result
            .get()
            .expect("result stored before waiters closed");
        this.done = true;
        Poll::Ready(map_record_outcome(res, this.offset))
    }
}

impl Drop for RecordSubmitTicket {
    fn drop(&mut self) {
        if let Some(idx) = self.waker_slot
            && !self.done
            && self.outcome.result.get().is_none()
        {
            // Release the `waiters` lock BEFORE dropping the removed waker so a custom waker
            // whose destructor drops another ticket from the same batch cannot deadlock.
            let dropped_waker = self
                .outcome
                .waiters
                .lock()
                .ok()
                .and_then(|mut guard| guard.as_mut()?.get_mut(idx)?.take());
            drop(dropped_waker);
        }
    }
}

impl FusedFuture for RecordSubmitTicket {
    fn is_terminated(&self) -> bool {
        self.done
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

    /// Set the fencing token for all [`AppendInput`](crate::types::AppendInput)s.
    ///
    /// Defaults to `None`.
    pub fn with_fencing_token(self, fencing_token: FencingToken) -> Self {
        Self {
            fencing_token: Some(fencing_token),
            ..self
        }
    }

    /// Set the match sequence number for the initial [`AppendInput`](crate::types::AppendInput). It
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

struct ReadyBatch {
    batch_id: u64,
    records: Vec<AppendRecord>,
    match_seq_num: Option<u64>,
    max_acceptance_id: u64,
    /// Declared before `outcome_writer` so implicit drop releases bytes before settling tickets.
    permit: AppendPermit,
    outcome_writer: BatchOutcomeWriter,
}

struct PartialBatch {
    max_batch_records: usize,
    max_batch_bytes: usize,
    records: Vec<AppendRecord>,
    metered_bytes: usize,
    batch_match_seq: Option<u64>,
    max_acceptance_id: u64,
    started_at: Option<Instant>,
    permit: Option<AppendPermit>,
    outcome: Option<(BatchOutcomeWriter, Arc<BatchOutcome>)>,
}

impl PartialBatch {
    fn new(max_batch_records: usize, max_batch_bytes: usize) -> Self {
        Self {
            max_batch_records,
            max_batch_bytes,
            records: Vec::new(),
            metered_bytes: 0,
            batch_match_seq: None,
            max_acceptance_id: 0,
            started_at: None,
            permit: None,
            outcome: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn is_full(&self) -> bool {
        self.records.len() >= self.max_batch_records || self.metered_bytes >= self.max_batch_bytes
    }

    fn would_overflow(&self, record_bytes: usize) -> bool {
        self.records.len() + 1 > self.max_batch_records
            || self.metered_bytes + record_bytes > self.max_batch_bytes
    }

    fn push(
        &mut self,
        record: AppendRecord,
        record_bytes: usize,
        acceptance_id: u64,
        match_seq_num: Option<u64>,
        permit: AppendPermit,
        shared: &ProducerShared,
    ) -> (Arc<BatchOutcome>, u32, Option<Instant>) {
        let started_now = if self.records.is_empty() {
            if self.records.capacity() == 0
                && let Ok(mut recycled) = shared.recycled_records.try_lock()
                && recycled.capacity() > 0
            {
                self.records = std::mem::take(&mut *recycled);
            }
            self.batch_match_seq = match_seq_num;
            let now = Instant::now();
            self.started_at = Some(now);
            let (writer, outcome) = BatchOutcomeWriter::new(
                shared.lifecycle.clone(),
                shared.unacked_records.clone(),
                shared.context.clone(),
            );
            self.outcome = Some((writer, outcome));
            Some(now)
        } else {
            None
        };

        let offset = self.records.len() as u32;
        self.records.push(record);
        self.metered_bytes += record_bytes;
        self.max_acceptance_id = acceptance_id;
        match &mut self.permit {
            Some(existing) => existing.merge(permit),
            None => self.permit = Some(permit),
        }
        let (writer, outcome) = self
            .outcome
            .as_mut()
            .expect("non-empty PartialBatch has outcome");
        writer.record_count += 1;
        shared.unacked_records.fetch_add(1, Ordering::Release);
        (outcome.clone(), offset, started_now)
    }

    fn take(&mut self, batch_id: u64) -> Option<ReadyBatch> {
        if self.records.is_empty() {
            return None;
        }
        let records = std::mem::take(&mut self.records);
        self.metered_bytes = 0;
        let match_seq_num = self.batch_match_seq.take();
        let max_acceptance_id = self.max_acceptance_id;
        self.started_at = None;
        let permit = self
            .permit
            .take()
            .expect("non-empty PartialBatch must hold a permit");
        let (outcome_writer, _) = self
            .outcome
            .take()
            .expect("non-empty PartialBatch must hold an outcome writer");
        Some(ReadyBatch {
            batch_id,
            records,
            match_seq_num,
            max_acceptance_id,
            outcome_writer,
            permit,
        })
    }
}

struct ProducerGate {
    match_seq: MatchSeqState,
    last_accepted_id: u64,
    next_batch_id: u64,
    partial: PartialBatch,
}

impl ProducerGate {
    fn take_partial(
        &mut self,
        has_partial: &AtomicBool,
        next_batch_id: &AtomicU64,
    ) -> Option<ReadyBatch> {
        let batch = self.partial.take(self.next_batch_id)?;
        self.next_batch_id += 1;
        next_batch_id.store(self.next_batch_id, Ordering::Release);
        has_partial.store(false, Ordering::Release);
        Some(batch)
    }
}

struct ProducerShared {
    basin: BasinName,
    stream: StreamName,
    gate: StdMutex<ProducerGate>,
    recycled_records: StdMutex<Vec<AppendRecord>>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    permits: AppendPermits,
    max_batch_bytes: usize,
    fencing_token_len: usize,
    match_seq_exhausted: AtomicBool,
    has_partial: AtomicBool,
    next_batch_id: AtomicU64,
    unacked_records: Arc<AtomicUsize>,
    acked_through_id: AtomicU64,
    lifecycle: Arc<SessionLifecycle>,
    session_lifecycle: Arc<SessionLifecycle>,
    /// Cancelled on client close or producer drop/abort; its child cancels the owned session.
    abort: SessionAbort,
    flush_partial_notify: Notify,
    context: ErrorContext,
}

impl ProducerShared {
    fn is_closing_or_closed(&self) -> bool {
        // Ignore a clean `session_lifecycle` close here: if `client.close()` aborts an idle owned
        // session while the producer still holds a partial batch, `ProducerTask` drives
        // `self.lifecycle` with `AbortedError` (`A8c`, `E6`).
        self.lifecycle.is_closing_or_closed() || self.session_lifecycle.has_terminal_err()
    }

    fn session_closed_err(&self, has_unacked_work: bool) -> AppendSessionError {
        let failure = self
            .lifecycle
            .terminal_err()
            .or_else(|| self.session_lifecycle.terminal_err())
            .or_else(|| {
                (has_unacked_work && self.abort.is_cancelled()).then(|| {
                    AppendSessionError::Aborted(AbortedError::new_with_context(
                        self.abort.reason(),
                        self.context.clone(),
                    ))
                })
            });
        AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
            failure,
            self.context.clone(),
        ))
    }

    fn recycle_records(&self, mut records: Vec<AppendRecord>) {
        records.clear();
        if records.capacity() == 0 {
            return;
        }
        if let Ok(mut slot) = self.recycled_records.try_lock()
            && records.capacity() > slot.capacity()
        {
            *slot = records;
        }
    }

    fn fail_unsent_batch(&self, batch: ReadyBatch, err: &AppendSessionError) {
        let ReadyBatch {
            records,
            outcome_writer,
            permit,
            ..
        } = batch;
        drop(records);
        drop(permit);
        outcome_writer.resolve(Err(err.clone()));
    }

    fn submit_with_permit(
        &self,
        append_permit: AppendPermit,
        record: AppendRecord,
        metered: usize,
    ) -> Result<RecordSubmitTicket, AppendSessionError> {
        let mut gate = self.gate.lock().unwrap();
        gate.match_seq
            .check_available()
            .map_err(|e| self.context.format_validation(e))?;
        let has_unacked_work =
            gate.last_accepted_id > self.acked_through_id.load(Ordering::Acquire);
        if self.is_closing_or_closed() || self.abort.is_cancelled() || self.cmd_tx.is_closed() {
            return Err(self.session_closed_err(has_unacked_work));
        }

        let match_seq_num = gate
            .match_seq
            .claim_next()
            .map_err(|e| self.context.format_validation(e))?;
        if gate.match_seq.is_exhausted() {
            self.match_seq_exhausted.store(true, Ordering::Release);
        }

        if !gate.partial.is_empty()
            && gate.partial.would_overflow(metered)
            && let Some(overflow_batch) = gate.take_partial(&self.has_partial, &self.next_batch_id)
            && let Err(mpsc::error::SendError(Command::Batch(unsent))) =
                self.cmd_tx.send(Command::Batch(overflow_batch))
        {
            let err = self.session_closed_err(true);
            self.fail_unsent_batch(unsent, &err);
            return Err(err);
        }

        let acceptance_id = gate.last_accepted_id + 1;
        let (outcome, offset, started_at) = gate.partial.push(
            record,
            metered,
            acceptance_id,
            match_seq_num,
            append_permit,
            self,
        );
        gate.last_accepted_id = acceptance_id;

        if gate.partial.is_full() {
            let ready_batch = gate
                .take_partial(&self.has_partial, &self.next_batch_id)
                .expect("full partial batch must be non-empty");
            if let Err(mpsc::error::SendError(Command::Batch(unsent))) =
                self.cmd_tx.send(Command::Batch(ready_batch))
            {
                let err = self.session_closed_err(true);
                self.fail_unsent_batch(unsent, &err);
                return Err(err);
            }
        } else if let Some(started_at) = started_at {
            self.has_partial.store(true, Ordering::Release);
            let batch_id = gate.next_batch_id;
            if self
                .cmd_tx
                .send(Command::PartialStarted {
                    batch_id,
                    started_at,
                })
                .is_err()
                && let Some(unsent) = gate.take_partial(&self.has_partial, &self.next_batch_id)
            {
                let err = self.session_closed_err(true);
                self.fail_unsent_batch(unsent, &err);
                return Err(err);
            }
        }

        Ok(RecordSubmitTicket::new(outcome, offset))
    }
}

/// High-level interface for submitting individual [`AppendRecord`]s.
///
/// Handles batching of records into [`AppendInput`](crate::types::AppendInput)s automatically based
/// on [`ProducerConfig`], and owns an internal append session. Opening a producer sends no request
/// until the first batch is ready.
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
        let abort = SessionAbort::new(
            client.shutdown_token(),
            EXPLICIT_ABORT_MSG,
            DROPPED_ABORT_MSG,
        );
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let permits = AppendPermits::new(None, config.max_unacked_bytes);
        let max_batch_bytes = config.max_batch_bytes;
        let fencing_token_len = config.fencing_token.as_ref().map_or(0, |t| t.len());
        let match_seq = MatchSeqState::from_option(config.match_seq_num);
        let match_seq_exhausted = AtomicBool::new(match_seq.is_exhausted());
        let gate = StdMutex::new(ProducerGate {
            match_seq,
            last_accepted_id: 0,
            next_batch_id: 0,
            partial: PartialBatch::new(config.max_batch_records, config.max_batch_bytes),
        });
        let lifecycle = Arc::new(SessionLifecycle::new());
        let session = AppendSessionCore::new_with_abort(
            client,
            stream.clone(),
            headers,
            "producer",
            abort.child(),
        );
        let session_lifecycle = session.lifecycle().clone();

        let shared = Arc::new(ProducerShared {
            basin: basin.clone(),
            stream: stream.clone(),
            gate,
            recycled_records: StdMutex::new(Vec::new()),
            cmd_tx,
            permits,
            max_batch_bytes,
            fencing_token_len,
            match_seq_exhausted,
            has_partial: AtomicBool::new(false),
            next_batch_id: AtomicU64::new(0),
            unacked_records: Arc::new(AtomicUsize::new(0)),
            acked_through_id: AtomicU64::new(0),
            lifecycle,
            session_lifecycle,
            abort,
            flush_partial_notify: Notify::new(),
            context,
        });

        let span = debug_span!("producer", op = "producer", basin = %basin, stream = %stream);
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

    async fn acquire_permit(&self, bytes: usize) -> Result<AppendPermit, AppendSessionError> {
        self.check_open_for_reserve().await?;

        if let Some(permit) = self.shared.permits.try_acquire(bytes) {
            self.check_open_for_reserve().await?;
            return Ok(permit);
        }

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
        Ok(append_permit)
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
        if self.shared.match_seq_exhausted.load(Ordering::Acquire) {
            return Err(self
                .shared
                .context
                .format_validation(MatchSeqState::overflow_error())
                .into());
        }
        let append_permit = self.acquire_permit(bytes).await?;
        self.shared.submit_with_permit(append_permit, record, bytes)
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
        let append_permit = self.acquire_permit(bytes).await?;

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
            // Hold gate across reading `last_accepted_id`, cutting any partial batch, and
            // enqueueing `Command::Flush` so the flush boundary linearizes strictly between
            // earlier and later submits (`A7`) and arrives in non-decreasing `target_id` order.
            let mut gate = self.shared.gate.lock().unwrap();
            let target_id = gate.last_accepted_id;

            if self.shared.acked_through_id.load(Ordering::Acquire) >= target_id {
                return Ok(());
            }

            if self.shared.lifecycle.is_closed() || self.shared.cmd_tx.is_closed() {
                Err(target_id)
            } else {
                if let Some(batch) =
                    gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id)
                    && let Err(mpsc::error::SendError(Command::Batch(unsent))) =
                        self.shared.cmd_tx.send(Command::Batch(batch))
                {
                    let err = self.shared.session_closed_err(true);
                    self.shared.fail_unsent_batch(unsent, &err);
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
            let mut gate = self.shared.gate.lock().unwrap();
            if !self.shared.abort.is_cancelled() && self.shared.lifecycle.mark_closing() {
                if let Some(batch) =
                    gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id)
                    && let Err(mpsc::error::SendError(Command::Batch(unsent))) =
                        self.shared.cmd_tx.send(Command::Batch(batch))
                {
                    let err = self.shared.session_closed_err(true);
                    self.shared.fail_unsent_batch(unsent, &err);
                }
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
            self.shared.abort.cancel_explicit();
        }
    }
}

impl Drop for Producer {
    fn drop(&mut self) {
        if !self.shared.lifecycle.is_closed() {
            self.shared.abort.cancel_dropped();
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
        self.shared
            .submit_with_permit(self.append_permit, record, metered)
    }
}

struct UnsubmittedBatch {
    /// Declared before `outcome_writer` so implicit drop releases bytes before settling tickets.
    _permit: AppendPermit,
    outcome_writer: BatchOutcomeWriter,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CutReason {
    Linger,
    Backpressure,
    ZeroLinger,
}

struct ProducerTask {
    shared: Arc<ProducerShared>,
    session: AppendSessionCore,
    fencing_token: Option<FencingToken>,
    linger_duration: Duration,
    linger: Linger,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    received_batches: u64,
    pending_batch_acks: VecDeque<PendingBatchAck>,
    pending_flushes: VecDeque<PendingFlush>,
}

impl Drop for ProducerTask {
    fn drop(&mut self) {
        if self.shared.lifecycle.is_closed() {
            return;
        }
        let aborted = AppendSessionError::Aborted(AbortedError::new_with_context(
            DROPPED_ABORT_MSG,
            self.shared.context.clone(),
        ));
        let (queued_cmds, partial_batch, err) = {
            let mut gate = self
                .shared
                .gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.shared.gate.clear_poison();
            let err = self.shared.lifecycle.terminal_err().unwrap_or(aborted);
            self.shared.lifecycle.set_terminal_err(err.clone());
            let queued = drain_queued_commands(&mut self.cmd_rx);
            let partial = gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id);
            (queued, partial, err)
        };

        self.session.abort_dropped();
        for mut pending in self.pending_batch_acks.drain(..) {
            drop(pending.permit.take());
            if let Some(writer) = pending.outcome_writer.take() {
                writer.resolve(Err(err.clone()));
            }
        }
        self.shared
            .settle_aborted_drop(&mut self.pending_flushes, queued_cmds, partial_batch, err);
    }
}

impl ProducerTask {
    fn new(
        shared: Arc<ProducerShared>,
        session: AppendSessionCore,
        config: ProducerConfig,
        cmd_rx: mpsc::UnboundedReceiver<Command>,
    ) -> Self {
        Self {
            shared,
            session,
            fencing_token: config.fencing_token,
            linger_duration: config.linger,
            linger: Linger::new(config.linger),
            cmd_rx,
            received_batches: 0,
            pending_batch_acks: VecDeque::new(),
            pending_flushes: VecDeque::new(),
        }
    }

    fn submit_ready_batch(&mut self, batch: ReadyBatch) -> Result<(), UnsubmittedBatch> {
        debug_assert_eq!(batch.batch_id, self.received_batches);
        self.received_batches += 1;
        let ReadyBatch {
            records,
            match_seq_num,
            max_acceptance_id,
            outcome_writer,
            permit,
            ..
        } = batch;
        let res =
            self.session
                .submit_parts(&records, match_seq_num, self.fencing_token.as_deref(), None);
        self.shared.recycle_records(records);
        match res {
            Ok(ticket) => {
                self.pending_batch_acks.push_back(PendingBatchAck {
                    ticket,
                    batch_max_id: max_acceptance_id,
                    permit: Some(permit),
                    outcome_writer: Some(outcome_writer),
                });
                Ok(())
            }
            Err(_) => Err(UnsubmittedBatch {
                _permit: permit,
                outcome_writer,
            }),
        }
    }

    /// Inspect `gate.partial` and cut/submit it if eligible and strictly ordered after all
    /// `Command::Batch` entries already queued in `cmd_rx`.
    ///
    /// Returns `Ok(false)` only when deferred because an earlier batch is still queued in `cmd_rx`.
    fn try_cut_partial(&mut self, reason: CutReason) -> Result<bool, UnsubmittedBatch> {
        let ready_batch = {
            let mut gate = self.shared.gate.lock().unwrap();
            // If an earlier batch is still sitting in `cmd_rx`, defer so FIFO batch order holds.
            if gate.next_batch_id != self.received_batches {
                return Ok(false);
            }
            if gate.partial.is_empty() {
                self.linger.disarm();
                return Ok(true);
            }
            if reason == CutReason::Linger {
                let started_at = gate
                    .partial
                    .started_at
                    .expect("non-empty PartialBatch has started_at");
                if let Some(deadline) = started_at.checked_add(self.linger_duration)
                    && Instant::now() < deadline
                {
                    self.linger.arm_from(started_at);
                    return Ok(true);
                }
            }
            gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id)
        };
        self.linger.disarm();
        if let Some(batch) = ready_batch {
            self.submit_ready_batch(batch)?;
        }
        Ok(true)
    }

    /// Cut the partial batch when backpressure is waiting and no other batch is in flight (`A5a`).
    fn should_flush_for_backpressure(&self) -> bool {
        self.pending_batch_acks.is_empty()
            && self.shared.has_partial.load(Ordering::Acquire)
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
                    self.shared.abort.reason(),
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
        outcome_writer: BatchOutcomeWriter,
        batch_permit: AppendPermit,
    ) {
        let ok = batch_ack.is_ok();
        // Release permit and update progress counters BEFORE waking tickets/flushes so callers
        // checking `unacked_bytes()` / `unacked_records()` / `acked_records()` immediately after
        // `ticket.await` or `flush().await` observe settled counts without racing.
        drop(batch_permit);
        if ok {
            self.shared
                .acked_through_id
                .store(batch_max_id, Ordering::Release);
        }
        outcome_writer.resolve(batch_ack);
        if ok {
            resolve_satisfied_flushes(&mut self.pending_flushes, batch_max_id);
        }
    }

    async fn drain_pending_batch_acks(&mut self) {
        while let Some(mut pending) = self.pending_batch_acks.pop_front() {
            let batch_ack = pending.ticket.await;
            let outcome_writer = pending
                .outcome_writer
                .take()
                .expect("outcome_writer should not be None");
            let permit = pending.permit.take().expect("permit should not be None");
            self.settle_batch_ack(batch_ack, pending.batch_max_id, outcome_writer, permit);
        }
    }

    fn settle_remaining(
        &mut self,
        unsubmitted: Option<UnsubmittedBatch>,
        queued_cmds: Vec<Command>,
        partial_batch: Option<ReadyBatch>,
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

        if let Some(UnsubmittedBatch {
            _permit,
            outcome_writer,
        }) = unsubmitted
        {
            drop(_permit);
            outcome_writer.resolve(Err(unsent_err.clone()));
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
                Command::Batch(batch) => {
                    self.shared.fail_unsent_batch(batch, &unsent_err);
                }
                Command::Flush { target_id, done_tx } => {
                    let outcome = if acked >= target_id {
                        Ok(())
                    } else {
                        final_result.clone()
                    };
                    let _ = done_tx.send(outcome);
                }
                Command::PartialStarted { .. } | Command::Close => {}
            }
        }

        if let Some(batch) = partial_batch {
            self.shared.fail_unsent_batch(batch, &unsent_err);
        }

        debug_assert_eq!(self.shared.unacked_records.load(Ordering::Acquire), 0);
        self.shared.lifecycle.finish(final_result);
    }

    async fn run(mut self) {
        let mut closing = false;
        let abort = self.shared.abort.clone();
        let mut abort_fut = pin!(abort.cancelled());
        let session_lifecycle = self.session.lifecycle().clone();
        let mut session_closing_fut = pin!(session_lifecycle.wait_closing_or_closed());
        let shared_for_notify = self.shared.clone();
        let mut flush_notified = pin!(shared_for_notify.flush_partial_notify.notified());

        loop {
            if closing && self.pending_batch_acks.is_empty() {
                break;
            }

            let no_earlier_batches =
                self.shared.next_batch_id.load(Ordering::Acquire) == self.received_batches;

            // For positive linger, flush before pulling more commands if deadline already elapsed.
            if no_earlier_batches
                && self.shared.has_partial.load(Ordering::Acquire)
                && !self.linger.is_zero()
                && self.linger.elapsed()
            {
                if let Err(unsubmitted) = self.try_cut_partial(CutReason::Linger) {
                    self.terminate(Some(unsubmitted)).await;
                    return;
                }
                if !self.shared.has_partial.load(Ordering::Acquire) {
                    continue;
                }
            }

            let has_pending_acks = !self.pending_batch_acks.is_empty();
            let has_partial = self.shared.has_partial.load(Ordering::Acquire);
            let no_earlier_batches =
                self.shared.next_batch_id.load(Ordering::Acquire) == self.received_batches;
            let linger_active = has_partial && no_earlier_batches && self.linger.is_armed();

            tokio::select! {
                biased;

                // Deliver completed batch outcomes strictly in submission order (A6d, A7).
                batch_ack = async {
                    (&mut self
                        .pending_batch_acks
                        .front_mut()
                        .expect("pending_batch_acks non-empty")
                        .ticket)
                        .await
                }, if has_pending_acks => {
                    let mut pending = self
                        .pending_batch_acks
                        .pop_front()
                        .expect("pending_batch_acks non-empty");
                    let outcome_writer = pending
                        .outcome_writer
                        .take()
                        .expect("outcome_writer should not be None");
                    let batch_permit = pending.permit.take().expect("permit should not be None");
                    if batch_ack.is_err() {
                        // Publish terminal error and close acceptance gate BEFORE dropping
                        // `batch_permit` and unblocking waiting `reserve()` callers (`A4c`, `A9`).
                        self.publish_closing_from_session(false);
                        self.settle_batch_ack(
                            batch_ack,
                            pending.batch_max_id,
                            outcome_writer,
                            batch_permit,
                        );
                        self.terminate(None).await;
                        return;
                    }
                    self.settle_batch_ack(
                        batch_ack,
                        pending.batch_max_id,
                        outcome_writer,
                        batch_permit,
                    );
                    if self.should_flush_for_backpressure() {
                        debug!("flushing partial batch early for backpressure waiter");
                        if let Err(unsubmitted) = self.try_cut_partial(CutReason::Backpressure) {
                            self.terminate(Some(unsubmitted)).await;
                            return;
                        }
                    }
                }

                _ = abort_fut.as_mut() => {
                    let reason = self.shared.abort.reason();
                    self.abort(reason).await;
                    return;
                }

                // A8b / A9: if the owned append session fails while no batch is in flight (for
                // example, a record is lingering in `partial_batch`), wake and settle immediately
                // rather than waiting out `linger`.
                _ = session_closing_fut.as_mut(), if !closing => {
                    self.terminate(None).await;
                    return;
                }

                cmd = self.cmd_rx.recv() => {
                    let mut current = cmd;
                    let mut pending_partial: Option<(u64, Instant)> = None;
                    for remaining in (0..32).rev() {
                        match current {
                            Some(Command::Batch(batch)) => {
                                pending_partial = None;
                                self.linger.disarm();
                                if let Err(unsubmitted) = self.submit_ready_batch(batch) {
                                    self.terminate(Some(unsubmitted)).await;
                                    return;
                                }
                                // Yield back to the biased `select!` after each heavy batch encode
                                // so completed acks immediately release backpressure permits.
                                break;
                            }
                            Some(Command::PartialStarted {
                                batch_id,
                                started_at,
                            }) => {
                                pending_partial = Some((batch_id, started_at));
                            }
                            Some(Command::Flush { target_id, done_tx }) => {
                                if self.shared.acked_through_id.load(Ordering::Acquire) >= target_id {
                                    let _ = done_tx.send(Ok(()));
                                } else {
                                    self.pending_flushes.push_back(PendingFlush { target_id, done_tx });
                                }
                            }
                            Some(Command::Close) => {
                                closing = true;
                                break;
                            }
                            None => {
                                self.abort(DROPPED_ABORT_MSG).await;
                                return;
                            }
                        }
                        if remaining == 0 {
                            break;
                        }
                        match self.cmd_rx.try_recv() {
                            Ok(next) => current = Some(next),
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => current = None,
                        }
                    }
                    if self.should_flush_for_backpressure() {
                        if let Err(unsubmitted) = self.try_cut_partial(CutReason::Backpressure) {
                            self.terminate(Some(unsubmitted)).await;
                            return;
                        }
                    } else if let Some((batch_id, started_at)) = pending_partial
                        && batch_id == self.received_batches
                        && !self.linger.is_zero()
                        && !self.linger.is_armed()
                        && self.shared.has_partial.load(Ordering::Acquire)
                    {
                        self.linger.arm_from(started_at);
                    }
                }

                _ = self.linger.wait(), if linger_active => {
                    if let Err(unsubmitted) = self.try_cut_partial(CutReason::Linger) {
                        self.terminate(Some(unsubmitted)).await;
                        return;
                    }
                }

                // When `linger == 0`, coalesce any immediately-queued commands above, then submit
                // as soon as no earlier batches are queued without touching the timer wheel.
                // Guarding on `no_earlier_batches` prevents `ready(())` from starving `cmd_rx.recv()`
                // if Tokio's cooperative budget is exhausted mid-burst.
                _ = std::future::ready(()), if self.linger.is_zero() && has_partial && no_earlier_batches => {
                    match self.try_cut_partial(CutReason::ZeroLinger) {
                        Ok(true) => {}
                        Ok(false) => tokio::task::yield_now().await,
                        Err(unsubmitted) => {
                            self.terminate(Some(unsubmitted)).await;
                            return;
                        }
                    }
                }

                // Wake when a caller begins waiting on capacity (`A5a`).
                _ = flush_notified.as_mut() => {
                    flush_notified.set(shared_for_notify.flush_partial_notify.notified());
                    if self.should_flush_for_backpressure() {
                        debug!("flushing partial batch early for backpressure waiter");
                        if let Err(unsubmitted) = self.try_cut_partial(CutReason::Backpressure) {
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
        let (queued_cmds, partial_batch) = {
            let mut gate = self.shared.gate.lock().unwrap();
            self.shared.lifecycle.mark_closing();
            let queued = drain_queued_commands(&mut self.cmd_rx);
            let partial = gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id);
            (queued, partial)
        };
        debug!(ok = session_close_res.is_ok(), "producer closed");
        self.settle_remaining(None, queued_cmds, partial_batch, session_close_res);
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
                    self.shared.abort.reason(),
                    self.shared.context.clone(),
                ))
            }
        };

        debug!(err = %session_failure, "terminating producer on session failure");
        let (queued_cmds, partial_batch) = {
            let mut gate = self.shared.gate.lock().unwrap();
            self.shared
                .lifecycle
                .set_terminal_err(session_failure.clone());
            let queued = drain_queued_commands(&mut self.cmd_rx);
            let partial = gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id);
            (queued, partial)
        };
        self.settle_remaining(
            unsubmitted,
            queued_cmds,
            partial_batch,
            Err(session_failure),
        );
    }

    async fn abort(mut self, reason: &'static str) {
        let aborted = AppendSessionError::Aborted(AbortedError::new_with_context(
            reason,
            self.shared.context.clone(),
        ));
        let (queued_cmds, partial_batch) = {
            let mut gate = self.shared.gate.lock().unwrap();
            let queued = drain_queued_commands(&mut self.cmd_rx);
            let partial = gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id);
            let has_unsubmitted =
                partial.is_some() || queued.iter().any(|cmd| matches!(cmd, Command::Batch(_)));
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
            (queued, partial)
        };

        debug!(
            reason,
            pending_batches = self.pending_batch_acks.len(),
            partial_records = partial_batch.as_ref().map_or(0, |b| b.records.len()),
            "aborting producer"
        );

        // Ensure the owned session is aborted (already cancelled via child token on normal
        // abort/drop/shutdown paths; defensive for the `cmd_rx == None` fallback) and forward its
        // exact outcomes (`A3b`, `A6d`, `A8c`).
        self.session.abort_dropped();
        self.drain_pending_batch_acks().await;
        let session_res = self.session.close().await;

        let has_queued_batches = queued_cmds
            .iter()
            .any(|cmd| matches!(cmd, Command::Batch(_)));
        let has_unsubmitted = partial_batch.is_some() || has_queued_batches;

        let final_result = match session_res {
            Err(session_err) => Err(session_err),
            Ok(()) if has_unsubmitted => Err(aborted),
            Ok(()) => Ok(()),
        };

        self.settle_remaining(None, queued_cmds, partial_batch, final_result);
    }
}

enum Command {
    Batch(ReadyBatch),
    PartialStarted {
        batch_id: u64,
        started_at: Instant,
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
    /// Declared before `outcome_writer` so implicit drop releases bytes before settling tickets.
    permit: Option<AppendPermit>,
    outcome_writer: Option<BatchOutcomeWriter>,
}

fn drain_queued_commands(cmd_rx: &mut mpsc::UnboundedReceiver<Command>) -> Vec<Command> {
    cmd_rx.close();
    let mut queued = Vec::new();
    while let Ok(cmd) = cmd_rx.try_recv() {
        queued.push(cmd);
    }
    queued
}

impl ProducerShared {
    /// Settle queued commands, pending flushes, and any buffered partial batch on abnormal task
    /// drop BEFORE marking `lifecycle` closed so `close()` waiters never observe unsettled tickets
    /// or non-zero unacked counters.
    fn settle_aborted_drop(
        &self,
        pending_flushes: &mut VecDeque<PendingFlush>,
        queued_cmds: Vec<Command>,
        partial_batch: Option<ReadyBatch>,
        err: AppendSessionError,
    ) {
        let acked = self.acked_through_id.load(Ordering::Acquire);
        for flush in pending_flushes.drain(..) {
            let outcome = if acked >= flush.target_id {
                Ok(())
            } else {
                Err(err.clone())
            };
            let _ = flush.done_tx.send(outcome);
        }

        for cmd in queued_cmds {
            match cmd {
                Command::Batch(batch) => {
                    self.fail_unsent_batch(batch, &err);
                }
                Command::Flush { target_id, done_tx } => {
                    let outcome = if acked >= target_id {
                        Ok(())
                    } else {
                        Err(err.clone())
                    };
                    let _ = done_tx.send(outcome);
                }
                Command::PartialStarted { .. } | Command::Close => {}
            }
        }

        if let Some(batch) = partial_batch {
            self.fail_unsent_batch(batch, &err);
        }

        self.lifecycle.finish(Err(err));
    }
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

#[cfg(test)]
mod tests {
    use std::task::{Wake, Waker};

    use super::*;
    use crate::types::StreamPosition;

    struct CountingWake(AtomicUsize);

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn batch_outcome_writer_drop_before_resolve_aborts_tickets() {
        let lifecycle = Arc::new(SessionLifecycle::new());
        let unacked = Arc::new(AtomicUsize::new(1));
        let ctx = ErrorContext::default();
        let (mut writer, outcome) = BatchOutcomeWriter::new(lifecycle, unacked.clone(), ctx);
        writer.record_count = 1;
        let mut ticket = RecordSubmitTicket::new(outcome, 0);

        let counter = Arc::new(CountingWake(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut ticket).poll(&mut cx).is_pending());
        assert!(ticket.try_ack().is_none());

        drop(writer);
        assert_eq!(unacked.load(Ordering::Acquire), 0);
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);

        let res = match Pin::new(&mut ticket).poll(&mut cx) {
            Poll::Ready(res) => res,
            Poll::Pending => panic!("ticket must resolve after writer drop"),
        };
        assert!(matches!(res, Err(AppendSessionError::Aborted(_))));
        assert!(ticket.is_terminated());
        assert!(ticket.try_ack().is_none());
    }

    #[test]
    fn batch_outcome_ticket_reuses_waker_slot_on_repoll() {
        let lifecycle = Arc::new(SessionLifecycle::new());
        let unacked = Arc::new(AtomicUsize::new(3));
        let ctx = ErrorContext::default();
        let (mut writer, outcome) = BatchOutcomeWriter::new(lifecycle, unacked.clone(), ctx);
        writer.record_count = 3;
        let mut ticket = RecordSubmitTicket::new(outcome.clone(), 2);

        let c1 = Arc::new(CountingWake(AtomicUsize::new(0)));
        let w1 = Waker::from(c1.clone());
        assert!(
            Pin::new(&mut ticket)
                .poll(&mut Context::from_waker(&w1))
                .is_pending()
        );

        let c2 = Arc::new(CountingWake(AtomicUsize::new(0)));
        let w2 = Waker::from(c2.clone());
        assert!(
            Pin::new(&mut ticket)
                .poll(&mut Context::from_waker(&w2))
                .is_pending()
        );
        assert_eq!(outcome.waiters.lock().unwrap().as_ref().unwrap().len(), 1);

        let ack = AppendAck {
            start: StreamPosition {
                seq_num: 10,
                timestamp: 1,
            },
            end: StreamPosition {
                seq_num: 13,
                timestamp: 2,
            },
            tail: StreamPosition {
                seq_num: 13,
                timestamp: 2,
            },
        };
        writer.resolve(Ok(ack.clone()));
        assert_eq!(unacked.load(Ordering::Acquire), 0);
        assert_eq!(c1.0.load(Ordering::SeqCst), 0);
        assert_eq!(c2.0.load(Ordering::SeqCst), 1);

        let rec_ack = ticket.try_ack().expect("resolved").expect("ok");
        assert_eq!(rec_ack.seq_num, 12);
        assert_eq!(rec_ack.batch, ack);
    }

    #[test]
    fn producer_settle_aborted_drop_fails_queued_and_partial_batches_before_closing() {
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let permits = AppendPermits::new(None, 1024);
        let lifecycle = Arc::new(SessionLifecycle::new());
        let session_lifecycle = Arc::new(SessionLifecycle::new());
        let abort = SessionAbort::new(
            tokio_util::sync::CancellationToken::new(),
            EXPLICIT_ABORT_MSG,
            DROPPED_ABORT_MSG,
        );
        let shared = Arc::new(ProducerShared {
            basin: "test-basin".parse().unwrap(),
            stream: "s".parse().unwrap(),
            gate: StdMutex::new(ProducerGate {
                match_seq: MatchSeqState::from_option(None),
                last_accepted_id: 0,
                next_batch_id: 0,
                partial: PartialBatch::new(10, 1024),
            }),
            recycled_records: StdMutex::new(Vec::new()),
            cmd_tx,
            permits,
            max_batch_bytes: 1024,
            fencing_token_len: 0,
            match_seq_exhausted: AtomicBool::new(false),
            has_partial: AtomicBool::new(false),
            next_batch_id: AtomicU64::new(0),
            unacked_records: Arc::new(AtomicUsize::new(0)),
            acked_through_id: AtomicU64::new(0),
            lifecycle,
            session_lifecycle,
            abort,
            flush_partial_notify: Notify::new(),
            context: ErrorContext::default(),
        });

        let rec = AppendRecord::new("hello").unwrap();
        let bytes = rec.metered_bytes();
        let permit = shared.permits.try_acquire(bytes).unwrap();
        let mut ticket = shared.submit_with_permit(permit, rec, bytes).unwrap();
        assert_eq!(shared.unacked_records.load(Ordering::Acquire), 1);
        assert_eq!(shared.permits.in_flight_bytes(), bytes);

        let aborted = AppendSessionError::Aborted(AbortedError::new_with_context(
            DROPPED_ABORT_MSG,
            shared.context.clone(),
        ));
        let (queued, partial) = {
            let mut gate = shared.gate.lock().unwrap();
            shared.lifecycle.set_terminal_err(aborted.clone());
            let queued = drain_queued_commands(&mut cmd_rx);
            let partial = gate.take_partial(&shared.has_partial, &shared.next_batch_id);
            (queued, partial)
        };
        let mut pending_flushes = VecDeque::new();
        shared.settle_aborted_drop(&mut pending_flushes, queued, partial, aborted);

        assert!(shared.lifecycle.is_closed());
        assert_eq!(shared.unacked_records.load(Ordering::Acquire), 0);
        assert_eq!(shared.permits.in_flight_bytes(), 0);
        assert!(!shared.has_partial.load(Ordering::Acquire));
        let err = ticket
            .try_ack()
            .expect("partial batch ticket must be resolved on task drop")
            .unwrap_err();
        assert!(matches!(err, AppendSessionError::Aborted(_)));
    }

    #[test]
    fn dropped_ticket_clears_waker_slot_without_shifting_siblings() {
        let lifecycle = Arc::new(SessionLifecycle::new());
        let unacked = Arc::new(AtomicUsize::new(2));
        let ctx = ErrorContext::default();
        let (mut writer, outcome) = BatchOutcomeWriter::new(lifecycle, unacked, ctx);
        writer.record_count = 2;
        let mut t0 = RecordSubmitTicket::new(outcome.clone(), 0);
        let mut t1 = RecordSubmitTicket::new(outcome.clone(), 1);

        let c0 = Arc::new(CountingWake(AtomicUsize::new(0)));
        let c1 = Arc::new(CountingWake(AtomicUsize::new(0)));
        {
            let w0 = Waker::from(c0.clone());
            let w1 = Waker::from(c1.clone());
            assert!(
                Pin::new(&mut t0)
                    .poll(&mut Context::from_waker(&w0))
                    .is_pending()
            );
            assert!(
                Pin::new(&mut t1)
                    .poll(&mut Context::from_waker(&w1))
                    .is_pending()
            );
        }
        assert_eq!(Arc::strong_count(&c0), 2);
        assert_eq!(Arc::strong_count(&c1), 2);

        // Dropping pending t0 releases its waker immediately without disturbing t1's slot.
        drop(t0);
        assert_eq!(Arc::strong_count(&c0), 1);
        assert_eq!(Arc::strong_count(&c1), 2);

        let ack = AppendAck {
            start: StreamPosition {
                seq_num: 5,
                timestamp: 1,
            },
            end: StreamPosition {
                seq_num: 7,
                timestamp: 2,
            },
            tail: StreamPosition {
                seq_num: 7,
                timestamp: 2,
            },
        };
        writer.resolve(Ok(ack.clone()));
        assert_eq!(c0.0.load(Ordering::SeqCst), 0);
        assert_eq!(c1.0.load(Ordering::SeqCst), 1);
        assert_eq!(t1.try_ack().unwrap().unwrap().seq_num, 6);
    }

    #[test]
    fn reentrant_waker_drop_of_sibling_ticket_does_not_deadlock() {
        struct SiblingOwnerWake {
            dropped: Arc<AtomicUsize>,
            sibling: StdMutex<Option<RecordSubmitTicket>>,
        }
        impl Wake for SiblingOwnerWake {
            fn wake(self: Arc<Self>) {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
        impl Drop for SiblingOwnerWake {
            fn drop(&mut self) {
                drop(self.sibling.lock().unwrap().take());
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }

        let lifecycle = Arc::new(SessionLifecycle::new());
        let unacked = Arc::new(AtomicUsize::new(3));
        let ctx = ErrorContext::default();
        let (mut writer, outcome) = BatchOutcomeWriter::new(lifecycle, unacked, ctx);
        writer.record_count = 3;

        let mut t0 = RecordSubmitTicket::new(outcome.clone(), 0);
        let mut t1 = RecordSubmitTicket::new(outcome.clone(), 1);
        let mut t2 = RecordSubmitTicket::new(outcome.clone(), 2);

        let dummy_wake = Arc::new(CountingWake(AtomicUsize::new(0)));
        let dummy_waker = Waker::from(dummy_wake.clone());
        assert!(
            Pin::new(&mut t1)
                .poll(&mut Context::from_waker(&dummy_waker))
                .is_pending()
        );
        assert!(
            Pin::new(&mut t2)
                .poll(&mut Context::from_waker(&dummy_waker))
                .is_pending()
        );

        let dropped = Arc::new(AtomicUsize::new(0));
        // 1. Replacing t0's waker during `poll()` drops the previous waker (which drops sibling t1)
        //    outside the `waiters` mutex without deadlocking.
        {
            let owner = Arc::new(SiblingOwnerWake {
                dropped: dropped.clone(),
                sibling: StdMutex::new(Some(t1)),
            });
            let w0 = Waker::from(owner);
            assert!(
                Pin::new(&mut t0)
                    .poll(&mut Context::from_waker(&w0))
                    .is_pending()
            );
        }
        assert!(
            Pin::new(&mut t0)
                .poll(&mut Context::from_waker(&dummy_waker))
                .is_pending()
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 1);

        // 2. Dropping t0 clears its slot and drops the stored waker (which drops sibling t2)
        //    outside the `waiters` mutex without deadlocking.
        {
            let owner = Arc::new(SiblingOwnerWake {
                dropped: dropped.clone(),
                sibling: StdMutex::new(Some(t2)),
            });
            let w0 = Waker::from(owner);
            assert!(
                Pin::new(&mut t0)
                    .poll(&mut Context::from_waker(&w0))
                    .is_pending()
            );
        }
        drop(t0);
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        drop(writer);
    }
}
