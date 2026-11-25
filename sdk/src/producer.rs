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
        AppendPermit, AppendPermits, AppendSessionCore, BatchSubmitTicket, LifecycleWake,
        SessionAbort, SessionLifecycle, StreamHeaders, send_oneshot_isolated,
        validate_max_unacked_bytes, validate_reserve_bytes,
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
        let waiters = self
            .waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(waiters) = waiters {
            for waker in waiters.into_iter().flatten() {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    waker.wake();
                }));
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

    /// Decrement `unacked_records` for this batch at most once. Called before publishing
    /// `acked_through_id` so concurrent `flush()` callers cannot observe stale `unacked_records()`.
    fn release_unacked(&mut self) {
        let count = std::mem::take(&mut self.record_count);
        if count > 0 {
            self.unacked_records.fetch_sub(count, Ordering::Release);
        }
    }

    fn resolve(mut self, result: Result<AppendAck, AppendSessionError>) {
        self.resolved = true;
        self.release_unacked();
        self.outcome.resolve(result);
    }
}

impl Drop for BatchOutcomeWriter {
    fn drop(&mut self) {
        if !self.resolved {
            self.resolved = true;
            self.release_unacked();
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
        // Fast path when re-polling an already-registered slot: avoid cloning if `will_wake`
        // (pointer/vtable check only). Any `Waker::clone` or displaced-waker drop happens strictly
        // outside `outcome.waiters` so custom waker hooks cannot re-enter the lock and deadlock.
        if let Some(idx) = this.waker_slot {
            let waiters = this.outcome.waiters.lock().unwrap();
            match waiters.as_ref() {
                Some(list) if list[idx].as_ref().is_some_and(|w| w.will_wake(cx.waker())) => {
                    return Poll::Pending;
                }
                Some(_) => {}
                None => {
                    drop(waiters);
                    let res = this
                        .outcome
                        .result
                        .get()
                        .expect("result stored before waiters closed");
                    this.done = true;
                    return Poll::Ready(map_record_outcome(res, this.offset));
                }
            }
        }

        let mut leftover = Some(cx.waker().clone());
        {
            let mut waiters = this.outcome.waiters.lock().unwrap();
            if let Some(list) = waiters.as_mut() {
                match this.waker_slot {
                    Some(idx) => {
                        let slot = &mut list[idx];
                        if !slot.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                            leftover = slot.replace(leftover.take().expect("candidate waker"));
                        }
                    }
                    None => {
                        this.waker_slot = Some(list.len());
                        list.push(leftover.take());
                    }
                }
                drop(waiters);
                drop(leftover);
                return Poll::Pending;
            }
        }
        drop(leftover);
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
            let now = shared.owner_now();
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
    linger_duration: Duration,
    /// Owning Tokio runtime of `ProducerTask` so linger timestamps and expiration checks under
    /// `gate` always use the producer driver's clock rather than a caller's clock.
    owner_handle: Option<tokio::runtime::Handle>,
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

fn drop_records_isolated(mut records: Vec<AppendRecord>) {
    while let Some(record) = records.pop() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            drop(record);
        }));
    }
}

impl ProducerShared {
    fn owner_now(&self) -> Instant {
        crate::session::try_now_on_runtime(self.owner_handle.as_ref()).unwrap_or_else(Instant::now)
    }

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
        // Isolate each record's destructor so a panicking `Bytes::from_owner` payload cannot abort
        // `ProducerTask` or leak subsequent records.
        while let Some(record) = records.pop() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                drop(record);
            }));
        }
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
        drop(permit);
        outcome_writer.resolve(Err(err.clone()));
        // Isolate payload destruction AFTER settling tickets so a panicking `Bytes::from_owner`
        // destructor can never skip settling remaining batches or `lifecycle.finish`.
        drop_records_isolated(records);
    }

    fn submit_with_permit(
        &self,
        append_permit: AppendPermit,
        record: AppendRecord,
        metered: usize,
    ) -> Result<RecordSubmitTicket, AppendSessionError> {
        let mut unsent_to_fail: Option<(ReadyBatch, AppendSessionError)> = None;
        let result = {
            let mut gate = self.gate.lock().unwrap();
            if let Err(e) = gate.match_seq.check_available() {
                drop(gate);
                drop(append_permit);
                return Err(self.context.format_validation(e).into());
            }
            let has_unacked_work =
                gate.last_accepted_id > self.acked_through_id.load(Ordering::Acquire);
            if self.is_closing_or_closed() || self.abort.is_cancelled() || self.cmd_tx.is_closed() {
                drop(gate);
                drop(append_permit);
                return Err(self.session_closed_err(has_unacked_work));
            }

            let match_seq_num = match gate.match_seq.claim_next() {
                Ok(n) => n,
                Err(e) => {
                    drop(gate);
                    drop(append_permit);
                    return Err(self.context.format_validation(e).into());
                }
            };
            if gate.match_seq.is_exhausted() {
                self.match_seq_exhausted.store(true, Ordering::Release);
            }

            let partial_expired = !self.linger_duration.is_zero()
                && gate.partial.started_at.is_some_and(|started_at| {
                    started_at
                        .checked_add(self.linger_duration)
                        .is_some_and(|deadline| self.owner_now() >= deadline)
                });

            if !gate.partial.is_empty()
                && (gate.partial.would_overflow(metered) || partial_expired)
                && let Some(cut_batch) = gate.take_partial(&self.has_partial, &self.next_batch_id)
                && let Err(mpsc::error::SendError(Command::Batch(unsent))) =
                    self.cmd_tx.send(Command::Batch(cut_batch))
            {
                let err = self.session_closed_err(true);
                unsent_to_fail = Some((unsent, err.clone()));
                Err(err)
            } else {
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
                        unsent_to_fail = Some((unsent, err.clone()));
                        Err(err)
                    } else {
                        Ok(RecordSubmitTicket::new(outcome, offset))
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
                        && let Some(unsent) =
                            gate.take_partial(&self.has_partial, &self.next_batch_id)
                    {
                        let err = self.session_closed_err(true);
                        unsent_to_fail = Some((unsent, err.clone()));
                        Err(err)
                    } else {
                        Ok(RecordSubmitTicket::new(outcome, offset))
                    }
                } else {
                    Ok(RecordSubmitTicket::new(outcome, offset))
                }
            }
        };
        // Fail any detached batch strictly AFTER releasing `self.gate` so permit release and
        // ticket waking cannot re-enter `self.gate` and deadlock.
        if let Some((unsent, err)) = unsent_to_fail {
            self.fail_unsent_batch(unsent, &err);
        }
        result
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
            linger_duration: config.linger,
            owner_handle: tokio::runtime::Handle::try_current().ok(),
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
        let mut unsent_to_fail: Option<(ReadyBatch, AppendSessionError)> = None;
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
            } else if let Some(batch) =
                gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id)
                && let Err(mpsc::error::SendError(Command::Batch(unsent))) =
                    self.shared.cmd_tx.send(Command::Batch(batch))
            {
                let err = self.shared.session_closed_err(true);
                unsent_to_fail = Some((unsent, err));
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
        if let Some((unsent, err)) = unsent_to_fail {
            self.shared.fail_unsent_batch(unsent, &err);
        }

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
        let mut unsent_to_fail: Option<(ReadyBatch, AppendSessionError)> = None;
        let wake = {
            let mut gate = self.shared.gate.lock().unwrap();
            if !self.shared.abort.is_cancelled() {
                let (marked, wake) = self.shared.lifecycle.mark_closing();
                if marked {
                    if let Some(batch) =
                        gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id)
                        && let Err(mpsc::error::SendError(Command::Batch(unsent))) =
                            self.shared.cmd_tx.send(Command::Batch(batch))
                    {
                        let err = self.shared.session_closed_err(true);
                        unsent_to_fail = Some((unsent, err));
                    }
                    let _ = self.shared.cmd_tx.send(Command::Close);
                }
                wake
            } else {
                LifecycleWake::NONE
            }
        };
        wake.fire();
        if let Some((unsent, err)) = unsent_to_fail {
            self.shared.fail_unsent_batch(unsent, &err);
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
    submit_err: Box<AppendSessionError>,
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
    /// Unsubmitted batches detached during `terminate()` or `abort()` and kept on `self` across
    /// `.await` points so abnormal cancellation still settles them via `settle_remaining` with
    /// `SessionClosed(Some(failure))` (`A6a`, `A8c`).
    detached_unsubmitted: Option<UnsubmittedBatch>,
    detached_queued: Vec<Command>,
    detached_partial: Option<ReadyBatch>,
}

impl Drop for ProducerTask {
    fn drop(&mut self) {
        if self.shared.lifecycle.is_closed() {
            return;
        }
        let explicit_abort = self.shared.abort.is_cancelled();
        let reason = if explicit_abort {
            self.shared.abort.reason()
        } else {
            DROPPED_ABORT_MSG
        };
        let aborted = AppendSessionError::Aborted(AbortedError::new_with_context(
            reason,
            self.shared.context.clone(),
        ));
        let unsubmitted = self.detached_unsubmitted.take();
        let (queued_cmds, partial_batch, has_unsubmitted, existing_err, wake) = {
            let mut gate = self
                .shared
                .gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.shared.gate.clear_poison();
            let mut queued = std::mem::take(&mut self.detached_queued);
            queued.extend(drain_queued_commands(&mut self.cmd_rx));
            let mut partial = self.detached_partial.take();
            if let Some(extra_partial) =
                gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id)
            {
                if partial.is_none() {
                    partial = Some(extra_partial);
                } else {
                    queued.push(Command::Batch(extra_partial));
                }
            }
            let has_unsubmitted = unsubmitted.is_some()
                || partial.is_some()
                || queued.iter().any(|cmd| matches!(cmd, Command::Batch(_)));
            let existing_err = self
                .shared
                .lifecycle
                .terminal_err()
                .or_else(|| self.session.terminal_err());
            let wake = if let Some(err) = existing_err.as_ref() {
                self.shared.lifecycle.set_terminal_err(err.clone())
            } else if has_unsubmitted || !explicit_abort {
                self.shared.lifecycle.set_terminal_err(aborted.clone())
            } else if self.pending_batch_acks.is_empty() {
                self.shared.lifecycle.mark_closing().1
            } else {
                LifecycleWake::NONE
            };
            (queued, partial, has_unsubmitted, existing_err, wake)
        };
        wake.fire();

        // Drain any durable outcomes already delivered by the owned append session strictly in
        // FIFO submission order before aborting or falling back (`A6d`, `A7`).
        #[derive(Default)]
        struct DropErrors {
            saw_batch_err: bool,
            first_non_closed: Option<AppendSessionError>,
            first_closed_cause: Option<AppendSessionError>,
        }
        impl DropErrors {
            fn record(&mut self, err: &AppendSessionError) {
                self.saw_batch_err = true;
                match err {
                    AppendSessionError::SessionClosed(closed) => {
                        if self.first_closed_cause.is_none()
                            && let Some(cause) = closed.failure()
                        {
                            self.first_closed_cause = Some(cause.clone());
                        }
                    }
                    other => {
                        if self.first_non_closed.is_none() {
                            self.first_non_closed = Some(other.clone());
                        }
                    }
                }
            }
        }
        let mut errors = DropErrors::default();

        while let Some(front) = self.pending_batch_acks.front_mut() {
            let Some(batch_ack) = front.ticket.try_ack() else {
                break;
            };
            let mut pending = self.pending_batch_acks.pop_front().expect("checked front");
            if let Err(err) = &batch_ack {
                errors.record(err);
            }
            let permit = pending.permit.take().expect("permit should not be None");
            let writer = pending
                .outcome_writer
                .take()
                .expect("outcome_writer should not be None");
            self.settle_batch_ack(
                batch_ack,
                pending.batch_max_id,
                writer,
                permit,
                !errors.saw_batch_err,
            );
        }

        // Stop the owned append session and synchronously freeze its wire-send watermark so any
        // unresolved batch with `submit_seq >= sent_watermark` is provably unsent (`A6a`, `A8c`),
        // regardless of whether `ProducerTask` or `AppendSessionTask` drops first on shutdown.
        self.session.abort_dropped();
        let sent_watermark = self.session.freeze_sent_watermark();

        // Snapshot remaining ticket outcomes newest-to-oldest BEFORE settling in FIFO order.
        // Because `AppendSessionTask` settles strictly in submission order, reverse polling
        // guarantees the resolved set is always a contiguous prefix and cannot invert batch k
        // (fallback) before batch k+1 (`Ok`) (`A6a`, `A6d`, `A10c`).
        let mut snapshot: Vec<_> = self
            .pending_batch_acks
            .iter_mut()
            .rev()
            .map(|p| p.ticket.try_ack())
            .collect();

        // Read the session's terminal classification and terminal error AFTER the reverse snapshot
        // so any concurrent `settle_terminal_error` that raced with the snapshot provides exact
        // per-batch classifications (`A6a`, `A6b`, `A9`).
        let terminal = self.session.terminal_classification();
        let session_err_now = terminal
            .as_ref()
            .map(|t| t.session_failure.clone())
            .or_else(|| self.session.terminal_err());

        let session_fallback_err = session_err_now
            .clone()
            .or_else(|| existing_err.clone())
            .or_else(|| errors.first_non_closed.clone())
            .or_else(|| errors.first_closed_cause.clone())
            .unwrap_or_else(|| aborted.clone());
        let unsent_fallback_err =
            AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
                Some(session_fallback_err.clone()),
                self.shared.context.clone(),
            ));

        let mut had_unresolved_pending = false;
        while let Some(mut pending) = self.pending_batch_acks.pop_front() {
            let batch_ack = match snapshot.pop().expect("one snapshot per pending batch") {
                Some(res) => {
                    if let Err(err) = &res {
                        errors.record(err);
                    }
                    res
                }
                None => {
                    had_unresolved_pending = true;
                    if let Some(ref t) = terminal {
                        Err(t.outcome_for(pending.ticket.submit_seq(), &self.shared.context))
                    } else if pending.ticket.submit_seq() < sent_watermark {
                        Err(session_fallback_err.clone())
                    } else {
                        Err(unsent_fallback_err.clone())
                    }
                }
            };
            let permit = pending.permit.take().expect("permit should not be None");
            let writer = pending
                .outcome_writer
                .take()
                .expect("outcome_writer should not be None");
            // Once any earlier batch fell back or failed, do not advance `acked_through_id` or
            // resolve covered flushes even if a later batch concurrently received `Ok` (`A7`,
            // `A10c`), while still forwarding the session's reported outcome to its tickets
            // (`A6d`).
            let publish_progress = !had_unresolved_pending && !errors.saw_batch_err;
            self.settle_batch_ack(
                batch_ack,
                pending.batch_max_id,
                writer,
                permit,
                publish_progress,
            );
        }

        let non_closed_unsub_err = unsubmitted.as_ref().and_then(|u| {
            (!matches!(u.submit_err.as_ref(), AppendSessionError::SessionClosed(_)))
                .then(|| (*u.submit_err).clone())
        });

        // Producer `close()` and `flush()` report the owned session's terminal failure (`A9`),
        // never promoting a per-batch `SessionClosedError` above it.
        let final_result = if let Some(err) = session_err_now
            .or(existing_err)
            .or(non_closed_unsub_err)
            .or(errors.first_non_closed)
            .or(errors.first_closed_cause)
        {
            Err(err)
        } else if has_unsubmitted
            || had_unresolved_pending
            || errors.saw_batch_err
            || !explicit_abort
        {
            Err(aborted)
        } else {
            // A8c: explicitly aborting an idle producer (with all prior batches durably acked)
            // loses nothing, so the close is clean.
            Ok(())
        };

        self.settle_remaining(unsubmitted, queued_cmds, partial_batch, final_result);
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
            detached_unsubmitted: None,
            detached_queued: Vec::new(),
            detached_partial: None,
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
        // Register the batch ticket/writer BEFORE recycling `records` so a panicking
        // `Bytes::from_owner` payload destructor can never lose the ticket or misclassify it.
        let outcome = match res {
            Ok(ticket) => {
                self.pending_batch_acks.push_back(PendingBatchAck {
                    ticket,
                    batch_max_id: max_acceptance_id,
                    permit: Some(permit),
                    outcome_writer: Some(outcome_writer),
                });
                Ok(())
            }
            Err(submit_err) => Err(UnsubmittedBatch {
                _permit: permit,
                outcome_writer,
                submit_err: Box::new(submit_err),
            }),
        };
        self.shared.recycle_records(records);
        outcome
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
        let wake = {
            let _gate = self.shared.gate.lock().unwrap();
            if let Some(err) = self.session.terminal_err() {
                self.shared.lifecycle.set_terminal_err(err)
            } else if has_unsubmitted && self.shared.abort.is_cancelled() {
                self.shared
                    .lifecycle
                    .set_terminal_err(AppendSessionError::Aborted(AbortedError::new_with_context(
                        self.shared.abort.reason(),
                        self.shared.context.clone(),
                    )))
            } else if !self.shared.abort.is_cancelled() {
                self.shared.lifecycle.mark_closing().1
            } else {
                LifecycleWake::NONE
            }
        };
        wake.fire();
    }

    fn settle_batch_ack(
        &mut self,
        batch_ack: Result<AppendAck, AppendSessionError>,
        batch_max_id: u64,
        mut outcome_writer: BatchOutcomeWriter,
        batch_permit: AppendPermit,
        publish_progress: bool,
    ) {
        let ok = batch_ack.is_ok();
        // Release permit and decrement `unacked_records` BEFORE publishing `acked_through_id` or
        // waking tickets/flushes so callers checking `unacked_bytes()` / `unacked_records()` /
        // `acked_records()` immediately after `ticket.await` or `flush().await` observe settled
        // counts without racing (`A10`).
        drop(batch_permit);
        outcome_writer.release_unacked();
        if ok && publish_progress {
            self.shared
                .acked_through_id
                .store(batch_max_id, Ordering::Release);
        }
        outcome_writer.resolve(batch_ack);
        if ok && publish_progress {
            resolve_satisfied_flushes(&mut self.pending_flushes, batch_max_id);
        }
    }

    async fn drain_pending_batch_acks(&mut self) {
        // Keep the front entry in `pending_batch_acks` across `.await` so if this future is
        // cancelled mid-wait, `ProducerTask::drop` can still observe any already-delivered ack.
        while let Some(front) = self.pending_batch_acks.front_mut() {
            let batch_ack = (&mut front.ticket).await;
            let mut pending = self
                .pending_batch_acks
                .pop_front()
                .expect("pending_batch_acks non-empty");
            let outcome_writer = pending
                .outcome_writer
                .take()
                .expect("outcome_writer should not be None");
            let permit = pending.permit.take().expect("permit should not be None");
            self.settle_batch_ack(
                batch_ack,
                pending.batch_max_id,
                outcome_writer,
                permit,
                true,
            );
        }
    }

    fn settle_remaining(
        &mut self,
        unsubmitted: Option<UnsubmittedBatch>,
        queued_cmds: Vec<Command>,
        partial_batch: Option<ReadyBatch>,
        final_result: Result<(), AppendSessionError>,
    ) {
        let wake = if let Err(err) = &final_result {
            self.shared.lifecycle.set_terminal_err(err.clone())
        } else {
            self.shared.lifecycle.mark_closing().1
        };
        wake.fire();

        let unsent_err = AppendSessionError::SessionClosed(SessionClosedError::new_with_context(
            final_result.as_ref().err().cloned(),
            self.shared.context.clone(),
        ));

        if let Some(UnsubmittedBatch {
            _permit,
            outcome_writer,
            submit_err,
        }) = unsubmitted
        {
            drop(_permit);
            let batch_err = if matches!(submit_err.as_ref(), AppendSessionError::SessionClosed(_)) {
                unsent_err.clone()
            } else {
                *submit_err
            };
            outcome_writer.resolve(Err(batch_err));
        }

        let acked = self.shared.acked_through_id.load(Ordering::Acquire);
        for flush in self.pending_flushes.drain(..) {
            let outcome = if acked >= flush.target_id {
                Ok(())
            } else {
                final_result.clone()
            };
            send_oneshot_isolated(flush.done_tx, outcome);
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
                    send_oneshot_isolated(done_tx, outcome);
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
                            true,
                        );
                        self.terminate(None).await;
                        return;
                    }
                    self.settle_batch_ack(
                        batch_ack,
                        pending.batch_max_id,
                        outcome_writer,
                        batch_permit,
                        true,
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
                                    send_oneshot_isolated(done_tx, Ok(()));
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
        let (queued_cmds, partial_batch, wake) = {
            let mut gate = self.shared.gate.lock().unwrap();
            let (_, wake) = self.shared.lifecycle.mark_closing();
            let queued = drain_queued_commands(&mut self.cmd_rx);
            let partial = gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id);
            (queued, partial, wake)
        };
        wake.fire();
        debug!(ok = session_close_res.is_ok(), "producer closed");
        self.settle_remaining(None, queued_cmds, partial_batch, session_close_res);
    }

    /// Settle all remaining batches using exact outcomes from the owned append session
    /// (`A6d`, `A9`), then fail any records still being batched or queued with
    /// `SessionClosedError` (`A6a`).
    async fn terminate(mut self, unsubmitted: Option<UnsubmittedBatch>) {
        // Keep any unsubmitted batch on `self` across `.await` points so abnormal cancellation
        // still settles it with `SessionClosed(Some(failure))` in `ProducerTask::drop`.
        self.detached_unsubmitted = unsubmitted;
        self.publish_closing_from_session(self.detached_unsubmitted.is_some());

        // Drain every remaining batch already submitted to the owned session so every record
        // receives the exact outcome reported by AppendSession strictly in submission order (A6d).
        self.drain_pending_batch_acks().await;

        let session_res = self.session.close().await;

        let non_closed_submit_err = self.detached_unsubmitted.as_ref().and_then(|u| {
            (!matches!(u.submit_err.as_ref(), AppendSessionError::SessionClosed(_)))
                .then(|| (*u.submit_err).clone())
        });

        let (queued_cmds, partial_batch, has_unsubmitted, wake) = {
            let mut gate = self.shared.gate.lock().unwrap();
            let queued = drain_queued_commands(&mut self.cmd_rx);
            let partial = gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id);
            let has_unsubmitted = self.detached_unsubmitted.is_some()
                || partial.is_some()
                || queued.iter().any(|cmd| matches!(cmd, Command::Batch(_)));
            let wake = match &session_res {
                Err(err) => self.shared.lifecycle.set_terminal_err(err.clone()),
                Ok(()) if non_closed_submit_err.is_some() => self
                    .shared
                    .lifecycle
                    .set_terminal_err(non_closed_submit_err.clone().expect("checked is_some")),
                Ok(()) if has_unsubmitted => {
                    self.shared
                        .lifecycle
                        .set_terminal_err(AppendSessionError::Aborted(
                            AbortedError::new_with_context(
                                self.shared.abort.reason(),
                                self.shared.context.clone(),
                            ),
                        ))
                }
                Ok(()) => self.shared.lifecycle.mark_closing().1,
            };
            (queued, partial, has_unsubmitted, wake)
        };
        wake.fire();

        // Obtain the owned session's exact failure (A9). If the owned session closed cleanly on
        // abort (`A8c`), preserve `Ok(())` when this producer also has no unsubmitted work, and
        // fail with `AbortedError` (`E6`) (or the direct submit error if frame encoding failed)
        // only if unsubmitted work was lost.
        let final_result = match session_res {
            Err(err) => Err(err),
            Ok(()) if non_closed_submit_err.is_some() => {
                Err(non_closed_submit_err.expect("checked is_some"))
            }
            Ok(()) if has_unsubmitted => {
                Err(AppendSessionError::Aborted(AbortedError::new_with_context(
                    self.shared.abort.reason(),
                    self.shared.context.clone(),
                )))
            }
            Ok(()) => Ok(()),
        };
        match &final_result {
            Err(err) => debug!(err = %err, "terminating producer on session failure"),
            Ok(()) => debug!("terminating idle producer cleanly after session close"),
        }
        let unsubmitted = self.detached_unsubmitted.take();
        self.settle_remaining(unsubmitted, queued_cmds, partial_batch, final_result);
    }

    async fn abort(mut self, reason: &'static str) {
        let aborted = AppendSessionError::Aborted(AbortedError::new_with_context(
            reason,
            self.shared.context.clone(),
        ));
        let wake = {
            let mut gate = self.shared.gate.lock().unwrap();
            let queued = drain_queued_commands(&mut self.cmd_rx);
            let partial = gate.take_partial(&self.shared.has_partial, &self.shared.next_batch_id);
            let has_unsubmitted =
                partial.is_some() || queued.iter().any(|cmd| matches!(cmd, Command::Batch(_)));
            // Retain detached batches on `self` across `.await` points so abnormal cancellation
            // during drain/close still settles them via `settle_remaining` with
            // `SessionClosed(Some(failure))` (`A6a`, `A8c`).
            self.detached_queued.extend(queued);
            if let Some(batch) = partial {
                if self.detached_partial.is_none() {
                    self.detached_partial = Some(batch);
                } else {
                    self.detached_queued.push(Command::Batch(batch));
                }
            }
            if has_unsubmitted {
                // Publish failure before marking closing so waiting reserve()/submit() calls
                // observe `SessionClosedError { failure: Some(..) }` (`E6`).
                self.shared.lifecycle.set_terminal_err(
                    self.session
                        .terminal_err()
                        .unwrap_or_else(|| aborted.clone()),
                )
            } else if self.pending_batch_acks.is_empty() {
                self.shared.lifecycle.mark_closing().1
            } else {
                LifecycleWake::NONE
            }
        };
        wake.fire();

        debug!(
            reason,
            pending_batches = self.pending_batch_acks.len(),
            partial_records = self
                .detached_partial
                .as_ref()
                .map_or(0, |b| b.records.len()),
            "aborting producer"
        );

        // Ensure the owned session is aborted (already cancelled via child token on normal
        // abort/drop/shutdown paths; defensive for the `cmd_rx == None` fallback) and forward its
        // exact outcomes (`A3b`, `A6d`, `A8c`).
        self.session.abort_dropped();
        self.drain_pending_batch_acks().await;
        let session_res = self.session.close().await;

        let queued_cmds = std::mem::take(&mut self.detached_queued);
        let partial_batch = self.detached_partial.take();
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

fn resolve_satisfied_flushes(pending_flushes: &mut VecDeque<PendingFlush>, acked_through_id: u64) {
    while let Some(front) = pending_flushes.front() {
        if front.target_id <= acked_through_id {
            let flush = pending_flushes.pop_front().expect("checked front");
            send_oneshot_isolated(flush.done_tx, Ok(()));
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
    fn panicking_waker_in_batch_outcome_still_wakes_sibling_tickets() {
        struct PanicWake;
        impl Wake for PanicWake {
            fn wake(self: Arc<Self>) {
                panic!("simulated waker panic");
            }
        }

        let lifecycle = Arc::new(SessionLifecycle::new());
        let unacked = Arc::new(AtomicUsize::new(2));
        let ctx = ErrorContext::default();
        let (mut writer, outcome) = BatchOutcomeWriter::new(lifecycle, unacked.clone(), ctx);
        writer.record_count = 2;

        let mut t0 = RecordSubmitTicket::new(outcome.clone(), 0);
        let mut t1 = RecordSubmitTicket::new(outcome.clone(), 1);

        let w0 = Waker::from(Arc::new(PanicWake));
        let c1 = Arc::new(CountingWake(AtomicUsize::new(0)));
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

        let ack = AppendAck {
            start: StreamPosition {
                seq_num: 1,
                timestamp: 1,
            },
            end: StreamPosition {
                seq_num: 3,
                timestamp: 2,
            },
            tail: StreamPosition {
                seq_num: 3,
                timestamp: 2,
            },
        };
        writer.resolve(Ok(ack));
        assert_eq!(unacked.load(Ordering::Acquire), 0);
        assert_eq!(
            c1.0.load(Ordering::SeqCst),
            1,
            "sibling ticket must still be woken after earlier waker panics"
        );
        assert_eq!(t1.try_ack().unwrap().unwrap().seq_num, 2);
    }

    #[test]
    fn reentrant_waker_clone_dropping_sibling_ticket_does_not_deadlock() {
        use std::task::{RawWaker, RawWakerVTable};

        struct CloneDropsSibling {
            sibling: StdMutex<Option<RecordSubmitTicket>>,
            cloned: AtomicUsize,
        }

        unsafe fn clone_fn(ptr: *const ()) -> RawWaker {
            let state = unsafe { &*(ptr as *const CloneDropsSibling) };
            // Dropping a sibling ticket from inside `Waker::clone` must not deadlock on
            // `BatchOutcome::waiters`.
            drop(state.sibling.lock().unwrap().take());
            state.cloned.fetch_add(1, Ordering::SeqCst);
            let arc = unsafe { Arc::from_raw(ptr as *const CloneDropsSibling) };
            let cloned = arc.clone();
            let _ = Arc::into_raw(arc);
            RawWaker::new(Arc::into_raw(cloned) as *const (), &VTABLE)
        }
        unsafe fn wake_fn(ptr: *const ()) {
            drop(unsafe { Arc::from_raw(ptr as *const CloneDropsSibling) });
        }
        unsafe fn wake_by_ref_fn(_ptr: *const ()) {}
        unsafe fn drop_fn(ptr: *const ()) {
            drop(unsafe { Arc::from_raw(ptr as *const CloneDropsSibling) });
        }
        static VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone_fn, wake_fn, wake_by_ref_fn, drop_fn);

        let lifecycle = Arc::new(SessionLifecycle::new());
        let unacked = Arc::new(AtomicUsize::new(2));
        let ctx = ErrorContext::default();
        let (mut writer, outcome) = BatchOutcomeWriter::new(lifecycle, unacked, ctx);
        writer.record_count = 2;

        let mut t0 = RecordSubmitTicket::new(outcome.clone(), 0);
        let mut t1 = RecordSubmitTicket::new(outcome.clone(), 1);
        let dummy = Waker::from(Arc::new(CountingWake(AtomicUsize::new(0))));
        assert!(
            Pin::new(&mut t1)
                .poll(&mut Context::from_waker(&dummy))
                .is_pending()
        );

        let state = Arc::new(CloneDropsSibling {
            sibling: StdMutex::new(Some(t1)),
            cloned: AtomicUsize::new(0),
        });
        let raw = RawWaker::new(Arc::into_raw(state.clone()) as *const (), &VTABLE);
        let waker = unsafe { Waker::from_raw(raw) };
        assert!(
            Pin::new(&mut t0)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(state.cloned.load(Ordering::SeqCst), 1);
        drop(waker);
        drop(t0);
        drop(writer);
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

    fn test_producer_task_parts() -> (
        ProducerTask,
        Arc<ProducerShared>,
        mpsc::UnboundedSender<Command>,
    ) {
        use crate::{
            api::{BaseClient, BasinClient},
            session::SessionAbort,
            types::{S2Config, S2Endpoints},
        };

        let endpoints = S2Endpoints::for_endpoint("http://localhost:8080").unwrap();
        let cfg = S2Config::new("test-token").with_endpoints(endpoints.clone());
        let base = BaseClient::init(&cfg).unwrap();
        let basin: BasinName = "test-basin".parse().unwrap();
        let stream: StreamName = "test-stream".parse().unwrap();
        let client = BasinClient::init(basin.clone(), &endpoints, base);
        let context = ErrorContext::stream("producer", basin.as_ref(), stream.as_ref(), false);
        let abort = SessionAbort::new(
            client.shutdown_token(),
            EXPLICIT_ABORT_MSG,
            DROPPED_ABORT_MSG,
        );
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let config = ProducerConfig::new();
        let permits = AppendPermits::new(None, config.max_unacked_bytes);
        let gate = StdMutex::new(ProducerGate {
            match_seq: MatchSeqState::from_option(None),
            last_accepted_id: 0,
            next_batch_id: 0,
            partial: PartialBatch::new(config.max_batch_records, config.max_batch_bytes),
        });
        let lifecycle = Arc::new(SessionLifecycle::new());
        let session = AppendSessionCore::new_with_abort(
            client,
            stream.clone(),
            StreamHeaders::default(),
            "producer",
            abort.child(),
        );
        let session_lifecycle = session.lifecycle().clone();
        let shared = Arc::new(ProducerShared {
            basin,
            stream,
            gate,
            recycled_records: StdMutex::new(Vec::new()),
            cmd_tx: cmd_tx.clone(),
            permits,
            max_batch_bytes: config.max_batch_bytes,
            linger_duration: config.linger,
            owner_handle: tokio::runtime::Handle::try_current().ok(),
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
            context,
        });
        let task = ProducerTask::new(shared.clone(), session, config, cmd_rx);
        (task, shared, cmd_tx)
    }

    #[tokio::test]
    async fn producer_task_drop_does_not_publish_later_ok_after_earlier_fallback() {
        let (mut task, shared, _cmd_tx) = test_producer_task_parts();

        // Batch 0: unresolved oneshot (will fall back on ProducerTask::drop).
        let (tx0, rx0) = oneshot::channel();
        let _keep_tx0_open = tx0;
        let p0 = shared.permits.try_acquire(16).unwrap();
        let (mut w0, o0) = BatchOutcomeWriter::new(
            shared.lifecycle.clone(),
            shared.unacked_records.clone(),
            shared.context.clone(),
        );
        w0.record_count = 1;
        shared.unacked_records.fetch_add(1, Ordering::Release);
        let mut rt0 = RecordSubmitTicket::new(o0, 0);

        // Batch 1: already-delivered Ok(ack) on its oneshot.
        let (tx1, rx1) = oneshot::channel();
        let ack1 = AppendAck {
            start: StreamPosition {
                seq_num: 1,
                timestamp: 10,
            },
            end: StreamPosition {
                seq_num: 2,
                timestamp: 10,
            },
            tail: StreamPosition {
                seq_num: 2,
                timestamp: 10,
            },
        };
        tx1.send(Ok(ack1.clone())).unwrap();
        let p1 = shared.permits.try_acquire(16).unwrap();
        let (mut w1, o1) = BatchOutcomeWriter::new(
            shared.lifecycle.clone(),
            shared.unacked_records.clone(),
            shared.context.clone(),
        );
        w1.record_count = 1;
        shared.unacked_records.fetch_add(1, Ordering::Release);
        let mut rt1 = RecordSubmitTicket::new(o1, 0);

        task.pending_batch_acks.push_back(PendingBatchAck {
            ticket: BatchSubmitTicket::for_test(
                rx0,
                0,
                shared.session_lifecycle.clone(),
                shared.context.clone(),
            ),
            batch_max_id: 1,
            permit: Some(p0),
            outcome_writer: Some(w0),
        });
        task.pending_batch_acks.push_back(PendingBatchAck {
            ticket: BatchSubmitTicket::for_test(
                rx1,
                1,
                shared.session_lifecycle.clone(),
                shared.context.clone(),
            ),
            batch_max_id: 2,
            permit: Some(p1),
            outcome_writer: Some(w1),
        });

        let (f0_tx, f0_rx) = oneshot::channel();
        let (f1_tx, f1_rx) = oneshot::channel();
        task.pending_flushes.push_back(PendingFlush {
            target_id: 1,
            done_tx: f0_tx,
        });
        task.pending_flushes.push_back(PendingFlush {
            target_id: 2,
            done_tx: f1_tx,
        });

        drop(task);

        // Batch 0 failed, so acked_through_id must remain 0 and both flushes covering batch 0 must
        // fail, while batch 1's ticket still receives the session's durable Ok(ack1).
        assert_eq!(shared.acked_through_id.load(Ordering::Acquire), 0);
        assert_eq!(shared.unacked_records.load(Ordering::Acquire), 0);
        assert!(rt0.try_ack().unwrap().is_err());
        assert_eq!(rt1.try_ack().unwrap().unwrap().batch, ack1);
        assert!(f0_rx.await.unwrap().is_err());
        assert!(f1_rx.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn producer_abort_and_terminate_cancellation_preserve_unsent_classification() {
        // 1. Cancellation mid-`abort()` while draining an in-flight batch must settle detached
        //    partial and queued batches with `SessionClosed(Some(Aborted))`.
        let (mut task, shared, cmd_tx) = test_producer_task_parts();
        let (tx_inflight, rx_inflight) = oneshot::channel();
        let _hold = tx_inflight;
        let p_in = shared.permits.try_acquire(16).unwrap();
        let (mut w_in, o_in) = BatchOutcomeWriter::new(
            shared.lifecycle.clone(),
            shared.unacked_records.clone(),
            shared.context.clone(),
        );
        w_in.record_count = 1;
        shared.unacked_records.fetch_add(1, Ordering::Release);
        let _t_in = RecordSubmitTicket::new(o_in, 0);
        task.pending_batch_acks.push_back(PendingBatchAck {
            ticket: BatchSubmitTicket::for_test(
                rx_inflight,
                0,
                shared.session_lifecycle.clone(),
                shared.context.clone(),
            ),
            batch_max_id: 1,
            permit: Some(p_in),
            outcome_writer: Some(w_in),
        });

        let p_part = shared.permits.try_acquire(16).unwrap();
        let t_part = shared
            .submit_with_permit(p_part, AppendRecord::new("lingering").unwrap(), 16)
            .unwrap();
        shared.abort.cancel_explicit();

        let mut abort_fut = Box::pin(task.abort(EXPLICIT_ABORT_MSG));
        let noop = Waker::from(Arc::new(CountingWake(AtomicUsize::new(0))));
        assert!(
            abort_fut
                .as_mut()
                .poll(&mut Context::from_waker(&noop))
                .is_pending()
        );
        drop(abort_fut);
        drop(cmd_tx);

        let err_part = t_part.await.unwrap_err();
        assert!(
            matches!(
                err_part,
                AppendSessionError::SessionClosed(ref sc)
                    if matches!(sc.failure(), Some(AppendSessionError::Aborted(_)))
            ),
            "detached partial batch must stay SessionClosed(Some(Aborted)), got: {err_part:?}"
        );
        assert!(err_part.has_no_side_effects());
        assert_eq!(shared.unacked_records.load(Ordering::Acquire), 0);

        // 2. Cancellation mid-`terminate(Some(unsubmitted))` preserves `SessionClosed` too.
        let (mut task2, shared2, _cmd_tx2) = test_producer_task_parts();
        let (tx_in2, rx_in2) = oneshot::channel();
        let _hold2 = tx_in2;
        let p_in2 = shared2.permits.try_acquire(16).unwrap();
        let (mut w_in2, o_in2) = BatchOutcomeWriter::new(
            shared2.lifecycle.clone(),
            shared2.unacked_records.clone(),
            shared2.context.clone(),
        );
        w_in2.record_count = 1;
        shared2.unacked_records.fetch_add(1, Ordering::Release);
        let _t_in2 = RecordSubmitTicket::new(o_in2, 0);
        task2.pending_batch_acks.push_back(PendingBatchAck {
            ticket: BatchSubmitTicket::for_test(
                rx_in2,
                0,
                shared2.session_lifecycle.clone(),
                shared2.context.clone(),
            ),
            batch_max_id: 1,
            permit: Some(p_in2),
            outcome_writer: Some(w_in2),
        });

        let p_unsub = shared2.permits.try_acquire(16).unwrap();
        let (mut w_unsub, o_unsub) = BatchOutcomeWriter::new(
            shared2.lifecycle.clone(),
            shared2.unacked_records.clone(),
            shared2.context.clone(),
        );
        w_unsub.record_count = 1;
        shared2.unacked_records.fetch_add(1, Ordering::Release);
        let t_unsub = RecordSubmitTicket::new(o_unsub, 0);

        let mut term_fut = Box::pin(task2.terminate(Some(UnsubmittedBatch {
            _permit: p_unsub,
            outcome_writer: w_unsub,
            submit_err: Box::new(AppendSessionError::SessionClosed(SessionClosedError::new(
                None,
            ))),
        })));
        assert!(
            term_fut
                .as_mut()
                .poll(&mut Context::from_waker(&noop))
                .is_pending()
        );
        drop(term_fut);

        let err_unsub = t_unsub.await.unwrap_err();
        assert!(
            matches!(
                err_unsub,
                AppendSessionError::SessionClosed(ref sc)
                    if matches!(sc.failure(), Some(AppendSessionError::Aborted(_)))
            ),
            "detached unsubmitted batch must stay SessionClosed(Some(Aborted)), got: {err_unsub:?}"
        );
        assert!(err_unsub.has_no_side_effects());
        assert_eq!(shared2.unacked_records.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn producer_terminate_preserves_clean_close_when_idle_aborted() {
        let (task, shared, _cmd_tx) = test_producer_task_parts();
        shared.abort.cancel_explicit();
        // Wait until the idle owned append session has closed cleanly with Ok(()), simulating
        // `session_closing_fut` winning `select!` over `abort_fut`.
        shared.session_lifecycle.wait_closed().await.unwrap();

        task.terminate(None).await;
        shared
            .lifecycle
            .wait_closed()
            .await
            .expect("explicitly aborting an idle producer via terminate(None) must close cleanly");
    }

    #[tokio::test]
    async fn producer_task_drop_preserves_per_batch_terminal_classification_on_concurrent_rejection()
     {
        use http::StatusCode;

        use crate::error::ServerError;

        let (mut task, shared, _cmd_tx) = test_producer_task_parts();
        let forbidden = AppendSessionError::Server(
            ServerError::new(StatusCode::FORBIDDEN, "permission denied")
                .with_code("permission_denied"),
        );
        let closed_forbidden = AppendSessionError::SessionClosed(
            SessionClosedError::new_with_context(Some(forbidden.clone()), shared.context.clone()),
        );

        let (tx0, rx0) = oneshot::channel();
        let (tx1, rx1) = oneshot::channel();
        let (_hold0, _hold1) = (tx0, tx1);

        let p0 = shared.permits.try_acquire(16).unwrap();
        let (mut w0, o0) = BatchOutcomeWriter::new(
            shared.lifecycle.clone(),
            shared.unacked_records.clone(),
            shared.context.clone(),
        );
        w0.record_count = 1;
        shared.unacked_records.fetch_add(1, Ordering::Release);
        let mut rt0 = RecordSubmitTicket::new(o0, 0);

        let p1 = shared.permits.try_acquire(16).unwrap();
        let (mut w1, o1) = BatchOutcomeWriter::new(
            shared.lifecycle.clone(),
            shared.unacked_records.clone(),
            shared.context.clone(),
        );
        w1.record_count = 1;
        shared.unacked_records.fetch_add(1, Ordering::Release);
        let mut rt1 = RecordSubmitTicket::new(o1, 0);

        task.pending_batch_acks.push_back(PendingBatchAck {
            ticket: BatchSubmitTicket::for_test(
                rx0,
                0,
                shared.session_lifecycle.clone(),
                shared.context.clone(),
            ),
            batch_max_id: 1,
            permit: Some(p0),
            outcome_writer: Some(w0),
        });
        task.pending_batch_acks.push_back(PendingBatchAck {
            ticket: BatchSubmitTicket::for_test(
                rx1,
                1,
                shared.session_lifecycle.clone(),
                shared.context.clone(),
            ),
            batch_max_id: 2,
            permit: Some(p1),
            outcome_writer: Some(w1),
        });

        // Simulate `AppendSessionTask::settle_terminal_error` having published terminal
        // classification & terminal_err before sending individual batch oneshots.
        task.session.publish_terminal_for_test(
            forbidden.clone(),
            0,
            vec![forbidden.clone(), closed_forbidden],
        );

        drop(task);

        let e0 = rt0.try_ack().expect("b0 settled").unwrap_err();
        let e1 = rt1.try_ack().expect("b1 settled").unwrap_err();
        assert!(matches!(e0, AppendSessionError::Server(_)), "{e0:?}");
        assert!(
            matches!(
                e1,
                AppendSessionError::SessionClosed(ref sc)
                    if matches!(sc.failure(), Some(AppendSessionError::Server(_)))
            ),
            "second batch must receive SessionClosed(Some(Server)), got: {e1:?}"
        );
        assert!(e1.has_no_side_effects());
        assert!(matches!(
            shared.lifecycle.wait_closed().await.unwrap_err(),
            AppendSessionError::Server(_)
        ));
    }

    #[tokio::test]
    async fn panicking_record_payload_destructor_never_strands_close_or_misclassifies_ticket() {
        struct PanicPayload(&'static [u8]);
        impl AsRef<[u8]> for PanicPayload {
            fn as_ref(&self) -> &[u8] {
                self.0
            }
        }
        impl Drop for PanicPayload {
            fn drop(&mut self) {
                panic!("simulated user Bytes::from_owner panic");
            }
        }

        // 1. Partial-batch teardown during ProducerTask::drop isolates payload panic and still
        //    completes lifecycle & settles ticket.
        {
            let (task, shared, _cmd_tx) = test_producer_task_parts();
            let body = bytes::Bytes::from_owner(PanicPayload(b"boom-partial"));
            let rec = AppendRecord::new(body).unwrap();
            let metered = rec.metered_bytes();
            let permit = shared.permits.try_acquire(metered).unwrap();
            let ticket = shared.submit_with_permit(permit, rec, metered).unwrap();

            drop(task);

            assert!(shared.lifecycle.is_closed());
            assert_eq!(shared.unacked_records.load(Ordering::Acquire), 0);
            assert_eq!(shared.permits.in_flight_bytes(), 0);
            let err = ticket.await.unwrap_err();
            assert!(
                matches!(
                    err,
                    AppendSessionError::SessionClosed(ref sc)
                        if matches!(sc.failure(), Some(AppendSessionError::Aborted(_)))
                ),
                "{err:?}"
            );
        }

        // 2. Post-submit `submit_ready_batch` registers ticket before recycling records and
        //    isolates payload panic so unsent classification stays `SessionClosed`.
        {
            let (mut task, shared, _cmd_tx) = test_producer_task_parts();
            let body = bytes::Bytes::from_owner(PanicPayload(b"boom-submitted"));
            let rec = AppendRecord::new(body).unwrap();
            let metered = rec.metered_bytes();
            let permit = shared.permits.try_acquire(metered).unwrap();
            let ticket = shared.submit_with_permit(permit, rec, metered).unwrap();
            let ready = {
                let mut gate = shared.gate.lock().unwrap();
                gate.take_partial(&shared.has_partial, &shared.next_batch_id)
                    .unwrap()
            };
            assert!(task.submit_ready_batch(ready).is_ok());
            assert_eq!(task.pending_batch_acks.len(), 1);
            drop(task);

            assert!(shared.lifecycle.is_closed());
            assert_eq!(shared.unacked_records.load(Ordering::Acquire), 0);
            let err = ticket.await.unwrap_err();
            assert!(
                matches!(
                    err,
                    AppendSessionError::SessionClosed(ref sc)
                        if matches!(sc.failure(), Some(AppendSessionError::Aborted(_)))
                ),
                "submitted-but-unsent batch must stay SessionClosed(Some(Aborted)), got: {err:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn expired_linger_partial_batch_cuts_before_accepting_late_record() {
        let (mut task, shared, _cmd_tx) = test_producer_task_parts();
        let rec1 = AppendRecord::new("first").unwrap();
        let m1 = rec1.metered_bytes();
        let p1 = shared.permits.try_acquire(m1).unwrap();
        let _t1 = shared.submit_with_permit(p1, rec1, m1).unwrap();

        // Advance well past default 5ms linger without polling ProducerTask.
        tokio::time::advance(Duration::from_millis(30)).await;

        let rec2 = AppendRecord::new("second").unwrap();
        let m2 = rec2.metered_bytes();
        let p2 = shared.permits.try_acquire(m2).unwrap();
        let _t2 = shared.submit_with_permit(p2, rec2, m2).unwrap();

        // First record must have been cut into its own Command::Batch (batch_id 0) before the
        // second record started batch_id 1.
        let mut saw_batch0 = false;
        while let Ok(cmd) = task.cmd_rx.try_recv() {
            if let Command::Batch(b) = cmd {
                assert_eq!(b.batch_id, 0);
                assert_eq!(b.records.len(), 1);
                saw_batch0 = true;
            }
        }
        assert!(
            saw_batch0,
            "expired partial batch must be cut before accepting later record"
        );
        let gate = shared.gate.lock().unwrap();
        assert_eq!(gate.next_batch_id, 1);
        assert_eq!(gate.partial.records.len(), 1);
    }

    #[test]
    fn producer_linger_uses_owner_runtime_clock_not_caller_clock() {
        let rt_owner = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let rt_caller = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();

        let (task, shared, _cmd_tx) = rt_owner.block_on(async { test_producer_task_parts() });
        let owner_t0 = rt_owner.block_on(async { Instant::now() });

        // Advance caller runtime by one full hour before submitting.
        rt_caller.block_on(async {
            tokio::time::advance(Duration::from_secs(3600)).await;
            let rec = AppendRecord::new("cross-rt").unwrap();
            let m = rec.metered_bytes();
            let p = shared.permits.try_acquire(m).unwrap();
            let _t = shared.submit_with_permit(p, rec, m).unwrap();
        });

        // `started_at` must be stamped on the owner runtime's clock (near `owner_t0`), NOT 1 hour
        // in the future.
        rt_owner.block_on(async {
            let started_at = shared.gate.lock().unwrap().partial.started_at.unwrap();
            assert!(
                started_at.saturating_duration_since(owner_t0) < Duration::from_secs(1),
                "started_at must track owner clock, not caller's +1h clock"
            );
            tokio::time::advance(Duration::from_millis(10)).await;
            assert!(Instant::now() >= started_at + shared.linger_duration);
            drop(task);
        });
    }
}
