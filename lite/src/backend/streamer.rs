use std::{
    collections::VecDeque,
    ops::{Range, RangeTo},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::{
    FutureExt as _,
    future::{BoxFuture, OptionFuture},
};
use parking_lot::Mutex;
use s2_common::{
    config::{RetentionPolicy, StreamConfig, TimestampingConfig, TimestampingMode},
    encryption::EncryptionAlgorithm,
    record::{
        CommandRecord, FencingToken, Metered, MeteredExt as _, MeteredSize, NonZeroSeqNum, Record,
        SeqNum, StreamPosition, Timestamp,
    },
    stream::AppendAck,
};
use s2_storage::record::{
    StoredAppendInput, StoredAppendRecord, StoredAppendRecordBatch, StoredAppendRecordParts,
    StoredRecord, StoredSequencedRecord,
};
use slatedb::{
    IsolationLevel, IterationOrder, WriteBatch,
    config::{PutOptions, ScanOptions, Ttl},
};
use tokio::{
    sync::{Semaphore, SemaphorePermit, broadcast, mpsc, oneshot},
    time::Instant,
};
use tracing::debug;

use crate::{
    backend::{
        append,
        bgtasks::BgtaskTrigger,
        doe,
        durability_notifier::DurabilityNotifier,
        error::{
            AppendConditionFailedError, AppendErrorInternal, AppendTimestampRequiredError,
            DeleteStreamError, MaxSeqNumError, RequestDroppedError, StorageError,
            StreamerMissingInActionError,
        },
        kv,
        timestamp::TimestampSecs,
    },
    metrics,
    stream_id::StreamId,
};

pub(super) const DORMANT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StreamerGenerationId(u64);

impl StreamerGenerationId {
    pub(super) fn next() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Debug)]
struct InFlightAppend {
    db_seq: u64,
    records: Vec<Metered<StoredSequencedRecord>>,
}

struct DbSubmitAppendOptions {
    retention: RetentionPolicy,
    fencing_token: Option<FencingToken>,
    trim_point: Option<RangeTo<SeqNum>>,
    /// When set, the terminal trim is written via a serializable snapshot
    /// transaction that revalidates the stream's configuration revision
    /// (`stream_meta.seq`) against this expected value before committing.
    /// Aborts (as a transaction conflict) when a concurrent `ReconfigureStream`
    /// has committed a newer configuration since the DOE check observed it.
    config_seq_guard: Option<u64>,
}

/// Snapshot of the actor state that [`handle_append`] mutates for a
/// config-guarded terminal trim. Held alongside the pending DB write so the
/// `run` loop can undo the mutation when the guarded transaction conflicts at
/// commit (a concurrent `ReconfigureStream` increased `min_age` first).
///
/// Guarding `finalize_trim` or `mark_stream_deleted` alone does not close the
/// race because destruction proceeds via the streamer's durability hook
/// (`BgtaskTrigger::StreamTrim`) the instant the terminal trim is durable.
/// Reverting here, before the append commits, keeps the irrevocable
/// `stream_trim_point = ..MAX` marker out of SlateDB and lets DOE retry under
/// the newer `min_age`.
struct TerminalTrimGuard {
    prev_trim_point: CommandState<RangeTo<SeqNum>>,
    prev_next_ack_pos: Option<StreamPosition>,
}

/// A pending DB write future plus optional revert metadata.
struct PendingDbWrite {
    future: BoxFuture<'static, Result<InFlightAppend, slatedb::Error>>,
    /// Revert information when this is a config-guarded terminal trim;
    /// `None` for ordinary appends and terminal trims that do not need to
    /// revalidate the configuration.
    config_guard: Option<TerminalTrimGuard>,
}

#[derive(Debug, Default)]
struct LeaseState {
    active: usize,
    closed: bool,
}

#[derive(Debug)]
struct StreamerLeaseState {
    state: Arc<Mutex<LeaseState>>,
}

impl StreamerLeaseState {
    fn new() -> (Self, StreamerClientLeaseState) {
        let state = Arc::new(Mutex::new(LeaseState::default()));
        (
            Self {
                state: state.clone(),
            },
            StreamerClientLeaseState { state },
        )
    }

    fn close_if_idle(&self) -> bool {
        let mut state = self.state.lock();
        if state.closed {
            return true;
        }
        if state.active == 0 {
            state.closed = true;
            true
        } else {
            false
        }
    }
}

impl Drop for StreamerLeaseState {
    fn drop(&mut self) {
        self.state.lock().closed = true;
    }
}

#[derive(Debug, Clone)]
struct StreamerClientLeaseState {
    state: Arc<Mutex<LeaseState>>,
}

pub(super) struct StreamerClientLeaseGuard {
    state: Arc<Mutex<LeaseState>>,
}

impl Drop for StreamerClientLeaseGuard {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        assert!(state.active > 0, "lease count underflow");
        state.active -= 1;
    }
}

impl StreamerClientLeaseState {
    fn try_acquire(&self) -> Result<StreamerClientLeaseGuard, StreamerMissingInActionError> {
        {
            let mut state = self.state.lock();
            if state.closed {
                return Err(StreamerMissingInActionError);
            }
            state.active += 1;
        }
        Ok(StreamerClientLeaseGuard {
            state: self.state.clone(),
        })
    }

    fn is_closed(&self) -> bool {
        self.state.lock().closed
    }
}

pub(super) struct GuardedStreamerClient {
    client: StreamerClient,
    _guard: StreamerClientLeaseGuard,
}

impl GuardedStreamerClient {
    pub(super) fn stream_id(&self) -> StreamId {
        self.client.stream_id
    }

    pub(super) fn cipher(&self) -> Option<EncryptionAlgorithm> {
        self.client.cipher
    }

    pub(super) async fn check_tail(&self) -> Result<StreamPosition, StreamerMissingInActionError> {
        self.client.check_tail().await
    }

    pub(super) async fn follow(
        &self,
        start_seq_num: SeqNum,
    ) -> Result<
        Result<broadcast::Receiver<Vec<Metered<StoredSequencedRecord>>>, StreamPosition>,
        StreamerMissingInActionError,
    > {
        self.client.follow(start_seq_num).await
    }

    pub(super) async fn append_permit(
        &self,
        input: StoredAppendInput,
    ) -> Result<AppendPermit<'_>, StreamerMissingInActionError> {
        self.client.append_permit(input).await
    }

    pub(super) async fn terminal_trim(
        &self,
        condition: TerminalTrimCondition,
    ) -> Result<TerminalTrimOutcome, DeleteStreamError> {
        self.client.terminal_trim(condition).await
    }
}

pub(super) struct Spawner {
    pub generation_id: StreamerGenerationId,
    pub db: slatedb::Db,
    pub stream_id: StreamId,
    /// Database commit sequence that created the stream's ID mapping.
    /// Stable across streamer restarts; changes when the stream is recreated.
    pub stream_creation_seq: u64,
    pub config: StreamConfig,
    pub config_seq: u64,
    pub cipher: Option<EncryptionAlgorithm>,
    pub tail_pos: StreamPosition,
    pub last_tail_write_timestamp: TimestampSecs,
    pub fencing_token: FencingToken,
    pub trim_point: RangeTo<SeqNum>,
    pub append_inflight_bytes_sema: Arc<Semaphore>,
    pub durability_notifier: DurabilityNotifier,
    pub bgtask_trigger_tx: broadcast::Sender<BgtaskTrigger>,
}

impl Spawner {
    pub fn spawn(
        self,
        on_exit: impl FnOnce(StreamerGenerationId) + Send + 'static,
    ) -> StreamerClient {
        let Self {
            generation_id,
            db,
            stream_id,
            stream_creation_seq,
            config,
            config_seq,
            cipher,
            tail_pos,
            last_tail_write_timestamp,
            fencing_token,
            trim_point,
            append_inflight_bytes_sema,
            durability_notifier,
            bgtask_trigger_tx,
        } = self;

        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (streamer_lease_state, client_lease_state) = StreamerLeaseState::new();
        let streamer = Streamer {
            db,
            stream_id,
            stream_creation_seq,
            msg_tx: msg_tx.clone(),
            config,
            config_seq,
            last_tail_write_timestamp,
            fencing_token: CommandState {
                state: fencing_token,
                applied_point: ..tail_pos.seq_num,
            },
            trim_point: CommandState {
                state: trim_point,
                applied_point: ..tail_pos.seq_num,
            },
            db_writes_pending: VecDeque::new(),
            db_durability_subscription: 0,
            inflight_appends: VecDeque::new(),
            pending_appends: append::PendingAppends::new(),
            stable_pos: tail_pos,
            follow_tx: broadcast::Sender::new(super::FOLLOWER_MAX_LAG),
            lease_state: streamer_lease_state,
            durability_notifier,
            bgtask_trigger_tx,
        };

        tokio::spawn(async move {
            streamer.run(msg_rx).await;
            on_exit(generation_id);
        });

        StreamerClient {
            generation_id,
            stream_id,
            cipher,
            msg_tx,
            append_inflight_bytes: append_inflight_bytes_sema,
            lease_state: client_lease_state,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppendType {
    Regular,
    Terminal,
}

#[derive(Debug, Clone)]
struct CommandState<T> {
    applied_point: RangeTo<SeqNum>,
    state: T,
}

impl<T> CommandState<T> {
    fn is_applied_in(&self, seq_num_range: &Range<SeqNum>) -> bool {
        seq_num_range.start < self.applied_point.end && self.applied_point.end <= seq_num_range.end
    }
}

struct Streamer {
    db: slatedb::Db,
    stream_id: StreamId,
    stream_creation_seq: u64,
    msg_tx: mpsc::UnboundedSender<Message>,
    config: StreamConfig,
    config_seq: u64,
    last_tail_write_timestamp: TimestampSecs,
    fencing_token: CommandState<FencingToken>,
    trim_point: CommandState<RangeTo<SeqNum>>,
    db_writes_pending: VecDeque<PendingDbWrite>,
    db_durability_subscription: u64,
    inflight_appends: VecDeque<InFlightAppend>,
    pending_appends: append::PendingAppends,
    stable_pos: StreamPosition,
    follow_tx: broadcast::Sender<Vec<Metered<StoredSequencedRecord>>>,
    lease_state: StreamerLeaseState,
    durability_notifier: DurabilityNotifier,
    bgtask_trigger_tx: broadcast::Sender<BgtaskTrigger>,
}

impl Streamer {
    fn next_assignable_pos(&self) -> StreamPosition {
        self.pending_appends
            .next_ack_pos()
            .unwrap_or(self.stable_pos)
    }

    fn sequence_records(
        &self,
        StoredAppendInput {
            records,
            match_seq_num,
            fencing_token,
        }: StoredAppendInput,
    ) -> Result<Vec<Metered<StoredSequencedRecord>>, AppendErrorInternal> {
        if let Some(provided_token) = fencing_token
            && provided_token != self.fencing_token.state
        {
            Err(AppendConditionFailedError::FencingTokenMismatch {
                expected: provided_token,
                actual: self.fencing_token.state.clone(),
                applied_point: self.fencing_token.applied_point,
            })?;
        }
        let next_assignable_pos = self.next_assignable_pos();
        let first_seq_num = next_assignable_pos.seq_num;
        if let Some(match_seq_num) = match_seq_num
            && match_seq_num != first_seq_num
        {
            Err(AppendConditionFailedError::SeqNumMismatch {
                assigned_seq_num: first_seq_num,
                match_seq_num,
            })?;
        }
        sequenced_records(
            records,
            first_seq_num,
            next_assignable_pos.timestamp,
            &self.config.timestamping,
        )
    }

    fn apply_command(&mut self, seq_num: SeqNum, cmd: &CommandRecord, append_type: AppendType) {
        let new_applied_point = ..(seq_num + 1);
        match cmd {
            CommandRecord::Fence(token) => {
                self.fencing_token = CommandState {
                    applied_point: new_applied_point,
                    state: token.clone(),
                };
            }
            CommandRecord::Trim(trim_point) => {
                let trim_point = ..(*trim_point).min(match append_type {
                    AppendType::Regular => new_applied_point.end,
                    AppendType::Terminal => SeqNum::MAX,
                });
                if self.trim_point.state.end < trim_point.end {
                    self.trim_point = CommandState {
                        applied_point: new_applied_point,
                        state: trim_point,
                    };
                }
            }
        }
    }

    fn handle_append(
        &mut self,
        input: StoredAppendInput,
        session: Option<append::SessionHandle>,
        reply_tx: oneshot::Sender<Result<AppendAck, AppendErrorInternal>>,
        append_type: AppendType,
        config_seq_guard: Option<u64>,
    ) {
        let Some(ticket) = append::admit(reply_tx, session) else {
            return;
        };
        let sequenced_records = if self.trim_point.state.end == SeqNum::MAX {
            Err(AppendErrorInternal::StreamDeletionPending {
                // The terminal trim must be durable before reporting deletion pending.
                durability_dependency: self.trim_point.applied_point,
            })
        } else {
            self.sequence_records(input)
        };
        match sequenced_records {
            Ok(sequenced_records) => {
                if append_type == AppendType::Terminal {
                    assert_eq!(sequenced_records.len(), 1);
                    assert_eq!(
                        sequenced_records[0].inner(),
                        &StoredRecord::Plaintext(Record::Command(CommandRecord::Trim(SeqNum::MAX)))
                    );
                }
                // Capture the pre-mutation state for a config-guarded terminal
                // trim before apply_command rewrites trim_point, so the run loop
                // can revert when the guarded transaction conflicts at commit.
                let config_guard = config_seq_guard.is_some().then(|| TerminalTrimGuard {
                    prev_trim_point: self.trim_point.clone(),
                    prev_next_ack_pos: self.pending_appends.next_ack_pos(),
                });
                for sr in sequenced_records.iter() {
                    if let StoredRecord::Plaintext(Record::Command(cmd)) = sr.inner() {
                        self.apply_command(sr.position().seq_num, cmd, append_type);
                    }
                }
                let (first_pos, next_pos) = pos_span(&sequenced_records);
                let seq_num_range = first_pos.seq_num..next_pos.seq_num;
                let opts = DbSubmitAppendOptions {
                    retention: self.config.retention_policy,
                    fencing_token: self
                        .fencing_token
                        .is_applied_in(&seq_num_range)
                        .then(|| self.fencing_token.state.clone()),
                    trim_point: self
                        .trim_point
                        .is_applied_in(&seq_num_range)
                        .then_some(self.trim_point.state),
                    config_seq_guard,
                };
                self.db_writes_pending.push_back(PendingDbWrite {
                    future: db_submit_append(
                        self.db.clone(),
                        self.stream_id,
                        sequenced_records,
                        opts,
                    )
                    .boxed(),
                    config_guard,
                });
                self.pending_appends.accept(ticket, first_pos..next_pos);
                self.last_tail_write_timestamp = TimestampSecs::now();
            }
            Err(e) => {
                self.pending_appends.reject(ticket, e, self.stable_pos);
            }
        }
    }

    fn handle_terminal_trim(
        &mut self,
        condition: TerminalTrimCondition,
        reply_tx: oneshot::Sender<Result<TerminalTrimOutcome, DeleteStreamError>>,
    ) {
        match condition {
            TerminalTrimCondition::Always => {
                self.ensure_terminal_trim(reply_tx, None);
            }
            TerminalTrimCondition::DeleteOnEmpty {
                expected_stream_creation_seq,
                expected_config_seq,
            } => {
                if self.stream_creation_seq != expected_stream_creation_seq {
                    let _ = reply_tx.send(Ok(TerminalTrimOutcome::Obsolete));
                } else if self.trim_point.state.end == SeqNum::MAX {
                    self.ensure_terminal_trim(reply_tx, None);
                } else if self.config_seq != expected_config_seq {
                    // The worker may have observed a configuration commit before
                    // its notification reached this actor (or vice versa). Do not
                    // defer using an age that may have just been decreased.
                    let _ = reply_tx.send(Ok(TerminalTrimOutcome::RetryAt(TimestampSecs::after(
                        doe::RETRY_INTERVAL,
                    ))));
                } else if self.config.delete_on_empty.min_age().is_none() {
                    let _ = reply_tx.send(Ok(TerminalTrimOutcome::Obsolete));
                } else {
                    let db = self.db.clone();
                    let stream_id = self.stream_id;
                    let stable_pos_snapshot = self.stable_pos;
                    let config_seq_snapshot = self.config_seq;
                    let msg_tx = self.msg_tx.clone();
                    tokio::spawn(async move {
                        let records = stream_record_presence(&db, stream_id).await;
                        let _ = msg_tx.send(Message::DeleteOnEmptyCheckResult {
                            stable_pos_snapshot,
                            config_seq_snapshot,
                            records,
                            reply_tx,
                        });
                    });
                }
            }
        }
    }

    fn handle_doe_check_result(
        &mut self,
        stable_pos_snapshot: StreamPosition,
        config_seq_snapshot: u64,
        records: Result<RecordPresence, StorageError>,
        reply_tx: oneshot::Sender<Result<TerminalTrimOutcome, DeleteStreamError>>,
    ) {
        let records = match records {
            Ok(records) => records,
            Err(err) => {
                let _ = reply_tx.send(Err(err.into()));
                return;
            }
        };
        if self.trim_point.state.end == SeqNum::MAX {
            self.ensure_terminal_trim(reply_tx, None);
            return;
        }
        if self.config_seq != config_seq_snapshot {
            let _ = reply_tx.send(Ok(TerminalTrimOutcome::RetryAt(TimestampSecs::after(
                doe::RETRY_INTERVAL,
            ))));
            return;
        }
        let Some(min_age) = self.config.delete_on_empty.min_age() else {
            let _ = reply_tx.send(Ok(TerminalTrimOutcome::Obsolete));
            return;
        };
        let outcome = match records {
            // Appends cannot remove an observed record, so these bounds remain
            // useful even when the tail advances. The scheduler's revision check
            // protects against a trim removing the record before we finish.
            RecordPresence::ExpiresAt(at) => self.doe_retry_at(at),
            RecordPresence::Unbounded => TerminalTrimOutcome::Parked,
            RecordPresence::Empty => {
                let old_enough = TimestampSecs::now()
                    .checked_sub_duration(min_age)
                    .is_some_and(|cutoff| self.last_tail_write_timestamp <= cutoff);
                if self.stable_pos == stable_pos_snapshot
                    && self.next_assignable_pos() == stable_pos_snapshot
                    && old_enough
                {
                    // Plumb the DOE-observed config revision so the terminal
                    // trim append revalidates it transactionally. Without this,
                    // a successful ReconfigureStream that increases min_age
                    // (which bumps stream_meta.seq in SlateDB) could still have
                    // the stream destroyed under the stale, smaller min_age the
                    // actor holds in memory, because TerminalTrimCheckResult
                    // is processed before the Reconfigure advise reaches the
                    // mailbox.
                    self.ensure_terminal_trim(reply_tx, Some(config_seq_snapshot));
                    return;
                }
                self.doe_retry_at(TimestampSecs::ZERO)
            }
        };
        let _ = reply_tx.send(Ok(outcome));
    }

    fn doe_retry_at(&self, earliest_empty: TimestampSecs) -> TerminalTrimOutcome {
        let age_at = self
            .last_tail_write_timestamp
            .saturating_add_duration(self.config.delete_on_empty.min_age().unwrap_or_default());
        TerminalTrimOutcome::RetryAt(
            TimestampSecs::after(doe::RETRY_INTERVAL)
                .max(age_at)
                .max(earliest_empty),
        )
    }

    fn ensure_terminal_trim(
        &mut self,
        reply_tx: oneshot::Sender<Result<TerminalTrimOutcome, DeleteStreamError>>,
        config_seq_guard: Option<u64>,
    ) {
        let (append_reply_tx, append_reply_rx) = oneshot::channel();
        self.handle_append(
            terminal_trim_input(),
            None,
            append_reply_tx,
            AppendType::Terminal,
            config_seq_guard,
        );
        tokio::spawn(async move {
            let result = match append_reply_rx.await {
                Ok(Ok(_)) => Ok(TerminalTrimOutcome::DeletionPending),
                Ok(Err(AppendErrorInternal::StreamDeletionPending { .. })) => {
                    Ok(TerminalTrimOutcome::DeletionPending)
                }
                // A concurrent ReconfigureStream increased min_age and
                // committed first; the config-guarded terminal trim transaction
                // aborted. Let DOE re-evaluate under the new configuration.
                Ok(Err(AppendErrorInternal::DeleteOnEmptyConfigConflict)) => Ok(
                    TerminalTrimOutcome::RetryAt(TimestampSecs::after(doe::RETRY_INTERVAL)),
                ),
                Ok(Err(AppendErrorInternal::Storage(e))) => Err(DeleteStreamError::Storage(e)),
                Ok(Err(AppendErrorInternal::StreamerMissingInActionError(e))) => {
                    Err(DeleteStreamError::StreamerMissingInActionError(e))
                }
                Ok(Err(AppendErrorInternal::RequestDroppedError(e))) => {
                    Err(DeleteStreamError::RequestDroppedError(e))
                }
                Ok(Err(AppendErrorInternal::ConditionFailed(_))) => {
                    unreachable!("unconditional write")
                }
                Ok(Err(AppendErrorInternal::TimestampMissing(_))) => {
                    unreachable!("Timestamp::MAX used")
                }
                Ok(Err(AppendErrorInternal::MaxSeqNum(_))) => {
                    unreachable!("terminal append is plaintext command record")
                }
                Err(_) => Err(RequestDroppedError.into()),
            };
            let _ = reply_tx.send(result);
        });
    }

    fn subscribe_durability(&mut self) {
        if let Some(inflight_append) = self
            .inflight_appends
            .front()
            .filter(|pa| pa.db_seq > self.db_durability_subscription)
        {
            let msg_tx = self.msg_tx.clone();
            self.durability_notifier
                .subscribe(inflight_append.db_seq, move |res| {
                    let _ = msg_tx.send(Message::DurabilityStatus(res));
                });
            self.db_durability_subscription = inflight_append.db_seq;
        }
    }

    fn on_db_durable_seq_advanced(&mut self, db_durable_seq: u64) {
        while self
            .inflight_appends
            .front()
            .is_some_and(|pa| pa.db_seq <= db_durable_seq)
        {
            let records = self
                .inflight_appends
                .pop_front()
                .expect("non-empty")
                .records;
            let (first_pos, stable_pos) = pos_span(&records);
            assert!(self.stable_pos.seq_num <= stable_pos.seq_num);
            self.pending_appends.on_stable(stable_pos);
            self.stable_pos = stable_pos;
            if self
                .trim_point
                .is_applied_in(&(first_pos.seq_num..stable_pos.seq_num))
            {
                let _ = self.bgtask_trigger_tx.send(BgtaskTrigger::StreamTrim);
            }
            if self.follow_tx.send(records).is_err() {
                debug!(stream_id = %self.stream_id, "no active followers for durable records broadcast");
            }
        }
    }

    async fn run(mut self, mut msg_rx: mpsc::UnboundedReceiver<Message>) {
        let dormancy = tokio::time::sleep(Duration::MAX);
        tokio::pin!(dormancy);
        loop {
            if self.trim_point.state.end == SeqNum::MAX {
                if self.trim_point.applied_point.end == self.stable_pos.seq_num {
                    // Terminal trim is durable.
                    break;
                } else {
                    assert!(self.stable_pos.seq_num < self.trim_point.applied_point.end);
                }
            }
            dormancy.as_mut().reset(Instant::now() + DORMANT_TIMEOUT);
            tokio::select! {
                biased;
                Some(res) = OptionFuture::from(self.db_writes_pending.front_mut().map(|p| p.future.as_mut())) => {
                    let pending = self.db_writes_pending.pop_front().expect("polled");
                    match res {
                        Ok(submitted_append) => {
                            if let Some(prev) = self.inflight_appends.back() {
                                assert!(prev.db_seq < submitted_append.db_seq);
                            }
                            self.inflight_appends.push_back(submitted_append);
                            self.subscribe_durability();
                        }
                        Err(db_err) => {
                            // A config-guarded terminal trim can conflict if a
                            // concurrent ReconfigureStream committed a newer
                            // stream_meta after the DOE check observed it. Undo
                            // the actor-side mutation and let DOE retry under the
                            // new configuration instead of killing the streamer.
                            if let Some(guard) = pending.config_guard
                                && db_err.kind() == slatedb::ErrorKind::Transaction
                            {
                                self.trim_point = guard.prev_trim_point;
                                self.pending_appends.retract_last(
                                    AppendErrorInternal::DeleteOnEmptyConfigConflict,
                                    guard.prev_next_ack_pos,
                                );
                                continue;
                            }
                            self.pending_appends.on_durability_failed(db_err);
                            break;
                        }
                    }
                }
                Some(msg) = msg_rx.recv() => {
                    match msg {
                        Message::Append {
                            input,
                            session,
                            reply_tx,
                            append_type,
                        } => {
                            self.handle_append(input, session, reply_tx, append_type, None);
                        }
                        Message::TerminalTrim {
                            condition,
                            reply_tx,
                        } => {
                            self.handle_terminal_trim(condition, reply_tx);
                        }
                        Message::DeleteOnEmptyCheckResult {
                            stable_pos_snapshot,
                            config_seq_snapshot,
                            records,
                            reply_tx,
                        } => {
                            self.handle_doe_check_result(
                                stable_pos_snapshot,
                                config_seq_snapshot,
                                records,
                                reply_tx,
                            );
                        }
                        Message::Follow {
                            start_seq_num,
                            reply_tx,
                        } => {
                            let reply = if start_seq_num == self.stable_pos.seq_num {
                                Ok(self.follow_tx.subscribe())
                            } else {
                                Err(self.stable_pos)
                            };
                            let _ = reply_tx.send(reply);
                        }
                        Message::CheckTail { reply_tx } => {
                            let _ = reply_tx.send(self.stable_pos);
                        }
                        Message::Reconfigure { seq, config } => {
                            if seq > self.config_seq {
                                self.config = config;
                                self.config_seq = seq;
                            }
                        }
                        Message::DurabilityStatus(status) => {
                            match status {
                                Ok(durable_seq) => {
                                    assert!(durable_seq >= self.db_durability_subscription);
                                    self.on_db_durable_seq_advanced(durable_seq);
                                    self.subscribe_durability();
                                }
                                Err(reason) => {
                                    self.pending_appends.on_durability_failed(slatedb::Error::closed(
                                        "database closed while waiting for durability".to_owned(),
                                        reason,
                                    ));
                                    break;
                                },
                            }
                        }
                    }
                }
                _ = dormancy.as_mut() => {
                    // Cancelled requests can still have writes become durable. Keep
                    // their assigned positions until a new streamer can recover them.
                    if self.db_writes_pending.is_empty()
                        && self.inflight_appends.is_empty()
                        && self.lease_state.close_if_idle()
                    {
                        break;
                    }
                }
            }
        }
    }
}

enum Message {
    Append {
        input: StoredAppendInput,
        session: Option<append::SessionHandle>,
        reply_tx: oneshot::Sender<Result<AppendAck, AppendErrorInternal>>,
        append_type: AppendType,
    },
    TerminalTrim {
        condition: TerminalTrimCondition,
        reply_tx: oneshot::Sender<Result<TerminalTrimOutcome, DeleteStreamError>>,
    },
    DeleteOnEmptyCheckResult {
        stable_pos_snapshot: StreamPosition,
        config_seq_snapshot: u64,
        records: Result<RecordPresence, StorageError>,
        reply_tx: oneshot::Sender<Result<TerminalTrimOutcome, DeleteStreamError>>,
    },
    Follow {
        start_seq_num: SeqNum,
        reply_tx: oneshot::Sender<
            Result<broadcast::Receiver<Vec<Metered<StoredSequencedRecord>>>, StreamPosition>,
        >,
    },
    CheckTail {
        reply_tx: oneshot::Sender<StreamPosition>,
    },
    Reconfigure {
        seq: u64,
        config: StreamConfig,
    },
    DurabilityStatus(Result<u64, slatedb::CloseReason>),
}

pub(super) enum TerminalTrimCondition {
    Always,
    DeleteOnEmpty {
        expected_stream_creation_seq: u64,
        expected_config_seq: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TerminalTrimOutcome {
    /// Deletion is durably pending.
    DeletionPending,
    RetryAt(TimestampSecs),
    Parked,
    /// DOE is disabled or this request belongs to an earlier incarnation.
    Obsolete,
}

#[derive(Debug, Clone)]
pub(super) struct StreamerClient {
    generation_id: StreamerGenerationId,
    stream_id: StreamId,
    cipher: Option<EncryptionAlgorithm>,
    msg_tx: mpsc::UnboundedSender<Message>,
    append_inflight_bytes: Arc<Semaphore>,
    lease_state: StreamerClientLeaseState,
}

impl StreamerClient {
    pub(super) fn generation_id(&self) -> StreamerGenerationId {
        self.generation_id
    }

    pub(super) fn is_dead(&self) -> bool {
        self.lease_state.is_closed()
    }

    pub(super) fn guard(self) -> Result<GuardedStreamerClient, StreamerMissingInActionError> {
        let _guard = self.lease_state.try_acquire()?;
        Ok(GuardedStreamerClient {
            client: self,
            _guard,
        })
    }

    async fn check_tail(&self) -> Result<StreamPosition, StreamerMissingInActionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.msg_tx
            .send(Message::CheckTail { reply_tx })
            .map_err(|_| StreamerMissingInActionError)?;
        reply_rx.await.map_err(|_| StreamerMissingInActionError)
    }

    async fn follow(
        &self,
        start_seq_num: SeqNum,
    ) -> Result<
        Result<broadcast::Receiver<Vec<Metered<StoredSequencedRecord>>>, StreamPosition>,
        StreamerMissingInActionError,
    > {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.msg_tx
            .send(Message::Follow {
                start_seq_num,
                reply_tx,
            })
            .map_err(|_| StreamerMissingInActionError)?;
        reply_rx.await.map_err(|_| StreamerMissingInActionError)
    }

    async fn append_permit(
        &self,
        input: StoredAppendInput,
    ) -> Result<AppendPermit<'_>, StreamerMissingInActionError> {
        let metered_size = input.records.metered_size();
        metrics::observe_append_batch_size(input.records.len(), metered_size);
        let start = Instant::now();
        let num_permits =
            u32::try_from(metered_size.max(1)).expect("append batch size fits in u32");
        let sema_permit = tokio::select! {
            res = self.append_inflight_bytes.acquire_many(num_permits) => {
                res.map_err(|_| StreamerMissingInActionError)
            }
            _ = self.msg_tx.closed() => {
                Err(StreamerMissingInActionError)
            }
        }?;
        metrics::observe_append_permit_latency(start.elapsed());
        Ok(AppendPermit {
            sema_permit,
            msg_tx: &self.msg_tx,
            input,
        })
    }

    pub(super) fn advise_reconfig(&self, seq: u64, config: StreamConfig) -> bool {
        self.msg_tx
            .send(Message::Reconfigure { seq, config })
            .is_ok()
    }

    async fn terminal_trim(
        &self,
        condition: TerminalTrimCondition,
    ) -> Result<TerminalTrimOutcome, DeleteStreamError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.msg_tx
            .send(Message::TerminalTrim {
                condition,
                reply_tx,
            })
            .map_err(|_| {
                DeleteStreamError::StreamerMissingInActionError(StreamerMissingInActionError)
            })?;
        reply_rx.await.map_err(|_| RequestDroppedError)?
    }
}

fn timestamp_now() -> Timestamp {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("21st century")
        .as_millis()
        .try_into()
        .expect("Milliseconds since Unix epoch fits into a u64")
}

fn terminal_trim_input() -> StoredAppendInput {
    let record: StoredAppendRecord = StoredAppendRecordParts {
        timestamp: Some(Timestamp::MAX),
        record: StoredRecord::from(Record::Command(CommandRecord::Trim(SeqNum::MAX))).metered(),
    }
    .try_into()
    .expect("valid append record");
    StoredAppendInput {
        records: vec![record].try_into().expect("valid append batch"),
        match_seq_num: None,
        fencing_token: None,
    }
}

#[derive(Debug)]
pub struct AppendPermit<'a> {
    sema_permit: SemaphorePermit<'a>,
    msg_tx: &'a mpsc::UnboundedSender<Message>,
    input: StoredAppendInput,
}

impl AppendPermit<'_> {
    pub async fn submit(self) -> Result<AppendAck, AppendErrorInternal> {
        self.submit_internal(None, AppendType::Regular).await
    }

    pub async fn submit_session(
        self,
        session: append::SessionHandle,
    ) -> Result<AppendAck, AppendErrorInternal> {
        self.submit_internal(Some(session), AppendType::Regular)
            .await
    }

    async fn submit_internal(
        self,
        session: Option<append::SessionHandle>,
        append_type: AppendType,
    ) -> Result<AppendAck, AppendErrorInternal> {
        let start = Instant::now();
        let AppendPermit {
            sema_permit,
            msg_tx,
            input,
        } = self;
        let (reply_tx, reply_rx) = oneshot::channel();
        msg_tx
            .send(Message::Append {
                input,
                session,
                reply_tx,
                append_type,
            })
            .map_err(|_| StreamerMissingInActionError)?;
        let ack = reply_rx.await.map_err(|_| RequestDroppedError)??;
        drop(sema_permit);
        metrics::observe_append_ack_latency(start.elapsed());
        Ok(ack)
    }
}

fn pos_span(records: &[Metered<StoredSequencedRecord>]) -> (StreamPosition, StreamPosition) {
    (
        *records.first().expect("non-empty").position(),
        next_pos(records),
    )
}

pub fn next_pos(records: &[Metered<StoredSequencedRecord>]) -> StreamPosition {
    let last_pos = records.last().expect("non-empty").position();
    StreamPosition {
        seq_num: last_pos.seq_num + 1,
        timestamp: last_pos.timestamp,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordPresence {
    Empty,
    ExpiresAt(TimestampSecs),
    Unbounded,
}

async fn stream_record_presence(
    db: &slatedb::Db,
    stream_id: StreamId,
) -> Result<RecordPresence, StorageError> {
    let prefix = kv::stream_record_timestamp::ser_key_prefix(stream_id);
    let scan_opts = ScanOptions::default().with_order(IterationOrder::Descending);
    let mut it = db.scan_prefix_with_options(prefix, .., &scan_opts).await?;
    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    while let Some(kv) = it.next().await? {
        match kv.expire_ts {
            None => return Ok(RecordPresence::Unbounded),
            Some(expire_ts) if expire_ts > now_millis => {
                // One live record bounds when the stream can become empty.
                // Use its stored TTL, since retention changes are not retroactive.
                // Round up so the check does not run just before expiration.
                return Ok(RecordPresence::ExpiresAt(TimestampSecs::from_millis(
                    expire_ts.saturating_add(999),
                )));
            }
            _ => (),
        }
    }
    Ok(RecordPresence::Empty)
}

fn sequenced_records(
    batch: StoredAppendRecordBatch,
    first_seq_num: SeqNum,
    prev_max_timestamp: Timestamp,
    config: &TimestampingConfig,
) -> Result<Vec<Metered<StoredSequencedRecord>>, AppendErrorInternal> {
    let mut sequenced_records = Vec::with_capacity(batch.len());
    let mut max_timestamp = prev_max_timestamp;
    let now = timestamp_now();
    for (i, StoredAppendRecordParts { timestamp, record }) in batch
        .into_iter()
        .map(|record| record.into_parts())
        .enumerate()
    {
        let assigned_seq_num = first_seq_num + i as u64;

        let max_assignable_seq_num = record.as_ref().into_inner().max_assignable_seq_num();
        if assigned_seq_num > max_assignable_seq_num {
            Err(MaxSeqNumError {
                first_seq_num,
                assigned_seq_num,
                max_assignable_seq_num,
            })?;
        }
        let mut timestamp = match config.mode {
            TimestampingMode::ClientPrefer => timestamp.unwrap_or(now),
            TimestampingMode::ClientRequire => timestamp.ok_or(AppendTimestampRequiredError)?,
            TimestampingMode::Arrival => now,
        };
        if !config.uncapped && timestamp > now {
            timestamp = now;
        }
        if timestamp < max_timestamp {
            timestamp = max_timestamp;
        } else {
            max_timestamp = timestamp;
        }

        sequenced_records.push(record.sequenced(StreamPosition {
            seq_num: assigned_seq_num,
            timestamp,
        }));
    }
    Ok(sequenced_records)
}

async fn db_submit_append(
    db: slatedb::Db,
    stream_id: StreamId,
    records: Vec<Metered<StoredSequencedRecord>>,
    DbSubmitAppendOptions {
        retention,
        fencing_token,
        trim_point,
        config_seq_guard,
    }: DbSubmitAppendOptions,
) -> Result<InFlightAppend, slatedb::Error> {
    let ttl = match retention {
        RetentionPolicy::Age(age) => Ttl::ExpireAfterMillis(age.as_millis() as u64),
        RetentionPolicy::Infinite() => Ttl::NoExpiry,
    };
    let ttl_put_opts = PutOptions { ttl };

    // A config-guarded terminal trim is the irrevocable step in the DOE
    // deletion path. Revalidate the stream's configuration revision that the
    // DOE check observed, transactionally, so a concurrent ReconfigureStream
    // that committed a newer stream_meta.seq forces the trim to abort instead
    // of destroying the stream under the stale (smaller) min_age the actor's
    // in-memory config still holds.
    if let Some(expected_config_seq) = config_seq_guard {
        let txn = db.begin(IsolationLevel::SerializableSnapshot).await?;

        // Resolve the basin/stream for stream_id. The read is tracked in the
        // SSI transaction's read set so a concurrent recreation is detected.
        let mapping = txn
            .get_key_value(kv::stream_id_mapping::ser_key(stream_id))
            .await?
            .ok_or_else(|| slatedb::Error::invalid("stream id mapping missing".into()))?;
        let (basin, stream) = kv::stream_id_mapping::deser_value(mapping.value)
            .map_err(|e| slatedb::Error::invalid(format!("invalid stream id mapping: {e}")))?;

        // Read stream_meta and check its commit sequence against the DOE
        // snapshot. The SSI read set tracks this key, so a concurrent
        // reconfigure that wrote stream_meta after this snapshot causes commit
        // to abort with a transaction conflict. The sequence comparison below
        // catches a reconfigure that already committed before this txn began.
        let meta_entry = txn
            .get_key_value(kv::stream_meta::ser_key(&basin, &stream))
            .await?
            .ok_or_else(|| slatedb::Error::invalid("stream meta missing".into()))?;
        if meta_entry.seq != expected_config_seq {
            return Err(slatedb::Error::transaction(
                "stream config changed before terminal trim could commit".into(),
            ));
        }

        for (position, record) in records.iter().map(|msr| msr.parts()) {
            txn.put_with_options(
                kv::stream_record_data::ser_key(stream_id, position),
                kv::stream_record_data::ser_value(record),
                &ttl_put_opts,
            )?;
            txn.put_with_options(
                kv::stream_record_timestamp::ser_key(stream_id, position),
                kv::stream_record_timestamp::ser_value(),
                &ttl_put_opts,
            )?;
        }
        if let Some(fencing_token) = fencing_token {
            txn.put(
                kv::stream_fencing_token::ser_key(stream_id),
                kv::stream_fencing_token::ser_value(&fencing_token),
            )?;
        }
        if let Some(trim_point) = trim_point.and_then(|tp| NonZeroSeqNum::new(tp.end)) {
            txn.put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(..trim_point),
            )?;
        }
        txn.put(
            kv::stream_tail_position::ser_key(stream_id),
            kv::stream_tail_position::ser_value(next_pos(&records)),
        )?;

        let handle = txn
            .commit()
            .await?
            .expect("terminal trim writes a non-empty batch");
        return Ok(InFlightAppend {
            db_seq: handle.seqnum(),
            records,
        });
    }

    let mut wb = WriteBatch::new();
    for (position, record) in records.iter().map(|msr| msr.parts()) {
        wb.put_bytes_with_options(
            kv::stream_record_data::ser_key(stream_id, position),
            kv::stream_record_data::ser_value(record),
            &ttl_put_opts,
        );
        wb.put_bytes_with_options(
            kv::stream_record_timestamp::ser_key(stream_id, position),
            kv::stream_record_timestamp::ser_value(),
            &ttl_put_opts,
        );
    }
    if let Some(fencing_token) = fencing_token {
        wb.put_bytes(
            kv::stream_fencing_token::ser_key(stream_id),
            kv::stream_fencing_token::ser_value(&fencing_token),
        );
    }
    if let Some(trim_point) = trim_point.and_then(|tp| NonZeroSeqNum::new(tp.end)) {
        wb.put_bytes(
            kv::stream_trim_point::ser_key(stream_id),
            kv::stream_trim_point::ser_value(..trim_point),
        );
    }
    wb.put_bytes(
        kv::stream_tail_position::ser_key(stream_id),
        kv::stream_tail_position::ser_value(next_pos(&records)),
    );
    // The durability notifier tracks this sequence and acknowledges the append after flush.
    let write_handle = db.write(wb).await?;
    Ok(InFlightAppend {
        db_seq: write_handle.seqnum(),
        records,
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Arc};

    use bytes::Bytes;
    use s2_common::{
        encryption::EncryptionSpec,
        record::{EnvelopeRecord, Record},
    };
    use s2_storage::record::{
        StoredAppendInput, StoredAppendRecord, StoredAppendRecordBatch, StoredAppendRecordParts,
        StoredRecord, encrypt_record,
    };
    use slatedb::object_store::memory::InMemory;
    use tokio::sync::{broadcast, mpsc, oneshot};

    use super::*;

    fn test_record(body: Bytes, timestamp: Option<Timestamp>) -> StoredAppendRecord {
        let envelope = EnvelopeRecord::try_from_parts(vec![], body).unwrap();
        let record = StoredRecord::from(Record::Envelope(envelope)).metered();
        let parts = StoredAppendRecordParts { timestamp, record };
        parts.try_into().unwrap()
    }

    fn test_command_record(
        command: CommandRecord,
        timestamp: Option<Timestamp>,
    ) -> StoredAppendRecord {
        let record = StoredRecord::from(Record::Command(command)).metered();
        let parts = StoredAppendRecordParts { timestamp, record };
        parts.try_into().unwrap()
    }

    fn test_encrypted_record(
        body: Bytes,
        timestamp: Option<Timestamp>,
        encryption: &EncryptionSpec,
    ) -> StoredAppendRecord {
        let envelope = EnvelopeRecord::try_from_parts(vec![], body).unwrap();
        let record = encrypt_record(
            Record::Envelope(envelope).metered(),
            encryption,
            b"test-streamer",
        );
        let parts = StoredAppendRecordParts { timestamp, record };
        parts.try_into().unwrap()
    }

    #[test]
    fn sequenced_records_client_prefer_with_timestamps() {
        let config = TimestampingConfig {
            mode: TimestampingMode::ClientPrefer,
            uncapped: false,
        };

        let records: StoredAppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), Some(900)),
            test_record(vec![4, 5, 6].into(), Some(950)),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].position().seq_num, 100);
        assert_eq!(result[0].position().timestamp, 900);
        assert_eq!(result[1].position().seq_num, 101);
        assert_eq!(result[1].position().timestamp, 950);
    }

    #[test]
    fn sequenced_records_client_prefer_without_timestamps() {
        let now = timestamp_now();
        let config = TimestampingConfig {
            mode: TimestampingMode::ClientPrefer,
            uncapped: false,
        };

        let records: StoredAppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), None),
            test_record(vec![4, 5, 6].into(), None),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].position().seq_num, 100);
        assert!(result[0].position().timestamp >= now);
        assert_eq!(result[1].position().seq_num, 101);
        assert!(result[1].position().timestamp >= now);
    }

    #[test]
    fn sequenced_records_client_require_missing_timestamp() {
        let config = TimestampingConfig {
            mode: TimestampingMode::ClientRequire,
            uncapped: false,
        };

        let records: StoredAppendRecordBatch = vec![test_record(vec![1, 2, 3].into(), None)]
            .try_into()
            .unwrap();

        let result = sequenced_records(records, 100, 0, &config);

        assert!(matches!(
            result,
            Err(AppendErrorInternal::TimestampMissing(_))
        ));
    }

    #[test]
    fn sequenced_records_client_require_with_timestamps() {
        let config = TimestampingConfig {
            mode: TimestampingMode::ClientRequire,
            uncapped: false,
        };

        let records: StoredAppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), Some(900)),
            test_record(vec![4, 5, 6].into(), Some(950)),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].position().timestamp, 900);
        assert_eq!(result[1].position().timestamp, 950);
    }

    #[test]
    fn sequenced_records_arrival_mode() {
        let now = timestamp_now();
        let config = TimestampingConfig {
            mode: TimestampingMode::Arrival,
            uncapped: false,
        };

        let records: StoredAppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), Some(900)),
            test_record(vec![4, 5, 6].into(), Some(950)),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result[0].position().timestamp >= now);
        assert!(result[1].position().timestamp >= now);
    }

    #[test]
    fn sequenced_records_timestamp_monotonicity() {
        let config = TimestampingConfig {
            mode: TimestampingMode::ClientPrefer,
            uncapped: false,
        };

        let records: StoredAppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), Some(1000)),
            test_record(vec![4, 5, 6].into(), Some(900)),
            test_record(vec![7, 8, 9].into(), Some(1100)),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].position().timestamp, 1000);
        assert_eq!(result[1].position().timestamp, 1000);
        assert_eq!(result[2].position().timestamp, 1100);
    }

    #[test]
    fn sequenced_records_prev_max_timestamp_enforced() {
        let config = TimestampingConfig {
            mode: TimestampingMode::ClientPrefer,
            uncapped: false,
        };

        let records: StoredAppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), Some(500)),
            test_record(vec![4, 5, 6].into(), Some(600)),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 1000, &config).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].position().timestamp, 1000);
        assert_eq!(result[1].position().timestamp, 1000);
    }

    #[test]
    fn sequenced_records_future_timestamp_capped() {
        let now = timestamp_now();
        let config = TimestampingConfig {
            mode: TimestampingMode::ClientPrefer,
            uncapped: false,
        };

        let future = now + 10_000;
        let records: StoredAppendRecordBatch =
            vec![test_record(vec![1, 2, 3].into(), Some(future))]
                .try_into()
                .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].position().timestamp <= now + 100);
    }

    #[test]
    fn sequenced_records_future_timestamp_uncapped() {
        let now = timestamp_now();
        let config = TimestampingConfig {
            mode: TimestampingMode::ClientPrefer,
            uncapped: true,
        };

        let future = now + 10_000;
        let records: StoredAppendRecordBatch =
            vec![test_record(vec![1, 2, 3].into(), Some(future))]
                .try_into()
                .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].position().timestamp, future);
    }

    #[test]
    fn sequenced_records_seq_num_assignment() {
        let config = TimestampingConfig::default();

        let records: StoredAppendRecordBatch = vec![
            test_record(vec![1].into(), None),
            test_record(vec![2].into(), None),
            test_record(vec![3].into(), None),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 42, 0, &config).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].position().seq_num, 42);
        assert_eq!(result[1].position().seq_num, 43);
        assert_eq!(result[2].position().seq_num, 44);
    }

    #[test]
    fn sequenced_records_reject_aes256gcm_records_past_random_nonce_limit() {
        let config = TimestampingConfig::default();
        let first_record = test_encrypted_record(
            vec![1, 2, 3].into(),
            None,
            &EncryptionSpec::aes256_gcm([0x24; 32]),
        );
        let max_assignable_seq_num = first_record.parts().record.max_assignable_seq_num();
        let first_rejected_seq_num = max_assignable_seq_num + 1;
        let records: StoredAppendRecordBatch = vec![
            first_record,
            test_encrypted_record(
                vec![4, 5, 6].into(),
                None,
                &EncryptionSpec::aes256_gcm([0x24; 32]),
            ),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, max_assignable_seq_num, 0, &config);

        assert!(matches!(
            result,
            Err(AppendErrorInternal::MaxSeqNum(error))
                if error.first_seq_num == max_assignable_seq_num
                    && error.assigned_seq_num == first_rejected_seq_num
                    && error.max_assignable_seq_num == max_assignable_seq_num
        ));
    }

    #[test]
    fn sequenced_records_allow_aes256gcm_command_records_past_random_nonce_limit() {
        let config = TimestampingConfig::default();
        let max_assignable_seq_num = test_encrypted_record(
            vec![1, 2, 3].into(),
            None,
            &EncryptionSpec::aes256_gcm([0x24; 32]),
        )
        .parts()
        .record
        .max_assignable_seq_num();

        let records: StoredAppendRecordBatch =
            vec![test_command_record(CommandRecord::Trim(42), None)]
                .try_into()
                .unwrap();

        let first_command_seq_num = max_assignable_seq_num + 1;
        let result = sequenced_records(records, first_command_seq_num, 0, &config).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].position().seq_num, first_command_seq_num);
    }

    #[test]
    fn command_state_is_applied_in_excludes_range_start() {
        let state = CommandState {
            applied_point: ..5,
            state: (),
        };

        assert!(!state.is_applied_in(&(5..10)));
        assert!(state.is_applied_in(&(4..10)));
        assert!(state.is_applied_in(&(0..5)));
    }

    fn append_input(body: &[u8]) -> StoredAppendInput {
        StoredAppendInput {
            records: vec![test_record(Bytes::copy_from_slice(body), None)]
                .try_into()
                .expect("valid batch"),
            match_seq_num: None,
            fencing_token: None,
        }
    }

    async fn make_pending_append_durable(streamer: &mut Streamer) {
        let pending = streamer.db_writes_pending.pop_front().unwrap();
        let submitted = pending.future.await.unwrap();
        let seq = submitted.db_seq;
        streamer.inflight_appends.push_back(submitted);
        streamer.db.flush().await.unwrap();
        streamer.on_db_durable_seq_advanced(seq);
    }

    async fn test_streamer() -> Streamer {
        test_streamer_with_settings(Default::default()).await
    }

    async fn test_streamer_with_settings(settings: slatedb::config::Settings) -> Streamer {
        let object_store = Arc::new(InMemory::new());
        let db = slatedb::Db::builder("/test", object_store)
            .with_settings(settings)
            .build()
            .await
            .expect("db");
        let (msg_tx, _msg_rx) = mpsc::unbounded_channel();
        let (bgtask_trigger_tx, _) = broadcast::channel(16);
        let (lease_state, _) = StreamerLeaseState::new();
        Streamer {
            db: db.clone(),
            stream_id: [3u8; StreamId::LEN].into(),
            stream_creation_seq: 0,
            msg_tx,
            config: StreamConfig::default(),
            config_seq: 0,
            last_tail_write_timestamp: TimestampSecs::ZERO,
            fencing_token: CommandState {
                state: FencingToken::default(),
                applied_point: ..SeqNum::MIN,
            },
            trim_point: CommandState {
                state: ..SeqNum::MIN,
                applied_point: ..SeqNum::MIN,
            },
            db_writes_pending: VecDeque::new(),
            db_durability_subscription: 0,
            inflight_appends: VecDeque::new(),
            pending_appends: append::PendingAppends::new(),
            stable_pos: StreamPosition::MIN,
            follow_tx: broadcast::Sender::new(super::super::FOLLOWER_MAX_LAG),
            lease_state,
            durability_notifier: DurabilityNotifier::spawn(&db),
            bgtask_trigger_tx,
        }
    }

    #[tokio::test]
    async fn stale_config_notifications_cannot_restore_old_retention() {
        let mut streamer = test_streamer().await;
        let db = streamer.db.clone();
        let stream_id = streamer.stream_id;
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        streamer.msg_tx = msg_tx.clone();
        streamer.config.retention_policy = RetentionPolicy::Age(Duration::from_secs(1));
        let task = tokio::spawn(streamer.run(msg_rx));
        msg_tx
            .send(Message::Reconfigure {
                seq: 20,
                config: StreamConfig {
                    retention_policy: RetentionPolicy::Infinite(),
                    ..Default::default()
                },
            })
            .unwrap();
        let old = StreamConfig {
            retention_policy: RetentionPolicy::Age(Duration::from_secs(1)),
            ..Default::default()
        };
        msg_tx
            .send(Message::Reconfigure {
                seq: 10,
                config: old,
            })
            .unwrap();
        let (reply_tx, reply_rx) = oneshot::channel();
        msg_tx
            .send(Message::Append {
                input: append_input(b"must not expire"),
                session: None,
                reply_tx,
                append_type: AppendType::Regular,
            })
            .unwrap();
        let ack = tokio::time::timeout(Duration::from_secs(5), reply_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let entry = db
            .get_key_value(kv::stream_record_data::ser_key(stream_id, ack.start))
            .await
            .unwrap()
            .unwrap();
        assert!(
            entry.expire_ts.is_none(),
            "late config notification restored stale retention"
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        db.close().await.unwrap();
    }

    #[test]
    fn lease_state_closes_when_idle_and_rejects_new_leases() {
        let (streamer_lease_state, client_lease_state) = StreamerLeaseState::new();

        let lease = client_lease_state
            .try_acquire()
            .expect("first lease should succeed");
        assert!(
            !streamer_lease_state.close_if_idle(),
            "an outstanding lease should keep the state open"
        );

        drop(lease);

        assert!(
            streamer_lease_state.close_if_idle(),
            "an idle state should close once dormancy wins"
        );
        assert!(client_lease_state.is_closed());
        assert!(matches!(
            client_lease_state.try_acquire(),
            Err(StreamerMissingInActionError)
        ));
    }

    #[test]
    fn streamer_lease_state_drop_blocks_new_leases_while_existing_guard_drops_cleanly() {
        let (streamer_lease_state, client_lease_state) = StreamerLeaseState::new();

        let lease = client_lease_state
            .try_acquire()
            .expect("first lease should succeed");
        drop(streamer_lease_state);

        assert!(matches!(
            client_lease_state.try_acquire(),
            Err(StreamerMissingInActionError)
        ));

        drop(lease);
        assert!(client_lease_state.is_closed());
    }

    #[tokio::test]
    async fn terminal_trim_and_rejections_wait_for_durability() {
        let mut streamer = test_streamer_with_settings(slatedb::config::Settings {
            flush_interval: None,
            ..Default::default()
        })
        .await;
        let mut replies = Vec::new();
        for _ in 0..2 {
            let (tx, rx) = oneshot::channel();
            streamer.handle_terminal_trim(TerminalTrimCondition::Always, tx);
            replies.push(rx);
        }
        // An empty-stream check can also finish after another deletion request starts.
        let (tx, rx) = oneshot::channel();
        streamer.handle_doe_check_result(
            StreamPosition::MIN,
            streamer.config_seq,
            Ok(RecordPresence::Empty),
            tx,
        );
        replies.push(rx);

        let (tx, mut append_reply) = oneshot::channel();
        streamer.handle_append(append_input(b"late"), None, tx, AppendType::Regular, None);
        assert_eq!(streamer.db_writes_pending.len(), 1);
        tokio::task::yield_now().await;
        assert!(matches!(
            append_reply.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        for reply in &mut replies {
            assert!(
                matches!(reply.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
                "stream deletion must wait even when the original trim has not been submitted"
            );
        }

        let pending = streamer.db_writes_pending.pop_front().unwrap();
        let submitted = pending.future.await.unwrap();
        let db_seq = submitted.db_seq;
        streamer.inflight_appends.push_back(submitted);
        tokio::task::yield_now().await;
        assert!(matches!(
            append_reply.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        for reply in &mut replies {
            assert!(
                matches!(reply.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
                "a committed but unflushed trim must not acknowledge stream deletion"
            );
        }
        streamer.db.flush().await.unwrap();
        streamer.on_db_durable_seq_advanced(db_seq);
        assert!(matches!(
            append_reply.await.unwrap(),
            Err(AppendErrorInternal::StreamDeletionPending { .. })
        ));
        for reply in replies {
            assert_eq!(
                reply.await.unwrap().unwrap(),
                TerminalTrimOutcome::DeletionPending
            );
        }
        streamer.db.close().await.unwrap();
    }

    #[rstest::rstest]
    #[case::pending_before_scan(false, false)]
    #[case::pending_after_scan(true, false)]
    #[case::durable_after_scan(true, true)]
    #[tokio::test]
    async fn delete_on_empty_uses_nonempty_observation_despite_appends(
        #[case] append_after_scan: bool,
        #[case] durable: bool,
        #[values(false, true)] infinite: bool,
    ) {
        let mut streamer = test_streamer().await;
        streamer.config.delete_on_empty.min_age = Duration::from_secs(60);
        streamer.config.retention_policy = if infinite {
            RetentionPolicy::Infinite()
        } else {
            RetentionPolicy::Age(Duration::from_secs(3600))
        };
        let (seed_tx, seed_rx) = oneshot::channel();
        streamer.handle_append(
            append_input(b"observed record"),
            None,
            seed_tx,
            AppendType::Regular,
            None,
        );
        make_pending_append_durable(&mut streamer).await;
        seed_rx.await.unwrap().unwrap();

        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel();
        streamer.msg_tx = msg_tx;
        let (append_tx, append_rx) = oneshot::channel();
        // Keep the sender until the selected point in the asynchronous check.
        let mut append_tx = Some(append_tx);
        if !append_after_scan {
            streamer.handle_append(
                append_input(b"pending before scan"),
                None,
                append_tx.take().unwrap(),
                AppendType::Regular,
                None,
            );
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        streamer.handle_terminal_trim(
            TerminalTrimCondition::DeleteOnEmpty {
                expected_stream_creation_seq: streamer.stream_creation_seq,
                expected_config_seq: streamer.config_seq,
            },
            reply_tx,
        );
        let Message::DeleteOnEmptyCheckResult {
            stable_pos_snapshot,
            config_seq_snapshot,
            records,
            reply_tx,
        } = msg_rx.recv().await.unwrap()
        else {
            panic!("expected record check even with a pending append");
        };
        if append_after_scan {
            streamer.handle_append(
                append_input(b"arrived after scan"),
                None,
                append_tx.take().unwrap(),
                AppendType::Regular,
                None,
            );
        }
        if durable {
            make_pending_append_durable(&mut streamer).await;
            append_rx.await.unwrap().unwrap();
        }
        streamer.handle_doe_check_result(
            stable_pos_snapshot,
            config_seq_snapshot,
            records,
            reply_tx,
        );
        assert_eq!(streamer.db_writes_pending.len(), usize::from(!durable));
        assert_ne!(streamer.trim_point.state.end, SeqNum::MAX);
        let outcome = reply_rx.await.unwrap().unwrap();
        if infinite {
            assert_eq!(outcome, TerminalTrimOutcome::Parked);
        } else {
            assert!(matches!(
                outcome,
                TerminalTrimOutcome::RetryAt(at)
                    if at > TimestampSecs::after(Duration::from_secs(3500))
            ));
        }
        streamer.db.close().await.unwrap();
    }

    #[rstest::rstest]
    #[case::pending_before_scan(false, false)]
    #[case::pending_after_scan(true, false)]
    #[case::durable_after_scan(true, true)]
    #[tokio::test]
    async fn delete_on_empty_rechecks_appends_after_empty_scan(
        #[case] append_after_scan: bool,
        #[case] durable: bool,
    ) {
        let mut streamer = test_streamer().await;
        streamer.config.delete_on_empty.min_age = Duration::from_secs(1);
        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel();
        streamer.msg_tx = msg_tx;
        let (append_tx, append_rx) = oneshot::channel();
        let mut append_tx = Some(append_tx);
        if !append_after_scan {
            streamer.handle_append(
                append_input(b"pending before scan"),
                None,
                append_tx.take().unwrap(),
                AppendType::Regular,
                None,
            );
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        streamer.handle_terminal_trim(
            TerminalTrimCondition::DeleteOnEmpty {
                expected_stream_creation_seq: 0,
                expected_config_seq: 0,
            },
            reply_tx,
        );
        let Message::DeleteOnEmptyCheckResult {
            stable_pos_snapshot,
            config_seq_snapshot,
            records,
            reply_tx,
        } = msg_rx.recv().await.unwrap()
        else {
            panic!("expected empty-stream check result");
        };
        assert_eq!(records.as_ref().unwrap(), &RecordPresence::Empty);
        if append_after_scan {
            streamer.handle_append(
                append_input(b"arrived during scan"),
                None,
                append_tx.take().unwrap(),
                AppendType::Regular,
                None,
            );
        }
        if durable {
            make_pending_append_durable(&mut streamer).await;
            append_rx.await.unwrap().unwrap();
        }
        // Let the minimum age elapse so it cannot mask a missing tail check.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        streamer.handle_doe_check_result(
            stable_pos_snapshot,
            config_seq_snapshot,
            records,
            reply_tx,
        );
        assert_eq!(streamer.db_writes_pending.len(), usize::from(!durable));
        assert_ne!(streamer.trim_point.state.end, SeqNum::MAX);
        assert!(matches!(
            reply_rx.await.unwrap().unwrap(),
            TerminalTrimOutcome::RetryAt(_)
        ));
        streamer.db.close().await.unwrap();
    }

    #[rstest::rstest]
    #[case::actor_behind(0, 1)]
    #[case::worker_behind(1, 0)]
    #[tokio::test]
    async fn delete_on_empty_bounds_retry_for_stale_config(
        #[case] actor_seq: u64,
        #[case] worker_seq: u64,
    ) {
        let mut streamer = test_streamer().await;
        streamer.config.delete_on_empty.min_age = Duration::from_secs(365 * 24 * 3600);
        streamer.last_tail_write_timestamp = TimestampSecs::now();
        streamer.config_seq = actor_seq;
        let earliest_retry = TimestampSecs::after(doe::RETRY_INTERVAL);
        let (reply_tx, reply_rx) = oneshot::channel();
        streamer.handle_terminal_trim(
            TerminalTrimCondition::DeleteOnEmpty {
                expected_stream_creation_seq: 0,
                expected_config_seq: worker_seq,
            },
            reply_tx,
        );
        let TerminalTrimOutcome::RetryAt(at) = reply_rx.await.unwrap().unwrap() else {
            panic!("expected a bounded retry for mismatched configuration");
        };
        assert!(at >= earliest_retry && at <= TimestampSecs::after(doe::RETRY_INTERVAL));
        assert!(streamer.db_writes_pending.is_empty());
        streamer.db.close().await.unwrap();
    }

    #[tokio::test]
    async fn delete_on_empty_bounds_retry_when_config_changes_during_scan() {
        let mut streamer = test_streamer().await;
        streamer.config.delete_on_empty.min_age = Duration::from_secs(365 * 24 * 3600);
        streamer.last_tail_write_timestamp = TimestampSecs::now();
        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel();
        streamer.msg_tx = msg_tx;
        let (reply_tx, reply_rx) = oneshot::channel();
        streamer.handle_terminal_trim(
            TerminalTrimCondition::DeleteOnEmpty {
                expected_stream_creation_seq: 0,
                expected_config_seq: 0,
            },
            reply_tx,
        );
        let Message::DeleteOnEmptyCheckResult {
            stable_pos_snapshot,
            config_seq_snapshot,
            records,
            reply_tx,
        } = msg_rx.recv().await.unwrap()
        else {
            panic!("expected record check");
        };
        streamer.config_seq += 1;
        let earliest_retry = TimestampSecs::after(doe::RETRY_INTERVAL);
        streamer.handle_doe_check_result(
            stable_pos_snapshot,
            config_seq_snapshot,
            records,
            reply_tx,
        );
        let TerminalTrimOutcome::RetryAt(at) = reply_rx.await.unwrap().unwrap() else {
            panic!("expected a bounded retry for mismatched configuration");
        };
        assert!(at >= earliest_retry && at <= TimestampSecs::after(doe::RETRY_INTERVAL));
        assert!(streamer.db_writes_pending.is_empty());
        streamer.db.close().await.unwrap();
    }

    /// Write the `stream_id_mapping` and `stream_meta` rows that the
    /// config-guarded terminal trim transaction reads, returning the committed
    /// sequence number of the `stream_meta` row (the DOE-observed config revision).
    async fn seed_serializable_stream(
        streamer: &Streamer,
        min_age: Duration,
    ) -> (
        s2_common::basin::BasinName,
        s2_common::stream::StreamName,
        u64,
    ) {
        use std::str::FromStr as _;

        use time::OffsetDateTime;
        let basin = s2_common::basin::BasinName::from_str("test-basin").unwrap();
        let stream = s2_common::stream::StreamName::from_str("test-stream").unwrap();
        let meta = kv::stream_meta::StreamMeta {
            config: StreamConfig {
                delete_on_empty: s2_common::config::DeleteOnEmptyConfig { min_age },
                ..Default::default()
            },
            cipher: None,
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
            creation_idempotency_key: None,
        };
        streamer
            .db
            .put(
                kv::stream_id_mapping::ser_key(streamer.stream_id),
                kv::stream_id_mapping::ser_value(&basin, &stream),
            )
            .await
            .unwrap()
            .await_durable()
            .await
            .unwrap();
        // The stream_meta write must be the most recent durable commit so its
        // sequence equals the observed config revision.
        let handle = streamer
            .db
            .put(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::ser_value(&meta),
            )
            .await
            .unwrap();
        handle.await_durable().await.unwrap();
        let observed = streamer
            .db
            .get_key_value(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream_meta was just written")
            .seq;
        (basin, stream, observed)
    }

    async fn read_trim_point(
        db: &slatedb::Db,
        stream_id: StreamId,
    ) -> Option<std::ops::RangeTo<NonZeroSeqNum>> {
        db.get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap()
            .map(|bytes| kv::stream_trim_point::deser_value(bytes).expect("decode trim point"))
    }

    // Regression guard for the happy path: the config-guarded terminal trim
    // commits when the stream configuration revision has not changed since the
    // DOE check observed it. Without this test, a broken guard could silently
    // drop every DOE deletion.
    #[tokio::test]
    async fn terminal_trim_with_config_guard_commits_when_config_unchanged() {
        let mut streamer = test_streamer().await;
        let stream_id = streamer.stream_id;
        streamer.config.delete_on_empty.min_age = Duration::from_secs(1);
        streamer.last_tail_write_timestamp = TimestampSecs::ZERO;
        let (_, _, observed_config_seq) =
            seed_serializable_stream(&streamer, Duration::from_secs(1)).await;
        let expected_creation_seq = streamer.stream_creation_seq;
        streamer.config_seq = observed_config_seq;

        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel();
        streamer.msg_tx = msg_tx;
        let (trim_reply_tx, trim_reply_rx) = oneshot::channel();
        streamer.handle_terminal_trim(
            TerminalTrimCondition::DeleteOnEmpty {
                expected_stream_creation_seq: expected_creation_seq,
                expected_config_seq: observed_config_seq,
            },
            trim_reply_tx,
        );
        let Message::DeleteOnEmptyCheckResult {
            stable_pos_snapshot,
            config_seq_snapshot,
            records,
            reply_tx,
        } = msg_rx.recv().await.unwrap()
        else {
            panic!("expected scan to complete");
        };
        assert_eq!(records.as_ref().unwrap(), &RecordPresence::Empty);
        // Let the minimum age elapse so the stream is old enough to delete.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        // Leave config_seq unchanged so the in-memory guard does not reject.
        streamer.handle_doe_check_result(
            stable_pos_snapshot,
            config_seq_snapshot,
            records,
            reply_tx,
        );
        assert_eq!(streamer.db_writes_pending.len(), 1);
        assert_eq!(streamer.trim_point.state.end, SeqNum::MAX);

        let pending = streamer.db_writes_pending.pop_front().unwrap();
        assert!(pending.config_guard.is_some());
        let submitted = pending.future.await.unwrap();
        let db_seq = submitted.db_seq;
        streamer.inflight_appends.push_back(submitted);
        streamer.db.flush().await.unwrap();
        streamer.on_db_durable_seq_advanced(db_seq);
        assert_eq!(
            read_trim_point(&streamer.db, stream_id).await,
            Some(..NonZeroSeqNum::MAX),
        );
        assert_eq!(
            trim_reply_rx.await.unwrap().unwrap(),
            TerminalTrimOutcome::DeletionPending,
        );
        streamer.db.close().await.unwrap();
    }

    // The bug: `handle_doe_check_result` can fire `ensure_terminal_trim` while
    // the actor still holds the stale configuration (Message::Reconfigure has
    // not reached the mailbox). After the fix, the terminal trim append
    // transactionally revalidates the configuration revision and aborts as a
    // transaction conflict when a concurrent reconfigure already incremented
    // `stream_meta.seq`. The run loop reverts the trim_point mutation and
    // returns `RetryAt` instead of destroying the stream under the old min_age.
    #[tokio::test]
    async fn terminal_trim_with_config_guard_aborts_when_config_changed() {
        let mut streamer = test_streamer().await;
        let stream_id = streamer.stream_id;
        streamer.config.delete_on_empty.min_age = Duration::from_secs(1);
        streamer.last_tail_write_timestamp = TimestampSecs::ZERO;
        let (basin, stream, observed_config_seq) =
            seed_serializable_stream(&streamer, Duration::from_secs(1)).await;
        let expected_creation_seq = streamer.stream_creation_seq;
        streamer.config_seq = observed_config_seq;

        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel();
        streamer.msg_tx = msg_tx;
        let (trim_reply_tx, trim_reply_rx) = oneshot::channel();
        streamer.handle_terminal_trim(
            TerminalTrimCondition::DeleteOnEmpty {
                expected_stream_creation_seq: expected_creation_seq,
                expected_config_seq: observed_config_seq,
            },
            trim_reply_tx,
        );
        let Message::DeleteOnEmptyCheckResult {
            stable_pos_snapshot,
            config_seq_snapshot,
            records,
            reply_tx,
        } = msg_rx.recv().await.unwrap()
        else {
            panic!("expected scan to complete");
        };
        assert_eq!(records.as_ref().unwrap(), &RecordPresence::Empty);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        // Capture the pre-trim actor state, then leave config_seq unchanged so
        // handle_doe_check_result proceeds to ensure_terminal_trim (the actor
        // has not processed Reconfigure yet).
        let prev_next_ack_pos = streamer.pending_appends.next_ack_pos();
        let prev_trim_point = streamer.trim_point.clone();
        streamer.handle_doe_check_result(
            stable_pos_snapshot,
            config_seq_snapshot,
            records,
            reply_tx,
        );
        assert_eq!(streamer.db_writes_pending.len(), 1);
        assert_eq!(streamer.trim_point.state.end, SeqNum::MAX);

        // Simulate a concurrent ReconfigureStream that successfully commits a
        // new (larger) min_age, bumping stream_meta.seq, AFTER the DOE scan
        // completed but BEFORE the actor's terminal trim write is submitted.
        let bumped_meta = kv::stream_meta::StreamMeta {
            config: StreamConfig {
                delete_on_empty: s2_common::config::DeleteOnEmptyConfig {
                    min_age: Duration::from_secs(3600),
                },
                ..Default::default()
            },
            cipher: None,
            created_at: time::OffsetDateTime::now_utc(),
            deleted_at: None,
            creation_idempotency_key: None,
        };
        streamer
            .db
            .put(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::ser_value(&bumped_meta),
            )
            .await
            .unwrap()
            .await_durable()
            .await
            .unwrap();
        let bumped_seq = streamer
            .db
            .get_key_value(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .unwrap()
            .seq;
        assert_ne!(bumped_seq, observed_config_seq);

        // Drain the pending write exactly like the run loop does. The
        // transaction must detect the config drift and abort, instead of
        // committing an irrevocable terminal trim marker.
        let pending = streamer.db_writes_pending.pop_front().unwrap();
        let guard = pending.config_guard.expect("config guard captured");
        let result = pending.future.await;
        assert_eq!(result.unwrap_err().kind(), slatedb::ErrorKind::Transaction);

        // Run-loop conflict handler: revert the actor state and reject the
        // terminal-trim append so DOE can retry under the larger min_age.
        streamer.trim_point = guard.prev_trim_point;
        streamer.pending_appends.retract_last(
            AppendErrorInternal::DeleteOnEmptyConfigConflict,
            guard.prev_next_ack_pos,
        );

        // The irrevocable terminal trim marker must NOT be durable in SlateDB.
        assert_eq!(read_trim_point(&streamer.db, stream_id).await, None);
        // The actor's trim_point must be reverted so further appends succeed.
        assert_ne!(streamer.trim_point.state.end, SeqNum::MAX);
        assert_eq!(
            streamer.trim_point.state, prev_trim_point.state,
            "trim_point state must be restored to its pre-trim value"
        );
        assert_eq!(
            streamer.trim_point.applied_point, prev_trim_point.applied_point,
            "trim_point applied_point must be restored"
        );
        // The pending-append cursor must be restored so further appends
        // continue from the previous position.
        assert_eq!(
            streamer.pending_appends.next_ack_pos(),
            prev_next_ack_pos,
            "next_ack_pos must be restored"
        );

        match trim_reply_rx.await.unwrap().unwrap() {
            TerminalTrimOutcome::RetryAt(at) => {
                assert!(
                    at >= TimestampSecs::after(
                        doe::RETRY_INTERVAL.saturating_sub(Duration::from_secs(1))
                    ),
                    "retry should let the DOE tick re-evaluate under the new min_age"
                );
            }
            other => panic!("expected RetryAt, got {other:?}"),
        }
        streamer.db.close().await.unwrap();
    }

    // End-to-end through the run loop: when the config-guarded trim transaction
    // conflicts, the run loop reverts the trim_point mutation, retracts the
    // pending append, and returns RetryAt without breaking the streamer. This
    // exercises the actual select! branch added for the conflict case.
    //
    // Determinism: stream_meta.seq is bumped BEFORE the run loop processes the
    // DeleteOnEmptyCheckResult, so the actor's in-memory config_seq still
    // matches the (stale) snapshot, but the trim transaction observes the new
    // stream_meta.seq when it reads and aborts as a transaction conflict.
    #[tokio::test]
    async fn terminal_trim_conflict_reverts_state_via_run_loop() {
        let mut streamer = test_streamer().await;
        let stream_id = streamer.stream_id;
        // The min_age slice is wall-clock based; with last_tail_write_timestamp
        // at the epoch, the stream is always old enough at first observation.
        streamer.config.delete_on_empty.min_age = Duration::from_millis(1);
        streamer.last_tail_write_timestamp = TimestampSecs::ZERO;
        let (basin, stream, observed_config_seq) =
            seed_serializable_stream(&streamer, Duration::from_millis(1)).await;
        streamer.config_seq = observed_config_seq;

        // Simulate the reconfigure that commits the increased min_age BEFORE
        // the run loop processes the DeleteOnEmptyCheckResult. The actor's
        // in-memory config_seq still matches the snapshot, so the DOE check
        // proceeds to ensure_terminal_trim, but the trim transaction will see
        // the newer stream_meta.seq and conflict.
        let bumped_meta = kv::stream_meta::StreamMeta {
            config: StreamConfig {
                delete_on_empty: s2_common::config::DeleteOnEmptyConfig {
                    min_age: Duration::from_secs(3600),
                },
                ..Default::default()
            },
            cipher: None,
            created_at: time::OffsetDateTime::now_utc(),
            deleted_at: None,
            creation_idempotency_key: None,
        };
        streamer
            .db
            .put(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::ser_value(&bumped_meta),
            )
            .await
            .unwrap()
            .await_durable()
            .await
            .unwrap();
        let bumped_seq = streamer
            .db
            .get_key_value(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .unwrap()
            .seq;
        assert_ne!(bumped_seq, observed_config_seq);

        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        streamer.msg_tx = msg_tx.clone();
        let db_clone = streamer.db.clone();
        let (trim_reply_tx, trim_reply_rx) = oneshot::channel();
        // Drive the terminal-trim path through the live run loop so the
        // select! branch for transaction conflicts is exercised.
        streamer.handle_terminal_trim(
            TerminalTrimCondition::DeleteOnEmpty {
                expected_stream_creation_seq: streamer.stream_creation_seq,
                expected_config_seq: observed_config_seq,
            },
            trim_reply_tx,
        );
        let task = tokio::spawn(streamer.run(msg_rx));

        // Let the run loop process the concatenated sequence: DeleteOnEmpty
        // scan completes (the stream is empty), mailbox delivers the result,
        // handle_doe_check_result fires ensure_terminal_trim with the stale
        // config_seq_guard, and the trim transaction conflicts and reverts.
        let outcome = tokio::time::timeout(Duration::from_secs(30), trim_reply_rx)
            .await
            .expect("reply must be delivered")
            .expect("reply channel not dropped")
            .expect("DOE outcome must be Ok");
        assert!(
            matches!(outcome, TerminalTrimOutcome::RetryAt(_)),
            "expected RetryAt after config-gated trim abort, got {outcome:?}"
        );

        // The irrevocable terminal trim marker must not be durable.
        assert_eq!(read_trim_point(&db_clone, stream_id).await, None);

        task.abort();
        db_clone.close().await.unwrap();
    }

    #[tokio::test]
    async fn append_acks_release_only_after_durable_seq_and_in_order() {
        let mut streamer = test_streamer().await;
        let mut follow_rx = streamer.follow_tx.subscribe();

        let (tx1, mut rx1) = oneshot::channel();
        streamer.handle_append(append_input(b"p0"), None, tx1, AppendType::Regular, None);

        let (tx2, mut rx2) = oneshot::channel();
        streamer.handle_append(append_input(b"p1"), None, tx2, AppendType::Regular, None);

        let (tx3, mut rx3) = oneshot::channel();
        streamer.handle_append(append_input(b"p2"), None, tx3, AppendType::Regular, None);

        let mut db_seqs = Vec::new();
        while let Some(pending) = streamer.db_writes_pending.pop_front() {
            let submitted = pending.future.await.expect("db submit");
            db_seqs.push(submitted.db_seq);
            streamer.inflight_appends.push_back(submitted);
        }
        assert_eq!(db_seqs.len(), 3);
        assert!(db_seqs.windows(2).all(|w| w[0] < w[1]));
        assert!(matches!(
            rx1.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            rx2.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            rx3.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        let first_seq = db_seqs[0];
        if first_seq > 0 {
            streamer.on_db_durable_seq_advanced(first_seq - 1);
            assert!(matches!(
                rx1.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ));
        }

        streamer.on_db_durable_seq_advanced(first_seq);
        let ack1 = rx1.await.expect("ack 1").expect("append ack 1");
        assert_eq!(ack1.start.seq_num, 0);
        assert_eq!(ack1.end.seq_num, 1);
        assert_eq!(ack1.tail.seq_num, 1);
        assert!(matches!(
            rx2.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            rx3.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        let batch1 = follow_rx.recv().await.expect("follow batch 1");
        assert_eq!(batch1.len(), 1);
        let StoredRecord::Plaintext(Record::Envelope(env)) = batch1[0].inner() else {
            panic!("expected envelope")
        };
        assert_eq!(env.body().as_ref(), b"p0");

        streamer.on_db_durable_seq_advanced(db_seqs[2]);
        let ack2 = rx2.await.expect("ack 2").expect("append ack 2");
        let ack3 = rx3.await.expect("ack 3").expect("append ack 3");
        assert_eq!(ack2.start.seq_num, 1);
        assert_eq!(ack2.end.seq_num, 2);
        assert_eq!(ack3.start.seq_num, 2);
        assert_eq!(ack3.end.seq_num, 3);
        assert_eq!(streamer.stable_pos.seq_num, 3);
        assert!(streamer.inflight_appends.is_empty());

        let batch2 = follow_rx.recv().await.expect("follow batch 2");
        let batch3 = follow_rx.recv().await.expect("follow batch 3");
        let StoredRecord::Plaintext(Record::Envelope(env2)) = batch2[0].inner() else {
            panic!("expected envelope")
        };
        let StoredRecord::Plaintext(Record::Envelope(env3)) = batch3[0].inner() else {
            panic!("expected envelope")
        };
        assert_eq!(env2.body().as_ref(), b"p1");
        assert_eq!(env3.body().as_ref(), b"p2");
    }

    #[tokio::test]
    async fn durable_seq_jump_releases_multiple_inflight_batches() {
        let mut streamer = test_streamer().await;
        let mut follow_rx = streamer.follow_tx.subscribe();
        let mut ack_rxs = Vec::new();

        for i in 0..4 {
            let (tx, rx) = oneshot::channel();
            ack_rxs.push(rx);
            let payload = format!("jump-{i}");
            streamer.handle_append(
                append_input(payload.as_bytes()),
                None,
                tx,
                AppendType::Regular,
                None,
            );
        }

        let mut db_seqs = Vec::new();
        while let Some(pending) = streamer.db_writes_pending.pop_front() {
            let submitted = pending.future.await.expect("db submit");
            db_seqs.push(submitted.db_seq);
            streamer.inflight_appends.push_back(submitted);
        }
        assert_eq!(db_seqs.len(), 4);

        streamer.on_db_durable_seq_advanced(*db_seqs.last().expect("non-empty"));

        for (i, rx) in ack_rxs.into_iter().enumerate() {
            let ack = rx.await.expect("ack").expect("append ack");
            assert_eq!(ack.start.seq_num, i as u64);
            assert_eq!(ack.end.seq_num, i as u64 + 1);
        }

        for i in 0..4 {
            let batch = follow_rx.recv().await.expect("follow batch");
            let StoredRecord::Plaintext(Record::Envelope(env)) = batch[0].inner() else {
                panic!("expected envelope")
            };
            assert_eq!(env.body(), format!("jump-{i}").as_bytes());
        }
        assert_eq!(streamer.stable_pos.seq_num, 4);
        assert!(streamer.inflight_appends.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_append_delays_dormancy_until_writes_are_durable() {
        let mut streamer = test_streamer_with_settings(slatedb::config::Settings {
            flush_interval: None,
            ..Default::default()
        })
        .await;
        let db = streamer.db.clone();
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        streamer.msg_tx = msg_tx;

        let (reply_tx, reply_rx) = oneshot::channel();
        streamer.handle_append(
            append_input(b"cancelled"),
            None,
            reply_tx,
            AppendType::Regular,
            None,
        );
        let task = tokio::spawn(streamer.run(msg_rx));
        tokio::time::timeout(Duration::from_secs(5), async {
            while db.snapshot().await.unwrap().seq() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(reply_rx);
        tokio::time::sleep(DORMANT_TIMEOUT + Duration::from_secs(1)).await;
        assert_eq!(
            db.status().durable_seq,
            0,
            "the write must still be unflushed"
        );
        assert!(
            !task.is_finished(),
            "dormancy abandoned an unflushed append"
        );

        db.flush().await.unwrap();
        tokio::time::timeout(DORMANT_TIMEOUT + Duration::from_secs(1), task)
            .await
            .expect("durable writes should allow normal dormancy")
            .unwrap();
        db.close().await.unwrap();
    }
}
