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
    encryption::EncryptionAlgorithm,
    record::{
        CommandRecord, FencingToken, Metered, MeteredSize, NonZeroSeqNum, Record, SeqNum,
        StoredRecord, StoredSequencedRecord, StreamPosition, Timestamp,
    },
    types::{
        config::{RetentionPolicy, StreamConfig, TimestampingConfig, TimestampingMode},
        stream::{
            AppendAck, StoredAppendInput, StoredAppendRecord, StoredAppendRecordBatch,
            StoredAppendRecordParts,
        },
    },
};
use slatedb::{
    IterationOrder, WriteBatch,
    config::{PutOptions, ScanOptions, Ttl, WriteOptions},
};
use tokio::{
    sync::{Semaphore, SemaphorePermit, broadcast, mpsc, oneshot},
    time::Instant,
};

use crate::{
    backend::{
        append,
        bgtasks::BgtaskTrigger,
        durability_notifier::DurabilityNotifier,
        error::{
            AppendConditionFailedError, AppendErrorInternal, AppendTimestampRequiredError,
            DeleteStreamError, MaxSeqNumError, RequestDroppedError, StorageError,
            StreamDeletionPendingError, StreamerMissingInActionError,
        },
        kv,
    },
    metrics,
    stream_id::StreamId,
};

pub(super) const DORMANT_TIMEOUT: Duration = Duration::from_secs(60);
// Rate-limit delete-on-empty scheduling and pad deadlines to cover the period.
const DOE_DEADLINE_REFRESH_PERIOD: Duration = Duration::from_secs(600);

pub(super) fn doe_arm_delay(base_delay: Duration, min_age: Duration) -> Duration {
    base_delay
        .saturating_add(min_age)
        .saturating_add(DOE_DEADLINE_REFRESH_PERIOD)
}

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
    doe_deadline: Option<kv::stream_doe_deadline::Entry>,
    fencing_token: Option<FencingToken>,
    trim_point: Option<RangeTo<SeqNum>>,
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
    pub config: StreamConfig,
    pub cipher: Option<EncryptionAlgorithm>,
    pub tail_pos: StreamPosition,
    pub last_tail_write_timestamp: kv::timestamp::TimestampSecs,
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
            config,
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
            msg_tx: msg_tx.clone(),
            config,
            last_tail_write_timestamp,
            fencing_token: CommandState {
                state: fencing_token,
                applied_point: ..tail_pos.seq_num,
            },
            trim_point: CommandState {
                state: trim_point,
                applied_point: ..tail_pos.seq_num,
            },
            last_doe_deadline_at: None,
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
    msg_tx: mpsc::UnboundedSender<Message>,
    config: StreamConfig,
    last_tail_write_timestamp: kv::timestamp::TimestampSecs,
    fencing_token: CommandState<FencingToken>,
    trim_point: CommandState<RangeTo<SeqNum>>,
    last_doe_deadline_at: Option<Instant>,
    db_writes_pending: VecDeque<BoxFuture<'static, Result<InFlightAppend, slatedb::Error>>>,
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
        reply_tx: impl append::ReplySender,
        append_type: AppendType,
    ) {
        let Some(ticket) = append::admit(reply_tx, session) else {
            return;
        };
        let sequenced_records = if self.trim_point.state.end == SeqNum::MAX {
            Err(StreamDeletionPendingError.into())
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
                for sr in sequenced_records.iter() {
                    if let StoredRecord::Plaintext(Record::Command(cmd)) = sr.inner() {
                        self.apply_command(sr.position().seq_num, cmd, append_type);
                    }
                }
                let (first_pos, next_pos) = pos_span(&sequenced_records);
                let seq_num_range = first_pos.seq_num..next_pos.seq_num;
                let opts = DbSubmitAppendOptions {
                    retention: self.config.retention_policy,
                    doe_deadline: self.doe_deadline_maybe(),
                    fencing_token: self
                        .fencing_token
                        .is_applied_in(&seq_num_range)
                        .then(|| self.fencing_token.state.clone()),
                    trim_point: self
                        .trim_point
                        .is_applied_in(&seq_num_range)
                        .then_some(self.trim_point.state),
                };
                self.db_writes_pending.push_back(
                    db_submit_append(self.db.clone(), self.stream_id, sequenced_records, opts)
                        .boxed(),
                );
                self.pending_appends.accept(ticket, first_pos..next_pos);
                self.last_tail_write_timestamp = kv::timestamp::TimestampSecs::now();
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
                self.append_terminal_trim(reply_tx);
            }
            TerminalTrimCondition::DeleteOnEmpty { last_write_cutoff } => {
                if self.last_tail_write_timestamp > last_write_cutoff
                    || self.next_assignable_pos().seq_num != self.stable_pos.seq_num
                {
                    let _ = reply_tx.send(Ok(TerminalTrimOutcome::Ineligible));
                    return;
                }

                let db = self.db.clone();
                let stream_id = self.stream_id;
                let stable_pos_snapshot = self.stable_pos;
                let msg_tx = self.msg_tx.clone();
                tokio::spawn(async move {
                    let has_records = stream_has_records(&db, stream_id).await;
                    let _ = msg_tx.send(Message::DeleteOnEmptyCheckResult {
                        stable_pos_snapshot,
                        last_write_cutoff,
                        has_records,
                        reply_tx,
                    });
                });
            }
        }
    }

    fn handle_doe_check_result(
        &mut self,
        stable_pos_snapshot: StreamPosition,
        last_write_cutoff: kv::timestamp::TimestampSecs,
        has_records: Result<bool, StorageError>,
        reply_tx: oneshot::Sender<Result<TerminalTrimOutcome, DeleteStreamError>>,
    ) {
        match has_records {
            Ok(true) => {
                let _ = reply_tx.send(Ok(TerminalTrimOutcome::Ineligible));
            }
            Ok(false) => {
                if self.trim_point.state.end == SeqNum::MAX {
                    let _ = reply_tx.send(Ok(TerminalTrimOutcome::DeletionPending));
                } else if self.stable_pos != stable_pos_snapshot
                    || self.next_assignable_pos() != stable_pos_snapshot
                    || self.last_tail_write_timestamp > last_write_cutoff
                {
                    let _ = reply_tx.send(Ok(TerminalTrimOutcome::Ineligible));
                } else {
                    self.append_terminal_trim(reply_tx);
                }
            }
            Err(err) => {
                let _ = reply_tx.send(Err(err.into()));
            }
        }
    }

    fn append_terminal_trim(
        &mut self,
        reply_tx: oneshot::Sender<Result<TerminalTrimOutcome, DeleteStreamError>>,
    ) {
        self.handle_append(
            terminal_trim_input(),
            None,
            TerminalTrimReplySender(reply_tx),
            AppendType::Terminal,
        );
    }

    fn doe_deadline_maybe(&mut self) -> Option<kv::stream_doe_deadline::Entry> {
        let retention_age = self.config.retention_policy.age()?;
        let min_age = self.config.delete_on_empty.min_age()?;
        let now = Instant::now();
        if self
            .last_doe_deadline_at
            .is_none_or(|t| now.duration_since(t) >= DOE_DEADLINE_REFRESH_PERIOD)
        {
            self.last_doe_deadline_at = Some(now);
            let deadline =
                kv::timestamp::TimestampSecs::after(doe_arm_delay(retention_age, min_age));
            Some(kv::stream_doe_deadline::Entry { deadline, min_age })
        } else {
            None
        }
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
            let _ = self.follow_tx.send(records);
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
                Some(res) = OptionFuture::from(self.db_writes_pending.front_mut()) => {
                    drop(self.db_writes_pending.pop_front().expect("polled"));
                    match res {
                        Ok(submitted_append) => {
                            if let Some(prev) = self.inflight_appends.back() {
                                assert!(prev.db_seq < submitted_append.db_seq);
                            }
                            self.inflight_appends.push_back(submitted_append);
                            self.subscribe_durability();
                        }
                        Err(db_err) => {
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
                            self.handle_append(input, session, reply_tx, append_type);
                        }
                        Message::TerminalTrim {
                            condition,
                            reply_tx,
                        } => {
                            self.handle_terminal_trim(condition, reply_tx);
                        }
                        Message::DeleteOnEmptyCheckResult {
                            stable_pos_snapshot,
                            last_write_cutoff,
                            has_records,
                            reply_tx,
                        } => {
                            self.handle_doe_check_result(
                                stable_pos_snapshot,
                                last_write_cutoff,
                                has_records,
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
                        Message::Reconfigure { config } => {
                            self.config = config;
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
                    if self.lease_state.close_if_idle() {
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
        last_write_cutoff: kv::timestamp::TimestampSecs,
        has_records: Result<bool, StorageError>,
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
        config: StreamConfig,
    },
    DurabilityStatus(Result<u64, slatedb::CloseReason>),
}

pub(super) enum TerminalTrimCondition {
    Always,
    DeleteOnEmpty {
        last_write_cutoff: kv::timestamp::TimestampSecs,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TerminalTrimOutcome {
    DeletionPending,
    Ineligible,
}

struct TerminalTrimReplySender(oneshot::Sender<Result<TerminalTrimOutcome, DeleteStreamError>>);

impl append::ReplySender for TerminalTrimReplySender {
    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }

    fn send(self: Box<Self>, reply: Result<AppendAck, AppendErrorInternal>) {
        let result = match reply {
            Ok(_) | Err(AppendErrorInternal::StreamDeletionPending(_)) => {
                Ok(TerminalTrimOutcome::DeletionPending)
            }
            Err(AppendErrorInternal::Storage(e)) => Err(DeleteStreamError::Storage(e)),
            Err(AppendErrorInternal::StreamerMissingInActionError(e)) => {
                Err(DeleteStreamError::StreamerMissingInActionError(e))
            }
            Err(AppendErrorInternal::RequestDroppedError(e)) => {
                Err(DeleteStreamError::RequestDroppedError(e))
            }
            Err(AppendErrorInternal::ConditionFailed(_)) => {
                unreachable!("unconditional write")
            }
            Err(AppendErrorInternal::TimestampMissing(_)) => {
                unreachable!("Timestamp::MAX used")
            }
            Err(AppendErrorInternal::MaxSeqNum(_)) => {
                unreachable!("terminal append is plaintext command record")
            }
        };
        let _ = self.0.send(result);
    }
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

    pub(super) fn advise_reconfig(&self, config: StreamConfig) -> bool {
        self.msg_tx.send(Message::Reconfigure { config }).is_ok()
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
        reply_rx.await.map_err(|_| {
            DeleteStreamError::StreamerMissingInActionError(StreamerMissingInActionError)
        })?
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
        record: Record::Command(CommandRecord::Trim(SeqNum::MAX)).into(),
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

async fn stream_has_records(db: &slatedb::Db, stream_id: StreamId) -> Result<bool, StorageError> {
    let prefix = kv::stream_record_timestamp::ser_key_prefix(stream_id);
    let scan_opts = ScanOptions::default().with_order(IterationOrder::Descending);
    let mut it = db.scan_prefix_with_options(prefix, &scan_opts).await?;
    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    while let Some(kv) = it.next().await? {
        if kv.expire_ts.is_none_or(|expire_ts| expire_ts > now_millis) {
            return Ok(true);
        }
    }
    Ok(false)
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
        doe_deadline,
        fencing_token,
        trim_point,
    }: DbSubmitAppendOptions,
) -> Result<InFlightAppend, slatedb::Error> {
    let ttl = match retention {
        RetentionPolicy::Age(age) => Ttl::ExpireAfter(age.as_millis() as u64),
        RetentionPolicy::Infinite() => Ttl::NoExpiry,
    };
    let ttl_put_opts = PutOptions { ttl };
    let mut wb = WriteBatch::new();
    for (position, record) in records.iter().map(|msr| msr.parts()) {
        wb.put_with_options(
            kv::stream_record_data::ser_key(stream_id, position),
            kv::stream_record_data::ser_value(record),
            &ttl_put_opts,
        );
        wb.put_with_options(
            kv::stream_record_timestamp::ser_key(stream_id, position),
            kv::stream_record_timestamp::ser_value(),
            &ttl_put_opts,
        );
    }
    if let Some(fencing_token) = fencing_token {
        wb.put(
            kv::stream_fencing_token::ser_key(stream_id),
            kv::stream_fencing_token::ser_value(&fencing_token),
        );
    }
    if let Some(trim_point) = trim_point.and_then(|tp| NonZeroSeqNum::new(tp.end)) {
        wb.put(
            kv::stream_trim_point::ser_key(stream_id),
            kv::stream_trim_point::ser_value(..trim_point),
        );
    }
    if let Some(doe_deadline) = doe_deadline {
        wb.put(
            kv::stream_doe_deadline::ser_key(doe_deadline.deadline, stream_id),
            kv::stream_doe_deadline::ser_value(doe_deadline.min_age),
        );
    }
    wb.put(
        kv::stream_tail_position::ser_key(stream_id),
        kv::stream_tail_position::ser_value(next_pos(&records)),
    );
    let write_opts = WriteOptions {
        await_durable: false,
        ..Default::default()
    };
    let write_handle = db.write_with_options(wb, &write_opts).await?;
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
        record::{EnvelopeRecord, Metered, Record, StoredRecord},
        types::stream::{
            StoredAppendInput, StoredAppendRecord, StoredAppendRecordBatch, StoredAppendRecordParts,
        },
    };
    use slatedb::object_store::memory::InMemory;
    use tokio::sync::{broadcast, mpsc, oneshot};

    use super::*;

    fn test_record(body: Bytes, timestamp: Option<Timestamp>) -> StoredAppendRecord {
        let envelope = EnvelopeRecord::try_from_parts(vec![], body).unwrap();
        let record = Metered::from(StoredRecord::from(Record::Envelope(envelope)));
        let parts = StoredAppendRecordParts { timestamp, record };
        parts.try_into().unwrap()
    }

    fn test_command_record(
        command: CommandRecord,
        timestamp: Option<Timestamp>,
    ) -> StoredAppendRecord {
        let record = Metered::from(StoredRecord::from(Record::Command(command)));
        let parts = StoredAppendRecordParts { timestamp, record };
        parts.try_into().unwrap()
    }

    fn test_encrypted_record(
        body: Bytes,
        timestamp: Option<Timestamp>,
        encryption: &EncryptionSpec,
    ) -> StoredAppendRecord {
        let envelope = EnvelopeRecord::try_from_parts(vec![], body).unwrap();
        let record = s2_common::record::encrypt_record(
            Metered::from(Record::Envelope(envelope)),
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

    async fn test_streamer() -> Streamer {
        let object_store = Arc::new(InMemory::new());
        let db = slatedb::Db::builder("/test", object_store)
            .build()
            .await
            .expect("db");
        let (msg_tx, _msg_rx) = mpsc::unbounded_channel();
        let (bgtask_trigger_tx, _) = broadcast::channel(16);
        let (lease_state, _) = StreamerLeaseState::new();
        Streamer {
            db: db.clone(),
            stream_id: [3u8; StreamId::LEN].into(),
            msg_tx,
            config: StreamConfig::default(),
            last_tail_write_timestamp: kv::timestamp::TimestampSecs::ZERO,
            fencing_token: CommandState {
                state: FencingToken::default(),
                applied_point: ..SeqNum::MIN,
            },
            trim_point: CommandState {
                state: ..SeqNum::MIN,
                applied_point: ..SeqNum::MIN,
            },
            last_doe_deadline_at: None,
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
    async fn append_during_terminal_trim_returns_stream_deletion_pending() {
        let mut streamer = test_streamer().await;
        streamer.trim_point = CommandState {
            state: ..SeqNum::MAX,
            applied_point: ..1,
        };
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let run_handle = tokio::spawn(streamer.run(msg_rx));

        let (reply_tx, reply_rx) = oneshot::channel();
        msg_tx
            .send(Message::Append {
                input: append_input(b"late"),
                session: None,
                reply_tx,
                append_type: AppendType::Regular,
            })
            .expect("streamer should accept append message");

        let err = reply_rx
            .await
            .expect("streamer should reply")
            .expect_err("append should be rejected");
        let AppendErrorInternal::StreamDeletionPending(_) = err else {
            panic!("expected stream deletion pending");
        };

        run_handle.abort();
    }

    #[tokio::test]
    async fn delete_on_empty_terminal_trim_skips_pending_append() {
        let mut streamer = test_streamer().await;
        let (append_tx, mut append_rx) = oneshot::channel();
        streamer.handle_append(append_input(b"live"), None, append_tx, AppendType::Regular);
        assert_eq!(streamer.db_writes_pending.len(), 1);
        assert!(matches!(
            append_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        let (trim_tx, trim_rx) = oneshot::channel();
        streamer.handle_terminal_trim(
            TerminalTrimCondition::DeleteOnEmpty {
                last_write_cutoff: kv::timestamp::TimestampSecs::MAX,
            },
            trim_tx,
        );

        assert_eq!(
            trim_rx.await.expect("terminal trim reply").unwrap(),
            TerminalTrimOutcome::Ineligible
        );
        assert_eq!(streamer.db_writes_pending.len(), 1);
    }

    #[tokio::test]
    async fn append_acks_release_only_after_durable_seq_and_in_order() {
        let mut streamer = test_streamer().await;
        let mut follow_rx = streamer.follow_tx.subscribe();

        let (tx1, mut rx1) = oneshot::channel();
        streamer.handle_append(append_input(b"p0"), None, tx1, AppendType::Regular);

        let (tx2, mut rx2) = oneshot::channel();
        streamer.handle_append(append_input(b"p1"), None, tx2, AppendType::Regular);

        let (tx3, mut rx3) = oneshot::channel();
        streamer.handle_append(append_input(b"p2"), None, tx3, AppendType::Regular);

        let mut db_seqs = Vec::new();
        while let Some(fut) = streamer.db_writes_pending.pop_front() {
            let submitted = fut.await.expect("db submit");
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
            );
        }

        let mut db_seqs = Vec::new();
        while let Some(fut) = streamer.db_writes_pending.pop_front() {
            let submitted = fut.await.expect("db submit");
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
}
