use std::{
    collections::VecDeque,
    ops::{Range, RangeTo},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
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
        config::{
            OptionalStreamConfig, OptionalTimestampingConfig, RetentionPolicy, TimestampingMode,
        },
        stream::{
            AppendAck, StoredAppendInput, StoredAppendRecord, StoredAppendRecordBatch,
            StoredAppendRecordParts,
        },
    },
};
use slatedb::{
    WriteBatch,
    config::{PutOptions, Ttl, WriteOptions},
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
            DeleteStreamError, RequestDroppedError, StreamEncryptedRecordLimitExceededError,
            StreamerMissingInActionError,
        },
        kv,
    },
    metrics,
    stream_id::StreamId,
};

pub(super) const DORMANT_TIMEOUT: Duration = Duration::from_secs(60);
// Rate-limit delete-on-empty scheduling and pad deadlines to cover the period.
const DOE_DEADLINE_REFRESH_PERIOD: Duration = Duration::from_secs(600);

pub(super) fn doe_arm_delay(retention_age: Duration, min_age: Duration) -> Duration {
    retention_age
        .saturating_add(min_age)
        .saturating_add(DOE_DEADLINE_REFRESH_PERIOD)
}

pub(super) fn retention_age_or_zero(config: &OptionalStreamConfig) -> Duration {
    config
        .retention_policy
        .unwrap_or_default()
        .age()
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StreamerGenerationId(u64);

impl StreamerGenerationId {
    pub(super) fn next() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Clone, Copy, Debug)]
struct DeleteOnEmptyDeadline {
    deadline: kv::timestamp::TimestampSecs,
    min_age: Duration,
}

#[derive(Debug)]
struct InFlightAppend {
    db_seq: u64,
    records: Vec<Metered<StoredSequencedRecord>>,
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

    pub(super) async fn terminal_trim(&self) -> Result<(), DeleteStreamError> {
        self.client.terminal_trim().await
    }
}

pub(super) struct Spawner {
    pub generation_id: StreamerGenerationId,
    pub db: slatedb::Db,
    pub stream_id: StreamId,
    pub config: OptionalStreamConfig,
    pub cipher: Option<EncryptionAlgorithm>,
    pub tail_pos: StreamPosition,
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
    config: OptionalStreamConfig,
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
        reply_tx: oneshot::Sender<Result<AppendAck, AppendErrorInternal>>,
        append_type: AppendType,
    ) {
        let Some(ticket) = append::admit(reply_tx, session) else {
            return;
        };
        match self.sequence_records(input) {
            Ok(sequenced_records) => {
                let retention = self.config.retention_policy.unwrap_or_default();
                let doe_deadline = self.maybe_doe_deadline(retention.age());
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
                self.db_writes_pending.push_back(
                    db_submit_append(
                        self.db.clone(),
                        self.stream_id,
                        retention,
                        doe_deadline,
                        sequenced_records,
                        self.fencing_token
                            .is_applied_in(&seq_num_range)
                            .then(|| self.fencing_token.state.clone()),
                        self.trim_point
                            .is_applied_in(&seq_num_range)
                            .then_some(self.trim_point.state),
                    )
                    .boxed(),
                );
                self.pending_appends.accept(ticket, first_pos..next_pos);
            }
            Err(e) => {
                self.pending_appends.reject(ticket, e, self.stable_pos);
            }
        }
    }

    fn maybe_doe_deadline(
        &mut self,
        retention_age: Option<Duration>,
    ) -> Option<DeleteOnEmptyDeadline> {
        let retention_age = retention_age?;
        let min_age = self
            .config
            .delete_on_empty
            .min_age
            .filter(|d| !d.is_zero())?;
        let now = Instant::now();
        if self
            .last_doe_deadline_at
            .is_none_or(|t| now.duration_since(t) >= DOE_DEADLINE_REFRESH_PERIOD)
        {
            self.last_doe_deadline_at = Some(now);
            let deadline =
                kv::timestamp::TimestampSecs::after(doe_arm_delay(retention_age, min_age));
            Some(DeleteOnEmptyDeadline { deadline, min_age })
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
                            if self.trim_point.state.end < SeqNum::MAX {
                                self.handle_append(
                                    input,
                                    session,
                                    reply_tx,
                                    append_type,
                                );
                            }
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
        config: OptionalStreamConfig,
    },
    DurabilityStatus(Result<u64, slatedb::CloseReason>),
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

    pub(super) fn advise_reconfig(&self, config: OptionalStreamConfig) -> bool {
        self.msg_tx.send(Message::Reconfigure { config }).is_ok()
    }

    async fn terminal_trim(&self) -> Result<(), DeleteStreamError> {
        let record: StoredAppendRecord = StoredAppendRecordParts {
            timestamp: Some(Timestamp::MAX),
            record: Record::Command(CommandRecord::Trim(SeqNum::MAX)).into(),
        }
        .try_into()
        .expect("valid append record");
        let input = StoredAppendInput {
            records: vec![record].try_into().expect("valid append batch"),
            match_seq_num: None,
            fencing_token: None,
        };
        match self
            .append_permit(input)
            .await?
            .submit_internal(None, AppendType::Terminal)
            .await
        {
            Ok(_ack) => Ok(()),
            Err(e) => Err(match e {
                AppendErrorInternal::Storage(e) => DeleteStreamError::Storage(e),
                AppendErrorInternal::StreamerMissingInActionError(e) => {
                    DeleteStreamError::StreamerMissingInActionError(e)
                }
                AppendErrorInternal::RequestDroppedError(e) => {
                    DeleteStreamError::RequestDroppedError(e)
                }
                AppendErrorInternal::ConditionFailed(_) => unreachable!("unconditional write"),
                AppendErrorInternal::TimestampMissing(_) => unreachable!("Timestamp::MAX used"),
                AppendErrorInternal::StreamEncryptedRecordLimitExceeded(_) => {
                    unreachable!("terminal append is plaintext command record")
                }
            }),
        }
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

fn sequenced_records(
    batch: StoredAppendRecordBatch,
    first_seq_num: SeqNum,
    prev_max_timestamp: Timestamp,
    config: &OptionalTimestampingConfig,
) -> Result<Vec<Metered<StoredSequencedRecord>>, AppendErrorInternal> {
    let mode = config.mode.unwrap_or_default();
    let uncapped = config.uncapped.unwrap_or_default();
    let mut sequenced_records = Vec::with_capacity(batch.len());
    let mut max_timestamp = prev_max_timestamp;
    let now = timestamp_now();
    for (i, StoredAppendRecordParts { timestamp, record }) in batch
        .into_iter()
        .map(|record| record.into_parts())
        .enumerate()
    {
        let assigned_seq_num = first_seq_num + i as u64;
        if let Some(limit) = record.as_ref().into_inner().stream_encrypted_record_limit()
            && assigned_seq_num >= limit
        {
            Err(StreamEncryptedRecordLimitExceededError {
                assigned_seq_num,
                limit,
            })?;
        }
        let mut timestamp = match mode {
            TimestampingMode::ClientPrefer => timestamp.unwrap_or(now),
            TimestampingMode::ClientRequire => timestamp.ok_or(AppendTimestampRequiredError)?,
            TimestampingMode::Arrival => now,
        };
        if !uncapped && timestamp > now {
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
    retention: RetentionPolicy,
    doe_deadline: Option<DeleteOnEmptyDeadline>,
    records: Vec<Metered<StoredSequencedRecord>>,
    fencing_token: Option<FencingToken>,
    trim_point: Option<RangeTo<SeqNum>>,
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
    let write_timestamp_secs = kv::timestamp::TimestampSecs::now();
    wb.put(
        kv::stream_tail_position::ser_key(stream_id),
        kv::stream_tail_position::ser_value(next_pos(&records), write_timestamp_secs),
    );
    static WRITE_OPTS: WriteOptions = WriteOptions {
        await_durable: false,
    };
    let write_handle = db.write_with_options(wb, &WRITE_OPTS).await?;
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
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(false),
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
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(false),
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
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            uncapped: Some(false),
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
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            uncapped: Some(false),
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
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::Arrival),
            uncapped: Some(false),
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
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(false),
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
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(false),
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
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(false),
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
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(true),
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
        let config = OptionalTimestampingConfig::default();

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
        let config = OptionalTimestampingConfig::default();
        let first_record = test_encrypted_record(
            vec![1, 2, 3].into(),
            None,
            &EncryptionSpec::aes256_gcm([0x24; 32]),
        );
        let limit = first_record
            .parts()
            .record
            .stream_encrypted_record_limit()
            .expect("aes-256-gcm record has stream message limit");
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

        let result = sequenced_records(records, limit - 1, 0, &config);

        assert!(matches!(
            result,
            Err(AppendErrorInternal::StreamEncryptedRecordLimitExceeded(
                StreamEncryptedRecordLimitExceededError {
                    assigned_seq_num: seq_num,
                    limit: err_limit,
                }
            ))
            if seq_num == limit && err_limit == limit,
        ));
    }

    #[test]
    fn sequenced_records_allow_aes256gcm_command_records_past_random_nonce_limit() {
        let config = OptionalTimestampingConfig::default();
        let limit = test_encrypted_record(
            vec![1, 2, 3].into(),
            None,
            &EncryptionSpec::aes256_gcm([0x24; 32]),
        )
        .parts()
        .record
        .stream_encrypted_record_limit()
        .expect("aes-256-gcm record has stream message limit");

        let records: StoredAppendRecordBatch =
            vec![test_command_record(CommandRecord::Trim(42), None)]
                .try_into()
                .unwrap();

        let result = sequenced_records(records, limit, 0, &config).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].position().seq_num, limit);
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
            config: OptionalStreamConfig::default(),
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
