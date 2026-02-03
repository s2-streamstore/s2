use std::{
    ops::{Range, RangeTo},
    sync::Arc,
    time::Duration,
};

use bytesize::ByteSize;
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::FuturesOrdered};
use s2_common::{
    record::{
        CommandRecord, FencingToken, Metered, MeteredSize, Record, SeqNum, SequencedRecord,
        StreamPosition, Timestamp,
    },
    types::{
        config::{
            OptionalStreamConfig, OptionalTimestampingConfig, RetentionPolicy, TimestampingMode,
        },
        stream::{AppendAck, AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts},
    },
};
use slatedb::{
    WriteBatch,
    config::{PutOptions, Ttl, WriteOptions},
};
use tokio::{
    sync::{self, Semaphore, SemaphorePermit, broadcast, mpsc, oneshot},
    time::Instant,
};

use crate::{
    backend::{
        append,
        bgtasks::BgtaskTrigger,
        error::{
            AppendConditionFailedError, AppendErrorInternal, AppendTimestampRequiredError,
            DeleteStreamError, RequestDroppedError, StreamerError, StreamerMissingInActionError,
        },
        kv,
        stream_id::StreamId,
    },
    metrics,
};

const DORMANT_TIMEOUT: Duration = Duration::from_secs(60);

pub(super) struct Spawner {
    pub db: slatedb::Db,
    pub stream_id: StreamId,
    pub config: OptionalStreamConfig,
    pub tail_pos: StreamPosition,
    pub fencing_token: FencingToken,
    pub trim_point: RangeTo<SeqNum>,
    pub append_inflight_max: ByteSize,
    pub bgtask_trigger_tx: broadcast::Sender<BgtaskTrigger>,
}

impl Spawner {
    pub fn spawn(self, on_exit: impl FnOnce() + Send + 'static) -> StreamerClient {
        let Self {
            db,
            stream_id,
            config,
            tail_pos,
            fencing_token,
            trim_point,
            append_inflight_max,
            bgtask_trigger_tx,
        } = self;

        let (msg_tx, msg_rx) = mpsc::unbounded_channel();

        let append_inflight_bytes_max =
            (append_inflight_max.as_u64() as usize).min(Semaphore::MAX_PERMITS);

        let append_inflight_bytes_sema = Arc::new(Semaphore::new(append_inflight_bytes_max));

        let streamer = Streamer {
            db,
            stream_id,
            config,
            fencing_token: CommandState {
                state: fencing_token,
                applied_point: ..tail_pos.seq_num,
            },
            trim_point: CommandState {
                state: trim_point,
                applied_point: ..tail_pos.seq_num,
            },
            append_futs: FuturesOrdered::new(),
            pending_appends: append::PendingAppends::new(),
            stable_pos: tail_pos,
            follow_tx: broadcast::Sender::new(super::FOLLOWER_MAX_LAG),
            bgtask_trigger_tx,
        };

        tokio::spawn(async move {
            streamer.run(msg_rx).await;
            on_exit();
        });

        StreamerClient {
            stream_id,
            msg_tx,
            append_inflight_bytes_sema,
            append_inflight_bytes_max,
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
        seq_num_range.start <= self.applied_point.end && self.applied_point.end <= seq_num_range.end
    }
}

struct Streamer {
    db: slatedb::Db,
    stream_id: StreamId,
    config: OptionalStreamConfig,
    fencing_token: CommandState<FencingToken>,
    trim_point: CommandState<RangeTo<SeqNum>>,
    append_futs:
        FuturesOrdered<BoxFuture<'static, Result<Vec<Metered<SequencedRecord>>, slatedb::Error>>>,
    pending_appends: append::PendingAppends,
    stable_pos: StreamPosition,
    follow_tx: broadcast::Sender<Vec<Metered<SequencedRecord>>>,
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
        AppendInput {
            records,
            match_seq_num,
            fencing_token,
        }: AppendInput,
    ) -> Result<Vec<Metered<SequencedRecord>>, AppendErrorInternal> {
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
        input: AppendInput,
        session: Option<append::SessionHandle>,
        reply_tx: oneshot::Sender<Result<AppendAck, AppendErrorInternal>>,
        append_type: AppendType,
    ) {
        let Some(ticket) = append::admit(reply_tx, session) else {
            return;
        };
        match self.sequence_records(input) {
            Ok(sequenced_records) => {
                if append_type == AppendType::Terminal {
                    assert_eq!(sequenced_records.len(), 1);
                    assert_eq!(
                        sequenced_records[0].record,
                        Record::Command(CommandRecord::Trim(SeqNum::MAX))
                    );
                }
                for sr in sequenced_records.iter() {
                    if let Record::Command(cmd) = &sr.record {
                        self.apply_command(sr.position.seq_num, cmd, append_type);
                    }
                }
                let first_pos = sequenced_records.first().expect("non-empty").position;
                let next_pos = next_pos(&sequenced_records);
                let seq_num_range = first_pos.seq_num..next_pos.seq_num;
                self.append_futs.push_back(
                    db_write_records(
                        self.db.clone(),
                        self.stream_id,
                        self.config.retention_policy.unwrap_or_default(),
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

    fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Append {
                input,
                session,
                reply_tx,
                append_type,
            } => {
                if self.trim_point.state.end < SeqNum::MAX {
                    self.handle_append(input, session, reply_tx, append_type);
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
                Some(msg) = msg_rx.recv() => {
                    self.handle_message(msg);
                }
                Some(res) = self.append_futs.next() => {
                    match res {
                        Ok(records) => {
                            let has_trim = records.iter().any(|record| {
                                matches!(record.record, Record::Command(CommandRecord::Trim(_)))
                            });
                            let last_pos = records.last().expect("non-empty").position;
                            let stable_pos = StreamPosition { seq_num: last_pos.seq_num + 1, timestamp: last_pos.timestamp };
                            self.pending_appends.on_stable(stable_pos);
                            self.stable_pos = stable_pos;
                            if has_trim {
                                let _ = self.bgtask_trigger_tx.send(BgtaskTrigger::StreamTrim);
                            }
                            let _ = self.follow_tx.send(records);
                        },
                        Err(db_err) => {
                            self.pending_appends.on_durability_failed(db_err);
                            break;
                        },
                    }
                }
                _ = dormancy.as_mut() => {
                    break;
                }
            }
        }
    }
}

enum Message {
    Append {
        input: AppendInput,
        session: Option<append::SessionHandle>,
        reply_tx: oneshot::Sender<Result<AppendAck, AppendErrorInternal>>,
        append_type: AppendType,
    },
    Follow {
        start_seq_num: SeqNum,
        reply_tx: oneshot::Sender<
            Result<broadcast::Receiver<Vec<Metered<SequencedRecord>>>, StreamPosition>,
        >,
    },
    CheckTail {
        reply_tx: oneshot::Sender<StreamPosition>,
    },
    Reconfigure {
        config: OptionalStreamConfig,
    },
}

#[derive(Debug, Clone)]
pub(super) struct StreamerClient {
    stream_id: StreamId,
    msg_tx: mpsc::UnboundedSender<Message>,
    append_inflight_bytes_sema: Arc<Semaphore>,
    append_inflight_bytes_max: usize,
}

impl StreamerClient {
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub async fn check_tail(&self) -> Result<StreamPosition, StreamerMissingInActionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.msg_tx
            .send(Message::CheckTail { reply_tx })
            .map_err(|_| StreamerMissingInActionError)?;
        reply_rx.await.map_err(|_| StreamerMissingInActionError)
    }

    pub async fn follow(
        &self,
        start_seq_num: SeqNum,
    ) -> Result<
        Result<broadcast::Receiver<Vec<Metered<SequencedRecord>>>, StreamPosition>,
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

    pub async fn append_permit(
        &self,
        input: AppendInput,
    ) -> Result<AppendPermit<'_>, StreamerMissingInActionError> {
        let metered_size = input.records.metered_size();
        metrics::observe_append_batch_size(input.records.len(), metered_size);
        let start = Instant::now();
        // Allow admitting at least one batch if none are in flight.
        let num_permits = metered_size.clamp(1, self.append_inflight_bytes_max) as u32;
        let sema_permit = tokio::select! {
            res = self.append_inflight_bytes_sema.acquire_many(num_permits) => {
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

    pub fn advise_reconfig(&self, config: OptionalStreamConfig) -> bool {
        self.msg_tx.send(Message::Reconfigure { config }).is_ok()
    }

    pub async fn terminal_trim(&self) -> Result<(), DeleteStreamError> {
        let record: AppendRecord = AppendRecordParts {
            timestamp: Some(Timestamp::MAX),
            record: Record::Command(CommandRecord::Trim(SeqNum::MAX)).into(),
        }
        .try_into()
        .expect("valid append record");
        let input = AppendInput {
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
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub enum StreamerClientState {
    /// in the process of init
    Blocked { notify: Arc<sync::Notify> },
    /// failed to init, but the event could be stale
    InitError {
        error: Box<StreamerError>,
        timestamp: Instant,
    },
    /// active and ready to talk
    Ready { client: StreamerClient },
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
    input: AppendInput,
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

pub fn next_pos<T>(records: &[T]) -> StreamPosition
where
    T: std::ops::Deref<Target = SequencedRecord>,
{
    let last_pos = records.last().expect("non-empty").position;
    StreamPosition {
        seq_num: last_pos.seq_num + 1,
        timestamp: last_pos.timestamp,
    }
}

fn sequenced_records(
    batch: AppendRecordBatch,
    first_seq_num: SeqNum,
    prev_max_timestamp: Timestamp,
    config: &OptionalTimestampingConfig,
) -> Result<Vec<Metered<SequencedRecord>>, AppendErrorInternal> {
    let mode = config.mode.unwrap_or_default();
    let uncapped = config.uncapped.unwrap_or_default();
    let mut sequenced_records = Vec::with_capacity(batch.len());
    let mut max_timestamp = prev_max_timestamp;
    let now = timestamp_now();
    for (i, AppendRecordParts { timestamp, record }) in
        batch.into_iter().map(Into::into).enumerate()
    {
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
            seq_num: first_seq_num + i as u64,
            timestamp,
        }));
    }
    Ok(sequenced_records)
}

async fn db_write_records(
    db: slatedb::Db,
    stream_id: StreamId,
    retention: RetentionPolicy,
    records: Vec<Metered<SequencedRecord>>,
    fencing_token: Option<FencingToken>,
    trim_point: Option<RangeTo<SeqNum>>,
) -> Result<Vec<Metered<SequencedRecord>>, slatedb::Error> {
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
    if let Some(trim_point) = trim_point {
        wb.put(
            kv::stream_trim_point::ser_key(stream_id),
            kv::stream_trim_point::ser_value(trim_point),
        );
    }
    wb.put(
        kv::stream_tail_position::ser_key(stream_id),
        kv::stream_tail_position::ser_value(next_pos(&records)),
    );
    static WRITE_OPTS: WriteOptions = WriteOptions {
        await_durable: true,
    };
    db.write_with_options(wb, &WRITE_OPTS).await?;
    Ok(records)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use s2_common::{
        record::{EnvelopeRecord, Metered, Record},
        types::stream::{AppendRecord, AppendRecordParts},
    };

    use super::*;

    fn test_record(body: Bytes, timestamp: Option<Timestamp>) -> AppendRecord {
        let envelope = EnvelopeRecord::try_from_parts(vec![], body).unwrap();
        let record: Metered<Record> = Record::Envelope(envelope).into();
        let parts = AppendRecordParts { timestamp, record };
        parts.try_into().unwrap()
    }

    #[test]
    fn sequenced_records_client_prefer_with_timestamps() {
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(false),
        };

        let records: AppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), Some(900)),
            test_record(vec![4, 5, 6].into(), Some(950)),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].position.seq_num, 100);
        assert_eq!(result[0].position.timestamp, 900);
        assert_eq!(result[1].position.seq_num, 101);
        assert_eq!(result[1].position.timestamp, 950);
    }

    #[test]
    fn sequenced_records_client_prefer_without_timestamps() {
        let now = timestamp_now();
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(false),
        };

        let records: AppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), None),
            test_record(vec![4, 5, 6].into(), None),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].position.seq_num, 100);
        assert!(result[0].position.timestamp >= now);
        assert_eq!(result[1].position.seq_num, 101);
        assert!(result[1].position.timestamp >= now);
    }

    #[test]
    fn sequenced_records_client_require_missing_timestamp() {
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            uncapped: Some(false),
        };

        let records: AppendRecordBatch = vec![test_record(vec![1, 2, 3].into(), None)]
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

        let records: AppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), Some(900)),
            test_record(vec![4, 5, 6].into(), Some(950)),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].position.timestamp, 900);
        assert_eq!(result[1].position.timestamp, 950);
    }

    #[test]
    fn sequenced_records_arrival_mode() {
        let now = timestamp_now();
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::Arrival),
            uncapped: Some(false),
        };

        let records: AppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), Some(900)),
            test_record(vec![4, 5, 6].into(), Some(950)),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result[0].position.timestamp >= now);
        assert!(result[1].position.timestamp >= now);
    }

    #[test]
    fn sequenced_records_timestamp_monotonicity() {
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(false),
        };

        let records: AppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), Some(1000)),
            test_record(vec![4, 5, 6].into(), Some(900)),
            test_record(vec![7, 8, 9].into(), Some(1100)),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].position.timestamp, 1000);
        assert_eq!(result[1].position.timestamp, 1000);
        assert_eq!(result[2].position.timestamp, 1100);
    }

    #[test]
    fn sequenced_records_prev_max_timestamp_enforced() {
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(false),
        };

        let records: AppendRecordBatch = vec![
            test_record(vec![1, 2, 3].into(), Some(500)),
            test_record(vec![4, 5, 6].into(), Some(600)),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 100, 1000, &config).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].position.timestamp, 1000);
        assert_eq!(result[1].position.timestamp, 1000);
    }

    #[test]
    fn sequenced_records_future_timestamp_capped() {
        let now = timestamp_now();
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(false),
        };

        let future = now + 10_000;
        let records: AppendRecordBatch = vec![test_record(vec![1, 2, 3].into(), Some(future))]
            .try_into()
            .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].position.timestamp <= now + 100);
    }

    #[test]
    fn sequenced_records_future_timestamp_uncapped() {
        let now = timestamp_now();
        let config = OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientPrefer),
            uncapped: Some(true),
        };

        let future = now + 10_000;
        let records: AppendRecordBatch = vec![test_record(vec![1, 2, 3].into(), Some(future))]
            .try_into()
            .unwrap();

        let result = sequenced_records(records, 100, 0, &config).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].position.timestamp, future);
    }

    #[test]
    fn sequenced_records_seq_num_assignment() {
        let config = OptionalTimestampingConfig::default();

        let records: AppendRecordBatch = vec![
            test_record(vec![1].into(), None),
            test_record(vec![2].into(), None),
            test_record(vec![3].into(), None),
        ]
        .try_into()
        .unwrap();

        let result = sequenced_records(records, 42, 0, &config).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].position.seq_num, 42);
        assert_eq!(result[1].position.seq_num, 43);
        assert_eq!(result[2].position.seq_num, 44);
    }
}
