use std::{
    collections::VecDeque,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use bytes::Bytes;
use dashmap::DashMap;
use futures::{FutureExt as _, Stream, StreamExt as _, future::BoxFuture, stream::FuturesOrdered};
use s2_common::{
    caps,
    read_extent::{EvaluatedReadLimit, ReadLimit, ReadUntil},
    record::{
        CommandRecord, FencingToken, MeteredSequencedRecord, MeteredSequencedRecords, MeteredSize,
        Record, SeqNum, StreamPosition, Timestamp,
    },
    types::{
        basin::{BasinInfo, BasinName, BasinState, ListBasinsRequest},
        config::{
            BasinConfig, OptionalStreamConfig, OptionalTimestampingConfig, RetentionPolicy,
            TimestampingMode,
        },
        resources::{CreateMode, ListItemsRequestParts, Page},
        stream::{
            AppendAck, AppendInput, AppendRecordBatch, AppendRecordParts, ListStreamsRequest,
            ReadBatch, ReadEnd, ReadFrom, ReadPosition, ReadSessionOutput, ReadStart, StreamInfo,
            StreamName,
        },
    },
};
use slatedb::{
    WriteBatch,
    config::{DurabilityLevel, PutOptions, ReadOptions, ScanOptions, Ttl, WriteOptions},
};
use time::OffsetDateTime;
use tokio::{
    sync::{self, broadcast, mpsc, oneshot},
    time::Instant,
};

use super::error::CheckTailError;
use crate::backend::{
    error::{
        AppendConditionFailed, AppendError, CreateBasinError, CreateStreamError, DeleteBasinError,
        DeleteStreamError, GetBasinConfigError, GetStreamConfigError, ListBasinsError,
        ListStreamsError, ReadError, StreamerError,
    },
    kv,
    stream_id::StreamId,
};

#[derive(Debug, Clone)]
pub struct AppendSessionState {
    poisoned: Arc<AtomicBool>,
}

impl AppendSessionState {
    pub fn poison(&self) {
        self.poisoned
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(std::sync::atomic::Ordering::Acquire)
    }
}

#[derive(Clone)]
pub struct SlateDbBackend {
    db: slatedb::Db,
    client_states: Arc<DashMap<StreamId, StreamerClientState>>,
}

impl SlateDbBackend {
    pub fn new(db: slatedb::Db) -> Self {
        Self {
            db,
            client_states: Arc::new(DashMap::new()),
        }
    }
    const FAILED_INIT_MEMORY: Duration = Duration::from_secs(1);

    async fn db_get<K: AsRef<[u8]> + Send, V>(
        &self,
        key: K,
        deser: impl FnOnce(Bytes) -> Result<V, kv::DeserializationError>,
    ) -> Result<Result<Option<V>, kv::DeserializationError>, Arc<slatedb::Error>> {
        const READ_OPTS: ReadOptions = ReadOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            cache_blocks: true,
        };
        let value = self
            .db
            .get_with_options(key, &READ_OPTS)
            .await
            .map_err(Arc::new)?;
        Ok(value.map(deser).transpose())
    }

    async fn db_get_flat<K: AsRef<[u8]> + Send, V>(
        &self,
        key: K,
        deser: impl FnOnce(Bytes) -> Result<V, kv::DeserializationError>,
    ) -> Result<Option<V>, StreamerError> {
        Ok(self.db_get(key, deser).await??)
    }

    async fn resolve_timestamp(
        &self,
        stream_id: StreamId,
        timestamp: Timestamp,
    ) -> Result<Option<StreamPosition>, StreamerError> {
        let start_key = kv::stream_record_timestamp::ser_key(stream_id, timestamp);
        const SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self
            .db
            .scan_with_options(start_key.., &SCAN_OPTS)
            .await
            .map_err(Arc::new)
            .map_err(StreamerError::Slate)?;
        Ok(match it.next().await.map_err(Arc::new)? {
            Some(kv) => {
                let (deser_stream_id, deser_timestamp) =
                    kv::stream_record_timestamp::deser_key(kv.key)?;
                assert_eq!(deser_stream_id, stream_id);
                assert!(deser_timestamp >= timestamp);
                let seq_num = kv::stream_record_timestamp::deser_value(kv.value)?;
                Some(StreamPosition {
                    seq_num,
                    timestamp: deser_timestamp,
                })
            }
            None => None,
        })
    }

    async fn start_streamer(
        &self,
        basin: BasinName,
        stream: StreamName,
        stream_id: StreamId,
    ) -> Result<StreamerClient, StreamerError> {
        let (append_tx, append_rx) = mpsc::channel(MAX_INFLIGHT_APPENDS);
        let (other_tx, other_rx) = mpsc::unbounded_channel();

        let (meta, tail_pos, fencing_token, trim_point) = tokio::try_join!(
            self.db_get_flat(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            ),
            self.db_get_flat(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::deser_value,
            ),
            self.db_get_flat(
                kv::stream_fencing_token::ser_key(stream_id),
                kv::stream_fencing_token::deser_value,
            ),
            self.db_get_flat(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::deser_value,
            )
        )?;
        let meta = meta.ok_or_else(|| StreamerError::StreamNotFound { basin, stream })?;
        let tail_pos = tail_pos.unwrap_or(StreamPosition::MIN);
        let fencing_token = CommandState {
            state: fencing_token.unwrap_or_default(),
            applied_point: tail_pos.seq_num,
        };
        let trim_point = CommandState {
            state: trim_point.unwrap_or(SeqNum::MIN),
            applied_point: tail_pos.seq_num,
        };

        let streamer = Streamer {
            db: self.db.clone(),
            stream_id,
            config: meta.config,
            fencing_token,
            trim_point,
            append_futs: FuturesOrdered::new(),
            pending_appends: PendingAppends::new(MAX_INFLIGHT_APPENDS),
            stable_pos: tail_pos,
            follower_tx: broadcast::Sender::new(10),
        };

        let client_states = self.client_states.clone();

        tokio::spawn(async move {
            streamer.run(append_rx, other_rx).await;
            client_states.remove(&stream_id);
        });

        Ok(StreamerClient {
            append_tx,
            other_tx,
        })
    }

    fn streamer_client_state(
        &self,
        basin: &BasinName,
        stream: &StreamName,
        stream_id: StreamId,
    ) -> StreamerClientState {
        match self.client_states.entry(stream_id) {
            dashmap::Entry::Occupied(oe) => oe.get().clone(),
            dashmap::Entry::Vacant(ve) => {
                let this = self.clone();
                let basin = basin.clone();
                let stream = stream.clone();
                tokio::spawn(async move {
                    let state = match this.start_streamer(basin, stream, stream_id).await {
                        Ok(client) => StreamerClientState::Ready { client },
                        Err(error) => StreamerClientState::InitError {
                            error: Box::new(error),
                            timestamp: Instant::now(),
                        },
                    };
                    let replaced_state = this.client_states.insert(stream_id, state);
                    let Some(StreamerClientState::Blocked { notify }) = replaced_state else {
                        panic!("expected Blocked client but replaced: {replaced_state:?}");
                    };
                    notify.notify_waiters();
                });
                ve.insert(StreamerClientState::Blocked {
                    notify: Default::default(),
                })
                .value()
                .clone()
            }
        }
    }

    fn streamer_remove_unready(&self, stream_id: StreamId) {
        if let dashmap::Entry::Occupied(oe) = self.client_states.entry(stream_id)
            && let StreamerClientState::InitError { .. } = oe.get()
        {
            oe.remove();
        }
    }

    async fn streamer_client(
        &self,
        basin: &BasinName,
        stream: &StreamName,
        stream_id: StreamId,
    ) -> Result<StreamerClient, StreamerError> {
        let mut waited = false;
        loop {
            match self.streamer_client_state(basin, stream, stream_id) {
                StreamerClientState::Blocked { notify } => {
                    notify.notified().await;
                    waited = true;
                }
                StreamerClientState::InitError { error, timestamp } => {
                    if !waited || timestamp.elapsed() > Self::FAILED_INIT_MEMORY {
                        self.streamer_remove_unready(stream_id);
                    } else {
                        return Err(*error);
                    }
                }
                StreamerClientState::Ready { client } => {
                    return Ok(client);
                }
            }
        }
    }

    async fn read_start_seq_num(
        &self,
        stream_id: StreamId,
        start: ReadStart,
        tail: StreamPosition,
    ) -> Result<SeqNum, ReadError> {
        let mut read_pos = match start.from {
            ReadFrom::SeqNum(seq_num) => ReadPosition::SeqNum(seq_num),
            ReadFrom::Timestamp(timestamp) => ReadPosition::Timestamp(timestamp),
            ReadFrom::TailOffset(tail_offset) => {
                ReadPosition::SeqNum(tail.seq_num.saturating_sub(tail_offset))
            }
        };
        if match read_pos {
            ReadPosition::SeqNum(start_seq_num) => start_seq_num > tail.seq_num,
            ReadPosition::Timestamp(start_timestamp) => start_timestamp > tail.timestamp,
        } {
            if start.clamp {
                read_pos = ReadPosition::SeqNum(tail.seq_num);
            } else {
                return Err(ReadError::TailExceeded(tail));
            }
        }
        Ok(match read_pos {
            ReadPosition::SeqNum(start_seq_num) => start_seq_num,
            ReadPosition::Timestamp(start_timestamp) => {
                self.resolve_timestamp(stream_id, start_timestamp)
                    .await?
                    .unwrap_or(tail)
                    .seq_num
            }
        })
    }

    pub async fn check_tail(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<StreamPosition, CheckTailError> {
        let stream_id = StreamId::new(&basin, &stream);
        let client = self.streamer_client(&basin, &stream, stream_id).await?;
        let tail = client.check_tail().await?;
        Ok(tail)
    }

    // TODO: ttl filtering (hmm does sl8 do it already?)
    pub async fn read(
        &self,
        basin: BasinName,
        stream: StreamName,
        start: ReadStart,
        end: ReadEnd,
    ) -> Result<impl Stream<Item = Result<ReadSessionOutput, ReadError>> + 'static, ReadError> {
        let stream_id = StreamId::new(&basin, &stream);
        let client = self.streamer_client(&basin, &stream, stream_id).await?;
        let tail = client.check_tail().await?;
        let mut state = ReadSessionState {
            start_seq_num: self.read_start_seq_num(stream_id, start, tail).await?,
            limit: EvaluatedReadLimit::Remaining(end.limit),
            until: end.until,
            tail,
        };
        let db = self.db.clone();
        let session = async_stream::try_stream! {
            'session: while let EvaluatedReadLimit::Remaining(limit) = state.limit {
                if state.start_seq_num < state.tail.seq_num {
                    let start_key = kv::stream_record_data::ser_key(
                        stream_id,
                        StreamPosition {
                            seq_num: state.start_seq_num,
                            timestamp: 0,
                        },
                    );
                    let end_key = kv::stream_record_data::ser_key(
                        stream_id,
                        StreamPosition {
                            seq_num: state.tail.seq_num,
                            timestamp: 0,
                        },
                    );
                    const SCAN_OPTS: ScanOptions = ScanOptions {
                        durability_filter: DurabilityLevel::Remote,
                        dirty: false,
                        read_ahead_bytes: 1024 * 1024,
                        cache_blocks: true,
                        max_fetch_tasks: 8,
                    };
                    let mut it = db
                        .scan_with_options(start_key..end_key, &SCAN_OPTS)
                        .await
                        .map_err(Arc::new)
                        .map_err(StreamerError::Slate)?;

                    let mut records = new_records_buf(limit);

                    while let EvaluatedReadLimit::Remaining(limit) = state.limit {
                        let Some(kv) = it.next().await.map_err(Arc::new).map_err(StreamerError::Slate)? else {
                            break;
                        };
                        let (deser_stream_id, pos) = kv::stream_record_data::deser_key(kv.key)
                            .map_err(StreamerError::Deserialization)?;
                        assert_eq!(deser_stream_id, stream_id);

                        let record = kv::stream_record_data::deser_value(kv.value)
                            .map_err(StreamerError::Deserialization)?
                            .sequenced(pos);

                        if end.until.deny(pos.timestamp)
                            || limit.deny(records.len() + 1, records.metered_size() + record.metered_size()) {
                            break;
                        }

                        if records.len() == caps::RECORD_BATCH_MAX.count
                            || records.metered_size() + record.metered_size() > caps::RECORD_BATCH_MAX.bytes
                        {
                            yield state.on_batch(ReadBatch {
                                records: std::mem::replace(
                                    &mut records,
                                    new_records_buf(limit),
                                ),
                                tail: None,
                            });
                        }

                        records.push(record);
                    }

                    if !records.is_empty() {
                        yield state.on_batch(ReadBatch {
                            records,
                            tail: None,
                        });
                    }
                } else {
                    assert_eq!(state.start_seq_num, state.tail.seq_num);
                    if !end.may_follow() {
                        break;
                    }
                    match client.follow(state.start_seq_num).await? {
                        Ok(mut follow_rx) => {
                            yield ReadSessionOutput::Heartbeat(state.tail);
                            while let EvaluatedReadLimit::Remaining(limit) = state.limit {
                                tokio::select! {
                                    biased;
                                    msg = follow_rx.recv() => {
                                        match msg {
                                            Ok(mut batch) => {
                                                if limit.deny(batch.records.len(), batch.records.metered_size())
                                                    || end.until.deny(batch.records.last().expect("non-empty").position.timestamp) {
                                                    batch.records = truncate_records(batch.records, limit, end.until);
                                                    if !batch.records.is_empty() {
                                                        yield state.on_batch(batch);
                                                    }
                                                    break 'session;
                                                }
                                                yield state.on_batch(batch);
                                            }
                                            Err(broadcast::error::RecvError::Lagged(_)) => {
                                                // Catch up using DB
                                                continue 'session;
                                            }
                                            Err(broadcast::error::RecvError::Closed) => {
                                                break;
                                            }
                                        }
                                    }
                                    _ = new_heartbeat_sleep() => {
                                        yield ReadSessionOutput::Heartbeat(state.tail);
                                    }
                                    _ = tokio::time::sleep(end.wait.unwrap()), if end.wait.is_some() => {
                                        break 'session;
                                    }
                                }
                            }
                            Err(StreamerError::Hangup)?;
                        }
                        Err(tail) => {
                            assert!(state.tail.seq_num < tail.seq_num, "tail cannot regress");
                            state.tail = tail;
                        }
                    }
                }
            }
        };
        Ok(session)
    }

    pub async fn append(
        &self,
        basin: BasinName,
        stream: StreamName,
        session: Option<AppendSessionState>,
        input: AppendInput,
    ) -> Result<AppendAck, AppendError> {
        let stream_id = StreamId::new(&basin, &stream);
        let client = self.streamer_client(&basin, &stream, stream_id).await?;
        client.append(session, input).await
    }

    pub async fn list_streams(
        &self,
        basin: BasinName,
        request: ListStreamsRequest,
    ) -> Result<Page<StreamInfo>, ListStreamsError> {
        let ListItemsRequestParts {
            prefix,
            start_after,
            limit,
        } = request.into();

        const SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };

        let mut it = self
            .db
            .scan_with_options(
                kv::stream_meta::ser_key_range(&basin, &prefix, &start_after),
                &SCAN_OPTS,
            )
            .await
            .map_err(Arc::new)?;

        let mut streams = Vec::with_capacity(limit.as_usize());
        let mut has_more = false;
        while let Some(kv) = it.next().await.map_err(Arc::new)? {
            let (deser_basin, stream) = kv::stream_meta::deser_key(kv.key)?;
            assert_eq!(deser_basin.as_ref(), basin.as_ref());
            assert!(stream.as_ref() > start_after.as_ref());
            assert!(stream.as_ref() >= prefix.as_ref());
            if streams.len() == limit.as_usize() {
                has_more = true;
                break;
            }
            let meta = kv::stream_meta::deser_value(kv.value)?;
            streams.push(StreamInfo {
                name: stream,
                created_at: meta.created_at,
                deleted_at: meta.deleted_at,
            });
        }
        Ok(Page::new(streams, has_more))
    }

    pub async fn create_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
        config: OptionalStreamConfig,
        mode: CreateMode,
        idempotence_key: Option<Bytes>,
    ) -> Result<(), CreateStreamError> {
        // TODO: idempotence
        if let Some(existing_meta) = self
            .db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            )
            .await??
        {
            match mode {
                CreateMode::CreateOnly => return Err(CreateStreamError::AlreadyExists),
                CreateMode::CreateOrReconfigure => {
                    todo!("reconfig not supported yet")
                }
            }
        }

        let meta = kv::StreamMeta {
            config,
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
        };

        self.db
            .put(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::ser_value(&meta),
            )
            .await
            .map_err(Arc::new)?;

        Ok(())
    }

    pub async fn get_stream_config(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<OptionalStreamConfig, GetStreamConfigError> {
        let meta = self
            .db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            )
            .await??
            .ok_or(GetStreamConfigError::StreamNotFound)?;
        Ok(meta.config)
    }

    pub async fn delete_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<(), DeleteStreamError> {
        let mut meta = self
            .db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            )
            .await??
            .ok_or(DeleteStreamError::StreamNotFound)?;

        meta.deleted_at = Some(OffsetDateTime::now_utc());

        self.db
            .put(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::ser_value(&meta),
            )
            .await
            .map_err(Arc::new)?;

        todo!("trigger stream deletion")
    }

    pub async fn list_basins(
        &self,
        request: ListBasinsRequest,
    ) -> Result<Page<BasinInfo>, ListBasinsError> {
        let ListItemsRequestParts {
            prefix,
            start_after,
            limit,
        } = request.into();

        const SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };

        let mut it = self
            .db
            .scan_with_options(
                kv::basin_meta::ser_key_range(&prefix, &start_after),
                &SCAN_OPTS,
            )
            .await
            .map_err(Arc::new)?;

        let mut basins = Vec::with_capacity(limit.as_usize());
        let mut has_more = false;
        while let Some(kv) = it.next().await.map_err(Arc::new)? {
            let basin = kv::basin_meta::deser_key(kv.key)?;
            assert!(basin.as_ref() > start_after.as_ref());
            assert!(basin.as_ref() >= prefix.as_ref());
            if basins.len() == limit.as_usize() {
                has_more = true;
                break;
            }
            let meta = kv::basin_meta::deser_value(kv.value)?;
            let state = if meta.deleted_at.is_some() {
                BasinState::Deleting
            } else {
                BasinState::Active
            };
            basins.push(BasinInfo {
                name: basin,
                scope: None,
                state,
            });
        }
        Ok(Page::new(basins, has_more))
    }

    pub async fn create_basin(
        &self,
        basin: BasinName,
        config: BasinConfig,
        mode: CreateMode,
        idempotence_key: Option<Bytes>,
    ) -> Result<BasinInfo, CreateBasinError> {
        // TODO: idempotence
        if let Some(existing_meta) = self
            .db_get(kv::basin_meta::ser_key(&basin), kv::basin_meta::deser_value)
            .await??
        {
            match mode {
                CreateMode::CreateOnly => return Err(CreateBasinError::AlreadyExists),
                CreateMode::CreateOrReconfigure => {
                    todo!("reconfig not supported yet")
                }
            }
        }

        let meta = kv::BasinMeta {
            config,
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
        };

        self.db
            .put(
                kv::basin_meta::ser_key(&basin),
                kv::basin_meta::ser_value(&meta),
            )
            .await
            .map_err(Arc::new)?;

        Ok(BasinInfo {
            name: basin,
            scope: None,
            state: BasinState::Active,
        })
    }

    pub async fn get_basin_config(
        &self,
        basin: BasinName,
    ) -> Result<BasinConfig, GetBasinConfigError> {
        let meta = self
            .db_get(kv::basin_meta::ser_key(&basin), kv::basin_meta::deser_value)
            .await??
            .ok_or(GetBasinConfigError::BasinNotFound)?;
        Ok(meta.config)
    }

    pub async fn delete_basin(&self, basin: BasinName) -> Result<(), DeleteBasinError> {
        let mut meta = self
            .db_get(kv::basin_meta::ser_key(&basin), kv::basin_meta::deser_value)
            .await??
            .ok_or(DeleteBasinError::BasinNotFound)?;

        meta.deleted_at = Some(OffsetDateTime::now_utc());

        self.db
            .put(
                kv::basin_meta::ser_key(&basin),
                kv::basin_meta::ser_value(&meta),
            )
            .await
            .map_err(Arc::new)?;

        todo!("trigger basin deletion incl all its streams")
    }
}

// TODO: https://github.com/slatedb/slatedb/issues/1138
const MAX_INFLIGHT_APPENDS: usize = 1;

const DORMANT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
struct AppendAckRange {
    start: StreamPosition,
    end: StreamPosition,
}

#[derive(Debug, Clone)]
struct CommandState<T> {
    applied_point: SeqNum,
    state: T,
}

struct Streamer {
    db: slatedb::Db,
    stream_id: StreamId,
    config: OptionalStreamConfig,
    fencing_token: CommandState<FencingToken>,
    trim_point: CommandState<SeqNum>,
    append_futs: FuturesOrdered<BoxFuture<'static, (AppendAckRange, Result<(), slatedb::Error>)>>,
    pending_appends: PendingAppends,
    stable_pos: StreamPosition,
    follower_tx: broadcast::Sender<ReadBatch>,
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
    ) -> Result<Vec<MeteredSequencedRecord>, AppendError> {
        if let Some(provided_token) = fencing_token
            && provided_token != self.fencing_token.state
        {
            Err(AppendConditionFailed::FencingTokenMismatch {
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
            Err(AppendConditionFailed::SeqNumMismatch {
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

    fn apply_command(&mut self, seq_num: SeqNum, cmd: &CommandRecord) {
        match cmd {
            CommandRecord::Fence(token) => {
                self.fencing_token = CommandState {
                    applied_point: seq_num,
                    state: token.clone(),
                };
            }
            CommandRecord::Trim(trim_point) => {
                // Trim point cannot exceed command record's seq num + 1.
                let trim_point = (*trim_point).min(seq_num + 1);
                if self.trim_point.state < trim_point {
                    self.trim_point = CommandState {
                        applied_point: seq_num,
                        state: trim_point,
                    };
                }
            }
        }
    }

    fn handle_append(&mut self, msg: AppendMessage) {
        if msg
            .session
            .as_ref()
            .is_some_and(|session| session.is_poisoned())
        {
            return;
        }
        let res = self.sequence_records(msg.input);
        if res.is_err()
            && let Some(session) = msg.session
        {
            session.poison();
        }
        match res {
            Ok(sequenced_records) => {
                for sr in sequenced_records.iter() {
                    if let Record::Command(cmd) = &sr.record {
                        self.apply_command(sr.position.seq_num, cmd);
                    }
                }
                let ack = AppendAckRange {
                    start: sequenced_records.first().expect("non-empty").position,
                    end: sequenced_records.last().expect("non-empty").position,
                };
                self.append_futs.push_back(
                    db_write_records(
                        self.db.clone(),
                        self.stream_id,
                        self.config.retention_policy.unwrap_or_default(),
                        sequenced_records,
                        (self.fencing_token.applied_point >= ack.start.seq_num)
                            .then(|| self.fencing_token.state.clone()),
                        (self.trim_point.applied_point >= ack.start.seq_num)
                            .then_some(self.trim_point.state),
                    )
                    .map(move |res| (ack, res))
                    .boxed(),
                );
                self.pending_appends.push_ack(ack, msg.reply_tx);
            }
            Err(AppendError::ConditionFailed(cond_fail))
                if cond_fail.durability_dependency() > self.stable_pos.seq_num =>
            {
                self.pending_appends.push_cond_err(cond_fail, msg.reply_tx);
            }
            Err(e) => {
                let _ = msg.reply_tx.send(Err(e));
            }
        }
    }

    fn handle_other(&mut self, msg: OtherMessage) {
        match msg {
            OtherMessage::Follow {
                start_seq_num,
                reply_tx,
            } => {
                let reply = if start_seq_num == self.stable_pos.seq_num {
                    Ok(self.follower_tx.subscribe())
                } else {
                    Err(self.stable_pos)
                };
                let _ = reply_tx.send(reply);
            }
            OtherMessage::CheckTail { reply_tx } => {
                let _ = reply_tx.send(self.stable_pos);
            }
            OtherMessage::Reconfigure { config } => {
                self.config = config;
            }
        }
    }

    async fn run(
        mut self,
        mut appends_rx: mpsc::Receiver<AppendMessage>,
        mut other_rx: mpsc::UnboundedReceiver<OtherMessage>,
    ) {
        let dormancy = tokio::time::sleep(Duration::MAX);
        tokio::pin!(dormancy);
        loop {
            dormancy.as_mut().reset(Instant::now() + DORMANT_TIMEOUT);
            tokio::select! {
                Some(msg) = appends_rx.recv(), if self.append_futs.len() < MAX_INFLIGHT_APPENDS => {
                    self.handle_append(msg);
                }
                Some(msg) = other_rx.recv() => {
                    self.handle_other(msg);
                }
                Some((ack, res)) = self.append_futs.next() => {
                    match res {
                        Ok(()) => {
                            self.pending_appends.on_stable(ack.end);
                            self.stable_pos = ack.end;
                            // TODO stable_command_state
                        },
                        Err(db_err) => {
                            self.pending_appends.on_fail(db_err);
                            break;
                        },
                    }
                }
                _ = dormancy.as_mut() => {
                    break;
                }
                // TODO dormancy timeout
            }
        }
    }
}

struct AppendMessage {
    session: Option<AppendSessionState>,
    input: AppendInput,
    reply_tx: oneshot::Sender<Result<AppendAck, AppendError>>,
}

enum OtherMessage {
    Follow {
        start_seq_num: SeqNum,
        reply_tx: oneshot::Sender<Result<broadcast::Receiver<ReadBatch>, StreamPosition>>,
    },
    CheckTail {
        reply_tx: oneshot::Sender<StreamPosition>,
    },
    Reconfigure {
        config: OptionalStreamConfig,
    },
}

#[derive(Debug, Clone)]
struct StreamerClient {
    append_tx: mpsc::Sender<AppendMessage>,
    other_tx: mpsc::UnboundedSender<OtherMessage>,
}

impl StreamerClient {
    async fn check_tail(&self) -> Result<StreamPosition, StreamerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.other_tx
            .send(OtherMessage::CheckTail { reply_tx })
            .map_err(|_| StreamerError::Hangup)?;
        let tail = reply_rx.await.map_err(|_| StreamerError::Hangup)?;
        Ok(tail)
    }

    async fn follow(
        &self,
        start_seq_num: SeqNum,
    ) -> Result<Result<broadcast::Receiver<ReadBatch>, StreamPosition>, StreamerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.other_tx
            .send(OtherMessage::Follow {
                start_seq_num,
                reply_tx,
            })
            .map_err(|_| StreamerError::Hangup)?;
        reply_rx.await.map_err(|_| StreamerError::Hangup)
    }

    async fn append(
        &self,
        session: Option<AppendSessionState>,
        input: AppendInput,
    ) -> Result<AppendAck, AppendError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.append_tx
            .send(AppendMessage {
                session,
                input,
                reply_tx,
            })
            .await
            .map_err(|_| StreamerError::Hangup)?;
        reply_rx.await.map_err(|_| StreamerError::Hangup)?
    }

    async fn reconfigure(&self, config: OptionalStreamConfig) -> Result<(), StreamerError> {
        self.other_tx
            .send(OtherMessage::Reconfigure { config })
            .map_err(|_| StreamerError::Hangup)
    }
}

#[derive(Debug, Clone)]
enum StreamerClientState {
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

fn new_records_buf(limit: ReadLimit) -> MeteredSequencedRecords {
    MeteredSequencedRecords::with_capacity(
        limit
            .count()
            .unwrap_or(usize::MAX)
            .min(caps::RECORD_BATCH_MAX.count),
    )
}

fn truncate_records(
    records_in: MeteredSequencedRecords,
    limit: ReadLimit,
    until: ReadUntil,
) -> MeteredSequencedRecords {
    let mut records_out = new_records_buf(limit);
    for record in records_in.into_iter().map(MeteredSequencedRecord::from) {
        if limit.deny(
            records_out.len() + 1,
            records_out.metered_size() + record.metered_size(),
        ) || until.deny(record.position.timestamp)
        {
            break;
        }
        records_out.push(record);
    }
    records_out
}

struct ReadSessionState {
    start_seq_num: u64,
    limit: EvaluatedReadLimit,
    until: ReadUntil,
    tail: StreamPosition,
}

impl ReadSessionState {
    fn on_batch(&mut self, batch: ReadBatch) -> ReadSessionOutput {
        if let Some(tail) = batch.tail {
            self.tail = tail;
        }
        let last_record = batch.records.last().expect("non-empty");
        let EvaluatedReadLimit::Remaining(limit) = self.limit else {
            panic!("batch after exhausted limit");
        };
        let count = batch.records.len();
        let bytes = batch.records.metered_size();
        assert!(limit.allow(count, bytes));
        assert!(self.until.allow(last_record.position.timestamp));
        self.start_seq_num = last_record.position.seq_num + 1;
        self.limit = limit.remaining(count, bytes);
        ReadSessionOutput::Batch(batch)
    }
}

fn new_heartbeat_sleep() -> tokio::time::Sleep {
    tokio::time::sleep(Duration::from_millis(rand::random_range(5_000..15_000)))
}

fn sequenced_records(
    records_in: AppendRecordBatch,
    first_seq_num: SeqNum,
    prev_max_timestamp: Timestamp,
    config: &OptionalTimestampingConfig,
) -> Result<Vec<MeteredSequencedRecord>, AppendError> {
    let mode = config.mode.unwrap_or_default();
    let uncapped = config.uncapped.unwrap_or_default();
    let mut records_out = Vec::with_capacity(records_in.len());
    let mut max_timestamp = prev_max_timestamp;
    let now = timestamp_now();
    for (i, AppendRecordParts { timestamp, record }) in
        records_in.into_iter().map(Into::into).enumerate()
    {
        let mut timestamp = match mode {
            TimestampingMode::ClientPrefer => timestamp.unwrap_or(now),
            // TODO
            TimestampingMode::ClientRequire => {
                timestamp.ok_or_else(|| AppendError::TimestampMissing)?
            }
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

        records_out.push(record.sequenced(StreamPosition {
            seq_num: first_seq_num + i as u64,
            timestamp,
        }));
    }
    Ok(records_out)
}

async fn db_write_records(
    db: slatedb::Db,
    stream_id: StreamId,
    retention: RetentionPolicy,
    records: Vec<MeteredSequencedRecord>,
    fencing_token: Option<FencingToken>,
    trim_point: Option<SeqNum>,
) -> Result<(), slatedb::Error> {
    let ttl = match retention {
        RetentionPolicy::Age(age) => Ttl::ExpireAfter(age.as_millis() as u64),
        RetentionPolicy::Infinite() => Ttl::NoExpiry,
    };
    let ttl_put_opts = PutOptions { ttl };
    let tail = records.last().expect("non-empty").position;
    let mut wb = WriteBatch::new();
    for (position, record) in records.into_iter().map(MeteredSequencedRecord::into_parts) {
        wb.put_with_options(
            kv::stream_record_data::ser_key(stream_id, position),
            kv::stream_record_data::ser_value(&record),
            &ttl_put_opts,
        );
        wb.put_with_options(
            kv::stream_record_timestamp::ser_key(stream_id, position.timestamp),
            kv::stream_record_timestamp::ser_value(position.seq_num),
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
        kv::stream_tail_position::ser_value(tail),
    );
    const WRITE_OPTIONS: WriteOptions = WriteOptions {
        await_durable: true,
    };
    db.write_with_options(wb, &WRITE_OPTIONS).await
}

fn timestamp_now() -> Timestamp {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .expect("Milliseconds since Unix epoch fits into a u64")
}

#[derive(Debug)]
struct PendingAppends {
    queue: VecDeque<PendingAppendReply>,
    next_ack_pos: Option<StreamPosition>,
}

impl PendingAppends {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            next_ack_pos: None,
        }
    }

    pub fn next_ack_pos(&self) -> Option<StreamPosition> {
        self.next_ack_pos
    }

    pub fn push_ack(
        &mut self,
        ack: AppendAckRange,
        reply_tx: oneshot::Sender<Result<AppendAck, AppendError>>,
    ) {
        if let Some(prev_pos) = self.next_ack_pos.replace(StreamPosition {
            seq_num: ack.end.seq_num,
            timestamp: ack.end.timestamp,
        }) {
            assert_eq!(ack.start.seq_num, prev_pos.seq_num);
            assert!(ack.start.timestamp >= prev_pos.timestamp);
        }
        self.queue.push_back(PendingAppendReply {
            reply: Ok(ack),
            reply_tx,
        });
    }

    pub fn push_cond_err(
        &mut self,
        cond_fail: AppendConditionFailed,
        reply_tx: oneshot::Sender<Result<AppendAck, AppendError>>,
    ) {
        self.queue.push_back(PendingAppendReply {
            reply: Err(cond_fail),
            reply_tx,
        });
    }

    pub fn on_stable(&mut self, stable_pos: StreamPosition) {
        let completable = self
            .queue
            .iter()
            .take_while(|pa| pa.durability_dependency() <= stable_pos.seq_num)
            .count();
        for pa in self.queue.drain(..completable) {
            pa.unblock(Ok(stable_pos));
        }
    }

    pub fn on_fail(self, e: slatedb::Error) {
        let err = StreamerError::Slate(Arc::new(e));
        for reply in self.queue {
            reply.unblock(Err(err.clone()));
        }
    }
}

#[derive(Debug)]
struct PendingAppendReply {
    reply: Result<AppendAckRange, AppendConditionFailed>,
    reply_tx: oneshot::Sender<Result<AppendAck, AppendError>>,
}

impl PendingAppendReply {
    fn durability_dependency(&self) -> SeqNum {
        match &self.reply {
            Ok(ack) => ack.end.seq_num,
            Err(e) => e.durability_dependency(),
        }
    }

    fn unblock(self, stable_pos: Result<StreamPosition, StreamerError>) {
        let reply = match stable_pos {
            Ok(stable_pos) => {
                assert!(self.durability_dependency() <= stable_pos.seq_num);
                match self.reply {
                    Ok(ack) => Ok(AppendAck {
                        start: ack.start,
                        end: ack.end,
                        tail: stable_pos,
                    }),
                    Err(cond_fail) => Err(cond_fail.into()),
                }
            }
            Err(e) => Err(e.into()),
        };
        let _ = self.reply_tx.send(reply);
    }
}
