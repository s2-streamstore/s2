use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytesize::ByteSize;
use dashmap::DashMap;
use enum_ordinalize::Ordinalize;
use futures::{
    FutureExt as _,
    future::{BoxFuture, Shared},
};
use s2_common::{
    record::{NonZeroSeqNum, SeqNum, StreamPosition},
    types::{
        basin::BasinName,
        config::{BasinConfig, OptionalStreamConfig},
        resources::CreateMode,
        stream::StreamName,
    },
};
use slatedb::config::{DurabilityLevel, ScanOptions};
use tokio::{sync::broadcast, time::Instant};

use super::{
    error::{
        BasinDeletionPendingError, BasinNotFoundError, CreateStreamError, GetBasinConfigError,
        StorageError, StreamDeletionPendingError, StreamNotFoundError, StreamerError,
        TransactionConflictError,
    },
    kv,
    stream_id::StreamId,
    streamer::StreamerClient,
};
use crate::backend::bgtasks::BgtaskTrigger;

type InitFuture = Shared<BoxFuture<'static, Result<StreamerClient, StreamerError>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StreamerInitId(u64);

impl StreamerInitId {
    fn next() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Clone)]
enum StreamerClientSlot {
    Initializing {
        init_id: StreamerInitId,
        future: InitFuture,
    },
    Failed {
        error: StreamerError,
        timestamp: Instant,
    },
    Ready {
        client: StreamerClient,
    },
}

#[derive(Clone)]
pub struct Backend {
    pub(super) db: slatedb::Db,
    client_states: Arc<DashMap<StreamId, StreamerClientSlot>>,
    append_inflight_max: ByteSize,
    bgtask_trigger_tx: broadcast::Sender<BgtaskTrigger>,
}

impl Backend {
    const STREAMER_FAILED_INIT_MEMORY: Duration = Duration::from_secs(1);

    pub fn new(db: slatedb::Db, append_inflight_max: ByteSize) -> Self {
        let (bgtask_trigger_tx, _) = broadcast::channel(16);
        Self {
            db,
            client_states: Arc::new(DashMap::new()),
            append_inflight_max,
            bgtask_trigger_tx,
        }
    }

    pub(super) fn bgtask_trigger(&self, trigger: BgtaskTrigger) {
        let _ = self.bgtask_trigger_tx.send(trigger);
    }

    pub(super) fn bgtask_trigger_subscribe(&self) -> broadcast::Receiver<BgtaskTrigger> {
        self.bgtask_trigger_tx.subscribe()
    }

    async fn start_streamer(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<StreamerClient, StreamerError> {
        let stream_id = StreamId::new(&basin, &stream);

        let (meta, tail_pos, fencing_token, trim_point) = tokio::try_join!(
            self.db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            ),
            self.db_get(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::deser_value,
            ),
            self.db_get(
                kv::stream_fencing_token::ser_key(stream_id),
                kv::stream_fencing_token::deser_value,
            ),
            self.db_get(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::deser_value,
            )
        )?;

        let Some(meta) = meta else {
            return Err(StreamNotFoundError { basin, stream }.into());
        };

        let tail_pos = tail_pos.map(|(pos, _)| pos).unwrap_or(StreamPosition::MIN);
        self.assert_no_records_following_tail(stream_id, &basin, &stream, tail_pos)
            .await?;

        let fencing_token = fencing_token.unwrap_or_default();

        if trim_point == Some(..NonZeroSeqNum::MAX) {
            return Err(StreamDeletionPendingError { basin, stream }.into());
        }

        let client_states = self.client_states.clone();
        Ok(super::streamer::Spawner {
            db: self.db.clone(),
            stream_id,
            config: meta.config,
            tail_pos,
            fencing_token,
            trim_point: ..trim_point.map_or(SeqNum::MIN, |tp| tp.end.get()),
            append_inflight_max: self.append_inflight_max,
            bgtask_trigger_tx: self.bgtask_trigger_tx.clone(),
        }
        .spawn(move |client_id| {
            client_states.remove_if(&stream_id, |_, state| {
                matches!(state, StreamerClientSlot::Ready { client } if client.id() == client_id)
            });
        }))
    }

    async fn assert_no_records_following_tail(
        &self,
        stream_id: StreamId,
        basin: &BasinName,
        stream: &StreamName,
        tail_pos: StreamPosition,
    ) -> Result<(), StorageError> {
        let start_key = kv::stream_record_data::ser_key(
            stream_id,
            StreamPosition {
                seq_num: tail_pos.seq_num,
                timestamp: 0,
            },
        );
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self.db.scan_with_options(start_key.., &SCAN_OPTS).await?;
        let Some(kv) = it.next().await? else {
            return Ok(());
        };
        if kv.key.first().copied() != Some(kv::KeyType::StreamRecordData.ordinal()) {
            return Ok(());
        }
        let (deser_stream_id, pos) = kv::stream_record_data::deser_key(kv.key)?;
        assert!(
            deser_stream_id != stream_id,
            "invariant violation: stream `{basin}/{stream}` tail_pos {tail_pos:?} but found record at {pos:?}"
        );
        Ok(())
    }

    fn streamer_client_slot(&self, basin: &BasinName, stream: &StreamName) -> StreamerClientSlot {
        match self.client_states.entry(StreamId::new(basin, stream)) {
            dashmap::Entry::Occupied(oe) => oe.get().clone(),
            dashmap::Entry::Vacant(ve) => {
                let this = self.clone();
                let basin = basin.clone();
                let stream = stream.clone();
                let init_id = StreamerInitId::next();
                let future = async move { this.start_streamer(basin, stream).await }
                    .boxed()
                    .shared();
                let slot = StreamerClientSlot::Initializing {
                    init_id,
                    future: future.clone(),
                };
                ve.insert(slot.clone());
                slot
            }
        }
    }

    fn streamer_finish_initializing(
        &self,
        stream_id: StreamId,
        init_id: StreamerInitId,
        result: &Result<StreamerClient, StreamerError>,
    ) {
        if let dashmap::Entry::Occupied(mut oe) = self.client_states.entry(stream_id) {
            let is_same_init = matches!(
                oe.get(),
                StreamerClientSlot::Initializing {
                    init_id: state_init_id,
                    ..
                } if *state_init_id == init_id
            );
            if is_same_init {
                oe.insert(match result {
                    Ok(client) => StreamerClientSlot::Ready {
                        client: client.clone(),
                    },
                    Err(error) => StreamerClientSlot::Failed {
                        error: error.clone(),
                        timestamp: Instant::now(),
                    },
                });
            }
        }
    }

    fn streamer_remove_failed(&self, stream_id: StreamId, failed_at: Instant) {
        if let dashmap::Entry::Occupied(oe) = self.client_states.entry(stream_id) {
            let is_same_failure = matches!(
                oe.get(),
                StreamerClientSlot::Failed { timestamp, .. } if *timestamp == failed_at
            );
            if is_same_failure {
                oe.remove();
            }
        }
    }

    fn streamer_remove_failed_any(&self, stream_id: StreamId) {
        if let dashmap::Entry::Occupied(oe) = self.client_states.entry(stream_id)
            && matches!(oe.get(), StreamerClientSlot::Failed { .. })
        {
            oe.remove();
        }
    }

    pub(super) async fn streamer_client(
        &self,
        basin: &BasinName,
        stream: &StreamName,
    ) -> Result<StreamerClient, StreamerError> {
        let stream_id = StreamId::new(basin, stream);
        loop {
            match self.streamer_client_slot(basin, stream) {
                StreamerClientSlot::Initializing { init_id, future } => {
                    let result = future.await;
                    self.streamer_finish_initializing(stream_id, init_id, &result);
                    match result {
                        Ok(client) => return Ok(client),
                        Err(error) => return Err(error),
                    }
                }
                StreamerClientSlot::Failed { error, timestamp } => {
                    if timestamp.elapsed() > Self::STREAMER_FAILED_INIT_MEMORY {
                        self.streamer_remove_failed(stream_id, timestamp);
                    } else {
                        return Err(error);
                    }
                }
                StreamerClientSlot::Ready { client } => {
                    return Ok(client);
                }
            }
        }
    }

    pub(super) fn streamer_client_if_active(
        &self,
        basin: &BasinName,
        stream: &StreamName,
    ) -> Option<StreamerClient> {
        let stream_id = StreamId::new(basin, stream);
        let state = self.client_states.get(&stream_id)?;
        match state.value() {
            StreamerClientSlot::Ready { client } => Some(client.clone()),
            _ => None,
        }
    }

    pub(super) async fn streamer_client_with_auto_create<E>(
        &self,
        basin: &BasinName,
        stream: &StreamName,
        should_auto_create: impl FnOnce(&BasinConfig) -> bool,
    ) -> Result<StreamerClient, E>
    where
        E: From<StreamerError>
            + From<StorageError>
            + From<BasinNotFoundError>
            + From<TransactionConflictError>
            + From<BasinDeletionPendingError>
            + From<StreamDeletionPendingError>
            + From<StreamNotFoundError>,
    {
        match self.streamer_client(basin, stream).await {
            Ok(client) => Ok(client),
            Err(StreamerError::StreamNotFound(e)) => {
                let config = match self.get_basin_config(basin.clone()).await {
                    Ok(config) => config,
                    Err(GetBasinConfigError::Storage(e)) => Err(e)?,
                    Err(GetBasinConfigError::BasinNotFound(e)) => Err(e)?,
                };
                if should_auto_create(&config) {
                    if let Err(e) = self
                        .create_stream(
                            basin.clone(),
                            stream.clone(),
                            OptionalStreamConfig::default(),
                            CreateMode::CreateOnly(None),
                        )
                        .await
                    {
                        match e {
                            CreateStreamError::Storage(e) => Err(e)?,
                            CreateStreamError::TransactionConflict(e) => Err(e)?,
                            CreateStreamError::BasinDeletionPending(e) => Err(e)?,
                            CreateStreamError::StreamDeletionPending(e) => Err(e)?,
                            CreateStreamError::BasinNotFound(e) => Err(e)?,
                            CreateStreamError::StreamAlreadyExists(_) => {}
                        }
                    }
                    // Clear stale StreamNotFound init failures before immediate re-fetch.
                    self.streamer_remove_failed_any(StreamId::new(basin, stream));
                    Ok(self.streamer_client(basin, stream).await?)
                } else {
                    Err(e.into())
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use bytes::Bytes;
    use s2_common::{
        record::{Metered, Record, StreamPosition},
        types::{config::BasinConfig, resources::CreateMode},
    };
    use slatedb::{WriteBatch, config::WriteOptions, object_store};
    use time::OffsetDateTime;

    use super::*;

    #[tokio::test]
    #[should_panic(expected = "invariant violation: stream `testbasin1/stream1` tail_pos")]
    async fn start_streamer_fails_if_records_exist_after_tail_pos() {
        let object_store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let db = slatedb::Db::builder("test", object_store)
            .build()
            .await
            .unwrap();

        let backend = Backend::new(db.clone(), ByteSize::b(1));

        let basin = BasinName::from_str("testbasin1").unwrap();
        let stream = StreamName::from_str("stream1").unwrap();
        let stream_id = StreamId::new(&basin, &stream);

        let meta = kv::stream_meta::StreamMeta {
            config: OptionalStreamConfig::default(),
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
            creation_idempotency_key: None,
        };

        let tail_pos = StreamPosition {
            seq_num: 1,
            timestamp: 123,
        };
        let record_pos = StreamPosition {
            seq_num: tail_pos.seq_num,
            timestamp: tail_pos.timestamp,
        };

        let record = Record::try_from_parts(vec![], Bytes::from_static(b"hello")).unwrap();
        let metered_record: Metered<Record> = record.into();

        let mut wb = WriteBatch::new();
        wb.put(
            kv::stream_meta::ser_key(&basin, &stream),
            kv::stream_meta::ser_value(&meta),
        );
        wb.put(
            kv::stream_tail_position::ser_key(stream_id),
            kv::stream_tail_position::ser_value(
                tail_pos,
                kv::timestamp::TimestampSecs::from_secs(1),
            ),
        );
        wb.put(
            kv::stream_record_data::ser_key(stream_id, record_pos),
            kv::stream_record_data::ser_value(metered_record.as_ref()),
        );
        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        db.write_with_options(wb, &WRITE_OPTS).await.unwrap();

        backend
            .start_streamer(basin.clone(), stream.clone())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn streamer_client_slot_uses_single_initializer() {
        let object_store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let db = slatedb::Db::builder("test", object_store)
            .build()
            .await
            .unwrap();

        let backend = Backend::new(db, ByteSize::b(1));
        let basin = BasinName::from_str("testbasin2").unwrap();
        let stream = StreamName::from_str("stream2").unwrap();

        let slot_1 = backend.streamer_client_slot(&basin, &stream);
        let slot_2 = backend.streamer_client_slot(&basin, &stream);

        let (init_id_1, init_id_2) = match (slot_1, slot_2) {
            (
                StreamerClientSlot::Initializing {
                    init_id: init_id_1, ..
                },
                StreamerClientSlot::Initializing {
                    init_id: init_id_2, ..
                },
            ) => (init_id_1, init_id_2),
            _ => panic!("expected both slots to be Initializing"),
        };
        assert_eq!(init_id_1, init_id_2);
        assert_eq!(backend.client_states.len(), 1);
    }

    #[tokio::test]
    async fn streamer_client_if_active_is_peek_only() {
        let object_store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let db = slatedb::Db::builder("test", object_store)
            .build()
            .await
            .unwrap();

        let backend = Backend::new(db, ByteSize::b(1));
        let basin = BasinName::from_str("testbasin3").unwrap();
        let stream = StreamName::from_str("stream3").unwrap();

        backend
            .create_basin(
                basin.clone(),
                BasinConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();
        backend
            .create_stream(
                basin.clone(),
                stream.clone(),
                OptionalStreamConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();

        assert!(backend.client_states.is_empty());
        assert!(backend.streamer_client_if_active(&basin, &stream).is_none());
        assert!(backend.client_states.is_empty());
    }

    #[tokio::test]
    async fn streamer_client_failed_init_is_temporarily_memoized() {
        let object_store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let db = slatedb::Db::builder("test", object_store)
            .build()
            .await
            .unwrap();

        let backend = Backend::new(db, ByteSize::b(1));
        let basin = BasinName::from_str("testbasin4").unwrap();
        let stream = StreamName::from_str("stream4").unwrap();
        let stream_id = StreamId::new(&basin, &stream);

        let err_1 = backend.streamer_client(&basin, &stream).await;
        assert!(matches!(err_1, Err(StreamerError::StreamNotFound(_))));
        let first_failed_at = match backend.client_states.get(&stream_id) {
            Some(slot) => match slot.value() {
                StreamerClientSlot::Failed { timestamp, .. } => *timestamp,
                _ => panic!("expected Failed slot after first init error"),
            },
            None => panic!("missing slot after first init error"),
        };

        let err_2 = backend.streamer_client(&basin, &stream).await;
        assert!(matches!(err_2, Err(StreamerError::StreamNotFound(_))));
        let second_failed_at = match backend.client_states.get(&stream_id) {
            Some(slot) => match slot.value() {
                StreamerClientSlot::Failed { timestamp, .. } => *timestamp,
                _ => panic!("expected Failed slot after second init error"),
            },
            None => panic!("missing slot after second init error"),
        };

        assert_eq!(first_failed_at, second_failed_at);
    }
}
