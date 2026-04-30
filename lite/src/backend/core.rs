use std::sync::Arc;

use bytesize::ByteSize;
use dashmap::DashMap;
use futures::{
    FutureExt as _,
    future::{BoxFuture, Shared},
};
use s2_common::{
    encryption::{EncryptionAlgorithm, EncryptionSpec},
    record::{NonZeroSeqNum, SeqNum, StreamPosition, Timestamp},
    types::{
        basin::BasinName,
        config::{BasinConfig, OptionalStreamConfig},
        resources::CreateMode,
        stream::StreamName,
    },
};
use slatedb::{
    IterationOrder,
    config::{DurabilityLevel, ScanOptions},
};
use tokio::sync::{Semaphore, broadcast};

use super::{
    StreamHandle,
    durability_notifier::DurabilityNotifier,
    error::{
        BasinDeletionPendingError, BasinNotFoundError, CreateStreamError, GetBasinConfigError,
        StorageError, StreamDeletionPendingError, StreamNotFoundError, StreamerError,
        StreamerMissingInActionError, TransactionConflictError,
    },
    kv,
    streamer::{GuardedStreamerClient, StreamerClient, StreamerGenerationId},
};
use crate::{backend::bgtasks::BgtaskTrigger, stream_id::StreamId};

type StreamerInitFuture = Shared<BoxFuture<'static, Result<StreamerClient, StreamerError>>>;

#[derive(Clone)]
enum StreamerClientSlot {
    Initializing {
        generation_id: StreamerGenerationId,
        future: StreamerInitFuture,
    },
    Ready {
        client: StreamerClient,
    },
}

#[derive(Clone)]
pub struct Backend {
    pub(super) db: slatedb::Db,
    streamer_slots: Arc<DashMap<StreamId, StreamerClientSlot>>,
    append_inflight_bytes_sema: Arc<Semaphore>,
    durability_notifier: DurabilityNotifier,
    bgtask_trigger_tx: broadcast::Sender<BgtaskTrigger>,
}

impl Backend {
    pub fn new(db: slatedb::Db, append_inflight_bytes: ByteSize) -> Self {
        let (bgtask_trigger_tx, _) = broadcast::channel(16);
        let append_inflight_bytes = Arc::new(Semaphore::new(
            (append_inflight_bytes.as_u64() as usize).clamp(
                s2_common::caps::RECORD_BATCH_MAX.bytes,
                Semaphore::MAX_PERMITS,
            ),
        ));
        let durability_notifier = DurabilityNotifier::spawn(&db);
        Self {
            db,
            streamer_slots: Arc::new(DashMap::new()),
            append_inflight_bytes_sema: append_inflight_bytes,
            durability_notifier,
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
        generation_id: StreamerGenerationId,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<StreamerClient, StreamerError> {
        let stream_id = StreamId::new(&basin, &stream);

        let (meta, tail_pos, fencing_token, trim_point) = tokio::try_join!(
            self.db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            ),
            self.derive_tail_position(stream_id),
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

        let (tail_pos, _write_ts) = tail_pos;

        let fencing_token = fencing_token.unwrap_or_default();

        if trim_point == Some(..NonZeroSeqNum::MAX) {
            return Err(StreamDeletionPendingError { basin, stream }.into());
        }

        let streamer_slots = self.streamer_slots.clone();
        Ok(super::streamer::Spawner {
            generation_id,
            db: self.db.clone(),
            stream_id,
            config: meta.config,
            cipher: meta.cipher,
            tail_pos,
            fencing_token,
            trim_point: ..trim_point.map_or(SeqNum::MIN, |tp| tp.end.get()),
            append_inflight_bytes_sema: self.append_inflight_bytes_sema.clone(),
            durability_notifier: self.durability_notifier.clone(),
            bgtask_trigger_tx: self.bgtask_trigger_tx.clone(),
        }
        .spawn(move |client_id| {
            streamer_slots.remove_if(&stream_id, |_, slot| {
                matches!(slot, StreamerClientSlot::Ready { client } if client.generation_id() == client_id)
            });
        }))
    }

    /// Derive the stream tail position by reverse-scanning `StreamRecordData` keys.
    /// If no records exist, falls back to the explicit `StreamTailPosition` marker key.
    ///
    /// Returns `(tail_position, Option<write_timestamp_secs>)`.
    /// - `write_timestamp_secs` is `Some` only when read from the marker key (empty stream).
    /// - `write_timestamp_secs` is `None` when derived from the last record.
    async fn derive_tail_position(
        &self,
        stream_id: StreamId,
    ) -> Result<(StreamPosition, Option<kv::timestamp::TimestampSecs>), StorageError> {
        // Scan StreamRecordData keys for this stream in reverse order.
        let lower_bound = kv::stream_record_data::ser_key(stream_id, StreamPosition::MIN);
        let upper_bound = kv::stream_record_data::ser_key(
            stream_id,
            StreamPosition {
                seq_num: SeqNum::MAX,
                timestamp: Timestamp::MAX,
            },
        );
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
            order: IterationOrder::Descending,
        };
        let mut it = self
            .db
            .scan_with_options(lower_bound..upper_bound, &SCAN_OPTS)
            .await?;
        if let Some(kv_entry) = it.next().await? {
            if kv_entry.key.first().copied() == Some(kv::KeyType::StreamRecordData as u8) {
                let (deser_stream_id, pos) =
                    kv::stream_record_data::deser_key(kv_entry.key)?;
                if deser_stream_id == stream_id {
                    // Found the last record — tail is one past it.
                    let tail = StreamPosition {
                        seq_num: pos.seq_num + 1,
                        timestamp: pos.timestamp,
                    };
                    return Ok((tail, None));
                }
            }
        }

        // No records found — fall back to the explicit tail position marker.
        if let Some((pos, write_ts)) = self
            .db_get(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::deser_value,
            )
            .await?
        {
            return Ok((pos, Some(write_ts)));
        }

        // No marker either — stream starts at MIN.
        Ok((StreamPosition::MIN, None))
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
            order: IterationOrder::Ascending,
        };
        let mut it = self.db.scan_with_options(start_key.., &SCAN_OPTS).await?;
        let Some(kv) = it.next().await? else {
            return Ok(());
        };
        if kv.key.first().copied() != Some(kv::KeyType::StreamRecordData as u8) {
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
        match self.streamer_slots.entry(StreamId::new(basin, stream)) {
            dashmap::Entry::Occupied(mut oe) => {
                if matches!(oe.get(), StreamerClientSlot::Ready { client } if client.is_dead()) {
                    let slot = self.clone().new_initializing_slot(basin, stream);
                    oe.insert(slot.clone());
                    slot
                } else {
                    oe.get().clone()
                }
            }
            dashmap::Entry::Vacant(ve) => {
                let slot = self.clone().new_initializing_slot(basin, stream);
                ve.insert(slot.clone());
                slot
            }
        }
    }

    fn new_initializing_slot(self, basin: &BasinName, stream: &StreamName) -> StreamerClientSlot {
        let basin = basin.clone();
        let stream = stream.clone();
        let generation_id = StreamerGenerationId::next();
        let future = async move { self.start_streamer(generation_id, basin, stream).await }
            .boxed()
            .shared();
        StreamerClientSlot::Initializing {
            generation_id,
            future,
        }
    }

    fn streamer_finish_initialization(
        &self,
        stream_id: StreamId,
        generation_id: StreamerGenerationId,
        result: &Result<StreamerClient, StreamerError>,
    ) {
        if let dashmap::Entry::Occupied(mut oe) = self.streamer_slots.entry(stream_id) {
            let is_same_init = matches!(
                oe.get(),
                StreamerClientSlot::Initializing {
                    generation_id: state_generation_id,
                    ..
                } if *state_generation_id == generation_id
            );
            if is_same_init {
                match result {
                    Ok(client) => {
                        debug_assert_eq!(client.generation_id(), generation_id);
                        if client.is_dead() {
                            oe.remove();
                        } else {
                            oe.insert(StreamerClientSlot::Ready {
                                client: client.clone(),
                            });
                        }
                    }
                    Err(_) => {
                        oe.remove();
                    }
                }
            }
        }
    }

    pub(super) async fn streamer_client(
        &self,
        basin: &BasinName,
        stream: &StreamName,
    ) -> Result<StreamerClient, StreamerError> {
        let stream_id = StreamId::new(basin, stream);
        match self.streamer_client_slot(basin, stream) {
            StreamerClientSlot::Initializing {
                generation_id,
                future,
            } => {
                let result = future.await;
                self.streamer_finish_initialization(stream_id, generation_id, &result);
                result
            }
            StreamerClientSlot::Ready { client } => Ok(client),
        }
    }

    pub(super) fn streamer_client_if_active(
        &self,
        basin: &BasinName,
        stream: &StreamName,
    ) -> Option<StreamerClient> {
        let stream_id = StreamId::new(basin, stream);
        let slot = self.streamer_slots.get(&stream_id)?;
        match slot.value() {
            StreamerClientSlot::Ready { client } if !client.is_dead() => Some(client.clone()),
            _ => None,
        }
    }

    pub(super) async fn streamer_client_guarded(
        &self,
        basin: &BasinName,
        stream: &StreamName,
    ) -> Result<GuardedStreamerClient, StreamerError> {
        loop {
            let client = self.streamer_client(basin, stream).await?;
            match client.guard() {
                Ok(client) => return Ok(client),
                Err(StreamerMissingInActionError) => continue,
            }
        }
    }

    pub(super) async fn stream_handle_with_auto_create<E>(
        &self,
        basin: &BasinName,
        stream: &StreamName,
        should_auto_create: impl FnOnce(&BasinConfig) -> bool,
        resolve_encryption: impl FnOnce(Option<EncryptionAlgorithm>) -> Result<EncryptionSpec, E>,
    ) -> Result<StreamHandle, E>
    where
        E: From<StreamerError>
            + From<StorageError>
            + From<BasinNotFoundError>
            + From<TransactionConflictError>
            + From<BasinDeletionPendingError>
            + From<StreamDeletionPendingError>
            + From<StreamNotFoundError>,
    {
        match self.streamer_client_guarded(basin, stream).await {
            Ok(client) => Ok(StreamHandle {
                db: self.db.clone(),
                encryption: resolve_encryption(client.cipher())?,
                client,
            }),
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
                            CreateStreamError::Validation(_) => {
                                unreachable!("auto-create uses default config")
                            }
                        }
                    }
                    let client = self.streamer_client_guarded(basin, stream).await?;
                    let encryption = resolve_encryption(client.cipher())?;
                    Ok(StreamHandle {
                        db: self.db.clone(),
                        encryption,
                        client,
                    })
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
        record::{Metered, Record, StoredRecord, StreamPosition},
        types::{
            config::{BasinConfig, OptionalStreamConfig},
            resources::CreateMode,
        },
    };
    use slatedb::{WriteBatch, config::WriteOptions, object_store};
    use time::OffsetDateTime;

    use super::*;

    async fn new_test_backend() -> Backend {
        let object_store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let db = slatedb::Db::builder("test", object_store)
            .build()
            .await
            .unwrap();
        Backend::new(db, ByteSize::b(1))
    }

    #[tokio::test]
    async fn start_streamer_derives_tail_from_records_not_marker() {
        let backend = new_test_backend().await;

        let basin = BasinName::from_str("testbasin1").unwrap();
        let stream = StreamName::from_str("stream1").unwrap();
        let stream_id = StreamId::new(&basin, &stream);

        let meta = kv::stream_meta::StreamMeta {
            config: OptionalStreamConfig::default(),
            cipher: None,
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
            creation_idempotency_key: None,
        };

        // Write a stale tail position marker at seq_num=1.
        let stale_tail_pos = StreamPosition {
            seq_num: 1,
            timestamp: 123,
        };
        // Write a record at seq_num=1 (past the marker).
        let record_pos = StreamPosition {
            seq_num: stale_tail_pos.seq_num,
            timestamp: stale_tail_pos.timestamp,
        };

        let record = Record::try_from_parts(vec![], Bytes::from_static(b"hello")).unwrap();
        let metered_record: Metered<StoredRecord> = StoredRecord::from(record).into();

        let mut wb = WriteBatch::new();
        wb.put(
            kv::stream_meta::ser_key(&basin, &stream),
            kv::stream_meta::ser_value(&meta),
        );
        wb.put(
            kv::stream_tail_position::ser_key(stream_id),
            kv::stream_tail_position::ser_value(
                stale_tail_pos,
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
        backend
            .db
            .write_with_options(wb, &WRITE_OPTS)
            .await
            .unwrap();

        // derive_tail_position should find the record and derive tail as seq_num=2.
        let (tail_pos, write_ts) = backend
            .derive_tail_position(stream_id)
            .await
            .unwrap();
        assert_eq!(tail_pos.seq_num, 2);
        assert_eq!(tail_pos.timestamp, 123);
        // Derived from records, not from marker key.
        assert!(write_ts.is_none());
    }

    #[tokio::test]
    async fn streamer_client_slot_uses_single_initializer() {
        let backend = new_test_backend().await;
        let basin = BasinName::from_str("testbasin2").unwrap();
        let stream = StreamName::from_str("stream2").unwrap();

        let slot_1 = backend.streamer_client_slot(&basin, &stream);
        let slot_2 = backend.streamer_client_slot(&basin, &stream);

        let (generation_id_1, generation_id_2) = match (slot_1, slot_2) {
            (
                StreamerClientSlot::Initializing {
                    generation_id: generation_id_1,
                    ..
                },
                StreamerClientSlot::Initializing {
                    generation_id: generation_id_2,
                    ..
                },
            ) => (generation_id_1, generation_id_2),
            _ => panic!("expected both slots to be Initializing"),
        };
        assert_eq!(generation_id_1, generation_id_2);
        assert_eq!(backend.streamer_slots.len(), 1);
    }

    #[tokio::test]
    async fn streamer_client_if_active_is_peek_only() {
        let backend = new_test_backend().await;
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

        assert!(backend.streamer_slots.is_empty());
        assert!(backend.streamer_client_if_active(&basin, &stream).is_none());
        assert!(backend.streamer_slots.is_empty());
    }

    #[tokio::test]
    async fn streamer_client_failed_init_is_not_memoized() {
        let backend = new_test_backend().await;
        let basin = BasinName::from_str("testbasin4").unwrap();
        let stream = StreamName::from_str("stream4").unwrap();
        let stream_id = StreamId::new(&basin, &stream);

        for _ in 0..2 {
            let err = backend.streamer_client(&basin, &stream).await;
            assert!(matches!(err, Err(StreamerError::StreamNotFound(_))));
            assert!(
                backend.streamer_slots.get(&stream_id).is_none(),
                "failed init should not be cached"
            );
        }
    }

    #[tokio::test]
    async fn streamer_finish_initialization_ignores_stale_generation_id() {
        let backend = new_test_backend().await;
        let basin = BasinName::from_str("testbasin5").unwrap();
        let stream = StreamName::from_str("stream5").unwrap();
        let stream_id = StreamId::new(&basin, &stream);

        let stale_generation_id = StreamerGenerationId::next();
        let current_generation_id = StreamerGenerationId::next();
        let future = futures::future::pending::<Result<StreamerClient, StreamerError>>()
            .boxed()
            .shared();
        backend.streamer_slots.insert(
            stream_id,
            StreamerClientSlot::Initializing {
                generation_id: current_generation_id,
                future: future.clone(),
            },
        );

        let stale_result = Err(StreamNotFoundError { basin, stream }.into());
        backend.streamer_finish_initialization(stream_id, stale_generation_id, &stale_result);

        let Some(slot) = backend.streamer_slots.get(&stream_id) else {
            panic!("stale init completion should not alter slot state");
        };
        match slot.value() {
            StreamerClientSlot::Initializing { generation_id, .. } => {
                assert_eq!(*generation_id, current_generation_id)
            }
            _ => panic!("expected initializing slot to remain unchanged"),
        }
    }
}
