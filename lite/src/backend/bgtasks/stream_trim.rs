use std::ops::RangeTo;

use enum_ordinalize::Ordinalize;
use futures::{StreamExt, stream};
use s2_common::{
    record::{SeqNum, StreamPosition, Timestamp},
    types::resources::Page,
};
use slatedb::{
    WriteBatch,
    config::{DurabilityLevel, ScanOptions, WriteOptions},
};
use tracing::instrument;

use crate::backend::{Backend, error::StorageError, kv, stream_id::StreamId};

const PENDING_LIST_LIMIT: usize = 128;
const CONCURRENCY: usize = 4;
const DELETE_BATCH_SIZE: usize = 10_000;

impl Backend {
    pub(crate) async fn tick_stream_trim(self) -> Result<bool, StorageError> {
        let page = self.list_stream_trim_pending().await?;
        if page.values.is_empty() {
            return Ok(page.has_more);
        }
        let mut processed = stream::iter(page.values)
            .map(|(stream_id, trim_point)| {
                let backend = self.clone();
                async move { backend.process_trim(stream_id, trim_point).await }
            })
            .buffer_unordered(CONCURRENCY);
        while let Some(result) = processed.next().await {
            result?;
        }
        Ok(page.has_more)
    }

    async fn list_stream_trim_pending(
        &self,
    ) -> Result<Page<(StreamId, RangeTo<SeqNum>)>, StorageError> {
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self
            .db
            .scan_with_options(kv::key_type_range(kv::KeyType::StreamTrimPoint), &SCAN_OPTS)
            .await?;
        let mut pending = Vec::new();
        while let Some(kv) = it.next().await? {
            let stream_id = kv::stream_trim_point::deser_key(kv.key)?;
            let trim_point = kv::stream_trim_point::deser_value(kv.value)?;
            pending.push((stream_id, trim_point));
            if pending.len() >= PENDING_LIST_LIMIT {
                return Ok(Page::new(pending, true));
            }
        }
        Ok(Page::new(pending, false))
    }

    async fn process_trim(
        &self,
        stream_id: StreamId,
        trim_point: RangeTo<SeqNum>,
    ) -> Result<(), StorageError> {
        if trim_point.end > SeqNum::MIN {
            self.delete_records(stream_id, trim_point).await?;
        }
        self.finalize_trim(stream_id, trim_point).await?;
        Ok(())
    }

    #[instrument(ret, err, skip(self))]
    async fn delete_records(
        &self,
        stream_id: StreamId,
        trim_point: RangeTo<SeqNum>,
    ) -> Result<(), StorageError> {
        let start_key = kv::stream_record_timestamp::ser_key(
            stream_id,
            StreamPosition {
                seq_num: SeqNum::MIN,
                timestamp: Timestamp::MIN,
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
        let mut batch = WriteBatch::new();
        let mut batch_size = 0usize;
        while let Some(kv) = it.next().await? {
            if kv.key.first().copied() != Some(kv::KeyType::StreamRecordTimestamp.ordinal()) {
                break;
            }
            let (deser_stream_id, pos) = kv::stream_record_timestamp::deser_key(kv.key.clone())?;
            if deser_stream_id != stream_id {
                break;
            }
            if pos.seq_num >= trim_point.end {
                break;
            }
            batch.delete(kv.key);
            batch.delete(kv::stream_record_data::ser_key(stream_id, pos));
            batch_size += 1;
            if batch_size >= DELETE_BATCH_SIZE {
                static WRITE_OPTS: WriteOptions = WriteOptions {
                    await_durable: true,
                };
                self.db.write_with_options(batch, &WRITE_OPTS).await?;
                batch = WriteBatch::new();
                batch_size = 0;
            }
        }
        if batch_size > 0 {
            static WRITE_OPTS: WriteOptions = WriteOptions {
                await_durable: true,
            };
            self.db.write_with_options(batch, &WRITE_OPTS).await?;
        }
        Ok(())
    }

    #[instrument(ret, err, skip(self))]
    async fn finalize_trim(
        &self,
        stream_id: StreamId,
        trim_point: RangeTo<SeqNum>,
    ) -> Result<(), StorageError> {
        let trim_point_key = kv::stream_trim_point::ser_key(stream_id);
        if trim_point.end < SeqNum::MAX {
            let Some(current_trim_point) = self
                .db_get(trim_point_key.clone(), kv::stream_trim_point::deser_value)
                .await?
            else {
                return Ok(());
            };
            if current_trim_point != trim_point {
                return Ok(());
            }
        }
        let mut batch = WriteBatch::new();
        batch.delete(trim_point_key);
        if trim_point.end == SeqNum::MAX {
            let id_mapping_key = kv::stream_id_mapping::ser_key(stream_id);
            let (basin, stream) = self
                .db_get(&id_mapping_key, kv::stream_id_mapping::deser_value)
                .await?
                .expect("invariant violation: missing stream ID mapping");
            batch.delete(kv::stream_meta::ser_key(&basin, &stream));
            batch.delete(id_mapping_key);
            batch.delete(kv::stream_tail_position::ser_key(stream_id));
            batch.delete(kv::stream_fencing_token::ser_key(stream_id));
        }
        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        self.db.write_with_options(batch, &WRITE_OPTS).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bytes::Bytes;
    use s2_common::{
        record::{FencingToken, Metered, Record, SeqNum, StreamPosition},
        types::{basin::BasinName, config::OptionalStreamConfig, stream::StreamName},
    };
    use slatedb::{WriteBatch, config::WriteOptions};
    use time::OffsetDateTime;

    use super::super::tests::test_backend;
    use crate::backend::{kv, stream_id::StreamId};

    fn test_record() -> Metered<Record> {
        let record = Record::try_from_parts(vec![], Bytes::from_static(b"trim-test")).unwrap();
        record.into()
    }

    #[tokio::test]
    async fn stream_trim_deletes_records_and_clears_trim_point() {
        let backend = test_backend().await;
        let stream_id: StreamId = [1u8; StreamId::LEN].into();
        let metered = test_record();

        for seq in 0..5 {
            let pos = StreamPosition {
                seq_num: seq,
                timestamp: 1000 + seq,
            };
            backend
                .db
                .put(
                    kv::stream_record_data::ser_key(stream_id, pos),
                    kv::stream_record_data::ser_value(metered.as_ref()),
                )
                .await
                .unwrap();
            backend
                .db
                .put(
                    kv::stream_record_timestamp::ser_key(stream_id, pos),
                    kv::stream_record_timestamp::ser_value(),
                )
                .await
                .unwrap();
        }

        backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(..3),
            )
            .await
            .unwrap();

        backend.clone().tick_stream_trim().await.unwrap();

        for seq in 0..5 {
            let pos = StreamPosition {
                seq_num: seq,
                timestamp: 1000 + seq,
            };
            let data = backend
                .db
                .get(kv::stream_record_data::ser_key(stream_id, pos))
                .await
                .unwrap();
            let timestamp = backend
                .db
                .get(kv::stream_record_timestamp::ser_key(stream_id, pos))
                .await
                .unwrap();
            if seq < 3 {
                assert!(data.is_none());
                assert!(timestamp.is_none());
            } else {
                assert!(data.is_some());
                assert!(timestamp.is_some());
            }
        }

        let trim_point = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap();
        assert!(trim_point.is_none());
    }

    #[tokio::test]
    async fn stream_trim_finalizes_full_delete() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("test-basin").unwrap();
        let stream = StreamName::from_str("test-stream").unwrap();
        let stream_id = StreamId::new(&basin, &stream);
        let metered = test_record();

        let meta = kv::stream_meta::StreamMeta {
            config: OptionalStreamConfig::default(),
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
            creation_idempotency_key: None,
        };

        backend
            .db
            .put(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::ser_value(&meta),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::stream_id_mapping::ser_key(stream_id),
                kv::stream_id_mapping::ser_value(&basin, &stream),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::ser_value(StreamPosition {
                    seq_num: 10,
                    timestamp: 1234,
                }),
            )
            .await
            .unwrap();
        let token = FencingToken::from_str("token-1").unwrap();
        backend
            .db
            .put(
                kv::stream_fencing_token::ser_key(stream_id),
                kv::stream_fencing_token::ser_value(&token),
            )
            .await
            .unwrap();

        for seq in 0..3 {
            let pos = StreamPosition {
                seq_num: seq,
                timestamp: 2000 + seq,
            };
            backend
                .db
                .put(
                    kv::stream_record_data::ser_key(stream_id, pos),
                    kv::stream_record_data::ser_value(metered.as_ref()),
                )
                .await
                .unwrap();
            backend
                .db
                .put(
                    kv::stream_record_timestamp::ser_key(stream_id, pos),
                    kv::stream_record_timestamp::ser_value(),
                )
                .await
                .unwrap();
        }

        backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(..SeqNum::MAX),
            )
            .await
            .unwrap();

        backend.clone().tick_stream_trim().await.unwrap();

        let meta_bytes = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap();
        assert!(meta_bytes.is_none());
        let mapping_bytes = backend
            .db
            .get(kv::stream_id_mapping::ser_key(stream_id))
            .await
            .unwrap();
        assert!(mapping_bytes.is_none());
        let tail_bytes = backend
            .db
            .get(kv::stream_tail_position::ser_key(stream_id))
            .await
            .unwrap();
        assert!(tail_bytes.is_none());
        let fencing_bytes = backend
            .db
            .get(kv::stream_fencing_token::ser_key(stream_id))
            .await
            .unwrap();
        assert!(fencing_bytes.is_none());
        let trim_bytes = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap();
        assert!(trim_bytes.is_none());

        for seq in 0..3 {
            let pos = StreamPosition {
                seq_num: seq,
                timestamp: 2000 + seq,
            };
            let data = backend
                .db
                .get(kv::stream_record_data::ser_key(stream_id, pos))
                .await
                .unwrap();
            let timestamp = backend
                .db
                .get(kv::stream_record_timestamp::ser_key(stream_id, pos))
                .await
                .unwrap();
            assert!(data.is_none());
            assert!(timestamp.is_none());
        }
    }

    #[tokio::test]
    async fn stream_trim_skips_stale_trim_point() {
        let backend = test_backend().await;
        let stream_id: StreamId = [9u8; StreamId::LEN].into();

        backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(..10),
            )
            .await
            .unwrap();

        backend.finalize_trim(stream_id, ..5).await.unwrap();

        let current = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap()
            .expect("trim point should remain");
        let decoded = kv::stream_trim_point::deser_value(current).unwrap();
        assert_eq!(decoded, ..10);
    }

    #[tokio::test]
    async fn stream_trim_paginates_pending_list() {
        let backend = test_backend().await;
        let total = super::PENDING_LIST_LIMIT + 1;

        let mut batch = WriteBatch::new();
        for idx in 0..total {
            let mut stream_id_bytes = [0u8; StreamId::LEN];
            stream_id_bytes[0] = idx as u8;
            let stream_id: StreamId = stream_id_bytes.into();
            batch.put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(..SeqNum::MIN),
            );
        }
        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        backend
            .db
            .write_with_options(batch, &WRITE_OPTS)
            .await
            .unwrap();

        let has_more = backend.clone().tick_stream_trim().await.unwrap();
        assert!(has_more);

        let has_more = backend.clone().tick_stream_trim().await.unwrap();
        assert!(!has_more);

        for idx in 0..total {
            let mut stream_id_bytes = [0u8; StreamId::LEN];
            stream_id_bytes[0] = idx as u8;
            let stream_id: StreamId = stream_id_bytes.into();
            let remaining = backend
                .db
                .get(kv::stream_trim_point::ser_key(stream_id))
                .await
                .unwrap();
            assert!(remaining.is_none());
        }
    }

    #[tokio::test]
    async fn stream_trim_end_min_keeps_records() {
        let backend = test_backend().await;
        let stream_id: StreamId = [7u8; StreamId::LEN].into();
        let metered = test_record();
        let pos = StreamPosition {
            seq_num: SeqNum::MIN,
            timestamp: 5000,
        };

        backend
            .db
            .put(
                kv::stream_record_data::ser_key(stream_id, pos),
                kv::stream_record_data::ser_value(metered.as_ref()),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::stream_record_timestamp::ser_key(stream_id, pos),
                kv::stream_record_timestamp::ser_value(),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(..SeqNum::MIN),
            )
            .await
            .unwrap();

        backend.clone().tick_stream_trim().await.unwrap();

        let data = backend
            .db
            .get(kv::stream_record_data::ser_key(stream_id, pos))
            .await
            .unwrap();
        let timestamp = backend
            .db
            .get(kv::stream_record_timestamp::ser_key(stream_id, pos))
            .await
            .unwrap();
        assert!(data.is_some());
        assert!(timestamp.is_some());

        let trim_point = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap();
        assert!(trim_point.is_none());
    }

    #[tokio::test]
    async fn stream_trim_does_not_touch_other_streams() {
        let backend = test_backend().await;
        let stream_id_a: StreamId = [1u8; StreamId::LEN].into();
        let stream_id_b: StreamId = [2u8; StreamId::LEN].into();
        let metered = test_record();

        for seq in 0..4 {
            let pos_a = StreamPosition {
                seq_num: seq,
                timestamp: 1000 + seq,
            };
            backend
                .db
                .put(
                    kv::stream_record_data::ser_key(stream_id_a, pos_a),
                    kv::stream_record_data::ser_value(metered.as_ref()),
                )
                .await
                .unwrap();
            backend
                .db
                .put(
                    kv::stream_record_timestamp::ser_key(stream_id_a, pos_a),
                    kv::stream_record_timestamp::ser_value(),
                )
                .await
                .unwrap();

            let pos_b = StreamPosition {
                seq_num: seq,
                timestamp: 2000 + seq,
            };
            backend
                .db
                .put(
                    kv::stream_record_data::ser_key(stream_id_b, pos_b),
                    kv::stream_record_data::ser_value(metered.as_ref()),
                )
                .await
                .unwrap();
            backend
                .db
                .put(
                    kv::stream_record_timestamp::ser_key(stream_id_b, pos_b),
                    kv::stream_record_timestamp::ser_value(),
                )
                .await
                .unwrap();
        }

        backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id_a),
                kv::stream_trim_point::ser_value(..2),
            )
            .await
            .unwrap();

        backend.clone().tick_stream_trim().await.unwrap();

        for seq in 0..4 {
            let pos_a = StreamPosition {
                seq_num: seq,
                timestamp: 1000 + seq,
            };
            let data_a = backend
                .db
                .get(kv::stream_record_data::ser_key(stream_id_a, pos_a))
                .await
                .unwrap();
            let timestamp_a = backend
                .db
                .get(kv::stream_record_timestamp::ser_key(stream_id_a, pos_a))
                .await
                .unwrap();
            if seq < 2 {
                assert!(data_a.is_none());
                assert!(timestamp_a.is_none());
            } else {
                assert!(data_a.is_some());
                assert!(timestamp_a.is_some());
            }

            let pos_b = StreamPosition {
                seq_num: seq,
                timestamp: 2000 + seq,
            };
            let data_b = backend
                .db
                .get(kv::stream_record_data::ser_key(stream_id_b, pos_b))
                .await
                .unwrap();
            let timestamp_b = backend
                .db
                .get(kv::stream_record_timestamp::ser_key(stream_id_b, pos_b))
                .await
                .unwrap();
            assert!(data_b.is_some());
            assert!(timestamp_b.is_some());
        }
    }

    #[tokio::test]
    async fn stream_trim_large_batch_flushes() {
        let backend = test_backend().await;
        let stream_id: StreamId = [3u8; StreamId::LEN].into();
        let metered = test_record();
        let total: SeqNum = (super::DELETE_BATCH_SIZE as SeqNum) + 5;

        let mut batch = WriteBatch::new();
        for seq in 0..total {
            let pos = StreamPosition {
                seq_num: seq,
                timestamp: 4000 + seq,
            };
            batch.put(
                kv::stream_record_data::ser_key(stream_id, pos),
                kv::stream_record_data::ser_value(metered.as_ref()),
            );
            batch.put(
                kv::stream_record_timestamp::ser_key(stream_id, pos),
                kv::stream_record_timestamp::ser_value(),
            );
        }

        batch.put(
            kv::stream_trim_point::ser_key(stream_id),
            kv::stream_trim_point::ser_value(..total),
        );
        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        backend
            .db
            .write_with_options(batch, &WRITE_OPTS)
            .await
            .unwrap();

        backend.clone().tick_stream_trim().await.unwrap();

        let samples: [SeqNum; 3] = [0, 9_999, total - 1];
        for seq in samples {
            let pos = StreamPosition {
                seq_num: seq,
                timestamp: 4000 + seq,
            };
            let data = backend
                .db
                .get(kv::stream_record_data::ser_key(stream_id, pos))
                .await
                .unwrap();
            let timestamp = backend
                .db
                .get(kv::stream_record_timestamp::ser_key(stream_id, pos))
                .await
                .unwrap();
            assert!(data.is_none());
            assert!(timestamp.is_none());
        }

        let trim_point = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap();
        assert!(trim_point.is_none());
    }

    #[tokio::test]
    async fn finalize_trim_no_trim_point_noop() {
        let backend = test_backend().await;
        let stream_id: StreamId = [4u8; StreamId::LEN].into();

        backend.finalize_trim(stream_id, ..5).await.unwrap();

        let trim_point = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap();
        assert!(trim_point.is_none());
    }

    #[tokio::test]
    async fn finalize_trim_clears_matching_trim_point() {
        let backend = test_backend().await;
        let stream_id: StreamId = [5u8; StreamId::LEN].into();

        backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(..5),
            )
            .await
            .unwrap();

        backend.finalize_trim(stream_id, ..5).await.unwrap();

        let trim_point = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap();
        assert!(trim_point.is_none());
    }
}
