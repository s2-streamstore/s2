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

use crate::backend::{Backend, error::StorageError, kv, stream_id::StreamId};

const PENDING_LIST_LIMIT: usize = 128;
const CONCURRENCY: usize = 4;

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
            if batch_size >= 10_000 {
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
}
