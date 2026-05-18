use std::ops::RangeTo;

use futures::{StreamExt, stream};
use s2_common::{
    record::{NonZeroSeqNum, StreamPosition},
    types::resources::Page,
};
use slatedb::{
    WriteBatch,
    config::{DurabilityLevel, ScanOptions, WriteOptions},
};
use tracing::instrument;

use crate::{
    backend::{Backend, error::StorageError, kv, store::db_txn_get},
    stream_id::StreamId,
};

const PENDING_LIST_LIMIT: usize = 128;
const CONCURRENCY: usize = 4;
const DELETE_BATCH_SIZE: usize = 10_000;

impl Backend {
    pub(super) async fn tick_stream_trim(self) -> Result<bool, StorageError> {
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
    ) -> Result<Page<(StreamId, RangeTo<NonZeroSeqNum>)>, StorageError> {
        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = self
            .db
            .scan_with_options(kv::key_type_range(kv::KeyType::StreamTrimPoint), &scan_opts)
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
        trim_point: RangeTo<NonZeroSeqNum>,
    ) -> Result<(), StorageError> {
        let stream_became_empty = self.delete_records(stream_id, trim_point).await?;
        if trim_point.end < NonZeroSeqNum::MAX && stream_became_empty {
            self.arm_doe_maybe(stream_id).await?;
        }
        self.finalize_trim(stream_id, trim_point).await?;
        Ok(())
    }

    #[instrument(ret, err, skip(self))]
    async fn delete_records(
        &self,
        stream_id: StreamId,
        trim_point: RangeTo<NonZeroSeqNum>,
    ) -> Result<bool, StorageError> {
        let prefix = kv::stream_record_timestamp::ser_key_prefix(stream_id);
        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = self.db.scan_prefix_with_options(prefix, &scan_opts).await?;
        let mut batch = WriteBatch::new();
        let mut batch_size = 0usize;
        let mut found_record_to_keep = false;
        let mut tail_after_last_deleted_record: Option<StreamPosition> = None;
        while let Some(kv) = it.next().await? {
            let (deser_stream_id, pos) = kv::stream_record_timestamp::deser_key(kv.key.clone())?;
            debug_assert_eq!(deser_stream_id, stream_id);
            if pos.seq_num >= trim_point.end.get() {
                found_record_to_keep = true;
                break;
            }
            // Flush before adding the next deletion so the current batch can
            // become the final batch with the empty-tail marker below.
            if batch_size >= DELETE_BATCH_SIZE {
                self.db.write(batch).await?;
                batch = WriteBatch::new();
                batch_size = 0;
            }
            batch.delete(kv.key);
            batch.delete(kv::stream_record_data::ser_key(stream_id, pos));
            batch_size += 1;
            let tail_pos = StreamPosition {
                seq_num: pos.seq_num + 1,
                timestamp: pos.timestamp,
            };
            if let Some(previous_tail) = tail_after_last_deleted_record.replace(tail_pos) {
                debug_assert_eq!(previous_tail.seq_num, pos.seq_num);
            }
        }
        let Some(tail_pos) = tail_after_last_deleted_record else {
            return Ok(false);
        };
        let stream_became_empty = !found_record_to_keep;
        if stream_became_empty {
            batch.put(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::ser_value(tail_pos, kv::timestamp::TimestampSecs::now()),
            );
            let write_opts = WriteOptions {
                await_durable: true,
                ..Default::default()
            };
            self.db.write_with_options(batch, &write_opts).await?;
        } else if batch_size > 0 {
            self.db.write(batch).await?;
        }
        Ok(stream_became_empty)
    }

    #[instrument(ret, err, skip(self))]
    async fn finalize_trim(
        &self,
        stream_id: StreamId,
        trim_point: RangeTo<NonZeroSeqNum>,
    ) -> Result<(), StorageError> {
        let trim_point_key = kv::stream_trim_point::ser_key(stream_id);
        let txn = self
            .db
            .begin(slatedb::IsolationLevel::SerializableSnapshot)
            .await?;
        let is_full_delete = trim_point == ..NonZeroSeqNum::MAX;
        let Some(current_trim_point) = db_txn_get(
            &txn,
            trim_point_key.clone(),
            kv::stream_trim_point::deser_value,
        )
        .await?
        else {
            return Ok(());
        };
        if current_trim_point != trim_point {
            return Ok(());
        }
        txn.delete(trim_point_key)?;
        if is_full_delete {
            let id_mapping_key = kv::stream_id_mapping::ser_key(stream_id);
            if let Some((basin, stream)) =
                db_txn_get(&txn, &id_mapping_key, kv::stream_id_mapping::deser_value).await?
            {
                txn.delete(kv::stream_meta::ser_key(&basin, &stream))?;
                txn.delete(id_mapping_key)?;
            }
            txn.delete(kv::stream_tail_position::ser_key(stream_id))?;
            txn.delete(kv::stream_fencing_token::ser_key(stream_id))?;
        }
        txn.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{ops::RangeTo, str::FromStr};

    use bytes::Bytes;
    use s2_common::{
        record::{
            FencingToken, Metered, NonZeroSeqNum, Record, SeqNum, StoredRecord, StreamPosition,
        },
        types::{basin::BasinName, config::OptionalStreamConfig, stream::StreamName},
    };
    use slatedb::WriteBatch;
    use time::OffsetDateTime;

    use super::super::tests::test_backend;
    use crate::{backend::kv, stream_id::StreamId};

    fn test_record() -> Metered<StoredRecord> {
        let record = Record::try_from_parts(vec![], Bytes::from_static(b"trim-test")).unwrap();
        StoredRecord::from(record).into()
    }

    fn trim_point(seq_num: SeqNum) -> RangeTo<NonZeroSeqNum> {
        ..NonZeroSeqNum::new(seq_num).expect("trim point must be non-zero")
    }

    #[tokio::test]
    async fn delete_records_writes_tail_marker_before_reporting_stream_became_empty() {
        let backend = test_backend().await;
        let stream_id: StreamId = [6u8; StreamId::LEN].into();
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

        let stream_became_empty = backend
            .delete_records(stream_id, trim_point(1))
            .await
            .unwrap();
        assert!(stream_became_empty);

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

        let tail_bytes = backend
            .db
            .get(kv::stream_tail_position::ser_key(stream_id))
            .await
            .unwrap()
            .expect("empty stream tail marker should be written");
        let (marker_pos, _) = kv::stream_tail_position::deser_value(tail_bytes).unwrap();
        assert_eq!(
            marker_pos,
            StreamPosition {
                seq_num: 1,
                timestamp: 5000,
            }
        );
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
                kv::stream_trim_point::ser_value(trim_point(3)),
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
        let tail_bytes = backend
            .db
            .get(kv::stream_tail_position::ser_key(stream_id))
            .await
            .unwrap();
        assert!(tail_bytes.is_none());
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
            cipher: None,
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
                kv::stream_tail_position::ser_value(
                    StreamPosition {
                        seq_num: 10,
                        timestamp: 1234,
                    },
                    kv::timestamp::TimestampSecs::from_secs(10),
                ),
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
                kv::stream_trim_point::ser_value(trim_point(SeqNum::MAX)),
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
                kv::stream_trim_point::ser_value(trim_point(10)),
            )
            .await
            .unwrap();

        backend
            .finalize_trim(stream_id, trim_point(5))
            .await
            .unwrap();

        let current = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap()
            .expect("trim point should remain");
        let decoded = kv::stream_trim_point::deser_value(current).unwrap();
        assert_eq!(decoded, trim_point(10));
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
                kv::stream_trim_point::ser_value(trim_point(1)),
            );
        }
        backend.db.write(batch).await.unwrap();

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
    async fn stream_trim_end_one_deletes_first_record() {
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
                kv::stream_trim_point::ser_value(trim_point(1)),
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
        assert!(data.is_none());
        assert!(timestamp.is_none());

        let trim_point = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap();
        assert!(trim_point.is_none());
        let tail_bytes = backend
            .db
            .get(kv::stream_tail_position::ser_key(stream_id))
            .await
            .unwrap()
            .expect("empty stream tail marker should be written");
        let (tail_pos, _) = kv::stream_tail_position::deser_value(tail_bytes).unwrap();
        assert_eq!(
            tail_pos,
            StreamPosition {
                seq_num: 1,
                timestamp: 5000,
            }
        );
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
                kv::stream_trim_point::ser_value(trim_point(2)),
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
            kv::stream_trim_point::ser_value(trim_point(total)),
        );
        backend.db.write(batch).await.unwrap();

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
        let tail_bytes = backend
            .db
            .get(kv::stream_tail_position::ser_key(stream_id))
            .await
            .unwrap()
            .expect("empty stream tail marker should be written");
        let (tail_pos, _) = kv::stream_tail_position::deser_value(tail_bytes).unwrap();
        assert_eq!(
            tail_pos,
            StreamPosition {
                seq_num: total,
                timestamp: 4000 + total - 1,
            }
        );
    }

    #[tokio::test]
    async fn finalize_trim_no_trim_point_noop() {
        let backend = test_backend().await;
        let stream_id: StreamId = [4u8; StreamId::LEN].into();

        backend
            .finalize_trim(stream_id, trim_point(5))
            .await
            .unwrap();

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
                kv::stream_trim_point::ser_value(trim_point(5)),
            )
            .await
            .unwrap();

        backend
            .finalize_trim(stream_id, trim_point(5))
            .await
            .unwrap();

        let trim_point = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap();
        assert!(trim_point.is_none());
    }
}
