use std::ops::RangeTo;

use futures::{StreamExt, stream};
use s2_common::{
    record::{NonZeroSeqNum, StreamPosition},
    resources::Page,
};
use slatedb::{
    DbTransaction, IsolationLevel,
    config::{DurabilityLevel, ScanOptions},
};
use tracing::instrument;

use crate::{
    backend::{
        Backend,
        error::StorageError,
        kv,
        store::{db_txn_commit_durable, db_txn_get, db_txn_get_with},
    },
    stream_id::StreamId,
};

const PENDING_LIST_LIMIT: usize = 128;
const CONCURRENCY: usize = 4;
const DELETE_BATCH_SIZE: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingTrim {
    stream_id: StreamId,
    trim_point: RangeTo<NonZeroSeqNum>,
    /// Database commit sequence of the observed trim marker.
    marker_seq: u64,
}

impl Backend {
    pub(in crate::backend) async fn tick_stream_trim(self) -> Result<bool, StorageError> {
        let page = self.list_stream_trim_pending().await?;
        if page.values.is_empty() {
            return Ok(page.has_more);
        }
        let mut processed = stream::iter(page.values)
            .map(|pending| {
                let backend = self.clone();
                async move { backend.process_trim(pending).await }
            })
            .buffer_unordered(CONCURRENCY);
        while let Some(result) = processed.next().await {
            result?;
        }
        Ok(page.has_more)
    }

    async fn list_stream_trim_pending(&self) -> Result<Page<PendingTrim>, StorageError> {
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
            pending.push(PendingTrim {
                stream_id,
                trim_point,
                marker_seq: kv.seq,
            });
            if pending.len() >= PENDING_LIST_LIMIT {
                return Ok(Page::new(pending, true));
            }
        }
        Ok(Page::new(pending, false))
    }

    async fn process_trim(&self, pending: PendingTrim) -> Result<(), StorageError> {
        let Some(has_remaining_records) = self.delete_records(pending).await? else {
            return Ok(());
        };
        self.finalize_trim(pending, has_remaining_records).await
    }

    /// Return a transaction only while the queued trim marker is still current.
    async fn begin_trim_txn_if_current(
        &self,
        pending: PendingTrim,
    ) -> Result<Option<DbTransaction>, StorageError> {
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
        let current = db_txn_get_with(
            &txn,
            kv::stream_trim_point::ser_key(pending.stream_id),
            |entry| {
                Ok(PendingTrim {
                    stream_id: pending.stream_id,
                    trim_point: kv::stream_trim_point::deser_value(entry.value)?,
                    marker_seq: entry.seq,
                })
            },
        )
        .await?;
        // The value alone can repeat after deletion and recreation. Validate the
        // queued marker's sequence in every transaction that deletes stream keys.
        Ok((current == Some(pending)).then_some(txn))
    }

    /// Return whether records remain, or `None` if the trim marker changed.
    #[instrument(ret, err, skip(self))]
    async fn delete_records(&self, pending: PendingTrim) -> Result<Option<bool>, StorageError> {
        let prefix = kv::stream_record_timestamp::ser_key_prefix(pending.stream_id);
        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = self
            .db
            .scan_prefix_with_options(prefix, .., &scan_opts)
            .await?;
        let mut batch = Vec::new();
        let mut has_remaining_records = false;
        while let Some(kv) = it.next().await? {
            let (deser_stream_id, pos) = kv::stream_record_timestamp::deser_key(kv.key)?;
            debug_assert_eq!(deser_stream_id, pending.stream_id);
            if pos.seq_num >= pending.trim_point.end.get() {
                has_remaining_records = true;
                break;
            }
            batch.push(pos);
            if batch.len() >= DELETE_BATCH_SIZE {
                if !self.delete_record_batch(pending, &batch).await? {
                    return Ok(None);
                }
                batch.clear();
            }
        }
        if !batch.is_empty() && !self.delete_record_batch(pending, &batch).await? {
            return Ok(None);
        }
        Ok(Some(has_remaining_records))
    }

    async fn delete_record_batch(
        &self,
        pending: PendingTrim,
        positions: &[StreamPosition],
    ) -> Result<bool, StorageError> {
        let Some(txn) = self.begin_trim_txn_if_current(pending).await? else {
            return Ok(false);
        };
        for pos in positions {
            txn.delete(kv::stream_record_timestamp::ser_key(
                pending.stream_id,
                *pos,
            ))?;
            txn.delete(kv::stream_record_data::ser_key(pending.stream_id, *pos))?;
        }
        db_txn_commit_durable(txn).await?;
        Ok(true)
    }

    #[instrument(ret, err, skip(self))]
    async fn finalize_trim(
        &self,
        pending: PendingTrim,
        has_remaining_records: bool,
    ) -> Result<(), StorageError> {
        let Some(txn) = self.begin_trim_txn_if_current(pending).await? else {
            return Ok(());
        };
        let trim_point_key = kv::stream_trim_point::ser_key(pending.stream_id);
        let is_terminal_trim = pending.trim_point == ..NonZeroSeqNum::MAX;
        txn.delete(trim_point_key)?;
        if is_terminal_trim {
            let id_mapping_key = kv::stream_id_mapping::ser_key(pending.stream_id);
            if let Some((basin, stream)) =
                db_txn_get(&txn, &id_mapping_key, kv::stream_id_mapping::deser_value).await?
            {
                txn.delete(kv::stream_meta::ser_key(&basin, &stream))?;
                txn.delete(id_mapping_key)?;
            }
            txn.delete(kv::stream_tail_position::ser_key(pending.stream_id))?;
            txn.delete(kv::stream_fencing_token::ser_key(pending.stream_id))?;
        } else if !has_remaining_records {
            self.arm_doe_on_full_trim(&txn, pending.stream_id).await?;
        }
        db_txn_commit_durable(txn).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{ops::RangeTo, str::FromStr};

    use bytes::Bytes;
    use s2_common::{
        basin::BasinName,
        config::StreamConfig,
        record::{
            FencingToken, Metered, MeteredExt as _, NonZeroSeqNum, Record, SeqNum, StreamPosition,
        },
        stream::StreamName,
    };
    use s2_storage::record::StoredRecord;
    use slatedb::WriteBatch;
    use time::OffsetDateTime;

    use super::{super::tests::test_backend, PendingTrim};
    use crate::{
        backend::{kv, test_util::DbWriteTestExt as _},
        stream_id::StreamId,
    };

    fn test_record() -> Metered<StoredRecord> {
        let record = Record::try_from_parts(vec![], Bytes::from_static(b"trim-test")).unwrap();
        StoredRecord::from(record).metered()
    }

    fn trim_point(seq_num: SeqNum) -> RangeTo<NonZeroSeqNum> {
        ..NonZeroSeqNum::new(seq_num).expect("trim point must be non-zero")
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
                .assert_durable()
                .await;
            backend
                .db
                .put(
                    kv::stream_record_timestamp::ser_key(stream_id, pos),
                    kv::stream_record_timestamp::ser_value(),
                )
                .assert_durable()
                .await;
        }

        backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(trim_point(3)),
            )
            .assert_durable()
            .await;

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
            config: StreamConfig::default(),
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
            .assert_durable()
            .await;
        backend
            .db
            .put(
                kv::stream_id_mapping::ser_key(stream_id),
                kv::stream_id_mapping::ser_value(&basin, &stream),
            )
            .assert_durable()
            .await;
        backend
            .db
            .put(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::ser_value(StreamPosition {
                    seq_num: 10,
                    timestamp: 1234,
                }),
            )
            .assert_durable()
            .await;
        let token = FencingToken::from_str("token-1").unwrap();
        backend
            .db
            .put(
                kv::stream_fencing_token::ser_key(stream_id),
                kv::stream_fencing_token::ser_value(&token),
            )
            .assert_durable()
            .await;

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
                .assert_durable()
                .await;
            backend
                .db
                .put(
                    kv::stream_record_timestamp::ser_key(stream_id, pos),
                    kv::stream_record_timestamp::ser_value(),
                )
                .assert_durable()
                .await;
        }

        backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(trim_point(SeqNum::MAX)),
            )
            .assert_durable()
            .await;

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

    #[rstest::rstest]
    #[case::same_trim_point(5)]
    #[case::advanced_trim_point(10)]
    #[tokio::test]
    async fn stream_trim_skips_replaced_marker(#[case] new_trim: u64) {
        let backend = test_backend().await;
        let stream_id: StreamId = [9u8; StreamId::LEN].into();
        let key = kv::stream_trim_point::ser_key(stream_id);
        let marker_seq = backend
            .db
            .put(&key, kv::stream_trim_point::ser_value(trim_point(5)))
            .assert_durable()
            .await;
        backend
            .db
            .put(&key, kv::stream_trim_point::ser_value(trim_point(new_trim)))
            .assert_durable()
            .await;
        let pos = StreamPosition {
            seq_num: 0,
            timestamp: 1234,
        };
        let mut batch = WriteBatch::new();
        batch.put(
            kv::stream_record_data::ser_key(stream_id, pos),
            kv::stream_record_data::ser_value(test_record().as_ref()),
        );
        batch.put(
            kv::stream_record_timestamp::ser_key(stream_id, pos),
            kv::stream_record_timestamp::ser_value(),
        );
        backend.db.write(batch).assert_durable().await;

        let pending = PendingTrim {
            stream_id,
            trim_point: trim_point(5),
            marker_seq,
        };
        backend.process_trim(pending).await.unwrap();
        assert!(
            backend
                .db
                .get(kv::stream_record_data::ser_key(stream_id, pos))
                .await
                .unwrap()
                .is_some()
        );
        // Also cover a stale worker whose record scan finished before recreation.
        backend.finalize_trim(pending, false).await.unwrap();
        assert_eq!(
            backend
                .db_get(&key, kv::stream_trim_point::deser_value)
                .await
                .unwrap(),
            Some(trim_point(new_trim))
        );
        backend.close().await.unwrap();
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
        backend.db.write(batch).assert_durable().await;

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
            .assert_durable()
            .await;
        backend
            .db
            .put(
                kv::stream_record_timestamp::ser_key(stream_id, pos),
                kv::stream_record_timestamp::ser_value(),
            )
            .assert_durable()
            .await;
        backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(trim_point(1)),
            )
            .assert_durable()
            .await;

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
                .assert_durable()
                .await;
            backend
                .db
                .put(
                    kv::stream_record_timestamp::ser_key(stream_id_a, pos_a),
                    kv::stream_record_timestamp::ser_value(),
                )
                .assert_durable()
                .await;

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
                .assert_durable()
                .await;
            backend
                .db
                .put(
                    kv::stream_record_timestamp::ser_key(stream_id_b, pos_b),
                    kv::stream_record_timestamp::ser_value(),
                )
                .assert_durable()
                .await;
        }

        backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id_a),
                kv::stream_trim_point::ser_value(trim_point(2)),
            )
            .assert_durable()
            .await;

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
        backend.db.write(batch).assert_durable().await;

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
        let pending = PendingTrim {
            stream_id,
            trim_point: trim_point(5),
            marker_seq: 0,
        };

        backend.finalize_trim(pending, false).await.unwrap();

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

        let marker_seq = backend
            .db
            .put(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::ser_value(trim_point(5)),
            )
            .assert_durable()
            .await;

        let pending = PendingTrim {
            stream_id,
            trim_point: trim_point(5),
            marker_seq,
        };
        backend.finalize_trim(pending, false).await.unwrap();

        let trim_point = backend
            .db
            .get(kv::stream_trim_point::ser_key(stream_id))
            .await
            .unwrap();
        assert!(trim_point.is_none());
    }

    #[tokio::test]
    async fn delayed_delete_and_trim_preserve_recreated_stream() {
        use s2_common::{config::OptionalStreamConfig, resources::ProvisionMode};

        use crate::backend::error::{ProvisionStreamError, ReconfigureStreamError};
        let backend = test_backend().await;
        let (basin, stream) =
            crate::backend::test_util::create_stream(&backend, OptionalStreamConfig::default())
                .await;
        let stream_id = StreamId::new(&basin, &stream);
        backend
            .open_for_check_tail(&basin, &stream)
            .await
            .unwrap()
            .check_tail()
            .await
            .unwrap();

        // Pause the DELETE after it submits terminal trim, before it marks metadata.
        let mut deletion = Box::pin(backend.delete_stream(basin.clone(), stream.clone()));
        assert!(futures::poll!(&mut deletion).is_pending());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if backend
                    .db_get(
                        kv::stream_trim_point::ser_key(stream_id),
                        kv::stream_trim_point::deser_value,
                    )
                    .await
                    .unwrap()
                    == Some(..NonZeroSeqNum::MAX)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // A crash here leaves a durable terminal trim with unmarked metadata.
        // Both Ensure and PATCH must reject updates that the pending trim would erase.
        assert!(matches!(
            backend
                .provision_stream(
                    basin.clone(),
                    stream.clone(),
                    OptionalStreamConfig::default(),
                    ProvisionMode::Ensure
                )
                .await,
            Err(ProvisionStreamError::StreamDeletionPending(_))
        ));
        assert!(matches!(
            backend
                .reconfigure_stream(basin.clone(), stream.clone(), Default::default())
                .await,
            Err(ReconfigureStreamError::StreamDeletionPending(_))
        ));

        let pending = backend
            .list_stream_trim_pending()
            .await
            .unwrap()
            .values
            .pop()
            .unwrap();
        backend.process_trim(pending).await.unwrap();
        backend
            .provision_stream(
                basin.clone(),
                stream.clone(),
                OptionalStreamConfig::default(),
                ProvisionMode::CreateOnly {
                    request_token: None,
                },
            )
            .await
            .unwrap();

        deletion.await.unwrap();
        let meta = backend
            .db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(
            meta.deleted_at.is_none(),
            "the old DELETE must not mark the replacement"
        );

        // A worker may also have fetched old trim work before recreation.
        let pos = StreamPosition {
            seq_num: 0,
            timestamp: 1234,
        };
        let mut batch = WriteBatch::new();
        batch.put(
            kv::stream_record_data::ser_key(stream_id, pos),
            kv::stream_record_data::ser_value(test_record().as_ref()),
        );
        batch.put(
            kv::stream_record_timestamp::ser_key(stream_id, pos),
            kv::stream_record_timestamp::ser_value(),
        );
        backend.db.write(batch).assert_durable().await;
        backend.process_trim(pending).await.unwrap();
        assert!(
            backend
                .db
                .get(kv::stream_record_data::ser_key(stream_id, pos))
                .await
                .unwrap()
                .is_some(),
            "stale trim work must not delete replacement records"
        );
        backend.close().await.unwrap();
    }
}
