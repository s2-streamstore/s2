use std::ops::RangeTo;

use futures::{StreamExt, stream};
use s2_common::{record::NonZeroSeqNum, resources::Page};
use slatedb::{
    DbTransaction, IsolationLevel, WriteBatch,
    config::{DurabilityLevel, ScanOptions},
};
use tracing::instrument;

use crate::{
    backend::{
        Backend, doe,
        error::StorageError,
        kv::{self, timestamp::TimestampSecs},
        store::{db_txn_commit_durable, db_txn_get, db_txn_get_with},
    },
    stream_id::StreamId,
};

const PENDING_LIST_LIMIT: usize = 128;
const CONCURRENCY: usize = 4;
const DELETE_BATCH_SIZE: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct PendingTrim {
    stream_id: StreamId,
    trim_point: RangeTo<NonZeroSeqNum>,
    /// Commit sequence of the observed marker; bounds the records this job may delete.
    marker_seq: u64,
}

impl Backend {
    pub(super) async fn tick_stream_trim(self) -> Result<bool, StorageError> {
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
        self.delete_records(pending).await?;
        self.finalize_trim(pending).await
    }

    #[instrument(ret, err, skip(self))]
    async fn delete_records(&self, pending: PendingTrim) -> Result<(), StorageError> {
        let prefix = kv::stream_record_timestamp::ser_key_prefix(pending.stream_id);
        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = self
            .db
            .scan_prefix_with_options(prefix, .., &scan_opts)
            .await?;
        let mut batch = WriteBatch::new();
        let mut batch_size = 0;
        while let Some(kv) = it.next().await? {
            let (deser_stream_id, pos) = kv::stream_record_timestamp::deser_key(kv.key.clone())?;
            debug_assert_eq!(deser_stream_id, pending.stream_id);
            // Name reuse requires all old records to be durably deleted first.
            // A stale job may see records from the recreated stream; stop before
            // deleting records committed after the trim marker it observed.
            if pos.seq_num >= pending.trim_point.end.get() || kv.seq > pending.marker_seq {
                break;
            }
            batch.delete(kv.key);
            batch.delete(kv::stream_record_data::ser_key(pending.stream_id, pos));
            batch_size += 1;
            if batch_size >= DELETE_BATCH_SIZE {
                self.db.write(batch).await?.await_durable().await?;
                batch = WriteBatch::new();
                batch_size = 0;
            }
        }
        if !batch.is_empty() {
            self.db.write(batch).await?.await_durable().await?;
        }
        Ok(())
    }

    #[instrument(ret, err, skip(self))]
    async fn finalize_trim(&self, pending: PendingTrim) -> Result<(), StorageError> {
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
        let trim_point_key = kv::stream_trim_point::ser_key(pending.stream_id);
        let current_seq = db_txn_get_with(&txn, &trim_point_key, |entry| Ok(entry.seq)).await?;
        // A tick can exit on error while its submitted cleanup is still running.
        // The next durable scan can capture the old marker before cleanup becomes
        // durable. Cleanup removes the old marker and metadata before name reuse,
        // but this scanned work can remain queued across recreation. The recreated
        // stream's marker may have the same trim point, so compare commit sequences.
        if current_seq != Some(pending.marker_seq) {
            return Ok(());
        }
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
            doe::clear(&txn, pending.stream_id).await?;
        } else {
            // A partial trim may remove the infinite-retention record that
            // parked DOE while leaving finite-retention records behind.
            wake_doe_on_trim(&txn, pending.stream_id).await?;
        }
        db_txn_commit_durable(txn).await?;
        Ok(())
    }
}

async fn wake_doe_on_trim(txn: &DbTransaction, stream_id: StreamId) -> Result<(), StorageError> {
    let Some((basin, stream)) = db_txn_get(
        txn,
        kv::stream_id_mapping::ser_key(stream_id),
        kv::stream_id_mapping::deser_value,
    )
    .await?
    else {
        return Ok(());
    };
    let Some(meta) = db_txn_get(
        txn,
        &kv::stream_meta::ser_key(&basin, &stream),
        kv::stream_meta::deser_value,
    )
    .await?
    else {
        return Ok(());
    };
    if meta.deleted_at.is_some() {
        return Ok(());
    }
    if meta.config.delete_on_empty.min_age().is_none() {
        return Ok(());
    }
    doe::schedule(txn, stream_id, TimestampSecs::now()).await?;
    Ok(())
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

    use super::super::tests::test_backend;
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
    async fn stale_deletion_work_preserves_recreated_stream() {
        use s2_common::{
            config::OptionalStreamConfig,
            resources::ProvisionMode,
            stream::{AppendInput, AppendRecord, AppendRecordParts},
        };

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

        // Pause stream deletion after it submits terminal trim, before it marks metadata.
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
        // Provisioning and reconfiguration must reject updates that the pending trim would erase.
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

        let stale_trim = backend
            .list_stream_trim_pending()
            .await
            .unwrap()
            .values
            .pop()
            .unwrap();
        backend.clone().tick_stream_trim().await.unwrap();
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
            "the old deletion request must not mark the recreated stream as deleted"
        );

        let record: AppendRecord = AppendRecordParts {
            timestamp: None,
            record: Record::try_from_parts(vec![], Bytes::from_static(b"recreated stream"))
                .unwrap()
                .metered(),
        }
        .try_into()
        .unwrap();
        let ack = backend
            .open_for_append(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .append(AppendInput {
                records: vec![record].try_into().unwrap(),
                match_seq_num: None,
                fencing_token: None,
            })
            .await
            .unwrap();
        // A previous tick can have scanned the old marker before cleanup became durable.
        backend.process_trim(stale_trim).await.unwrap();
        assert!(
            backend
                .db_get(
                    kv::stream_record_data::ser_key(stream_id, ack.start),
                    kv::stream_record_data::deser_value,
                )
                .await
                .unwrap()
                .is_some(),
            "old trim work must not delete records from the recreated stream"
        );

        // Even another terminal marker belongs to different work after recreation.
        backend.delete_stream(basin, stream).await.unwrap();
        backend.process_trim(stale_trim).await.unwrap();
        assert_eq!(
            backend
                .db_get(
                    kv::stream_trim_point::ser_key(stream_id),
                    kv::stream_trim_point::deser_value,
                )
                .await
                .unwrap(),
            Some(..NonZeroSeqNum::MAX),
            "old trim work must not finalize the recreated stream's deletion"
        );
        backend.close().await.unwrap();
    }
}
