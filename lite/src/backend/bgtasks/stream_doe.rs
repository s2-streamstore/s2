use std::time::Duration;

use enum_ordinalize::Ordinalize;
use futures::{StreamExt, stream};
use indexmap::IndexMap;
use itertools::Itertools;
use s2_common::{
    record::{SeqNum, StreamPosition, Timestamp},
    types::resources::Page,
};
use slatedb::{
    WriteBatch,
    config::{DurabilityLevel, PutOptions, ScanOptions, WriteOptions},
};
use tracing::instrument;

use crate::backend::{
    Backend,
    error::{DeleteStreamError, StorageError, StreamDeleteOnEmptyError},
    kv::{self, timestamp::TimestampSecs},
    stream_id::StreamId,
    streamer::{doe_arm_delay, retention_age_or_zero},
};

const PENDING_LIST_LIMIT: usize = 10_000;
const CONCURRENCY: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingDoeEntry {
    deadline: TimestampSecs,
    min_age: Duration,
}

impl Backend {
    pub(super) async fn tick_stream_doe(self) -> Result<bool, StreamDeleteOnEmptyError> {
        let now = TimestampSecs::now();
        let page = self.list_pending_stream_doe(now).await?;
        if page.values.is_empty() {
            return Ok(page.has_more);
        }
        let mut processed = stream::iter(page.values)
            .map(|(stream_id, pending)| {
                let backend = self.clone();
                async move { backend.process_stream_doe(stream_id, pending).await }
            })
            .buffer_unordered(CONCURRENCY);
        while let Some(result) = processed.next().await {
            result?;
        }
        Ok(page.has_more)
    }

    async fn list_pending_stream_doe(
        &self,
        now: TimestampSecs,
    ) -> Result<Page<(StreamId, Vec<PendingDoeEntry>)>, StorageError> {
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self
            .db
            .scan_with_options(kv::stream_doe_deadline::expired_key_range(now), &SCAN_OPTS)
            .await?;
        let mut pending: IndexMap<StreamId, Vec<PendingDoeEntry>> = IndexMap::new();
        let mut has_more = false;
        let mut count = 0;
        while let Some(kv) = it.next().await? {
            let (deadline, stream_id) = kv::stream_doe_deadline::deser_key(kv.key)?;
            let min_age = kv::stream_doe_deadline::deser_value(kv.value)?;
            assert!(deadline <= now);
            pending
                .entry(stream_id)
                .or_default()
                .push(PendingDoeEntry { deadline, min_age });
            count += 1;
            if count == PENDING_LIST_LIMIT {
                has_more = true;
                break;
            }
        }
        Ok(Page::new(pending.into_iter().collect_vec(), has_more))
    }

    async fn process_stream_doe(
        &self,
        stream_id: StreamId,
        pending: Vec<PendingDoeEntry>,
    ) -> Result<(), StreamDeleteOnEmptyError> {
        let should_delete = if self.stream_has_records(stream_id).await? {
            false
        } else {
            self.stream_doe_is_eligible(stream_id, &pending).await?
        };
        if should_delete && let Some((basin, stream)) = self.stream_id_mapping(stream_id).await? {
            match self.delete_stream(basin, stream).await {
                Ok(()) | Err(DeleteStreamError::StreamNotFound(_)) => {}
                Err(err) => return Err(err.into()),
            }
        }
        self.clear_doe_deadlines(stream_id, &pending).await?;
        Ok(())
    }

    async fn stream_doe_is_eligible(
        &self,
        stream_id: StreamId,
        pending: &[PendingDoeEntry],
    ) -> Result<bool, StorageError> {
        let Some((_, write_timestamp)) = self
            .db_get(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::deser_value,
            )
            .await?
        else {
            return Ok(false);
        };
        let write_timestamp = u64::from(write_timestamp.as_u32());
        Ok(pending.iter().any(|entry| {
            let deadline_secs = u64::from(entry.deadline.as_u32());
            write_timestamp
                .checked_add(entry.min_age.as_secs())
                .is_some_and(|sum| sum <= deadline_secs)
        }))
    }

    #[instrument(ret, err, skip(self, pending), fields(num_deadlines = pending.len()))]
    async fn clear_doe_deadlines(
        &self,
        stream_id: StreamId,
        pending: &[PendingDoeEntry],
    ) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();
        for entry in pending {
            batch.delete(kv::stream_doe_deadline::ser_key(entry.deadline, stream_id));
        }
        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        self.db.write_with_options(batch, &WRITE_OPTS).await?;
        Ok(())
    }

    #[instrument(ret, err, skip(self))]
    async fn stream_has_records(&self, stream_id: StreamId) -> Result<bool, StorageError> {
        let start_key = kv::stream_record_timestamp::ser_key(
            stream_id,
            StreamPosition {
                seq_num: SeqNum::MIN,
                timestamp: Timestamp::MIN,
            },
        );
        // Use Memory durability so TTL filtering advances with wall time even when the DB is idle.
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Memory,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self.db.scan_with_options(start_key.., &SCAN_OPTS).await?;
        let Some(kv) = it.next().await? else {
            return Ok(false);
        };
        if kv.key.first().copied() != Some(kv::KeyType::StreamRecordTimestamp.ordinal()) {
            return Ok(false);
        }
        let (candidate_stream_id, _pos) = kv::stream_record_timestamp::deser_key(kv.key)?;
        Ok(candidate_stream_id == stream_id)
    }

    pub(super) async fn arm_doe_maybe(&self, stream_id: StreamId) -> Result<(), StorageError> {
        let Some((basin, stream)) = self.stream_id_mapping(stream_id).await? else {
            return Ok(());
        };
        let Some(meta) = self
            .db_get(
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
        let Some(min_age) = meta.config.delete_on_empty.min_age.filter(|d| !d.is_zero()) else {
            return Ok(());
        };
        let deadline =
            TimestampSecs::after(doe_arm_delay(retention_age_or_zero(&meta.config), min_age));
        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        self.db
            .put_with_options(
                kv::stream_doe_deadline::ser_key(deadline, stream_id),
                kv::stream_doe_deadline::ser_value(min_age),
                &PutOptions::default(),
                &WRITE_OPTS,
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use s2_common::{
        maybe::Maybe,
        record::StreamPosition,
        types::{
            basin::BasinName,
            config::{
                DeleteOnEmptyReconfiguration, OptionalStreamConfig, RetentionPolicy,
                StreamReconfiguration,
            },
            stream::StreamName,
        },
    };
    use slatedb::config::{DurabilityLevel, ScanOptions};
    use time::OffsetDateTime;

    use super::{super::tests::test_backend, TimestampSecs};
    use crate::backend::{Backend, kv, stream_id::StreamId};

    const MIN_AGE: Duration = Duration::from_secs(60);

    fn stream_meta() -> kv::stream_meta::StreamMeta {
        stream_meta_with_config(OptionalStreamConfig::default(), OffsetDateTime::now_utc())
    }

    fn stream_meta_with_config(
        config: OptionalStreamConfig,
        created_at: OffsetDateTime,
    ) -> kv::stream_meta::StreamMeta {
        kv::stream_meta::StreamMeta {
            config,
            created_at,
            deleted_at: None,
            creation_idempotency_key: None,
        }
    }

    async fn seed_stream(backend: &Backend, basin: &BasinName, stream: &StreamName) -> StreamId {
        seed_stream_with_meta(backend, basin, stream, stream_meta()).await
    }

    async fn seed_stream_with_meta(
        backend: &Backend,
        basin: &BasinName,
        stream: &StreamName,
        meta: kv::stream_meta::StreamMeta,
    ) -> StreamId {
        let stream_id = StreamId::new(basin, stream);
        backend
            .db
            .put(
                kv::stream_meta::ser_key(basin, stream),
                kv::stream_meta::ser_value(&meta),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::stream_id_mapping::ser_key(stream_id),
                kv::stream_id_mapping::ser_value(basin, stream),
            )
            .await
            .unwrap();
        stream_id
    }

    async fn list_doe_entries(backend: &Backend) -> Vec<(TimestampSecs, StreamId, Duration)> {
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = backend
            .db
            .scan_with_options(
                kv::key_type_range(kv::KeyType::StreamDeleteOnEmptyDeadline),
                &SCAN_OPTS,
            )
            .await
            .unwrap();
        let mut entries = Vec::new();
        while let Some(kv) = it.next().await.unwrap() {
            let (deadline, stream_id) = kv::stream_doe_deadline::deser_key(kv.key).unwrap();
            let min_age = kv::stream_doe_deadline::deser_value(kv.value).unwrap();
            entries.push((deadline, stream_id, min_age));
        }
        entries
    }

    #[tokio::test]
    async fn stream_doe_marks_deleted_and_clears_deadline() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin").unwrap();
        let stream = StreamName::from_str("doe-stream").unwrap();
        let stream_id = seed_stream(&backend, &basin, &stream).await;
        let deadline = TimestampSecs::from_secs(10_000);
        let write_timestamp = TimestampSecs::from_secs(9_000);

        backend
            .db
            .put(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::ser_value(
                    StreamPosition {
                        seq_num: 1,
                        timestamp: 1234,
                    },
                    write_timestamp,
                ),
            )
            .await
            .unwrap();

        backend
            .db
            .put(
                kv::stream_doe_deadline::ser_key(deadline, stream_id),
                kv::stream_doe_deadline::ser_value(MIN_AGE),
            )
            .await
            .unwrap();

        let has_more = backend.clone().tick_stream_doe().await.unwrap();
        assert!(!has_more);

        let meta = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream meta should remain");
        let decoded = kv::stream_meta::deser_value(meta).unwrap();
        assert!(decoded.deleted_at.is_some());

        let deadline_key = backend
            .db
            .get(kv::stream_doe_deadline::ser_key(deadline, stream_id))
            .await
            .unwrap();
        assert!(deadline_key.is_none());
    }

    #[tokio::test]
    async fn stream_doe_deletes_never_written_stream() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-never").unwrap();
        let stream = StreamName::from_str("doe-stream-never").unwrap();
        let stream_id = StreamId::new(&basin, &stream);
        let created_at = OffsetDateTime::from_unix_timestamp(10).unwrap();
        let mut config = OptionalStreamConfig::default();
        config.delete_on_empty.min_age = Some(MIN_AGE);
        let meta = stream_meta_with_config(config, created_at);

        seed_stream_with_meta(&backend, &basin, &stream, meta).await;

        let write_timestamp = TimestampSecs::from_secs(10);
        backend
            .db
            .put(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::ser_value(StreamPosition::MIN, write_timestamp),
            )
            .await
            .unwrap();
        let deadline_secs = u64::from(write_timestamp.as_u32())
            .saturating_add(MIN_AGE.as_secs())
            .min(u64::from(u32::MAX)) as u32;
        let deadline = TimestampSecs::from_secs(deadline_secs);
        backend
            .db
            .put(
                kv::stream_doe_deadline::ser_key(deadline, stream_id),
                kv::stream_doe_deadline::ser_value(MIN_AGE),
            )
            .await
            .unwrap();

        let has_more = backend.clone().tick_stream_doe().await.unwrap();
        assert!(!has_more);

        let meta = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream meta should remain");
        let decoded = kv::stream_meta::deser_value(meta).unwrap();
        assert!(decoded.deleted_at.is_some());

        let deadline_key = backend
            .db
            .get(kv::stream_doe_deadline::ser_key(deadline, stream_id))
            .await
            .unwrap();
        assert!(deadline_key.is_none());
    }

    #[tokio::test]
    async fn stream_doe_skips_recent_tail_write() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-recent").unwrap();
        let stream = StreamName::from_str("doe-stream-recent").unwrap();
        let stream_id = seed_stream(&backend, &basin, &stream).await;
        let deadline = TimestampSecs::from_secs(10_000);
        let write_timestamp = TimestampSecs::from_secs(10_000);

        backend
            .db
            .put(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::ser_value(
                    StreamPosition {
                        seq_num: 1,
                        timestamp: 1234,
                    },
                    write_timestamp,
                ),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::stream_doe_deadline::ser_key(deadline, stream_id),
                kv::stream_doe_deadline::ser_value(MIN_AGE),
            )
            .await
            .unwrap();

        let has_more = backend.clone().tick_stream_doe().await.unwrap();
        assert!(!has_more);

        let meta = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream meta should remain");
        let decoded = kv::stream_meta::deser_value(meta).unwrap();
        assert!(decoded.deleted_at.is_none());

        let deadline_key = backend
            .db
            .get(kv::stream_doe_deadline::ser_key(deadline, stream_id))
            .await
            .unwrap();
        assert!(deadline_key.is_none());
    }

    #[tokio::test]
    async fn stream_doe_skips_stream_with_records() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-nonempty").unwrap();
        let stream = StreamName::from_str("doe-stream-nonempty").unwrap();
        let stream_id = seed_stream(&backend, &basin, &stream).await;
        let deadline = TimestampSecs::now();

        let pos = StreamPosition {
            seq_num: 1,
            timestamp: 1234,
        };
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
                kv::stream_doe_deadline::ser_key(deadline, stream_id),
                kv::stream_doe_deadline::ser_value(MIN_AGE),
            )
            .await
            .unwrap();

        let has_more = backend.clone().tick_stream_doe().await.unwrap();
        assert!(!has_more);

        let meta = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream meta should remain");
        let decoded = kv::stream_meta::deser_value(meta).unwrap();
        assert!(decoded.deleted_at.is_none());

        let deadline_key = backend
            .db
            .get(kv::stream_doe_deadline::ser_key(deadline, stream_id))
            .await
            .unwrap();
        assert!(deadline_key.is_none());

        let timestamp_key = backend
            .db
            .get(kv::stream_record_timestamp::ser_key(stream_id, pos))
            .await
            .unwrap();
        assert!(timestamp_key.is_some());
    }

    #[tokio::test]
    async fn stream_doe_ignores_future_deadline() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-future").unwrap();
        let stream = StreamName::from_str("doe-stream-future").unwrap();
        let stream_id = seed_stream(&backend, &basin, &stream).await;
        let deadline = TimestampSecs::after(Duration::from_secs(3600));

        backend
            .db
            .put(
                kv::stream_doe_deadline::ser_key(deadline, stream_id),
                kv::stream_doe_deadline::ser_value(MIN_AGE),
            )
            .await
            .unwrap();

        let has_more = backend.clone().tick_stream_doe().await.unwrap();
        assert!(!has_more);

        let meta = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream meta should remain");
        let decoded = kv::stream_meta::deser_value(meta).unwrap();
        assert!(decoded.deleted_at.is_none());

        let deadline_key = backend
            .db
            .get(kv::stream_doe_deadline::ser_key(deadline, stream_id))
            .await
            .unwrap();
        assert!(deadline_key.is_some());
    }

    #[tokio::test]
    async fn stream_doe_groups_multiple_deadlines() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-multi").unwrap();
        let stream = StreamName::from_str("doe-stream-multi").unwrap();
        let stream_id = seed_stream(&backend, &basin, &stream).await;
        let far_future = TimestampSecs::after(Duration::from_secs(3600));
        let deadline_a = TimestampSecs::after(Duration::from_secs(0));
        let deadline_b = TimestampSecs::after(Duration::from_secs(1));

        backend
            .db
            .put(
                kv::stream_doe_deadline::ser_key(deadline_a, stream_id),
                kv::stream_doe_deadline::ser_value(MIN_AGE),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::stream_doe_deadline::ser_key(deadline_b, stream_id),
                kv::stream_doe_deadline::ser_value(MIN_AGE),
            )
            .await
            .unwrap();

        let page = backend.list_pending_stream_doe(far_future).await.unwrap();
        assert!(!page.has_more);
        assert_eq!(page.values.len(), 1);
        let (pending_stream_id, pending) = page.values.into_iter().next().unwrap();
        assert_eq!(pending_stream_id, stream_id);
        let mut deadlines: Vec<_> = pending.iter().map(|entry| entry.deadline).collect();
        deadlines.sort();
        let mut expected = vec![deadline_a, deadline_b];
        expected.sort();
        assert_eq!(deadlines, expected);

        backend
            .process_stream_doe(stream_id, pending)
            .await
            .unwrap();

        for deadline in [deadline_a, deadline_b] {
            let deadline_key = backend
                .db
                .get(kv::stream_doe_deadline::ser_key(deadline, stream_id))
                .await
                .unwrap();
            assert!(deadline_key.is_none());
        }
    }

    #[tokio::test]
    async fn stream_doe_deletes_if_any_pending_entry_is_eligible() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-pairs").unwrap();
        let stream = StreamName::from_str("doe-stream-pairs").unwrap();
        let stream_id = seed_stream(&backend, &basin, &stream).await;

        backend
            .db
            .put(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::ser_value(
                    StreamPosition {
                        seq_num: 1,
                        timestamp: 1234,
                    },
                    TimestampSecs::from_secs(1_050),
                ),
            )
            .await
            .unwrap();

        for (deadline, min_age) in [
            (TimestampSecs::from_secs(1_100), Duration::from_secs(100)),
            (TimestampSecs::from_secs(1_062), Duration::from_secs(10)),
        ] {
            backend
                .db
                .put(
                    kv::stream_doe_deadline::ser_key(deadline, stream_id),
                    kv::stream_doe_deadline::ser_value(min_age),
                )
                .await
                .unwrap();
        }

        backend.clone().tick_stream_doe().await.unwrap();

        let meta = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream meta should remain");
        let decoded = kv::stream_meta::deser_value(meta).unwrap();
        assert!(decoded.deleted_at.is_some());
    }

    #[tokio::test]
    async fn reconfigure_enabling_doe_on_nonempty_retained_stream_arms_future_deadline() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-enable").unwrap();
        let stream = StreamName::from_str("doe-stream-enable").unwrap();
        let config = OptionalStreamConfig {
            retention_policy: Some(RetentionPolicy::Age(Duration::from_secs(120))),
            ..Default::default()
        };
        let stream_id = seed_stream_with_meta(
            &backend,
            &basin,
            &stream,
            stream_meta_with_config(config, OffsetDateTime::now_utc()),
        )
        .await;
        let pos = StreamPosition {
            seq_num: 1,
            timestamp: 1234,
        };
        backend
            .db
            .put(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::ser_value(pos, TimestampSecs::now()),
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

        let min_age = Duration::from_secs(30);
        let expected_delay =
            crate::backend::streamer::doe_arm_delay(Duration::from_secs(120), min_age);
        let lower_bound = TimestampSecs::now();
        backend
            .reconfigure_stream(
                basin,
                stream,
                StreamReconfiguration {
                    delete_on_empty: Maybe::from(Some(DeleteOnEmptyReconfiguration {
                        min_age: Maybe::from(Some(min_age)),
                    })),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let upper_bound = TimestampSecs::now();

        let entries = list_doe_entries(&backend).await;
        assert_eq!(entries.len(), 1);
        let (deadline, scheduled_stream_id, scheduled_min_age) = entries[0];
        assert_eq!(scheduled_stream_id, stream_id);
        assert_eq!(scheduled_min_age, min_age);

        let lower_secs = u64::from(lower_bound.as_u32()).saturating_add(expected_delay.as_secs());
        let upper_secs = u64::from(upper_bound.as_u32()).saturating_add(expected_delay.as_secs());
        let deadline_secs = u64::from(deadline.as_u32());
        assert!(lower_secs <= deadline_secs);
        assert!(deadline_secs <= upper_secs);
    }

    #[tokio::test]
    async fn reconfigure_changing_enabled_doe_does_not_arm_new_deadline() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-stale").unwrap();
        let stream = StreamName::from_str("doe-stream-stale").unwrap();
        let initial_min_age = Duration::from_secs(10);
        let mut config = OptionalStreamConfig::default();
        config.delete_on_empty.min_age = Some(initial_min_age);
        let stream_id = seed_stream_with_meta(
            &backend,
            &basin,
            &stream,
            stream_meta_with_config(config, OffsetDateTime::now_utc()),
        )
        .await;
        let existing_deadline = TimestampSecs::from_secs(4_242);
        backend
            .db
            .put(
                kv::stream_doe_deadline::ser_key(existing_deadline, stream_id),
                kv::stream_doe_deadline::ser_value(initial_min_age),
            )
            .await
            .unwrap();

        backend
            .reconfigure_stream(
                basin,
                stream,
                StreamReconfiguration {
                    delete_on_empty: Maybe::from(Some(DeleteOnEmptyReconfiguration {
                        min_age: Maybe::from(Some(Duration::from_secs(600))),
                    })),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let entries = list_doe_entries(&backend).await;
        assert_eq!(
            entries,
            vec![(existing_deadline, stream_id, initial_min_age)]
        );
    }
}
