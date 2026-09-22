use std::time::Duration;

use bytes::Bytes;
use futures::{StreamExt, stream};
use indexmap::IndexMap;
use itertools::Itertools;
use s2_common::resources::Page;
use slatedb::{
    WriteBatch,
    config::{DurabilityLevel, ScanOptions},
};
use tracing::instrument;

use crate::{
    backend::{
        Backend,
        error::{DeleteStreamError, StorageError, StreamDeleteOnEmptyError},
        kv::{self, timestamp::TimestampSecs},
        streamer::TerminalTrimCondition,
    },
    stream_id::StreamId,
};

const PENDING_LIST_LIMIT: usize = 10_000;
const CONCURRENCY: usize = 4;

#[derive(Debug)]
struct PendingDoeEntry {
    key: Bytes,
    deadline: TimestampSecs,
    min_age: Duration,
    /// Database commit sequence of the observed deadline row.
    deadline_seq: u64,
}

fn last_write_cutoff(
    pending: &[PendingDoeEntry],
    stream_creation_seq: u64,
) -> Option<TimestampSecs> {
    pending
        .iter()
        // The ID mapping is written only when this incarnation is created.
        .filter(|entry| entry.deadline_seq >= stream_creation_seq)
        .filter_map(|entry| entry.deadline.checked_sub_duration(entry.min_age))
        .max()
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
        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = self
            .db
            .scan_with_options(kv::stream_doe_deadline::expired_key_range(now), &scan_opts)
            .await?;
        let mut pending: IndexMap<StreamId, Vec<PendingDoeEntry>> = IndexMap::new();
        let mut has_more = false;
        let mut count = 0;
        while let Some(kv) = it.next().await? {
            let (deadline, stream_id, _) = kv::stream_doe_deadline::deser_key(kv.key.clone())?;
            let min_age = kv::stream_doe_deadline::deser_value(kv.value)?;
            assert!(deadline <= now);
            pending.entry(stream_id).or_default().push(PendingDoeEntry {
                key: kv.key,
                deadline,
                min_age,
                deadline_seq: kv.seq,
            });
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
        if let Some(((basin, stream), stream_creation_seq)) = self
            .db_get_with(kv::stream_id_mapping::ser_key(stream_id), |entry| {
                Ok((kv::stream_id_mapping::deser_value(entry.value)?, entry.seq))
            })
            .await?
            && let Some(last_write_cutoff) = last_write_cutoff(&pending, stream_creation_seq)
        {
            match self
                .delete_stream_with_condition(
                    basin,
                    stream,
                    TerminalTrimCondition::DeleteOnEmpty {
                        last_write_cutoff,
                        expected_stream_creation_seq: stream_creation_seq,
                    },
                )
                .await
            {
                Ok(()) | Err(DeleteStreamError::StreamNotFound(_)) => {}
                Err(err) => return Err(err.into()),
            }
        }
        self.clear_doe_deadlines(&pending).await?;
        Ok(())
    }

    #[instrument(ret, err, skip(self, pending), fields(num_deadlines = pending.len()))]
    async fn clear_doe_deadlines(&self, pending: &[PendingDoeEntry]) -> Result<(), StorageError> {
        // New schedules use unique keys and never overwrite legacy keys.
        // The scan already limits this batch to PENDING_LIST_LIMIT entries.
        let mut batch = WriteBatch::new();
        for entry in pending {
            batch.delete(&entry.key);
        }
        if !batch.is_empty() {
            self.db.write(batch).await?.await_durable().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use s2_common::{
        basin::BasinName,
        config::{
            BasinConfig, DeleteOnEmptyReconfiguration, OptionalStreamConfig, RetentionPolicy,
            StreamReconfiguration,
        },
        maybe::Maybe,
        record::StreamPosition,
        resources::ProvisionMode,
        stream::StreamName,
    };
    use slatedb::config::{DurabilityLevel, ScanOptions};
    use time::OffsetDateTime;

    use super::{super::tests::test_backend, TimestampSecs};
    use crate::{
        backend::{Backend, kv, test_util::DbWriteTestExt as _},
        stream_id::StreamId,
    };

    const MIN_AGE: Duration = Duration::from_secs(60);

    fn stream_meta_with_config(
        config: OptionalStreamConfig,
        created_at: OffsetDateTime,
    ) -> kv::stream_meta::StreamMeta {
        kv::stream_meta::StreamMeta {
            config: config.into(),
            cipher: None,
            created_at,
            deleted_at: None,
            creation_idempotency_key: None,
        }
    }

    fn stream_meta_with_doe_min_age(min_age: Duration) -> kv::stream_meta::StreamMeta {
        let mut config = OptionalStreamConfig::default();
        config.delete_on_empty.min_age = Some(min_age);
        stream_meta_with_config(config, OffsetDateTime::now_utc())
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
                kv::basin_meta::ser_key(basin),
                kv::basin_meta::ser_value(&kv::basin_meta::BasinMeta {
                    config: BasinConfig::default(),
                    created_at: OffsetDateTime::now_utc(),
                    deleted_at: None,
                    creation_idempotency_key: None,
                }),
            )
            .assert_durable()
            .await;
        backend
            .db
            .put(
                kv::stream_meta::ser_key(basin, stream),
                kv::stream_meta::ser_value(&meta),
            )
            .assert_durable()
            .await;
        backend
            .db
            .put(
                kv::stream_id_mapping::ser_key(stream_id),
                kv::stream_id_mapping::ser_value(basin, stream),
            )
            .assert_durable()
            .await;
        stream_id
    }

    async fn list_doe_entries(backend: &Backend) -> Vec<(TimestampSecs, StreamId, Duration)> {
        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = backend
            .db
            .scan_with_options(
                kv::key_type_range(kv::KeyType::StreamDeleteOnEmptyDeadline),
                &scan_opts,
            )
            .await
            .unwrap();
        let mut entries = Vec::new();
        while let Some(kv) = it.next().await.unwrap() {
            let (deadline, stream_id, _) = kv::stream_doe_deadline::deser_key(kv.key).unwrap();
            let min_age = kv::stream_doe_deadline::deser_value(kv.value).unwrap();
            entries.push((deadline, stream_id, min_age));
        }
        entries
    }

    async fn put_tail_position(
        backend: &Backend,
        stream_id: StreamId,
        position: StreamPosition,
    ) -> TimestampSecs {
        let key = kv::stream_tail_position::ser_key(stream_id);
        backend
            .db
            .put(key.clone(), kv::stream_tail_position::ser_value(position))
            .assert_durable()
            .await;
        let kv = backend
            .db
            .get_key_value(key)
            .await
            .unwrap()
            .expect("tail position should exist");
        TimestampSecs::from_millis(kv.create_ts)
    }

    fn deadline_after(write_timestamp: TimestampSecs, age: Duration) -> TimestampSecs {
        let deadline_secs = u64::from(write_timestamp.as_u32())
            .saturating_add(age.as_secs())
            .min(u64::from(u32::MAX)) as u32;
        TimestampSecs::from_secs(deadline_secs)
    }

    async fn process_pending_stream_doe_at(
        backend: &Backend,
        stream_id: StreamId,
        now: TimestampSecs,
    ) {
        let mut page = backend.list_pending_stream_doe(now).await.unwrap();
        assert!(!page.has_more);
        assert_eq!(page.values.len(), 1);
        let (pending_stream_id, pending) = page.values.pop().unwrap();
        assert_eq!(pending_stream_id, stream_id);

        backend
            .process_stream_doe(stream_id, pending)
            .await
            .unwrap();
    }

    async fn configure_min_age(
        backend: &Backend,
        basin: &BasinName,
        stream: &StreamName,
        min_age: Duration,
        via_ensure: bool,
    ) {
        if via_ensure {
            let mut config = backend
                .get_stream_config(basin.clone(), stream.clone())
                .await
                .unwrap();
            config.delete_on_empty.min_age = min_age;
            backend
                .provision_stream(
                    basin.clone(),
                    stream.clone(),
                    config.into(),
                    ProvisionMode::Ensure,
                )
                .await
                .unwrap();
        } else {
            backend
                .reconfigure_stream(
                    basin.clone(),
                    stream.clone(),
                    StreamReconfiguration {
                        delete_on_empty: Maybe::from(Some(DeleteOnEmptyReconfiguration {
                            min_age: Maybe::from(Some(min_age)),
                        })),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn stream_doe_marks_deleted_and_clears_deadline() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin").unwrap();
        let stream = StreamName::from_str("doe-stream").unwrap();
        let min_age = Duration::from_secs(1);
        let stream_id = seed_stream_with_meta(
            &backend,
            &basin,
            &stream,
            stream_meta_with_doe_min_age(min_age),
        )
        .await;
        let write_timestamp = put_tail_position(
            &backend,
            stream_id,
            StreamPosition {
                seq_num: 1,
                timestamp: 1234,
            },
        )
        .await;
        let deadline = deadline_after(write_timestamp, min_age);
        let key = kv::stream_doe_deadline::new_key(deadline, stream_id);

        backend
            .db
            .put(&key, kv::stream_doe_deadline::ser_value(min_age))
            .assert_durable()
            .await;

        tokio::time::sleep(min_age).await;
        process_pending_stream_doe_at(&backend, stream_id, deadline).await;

        let meta = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream meta should remain");
        let decoded = kv::stream_meta::deser_value(meta).unwrap();
        assert!(decoded.deleted_at.is_some());

        let deadline_key = backend.db.get(&key).await.unwrap();
        assert!(deadline_key.is_none());
    }

    #[tokio::test]
    async fn stream_doe_deletes_never_written_stream() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-never").unwrap();
        let stream = StreamName::from_str("doe-stream-never").unwrap();
        let stream_id = StreamId::new(&basin, &stream);
        let min_age = Duration::from_secs(1);
        let meta = stream_meta_with_doe_min_age(min_age);

        seed_stream_with_meta(&backend, &basin, &stream, meta).await;

        let write_timestamp = put_tail_position(&backend, stream_id, StreamPosition::MIN).await;
        let deadline = deadline_after(write_timestamp, min_age);
        let key = kv::stream_doe_deadline::new_key(deadline, stream_id);
        backend
            .db
            .put(&key, kv::stream_doe_deadline::ser_value(min_age))
            .assert_durable()
            .await;

        tokio::time::sleep(min_age).await;
        process_pending_stream_doe_at(&backend, stream_id, deadline).await;

        let meta = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream meta should remain");
        let decoded = kv::stream_meta::deser_value(meta).unwrap();
        assert!(decoded.deleted_at.is_some());

        let deadline_key = backend.db.get(&key).await.unwrap();
        assert!(deadline_key.is_none());
    }

    #[tokio::test]
    async fn stream_doe_skips_recent_tail_write() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-recent").unwrap();
        let stream = StreamName::from_str("doe-stream-recent").unwrap();
        let stream_id = seed_stream_with_meta(
            &backend,
            &basin,
            &stream,
            stream_meta_with_doe_min_age(MIN_AGE),
        )
        .await;
        let write_timestamp = put_tail_position(
            &backend,
            stream_id,
            StreamPosition {
                seq_num: 1,
                timestamp: 1234,
            },
        )
        .await;
        let deadline = write_timestamp;
        let key = kv::stream_doe_deadline::new_key(deadline, stream_id);

        backend
            .db
            .put(&key, kv::stream_doe_deadline::ser_value(MIN_AGE))
            .assert_durable()
            .await;

        process_pending_stream_doe_at(&backend, stream_id, deadline).await;

        let meta = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream meta should remain");
        let decoded = kv::stream_meta::deser_value(meta).unwrap();
        assert!(decoded.deleted_at.is_none());

        let deadline_key = backend.db.get(&key).await.unwrap();
        assert!(deadline_key.is_none());
    }

    #[tokio::test]
    async fn stream_doe_skips_stream_with_records() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-nonempty").unwrap();
        let stream = StreamName::from_str("doe-stream-nonempty").unwrap();
        let stream_id = seed_stream_with_meta(
            &backend,
            &basin,
            &stream,
            stream_meta_with_doe_min_age(MIN_AGE),
        )
        .await;
        let deadline = TimestampSecs::now();
        let key = kv::stream_doe_deadline::new_key(deadline, stream_id);

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
            .assert_durable()
            .await;
        backend
            .db
            .put(&key, kv::stream_doe_deadline::ser_value(MIN_AGE))
            .assert_durable()
            .await;

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

        let deadline_key = backend.db.get(&key).await.unwrap();
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
        let stream_id = seed_stream_with_meta(
            &backend,
            &basin,
            &stream,
            stream_meta_with_doe_min_age(MIN_AGE),
        )
        .await;
        let deadline = TimestampSecs::after(Duration::from_secs(3600));
        let key = kv::stream_doe_deadline::new_key(deadline, stream_id);

        backend
            .db
            .put(&key, kv::stream_doe_deadline::ser_value(MIN_AGE))
            .assert_durable()
            .await;

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

        let deadline_key = backend.db.get(&key).await.unwrap();
        assert!(deadline_key.is_some());
    }

    #[tokio::test]
    async fn stream_doe_groups_and_clears_only_scanned_deadlines() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-multi").unwrap();
        let stream = StreamName::from_str("doe-stream-multi").unwrap();
        let stream_id = seed_stream_with_meta(
            &backend,
            &basin,
            &stream,
            stream_meta_with_doe_min_age(MIN_AGE),
        )
        .await;
        let deadline = TimestampSecs::now();
        let next_deadline = TimestampSecs::from_secs(deadline.as_u32() + 1);
        let keys = [
            kv::stream_doe_deadline::ser_key(deadline, stream_id, None),
            kv::stream_doe_deadline::new_key(deadline, stream_id),
            kv::stream_doe_deadline::new_key(next_deadline, stream_id),
        ];
        let mut batch = slatedb::WriteBatch::new();
        for key in &keys {
            batch.put(key, kv::stream_doe_deadline::ser_value(MIN_AGE));
        }
        backend.db.write(batch).assert_durable().await;

        let page = backend
            .list_pending_stream_doe(next_deadline)
            .await
            .unwrap();
        assert!(!page.has_more);
        assert_eq!(page.values.len(), 1);
        let (pending_stream_id, pending) = page.values.into_iter().next().unwrap();
        assert_eq!(pending_stream_id, stream_id);
        assert_eq!(
            pending
                .iter()
                .map(|entry| entry.deadline)
                .collect::<Vec<_>>(),
            [deadline, deadline, next_deadline]
        );

        // Re-arming the same deadline within this incarnation must also survive cleanup.
        let rescheduled_key = kv::stream_doe_deadline::new_key(deadline, stream_id);
        backend
            .db
            .put(
                &rescheduled_key,
                kv::stream_doe_deadline::ser_value(MIN_AGE),
            )
            .assert_durable()
            .await;
        backend
            .process_stream_doe(stream_id, pending)
            .await
            .unwrap();

        for key in keys {
            assert!(
                backend
                    .db_get(key, kv::stream_doe_deadline::deser_value)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            backend
                .db_get(rescheduled_key, kv::stream_doe_deadline::deser_value)
                .await
                .unwrap(),
            Some(MIN_AGE)
        );
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
                kv::stream_tail_position::ser_value(pos),
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

    #[rstest::rstest]
    #[case::increased(600, true)]
    #[case::decreased(5, true)]
    #[case::unchanged(10, false)]
    #[case::disabled(0, false)]
    #[tokio::test]
    async fn configure_doe_rearms_only_when_enabled_min_age_changes(
        #[case] min_age_secs: u64,
        #[case] rearmed: bool,
        #[values(false, true)] via_ensure: bool,
    ) {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-basin-stale").unwrap();
        let stream = StreamName::from_str("doe-stream-stale").unwrap();
        let initial_min_age = Duration::from_secs(10);
        let retention_age = Duration::from_secs(120);
        let mut config = OptionalStreamConfig {
            retention_policy: Some(RetentionPolicy::Age(retention_age)),
            ..Default::default()
        };
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
                kv::stream_doe_deadline::new_key(existing_deadline, stream_id),
                kv::stream_doe_deadline::ser_value(initial_min_age),
            )
            .assert_durable()
            .await;

        let min_age = Duration::from_secs(min_age_secs);
        let delay = crate::backend::streamer::doe_arm_delay(retention_age, min_age);
        let lower_bound = TimestampSecs::after(delay);
        configure_min_age(&backend, &basin, &stream, min_age, via_ensure).await;
        let upper_bound = TimestampSecs::after(delay);

        let entries = list_doe_entries(&backend).await;
        assert_eq!(entries.len(), 1 + usize::from(rearmed));
        assert_eq!(entries[0], (existing_deadline, stream_id, initial_min_age));
        if rearmed {
            let (deadline, scheduled_stream_id, scheduled_min_age) = entries[1];
            assert_eq!(scheduled_stream_id, stream_id);
            assert_eq!(scheduled_min_age, min_age);
            assert!((lower_bound..=upper_bound).contains(&deadline));
        }
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn configure_increasing_doe_min_age_rejects_stale_deadline_and_keeps_new_one(
        #[values(false, true)] via_ensure: bool,
        #[values(false, true)] start_streamer_before_configure: bool,
    ) {
        let backend = test_backend().await;
        let initial_min_age = Duration::from_secs(1);
        let min_age = Duration::from_secs(600);
        let basin = BasinName::from_str("doe-basin-increase").unwrap();
        let stream = StreamName::from_str("doe-stream-increase").unwrap();
        let stream_id = seed_stream_with_meta(
            &backend,
            &basin,
            &stream,
            stream_meta_with_doe_min_age(initial_min_age),
        )
        .await;
        let write_timestamp = put_tail_position(&backend, stream_id, StreamPosition::MIN).await;
        let deadline = deadline_after(write_timestamp, initial_min_age);
        backend
            .db
            .put(
                kv::stream_doe_deadline::new_key(deadline, stream_id),
                kv::stream_doe_deadline::ser_value(initial_min_age),
            )
            .assert_durable()
            .await;
        // Cover both config notifications and recovery of the persisted config and tail.
        let client = if start_streamer_before_configure {
            Some(
                backend
                    .streamer_client_guarded(&basin, &stream)
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        configure_min_age(&backend, &basin, &stream, min_age, via_ensure).await;

        tokio::time::sleep(initial_min_age).await;
        assert!(!backend.clone().tick_stream_doe().await.unwrap());
        let config = backend
            .get_stream_config(basin.clone(), stream.clone())
            .await
            .unwrap();
        assert_eq!(config.delete_on_empty.min_age(), Some(min_age));
        assert_eq!(
            backend
                .streamer_client_guarded(&basin, &stream)
                .await
                .unwrap()
                .check_tail()
                .await
                .unwrap(),
            StreamPosition::MIN
        );
        let entries = list_doe_entries(&backend).await;
        assert_eq!(
            entries.len(),
            1,
            "only the new schedule should survive cleanup"
        );
        assert_eq!(entries[0].1, stream_id);
        assert_eq!(entries[0].2, min_age);
        assert!(entries[0].0 > TimestampSecs::now());
        drop(client);
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_doe_work_cannot_delete_recreated_stream() {
        use s2_common::resources::ProvisionMode;

        use crate::backend::streamer::{TerminalTrimCondition, TerminalTrimOutcome};
        let backend = test_backend().await;
        let mut config = OptionalStreamConfig::default();
        config.delete_on_empty.min_age = Some(MIN_AGE);
        let (basin, stream) =
            crate::backend::test_util::create_stream(&backend, config.clone()).await;
        let stream_id = StreamId::new(&basin, &stream);
        let stream_creation_seq = backend
            .db_get_with(kv::stream_id_mapping::ser_key(stream_id), |row| Ok(row.seq))
            .await
            .unwrap()
            .unwrap();
        let deadline = TimestampSecs::after(Duration::from_secs(3600));
        let keys = [
            kv::stream_doe_deadline::ser_key(deadline, stream_id, None),
            kv::stream_doe_deadline::new_key(deadline, stream_id),
        ];
        let mut batch = slatedb::WriteBatch::new();
        for key in &keys {
            batch.put(key, kv::stream_doe_deadline::ser_value(MIN_AGE));
        }
        backend.db.write(batch).assert_durable().await;
        let (_, pending) = backend
            .list_pending_stream_doe(deadline)
            .await
            .unwrap()
            .values
            .pop()
            .unwrap();
        backend
            .delete_stream(basin.clone(), stream.clone())
            .await
            .unwrap();
        backend.clone().tick_stream_trim().await.unwrap();
        backend
            .provision_stream(
                basin.clone(),
                stream.clone(),
                config,
                ProvisionMode::CreateOnly {
                    request_token: None,
                },
            )
            .await
            .unwrap();
        let recreated_stream_deadline_key = kv::stream_doe_deadline::new_key(deadline, stream_id);
        backend
            .db
            .put(
                &recreated_stream_deadline_key,
                kv::stream_doe_deadline::ser_value(MIN_AGE),
            )
            .assert_durable()
            .await;

        // Cover recreation after the worker already validated the ID mapping.
        let outcome = backend
            .streamer_client_guarded(&basin, &stream)
            .await
            .unwrap()
            .terminal_trim(TerminalTrimCondition::DeleteOnEmpty {
                last_write_cutoff: deadline,
                expected_stream_creation_seq: stream_creation_seq,
            })
            .await
            .unwrap();
        assert_eq!(outcome, TerminalTrimOutcome::Ineligible);
        backend
            .process_stream_doe(stream_id, pending)
            .await
            .unwrap();
        assert!(
            backend
                .get_stream_config(basin.clone(), stream.clone())
                .await
                .is_ok()
        );
        for key in keys {
            assert!(
                backend
                    .db_get(key, kv::stream_doe_deadline::deser_value)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            backend
                .db_get(
                    recreated_stream_deadline_key,
                    kv::stream_doe_deadline::deser_value
                )
                .await
                .unwrap(),
            Some(MIN_AGE),
            "cleanup must preserve a new schedule for the same deadline"
        );
        backend.close().await.unwrap();
    }
}
