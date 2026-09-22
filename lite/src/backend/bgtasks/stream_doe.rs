use bytes::Bytes;
use futures::{StreamExt, stream};
use indexmap::IndexMap;
use s2_common::{basin::BasinName, resources::Page, stream::StreamName};
use slatedb::{
    IsolationLevel, WriteBatch,
    config::{DurabilityLevel, ScanOptions},
};

use super::PageProgress;
use crate::{
    backend::{
        Backend, doe,
        error::{DeleteStreamError, StorageError, StreamDeleteOnEmptyError},
        kv,
        store::{db_snapshot_get_with, db_txn_commit_durable, db_txn_get, db_txn_get_with},
        streamer::{TerminalTrimCondition, TerminalTrimOutcome},
    },
    stream_id::StreamId,
};

const PENDING_LIST_LIMIT: usize = 128;
const CONCURRENCY: usize = 4;

#[derive(Clone, Copy, Debug)]
struct PendingCheck {
    stream_id: StreamId,
    check: kv::stream_doe_state::Check,
}

struct CheckSnapshot {
    revision: u64,
    creation_seq: u64,
    config_seq: u64,
    basin: BasinName,
    stream: StreamName,
}

impl Backend {
    pub(super) async fn tick_stream_doe(self) -> Result<bool, StreamDeleteOnEmptyError> {
        // Drain legacy keys regardless of their old deadlines. Their timestamps
        // and values have no role in the new scheduler or deletion eligibility.
        let mut progress = self.migrate_stream_doe().await?;
        let page = self
            .list_pending_stream_doe(kv::timestamp::TimestampSecs::now())
            .await?;
        progress.has_more |= page.has_more;
        let mut processed = stream::iter(page.values)
            .map(|pending| {
                let backend = self.clone();
                async move { backend.process_stream_doe(pending).await }
            })
            .buffer_unordered(CONCURRENCY);
        while let Some(result) = processed.next().await {
            progress.record(result, StreamDeleteOnEmptyError::is_transaction_conflict)?;
        }
        Ok(progress.should_continue())
    }

    async fn list_pending_stream_doe(
        &self,
        now: kv::timestamp::TimestampSecs,
    ) -> Result<Page<PendingCheck>, StorageError> {
        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = self
            .db
            .scan_with_options(kv::stream_doe_check::due_key_range(now), &scan_opts)
            .await?;
        let mut pending = Vec::new();
        while let Some(kv) = it.next().await? {
            let (stream_id, check) = kv::stream_doe_check::deser_key(kv.key)?;
            pending.push(PendingCheck { stream_id, check });
            if pending.len() == PENDING_LIST_LIMIT {
                return Ok(Page::new(pending, true));
            }
        }
        Ok(Page::new(pending, false))
    }

    async fn process_stream_doe(
        &self,
        pending: PendingCheck,
    ) -> Result<(), StreamDeleteOnEmptyError> {
        let Some(snapshot) = self.observe_doe_check(pending).await? else {
            return Ok(());
        };
        let outcome = match self
            .delete_stream_with_condition(
                snapshot.basin.clone(),
                snapshot.stream.clone(),
                TerminalTrimCondition::DeleteOnEmpty {
                    expected_stream_creation_seq: snapshot.creation_seq,
                    expected_config_seq: snapshot.config_seq,
                },
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(DeleteStreamError::StreamNotFound(_)) => TerminalTrimOutcome::Obsolete,
            Err(err) => return Err(err.into()),
        };
        self.finish_doe_check(pending, snapshot, outcome).await?;
        Ok(())
    }

    /// Capture the scheduler revision before the streamer's asynchronous scan.
    async fn observe_doe_check(
        &self,
        pending: PendingCheck,
    ) -> Result<Option<CheckSnapshot>, StorageError> {
        // Observation needs a consistent view, but no transaction read set. The
        // completion transaction validates this revision after the actor's scan.
        let snapshot = self.db.snapshot().await?;
        let state = db_snapshot_get_with(
            &snapshot,
            kv::stream_doe_state::ser_key(pending.stream_id),
            |entry| Ok((kv::stream_doe_state::deser_value(entry.value)?, entry.seq)),
        )
        .await?;
        let Some((kv::stream_doe_state::State::Scheduled(_), revision)) = state
            .filter(|(state, _)| *state == kv::stream_doe_state::State::Scheduled(pending.check))
        else {
            drop(snapshot);
            self.discard_doe_check(pending, state).await?;
            return Ok(None);
        };
        let mapping = db_snapshot_get_with(
            &snapshot,
            kv::stream_id_mapping::ser_key(pending.stream_id),
            |entry| Ok((kv::stream_id_mapping::deser_value(entry.value)?, entry.seq)),
        )
        .await?;
        if let Some(((basin, stream), creation_seq)) = mapping
            && revision >= creation_seq
            && let Some((meta, config_seq)) = db_snapshot_get_with(
                &snapshot,
                kv::stream_meta::ser_key(&basin, &stream),
                |entry| Ok((kv::stream_meta::deser_value(entry.value)?, entry.seq)),
            )
            .await?
            && meta.deleted_at.is_none()
            && meta.config.delete_on_empty.min_age().is_some()
        {
            return Ok(Some(CheckSnapshot {
                revision,
                creation_seq,
                config_seq,
                basin,
                stream,
            }));
        }
        drop(snapshot);
        self.discard_doe_check(pending, state).await?;
        Ok(None)
    }

    /// Obsolete work needs a transaction only when it is actually discarded.
    /// Revalidate the snapshot so cleanup cannot erase a concurrent wake.
    async fn discard_doe_check(
        &self,
        pending: PendingCheck,
        observed: Option<(kv::stream_doe_state::State, u64)>,
    ) -> Result<(), StorageError> {
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
        let current = db_txn_get_with(
            &txn,
            kv::stream_doe_state::ser_key(pending.stream_id),
            |entry| Ok((kv::stream_doe_state::deser_value(entry.value)?, entry.seq)),
        )
        .await?;
        if current != observed {
            return Ok(());
        }
        match current {
            Some((kv::stream_doe_state::State::Scheduled(check), _)) if check == pending.check => {
                doe::replace(
                    &txn,
                    pending.stream_id,
                    Some(kv::stream_doe_state::State::Scheduled(check)),
                    None,
                )?;
            }
            _ => {
                txn.delete(kv::stream_doe_check::ser_key(
                    pending.stream_id,
                    pending.check,
                ))?;
            }
        }
        db_txn_commit_durable(txn).await?;
        Ok(())
    }

    async fn finish_doe_check(
        &self,
        pending: PendingCheck,
        snapshot: CheckSnapshot,
        outcome: TerminalTrimOutcome,
    ) -> Result<(), StorageError> {
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
        let state = db_txn_get_with(
            &txn,
            kv::stream_doe_state::ser_key(pending.stream_id),
            |entry| Ok((kv::stream_doe_state::deser_value(entry.value)?, entry.seq)),
        )
        .await?;
        if state
            != Some((
                kv::stream_doe_state::State::Scheduled(pending.check),
                snapshot.revision,
            ))
        {
            // A trim/configuration event owns the next check, even if it kept the
            // same ticket. Consuming or postponing it here would lose that wake.
            return Ok(());
        }
        // Successful deletion marks metadata and advances its sequence. Deferred
        // outcomes must still belong to the configuration that was inspected.
        if outcome != TerminalTrimOutcome::DeletionPending {
            let config_seq = db_txn_get_with(
                &txn,
                kv::stream_meta::ser_key(&snapshot.basin, &snapshot.stream),
                |entry| Ok(entry.seq),
            )
            .await?;
            if config_seq != Some(snapshot.config_seq) {
                return Ok(());
            }
        }
        let next = match outcome {
            TerminalTrimOutcome::RetryAt(at) => Some(kv::stream_doe_state::State::Scheduled(
                kv::stream_doe_state::Check {
                    at,
                    id: rand::random(),
                },
            )),
            TerminalTrimOutcome::Parked => Some(kv::stream_doe_state::State::Parked),
            TerminalTrimOutcome::DeletionPending | TerminalTrimOutcome::Obsolete => None,
        };
        // Consuming the old check and installing its successor is one durable
        // transaction, including when the caller disappears during commit.
        doe::replace(
            &txn,
            pending.stream_id,
            Some(kv::stream_doe_state::State::Scheduled(pending.check)),
            next,
        )?;
        db_txn_commit_durable(txn).await?;
        Ok(())
    }

    async fn migrate_stream_doe(&self) -> Result<PageProgress, StorageError> {
        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = self
            .db
            .scan_with_options(
                kv::key_type_range(kv::KeyType::StreamDeleteOnEmptyDeadline),
                &scan_opts,
            )
            .await?;
        let mut pending: IndexMap<StreamId, Vec<Bytes>> = IndexMap::new();
        let mut count = 0;
        while let Some(entry) = it.next().await? {
            let (_, stream_id, _) = kv::stream_doe_deadline::deser_key(entry.key.clone())?;
            pending.entry(stream_id).or_default().push(entry.key);
            count += 1;
            if count == PENDING_LIST_LIMIT {
                break;
            }
        }
        let mut progress = PageProgress {
            has_more: count == PENDING_LIST_LIMIT,
            ..Default::default()
        };
        if pending.is_empty() {
            return Ok(progress);
        }
        let snapshot = self.db.snapshot().await?;
        let mut migrations = stream::iter(pending)
            .map(|(stream_id, keys)| self.migrate_doe_deadlines(&snapshot, stream_id, keys))
            .buffer_unordered(CONCURRENCY);
        let mut cleanup = WriteBatch::new();
        while let Some(result) = migrations.next().await {
            if let Some(keys) = progress.record(result, StorageError::is_transaction_conflict)? {
                for key in keys {
                    cleanup.delete(key);
                }
            }
        }
        if !cleanup.is_empty() {
            // Later enablement/recreation installs its own schedule. Only
            // legacy keys are removed; new state and its revision stay intact.
            // Durability also covers any commits observed by the snapshot.
            self.db.write(cleanup).await?.await_durable().await?;
        }
        Ok(progress)
    }

    async fn migrate_doe_deadlines(
        &self,
        snapshot: &slatedb::DbSnapshot,
        stream_id: StreamId,
        keys: Vec<Bytes>,
    ) -> Result<Vec<Bytes>, StorageError> {
        if needs_doe_migration(snapshot, stream_id).await? {
            // Initialization and removal remain atomic. Recheck all eligibility
            // in the transaction after the snapshot.
            self.initialize_doe_from_deadlines(stream_id, keys).await?;
            Ok(Vec::new())
        } else {
            Ok(keys)
        }
    }

    async fn initialize_doe_from_deadlines(
        &self,
        stream_id: StreamId,
        keys: Vec<Bytes>,
    ) -> Result<(), StorageError> {
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
        let mapping = db_txn_get_with(&txn, kv::stream_id_mapping::ser_key(stream_id), |entry| {
            Ok((kv::stream_id_mapping::deser_value(entry.value)?, entry.seq))
        })
        .await?;
        if let Some(((basin, stream), creation_seq)) = mapping
            && let Some(meta) = db_txn_get(
                &txn,
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            )
            .await?
            && meta.deleted_at.is_none()
            && meta.config.delete_on_empty.min_age().is_some()
        {
            let state = db_txn_get_with(&txn, kv::stream_doe_state::ser_key(stream_id), |entry| {
                Ok((kv::stream_doe_state::deser_value(entry.value)?, entry.seq))
            })
            .await?;
            if state.is_none_or(|(_, seq)| seq < creation_seq) {
                let next = kv::stream_doe_state::State::Scheduled(kv::stream_doe_state::Check {
                    at: kv::timestamp::TimestampSecs::now(),
                    id: rand::random(),
                });
                doe::replace(&txn, stream_id, state.map(|(state, _)| state), Some(next))?;
            }
            // Existing state, including Parked, is deliberately untouched.
        }
        for key in keys {
            txn.delete(key)?;
        }
        db_txn_commit_durable(txn).await?;
        Ok(())
    }
}

async fn needs_doe_migration(
    snapshot: &slatedb::DbSnapshot,
    stream_id: StreamId,
) -> Result<bool, StorageError> {
    let Some(((basin, stream), creation_seq)) = db_snapshot_get_with(
        snapshot,
        kv::stream_id_mapping::ser_key(stream_id),
        |entry| Ok((kv::stream_id_mapping::deser_value(entry.value)?, entry.seq)),
    )
    .await?
    else {
        return Ok(false);
    };
    let Some(meta) = db_snapshot_get_with(
        snapshot,
        kv::stream_meta::ser_key(&basin, &stream),
        |entry| kv::stream_meta::deser_value(entry.value),
    )
    .await?
    else {
        return Ok(false);
    };
    if meta.deleted_at.is_some() || meta.config.delete_on_empty.min_age().is_none() {
        return Ok(false);
    }
    let state_seq = db_snapshot_get_with(
        snapshot,
        kv::stream_doe_state::ser_key(stream_id),
        |entry| {
            kv::stream_doe_state::deser_value(entry.value)?;
            Ok(entry.seq)
        },
    )
    .await?;
    Ok(state_seq.is_none_or(|seq| seq < creation_seq))
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use bytesize::ByteSize;
    use s2_common::{
        config::{
            DeleteOnEmptyReconfiguration, OptionalStreamConfig, RetentionPolicy,
            StreamReconfiguration,
        },
        maybe::Maybe,
        record::{CommandRecord, MeteredExt as _, Record},
        resources::ProvisionMode,
        stream::{AppendInput, AppendRecord, AppendRecordParts},
    };
    use slatedb::object_store::memory::InMemory;

    use super::*;
    use crate::backend::{
        bgtasks::tests::test_backend,
        test_util::{DbWriteTestExt as _, create_stream},
    };

    fn config(min_age: u64, retention: RetentionPolicy) -> OptionalStreamConfig {
        let mut config = OptionalStreamConfig {
            retention_policy: Some(retention),
            ..Default::default()
        };
        config.delete_on_empty.min_age = Some(Duration::from_secs(min_age));
        config
    }

    async fn state(
        backend: &Backend,
        stream_id: StreamId,
    ) -> Option<(kv::stream_doe_state::State, u64)> {
        backend
            .db_get_with(kv::stream_doe_state::ser_key(stream_id), |entry| {
                Ok((kv::stream_doe_state::deser_value(entry.value)?, entry.seq))
            })
            .await
            .unwrap()
    }

    async fn scheduled(backend: &Backend, stream_id: StreamId) -> kv::stream_doe_state::Check {
        let Some((kv::stream_doe_state::State::Scheduled(check), _)) =
            state(backend, stream_id).await
        else {
            panic!("expected a scheduled check");
        };
        let checks = backend
            .list_pending_stream_doe(kv::timestamp::TimestampSecs::MAX)
            .await
            .unwrap();
        assert_eq!(checks.values.len(), 1);
        assert_eq!(checks.values[0].stream_id, stream_id);
        assert_eq!(checks.values[0].check, check);
        check
    }

    async fn due(backend: &Backend, stream_id: StreamId) -> PendingCheck {
        let txn = backend
            .db
            .begin(IsolationLevel::SerializableSnapshot)
            .await
            .unwrap();
        doe::schedule(&txn, stream_id, kv::timestamp::TimestampSecs::ZERO)
            .await
            .unwrap();
        db_txn_commit_durable(txn).await.unwrap();
        PendingCheck {
            stream_id,
            check: scheduled(backend, stream_id).await,
        }
    }

    async fn append(backend: &Backend, basin: &BasinName, stream: &StreamName, record: Record) {
        let record: AppendRecord = AppendRecordParts {
            timestamp: None,
            record: record.metered(),
        }
        .try_into()
        .unwrap();
        backend
            .open_for_append(basin, stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .append(AppendInput {
                records: vec![record].try_into().unwrap(),
                match_seq_num: None,
                fencing_token: None,
            })
            .await
            .unwrap();
    }

    fn record() -> Record {
        Record::try_from_parts(vec![], Bytes::from_static(b"live")).unwrap()
    }

    async fn configure_min_age(
        backend: &Backend,
        basin: &BasinName,
        stream: &StreamName,
        min_age: u64,
        via_ensure: bool,
    ) {
        let min_age = Duration::from_secs(min_age);
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

    async fn configure_retention(
        backend: &Backend,
        basin: &BasinName,
        stream: &StreamName,
        age: u64,
    ) {
        backend
            .reconfigure_stream(
                basin.clone(),
                stream.clone(),
                StreamReconfiguration {
                    retention_policy: Maybe::from(Some(RetentionPolicy::Age(Duration::from_secs(
                        age,
                    )))),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    async fn legacy(backend: &Backend, stream_id: StreamId, id: Option<u128>) -> Bytes {
        let key =
            kv::stream_doe_deadline::ser_key(kv::timestamp::TimestampSecs::MAX, stream_id, id);
        // Migration must not interpret the old min_age, even for future keys.
        backend.db.put(&key, [0xff]).assert_durable().await;
        key
    }

    #[tokio::test]
    async fn creation_schedules_once_and_appends_do_not_write_schedules() {
        let backend = test_backend().await;
        let before = kv::timestamp::TimestampSecs::after(Duration::from_secs(60));
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        let check = scheduled(&backend, stream_id).await;
        assert!(check.at >= before);
        assert!(check.at <= kv::timestamp::TimestampSecs::after(Duration::from_secs(60)));
        assert!(
            backend
                .list_pending_stream_doe(kv::timestamp::TimestampSecs::now())
                .await
                .unwrap()
                .values
                .is_empty()
        );
        let original = state(&backend, stream_id).await;
        for _ in 0..3 {
            append(&backend, &basin, &stream, record()).await;
        }
        assert_eq!(state(&backend, stream_id).await, original);
        assert_eq!(scheduled(&backend, stream_id).await, check);
        let mut old = backend
            .db
            .scan(kv::key_type_range(kv::KeyType::StreamDeleteOnEmptyDeadline))
            .await
            .unwrap();
        assert!(old.next().await.unwrap().is_none());
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[case::increase(3600, true)]
    #[case::decrease(10, false)]
    #[tokio::test]
    async fn retry_uses_record_expiration_across_retention_changes(
        #[case] new_age: u64,
        #[case] append_after: bool,
    ) {
        let backend = test_backend().await;
        let initial_age = if append_after { 10 } else { 3600 };
        let (basin, stream) = create_stream(
            &backend,
            config(60, RetentionPolicy::Age(Duration::from_secs(initial_age))),
        )
        .await;
        let stream_id = StreamId::new(&basin, &stream);
        let lower_bound = kv::timestamp::TimestampSecs::after(Duration::from_secs(3600));
        append(&backend, &basin, &stream, record()).await;
        let original = state(&backend, stream_id).await;
        configure_retention(&backend, &basin, &stream, new_age).await;
        if append_after {
            append(&backend, &basin, &stream, record()).await;
        }
        assert_eq!(state(&backend, stream_id).await, original);
        let pending = due(&backend, stream_id).await;
        backend.process_stream_doe(pending).await.unwrap();
        let replacement = scheduled(&backend, stream_id).await;
        assert_ne!(replacement.id, pending.check.id);
        assert!(
            replacement.at >= lower_bound,
            "must preserve a check for the actual stored expiration"
        );
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[case::never_written(false)]
    #[case::expired_records(true)]
    #[tokio::test]
    async fn empty_old_stream_is_deleted(#[case] written: bool) {
        let backend = test_backend().await;
        let (basin, stream) = create_stream(
            &backend,
            config(1, RetentionPolicy::Age(Duration::from_secs(1))),
        )
        .await;
        let stream_id = StreamId::new(&basin, &stream);
        if written {
            append(&backend, &basin, &stream, record()).await;
        }
        tokio::time::sleep(Duration::from_millis(1100)).await;
        backend.clone().tick_stream_doe().await.unwrap();
        let meta = backend
            .db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(meta.deleted_at.is_some());
        assert!(state(&backend, stream_id).await.is_none());
        assert!(
            backend
                .list_pending_stream_doe(kv::timestamp::TimestampSecs::MAX)
                .await
                .unwrap()
                .values
                .is_empty()
        );
        backend.clone().tick_stream_trim().await.unwrap();
        assert!(
            backend
                .db_get(
                    kv::stream_id_mapping::ser_key(stream_id),
                    kv::stream_id_mapping::deser_value
                )
                .await
                .unwrap()
                .is_none()
        );
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[case::increase(3600)]
    #[case::decrease(30)]
    #[case::unchanged(60)]
    #[case::disable(0)]
    #[tokio::test]
    async fn configuration_coalesces_or_removes_the_schedule(
        #[case] age: u64,
        #[values(false, true)] via_ensure: bool,
    ) {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        let original = state(&backend, stream_id).await;
        configure_min_age(&backend, &basin, &stream, age, via_ensure).await;
        if age == 0 {
            assert!(state(&backend, stream_id).await.is_none());
            assert!(
                backend
                    .list_pending_stream_doe(kv::timestamp::TimestampSecs::MAX)
                    .await
                    .unwrap()
                    .values
                    .is_empty()
            );
            configure_min_age(&backend, &basin, &stream, 60, via_ensure).await;
            assert!(scheduled(&backend, stream_id).await.at <= kv::timestamp::TimestampSecs::now());
        } else if age == 60 {
            assert_eq!(state(&backend, stream_id).await, original);
        } else {
            assert!(scheduled(&backend, stream_id).await.at <= kv::timestamp::TimestampSecs::now());
            backend.clone().tick_stream_doe().await.unwrap();
            assert!(
                scheduled(&backend, stream_id).await.at
                    >= kv::timestamp::TimestampSecs::now()
                        .saturating_add_duration(Duration::from_secs(age.saturating_sub(1)))
            );
            assert!(backend.get_stream_config(basin, stream).await.is_ok());
        }
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn partial_trim_wakes_parked_stream_with_finite_records_remaining() {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        append(&backend, &basin, &stream, record()).await;
        backend
            .process_stream_doe(due(&backend, stream_id).await)
            .await
            .unwrap();
        let parked = state(&backend, stream_id).await;
        assert!(matches!(
            parked,
            Some((kv::stream_doe_state::State::Parked, _))
        ));
        assert!(
            backend
                .list_pending_stream_doe(kv::timestamp::TimestampSecs::MAX)
                .await
                .unwrap()
                .values
                .is_empty()
        );
        configure_retention(&backend, &basin, &stream, 3600).await;
        append(&backend, &basin, &stream, record()).await;
        assert_eq!(state(&backend, stream_id).await, parked);
        append(
            &backend,
            &basin,
            &stream,
            Record::Command(CommandRecord::Trim(1)),
        )
        .await;
        backend.clone().tick_stream_trim().await.unwrap();
        assert!(scheduled(&backend, stream_id).await.at <= kv::timestamp::TimestampSecs::now());
        backend.clone().tick_stream_doe().await.unwrap();
        assert!(
            scheduled(&backend, stream_id).await.at
                > kv::timestamp::TimestampSecs::after(Duration::from_secs(3500))
        );
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[case::disabled(0, false)]
    #[case::disabled_before_cleanup(60, false)]
    #[case::legacy_only(60, true)]
    #[tokio::test]
    async fn trim_initializes_missing_state_only_for_enabled_empty_streams(
        #[case] min_age: u64,
        #[case] legacy_only: bool,
        #[values(false, true)] full_trim: bool,
    ) {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(min_age, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        append(&backend, &basin, &stream, record()).await;
        append(
            &backend,
            &basin,
            &stream,
            Record::Command(CommandRecord::Trim(if full_trim { u64::MAX } else { 1 })),
        )
        .await;
        if legacy_only {
            // Model an enabled stream that has not migrated yet.
            let txn = backend
                .db
                .begin(IsolationLevel::SerializableSnapshot)
                .await
                .unwrap();
            doe::clear(&txn, stream_id).await.unwrap();
            db_txn_commit_durable(txn).await.unwrap();
            legacy(&backend, stream_id, None).await;
        } else if min_age != 0 {
            configure_min_age(&backend, &basin, &stream, 0, false).await;
        }
        assert!(state(&backend, stream_id).await.is_none());

        backend.clone().tick_stream_trim().await.unwrap();
        let after_trim = state(&backend, stream_id).await;
        if legacy_only && full_trim {
            assert!(scheduled(&backend, stream_id).await.at <= kv::timestamp::TimestampSecs::now());
        } else {
            assert!(after_trim.is_none());
            assert!(
                backend
                    .list_pending_stream_doe(kv::timestamp::TimestampSecs::MAX)
                    .await
                    .unwrap()
                    .values
                    .is_empty()
            );
        }

        // Migration preserves a full trim's wake or initializes missing state.
        if legacy_only {
            backend.migrate_stream_doe().await.unwrap();
            if full_trim {
                assert_eq!(state(&backend, stream_id).await, after_trim);
            }
        } else {
            configure_min_age(&backend, &basin, &stream, 60, false).await;
        }
        assert!(scheduled(&backend, stream_id).await.at <= kv::timestamp::TimestampSecs::now());
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn full_trim_restores_doe_without_any_legacy_deadline() {
        let backend = test_backend().await;
        let (basin, stream) = create_stream(&backend, config(1, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        append(&backend, &basin, &stream, record()).await;
        // Before upgrade, an infinite-retention stream normally loses its last
        // deadline when it fires while the stream is nonempty.
        let txn = backend
            .db
            .begin(IsolationLevel::SerializableSnapshot)
            .await
            .unwrap();
        doe::clear(&txn, stream_id).await.unwrap();
        db_txn_commit_durable(txn).await.unwrap();
        backend.migrate_stream_doe().await.unwrap();
        assert!(state(&backend, stream_id).await.is_none());

        append(
            &backend,
            &basin,
            &stream,
            Record::Command(CommandRecord::Trim(u64::MAX)),
        )
        .await;
        backend.clone().tick_stream_trim().await.unwrap();
        assert!(scheduled(&backend, stream_id).await.at <= kv::timestamp::TimestampSecs::now());
        tokio::time::sleep(Duration::from_millis(1100)).await;
        backend.clone().tick_stream_doe().await.unwrap();
        let meta = backend
            .db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(meta.deleted_at.is_some());
        assert!(state(&backend, stream_id).await.is_none());
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn trim_wake_conflicts_with_concurrent_disablement(
        #[values(false, true)] missing_state: bool,
    ) {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        if missing_state {
            let txn = backend
                .db
                .begin(IsolationLevel::SerializableSnapshot)
                .await
                .unwrap();
            doe::clear(&txn, stream_id).await.unwrap();
            db_txn_commit_durable(txn).await.unwrap();
        }
        let txn = backend
            .db
            .begin(IsolationLevel::SerializableSnapshot)
            .await
            .unwrap();
        doe::wake_after_trim(&txn, stream_id, false).await.unwrap();
        configure_min_age(&backend, &basin, &stream, 0, false).await;
        let error = StorageError::from(txn.commit().await.unwrap_err());
        assert!(error.is_transaction_conflict());
        assert!(state(&backend, stream_id).await.is_none());
        assert!(
            backend
                .list_pending_stream_doe(kv::timestamp::TimestampSecs::MAX)
                .await
                .unwrap()
                .values
                .is_empty()
        );
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn event_retaining_same_ticket_invalidates_inflight_result(
        #[values(false, true)] trim: bool,
        #[values(false, true)] park: bool,
    ) {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        append(&backend, &basin, &stream, record()).await;
        if trim {
            configure_retention(&backend, &basin, &stream, 3600).await;
        }
        let pending = due(&backend, stream_id).await;
        let snapshot = backend.observe_doe_check(pending).await.unwrap().unwrap();
        if trim {
            // The worker may already have observed the infinite-retention
            // record and decided to park. Subsequent appends do not invalidate
            // that observation, but removing the blocker must invalidate it.
            append(&backend, &basin, &stream, record()).await;
            append(
                &backend,
                &basin,
                &stream,
                Record::Command(CommandRecord::Trim(1)),
            )
            .await;
            backend.clone().tick_stream_trim().await.unwrap();
        } else {
            configure_min_age(&backend, &basin, &stream, 120, false).await;
        }
        assert_eq!(scheduled(&backend, stream_id).await, pending.check);
        let woken = state(&backend, stream_id).await;
        assert!(woken.unwrap().1 > snapshot.revision);
        let outcome = if park {
            TerminalTrimOutcome::Parked
        } else {
            TerminalTrimOutcome::RetryAt(kv::timestamp::TimestampSecs::MAX)
        };
        backend
            .finish_doe_check(pending, snapshot, outcome)
            .await
            .unwrap();
        assert_eq!(state(&backend, stream_id).await, woken);
        assert_eq!(scheduled(&backend, stream_id).await, pending.check);
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn obsolete_check_cleanup_preserves_wake_after_snapshot() {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        let pending = due(&backend, stream_id).await;
        let observed = state(&backend, stream_id).await;
        configure_min_age(&backend, &basin, &stream, 120, false).await;
        let woken = state(&backend, stream_id).await;
        assert!(woken.unwrap().1 > observed.unwrap().1);
        assert_eq!(scheduled(&backend, stream_id).await, pending.check);
        backend.discard_doe_check(pending, observed).await.unwrap();
        assert_eq!(state(&backend, stream_id).await, woken);
        assert_eq!(scheduled(&backend, stream_id).await, pending.check);
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn observation_discards_deleted_stream_schedule() {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        let pending = due(&backend, stream_id).await;
        backend.delete_stream(basin, stream).await.unwrap();
        assert!(state(&backend, stream_id).await.is_some());
        assert!(backend.observe_doe_check(pending).await.unwrap().is_none());
        assert!(state(&backend, stream_id).await.is_none());
        assert!(
            backend
                .list_pending_stream_doe(kv::timestamp::TimestampSecs::MAX)
                .await
                .unwrap()
                .values
                .is_empty()
        );
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn legacy_deadlines_only_initialize_missing_state() {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        let txn = backend
            .db
            .begin(IsolationLevel::SerializableSnapshot)
            .await
            .unwrap();
        doe::clear(&txn, stream_id).await.unwrap();
        db_txn_commit_durable(txn).await.unwrap();
        let old = legacy(&backend, stream_id, None).await;
        let unique = legacy(&backend, stream_id, Some(42)).await;
        backend.migrate_stream_doe().await.unwrap();
        assert!(scheduled(&backend, stream_id).await.at <= kv::timestamp::TimestampSecs::now());
        assert!(backend.db.get(&old).await.unwrap().is_none());
        assert!(backend.db.get(&unique).await.unwrap().is_none());
        let initialized = state(&backend, stream_id).await;
        backend
            .initialize_doe_from_deadlines(stream_id, vec![old, unique])
            .await
            .unwrap();
        assert_eq!(state(&backend, stream_id).await, initialized);
        append(&backend, &basin, &stream, record()).await;
        backend.clone().tick_stream_doe().await.unwrap();
        let parked = state(&backend, stream_id).await;
        assert!(matches!(
            parked,
            Some((kv::stream_doe_state::State::Parked, _))
        ));
        legacy(&backend, stream_id, Some(43)).await;
        backend.migrate_stream_doe().await.unwrap();
        assert_eq!(state(&backend, stream_id).await, parked);
        assert!(
            backend
                .list_pending_stream_doe(kv::timestamp::TimestampSecs::MAX)
                .await
                .unwrap()
                .values
                .is_empty()
        );
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn migration_pages_do_not_duplicate_schedules() {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        let before = state(&backend, stream_id).await;
        let mut batch = slatedb::WriteBatch::new();
        for id in 0..=PENDING_LIST_LIMIT {
            batch.put(
                kv::stream_doe_deadline::ser_key(
                    kv::timestamp::TimestampSecs::MAX,
                    stream_id,
                    Some(id as u128),
                ),
                [],
            );
        }
        backend.db.write(batch).assert_durable().await;
        assert!(
            backend
                .migrate_stream_doe()
                .await
                .unwrap()
                .should_continue()
        );
        assert!(
            !backend
                .migrate_stream_doe()
                .await
                .unwrap()
                .should_continue()
        );
        assert_eq!(state(&backend, stream_id).await, before);
        scheduled(&backend, stream_id).await;
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn migration_batches_cleanup_across_streams() {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let scheduled_id = StreamId::new(&basin, &stream);
        let before = state(&backend, scheduled_id).await;
        let disabled: StreamName = "disabled".parse().unwrap();
        let deleted: StreamName = "deleted".parse().unwrap();
        for (stream, min_age) in [(&disabled, 0), (&deleted, 60)] {
            backend
                .provision_stream(
                    basin.clone(),
                    stream.clone(),
                    config(min_age, RetentionPolicy::Infinite()),
                    ProvisionMode::Ensure,
                )
                .await
                .unwrap();
        }
        backend
            .delete_stream(basin.clone(), deleted.clone())
            .await
            .unwrap();
        let disabled_id = StreamId::new(&basin, &disabled);
        let deleted_id = StreamId::new(&basin, &deleted);
        let deleted_state = state(&backend, deleted_id).await;
        let mut keys = Vec::new();
        for stream_id in [scheduled_id, disabled_id, deleted_id] {
            for id in 0..3 {
                keys.push(legacy(&backend, stream_id, Some(id)).await);
            }
        }
        let before_seq = backend.db.snapshot().await.unwrap().seq();
        backend.migrate_stream_doe().await.unwrap();
        assert_eq!(
            backend.db.snapshot().await.unwrap().seq(),
            before_seq + 1,
            "all cleanup-only streams should share one durable batch"
        );
        for key in keys {
            assert!(backend.db.get(key).await.unwrap().is_none());
        }
        assert_eq!(state(&backend, scheduled_id).await, before);
        assert_eq!(state(&backend, deleted_id).await, deleted_state);
        assert!(state(&backend, disabled_id).await.is_none());
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn migration_revalidates_configuration_after_snapshot(#[values(0, 120)] min_age: u64) {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        let txn = backend
            .db
            .begin(IsolationLevel::SerializableSnapshot)
            .await
            .unwrap();
        doe::clear(&txn, stream_id).await.unwrap();
        db_txn_commit_durable(txn).await.unwrap();
        let key = legacy(&backend, stream_id, None).await;
        let snapshot = backend.db.snapshot().await.unwrap();
        assert!(needs_doe_migration(&snapshot, stream_id).await.unwrap());
        configure_min_age(&backend, &basin, &stream, min_age, false).await;
        let configured = state(&backend, stream_id).await;
        backend
            .initialize_doe_from_deadlines(stream_id, vec![key.clone()])
            .await
            .unwrap();
        assert_eq!(state(&backend, stream_id).await, configured);
        assert!(backend.db.get(key).await.unwrap().is_none());
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn batched_legacy_cleanup_preserves_later_enablement_or_recreation(
        #[values(false, true)] recreate: bool,
    ) {
        let backend = test_backend().await;
        let (basin, stream) = create_stream(
            &backend,
            config(if recreate { 60 } else { 0 }, RetentionPolicy::Infinite()),
        )
        .await;
        let stream_id = StreamId::new(&basin, &stream);
        let key = legacy(&backend, stream_id, None).await;
        let snapshot = backend.db.snapshot().await.unwrap();
        let cleanup = backend
            .migrate_doe_deadlines(&snapshot, stream_id, vec![key.clone()])
            .await
            .unwrap();
        assert_eq!(cleanup, vec![key.clone()]);
        drop(snapshot);

        // Pause after classification, before the page's cleanup batch commits.
        if recreate {
            backend
                .delete_stream(basin.clone(), stream.clone())
                .await
                .unwrap();
            backend.clone().tick_stream_trim().await.unwrap();
            backend
                .provision_stream(
                    basin.clone(),
                    stream.clone(),
                    config(60, RetentionPolicy::Infinite()),
                    ProvisionMode::Ensure,
                )
                .await
                .unwrap();
        } else {
            configure_min_age(&backend, &basin, &stream, 60, false).await;
        }
        let before = state(&backend, stream_id).await;
        let mut batch = WriteBatch::new();
        for key in cleanup {
            batch.delete(key);
        }
        backend.db.write(batch).assert_durable().await;
        assert!(backend.db.get(key).await.unwrap().is_none());
        assert_eq!(state(&backend, stream_id).await, before);
        scheduled(&backend, stream_id).await;
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_wake_conflicts_with_completion_transaction() {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        let pending = due(&backend, stream_id).await;
        let txn = backend
            .db
            .begin(IsolationLevel::SerializableSnapshot)
            .await
            .unwrap();
        let previous = doe::state(&txn, stream_id).await.unwrap();
        doe::replace(
            &txn,
            stream_id,
            previous,
            Some(kv::stream_doe_state::State::Parked),
        )
        .unwrap();
        // The same ticket is retained, but the scheduler revision changes.
        let wake = backend
            .db
            .begin(IsolationLevel::SerializableSnapshot)
            .await
            .unwrap();
        doe::schedule(&wake, stream_id, kv::timestamp::TimestampSecs::now())
            .await
            .unwrap();
        db_txn_commit_durable(wake).await.unwrap();
        let error = txn.commit().await.unwrap_err();
        assert_eq!(error.kind(), slatedb::ErrorKind::Transaction);
        let error = StorageError::from(error);
        assert!(error.is_transaction_conflict());
        assert!(StreamDeleteOnEmptyError::Storage(error.clone()).is_transaction_conflict());
        assert!(
            StreamDeleteOnEmptyError::DeleteStream(DeleteStreamError::Storage(error.clone()))
                .is_transaction_conflict()
        );
        // Scheduling adds transactional reads to configuration commits, but
        // conflicts must retain the API's retryable 409 classification.
        assert!(matches!(
            crate::backend::error::ProvisionStreamError::from(error.clone()),
            crate::backend::error::ProvisionStreamError::TransactionConflict(_)
        ));
        assert!(matches!(
            crate::backend::error::ReconfigureStreamError::from(error),
            crate::backend::error::ReconfigureStreamError::TransactionConflict(_)
        ));
        assert_eq!(scheduled(&backend, stream_id).await, pending.check);
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn full_trim_wakes_parked_stream_and_waits_for_minimum_age() {
        let backend = test_backend().await;
        let (basin, stream) =
            create_stream(&backend, config(60, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        append(&backend, &basin, &stream, record()).await;
        backend
            .process_stream_doe(due(&backend, stream_id).await)
            .await
            .unwrap();
        assert!(matches!(
            state(&backend, stream_id).await,
            Some((kv::stream_doe_state::State::Parked, _))
        ));
        append(
            &backend,
            &basin,
            &stream,
            Record::Command(CommandRecord::Trim(u64::MAX)),
        )
        .await;
        backend.clone().tick_stream_trim().await.unwrap();
        assert!(scheduled(&backend, stream_id).await.at <= kv::timestamp::TimestampSecs::now());
        backend.clone().tick_stream_doe().await.unwrap();
        assert!(scheduled(&backend, stream_id).await.at > kv::timestamp::TimestampSecs::now());
        let meta = backend
            .db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(meta.deleted_at.is_none());
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn migration_does_not_schedule_disabled_or_deleted_streams(
        #[values(false, true)] deleted: bool,
    ) {
        let backend = test_backend().await;
        let (basin, stream) = create_stream(&backend, config(0, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        if deleted {
            backend.delete_stream(basin, stream).await.unwrap();
            backend.clone().tick_stream_trim().await.unwrap();
        }
        let old = legacy(&backend, stream_id, None).await;
        backend.migrate_stream_doe().await.unwrap();
        assert!(backend.db.get(&old).await.unwrap().is_none());
        assert!(state(&backend, stream_id).await.is_none());
        assert!(
            backend
                .list_pending_stream_doe(kv::timestamp::TimestampSecs::MAX)
                .await
                .unwrap()
                .values
                .is_empty()
        );
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn stale_work_cannot_delete_or_reschedule_recreated_stream(
        #[values(false, true)] deletion_pending: bool,
    ) {
        let backend = test_backend().await;
        let configuration = config(60, RetentionPolicy::Infinite());
        let (basin, stream) = create_stream(&backend, configuration.clone()).await;
        let stream_id = StreamId::new(&basin, &stream);
        let pending = due(&backend, stream_id).await;
        let snapshot = backend.observe_doe_check(pending).await.unwrap().unwrap();
        backend
            .delete_stream(basin.clone(), stream.clone())
            .await
            .unwrap();
        backend.clone().tick_stream_trim().await.unwrap();
        backend
            .provision_stream(
                basin.clone(),
                stream.clone(),
                configuration,
                ProvisionMode::Ensure,
            )
            .await
            .unwrap();
        let recreated = state(&backend, stream_id).await;
        let client = backend
            .streamer_client_guarded(&basin, &stream)
            .await
            .unwrap();
        assert_eq!(
            client
                .terminal_trim(TerminalTrimCondition::DeleteOnEmpty {
                    expected_stream_creation_seq: snapshot.creation_seq,
                    expected_config_seq: snapshot.config_seq,
                })
                .await
                .unwrap(),
            TerminalTrimOutcome::Obsolete
        );
        let outcome = if deletion_pending {
            TerminalTrimOutcome::DeletionPending
        } else {
            TerminalTrimOutcome::Parked
        };
        backend
            .finish_doe_check(pending, snapshot, outcome)
            .await
            .unwrap();
        backend.process_stream_doe(pending).await.unwrap();
        legacy(&backend, stream_id, None).await;
        backend.migrate_stream_doe().await.unwrap();
        assert_eq!(state(&backend, stream_id).await, recreated);
        scheduled(&backend, stream_id).await;
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn replacement_and_parked_state_survive_database_reopen() {
        let store = Arc::new(InMemory::new());
        let db = slatedb::Db::builder("/restart", store.clone())
            .build()
            .await
            .unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));
        let (basin, stream) =
            create_stream(&backend, config(3600, RetentionPolicy::Infinite())).await;
        let stream_id = StreamId::new(&basin, &stream);
        backend
            .process_stream_doe(due(&backend, stream_id).await)
            .await
            .unwrap();
        let before = state(&backend, stream_id).await;
        backend.close().await.unwrap();
        let db = slatedb::Db::builder("/restart", store.clone())
            .build()
            .await
            .unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));
        assert_eq!(state(&backend, stream_id).await, before);
        scheduled(&backend, stream_id).await;
        append(&backend, &basin, &stream, record()).await;
        backend
            .process_stream_doe(due(&backend, stream_id).await)
            .await
            .unwrap();
        let before = state(&backend, stream_id).await;
        assert!(matches!(
            before,
            Some((kv::stream_doe_state::State::Parked, _))
        ));
        backend.close().await.unwrap();
        let db = slatedb::Db::builder("/restart", store)
            .build()
            .await
            .unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));
        assert_eq!(state(&backend, stream_id).await, before);
        assert!(
            backend
                .list_pending_stream_doe(kv::timestamp::TimestampSecs::MAX)
                .await
                .unwrap()
                .values
                .is_empty()
        );
        backend.close().await.unwrap();
    }
}
