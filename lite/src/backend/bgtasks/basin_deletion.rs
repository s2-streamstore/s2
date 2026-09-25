use futures::{StreamExt, stream};
use s2_common::{
    basin::BasinName,
    resources::{ListLimit, Page},
    stream::{ListStreamsRequest, StreamNamePrefix, StreamNameStartAfter},
};
use slatedb::{
    WriteBatch,
    config::{DurabilityLevel, ScanOptions},
};
use tracing::instrument;

use crate::backend::{
    Backend,
    error::{BasinDeletionError, ListStreamsError, StorageError},
    kv,
};

const PENDING_LIST_LIMIT: usize = 32;
const CONCURRENCY: usize = 4;

/// Per-basin outcome of a deletion tick. Unlike a single `bool`, this
/// distinguishes forward progress from a basin blocked waiting for
/// `stream_trim` to purge its tombstoned `stream_meta` rows, so a full
/// pending page that makes no progress yields to the scheduler instead of
/// tight-looping — mirroring the `PageProgress` contract used by the sibling
/// bgtasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BasinProgress {
    /// The stream cursor advanced past a full stream page; re-scan
    /// immediately to keep draining this basin's remaining streams.
    Advanced,
    /// The basin had no remaining streams and was fully removed.
    Completed,
    /// Tombstoned stream metadata still exists; the basin waits for
    /// `stream_trim` to purge it before it can complete.
    Blocked,
}

impl Backend {
    pub(super) async fn tick_basin_deletion(self) -> Result<bool, BasinDeletionError> {
        let page = self.list_basin_deletion_pending().await?;
        if page.values.is_empty() {
            return Ok(page.has_more);
        }
        let mut processed = stream::iter(page.values)
            .map(|(basin, cursor)| {
                let backend = self.clone();
                async move { backend.process_basin_deletion(basin, cursor).await }
            })
            .buffer_unordered(CONCURRENCY);
        let mut any_succeeded = false;
        let mut any_advanced = false;
        while let Some(result) = processed.next().await {
            let progress = result?;
            any_succeeded |= progress != BasinProgress::Blocked;
            any_advanced |= progress == BasinProgress::Advanced;
        }
        // Keep draining only when the page made progress: a full page where
        // every basin is blocked yields to the scheduler instead of retrying
        // in a tight loop. A basin whose stream cursor advanced re-ticks
        // immediately regardless of `page.has_more` so its remaining streams
        // drain without waiting for the next timer interval.
        Ok(any_advanced || (page.has_more && any_succeeded))
    }

    async fn list_basin_deletion_pending(
        &self,
    ) -> Result<Page<(BasinName, StreamNameStartAfter)>, StorageError> {
        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = self
            .db
            .scan_with_options(
                kv::key_type_range(kv::KeyType::BasinDeletionPending),
                &scan_opts,
            )
            .await?;
        let mut pending = Vec::new();
        while let Some(kv) = it.next().await? {
            let basin = kv::basin_deletion_pending::deser_key(kv.key)?;
            let cursor = kv::basin_deletion_pending::deser_value(kv.value)?;
            pending.push((basin, cursor));
            if pending.len() >= PENDING_LIST_LIMIT {
                return Ok(Page::new(pending, true));
            }
        }
        Ok(Page::new(pending, false))
    }

    async fn process_basin_deletion(
        &self,
        basin: BasinName,
        cursor: StreamNameStartAfter,
    ) -> Result<BasinProgress, BasinDeletionError> {
        let request = ListStreamsRequest {
            prefix: StreamNamePrefix::default(),
            start_after: cursor.clone(),
            limit: ListLimit::MAX,
        };
        let page = self
            .list_streams(basin.clone(), request)
            .await
            .map_err(|err| match err {
                ListStreamsError::Storage(error) => error,
            })?;

        let mut last_stream = None;
        for info in page.values {
            let stream = info.name;
            last_stream = Some(StreamNameStartAfter::from(stream.clone()));
            if info.deleted_at.is_some() {
                continue;
            }
            self.delete_stream(basin.clone(), stream.clone()).await?;
        }

        if page.has_more {
            self.set_basin_deletion_cursor(&basin, &last_stream.expect("non-empty stream page"))
                .await?;
            Ok(BasinProgress::Advanced)
        } else if last_stream.is_some() || !cursor.as_ref().is_empty() {
            // Streams still pending deletion or cursor was advanced past
            // earlier entries. Reset cursor so the next tick re-scans from
            // the beginning.
            if !cursor.as_ref().is_empty() {
                self.set_basin_deletion_cursor(&basin, &StreamNameStartAfter::default())
                    .await?;
            }
            Ok(BasinProgress::Blocked)
        } else {
            // No streams from the very beginning — safe to complete.
            self.complete_basin_deletion(&basin).await?;
            Ok(BasinProgress::Completed)
        }
    }

    #[instrument(ret, err, skip(self))]
    async fn set_basin_deletion_cursor(
        &self,
        basin: &BasinName,
        cursor: &StreamNameStartAfter,
    ) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();
        batch.put(
            kv::basin_deletion_pending::ser_key(basin),
            kv::basin_deletion_pending::ser_value(cursor),
        );
        self.db.write(batch).await?.await_durable().await?;
        Ok(())
    }

    #[instrument(ret, err, skip(self))]
    async fn complete_basin_deletion(&self, basin: &BasinName) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();
        batch.delete(kv::basin_meta::ser_key(basin));
        batch.delete(kv::basin_deletion_pending::ser_key(basin));
        self.db.write(batch).await?.await_durable().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use s2_common::{
        basin::BasinName,
        config::{BasinConfig, StreamConfig},
        resources::ListLimit,
        stream::{StreamName, StreamNameStartAfter},
    };
    use time::OffsetDateTime;

    use super::super::tests::test_backend;
    use crate::backend::{Backend, kv, test_util::DbWriteTestExt as _};

    fn basin_meta(deleted_at: Option<OffsetDateTime>) -> kv::basin_meta::BasinMeta {
        kv::basin_meta::BasinMeta {
            config: BasinConfig::default(),
            created_at: OffsetDateTime::now_utc(),
            deleted_at,
            creation_idempotency_key: None,
        }
    }

    fn stream_meta(deleted_at: Option<OffsetDateTime>) -> kv::stream_meta::StreamMeta {
        kv::stream_meta::StreamMeta {
            config: StreamConfig::default(),
            cipher: None,
            created_at: OffsetDateTime::now_utc(),
            deleted_at,
            creation_idempotency_key: None,
        }
    }

    fn stream_name_for_index(index: usize) -> StreamName {
        StreamName::from_str(&format!("stream-{index:04}")).unwrap()
    }

    fn expected_page_cursor(limit: usize) -> StreamNameStartAfter {
        StreamNameStartAfter::from(stream_name_for_index(limit.saturating_sub(1)))
    }

    async fn seed_basin_for_deletion(backend: &Backend, basin: &BasinName) {
        backend
            .db
            .put(
                kv::basin_meta::ser_key(basin),
                kv::basin_meta::ser_value(&basin_meta(Some(OffsetDateTime::now_utc()))),
            )
            .assert_durable()
            .await;
        backend
            .db
            .put(
                kv::basin_deletion_pending::ser_key(basin),
                kv::basin_deletion_pending::ser_value(&StreamNameStartAfter::default()),
            )
            .assert_durable()
            .await;
    }

    async fn seed_tombstoned_streams(backend: &Backend, basin: &BasinName, count: usize) {
        let deleted_at = OffsetDateTime::from_unix_timestamp(1234567890).unwrap();
        let mut batch = slatedb::WriteBatch::new();
        for i in 0..count {
            let stream = stream_name_for_index(i);
            batch.put(
                kv::stream_meta::ser_key(basin, &stream),
                kv::stream_meta::ser_value(&stream_meta(Some(deleted_at))),
            );
        }
        backend.db.write(batch).assert_durable().await;
    }

    #[tokio::test]
    async fn basin_deletion_completes_empty_basin() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("test-basin").unwrap();

        backend
            .db
            .put(
                kv::basin_meta::ser_key(&basin),
                kv::basin_meta::ser_value(&basin_meta(Some(OffsetDateTime::now_utc()))),
            )
            .assert_durable()
            .await;
        backend
            .db
            .put(
                kv::basin_deletion_pending::ser_key(&basin),
                kv::basin_deletion_pending::ser_value(&StreamNameStartAfter::default()),
            )
            .assert_durable()
            .await;

        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more);

        assert!(
            backend
                .db
                .get(kv::basin_meta::ser_key(&basin))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .db
                .get(kv::basin_deletion_pending::ser_key(&basin))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn basin_deletion_tombstones_active_stream() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("test-basin").unwrap();
        let stream = StreamName::from_str("live-stream").unwrap();

        seed_basin_for_deletion(&backend, &basin).await;
        backend
            .db
            .put(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::ser_value(&stream_meta(None)),
            )
            .assert_durable()
            .await;

        backend
            .db
            .put(
                kv::stream_id_mapping::ser_key(crate::stream_id::StreamId::new(&basin, &stream)),
                kv::stream_id_mapping::ser_value(&basin, &stream),
            )
            .assert_durable()
            .await;

        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more);

        let meta = backend
            .db
            .get(kv::stream_meta::ser_key(&basin, &stream))
            .await
            .unwrap()
            .expect("stream meta present");
        let meta = kv::stream_meta::deser_value(meta).unwrap();
        assert!(meta.deleted_at.is_some());
        // Basin deletion is blocked until tombstoned stream metadata is cleaned
        // up by stream_trim.
        assert!(
            backend
                .db
                .get(kv::basin_meta::ser_key(&basin))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            backend
                .db
                .get(kv::basin_deletion_pending::ser_key(&basin))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn basin_deletion_advances_cursor_when_page_has_more() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("test-basin").unwrap();
        let limit = ListLimit::MAX.as_usize();

        seed_basin_for_deletion(&backend, &basin).await;
        seed_tombstoned_streams(&backend, &basin, limit + 1).await;

        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(has_more);

        let pending = backend
            .db
            .get(kv::basin_deletion_pending::ser_key(&basin))
            .await
            .unwrap()
            .expect("pending cursor still exists");
        let cursor = kv::basin_deletion_pending::deser_value(pending).unwrap();
        let expected_cursor = expected_page_cursor(limit);
        assert_eq!(cursor.as_ref(), expected_cursor.as_ref());
        assert!(
            backend
                .db
                .get(kv::basin_meta::ser_key(&basin))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn basin_deletion_aggregates_has_more_across_basins() {
        let backend = test_backend().await;
        let paged_basin = BasinName::from_str("paged-basin").unwrap();
        let empty_basin = BasinName::from_str("empty-basin").unwrap();
        let limit = ListLimit::MAX.as_usize();

        seed_basin_for_deletion(&backend, &paged_basin).await;
        seed_basin_for_deletion(&backend, &empty_basin).await;
        seed_tombstoned_streams(&backend, &paged_basin, limit + 1).await;

        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(has_more);

        assert!(
            backend
                .db
                .get(kv::basin_meta::ser_key(&empty_basin))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .db
                .get(kv::basin_deletion_pending::ser_key(&empty_basin))
                .await
                .unwrap()
                .is_none()
        );
        let pending = backend
            .db
            .get(kv::basin_deletion_pending::ser_key(&paged_basin))
            .await
            .unwrap()
            .expect("paged basin still pending");
        let cursor = kv::basin_deletion_pending::deser_value(pending).unwrap();
        let expected_cursor = expected_page_cursor(limit);
        assert_eq!(cursor.as_ref(), expected_cursor.as_ref());
    }

    #[tokio::test]
    async fn basin_deletion_completes_when_cursor_past_end() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("test-basin").unwrap();
        let cursor = StreamNameStartAfter::from_str("zzz-stream").unwrap();

        backend
            .db
            .put(
                kv::basin_meta::ser_key(&basin),
                kv::basin_meta::ser_value(&basin_meta(Some(OffsetDateTime::now_utc()))),
            )
            .assert_durable()
            .await;
        backend
            .db
            .put(
                kv::basin_deletion_pending::ser_key(&basin),
                kv::basin_deletion_pending::ser_value(&cursor),
            )
            .assert_durable()
            .await;

        // First tick resets cursor from past-end back to the beginning.
        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more);

        // Second tick scans from the beginning, finds no streams, completes.
        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more);

        assert!(
            backend
                .db
                .get(kv::basin_meta::ser_key(&basin))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .db
                .get(kv::basin_deletion_pending::ser_key(&basin))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn basin_deletion_blocked_when_only_tombstones_remain() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("test-basin").unwrap();
        let stream = StreamName::from_str("tombstoned-stream").unwrap();
        let deleted_at = OffsetDateTime::from_unix_timestamp(1234567890).unwrap();

        seed_basin_for_deletion(&backend, &basin).await;
        backend
            .db
            .put(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::ser_value(&stream_meta(Some(deleted_at))),
            )
            .assert_durable()
            .await;

        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more);

        // Basin deletion is blocked while tombstoned stream metadata exists.
        assert!(
            backend
                .db
                .get(kv::basin_meta::ser_key(&basin))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            backend
                .db
                .get(kv::basin_deletion_pending::ser_key(&basin))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn basin_deletion_completes_after_tombstones_cleaned() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("test-basin").unwrap();
        let stream = StreamName::from_str("tombstoned-stream").unwrap();
        let deleted_at = OffsetDateTime::from_unix_timestamp(1234567890).unwrap();

        seed_basin_for_deletion(&backend, &basin).await;
        backend
            .db
            .put(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::ser_value(&stream_meta(Some(deleted_at))),
            )
            .assert_durable()
            .await;

        // First tick: blocked by tombstoned stream.
        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more);
        assert!(
            backend
                .db
                .get(kv::basin_meta::ser_key(&basin))
                .await
                .unwrap()
                .is_some()
        );

        // Simulate stream_trim cleaning up the tombstoned stream metadata.
        backend
            .db
            .delete(kv::stream_meta::ser_key(&basin, &stream))
            .assert_durable()
            .await;

        // Second tick: no streams remain, completes.
        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more);
        assert!(
            backend
                .db
                .get(kv::basin_meta::ser_key(&basin))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .db
                .get(kv::basin_deletion_pending::ser_key(&basin))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn basin_deletion_yields_when_page_full_of_blocked_basins() {
        let backend = test_backend().await;
        let deleted_at = OffsetDateTime::from_unix_timestamp(1234567890).unwrap();
        let total = super::PENDING_LIST_LIMIT;

        // Seed exactly `PENDING_LIST_LIMIT` basins, each blocked by a tombstoned
        // stream that `stream_trim` has not cleaned up yet, in a single batch.
        let mut batch = slatedb::WriteBatch::new();
        for i in 0..total {
            let basin = BasinName::from_str(&format!("basin-{i:02}")).unwrap();
            batch.put(
                kv::basin_meta::ser_key(&basin),
                kv::basin_meta::ser_value(&basin_meta(Some(OffsetDateTime::now_utc()))),
            );
            batch.put(
                kv::basin_deletion_pending::ser_key(&basin),
                kv::basin_deletion_pending::ser_value(&StreamNameStartAfter::default()),
            );
            batch.put(
                kv::stream_meta::ser_key(&basin, &stream_name_for_index(0)),
                kv::stream_meta::ser_value(&stream_meta(Some(deleted_at))),
            );
        }
        backend.db.write(batch).assert_durable().await;

        // No basin can make progress (all blocked waiting for `stream_trim`),
        // yet the page is full so `page.has_more` is true. The tick must yield
        // so the scheduler governs the next attempt rather than busy-looping.
        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more, "tick yields when a full page makes no progress");

        // All 32 basins remain pending — confirming zero progress.
        for i in 0..total {
            let basin = BasinName::from_str(&format!("basin-{i:02}")).unwrap();
            assert!(
                backend
                    .db
                    .get(kv::basin_meta::ser_key(&basin))
                    .await
                    .unwrap()
                    .is_some(),
                "basin {i} still pending after blocked tick"
            );
        }

        // A second tick still yields with zero progress: the tight loop that
        // previously starved the scheduler between `spawn_bgtask` ticks is gone.
        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more, "tick keeps yielding without progress");

        // A single blocked basin (under the page limit) also yields — now
        // consistent with the full-page case.
        let single = test_backend().await;
        let basin = BasinName::from_str("single-basin").unwrap();
        seed_basin_for_deletion(&single, &basin).await;
        single
            .db
            .put(
                kv::stream_meta::ser_key(&basin, &stream_name_for_index(0)),
                kv::stream_meta::ser_value(&stream_meta(Some(deleted_at))),
            )
            .assert_durable()
            .await;
        let has_more = single.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more, "a single blocked basin yields to the timer");
    }

    #[tokio::test]
    async fn basin_deletion_continues_when_full_page_makes_progress() {
        let backend = test_backend().await;
        let deleted_at = OffsetDateTime::from_unix_timestamp(1234567890).unwrap();
        let total = super::PENDING_LIST_LIMIT;

        // 31 blocked basins + 1 empty basin that can complete on this tick,
        // exactly filling the pending page so `page.has_more` is true.
        let mut batch = slatedb::WriteBatch::new();
        for i in 0..(total - 1) {
            let basin = BasinName::from_str(&format!("blocked-{i:02}")).unwrap();
            batch.put(
                kv::basin_meta::ser_key(&basin),
                kv::basin_meta::ser_value(&basin_meta(Some(OffsetDateTime::now_utc()))),
            );
            batch.put(
                kv::basin_deletion_pending::ser_key(&basin),
                kv::basin_deletion_pending::ser_value(&StreamNameStartAfter::default()),
            );
            batch.put(
                kv::stream_meta::ser_key(&basin, &stream_name_for_index(0)),
                kv::stream_meta::ser_value(&stream_meta(Some(deleted_at))),
            );
        }
        let empty_basin = BasinName::from_str("empty-basin").unwrap();
        batch.put(
            kv::basin_meta::ser_key(&empty_basin),
            kv::basin_meta::ser_value(&basin_meta(Some(OffsetDateTime::now_utc()))),
        );
        batch.put(
            kv::basin_deletion_pending::ser_key(&empty_basin),
            kv::basin_deletion_pending::ser_value(&StreamNameStartAfter::default()),
        );
        backend.db.write(batch).assert_durable().await;

        // Full page (32 basins) with one completion: progress was made, so the
        // tick reports more work to drain basins beyond the first page.
        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(has_more, "tick continues when a full page makes progress");

        // The empty basin completed; the 31 blocked basins remain pending.
        assert!(
            backend
                .db
                .get(kv::basin_meta::ser_key(&empty_basin))
                .await
                .unwrap()
                .is_none(),
            "empty basin completed on a progressing tick"
        );

        // Second tick: 31 blocked basins remain, under the page limit; with no
        // progress the tick yields.
        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(
            !has_more,
            "tick yields once the page is no longer progressing"
        );
    }
}
