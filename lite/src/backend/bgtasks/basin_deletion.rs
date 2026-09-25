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

use super::PageProgress;
use crate::backend::{
    Backend,
    error::{BasinDeletionError, ListStreamsError, StorageError},
    kv,
};

const PENDING_LIST_LIMIT: usize = 32;
const CONCURRENCY: usize = 4;

enum BasinProgress {
    /// More streams remain past the advanced cursor.
    Advanced,
    Completed,
    /// Tombstoned streams await `stream_trim`, or the cursor was reset. A reset is not progress:
    /// counting it would rescan a multi-page basin in a tight loop.
    Blocked,
}

impl Backend {
    pub(super) async fn tick_basin_deletion(self) -> Result<bool, BasinDeletionError> {
        let page = self.list_basin_deletion_pending().await?;
        if page.values.is_empty() {
            return Ok(page.has_more);
        }
        let mut progress = PageProgress {
            has_more: page.has_more,
            ..Default::default()
        };
        let mut processed = stream::iter(page.values)
            .map(|(basin, cursor)| {
                let backend = self.clone();
                async move { backend.process_basin_deletion(basin, cursor).await }
            })
            .buffer_unordered(CONCURRENCY);
        while let Some(result) = processed.next().await {
            match result? {
                BasinProgress::Advanced => {
                    progress.has_more = true;
                    progress.any_succeeded = true;
                }
                BasinProgress::Completed => progress.any_succeeded = true,
                BasinProgress::Blocked => {}
            }
        }
        Ok(progress.should_continue())
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
    async fn basin_deletion_drains_backlog_only_on_progress() {
        let backend = test_backend().await;
        // More basins are pending than fit in one page, and all are blocked.
        let basins: Vec<_> = (0..=super::PENDING_LIST_LIMIT)
            .map(|i| BasinName::from_str(&format!("basin-{i:02}")).unwrap())
            .collect();
        futures::future::join_all(basins.iter().map(|basin| {
            let backend = backend.clone();
            async move {
                seed_basin_for_deletion(&backend, basin).await;
                seed_tombstoned_streams(&backend, basin, 1).await;
            }
        }))
        .await;

        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(!has_more);

        // Simulate stream_trim cleaning up one basin's tombstoned stream.
        let tombstone = kv::stream_meta::ser_key(&basins[0], &stream_name_for_index(0));
        backend.db.delete(tombstone).assert_durable().await;
        let has_more = backend.clone().tick_basin_deletion().await.unwrap();
        assert!(has_more);
    }
}
