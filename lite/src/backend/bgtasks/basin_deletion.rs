use futures::{StreamExt, stream};
use s2_common::types::{
    basin::BasinName,
    resources::{ListItemsRequestParts, ListLimit, Page},
    stream::{ListStreamsRequest, StreamNamePrefix, StreamNameStartAfter},
};
use slatedb::{
    WriteBatch,
    config::{DurabilityLevel, ScanOptions, WriteOptions},
};
use tracing::instrument;

use crate::backend::{
    Backend,
    error::{BasinDeletionError, ListStreamsError, StorageError},
    kv,
};

const PENDING_LIST_LIMIT: usize = 32;
const CONCURRENCY: usize = 4;

impl Backend {
    pub(crate) async fn tick_basin_deletion(self) -> Result<bool, BasinDeletionError> {
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
        let mut has_more = page.has_more;
        while let Some(result) = processed.next().await {
            has_more |= result?;
        }
        Ok(has_more)
    }

    async fn list_basin_deletion_pending(
        &self,
    ) -> Result<Page<(BasinName, StreamNameStartAfter)>, StorageError> {
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self
            .db
            .scan_with_options(
                kv::key_type_range(kv::KeyType::BasinDeletionPending),
                &SCAN_OPTS,
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
    ) -> Result<bool, BasinDeletionError> {
        let request: ListStreamsRequest = ListItemsRequestParts {
            prefix: StreamNamePrefix::default(),
            start_after: cursor.clone(),
            limit: ListLimit::MAX,
        }
        .try_into()
        .expect("valid list streams request");
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
            Ok(true)
        } else {
            self.complete_basin_deletion(&basin).await?;
            Ok(false)
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
        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        self.db.write_with_options(batch, &WRITE_OPTS).await?;
        Ok(())
    }

    #[instrument(ret, err, skip(self))]
    async fn complete_basin_deletion(&self, basin: &BasinName) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();
        batch.delete(kv::basin_meta::ser_key(basin));
        batch.delete(kv::basin_deletion_pending::ser_key(basin));
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

    use s2_common::types::{
        basin::BasinName,
        config::BasinConfig,
        resources::ListLimit,
        stream::{StreamName, StreamNameStartAfter},
    };
    use time::OffsetDateTime;

    use super::super::tests::test_backend;
    use crate::backend::{Backend, kv};

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
            config: Default::default(),
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
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::basin_deletion_pending::ser_key(basin),
                kv::basin_deletion_pending::ser_value(&StreamNameStartAfter::default()),
            )
            .await
            .unwrap();
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
        let write_opts = slatedb::config::WriteOptions {
            await_durable: true,
        };
        backend
            .db
            .write_with_options(batch, &write_opts)
            .await
            .unwrap();
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
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::basin_deletion_pending::ser_key(&basin),
                kv::basin_deletion_pending::ser_value(&StreamNameStartAfter::default()),
            )
            .await
            .unwrap();

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
            .await
            .unwrap();

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
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::basin_deletion_pending::ser_key(&basin),
                kv::basin_deletion_pending::ser_value(&cursor),
            )
            .await
            .unwrap();

        backend.clone().tick_basin_deletion().await.unwrap();

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
    async fn basin_deletion_completes_when_only_tombstones_remain() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("test-basin").unwrap();
        let stream = StreamName::from_str("tombstoned-stream").unwrap();
        let deleted_at = OffsetDateTime::from_unix_timestamp(1234567890).unwrap();

        backend
            .db
            .put(
                kv::basin_meta::ser_key(&basin),
                kv::basin_meta::ser_value(&basin_meta(Some(OffsetDateTime::now_utc()))),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::basin_deletion_pending::ser_key(&basin),
                kv::basin_deletion_pending::ser_value(&StreamNameStartAfter::default()),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::ser_value(&stream_meta(Some(deleted_at))),
            )
            .await
            .unwrap();

        backend.clone().tick_basin_deletion().await.unwrap();

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
}
