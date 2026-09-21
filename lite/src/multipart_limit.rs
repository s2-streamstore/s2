//! Optional per-upload concurrency cap. Ordinary PUTs remain independent.

use std::{fmt, num::NonZeroUsize, ops::Range, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use slatedb::object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMultipartOptions, PutOptions, PutPayload, PutResult, RenameOptions, Result,
    limit::LimitUpload, path::Path,
};

#[derive(Debug)]
pub(crate) struct MultipartLimitStore {
    inner: Arc<dyn ObjectStore>,
    concurrency: NonZeroUsize,
}

impl MultipartLimitStore {
    pub(crate) fn new(inner: Arc<dyn ObjectStore>, concurrency: NonZeroUsize) -> Self {
        Self { inner, concurrency }
    }
}

impl fmt::Display for MultipartLimitStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MultipartLimitStore({}, {})",
            self.concurrency, self.inner
        )
    }
}

#[async_trait]
impl ObjectStore for MultipartLimitStore {
    async fn put_opts(&self, path: &Path, data: PutPayload, opts: PutOptions) -> Result<PutResult> {
        self.inner.put_opts(path, data, opts).await
    }

    async fn put_multipart_opts(
        &self,
        path: &Path,
        opts: PutMultipartOptions,
    ) -> Result<Box<dyn MultipartUpload>> {
        let upload = self.inner.put_multipart_opts(path, opts).await?;
        Ok(Box::new(LimitUpload::new(upload, self.concurrency.get())))
    }

    async fn get_opts(&self, path: &Path, opts: GetOptions) -> Result<GetResult> {
        self.inner.get_opts(path, opts).await
    }

    async fn get_ranges(&self, path: &Path, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        self.inner.get_ranges(path, ranges).await
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, Result<Path>>,
    ) -> BoxStream<'static, Result<Path>> {
        self.inner.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, Result<ObjectMeta>> {
        self.inner.list(prefix)
    }

    fn list_with_offset(
        &self,
        prefix: Option<&Path>,
        offset: &Path,
    ) -> BoxStream<'static, Result<ObjectMeta>> {
        self.inner.list_with_offset(prefix, offset)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> Result<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(&self, from: &Path, to: &Path, opts: CopyOptions) -> Result<()> {
        self.inner.copy_opts(from, to, opts).await
    }

    async fn rename_opts(&self, from: &Path, to: &Path, opts: RenameOptions) -> Result<()> {
        self.inner.rename_opts(from, to, opts).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::future::try_join_all;
    use slatedb::object_store::{
        Error, ObjectStoreExt, PutMode,
        memory::InMemory,
        throttle::{ThrottleConfig, ThrottledStore},
    };
    use tokio::time::Instant;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn separate_uploads_have_independent_limits() {
        let inner = ThrottledStore::new(
            InMemory::new(),
            ThrottleConfig {
                wait_put_per_call: Duration::from_millis(100),
                ..Default::default()
            },
        );
        let store = MultipartLimitStore::new(Arc::new(inner), NonZeroUsize::new(1).unwrap());
        let mut first = store.put_multipart(&Path::from("first")).await.unwrap();
        let mut second = store.put_multipart(&Path::from("second")).await.unwrap();
        let parts = [&mut first, &mut second]
            .into_iter()
            .flat_map(|upload| {
                ["a", "b"].map(|part| upload.put_part(Bytes::from_static(part.as_bytes()).into()))
            })
            .collect::<Vec<_>>();
        let started = Instant::now();
        try_join_all(parts).await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_millis(200));
        first.complete().await.unwrap();
        second.complete().await.unwrap();
        for name in ["first", "second"] {
            assert_eq!(
                store
                    .get(&Path::from(name))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap(),
                "ab"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn limits_parts_without_blocking_ordinary_puts() {
        let inner = ThrottledStore::new(
            InMemory::new(),
            ThrottleConfig {
                wait_put_per_call: Duration::from_millis(100),
                ..Default::default()
            },
        );
        let store = MultipartLimitStore::new(Arc::new(inner), NonZeroUsize::new(1).unwrap());
        let path = Path::from("bulk");
        let ordinary_path = Path::from("wal");
        let mut upload = store.put_multipart(&path).await.unwrap();
        let parts = ["first", "second", "third"]
            .map(|s| upload.put_part(Bytes::from_static(s.as_bytes()).into()));
        let started = Instant::now();
        let (uploaded, ordinary_elapsed) = tokio::join!(try_join_all(parts), async {
            store
                .put(&ordinary_path, Bytes::from_static(b"durable").into())
                .await
                .unwrap();
            started.elapsed()
        });
        uploaded.unwrap();
        assert_eq!(ordinary_elapsed, Duration::from_millis(100));
        assert_eq!(started.elapsed(), Duration::from_millis(300));
        upload.complete().await.unwrap();
        assert_eq!(
            store.get(&path).await.unwrap().bytes().await.unwrap(),
            "firstsecondthird"
        );
        assert_eq!(
            store
                .get(&ordinary_path)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
            "durable"
        );

        let duplicate = store
            .put_opts(
                &ordinary_path,
                Bytes::from_static(b"replacement").into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(duplicate, Err(Error::AlreadyExists { .. })));
    }

    #[tokio::test]
    async fn abort_does_not_publish_partial_data() {
        let store =
            MultipartLimitStore::new(Arc::new(InMemory::new()), NonZeroUsize::new(1).unwrap());
        let path = Path::from("aborted");
        let mut upload = store.put_multipart(&path).await.unwrap();
        upload
            .put_part(Bytes::from_static(b"partial").into())
            .await
            .unwrap();
        upload.abort().await.unwrap();
        assert!(matches!(
            store.get(&path).await,
            Err(Error::NotFound { .. })
        ));
    }
}
