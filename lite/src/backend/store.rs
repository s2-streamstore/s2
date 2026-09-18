use bytes::Bytes;
use slatedb::{
    DbTransaction,
    config::{DurabilityLevel, ReadOptions},
};

use super::Backend;
use crate::backend::{error::StorageError, kv};

impl Backend {
    pub fn db_status(&self) -> Result<(), slatedb::CloseReason> {
        match self.db.status().close_reason {
            None => Ok(()),
            Some(reason) => Err(reason),
        }
    }

    pub(super) async fn db_get<K: AsRef<[u8]> + Send, V>(
        &self,
        key: K,
        deser: impl FnOnce(Bytes) -> Result<V, kv::DeserializationError>,
    ) -> Result<Option<V>, StorageError> {
        let read_opts = ReadOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let value = self
            .db
            .get_with_options(key, &read_opts)
            .await?
            .map(deser)
            .transpose()?;
        Ok(value)
    }
}

pub(super) async fn db_txn_get<K: AsRef<[u8]> + Send, V>(
    txn: &DbTransaction,
    key: K,
    deser: impl FnOnce(Bytes) -> Result<V, kv::DeserializationError>,
) -> Result<Option<V>, StorageError> {
    let value = txn.get(key).await?.map(deser).transpose()?;
    Ok(value)
}

/// Commit metadata changes and wait until remote reads can observe them.
pub(super) async fn db_txn_commit_durable(txn: DbTransaction) -> Result<(), slatedb::Error> {
    if let Some(handle) = txn.commit().await? {
        handle.await_durable().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fmt::Debug, future::Future, sync::Arc, time::Duration};

    use bytesize::ByteSize;
    use s2_common::{
        config::BasinConfig,
        resources::{ProvisionMode, ProvisionResult},
    };
    use slatedb::{Db, config::Settings, object_store::memory::InMemory};

    use super::*;
    use crate::backend::error::ProvisionBasinError;

    async fn backend_without_auto_flush() -> Backend {
        let db = Db::builder("durable-metadata", Arc::new(InMemory::new()))
            .with_settings(Settings {
                flush_interval: None,
                ..Default::default()
            })
            .build()
            .await
            .unwrap();
        Backend::new(db, ByteSize::mib(1))
    }

    async fn assert_pending_until_visible<T: Debug>(
        db: &Db,
        key: &Bytes,
        operation: &mut (impl Future<Output = T> + Unpin),
    ) {
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                biased;
                result = operation => panic!("metadata acknowledged before flush: {result:?}"),
                () = async {
                    while db.get(key).await.unwrap().is_none() {
                        tokio::task::yield_now().await;
                    }
                } => {}
            }
        })
        .await
        .expect("metadata should become visible in memory before flushing");
    }

    async fn assert_waits_for_flush<T: Debug>(
        db: &Db,
        key: Bytes,
        operation: impl Future<Output = T>,
    ) -> T {
        tokio::pin!(operation);
        tokio::time::timeout(Duration::from_secs(5), async {
            assert_pending_until_visible(db, &key, &mut operation).await;
            let remote = ReadOptions {
                durability_filter: DurabilityLevel::Remote,
                ..Default::default()
            };
            assert!(db.get_with_options(&key, &remote).await.unwrap().is_none());
            assert!(futures::poll!(&mut operation).is_pending());
            db.flush().await.unwrap();
            let result = operation.await;
            assert!(db.get_with_options(&key, &remote).await.unwrap().is_some());
            result
        })
        .await
        .expect("metadata write should finish after an explicit flush")
    }

    #[tokio::test]
    async fn provisioning_acknowledges_only_durable_metadata() {
        let backend = backend_without_auto_flush().await;
        let basin = "durable-basin".parse().unwrap();
        let stream = "durable-stream".parse().unwrap();
        assert_waits_for_flush(
            &backend.db,
            kv::basin_meta::ser_key(&basin),
            backend.provision_basin(basin.clone(), BasinConfig::default(), ProvisionMode::Ensure),
        )
        .await
        .unwrap();
        assert_waits_for_flush(
            &backend.db,
            kv::stream_meta::ser_key(&basin, &stream),
            backend.provision_stream(basin, stream, Default::default(), ProvisionMode::Ensure),
        )
        .await
        .unwrap();
        backend.close().await.unwrap();
    }

    #[rstest::rstest]
    #[case::ensure(ProvisionMode::Ensure, false)]
    #[case::idempotent_create(ProvisionMode::CreateOnly {
        request_token: Some("original".parse().unwrap()),
    }, false)]
    #[case::create_without_token(ProvisionMode::CreateOnly {
        request_token: None,
    }, true)]
    #[case::create_with_different_token(ProvisionMode::CreateOnly {
        request_token: Some("different".parse().unwrap()),
    }, true)]
    #[tokio::test]
    async fn basin_retries_acknowledge_only_durable_metadata(
        #[case] retry_mode: ProvisionMode,
        #[case] expect_already_exists: bool,
    ) {
        let backend = backend_without_auto_flush().await;
        let basin = "durable-basin".parse().unwrap();
        let key = kv::basin_meta::ser_key(&basin);
        let creation = backend.provision_basin(
            basin.clone(),
            BasinConfig::default(),
            ProvisionMode::CreateOnly {
                request_token: Some("original".parse().unwrap()),
            },
        );
        tokio::pin!(creation);
        assert_pending_until_visible(&backend.db, &key, &mut creation).await;

        let retry = assert_waits_for_flush(
            &backend.db,
            key,
            backend.provision_basin(basin, BasinConfig::default(), retry_mode),
        )
        .await;
        if expect_already_exists {
            assert!(matches!(
                retry,
                Err(ProvisionBasinError::BasinAlreadyExists(_))
            ));
        } else {
            assert!(matches!(retry, Ok(ProvisionResult::Noop(_))));
        }
        assert!(matches!(
            creation.await.unwrap(),
            ProvisionResult::Created(_)
        ));
        backend.close().await.unwrap();
    }
}
