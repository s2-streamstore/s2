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
    use s2_common::{config::BasinConfig, resources::ProvisionMode};
    use slatedb::{Db, config::Settings, object_store::memory::InMemory};

    use super::*;

    async fn assert_waits_for_flush<T: Debug>(
        db: &Db,
        key: Bytes,
        operation: impl Future<Output = T>,
    ) -> T {
        tokio::pin!(operation);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                biased;
                result = &mut operation => panic!("metadata acknowledged before flush: {result:?}"),
                () = async {
                    while db.get(&key).await.unwrap().is_none() {
                        tokio::task::yield_now().await;
                    }
                } => {}
            }
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
        let db = Db::builder("durable-metadata", Arc::new(InMemory::new()))
            .with_settings(Settings {
                flush_interval: None,
                ..Default::default()
            })
            .build()
            .await
            .unwrap();
        let backend = Backend::new(db.clone(), ByteSize::mib(1));
        let basin = "durable-basin".parse().unwrap();
        let stream = "durable-stream".parse().unwrap();
        assert_waits_for_flush(
            &db,
            kv::basin_meta::ser_key(&basin),
            backend.provision_basin(basin.clone(), BasinConfig::default(), ProvisionMode::Ensure),
        )
        .await
        .unwrap();
        assert_waits_for_flush(
            &db,
            kv::stream_meta::ser_key(&basin, &stream),
            backend.provision_stream(basin, stream, Default::default(), ProvisionMode::Ensure),
        )
        .await
        .unwrap();
        backend.close().await.unwrap();
    }
}
