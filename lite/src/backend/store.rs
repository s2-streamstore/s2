use bytes::Bytes;
use slatedb::{
    DbSnapshot, DbTransaction, KeyValue,
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
        self.db_get_with(key, |entry| deser(entry.value)).await
    }

    /// Read a remotely durable row, including its sequence and timestamps.
    pub(super) async fn db_get_with<K: AsRef<[u8]> + Send, V>(
        &self,
        key: K,
        deser: impl FnOnce(KeyValue) -> Result<V, kv::DeserializationError>,
    ) -> Result<Option<V>, StorageError> {
        let read_opts = ReadOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let value = self
            .db
            .get_key_value_with_options(key, &read_opts)
            .await?
            .map(deser)
            .transpose()?;
        Ok(value)
    }
}

pub(super) async fn db_snapshot_get_with<K: AsRef<[u8]> + Send, V>(
    snapshot: &DbSnapshot,
    key: K,
    deser: impl FnOnce(KeyValue) -> Result<V, kv::DeserializationError>,
) -> Result<Option<V>, StorageError> {
    Ok(snapshot.get_key_value(key).await?.map(deser).transpose()?)
}

pub(super) async fn db_txn_get<K: AsRef<[u8]> + Send, V>(
    txn: &DbTransaction,
    key: K,
    deser: impl FnOnce(Bytes) -> Result<V, kv::DeserializationError>,
) -> Result<Option<V>, StorageError> {
    db_txn_get_with(txn, key, |entry| deser(entry.value)).await
}

/// Read a transaction row, which may not yet be durable.
pub(super) async fn db_txn_get_with<K: AsRef<[u8]> + Send, V>(
    txn: &DbTransaction,
    key: K,
    deser: impl FnOnce(KeyValue) -> Result<V, kv::DeserializationError>,
) -> Result<Option<V>, StorageError> {
    let value = txn.get_key_value(key).await?.map(deser).transpose()?;
    Ok(value)
}

/// Commit metadata changes and wait until remote reads can observe them.
/// Return the committed sequence number, or `None` if there were no writes.
pub(super) async fn db_txn_commit_durable(
    txn: DbTransaction,
) -> Result<Option<u64>, slatedb::Error> {
    let Some(handle) = txn.commit().await? else {
        return Ok(None);
    };
    handle.await_durable().await?;
    Ok(Some(handle.seqnum()))
}
