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
