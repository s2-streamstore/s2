use bytes::Bytes;
use slatedb::{
    DbTransaction,
    config::{DurabilityLevel, ReadOptions},
};

use super::Backend;
use crate::backend::{error::StorageError, kv};

impl Backend {
    // TODO: switch to `self.db.status()` once slatedb releases with
    // https://github.com/slatedb/slatedb/pull/1234
    pub async fn db_status(&self) -> Result<(), slatedb::Error> {
        let _ = self.db.get(b"ping").await?;
        Ok(())
    }

    pub(super) async fn db_get<K: AsRef<[u8]> + Send, V>(
        &self,
        key: K,
        deser: impl FnOnce(Bytes) -> Result<V, kv::DeserializationError>,
    ) -> Result<Option<V>, StorageError> {
        static READ_OPTS: ReadOptions = ReadOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            cache_blocks: true,
        };
        let value = self
            .db
            .get_with_options(key, &READ_OPTS)
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
    static READ_OPTS: ReadOptions = ReadOptions {
        durability_filter: DurabilityLevel::Memory,
        dirty: false,
        cache_blocks: true,
    };
    let value = txn
        .get_with_options(key, &READ_OPTS)
        .await?
        .map(deser)
        .transpose()?;
    Ok(value)
}
