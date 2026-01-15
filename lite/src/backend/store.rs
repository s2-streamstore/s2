use bytes::Bytes;
use s2_common::record::{SeqNum, StreamPosition, Timestamp};
use slatedb::{
    DbTransaction,
    config::{DurabilityLevel, ReadOptions, ScanOptions},
};

use super::Backend;
use crate::backend::{error::StorageError, kv, stream_id::StreamId};

impl Backend {
    pub(super) async fn db_get<K: AsRef<[u8]> + Send, V>(
        &self,
        key: K,
        deser: impl FnOnce(Bytes) -> Result<V, kv::DeserializationError>,
    ) -> Result<Option<V>, StorageError> {
        static READ_OPTS: ReadOptions = ReadOptions {
            durability_filter: DurabilityLevel::Memory,
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

    pub(super) async fn resolve_timestamp(
        &self,
        stream_id: StreamId,
        timestamp: Timestamp,
    ) -> Result<Option<StreamPosition>, StorageError> {
        let start_key = kv::stream_record_timestamp::ser_key(stream_id, timestamp, SeqNum::MIN);
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self.db.scan_with_options(start_key.., &SCAN_OPTS).await?;
        Ok(match it.next().await? {
            Some(kv) => {
                let (deser_stream_id, deser_timestamp, deser_seq_num) =
                    kv::stream_record_timestamp::deser_key(kv.key)?;
                assert_eq!(deser_stream_id, stream_id);
                assert!(deser_timestamp >= timestamp);
                kv::stream_record_timestamp::deser_value(kv.value)?;
                Some(StreamPosition {
                    seq_num: deser_seq_num,
                    timestamp: deser_timestamp,
                })
            }
            None => None,
        })
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
