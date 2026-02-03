use bytes::Bytes;
use s2_common::record::{SeqNum, StreamPosition, Timestamp};
use slatedb::{
    DbTransaction,
    config::{DurabilityLevel, ReadOptions, ScanOptions},
};

use super::Backend;
use crate::backend::{error::StorageError, kv, stream_id::StreamId};

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

    pub(super) async fn resolve_timestamp(
        &self,
        stream_id: StreamId,
        timestamp: Timestamp,
    ) -> Result<Option<StreamPosition>, StorageError> {
        let start_key = kv::stream_record_timestamp::ser_key(
            stream_id,
            StreamPosition {
                seq_num: SeqNum::MIN,
                timestamp,
            },
        );
        let end_key = kv::stream_record_timestamp::ser_key(
            stream_id,
            StreamPosition {
                seq_num: SeqNum::MAX,
                timestamp: Timestamp::MAX,
            },
        );
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self
            .db
            .scan_with_options(start_key..end_key, &SCAN_OPTS)
            .await?;
        Ok(match it.next().await? {
            Some(kv) => {
                let (deser_stream_id, pos) = kv::stream_record_timestamp::deser_key(kv.key)?;
                assert_eq!(deser_stream_id, stream_id);
                assert!(pos.timestamp >= timestamp);
                kv::stream_record_timestamp::deser_value(kv.value)?;
                Some(StreamPosition {
                    seq_num: pos.seq_num,
                    timestamp: pos.timestamp,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytesize::ByteSize;
    use slatedb::{Db, object_store::memory::InMemory};

    use super::*;

    #[tokio::test]
    async fn resolve_timestamp_bounded_to_stream() {
        let object_store = Arc::new(InMemory::new());
        let db = Db::builder("/test", object_store).build().await.unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));

        let stream_a: StreamId = [0u8; 32].into();
        let stream_b: StreamId = [1u8; 32].into();

        backend
            .db
            .put(
                kv::stream_record_timestamp::ser_key(
                    stream_a,
                    StreamPosition {
                        seq_num: 0,
                        timestamp: 1000,
                    },
                ),
                kv::stream_record_timestamp::ser_value(),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::stream_record_timestamp::ser_key(
                    stream_b,
                    StreamPosition {
                        seq_num: 0,
                        timestamp: 2000,
                    },
                ),
                kv::stream_record_timestamp::ser_value(),
            )
            .await
            .unwrap();

        // Should find record in stream_a
        let result = backend.resolve_timestamp(stream_a, 500).await.unwrap();
        assert_eq!(
            result,
            Some(StreamPosition {
                seq_num: 0,
                timestamp: 1000
            })
        );

        // Should return None, not find stream_b's record
        let result = backend.resolve_timestamp(stream_a, 1500).await.unwrap();
        assert_eq!(result, None);
    }
}
