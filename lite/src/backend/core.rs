use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use enum_ordinalize::Ordinalize;
use s2_common::{
    record::{SeqNum, StreamPosition},
    types::{
        basin::BasinName,
        config::{BasinConfig, OptionalStreamConfig},
        resources::CreateMode,
        stream::StreamName,
    },
};
use slatedb::config::{DurabilityLevel, ScanOptions};
use tokio::time::Instant;

use super::{
    error::{
        BasinDeletionPendingError, BasinNotFoundError, CreateStreamError, GetBasinConfigError,
        StorageError, StreamDeletionPendingError, StreamNotFoundError, StreamerError,
        TransactionConflictError, UnavailableError,
    },
    kv,
    stream_id::StreamId,
    streamer::{StreamerClient, StreamerClientState},
};

pub const FOLLOWER_MAX_LAG: usize = 25;

#[derive(Clone)]
pub struct Backend {
    pub(super) db: slatedb::Db,
    client_states: Arc<DashMap<StreamId, StreamerClientState>>,
}

impl Backend {
    const FAILED_INIT_MEMORY: Duration = Duration::from_secs(1);

    pub fn new(db: slatedb::Db) -> Self {
        Self {
            db,
            client_states: Arc::new(DashMap::new()),
        }
    }

    async fn start_streamer(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<StreamerClient, StreamerError> {
        let stream_id = StreamId::new(&basin, &stream);

        let (meta, tail_pos, fencing_token, trim_point) = tokio::try_join!(
            self.db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            ),
            self.db_get(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::deser_value,
            ),
            self.db_get(
                kv::stream_fencing_token::ser_key(stream_id),
                kv::stream_fencing_token::deser_value,
            ),
            self.db_get(
                kv::stream_trim_point::ser_key(stream_id),
                kv::stream_trim_point::deser_value,
            )
        )?;

        let Some(meta) = meta else {
            return Err(StreamNotFoundError { basin, stream }.into());
        };

        let tail_pos = tail_pos.unwrap_or(StreamPosition::MIN);
        self.assert_no_records_following_tail(stream_id, &basin, &stream, tail_pos)
            .await?;

        let fencing_token = fencing_token.unwrap_or_default();
        let trim_point = trim_point.unwrap_or(..SeqNum::MIN);

        if trim_point.end == SeqNum::MAX {
            return Err(StreamDeletionPendingError { basin, stream }.into());
        }

        let client_states = self.client_states.clone();
        Ok(super::streamer::spawn_streamer(
            self.db.clone(),
            stream_id,
            meta.config,
            tail_pos,
            fencing_token,
            trim_point,
            client_states,
        ))
    }

    async fn assert_no_records_following_tail(
        &self,
        stream_id: StreamId,
        basin: &BasinName,
        stream: &StreamName,
        tail_pos: StreamPosition,
    ) -> Result<(), StorageError> {
        let start_key = kv::stream_record_data::ser_key(
            stream_id,
            StreamPosition {
                seq_num: tail_pos.seq_num,
                timestamp: 0,
            },
        );
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self.db.scan_with_options(start_key.., &SCAN_OPTS).await?;
        let Some(kv) = it.next().await? else {
            return Ok(());
        };
        if kv.key.first().copied() != Some(kv::KeyType::StreamRecordData.ordinal()) {
            return Ok(());
        }
        let (deser_stream_id, pos) = kv::stream_record_data::deser_key(kv.key)?;
        assert!(
            deser_stream_id != stream_id,
            "invariant violation: stream `{basin}/{stream}` tail_pos {tail_pos:?} but found record at {pos:?}"
        );
        Ok(())
    }

    fn streamer_client_state(&self, basin: &BasinName, stream: &StreamName) -> StreamerClientState {
        match self.client_states.entry(StreamId::new(basin, stream)) {
            dashmap::Entry::Occupied(oe) => oe.get().clone(),
            dashmap::Entry::Vacant(ve) => {
                let this = self.clone();
                let stream_id = *(ve.key());
                let basin = basin.clone();
                let stream = stream.clone();
                tokio::spawn(async move {
                    let state = match this.start_streamer(basin, stream).await {
                        Ok(client) => StreamerClientState::Ready { client },
                        Err(error) => StreamerClientState::InitError {
                            error: Box::new(error),
                            timestamp: Instant::now(),
                        },
                    };
                    let replaced_state = this.client_states.insert(stream_id, state);
                    let Some(StreamerClientState::Blocked { notify }) = replaced_state else {
                        panic!("expected Blocked client but replaced: {replaced_state:?}");
                    };
                    notify.notify_waiters();
                });
                ve.insert(StreamerClientState::Blocked {
                    notify: Default::default(),
                })
                .value()
                .clone()
            }
        }
    }

    fn streamer_remove_unready(&self, stream_id: StreamId) {
        if let dashmap::Entry::Occupied(oe) = self.client_states.entry(stream_id)
            && let StreamerClientState::InitError { .. } = oe.get()
        {
            oe.remove();
        }
    }

    pub(super) async fn streamer_client(
        &self,
        basin: &BasinName,
        stream: &StreamName,
    ) -> Result<StreamerClient, StreamerError> {
        let mut waited = false;
        loop {
            match self.streamer_client_state(basin, stream) {
                StreamerClientState::Blocked { notify } => {
                    notify.notified().await;
                    waited = true;
                }
                StreamerClientState::InitError { error, timestamp } => {
                    if !waited || timestamp.elapsed() > Self::FAILED_INIT_MEMORY {
                        self.streamer_remove_unready(StreamId::new(basin, stream));
                    } else {
                        return Err(*error);
                    }
                }
                StreamerClientState::Ready { client } => {
                    return Ok(client);
                }
            }
        }
    }

    pub(super) fn streamer_client_if_active(
        &self,
        basin: &BasinName,
        stream: &StreamName,
    ) -> Option<StreamerClient> {
        match self.streamer_client_state(basin, stream) {
            StreamerClientState::Ready { client } => Some(client),
            _ => None,
        }
    }

    pub(super) async fn streamer_client_with_auto_create<E>(
        &self,
        basin: &BasinName,
        stream: &StreamName,
        should_auto_create: impl FnOnce(&BasinConfig) -> bool,
    ) -> Result<StreamerClient, E>
    where
        E: From<StreamerError>
            + From<StorageError>
            + From<BasinNotFoundError>
            + From<TransactionConflictError>
            + From<UnavailableError>
            + From<BasinDeletionPendingError>
            + From<StreamDeletionPendingError>
            + From<StreamNotFoundError>,
    {
        match self.streamer_client(basin, stream).await {
            Ok(client) => Ok(client),
            Err(StreamerError::StreamNotFound(e)) => {
                let config = match self.get_basin_config(basin.clone()).await {
                    Ok(config) => config,
                    Err(GetBasinConfigError::Storage(e)) => Err(e)?,
                    Err(GetBasinConfigError::BasinNotFound(e)) => Err(e)?,
                };
                if should_auto_create(&config) {
                    if let Err(e) = self
                        .create_stream(
                            basin.clone(),
                            stream.clone(),
                            OptionalStreamConfig::default(),
                            CreateMode::CreateOnly(None),
                        )
                        .await
                    {
                        match e {
                            CreateStreamError::Storage(e) => Err(e)?,
                            CreateStreamError::TransactionConflict(e) => Err(e)?,
                            CreateStreamError::Unavailable(e) => Err(e)?,
                            CreateStreamError::BasinDeletionPending(e) => Err(e)?,
                            CreateStreamError::StreamDeletionPending(e) => Err(e)?,
                            CreateStreamError::BasinNotFound(e) => Err(e)?,
                            CreateStreamError::StreamAlreadyExists(_) => {}
                        }
                    }
                    Ok(self.streamer_client(basin, stream).await?)
                } else {
                    Err(e.into())
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use bytes::Bytes;
    use s2_common::record::{Metered, Record, StreamPosition};
    use slatedb::{WriteBatch, config::WriteOptions, object_store};
    use time::OffsetDateTime;

    use super::*;

    #[tokio::test]
    #[should_panic(expected = "invariant violation: stream `testbasin1/stream1` tail_pos")]
    async fn start_streamer_fails_if_records_exist_after_tail_pos() {
        let object_store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let db = slatedb::Db::builder("test", object_store)
            .build()
            .await
            .unwrap();

        let backend = Backend::new(db.clone());

        let basin = BasinName::from_str("testbasin1").unwrap();
        let stream = StreamName::from_str("stream1").unwrap();
        let stream_id = StreamId::new(&basin, &stream);

        let meta = kv::stream_meta::StreamMeta {
            config: OptionalStreamConfig::default(),
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
            creation_idempotency_key: None,
        };

        let tail_pos = StreamPosition {
            seq_num: 1,
            timestamp: 123,
        };
        let record_pos = StreamPosition {
            seq_num: tail_pos.seq_num,
            timestamp: tail_pos.timestamp,
        };

        let record = Record::try_from_parts(vec![], Bytes::from_static(b"hello")).unwrap();
        let metered_record: Metered<Record> = record.into();

        let mut wb = WriteBatch::new();
        wb.put(
            kv::stream_meta::ser_key(&basin, &stream),
            kv::stream_meta::ser_value(&meta),
        );
        wb.put(
            kv::stream_tail_position::ser_key(stream_id),
            kv::stream_tail_position::ser_value(tail_pos),
        );
        wb.put(
            kv::stream_record_data::ser_key(stream_id, record_pos),
            kv::stream_record_data::ser_value(metered_record.as_ref()),
        );
        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        db.write_with_options(wb, &WRITE_OPTS).await.unwrap();

        backend
            .start_streamer(basin.clone(), stream.clone())
            .await
            .unwrap();
    }
}
