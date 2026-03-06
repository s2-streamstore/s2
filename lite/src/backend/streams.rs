use std::time::Duration;

use enum_ordinalize::Ordinalize;
use s2_common::{
    bash::Bash,
    record::StreamPosition,
    types::{
        basin::BasinName,
        config::{OptionalStreamConfig, StreamReconfiguration},
        resources::{CreateMode, ListItemsRequestParts, Page, RequestToken},
        stream::{ListStreamsRequest, StreamInfo, StreamName},
    },
};
use slatedb::{
    DbTransaction, IsolationLevel,
    config::{DurabilityLevel, ScanOptions, WriteOptions},
};
use time::OffsetDateTime;
use tracing::instrument;

use super::{Backend, CreatedOrReconfigured, store::db_txn_get, streamer::StreamerRuntimeConfig};
use crate::backend::{
    error::{
        BasinDeletionPendingError, BasinNotFoundError, CreateStreamError, DeleteStreamError,
        GetStreamConfigError, ListStreamsError, ReconfigureStreamError, StorageError,
        StreamAlreadyExistsError, StreamDeletionPendingError, StreamNotFoundError, StreamerError,
    },
    kv,
    stream_id::StreamId,
};

fn doe_min_age(config: &OptionalStreamConfig) -> Option<std::time::Duration> {
    config.delete_on_empty.min_age.filter(|age| !age.is_zero())
}

fn retention_age(config: &OptionalStreamConfig) -> Option<Duration> {
    config.retention_policy.unwrap_or_default().age()
}

fn next_doe_config_epoch(
    current_epoch: u64,
    previous_min_age: Option<std::time::Duration>,
    current_min_age: Option<std::time::Duration>,
) -> u64 {
    if previous_min_age == current_min_age {
        current_epoch
    } else {
        current_epoch.saturating_add(1)
    }
}

fn doe_deadline_from_last_write(
    write_timestamp: kv::timestamp::TimestampSecs,
    retention_age: Duration,
    min_age: Duration,
) -> kv::timestamp::TimestampSecs {
    let deadline_secs = u64::from(write_timestamp.as_u32())
        .saturating_add(retention_age.as_secs())
        .saturating_add(min_age.as_secs())
        .min(u64::from(u32::MAX)) as u32;
    kv::timestamp::TimestampSecs::from_secs(deadline_secs)
}

async fn txn_stream_has_records(
    txn: &DbTransaction,
    stream_id: StreamId,
) -> Result<bool, StorageError> {
    let start_key = kv::stream_record_timestamp::ser_key(stream_id, StreamPosition::MIN);
    static SCAN_OPTS: ScanOptions = ScanOptions {
        durability_filter: DurabilityLevel::Memory,
        dirty: false,
        read_ahead_bytes: 1,
        cache_blocks: false,
        max_fetch_tasks: 1,
    };
    let mut it = txn.scan_with_options(start_key.., &SCAN_OPTS).await?;
    let Some(kv) = it.next().await? else {
        return Ok(false);
    };
    if kv.key.first().copied() != Some(kv::KeyType::StreamRecordTimestamp.ordinal()) {
        return Ok(false);
    }
    let (candidate_stream_id, _pos) = kv::stream_record_timestamp::deser_key(kv.key)?;
    Ok(candidate_stream_id == stream_id)
}

async fn doe_deadline_for_current_state(
    txn: &DbTransaction,
    stream_id: StreamId,
    retention_age: Option<Duration>,
    min_age: Duration,
) -> Result<Option<kv::timestamp::TimestampSecs>, StorageError> {
    if !txn_stream_has_records(txn, stream_id).await? {
        return Ok(Some(kv::timestamp::TimestampSecs::after(min_age)));
    }

    let Some(retention_age) = retention_age else {
        return Ok(None);
    };
    let (_, write_timestamp) = db_txn_get(
        txn,
        kv::stream_tail_position::ser_key(stream_id),
        kv::stream_tail_position::deser_value,
    )
    .await?
    .expect("invariant violation: missing stream tail position");
    Ok(Some(doe_deadline_from_last_write(
        write_timestamp,
        retention_age,
        min_age,
    )))
}

async fn seed_doe_deadline_if_needed(
    txn: &DbTransaction,
    stream_id: StreamId,
    prior_doe_min_age: Option<Duration>,
    prior_retention_age: Option<Duration>,
    current_doe_min_age: Option<Duration>,
    current_retention_age: Option<Duration>,
    doe_config_epoch: u64,
) -> Result<(), StorageError> {
    if prior_doe_min_age == current_doe_min_age && prior_retention_age == current_retention_age {
        return Ok(());
    }

    let Some(min_age) = current_doe_min_age else {
        return Ok(());
    };
    let Some(deadline) =
        doe_deadline_for_current_state(txn, stream_id, current_retention_age, min_age).await?
    else {
        return Ok(());
    };
    txn.put(
        kv::stream_doe_deadline::ser_key(deadline, stream_id),
        kv::stream_doe_deadline::ser_value(kv::stream_doe_deadline::StreamDoeDeadlineValue {
            min_age,
            doe_config_epoch,
        }),
    )?;
    Ok(())
}

impl Backend {
    pub async fn list_streams(
        &self,
        basin: BasinName,
        request: ListStreamsRequest,
    ) -> Result<Page<StreamInfo>, ListStreamsError> {
        let ListItemsRequestParts {
            prefix,
            start_after,
            limit,
        } = request.into();

        let key_range = kv::stream_meta::ser_key_range(&basin, &prefix, &start_after);
        if key_range.is_empty() {
            return Ok(Page::new_empty());
        }

        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self.db.scan_with_options(key_range, &SCAN_OPTS).await?;

        let mut streams = Vec::with_capacity(limit.as_usize());
        let mut has_more = false;
        while let Some(kv) = it.next().await? {
            let (deser_basin, stream) = kv::stream_meta::deser_key(kv.key)?;
            assert_eq!(deser_basin.as_ref(), basin.as_ref());
            assert!(stream.as_ref() > start_after.as_ref());
            assert!(stream.as_ref() >= prefix.as_ref());
            if streams.len() == limit.as_usize() {
                has_more = true;
                break;
            }
            let meta = kv::stream_meta::deser_value(kv.value)?;
            streams.push(StreamInfo {
                name: stream,
                created_at: meta.created_at,
                deleted_at: meta.deleted_at,
            });
        }
        Ok(Page::new(streams, has_more))
    }

    pub async fn create_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
        config: impl Into<StreamReconfiguration>,
        mode: CreateMode,
    ) -> Result<CreatedOrReconfigured<StreamInfo>, CreateStreamError> {
        let config = config.into();
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;

        let Some(basin_meta) = db_txn_get(
            &txn,
            kv::basin_meta::ser_key(&basin),
            kv::basin_meta::deser_value,
        )
        .await?
        else {
            return Err(BasinNotFoundError { basin }.into());
        };

        if basin_meta.deleted_at.is_some() {
            return Err(BasinDeletionPendingError { basin }.into());
        }

        let stream_meta_key = kv::stream_meta::ser_key(&basin, &stream);

        let creation_idempotency_key = match &mode {
            CreateMode::CreateOnly(Some(req_token)) => {
                let resolved = OptionalStreamConfig::default().reconfigure(config.clone());
                Some(creation_idempotency_key(req_token, &resolved))
            }
            _ => None,
        };

        let mut existing_meta_opt = None;
        let mut prior_doe_min_age = None;
        let mut prior_retention_age = None;
        let mut prior_doe_config_epoch = 0;

        if let Some(existing_meta) =
            db_txn_get(&txn, &stream_meta_key, kv::stream_meta::deser_value).await?
        {
            if existing_meta.deleted_at.is_some() {
                return Err(CreateStreamError::StreamDeletionPending(
                    StreamDeletionPendingError { basin, stream },
                ));
            }
            prior_doe_min_age = existing_meta
                .config
                .delete_on_empty
                .min_age
                .filter(|age| !age.is_zero());
            prior_retention_age = retention_age(&existing_meta.config);
            prior_doe_config_epoch = existing_meta.doe_config_epoch;
            match mode {
                CreateMode::CreateOnly(_) => {
                    return if creation_idempotency_key.is_some()
                        && existing_meta.creation_idempotency_key == creation_idempotency_key
                    {
                        Ok(CreatedOrReconfigured::Created(StreamInfo {
                            name: stream,
                            created_at: existing_meta.created_at,
                            deleted_at: None,
                        }))
                    } else {
                        Err(StreamAlreadyExistsError { basin, stream }.into())
                    };
                }
                CreateMode::CreateOrReconfigure => {
                    existing_meta_opt = Some(existing_meta);
                }
            }
        }

        let is_reconfigure = existing_meta_opt.is_some();
        let (resolved, created_at) = match existing_meta_opt {
            Some(existing) => (existing.config.reconfigure(config), existing.created_at),
            None => (
                OptionalStreamConfig::default().reconfigure(config),
                OffsetDateTime::now_utc(),
            ),
        };
        let resolved: OptionalStreamConfig = resolved
            .merge(basin_meta.config.default_stream_config)
            .into();
        let current_doe_min_age = doe_min_age(&resolved);
        let current_retention_age = retention_age(&resolved);
        let doe_config_epoch = next_doe_config_epoch(
            prior_doe_config_epoch,
            prior_doe_min_age,
            current_doe_min_age,
        );

        let meta = kv::stream_meta::StreamMeta {
            config: resolved.clone(),
            created_at,
            deleted_at: None,
            doe_config_epoch,
            creation_idempotency_key,
        };

        txn.put(&stream_meta_key, kv::stream_meta::ser_value(&meta))?;
        let stream_id = StreamId::new(&basin, &stream);
        if !is_reconfigure {
            txn.put(
                kv::stream_id_mapping::ser_key(stream_id),
                kv::stream_id_mapping::ser_value(&basin, &stream),
            )?;
            let created_secs = created_at.unix_timestamp();
            let created_secs = if created_secs <= 0 {
                0
            } else if created_secs >= i64::from(u32::MAX) {
                u32::MAX
            } else {
                created_secs as u32
            };
            txn.put(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::ser_value(
                    StreamPosition::MIN,
                    kv::timestamp::TimestampSecs::from_secs(created_secs),
                ),
            )?;
        }
        seed_doe_deadline_if_needed(
            &txn,
            stream_id,
            prior_doe_min_age,
            prior_retention_age,
            current_doe_min_age,
            current_retention_age,
            doe_config_epoch,
        )
        .await?;

        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        txn.commit_with_options(&WRITE_OPTS).await?;

        if is_reconfigure && let Some(client) = self.streamer_client_if_active(&basin, &stream) {
            client.advise_reconfig(StreamerRuntimeConfig {
                stream: resolved,
                doe_config_epoch,
            });
        }

        let info = StreamInfo {
            name: stream,
            created_at,
            deleted_at: None,
        };

        Ok(if is_reconfigure {
            CreatedOrReconfigured::Reconfigured(info)
        } else {
            CreatedOrReconfigured::Created(info)
        })
    }

    pub(super) async fn stream_id_mapping(
        &self,
        stream_id: StreamId,
    ) -> Result<Option<(BasinName, StreamName)>, StorageError> {
        self.db_get(
            kv::stream_id_mapping::ser_key(stream_id),
            kv::stream_id_mapping::deser_value,
        )
        .await
    }

    pub async fn get_stream_config(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<OptionalStreamConfig, GetStreamConfigError> {
        let meta = self
            .db_get(
                kv::stream_meta::ser_key(&basin, &stream),
                kv::stream_meta::deser_value,
            )
            .await?
            .ok_or_else(|| StreamNotFoundError {
                basin: basin.clone(),
                stream: stream.clone(),
            })?;
        if meta.deleted_at.is_some() {
            return Err(StreamDeletionPendingError { basin, stream }.into());
        }
        Ok(meta.config)
    }

    pub async fn reconfigure_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
        reconfig: StreamReconfiguration,
    ) -> Result<OptionalStreamConfig, ReconfigureStreamError> {
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;

        let meta_key = kv::stream_meta::ser_key(&basin, &stream);

        let mut meta = db_txn_get(&txn, &meta_key, kv::stream_meta::deser_value)
            .await?
            .ok_or_else(|| StreamNotFoundError {
                basin: basin.clone(),
                stream: stream.clone(),
            })?;

        if meta.deleted_at.is_some() {
            return Err(StreamDeletionPendingError { basin, stream }.into());
        }

        let prior_doe_min_age = meta
            .config
            .delete_on_empty
            .min_age
            .filter(|age| !age.is_zero());
        let prior_retention_age = retention_age(&meta.config);
        let prior_doe_config_epoch = meta.doe_config_epoch;

        meta.config = meta.config.reconfigure(reconfig);
        let current_doe_min_age = doe_min_age(&meta.config);
        let current_retention_age = retention_age(&meta.config);
        meta.doe_config_epoch = next_doe_config_epoch(
            prior_doe_config_epoch,
            prior_doe_min_age,
            current_doe_min_age,
        );

        txn.put(&meta_key, kv::stream_meta::ser_value(&meta))?;

        let stream_id = StreamId::new(&basin, &stream);
        seed_doe_deadline_if_needed(
            &txn,
            stream_id,
            prior_doe_min_age,
            prior_retention_age,
            current_doe_min_age,
            current_retention_age,
            meta.doe_config_epoch,
        )
        .await?;

        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        txn.commit_with_options(&WRITE_OPTS).await?;

        if let Some(client) = self.streamer_client_if_active(&basin, &stream) {
            client.advise_reconfig(StreamerRuntimeConfig {
                stream: meta.config.clone(),
                doe_config_epoch: meta.doe_config_epoch,
            });
        }

        Ok(meta.config)
    }

    #[instrument(ret, err, skip(self))]
    pub async fn delete_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<(), DeleteStreamError> {
        match self.streamer_client(&basin, &stream).await {
            Ok(client) => {
                client.terminal_trim().await?;
            }
            Err(StreamerError::Storage(e)) => {
                return Err(DeleteStreamError::Storage(e));
            }
            Err(StreamerError::StreamNotFound(e)) => {
                return Err(DeleteStreamError::StreamNotFound(e));
            }
            Err(StreamerError::StreamDeletionPending(e)) => {
                assert_eq!(e.basin, basin);
                assert_eq!(e.stream, stream);
            }
        }

        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
        let meta_key = kv::stream_meta::ser_key(&basin, &stream);
        let mut meta = db_txn_get(&txn, &meta_key, kv::stream_meta::deser_value)
            .await?
            .ok_or_else(|| StreamNotFoundError {
                basin,
                stream: stream.clone(),
            })?;
        if meta.deleted_at.is_none() {
            meta.deleted_at = Some(OffsetDateTime::now_utc());
            txn.put(&meta_key, kv::stream_meta::ser_value(&meta))?;
            static WRITE_OPTS: WriteOptions = WriteOptions {
                await_durable: true,
            };
            txn.commit_with_options(&WRITE_OPTS).await?;
        }

        Ok(())
    }
}

fn creation_idempotency_key(req_token: &RequestToken, config: &OptionalStreamConfig) -> Bash {
    Bash::length_prefixed(&[
        req_token.as_bytes(),
        &s2_api::v1::config::StreamConfig::to_opt(config.clone())
            .as_ref()
            .map(|v| serde_json::to_vec(v).expect("serializable"))
            .unwrap_or_default(),
    ])
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc, time::Duration};

    use bytesize::ByteSize;
    use s2_common::{
        maybe::Maybe,
        record::StreamPosition,
        types::{
            basin::BasinName,
            config::{
                BasinConfig, DeleteOnEmptyReconfiguration, OptionalStreamConfig, RetentionPolicy,
                StreamReconfiguration,
            },
            resources::CreateMode,
            stream::StreamName,
        },
    };
    use slatedb::object_store::memory::InMemory;

    use super::*;
    use crate::backend::{Backend, kv};

    async fn test_backend() -> Backend {
        let object_store = Arc::new(InMemory::new());
        let db = slatedb::Db::builder("/test", object_store)
            .build()
            .await
            .unwrap();
        Backend::new(db, ByteSize::mib(10))
    }

    async fn seed_nonempty_stream(
        backend: &Backend,
        basin: &BasinName,
        stream: &StreamName,
        retention_age: Duration,
        write_timestamp: kv::timestamp::TimestampSecs,
    ) -> StreamId {
        backend
            .create_basin(
                basin.clone(),
                BasinConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();
        backend
            .create_stream(
                basin.clone(),
                stream.clone(),
                OptionalStreamConfig {
                    retention_policy: Some(RetentionPolicy::Age(retention_age)),
                    ..Default::default()
                },
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();
        let stream_id = StreamId::new(basin, stream);
        let pos = StreamPosition {
            seq_num: 0,
            timestamp: 1234,
        };
        backend
            .db
            .put(
                kv::stream_record_timestamp::ser_key(stream_id, pos),
                kv::stream_record_timestamp::ser_value(),
            )
            .await
            .unwrap();
        backend
            .db
            .put(
                kv::stream_tail_position::ser_key(stream_id),
                kv::stream_tail_position::ser_value(
                    StreamPosition {
                        seq_num: 1,
                        timestamp: pos.timestamp,
                    },
                    write_timestamp,
                ),
            )
            .await
            .unwrap();
        stream_id
    }

    fn enable_doe_reconfig(min_age: Duration) -> StreamReconfiguration {
        StreamReconfiguration {
            delete_on_empty: Maybe::from(Some(DeleteOnEmptyReconfiguration {
                min_age: Maybe::from(Some(min_age)),
            })),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn create_or_reconfigure_nonempty_stream_arms_deadline_from_last_write_and_retention() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-reconfig-basin").unwrap();
        let stream = StreamName::from_str("doe-reconfig-stream").unwrap();
        let retention_age = Duration::from_secs(300);
        let write_timestamp = kv::timestamp::TimestampSecs::from_secs(10_000);
        let min_age = Duration::from_secs(45);
        let stream_id =
            seed_nonempty_stream(&backend, &basin, &stream, retention_age, write_timestamp).await;

        backend
            .create_stream(
                basin.clone(),
                stream.clone(),
                enable_doe_reconfig(min_age),
                CreateMode::CreateOrReconfigure,
            )
            .await
            .unwrap();

        let expected_deadline =
            doe_deadline_from_last_write(write_timestamp, retention_age, min_age);
        let deadline = backend
            .db
            .get(kv::stream_doe_deadline::ser_key(
                expected_deadline,
                stream_id,
            ))
            .await
            .unwrap();
        assert!(deadline.is_some());
    }

    #[tokio::test]
    async fn reconfigure_nonempty_stream_arms_deadline_from_last_write_and_retention() {
        let backend = test_backend().await;
        let basin = BasinName::from_str("doe-explicit-basin").unwrap();
        let stream = StreamName::from_str("doe-explicit-stream").unwrap();
        let retention_age = Duration::from_secs(600);
        let write_timestamp = kv::timestamp::TimestampSecs::from_secs(20_000);
        let min_age = Duration::from_secs(90);
        let stream_id =
            seed_nonempty_stream(&backend, &basin, &stream, retention_age, write_timestamp).await;

        backend
            .reconfigure_stream(basin.clone(), stream.clone(), enable_doe_reconfig(min_age))
            .await
            .unwrap();

        let expected_deadline =
            doe_deadline_from_last_write(write_timestamp, retention_age, min_age);
        let deadline = backend
            .db
            .get(kv::stream_doe_deadline::ser_key(
                expected_deadline,
                stream_id,
            ))
            .await
            .unwrap();
        assert!(deadline.is_some());
    }
}
