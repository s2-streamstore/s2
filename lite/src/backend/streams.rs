use s2_common::{
    bash::Bash,
    record::StreamPosition,
    types::{
        basin::BasinName,
        config::{OptionalStreamConfig, StreamReconfiguration},
        resources::{Page, RequestToken},
        stream::{CreateStreamIntent, ListStreamsRequest, StreamInfo, StreamName},
    },
};
use slatedb::{
    IsolationLevel, IterationOrder,
    config::{DurabilityLevel, ScanOptions, WriteOptions},
};
use time::OffsetDateTime;
use tracing::instrument;

use super::{
    Backend, CreatedOrReconfigured,
    store::db_txn_get,
    streamer::{doe_arm_delay, retention_age_or_zero},
};
use crate::{
    backend::{
        error::{
            BasinDeletionPendingError, BasinNotFoundError, CreateStreamError, DeleteStreamError,
            GetStreamConfigError, ListStreamsError, ReconfigureStreamError, StorageError,
            StreamAlreadyExistsError, StreamDeletionPendingError, StreamNotFoundError,
            StreamerError,
        },
        kv,
    },
    stream_id::StreamId,
};

impl Backend {
    pub async fn list_streams(
        &self,
        basin: BasinName,
        request: ListStreamsRequest,
    ) -> Result<Page<StreamInfo>, ListStreamsError> {
        let ListStreamsRequest {
            prefix,
            start_after,
            limit,
        } = request;

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
            order: IterationOrder::Ascending,
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
                cipher: meta.cipher,
            });
        }
        Ok(Page::new(streams, has_more))
    }

    pub async fn create_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
        intent: CreateStreamIntent,
    ) -> Result<CreatedOrReconfigured<StreamInfo>, CreateStreamError> {
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

        let existing_meta =
            db_txn_get(&txn, &stream_meta_key, kv::stream_meta::deser_value).await?;
        if let Some(existing_meta) = &existing_meta
            && existing_meta.deleted_at.is_some()
        {
            return Err(CreateStreamError::StreamDeletionPending(
                StreamDeletionPendingError { basin, stream },
            ));
        }

        let (mut meta, is_reconfigure, prior_doe_min_age) = match (existing_meta, intent) {
            (
                Some(existing),
                CreateStreamIntent::CreateOnly {
                    config,
                    request_token,
                },
            ) => {
                let new_creation_idempotency_key = request_token
                    .as_ref()
                    .map(|req_token| creation_idempotency_key(req_token, &config));
                return if new_creation_idempotency_key.is_some()
                    && existing.creation_idempotency_key == new_creation_idempotency_key
                {
                    Ok(CreatedOrReconfigured::Created(StreamInfo {
                        name: stream,
                        created_at: existing.created_at,
                        deleted_at: None,
                        cipher: existing.cipher,
                    }))
                } else {
                    Err(StreamAlreadyExistsError { basin, stream }.into())
                };
            }
            (Some(existing), CreateStreamIntent::CreateOrReconfigure { reconfiguration }) => {
                let prior_doe_min_age = existing
                    .config
                    .delete_on_empty
                    .min_age
                    .filter(|age| !age.is_zero());
                (
                    kv::stream_meta::StreamMeta {
                        config: existing.config.reconfigure(reconfiguration),
                        cipher: existing.cipher,
                        created_at: existing.created_at,
                        deleted_at: None,
                        creation_idempotency_key: existing.creation_idempotency_key,
                    },
                    true,
                    prior_doe_min_age,
                )
            }
            (
                None,
                CreateStreamIntent::CreateOnly {
                    config,
                    request_token,
                },
            ) => {
                let new_creation_idempotency_key = request_token
                    .as_ref()
                    .map(|req_token| creation_idempotency_key(req_token, &config));
                (
                    kv::stream_meta::StreamMeta {
                        config,
                        cipher: basin_meta.config.stream_cipher,
                        created_at: OffsetDateTime::now_utc(),
                        deleted_at: None,
                        creation_idempotency_key: new_creation_idempotency_key,
                    },
                    false,
                    None,
                )
            }
            (None, CreateStreamIntent::CreateOrReconfigure { reconfiguration }) => (
                kv::stream_meta::StreamMeta {
                    config: OptionalStreamConfig::default().reconfigure(reconfiguration),
                    cipher: basin_meta.config.stream_cipher,
                    created_at: OffsetDateTime::now_utc(),
                    deleted_at: None,
                    creation_idempotency_key: None,
                },
                false,
                None,
            ),
        };
        let basin_defaults = basin_meta.config.default_stream_config;
        meta.config = meta.config.merge(basin_defaults).into();

        txn.put(&stream_meta_key, kv::stream_meta::ser_value(&meta))?;
        let stream_id = StreamId::new(&basin, &stream);
        if !is_reconfigure {
            txn.put(
                kv::stream_id_mapping::ser_key(stream_id),
                kv::stream_id_mapping::ser_value(&basin, &stream),
            )?;
            let created_secs = meta.created_at.unix_timestamp();
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
        if let Some(min_age) = meta
            .config
            .delete_on_empty
            .min_age
            .filter(|age| !age.is_zero())
            && (!is_reconfigure || prior_doe_min_age.is_none())
        {
            txn.put(
                kv::stream_doe_deadline::ser_key(
                    kv::timestamp::TimestampSecs::after(doe_arm_delay(
                        retention_age_or_zero(&meta.config),
                        min_age,
                    )),
                    stream_id,
                ),
                kv::stream_doe_deadline::ser_value(min_age),
            )?;
        }

        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        txn.commit_with_options(&WRITE_OPTS).await?;

        if is_reconfigure && let Some(client) = self.streamer_client_if_active(&basin, &stream) {
            client.advise_reconfig(meta.config.clone());
        }

        let info = StreamInfo {
            name: stream,
            created_at: meta.created_at,
            deleted_at: None,
            cipher: meta.cipher,
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

        meta.config = meta.config.reconfigure(reconfig);

        txn.put(&meta_key, kv::stream_meta::ser_value(&meta))?;

        let stream_id = StreamId::new(&basin, &stream);
        if let Some(min_age) = meta
            .config
            .delete_on_empty
            .min_age
            .filter(|age| !age.is_zero())
            && prior_doe_min_age.is_none()
        {
            txn.put(
                kv::stream_doe_deadline::ser_key(
                    kv::timestamp::TimestampSecs::after(doe_arm_delay(
                        retention_age_or_zero(&meta.config),
                        min_age,
                    )),
                    stream_id,
                ),
                kv::stream_doe_deadline::ser_value(min_age),
            )?;
        }

        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        txn.commit_with_options(&WRITE_OPTS).await?;

        if let Some(client) = self.streamer_client_if_active(&basin, &stream) {
            client.advise_reconfig(meta.config.clone());
        }

        Ok(meta.config)
    }

    #[instrument(ret, err, skip(self))]
    pub async fn delete_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<(), DeleteStreamError> {
        match self.streamer_client_guarded(&basin, &stream).await {
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
