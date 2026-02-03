use s2_common::{
    bash::Bash,
    types::{
        basin::BasinName,
        config::{OptionalStreamConfig, StreamReconfiguration},
        resources::{CreateMode, ListItemsRequestParts, Page, RequestToken},
        stream::{ListStreamsRequest, StreamInfo, StreamName},
    },
};
use slatedb::{
    IsolationLevel,
    config::{DurabilityLevel, ScanOptions, WriteOptions},
};
use time::OffsetDateTime;
use tracing::instrument;

use super::{Backend, CreatedOrReconfigured, store::db_txn_get};
use crate::backend::{
    error::{
        BasinDeletionPendingError, BasinNotFoundError, CreateStreamError, DeleteStreamError,
        GetStreamConfigError, ListStreamsError, ReconfigureStreamError, StreamAlreadyExistsError,
        StreamDeletionPendingError, StreamNotFoundError, StreamerError,
    },
    kv,
    stream_id::StreamId,
};

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
        mut config: OptionalStreamConfig,
        mode: CreateMode,
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

        let creation_idempotency_key = match &mode {
            CreateMode::CreateOnly(Some(req_token)) => {
                Some(creation_idempotency_key(req_token, &config))
            }
            _ => None,
        };

        let mut existing_created_at = None;

        if let Some(existing_meta) =
            db_txn_get(&txn, &stream_meta_key, kv::stream_meta::deser_value).await?
        {
            if existing_meta.deleted_at.is_some() {
                return Err(CreateStreamError::StreamDeletionPending(
                    StreamDeletionPendingError { basin, stream },
                ));
            }
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
                    existing_created_at = Some(existing_meta.created_at);
                }
            }
        }

        config = config.merge(basin_meta.config.default_stream_config).into();

        let created_at = existing_created_at.unwrap_or_else(OffsetDateTime::now_utc);
        let meta = kv::stream_meta::StreamMeta {
            config: config.clone(),
            created_at,
            deleted_at: None,
            creation_idempotency_key,
        };

        txn.put(&stream_meta_key, kv::stream_meta::ser_value(&meta))?;
        if existing_created_at.is_none() {
            txn.put(
                kv::stream_id_mapping::ser_key(StreamId::new(&basin, &stream)),
                kv::stream_id_mapping::ser_value(&basin, &stream),
            )?;
        }

        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        txn.commit_with_options(&WRITE_OPTS).await?;

        if existing_created_at.is_some()
            && let Some(client) = self.streamer_client_if_active(&basin, &stream)
        {
            client.advise_reconfig(config);
        }

        let info = StreamInfo {
            name: stream,
            created_at,
            deleted_at: None,
        };

        Ok(if existing_created_at.is_some() {
            CreatedOrReconfigured::Reconfigured(info)
        } else {
            CreatedOrReconfigured::Created(info)
        })
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
            .ok_or_else(|| StreamNotFoundError { basin, stream })?;
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

        meta.config = meta.config.reconfigure(reconfig);

        txn.put(&meta_key, kv::stream_meta::ser_value(&meta))?;

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
    Bash::new(&[
        req_token.as_bytes(),
        &s2_api::v1::config::StreamConfig::to_opt(config.clone())
            .as_ref()
            .map(|v| serde_json::to_vec(v).expect("serializable"))
            .unwrap_or_default(),
    ])
}
