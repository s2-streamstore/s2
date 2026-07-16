use s2_common::{
    basin::BasinName,
    config::{OptionalStreamConfig, StreamConfig, StreamReconfiguration},
    record::StreamPosition,
    resources::{Page, ProvisionMode, ProvisionResult, RequestToken},
    stream::{ListStreamsRequest, StreamInfo, StreamName},
};
use s2_storage::bash::Bash;
use slatedb::{
    IsolationLevel,
    config::{DurabilityLevel, ScanOptions},
};
use time::OffsetDateTime;
use tracing::instrument;

use super::{
    Backend,
    store::db_txn_get,
    streamer::{TerminalTrimCondition, TerminalTrimOutcome, doe_arm_delay},
};
use crate::{
    backend::{
        error::{
            BasinDeletionPendingError, BasinNotFoundError, DeleteStreamError, GetStreamConfigError,
            ListStreamsError, ProvisionStreamError, ReconfigureStreamError, StorageError,
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

        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = self.db.scan_with_options(key_range, &scan_opts).await?;

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

    /// Invariant: any outcome asserting the stream exists — `Created`,
    /// `Updated`, `Noop`, or `StreamAlreadyExists` — is durably visible
    /// (readable at `DurabilityLevel::Remote`) by the time this returns.
    pub async fn provision_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
        config: OptionalStreamConfig,
        mode: ProvisionMode,
    ) -> Result<ProvisionResult<StreamInfo>, ProvisionStreamError> {
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

        // Existence is decided from a Memory-level read; capture the row's
        // commit seq so exists-outcomes can await durability (see fn doc).
        let existing_entry = txn.get_key_value(&stream_meta_key).await?;
        let existing_seq = existing_entry.as_ref().map(|kv| kv.seq);
        let existing_meta = existing_entry
            .map(|kv| kv::stream_meta::deser_value(kv.value))
            .transpose()
            .map_err(StorageError::from)?;
        if let Some(existing_meta) = &existing_meta
            && existing_meta.deleted_at.is_some()
        {
            return Err(ProvisionStreamError::StreamDeletionPending(
                StreamDeletionPendingError,
            ));
        }

        let basin_defaults = basin_meta.config.default_stream_config;
        let (outcome, prior_doe_min_age) = match (existing_meta, mode) {
            (Some(existing), ProvisionMode::CreateOnly { request_token }) => {
                let new_creation_idempotency_key = request_token
                    .as_ref()
                    .map(|req_token| creation_idempotency_key(req_token, &config));
                let result = if new_creation_idempotency_key.is_some()
                    && existing.creation_idempotency_key == new_creation_idempotency_key
                {
                    Ok(ProvisionResult::Noop(StreamInfo {
                        name: stream,
                        created_at: existing.created_at,
                        deleted_at: None,
                        cipher: existing.cipher,
                    }))
                } else {
                    Err(StreamAlreadyExistsError { basin, stream }.into())
                };
                drop(txn);
                self.await_durable_seq(existing_seq.expect("existing meta was read"))
                    .await?;
                return result;
            }
            (Some(existing), ProvisionMode::Ensure) => {
                let desired_config = config.merge(basin_defaults);
                let config_unchanged = existing.config == desired_config;
                let meta = kv::stream_meta::StreamMeta {
                    config: desired_config,
                    cipher: existing.cipher,
                    created_at: existing.created_at,
                    deleted_at: None,
                    creation_idempotency_key: existing.creation_idempotency_key,
                };
                (
                    if config_unchanged {
                        ProvisionResult::Noop(meta)
                    } else {
                        ProvisionResult::Updated(meta)
                    },
                    existing.config.delete_on_empty.min_age(),
                )
            }
            (None, ProvisionMode::CreateOnly { request_token }) => {
                let new_creation_idempotency_key = request_token
                    .as_ref()
                    .map(|req_token| creation_idempotency_key(req_token, &config));
                (
                    ProvisionResult::Created(kv::stream_meta::StreamMeta {
                        config: config.merge(basin_defaults),
                        cipher: basin_meta.config.stream_cipher,
                        created_at: OffsetDateTime::now_utc(),
                        deleted_at: None,
                        creation_idempotency_key: new_creation_idempotency_key,
                    }),
                    None,
                )
            }
            (None, ProvisionMode::Ensure) => (
                ProvisionResult::Created(kv::stream_meta::StreamMeta {
                    config: config.merge(basin_defaults),
                    cipher: basin_meta.config.stream_cipher,
                    created_at: OffsetDateTime::now_utc(),
                    deleted_at: None,
                    creation_idempotency_key: None,
                }),
                None,
            ),
        };

        if matches!(&outcome, ProvisionResult::Noop(_)) {
            drop(txn);
            self.await_durable_seq(existing_seq.expect("noop implies existing meta"))
                .await?;
        } else {
            let meta = outcome.inner();

            txn.put(&stream_meta_key, kv::stream_meta::ser_value(meta))?;

            let stream_id = StreamId::new(&basin, &stream);

            if matches!(&outcome, ProvisionResult::Created(_)) {
                txn.put(
                    kv::stream_id_mapping::ser_key(stream_id),
                    kv::stream_id_mapping::ser_value(&basin, &stream),
                )?;
                txn.put(
                    kv::stream_tail_position::ser_key(stream_id),
                    kv::stream_tail_position::ser_value(StreamPosition::MIN),
                )?;
            }

            if let Some(min_age) = meta.config.delete_on_empty.min_age()
                && (matches!(&outcome, ProvisionResult::Created(_)) || prior_doe_min_age.is_none())
            {
                txn.put(
                    kv::stream_doe_deadline::ser_key(
                        kv::timestamp::TimestampSecs::after(doe_arm_delay(
                            meta.config.retention_policy.age().unwrap_or_default(),
                            min_age,
                        )),
                        stream_id,
                    ),
                    kv::stream_doe_deadline::ser_value(min_age),
                )?;
            }

            txn.commit().await?;
        }

        if let ProvisionResult::Updated(meta) = &outcome
            && let Some(client) = self.streamer_client_if_active(&basin, &stream)
        {
            client.advise_reconfig(meta.config.clone());
        }

        Ok(outcome.map(|meta| StreamInfo {
            name: stream,
            created_at: meta.created_at,
            deleted_at: None,
            cipher: meta.cipher,
        }))
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
    ) -> Result<StreamConfig, GetStreamConfigError> {
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
            return Err(StreamDeletionPendingError.into());
        }
        Ok(meta.config)
    }

    pub async fn reconfigure_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
        reconfig: StreamReconfiguration,
    ) -> Result<StreamConfig, ReconfigureStreamError> {
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;

        let meta_key = kv::stream_meta::ser_key(&basin, &stream);
        let (basin_meta, meta) = tokio::try_join!(
            db_txn_get(
                &txn,
                kv::basin_meta::ser_key(&basin),
                kv::basin_meta::deser_value,
            ),
            db_txn_get(&txn, &meta_key, kv::stream_meta::deser_value),
        )?;

        let basin_meta = basin_meta.ok_or_else(|| BasinNotFoundError {
            basin: basin.clone(),
        })?;
        if basin_meta.deleted_at.is_some() {
            return Err(BasinDeletionPendingError { basin }.into());
        }

        let mut meta = meta.ok_or_else(|| StreamNotFoundError {
            basin: basin.clone(),
            stream: stream.clone(),
        })?;

        if meta.deleted_at.is_some() {
            return Err(StreamDeletionPendingError.into());
        }

        let prior_doe_min_age = meta.config.delete_on_empty.min_age();

        meta.config = OptionalStreamConfig::from(meta.config)
            .reconfigure(reconfig)
            .merge(basin_meta.config.default_stream_config);

        txn.put(&meta_key, kv::stream_meta::ser_value(&meta))?;

        let stream_id = StreamId::new(&basin, &stream);
        if let Some(min_age) = meta.config.delete_on_empty.min_age()
            && prior_doe_min_age.is_none()
        {
            txn.put(
                kv::stream_doe_deadline::ser_key(
                    kv::timestamp::TimestampSecs::after(doe_arm_delay(
                        meta.config.retention_policy.age().unwrap_or_default(),
                        min_age,
                    )),
                    stream_id,
                ),
                kv::stream_doe_deadline::ser_value(min_age),
            )?;
        }

        txn.commit().await?;

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
        self.delete_stream_with_condition(basin, stream, TerminalTrimCondition::Always)
            .await
    }

    pub(super) async fn delete_stream_with_condition(
        &self,
        basin: BasinName,
        stream: StreamName,
        condition: TerminalTrimCondition,
    ) -> Result<(), DeleteStreamError> {
        let outcome = match self.streamer_client_guarded(&basin, &stream).await {
            Ok(client) => client.terminal_trim(condition).await?,
            Err(StreamerError::Storage(e)) => {
                return Err(DeleteStreamError::Storage(e));
            }
            Err(StreamerError::StreamNotFound(e)) => {
                return Err(DeleteStreamError::StreamNotFound(e));
            }
            Err(StreamerError::StreamDeletionPending(_)) => TerminalTrimOutcome::DeletionPending,
        };
        match outcome {
            TerminalTrimOutcome::DeletionPending => self.mark_stream_deleted(basin, stream).await,
            TerminalTrimOutcome::Ineligible => Ok(()),
        }
    }

    async fn mark_stream_deleted(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<(), DeleteStreamError> {
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
            txn.commit().await?;
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
