use s2_common::{
    basin::BasinName,
    config::{DeleteOnEmptyConfig, OptionalStreamConfig, StreamConfig, StreamReconfiguration},
    encryption::EncryptionAlgorithm,
    record::{NonZeroSeqNum, StreamPosition},
    resources::{Page, ProvisionMode, ProvisionResult, RequestToken},
    stream::{ListStreamsRequest, StreamInfo, StreamName},
};
use s2_storage::bash::Bash;
use slatedb::{
    DbTransaction, IsolationLevel,
    config::{DurabilityLevel, ScanOptions},
};
use time::OffsetDateTime;
use tracing::instrument;

use super::{
    Backend, doe, resolve_stream_config,
    store::{db_txn_commit_durable, db_txn_get, db_txn_get_with},
    streamer::{TerminalTrimCondition, TerminalTrimOutcome},
    timestamp::TimestampSecs,
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
        if self
            .db_get(kv::basin_meta::ser_key(&basin), kv::basin_meta::deser_value)
            .await?
            .is_none()
        {
            return Err(BasinNotFoundError { basin }.into());
        }
        Ok(self.scan_streams(basin, request).await?)
    }

    pub(super) async fn scan_streams(
        &self,
        basin: BasinName,
        request: ListStreamsRequest,
    ) -> Result<Page<StreamInfo>, StorageError> {
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
        self.provision_stream_with_check(basin, stream, config, mode, |_| Ok(()))
            .await
    }

    /// Check admission against the same basin snapshot used to create the stream.
    /// A concurrent change to that snapshot conflicts with the creation commit.
    pub(super) async fn provision_stream_with_check<E: From<ProvisionStreamError>>(
        &self,
        basin: BasinName,
        stream: StreamName,
        config: OptionalStreamConfig,
        mode: ProvisionMode,
        check_create: impl FnOnce(Option<EncryptionAlgorithm>) -> Result<(), E>,
    ) -> Result<ProvisionResult<StreamInfo>, E> {
        let txn = self
            .db
            .begin(IsolationLevel::SerializableSnapshot)
            .map_err(ProvisionStreamError::from)?;

        let Some(basin_meta) = db_txn_get(
            &txn,
            kv::basin_meta::ser_key(&basin),
            kv::basin_meta::deser_value,
        )
        .await
        .map_err(ProvisionStreamError::from)?
        else {
            return Err(ProvisionStreamError::from(BasinNotFoundError { basin }).into());
        };

        if basin_meta.deleted_at.is_some() {
            return Err(ProvisionStreamError::from(BasinDeletionPendingError { basin }).into());
        }

        let stream_meta_key = kv::stream_meta::ser_key(&basin, &stream);

        // Existence is decided from a Memory-level read; capture the row's
        // commit seq so exists-outcomes can await durability (see fn doc).
        let (existing_meta, existing_seq) = db_txn_get_with(&txn, &stream_meta_key, |entry| {
            Ok((kv::stream_meta::deser_value(entry.value)?, entry.seq))
        })
        .await
        .map_err(ProvisionStreamError::from)?
        .unzip();
        if existing_meta
            .as_ref()
            .is_some_and(|meta| meta.deleted_at.is_some())
            || has_terminal_trim(&txn, StreamId::new(&basin, &stream))
                .await
                .map_err(ProvisionStreamError::from)?
        {
            return Err(
                ProvisionStreamError::StreamDeletionPending(StreamDeletionPendingError).into(),
            );
        }

        if existing_meta.is_none() {
            check_create(basin_meta.config.stream_cipher)?;
        }

        let prior_doe = existing_meta
            .as_ref()
            .map(|meta| meta.config.delete_on_empty);
        let basin_defaults = basin_meta.config.default_stream_config;
        let outcome = match (existing_meta, mode) {
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
                    Err(
                        ProvisionStreamError::from(StreamAlreadyExistsError { basin, stream })
                            .into(),
                    )
                };
                drop(txn);
                self.await_durable_seq(existing_seq.expect("existing meta was read"))
                    .await
                    .map_err(ProvisionStreamError::from)?;
                return result;
            }
            (Some(existing), ProvisionMode::Ensure) => {
                let desired_config = resolve_stream_config(config, basin_defaults);
                let config_unchanged = existing.config == desired_config;
                let meta = kv::stream_meta::StreamMeta {
                    config: desired_config,
                    cipher: existing.cipher,
                    created_at: existing.created_at,
                    deleted_at: None,
                    creation_idempotency_key: existing.creation_idempotency_key,
                };
                if config_unchanged {
                    ProvisionResult::Noop(meta)
                } else {
                    ProvisionResult::Updated(meta)
                }
            }
            (None, ProvisionMode::CreateOnly { request_token }) => {
                let new_creation_idempotency_key = request_token
                    .as_ref()
                    .map(|req_token| creation_idempotency_key(req_token, &config));
                ProvisionResult::Created(kv::stream_meta::StreamMeta {
                    config: resolve_stream_config(config, basin_defaults),
                    cipher: basin_meta.config.stream_cipher,
                    created_at: OffsetDateTime::now_utc(),
                    deleted_at: None,
                    creation_idempotency_key: new_creation_idempotency_key,
                })
            }
            (None, ProvisionMode::Ensure) => {
                ProvisionResult::Created(kv::stream_meta::StreamMeta {
                    config: resolve_stream_config(config, basin_defaults),
                    cipher: basin_meta.config.stream_cipher,
                    created_at: OffsetDateTime::now_utc(),
                    deleted_at: None,
                    creation_idempotency_key: None,
                })
            }
        };

        if matches!(&outcome, ProvisionResult::Noop(_)) {
            drop(txn);
            self.await_durable_seq(existing_seq.expect("noop implies existing meta"))
                .await
                .map_err(ProvisionStreamError::from)?;
        } else {
            let meta = outcome.inner();

            txn.put_bytes(stream_meta_key, kv::stream_meta::ser_value(meta))
                .map_err(ProvisionStreamError::from)?;

            let stream_id = StreamId::new(&basin, &stream);

            if matches!(&outcome, ProvisionResult::Created(_)) {
                txn.put_bytes(
                    kv::stream_id_mapping::ser_key(stream_id),
                    kv::stream_id_mapping::ser_value(&basin, &stream),
                )
                .map_err(ProvisionStreamError::from)?;
                txn.put_bytes(
                    kv::stream_tail_position::ser_key(stream_id),
                    kv::stream_tail_position::ser_value(StreamPosition::MIN),
                )
                .map_err(ProvisionStreamError::from)?;
            }

            self.commit_stream_config(
                txn,
                basin.clone(),
                stream.clone(),
                meta.config.clone(),
                prior_doe,
            )
            .await
            .map_err(ProvisionStreamError::from)?;
        }

        Ok(outcome.map(|meta| StreamInfo {
            name: stream,
            created_at: meta.created_at,
            deleted_at: None,
            cipher: meta.cipher,
        }))
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
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot)?;

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

        if meta.deleted_at.is_some()
            || has_terminal_trim(&txn, StreamId::new(&basin, &stream)).await?
        {
            return Err(StreamDeletionPendingError.into());
        }

        let prior_doe = meta.config.delete_on_empty;

        meta.config = resolve_stream_config(
            OptionalStreamConfig::from(meta.config).reconfigure(reconfig),
            basin_meta.config.default_stream_config,
        );

        txn.put_bytes(meta_key, kv::stream_meta::ser_value(&meta))?;

        self.commit_stream_config(txn, basin, stream, meta.config.clone(), Some(prior_doe))
            .await?;

        Ok(meta.config)
    }

    async fn commit_stream_config(
        &self,
        txn: DbTransaction,
        basin: BasinName,
        stream: StreamName,
        config: StreamConfig,
        prior_doe: Option<DeleteOnEmptyConfig>,
    ) -> Result<(), StorageError> {
        let stream_id = StreamId::new(&basin, &stream);
        match (prior_doe, config.delete_on_empty.min_age()) {
            (None, Some(min_age)) => {
                doe::schedule(&txn, stream_id, TimestampSecs::after(min_age)).await?;
            }
            (Some(prior), Some(min_age)) if prior.min_age != min_age => {
                doe::schedule(&txn, stream_id, TimestampSecs::now()).await?;
            }
            (Some(prior), None) if prior.min_age().is_some() => {
                doe::clear(&txn, stream_id).await?;
            }
            _ => (),
        }

        let backend = self.clone();
        // Once a commit starts, cancellation must not discard its notification.
        tokio::spawn(async move {
            let seq = db_txn_commit_durable(txn)
                .await?
                .expect("stream metadata was written");
            backend.advise_stream_config(&basin, &stream, seq, config);
            Ok::<_, StorageError>(())
        })
        .await
        .expect("stream config commit task panicked")
    }

    #[instrument(ret, err, skip(self))]
    pub async fn delete_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<(), DeleteStreamError> {
        self.delete_stream_with_condition(basin, stream, TerminalTrimCondition::Always)
            .await
            .map(|_| ())
    }

    pub(super) async fn delete_stream_with_condition(
        &self,
        basin: BasinName,
        stream: StreamName,
        condition: TerminalTrimCondition,
    ) -> Result<TerminalTrimOutcome, DeleteStreamError> {
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
        if outcome == TerminalTrimOutcome::DeletionPending {
            self.mark_stream_deleted(basin, stream).await?;
        }
        Ok(outcome)
    }

    async fn mark_stream_deleted(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<(), DeleteStreamError> {
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot)?;
        // A delayed deletion request may resume after the trim worker has deleted the old
        // stream and the name has been reused. Only mark metadata when this
        // transaction also sees a terminal trim marker.
        if !has_terminal_trim(&txn, StreamId::new(&basin, &stream)).await? {
            let read_seq = txn.seqnum();
            drop(txn);
            // The trim worker may have removed the marker without flushing yet.
            // Wait for that removal to become durable before acknowledging deletion.
            self.await_durable_seq(read_seq).await?;
            return Ok(());
        }
        let meta_key = kv::stream_meta::ser_key(&basin, &stream);
        let (mut meta, seq) = db_txn_get_with(&txn, &meta_key, |entry| {
            Ok((kv::stream_meta::deser_value(entry.value)?, entry.seq))
        })
        .await?
        .ok_or_else(|| StreamNotFoundError {
            basin,
            stream: stream.clone(),
        })?;
        if meta.deleted_at.is_none() {
            meta.deleted_at = Some(OffsetDateTime::now_utc());
            txn.put_bytes(meta_key, kv::stream_meta::ser_value(&meta))?;
            db_txn_commit_durable(txn).await?;
        } else {
            // The terminal trim is durable, but the metadata marker may not be yet.
            drop(txn);
            self.await_durable_seq(seq).await?;
        }
        Ok(())
    }
}

async fn has_terminal_trim(txn: &DbTransaction, stream_id: StreamId) -> Result<bool, StorageError> {
    Ok(db_txn_get(
        txn,
        kv::stream_trim_point::ser_key(stream_id),
        kv::stream_trim_point::deser_value,
    )
    .await?
        == Some(..NonZeroSeqNum::MAX))
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
