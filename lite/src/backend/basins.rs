use s2_common::{
    bash::Bash,
    types::{
        basin::{BasinInfo, BasinName, ListBasinsRequest},
        config::{BasinConfig, BasinReconfiguration},
        resources::{ListItemsRequestParts, Page, ProvisionMode, ProvisionResult, RequestToken},
        stream::StreamNameStartAfter,
    },
};
use slatedb::{
    IsolationLevel, IterationOrder,
    config::{DurabilityLevel, ScanOptions, WriteOptions},
};
use time::OffsetDateTime;

use super::{Backend, bgtasks::BgtaskTrigger, store::db_txn_get};
use crate::backend::{
    error::{
        BasinAlreadyExistsError, BasinDeletionPendingError, BasinNotFoundError, DeleteBasinError,
        GetBasinConfigError, ListBasinsError, ProvisionBasinError, ReconfigureBasinError,
    },
    kv,
};

impl Backend {
    pub async fn list_basins(
        &self,
        request: ListBasinsRequest,
    ) -> Result<Page<BasinInfo>, ListBasinsError> {
        let ListItemsRequestParts {
            prefix,
            start_after,
            limit,
        } = request.into();

        let key_range = kv::basin_meta::ser_key_range(&prefix, &start_after);
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

        let mut basins = Vec::with_capacity(limit.as_usize());
        let mut has_more = false;
        while let Some(kv) = it.next().await? {
            let basin = kv::basin_meta::deser_key(kv.key)?;
            assert!(basin.as_ref() > start_after.as_ref());
            assert!(basin.as_ref() >= prefix.as_ref());
            if basins.len() == limit.as_usize() {
                has_more = true;
                break;
            }
            let meta = kv::basin_meta::deser_value(kv.value)?;
            basins.push(BasinInfo {
                name: basin,
                scope: None,
                created_at: meta.created_at,
                deleted_at: meta.deleted_at,
            });
        }
        Ok(Page::new(basins, has_more))
    }

    pub async fn provision_basin(
        &self,
        basin: BasinName,
        config: BasinConfig,
        mode: ProvisionMode,
    ) -> Result<ProvisionResult<BasinInfo>, ProvisionBasinError> {
        let meta_key = kv::basin_meta::ser_key(&basin);

        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;

        let existing_meta = db_txn_get(&txn, &meta_key, kv::basin_meta::deser_value).await?;
        if let Some(existing_meta) = &existing_meta
            && existing_meta.deleted_at.is_some()
        {
            return Err(BasinDeletionPendingError { basin }.into());
        }

        let (outcome, should_write) = match (existing_meta, mode) {
            (Some(existing), ProvisionMode::CreateOnly { request_token }) => {
                let new_creation_idempotency_key = request_token
                    .as_ref()
                    .map(|req_token| creation_idempotency_key(req_token, &config));
                return if new_creation_idempotency_key.is_some()
                    && existing.creation_idempotency_key == new_creation_idempotency_key
                {
                    Ok(ProvisionResult::Created(BasinInfo {
                        name: basin,
                        scope: None,
                        created_at: existing.created_at,
                        deleted_at: None,
                    }))
                } else {
                    Err(BasinAlreadyExistsError { basin }.into())
                };
            }
            (Some(existing), ProvisionMode::Ensure) => {
                let should_write = existing.config != config;
                (
                    ProvisionResult::Updated(kv::basin_meta::BasinMeta {
                        config,
                        created_at: existing.created_at,
                        deleted_at: None,
                        creation_idempotency_key: existing.creation_idempotency_key,
                    }),
                    should_write,
                )
            }
            (None, ProvisionMode::CreateOnly { request_token }) => {
                let new_creation_idempotency_key = request_token
                    .as_ref()
                    .map(|req_token| creation_idempotency_key(req_token, &config));
                (
                    ProvisionResult::Created(kv::basin_meta::BasinMeta {
                        config,
                        created_at: OffsetDateTime::now_utc(),
                        deleted_at: None,
                        creation_idempotency_key: new_creation_idempotency_key,
                    }),
                    true,
                )
            }
            (None, ProvisionMode::Ensure) => (
                ProvisionResult::Created(kv::basin_meta::BasinMeta {
                    config,
                    created_at: OffsetDateTime::now_utc(),
                    deleted_at: None,
                    creation_idempotency_key: None,
                }),
                true,
            ),
        };

        if should_write {
            let meta = outcome.inner();
            txn.put(&meta_key, kv::basin_meta::ser_value(meta))?;

            static WRITE_OPTS: WriteOptions = WriteOptions {
                await_durable: true,
            };
            txn.commit_with_options(&WRITE_OPTS).await?;
        }

        Ok(outcome.map(|meta| BasinInfo {
            name: basin,
            scope: None,
            created_at: meta.created_at,
            deleted_at: None,
        }))
    }

    pub async fn get_basin_config(
        &self,
        basin: BasinName,
    ) -> Result<BasinConfig, GetBasinConfigError> {
        let Some(meta) = self
            .db_get(kv::basin_meta::ser_key(&basin), kv::basin_meta::deser_value)
            .await?
        else {
            return Err(BasinNotFoundError { basin }.into());
        };
        Ok(meta.config)
    }

    pub async fn reconfigure_basin(
        &self,
        basin: BasinName,
        reconfig: BasinReconfiguration,
    ) -> Result<BasinConfig, ReconfigureBasinError> {
        let meta_key = kv::basin_meta::ser_key(&basin);

        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;

        let Some(mut meta) = db_txn_get(&txn, &meta_key, kv::basin_meta::deser_value).await? else {
            return Err(BasinNotFoundError { basin }.into());
        };

        if meta.deleted_at.is_some() {
            return Err(BasinDeletionPendingError { basin }.into());
        }

        meta.config = meta.config.reconfigure(reconfig);

        txn.put(&meta_key, kv::basin_meta::ser_value(&meta))?;

        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        txn.commit_with_options(&WRITE_OPTS).await?;

        Ok(meta.config)
    }

    pub async fn delete_basin(&self, basin: BasinName) -> Result<(), DeleteBasinError> {
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
        let meta_key = kv::basin_meta::ser_key(&basin);
        let Some(mut meta) = db_txn_get(&txn, &meta_key, kv::basin_meta::deser_value).await? else {
            return Err(BasinNotFoundError { basin }.into());
        };
        if meta.deleted_at.is_none() {
            meta.deleted_at = Some(OffsetDateTime::now_utc());
            txn.put(&meta_key, kv::basin_meta::ser_value(&meta))?;
            txn.put(
                kv::basin_deletion_pending::ser_key(&basin),
                kv::basin_deletion_pending::ser_value(&StreamNameStartAfter::default()),
            )?;
            static WRITE_OPTS: WriteOptions = WriteOptions {
                await_durable: true,
            };
            txn.commit_with_options(&WRITE_OPTS).await?;
            self.bgtask_trigger(BgtaskTrigger::BasinDeletion);
        }
        Ok(())
    }
}

fn creation_idempotency_key(req_token: &RequestToken, config: &BasinConfig) -> Bash {
    Bash::length_prefixed(&[
        req_token.as_bytes(),
        &serde_json::to_vec(&s2_api::v1::config::BasinConfig::from(config.clone()))
            .expect("serializable"),
    ])
}
