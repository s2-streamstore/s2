use s2_common::{
    bash::Bash,
    types::{
        basin::{BasinInfo, BasinName, BasinState, ListBasinsRequest},
        config::{BasinConfig, BasinReconfiguration},
        resources::{CreateMode, ListItemsRequestParts, Page, RequestToken},
        stream::StreamNameStartAfter,
    },
};
use slatedb::{
    IsolationLevel,
    config::{DurabilityLevel, ScanOptions, WriteOptions},
};
use time::OffsetDateTime;

use super::{Backend, CreatedOrReconfigured, store::db_txn_get};
use crate::backend::{
    error::{
        BasinAlreadyExistsError, BasinDeletionPendingError, BasinNotFoundError, CreateBasinError,
        DeleteBasinError, GetBasinConfigError, ListBasinsError, ReconfigureBasinError,
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

        const SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
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
            let state = if meta.deleted_at.is_some() {
                BasinState::Deleting
            } else {
                BasinState::Active
            };
            basins.push(BasinInfo {
                name: basin,
                scope: None,
                state,
            });
        }
        Ok(Page::new(basins, has_more))
    }

    pub async fn create_basin(
        &self,
        basin: BasinName,
        config: BasinConfig,
        mode: CreateMode,
    ) -> Result<CreatedOrReconfigured<BasinInfo>, CreateBasinError> {
        let meta_key = kv::basin_meta::ser_key(&basin);

        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;

        let creation_idempotency_key = match &mode {
            CreateMode::CreateOnly(Some(req_token)) => {
                Some(creation_idempotency_key(req_token, &config))
            }
            _ => None,
        };

        let mut existing_created_at = None;
        if let Some(existing_meta) =
            db_txn_get(&txn, &meta_key, kv::basin_meta::deser_value).await?
        {
            if existing_meta.deleted_at.is_some() {
                return Err(BasinDeletionPendingError { basin }.into());
            }
            match mode {
                CreateMode::CreateOnly(_) => {
                    return if creation_idempotency_key.is_some()
                        && existing_meta.creation_idempotency_key == creation_idempotency_key
                    {
                        Ok(CreatedOrReconfigured::Created(BasinInfo {
                            name: basin,
                            scope: None,
                            state: BasinState::Active,
                        }))
                    } else {
                        Err(BasinAlreadyExistsError { basin }.into())
                    };
                }
                CreateMode::CreateOrReconfigure => {
                    existing_created_at = Some(existing_meta.created_at);
                }
            }
        }

        let created_at = existing_created_at.unwrap_or_else(OffsetDateTime::now_utc);

        let meta = kv::basin_meta::BasinMeta {
            config,
            created_at,
            deleted_at: None,
            creation_idempotency_key,
        };

        txn.put(&meta_key, kv::basin_meta::ser_value(&meta))?;

        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        txn.commit_with_options(&WRITE_OPTS).await?;

        let info = BasinInfo {
            name: basin,
            scope: None,
            state: BasinState::Active,
        };

        Ok(if existing_created_at.is_some() {
            CreatedOrReconfigured::Reconfigured(info)
        } else {
            CreatedOrReconfigured::Created(info)
        })
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
        }
        Ok(())
    }
}

fn creation_idempotency_key(req_token: &RequestToken, config: &BasinConfig) -> Bash {
    Bash::new(&[
        req_token.as_bytes(),
        &serde_json::to_vec(&s2_api::v1::config::BasinConfig::from(config.clone()))
            .expect("serializable"),
    ])
}
