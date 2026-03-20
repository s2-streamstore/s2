use futures::StreamExt;

#[cfg(feature = "_hidden")]
use crate::client::Connect;
#[cfg(feature = "_hidden")]
use crate::types::{
    CreateOrReconfigureBasinInput, CreateOrReconfigureStreamInput, CreateOrReconfigured,
};
use crate::{
    api::{AccountClient, BaseClient, BasinClient},
    producer::{Producer, ProducerConfig},
    session::{self, AppendSession, AppendSessionConfig},
    types::{
        AccessTokenId, AccessTokenInfo, AppendAck, AppendInput, BasinConfig, BasinInfo, BasinName,
        BasinNameStartAfter, CreateBasinInput, CreateStreamInput, DeleteBasinInput,
        DeleteStreamInput, GetAccountMetricsInput, GetBasinMetricsInput, GetStreamMetricsInput,
        IssueAccessTokenInput, ListAccessTokensInput, ListAllAccessTokensInput, ListAllBasinsInput,
        ListAllStreamsInput, ListBasinsInput, ListStreamsInput, Metric, Page, ReadBatch, ReadInput,
        ReconfigureBasinInput, ReconfigureStreamInput, S2Config, S2Error, StreamConfig, StreamInfo,
        StreamName, StreamNameStartAfter, StreamPosition, Streaming,
    },
};

fn filter_basin_infos(values: Vec<BasinInfo>, include_deleted: bool) -> Vec<BasinInfo> {
    if include_deleted {
        values
    } else {
        values
            .into_iter()
            .filter(|info| info.deleted_at.is_none())
            .collect()
    }
}

fn basin_page_values_and_start_after(
    values: Vec<BasinInfo>,
    include_deleted: bool,
) -> (Vec<BasinInfo>, Option<BasinNameStartAfter>) {
    let start_after = values.last().map(|info| info.name.clone().into());
    (filter_basin_infos(values, include_deleted), start_after)
}

fn filter_stream_infos(values: Vec<StreamInfo>, include_deleted: bool) -> Vec<StreamInfo> {
    if include_deleted {
        values
    } else {
        values
            .into_iter()
            .filter(|info| info.deleted_at.is_none())
            .collect()
    }
}

fn stream_page_values_and_start_after(
    values: Vec<StreamInfo>,
    include_deleted: bool,
) -> (Vec<StreamInfo>, Option<StreamNameStartAfter>) {
    let start_after = values.last().map(|info| info.name.clone().into());
    (filter_stream_infos(values, include_deleted), start_after)
}

#[derive(Debug, Clone)]
/// An S2 account.
pub struct S2 {
    client: AccountClient,
}

impl S2 {
    /// Create a new [`S2`].
    pub fn new(config: S2Config) -> Result<Self, S2Error> {
        let base_client = BaseClient::init(&config)?;
        Ok(Self {
            client: AccountClient::init(config, base_client),
        })
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub fn new_with_connector<C>(config: S2Config, connector: C) -> Result<Self, S2Error>
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        let base_client = BaseClient::init_with_connector(&config, connector)?;
        Ok(Self {
            client: AccountClient::init(config, base_client),
        })
    }

    /// Get an [`S2Basin`].
    pub fn basin(&self, name: BasinName) -> S2Basin {
        S2Basin {
            client: self.client.basin_client(name),
        }
    }

    /// List a page of basins.
    ///
    /// See [`list_all_basins`](crate::S2::list_all_basins) for automatic pagination.
    pub async fn list_basins(&self, input: ListBasinsInput) -> Result<Page<BasinInfo>, S2Error> {
        let ListBasinsInput {
            prefix,
            mut start_after,
            limit,
            include_deleted,
        } = input;
        let page_limit = limit.unwrap_or(1000);
        if page_limit == 0 {
            return Ok(Page::new(Vec::new(), false));
        }

        let mut values = Vec::with_capacity(page_limit);
        loop {
            let response = self
                .client
                .list_basins(
                    ListBasinsInput::new()
                        .with_prefix(prefix.clone())
                        .with_start_after(start_after.clone())
                        .with_limit(page_limit - values.len())
                        .into(),
                )
                .await?;
            let raw_values: Vec<BasinInfo> = response
                .basins
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?;
            let (page_values, next_start_after) =
                basin_page_values_and_start_after(raw_values, include_deleted);
            values.extend(page_values);

            if values.len() == page_limit {
                return Ok(Page::new(values, response.has_more));
            }

            if response.has_more
                && let Some(next_start_after) = next_start_after
            {
                start_after = next_start_after;
            } else {
                return Ok(Page::new(values, false));
            }
        }
    }

    /// List all basins, paginating automatically.
    pub fn list_all_basins(&self, input: ListAllBasinsInput) -> Streaming<BasinInfo> {
        let s2 = self.clone();
        let prefix = input.prefix;
        let start_after = input.start_after;
        let include_deleted = input.include_deleted;
        let mut input = ListBasinsInput::new()
            .with_prefix(prefix)
            .with_start_after(start_after)
            .with_include_deleted(include_deleted);
        Box::pin(async_stream::try_stream! {
            loop {
                let page = s2.list_basins(input.clone()).await?;
                let start_after = page.values.last().map(|info| info.name.clone().into());

                for info in page.values {
                    yield info;
                }

                if page.has_more && let Some(start_after) = start_after {
                    input = input.with_start_after(start_after);
                } else {
                    break;
                }
            }
        })
    }

    /// Create a basin.
    pub async fn create_basin(&self, input: CreateBasinInput) -> Result<BasinInfo, S2Error> {
        let (request, idempotency_token) = input.into();
        let info = self.client.create_basin(request, idempotency_token).await?;
        Ok(info.try_into()?)
    }

    /// Create or reconfigure a basin.
    ///
    /// Creates the basin if it doesn't exist, or reconfigures it to match the provided
    /// configuration if it does. Uses HTTP PUT semantics — always idempotent.
    ///
    /// Returns [`CreateOrReconfigured::Created`] with the basin info if the basin was newly
    /// created, or [`CreateOrReconfigured::Reconfigured`] if it already existed.
    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub async fn create_or_reconfigure_basin(
        &self,
        input: CreateOrReconfigureBasinInput,
    ) -> Result<CreateOrReconfigured<BasinInfo>, S2Error> {
        let (name, request) = input.into();
        let (was_created, info) = self
            .client
            .create_or_reconfigure_basin(name, request)
            .await?;
        let info = info.try_into()?;
        Ok(if was_created {
            CreateOrReconfigured::Created(info)
        } else {
            CreateOrReconfigured::Reconfigured(info)
        })
    }

    /// Get basin configuration.
    pub async fn get_basin_config(&self, name: BasinName) -> Result<BasinConfig, S2Error> {
        let config = self.client.get_basin_config(name).await?;
        Ok(config.into())
    }

    /// Delete a basin.
    pub async fn delete_basin(&self, input: DeleteBasinInput) -> Result<(), S2Error> {
        Ok(self
            .client
            .delete_basin(input.name, input.ignore_not_found)
            .await?)
    }

    /// Reconfigure a basin.
    pub async fn reconfigure_basin(
        &self,
        input: ReconfigureBasinInput,
    ) -> Result<BasinConfig, S2Error> {
        let config = self
            .client
            .reconfigure_basin(input.name, input.config.into())
            .await?;
        Ok(config.into())
    }

    /// List a page of access tokens.
    ///
    /// See [`list_all_access_tokens`](crate::S2::list_all_access_tokens) for automatic pagination.
    pub async fn list_access_tokens(
        &self,
        input: ListAccessTokensInput,
    ) -> Result<Page<AccessTokenInfo>, S2Error> {
        let response = self.client.list_access_tokens(input.into()).await?;
        Ok(Page::new(
            response
                .access_tokens
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            response.has_more,
        ))
    }

    /// List all access tokens, paginating automatically.
    pub fn list_all_access_tokens(
        &self,
        input: ListAllAccessTokensInput,
    ) -> Streaming<AccessTokenInfo> {
        let s2 = self.clone();
        let prefix = input.prefix;
        let start_after = input.start_after;
        let mut input = ListAccessTokensInput::new()
            .with_prefix(prefix)
            .with_start_after(start_after);
        Box::pin(async_stream::try_stream! {
            loop {
                let page = s2.list_access_tokens(input.clone()).await?;

                let start_after = page.values.last().map(|info| info.id.clone().into());
                for info in page.values {
                    yield info;
                }

                if page.has_more && let Some(start_after) = start_after {
                    input = input.with_start_after(start_after);
                } else {
                    break;
                }
            }
        })
    }

    /// Issue an access token.
    pub async fn issue_access_token(
        &self,
        input: IssueAccessTokenInput,
    ) -> Result<String, S2Error> {
        let response = self.client.issue_access_token(input.into()).await?;
        Ok(response.access_token)
    }

    /// Revoke an access token.
    pub async fn revoke_access_token(&self, id: AccessTokenId) -> Result<(), S2Error> {
        Ok(self.client.revoke_access_token(id).await?)
    }

    /// Get account metrics.
    pub async fn get_account_metrics(
        &self,
        input: GetAccountMetricsInput,
    ) -> Result<Vec<Metric>, S2Error> {
        let response = self.client.get_account_metrics(input.into()).await?;
        Ok(response.values.into_iter().map(Into::into).collect())
    }

    /// Get basin metrics.
    pub async fn get_basin_metrics(
        &self,
        input: GetBasinMetricsInput,
    ) -> Result<Vec<Metric>, S2Error> {
        let (name, request) = input.into();
        let response = self.client.get_basin_metrics(name, request).await?;
        Ok(response.values.into_iter().map(Into::into).collect())
    }

    /// Get stream metrics.
    pub async fn get_stream_metrics(
        &self,
        input: GetStreamMetricsInput,
    ) -> Result<Vec<Metric>, S2Error> {
        let (basin_name, stream_name, request) = input.into();
        let response = self
            .client
            .get_stream_metrics(basin_name, stream_name, request)
            .await?;
        Ok(response.values.into_iter().map(Into::into).collect())
    }
}

#[derive(Debug, Clone)]
/// A basin in an S2 account.
///
/// See [`S2::basin`].
pub struct S2Basin {
    client: BasinClient,
}

impl S2Basin {
    /// Get an [`S2Stream`].
    pub fn stream(&self, name: StreamName) -> S2Stream {
        S2Stream {
            client: self.client.clone(),
            name,
        }
    }

    /// List a page of streams.
    ///
    /// See [`list_all_streams`](crate::S2Basin::list_all_streams) for automatic pagination.
    pub async fn list_streams(&self, input: ListStreamsInput) -> Result<Page<StreamInfo>, S2Error> {
        let ListStreamsInput {
            prefix,
            mut start_after,
            limit,
            include_deleted,
        } = input;
        let page_limit = limit.unwrap_or(1000);
        if page_limit == 0 {
            return Ok(Page::new(Vec::new(), false));
        }

        let mut values = Vec::with_capacity(page_limit);
        loop {
            let response = self
                .client
                .list_streams(
                    ListStreamsInput::new()
                        .with_prefix(prefix.clone())
                        .with_start_after(start_after.clone())
                        .with_limit(page_limit - values.len())
                        .into(),
                )
                .await?;
            let raw_values: Vec<StreamInfo> = response
                .streams
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?;
            let (page_values, next_start_after) =
                stream_page_values_and_start_after(raw_values, include_deleted);
            values.extend(page_values);

            if values.len() == page_limit {
                return Ok(Page::new(values, response.has_more));
            }

            if response.has_more
                && let Some(next_start_after) = next_start_after
            {
                start_after = next_start_after;
            } else {
                return Ok(Page::new(values, false));
            }
        }
    }

    /// List all streams, paginating automatically.
    pub fn list_all_streams(&self, input: ListAllStreamsInput) -> Streaming<StreamInfo> {
        let basin = self.clone();
        let prefix = input.prefix;
        let start_after = input.start_after;
        let include_deleted = input.include_deleted;
        let mut input = ListStreamsInput::new()
            .with_prefix(prefix)
            .with_start_after(start_after)
            .with_include_deleted(include_deleted);
        Box::pin(async_stream::try_stream! {
            loop {
                let page = basin.list_streams(input.clone()).await?;
                let start_after = page.values.last().map(|info| info.name.clone().into());

                for info in page.values {
                    yield info;
                }

                if page.has_more && let Some(start_after) = start_after {
                    input = input.with_start_after(start_after);
                } else {
                    break;
                }
            }
        })
    }

    /// Create a stream.
    pub async fn create_stream(&self, input: CreateStreamInput) -> Result<StreamInfo, S2Error> {
        let (request, idempotency_token) = input.into();
        let info = self
            .client
            .create_stream(request, idempotency_token)
            .await?;
        Ok(info.try_into()?)
    }

    /// Create or reconfigure a stream.
    ///
    /// Creates the stream if it doesn't exist, or reconfigures it to match the provided
    /// configuration if it does. Uses HTTP PUT semantics — always idempotent.
    ///
    /// Returns [`CreateOrReconfigured::Created`] with the stream info if the stream was newly
    /// created, or [`CreateOrReconfigured::Reconfigured`] if it already existed.
    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub async fn create_or_reconfigure_stream(
        &self,
        input: CreateOrReconfigureStreamInput,
    ) -> Result<CreateOrReconfigured<StreamInfo>, S2Error> {
        let (name, config) = input.into();
        let (was_created, info) = self
            .client
            .create_or_reconfigure_stream(name, config)
            .await?;
        let info = info.try_into()?;
        Ok(if was_created {
            CreateOrReconfigured::Created(info)
        } else {
            CreateOrReconfigured::Reconfigured(info)
        })
    }

    /// Get stream configuration.
    pub async fn get_stream_config(&self, name: StreamName) -> Result<StreamConfig, S2Error> {
        let config = self.client.get_stream_config(name).await?;
        Ok(config.into())
    }

    /// Delete a stream.
    pub async fn delete_stream(&self, input: DeleteStreamInput) -> Result<(), S2Error> {
        Ok(self
            .client
            .delete_stream(input.name, input.ignore_not_found)
            .await?)
    }

    /// Reconfigure a stream.
    pub async fn reconfigure_stream(
        &self,
        input: ReconfigureStreamInput,
    ) -> Result<StreamConfig, S2Error> {
        let config = self
            .client
            .reconfigure_stream(input.name, input.config.into())
            .await?;
        Ok(config.into())
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::{basin_page_values_and_start_after, stream_page_values_and_start_after};
    use crate::types::{BasinInfo, BasinName, S2DateTime, StreamInfo, StreamName};

    fn timestamp() -> S2DateTime {
        OffsetDateTime::UNIX_EPOCH
            .try_into()
            .expect("unix epoch is valid RFC3339")
    }

    #[test]
    fn basin_pagination_cursor_uses_last_raw_item() {
        let basin_name: BasinName = "basin-0001".parse().expect("valid basin name");
        let (values, start_after) = basin_page_values_and_start_after(
            vec![BasinInfo {
                name: basin_name.clone(),
                scope: None,
                created_at: timestamp(),
                deleted_at: Some(timestamp()),
            }],
            false,
        );

        assert!(values.is_empty());
        assert_eq!(
            start_after,
            Some(basin_name.as_ref().parse().expect("valid start after"))
        );
    }

    #[test]
    fn stream_pagination_cursor_uses_last_raw_item() {
        let stream_name: StreamName = "events".parse().expect("valid stream name");
        let (values, start_after) = stream_page_values_and_start_after(
            vec![StreamInfo {
                name: stream_name.clone(),
                created_at: timestamp(),
                deleted_at: Some(timestamp()),
            }],
            false,
        );

        assert!(values.is_empty());
        assert_eq!(
            start_after,
            Some(stream_name.as_ref().parse().expect("valid start after"))
        );
    }
}

#[derive(Debug, Clone)]
/// A stream in an S2 basin.
///
/// See [`S2Basin::stream`].
pub struct S2Stream {
    client: BasinClient,
    name: StreamName,
}

impl S2Stream {
    /// Check tail position.
    pub async fn check_tail(&self) -> Result<StreamPosition, S2Error> {
        let response = self.client.check_tail(&self.name).await?;
        Ok(response.tail.into())
    }

    /// Append records.
    pub async fn append(&self, input: AppendInput) -> Result<AppendAck, S2Error> {
        let ack = self
            .client
            .append(
                &self.name,
                input.into(),
                self.client.config.retry.append_retry_policy,
            )
            .await?;
        Ok(ack.into())
    }

    /// Read records.
    pub async fn read(&self, input: ReadInput) -> Result<ReadBatch, S2Error> {
        let batch = self
            .client
            .read(&self.name, input.start.into(), input.stop.into())
            .await?;
        Ok(ReadBatch::from_api(batch, input.ignore_command_records))
    }

    /// Create an append session for submitting [`AppendInput`]s.
    pub fn append_session(&self, config: AppendSessionConfig) -> AppendSession {
        AppendSession::new(self.client.clone(), self.name.clone(), config)
    }

    /// Create a producer for submitting individual [`AppendRecord`](crate::types::AppendRecord)s.
    pub fn producer(&self, config: ProducerConfig) -> Producer {
        Producer::new(self.client.clone(), self.name.clone(), config)
    }

    /// Create a read session.
    pub async fn read_session(&self, input: ReadInput) -> Result<Streaming<ReadBatch>, S2Error> {
        let batches = session::read_session(
            self.client.clone(),
            self.name.clone(),
            input.start.into(),
            input.stop.into(),
            input.ignore_command_records,
        )
        .await?;
        Ok(Box::pin(batches.map(|res| match res {
            Ok(batch) => Ok(batch),
            Err(err) => Err(err.into()),
        })))
    }
}
