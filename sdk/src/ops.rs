use futures::StreamExt;

#[cfg(feature = "_hidden")]
use crate::client::Connect;
use crate::{
    api::{AccountClient, BaseClient, BasinClient},
    producer::{Producer, ProducerConfig},
    session::{self, AppendSession, AppendSessionConfig},
    types::{
        AccessTokenId, AccessTokenInfo, AppendAck, AppendInput, BasinConfig, BasinInfo, BasinName,
        BasinState, CreateBasinInput, CreateStreamInput, DeleteBasinInput, DeleteStreamInput,
        GetAccountMetricsInput, GetBasinMetricsInput, GetStreamMetricsInput, IssueAccessTokenInput,
        ListAccessTokensInput, ListAllAccessTokensInput, ListAllBasinsInput, ListAllStreamsInput,
        ListBasinsInput, ListStreamsInput, Metric, Page, ReadBatch, ReadInput,
        ReconfigureBasinInput, ReconfigureStreamInput, S2Config, S2Error, StreamConfig, StreamInfo,
        StreamName, StreamPosition, Streaming,
    },
};

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
        let response = self.client.list_basins(input.into()).await?;
        Ok(Page::new(
            response
                .basins
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
            response.has_more,
        ))
    }

    /// List all basins, paginating automatically.
    pub fn list_all_basins(&self, input: ListAllBasinsInput) -> Streaming<BasinInfo> {
        let s2 = self.clone();
        let prefix = input.prefix;
        let start_after = input.start_after;
        let include_deleted = input.include_deleted;
        let mut input = ListBasinsInput::new()
            .with_prefix(prefix)
            .with_start_after(start_after);
        Box::pin(async_stream::try_stream! {
            loop {
                let page = s2.list_basins(input.clone()).await?;

                let start_after = page.values.last().map(|info| info.name.clone().into());
                for info in page.values {
                    if !include_deleted && info.state == BasinState::Deleting {
                        continue;
                    }
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
        Ok(info.into())
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
        let response = self.client.list_streams(input.into()).await?;
        Ok(Page::new(
            response
                .streams
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            response.has_more,
        ))
    }

    /// List all streams, paginating automatically.
    pub fn list_all_streams(&self, input: ListAllStreamsInput) -> Streaming<StreamInfo> {
        let basin = self.clone();
        let prefix = input.prefix;
        let start_after = input.start_after;
        let include_deleted = input.include_deleted;
        let mut input = ListStreamsInput::new()
            .with_prefix(prefix)
            .with_start_after(start_after);
        Box::pin(async_stream::try_stream! {
            loop {
                let page = basin.list_streams(input.clone()).await?;

                let start_after = page.values.last().map(|info| info.name.clone().into());
                for info in page.values {
                    if !include_deleted && info.deleted_at.is_some() {
                        continue;
                    }
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
        let retry_enabled = self
            .client
            .config
            .retry
            .append_retry_policy
            .is_compliant(&input);
        let ack = self
            .client
            .append(&self.name, input.into(), retry_enabled)
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
