#[cfg(feature = "_hidden")]
use crate::client::Connect;
use crate::{
    api::{AccountClient, BaseClient, BasinClient},
    error::{AppendError, ClientClosedError, ErrorContext, ProtocolError, ReadError, RequestError},
    producer::{Producer, ProducerConfig},
    session::{
        self, AppendSession, AppendSessionConfig, ReadBatchSession, ReadSession, StreamHeaders,
    },
    types::{
        AccessTokenId, AccessTokenInfo, AppendAck, AppendInput, BasinConfig, BasinInfo, BasinName,
        CreateBasinInput, CreateNetworkPolicyInput, CreateStreamInput, EncryptionKey,
        EnsureBasinInput, EnsureOutput, EnsureStreamInput, GetAccountMetricsInput,
        GetBasinMetricsInput, GetStreamMetricsInput, IssueAccessTokenInput, ListAccessTokensInput,
        ListAllAccessTokensInput, ListAllBasinsInput, ListAllNetworkPoliciesInput,
        ListAllStreamsInput, ListBasinsInput, ListNetworkPoliciesInput, ListStreamsInput,
        LocationInfo, LocationName, Metric, NetworkPolicyInfo, NetworkPolicySelector, Page,
        ReadBatch, ReadInput, ReadSessionConfig, ReconfigureBasinInput, ReconfigureStreamInput,
        S2Config, StreamConfig, StreamInfo, StreamName, StreamPosition, Streaming, ValidationError,
        idempotency_token,
    },
};

fn response_protocol_error(err: ValidationError, ctx: ErrorContext) -> RequestError {
    RequestError::Protocol(ProtocolError::new(err.0, ctx))
}

fn init_error(err: RequestError, op: &'static str) -> RequestError {
    let ctx = ErrorContext::account(op, true);
    match err {
        RequestError::Validation(e) => {
            RequestError::Validation(ValidationError(ctx.format_string(&e.0)))
        }
        other => other,
    }
}

#[derive(Debug, Clone)]
/// An S2 account.
pub struct S2 {
    client: AccountClient,
}

impl S2 {
    /// Create a new [`S2`].
    pub fn new(config: S2Config) -> Result<Self, RequestError> {
        Self::init_with_op(config, "S2::new")
    }

    /// Create a new [`S2`] from environment variables.
    ///
    /// Reads `S2_ACCESS_TOKEN`, and optionally `S2_ACCOUNT_ENDPOINT` and `S2_BASIN_ENDPOINT`
    /// (empty endpoint variables are treated as unset; if one is set, both must be set).
    pub fn from_env() -> Result<Self, RequestError> {
        let config = S2Config::from_env()
            .map_err(|e| init_error(RequestError::Validation(e), "S2::from_env"))?;
        Self::init_with_op(config, "S2::from_env")
    }

    fn init_with_op(config: S2Config, op: &'static str) -> Result<Self, RequestError> {
        let base_client = BaseClient::init(&config).map_err(|e| init_error(e.into(), op))?;
        Ok(Self {
            client: AccountClient::init(config, base_client),
        })
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub fn new_with_connector<C>(config: S2Config, connector: C) -> Result<Self, RequestError>
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        let base_client = BaseClient::init_with_connector(&config, connector)
            .map_err(|e| init_error(e.into(), "S2::new"))?;
        Ok(Self {
            client: AccountClient::init(config, base_client),
        })
    }

    /// Close the client, aborting all active sessions and in-flight requests and terminating all
    /// connections without waiting for the server.
    ///
    /// Repeated calls are idempotent. After `close()`, any new operation on this client or handles
    /// derived from it fails immediately with [`ClientClosedError`].
    ///
    /// Dropping an [`S2`] without calling `close()` keeps it alive while any handle or session
    /// opened from it remains open.
    pub fn close(&self) {
        self.client.close();
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
    pub async fn list_basins(
        &self,
        input: ListBasinsInput,
    ) -> Result<Page<BasinInfo>, RequestError> {
        let ctx = ErrorContext::account("list_basins", true);
        let response = self.client.list_basins(input.into()).await?;
        Ok(Page::new(
            response
                .basins
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| response_protocol_error(e, ctx))?,
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

    /// Create a basin.
    pub async fn create_basin(&self, input: CreateBasinInput) -> Result<BasinInfo, RequestError> {
        let ctx = ErrorContext::basin("create_basin", input.name.as_ref(), false);
        let info = self
            .client
            .create_basin(input.into(), idempotency_token())
            .await?;
        info.try_into().map_err(|e| response_protocol_error(e, ctx))
    }

    /// Ensure a basin.
    ///
    /// If the basin doesn't exist, creates the basin with specified configuration.
    ///
    /// If the basin already exists:
    /// - Its configuration is updated to the specified configuration, if different.
    /// - Its configuration is unchanged, if the specified configuration is same.
    pub async fn ensure_basin(
        &self,
        input: EnsureBasinInput,
    ) -> Result<EnsureOutput<BasinInfo>, RequestError> {
        let ctx = ErrorContext::basin("ensure_basin", input.name.as_ref(), false);
        let (name, request) = input.into();
        Ok(self
            .client
            .ensure_basin(name, request)
            .await?
            .try_map(BasinInfo::try_from)
            .map_err(|e| response_protocol_error(e, ctx))?
            .into())
    }

    /// Get basin configuration.
    pub async fn get_basin_config(&self, name: BasinName) -> Result<BasinConfig, RequestError> {
        let config = self.client.get_basin_config(name).await?;
        Ok(config.into())
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub async fn get_basin_config_api(
        &self,
        name: BasinName,
    ) -> Result<s2_api::v1::config::BasinConfig, RequestError> {
        Ok(self.client.get_basin_config(name).await?)
    }

    /// Delete a basin.
    ///
    /// Succeeds if the basin is already being deleted or does not exist.
    pub async fn delete_basin(&self, name: BasinName) -> Result<(), RequestError> {
        Ok(self.client.delete_basin(name).await?)
    }

    /// Reconfigure a basin.
    pub async fn reconfigure_basin(
        &self,
        input: ReconfigureBasinInput,
    ) -> Result<BasinConfig, RequestError> {
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
    ) -> Result<Page<AccessTokenInfo>, RequestError> {
        let ctx = ErrorContext::account("list_access_tokens", true);
        let response = self.client.list_access_tokens(input.into()).await?;
        Ok(Page::new(
            response
                .access_tokens
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| response_protocol_error(e, ctx))?,
            response.has_more,
        ))
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub async fn list_access_tokens_api(
        &self,
        input: ListAccessTokensInput,
    ) -> Result<s2_api::v1::access::ListAccessTokensResponse, RequestError> {
        Ok(self.client.list_access_tokens(input.into()).await?)
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
    ) -> Result<String, RequestError> {
        let request = input.try_into()?;
        let response = self.client.issue_access_token(request).await?;
        Ok(response.access_token)
    }

    /// Revoke an access token.
    ///
    /// Succeeds if the access token does not exist.
    pub async fn revoke_access_token(&self, id: AccessTokenId) -> Result<(), RequestError> {
        Ok(self.client.revoke_access_token(id).await?)
    }

    /// List a page of network policies.
    ///
    /// See [`list_all_network_policies`](crate::S2::list_all_network_policies) for automatic
    /// pagination.
    pub async fn list_network_policies(
        &self,
        input: ListNetworkPoliciesInput,
    ) -> Result<Page<NetworkPolicyInfo>, RequestError> {
        let ctx = ErrorContext::account("list_network_policies", true);
        let response = self.client.list_network_policies(input.into()).await?;
        Ok(Page::new(
            response
                .network_policies
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| response_protocol_error(e, ctx))?,
            response.has_more,
        ))
    }

    /// List all network policies, paginating automatically.
    pub fn list_all_network_policies(
        &self,
        input: ListAllNetworkPoliciesInput,
    ) -> Streaming<NetworkPolicyInfo> {
        let s2 = self.clone();
        let prefix = input.prefix;
        let start_after = input.start_after;
        let mut input = ListNetworkPoliciesInput::new()
            .with_prefix(prefix)
            .with_start_after(start_after);
        Box::pin(async_stream::try_stream! {
            loop {
                let page = s2.list_network_policies(input.clone()).await?;

                let start_after = page.values.last().map(|info| info.id.slug().clone().into());
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

    /// Create a network policy.
    pub async fn create_network_policy(
        &self,
        input: CreateNetworkPolicyInput,
    ) -> Result<NetworkPolicyInfo, RequestError> {
        let ctx = ErrorContext::account("create_network_policy", false);
        let response = self.client.create_network_policy(input.into()).await?;
        response
            .try_into()
            .map_err(|e| response_protocol_error(e, ctx))
    }

    /// Get a network policy by slug or full reference.
    pub async fn get_network_policy(
        &self,
        selector: NetworkPolicySelector,
    ) -> Result<NetworkPolicyInfo, RequestError> {
        let ctx = ErrorContext::account("get_network_policy", true);
        let response = self.client.get_network_policy(selector).await?;
        response
            .try_into()
            .map_err(|e| response_protocol_error(e, ctx))
    }

    /// Delete a network policy by slug or full reference. It must not be bound to any access
    /// token.
    ///
    /// Succeeds if the network policy does not exist.
    pub async fn delete_network_policy(
        &self,
        selector: NetworkPolicySelector,
    ) -> Result<(), RequestError> {
        Ok(self.client.delete_network_policy(selector).await?)
    }

    /// List locations.
    pub async fn list_locations(&self) -> Result<Vec<LocationInfo>, RequestError> {
        let response = self.client.list_locations().await?;
        Ok(response.into_iter().map(Into::into).collect())
    }

    /// Get the default location.
    pub async fn get_default_location(&self) -> Result<LocationInfo, RequestError> {
        Ok(self.client.get_default_location().await?.into())
    }

    /// Set the default location.
    pub async fn set_default_location(
        &self,
        location: LocationName,
    ) -> Result<LocationInfo, RequestError> {
        Ok(self.client.set_default_location(location).await?.into())
    }

    /// Get account metrics.
    pub async fn get_account_metrics(
        &self,
        input: GetAccountMetricsInput,
    ) -> Result<Vec<Metric>, RequestError> {
        let response = self.client.get_account_metrics(input.into()).await?;
        Ok(response.values.into_iter().map(Into::into).collect())
    }

    /// Get basin metrics.
    pub async fn get_basin_metrics(
        &self,
        input: GetBasinMetricsInput,
    ) -> Result<Vec<Metric>, RequestError> {
        let (name, request) = input.into();
        let response = self.client.get_basin_metrics(name, request).await?;
        Ok(response.values.into_iter().map(Into::into).collect())
    }

    /// Get stream metrics.
    pub async fn get_stream_metrics(
        &self,
        input: GetStreamMetricsInput,
    ) -> Result<Vec<Metric>, RequestError> {
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
            encryption: None,
        }
    }

    /// List a page of streams.
    ///
    /// See [`list_all_streams`](crate::S2Basin::list_all_streams) for automatic pagination.
    pub async fn list_streams(
        &self,
        input: ListStreamsInput,
    ) -> Result<Page<StreamInfo>, RequestError> {
        let ctx = ErrorContext::basin("list_streams", self.client.name.as_ref(), true);
        let response = self.client.list_streams(input.into()).await?;
        Ok(Page::new(
            response
                .streams
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| response_protocol_error(e, ctx))?,
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
    pub async fn create_stream(
        &self,
        input: CreateStreamInput,
    ) -> Result<StreamInfo, RequestError> {
        let ctx = ErrorContext::stream(
            "create_stream",
            self.client.name.as_ref(),
            input.name.as_ref(),
            false,
        );
        let info = self
            .client
            .create_stream(input.into(), idempotency_token())
            .await?;
        info.try_into().map_err(|e| response_protocol_error(e, ctx))
    }

    /// Ensure a stream.
    ///
    /// If the stream doesn't exist, creates the stream with specified configuration.
    ///
    /// If the stream already exists:
    /// - Its configuration is updated to the specified configuration, if different.
    /// - Its configuration is unchanged, if the specified configuration is same.
    pub async fn ensure_stream(
        &self,
        input: EnsureStreamInput,
    ) -> Result<EnsureOutput<StreamInfo>, RequestError> {
        let ctx = ErrorContext::stream(
            "ensure_stream",
            self.client.name.as_ref(),
            input.name.as_ref(),
            false,
        );
        let (name, config) = input.into();
        Ok(self
            .client
            .ensure_stream(name, config)
            .await?
            .try_map(StreamInfo::try_from)
            .map_err(|e| response_protocol_error(e, ctx))?
            .into())
    }

    /// Get stream configuration.
    pub async fn get_stream_config(&self, name: StreamName) -> Result<StreamConfig, RequestError> {
        let config = self.client.get_stream_config(name).await?;
        Ok(config.into())
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub async fn get_stream_config_api(
        &self,
        name: StreamName,
    ) -> Result<s2_api::v1::config::StreamConfig, RequestError> {
        Ok(self.client.get_stream_config(name).await?)
    }

    /// Delete a stream.
    ///
    /// Succeeds if the stream is already being deleted or does not exist.
    pub async fn delete_stream(&self, name: StreamName) -> Result<(), RequestError> {
        Ok(self.client.delete_stream(name).await?)
    }

    /// Reconfigure a stream.
    pub async fn reconfigure_stream(
        &self,
        input: ReconfigureStreamInput,
    ) -> Result<StreamConfig, RequestError> {
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
    encryption: Option<EncryptionKey>,
}

impl S2Stream {
    /// Set the encryption key for this stream handle.
    pub fn with_encryption_key(self, encryption: EncryptionKey) -> Self {
        Self {
            encryption: Some(encryption),
            ..self
        }
    }

    fn headers(&self, stream_config: Option<&StreamConfig>) -> StreamHeaders {
        StreamHeaders {
            encryption: self.encryption.clone(),
            stream_config: stream_config.cloned().map(Into::into),
        }
    }

    /// Check tail position.
    pub async fn check_tail(&self) -> Result<StreamPosition, ReadError> {
        let response = self.client.check_tail(&self.name).await?;
        Ok(response.tail.into())
    }

    /// Append records.
    pub async fn append(&self, mut input: AppendInput) -> Result<AppendAck, AppendError> {
        let ctx = ErrorContext::stream(
            "append",
            self.client.name.as_ref(),
            self.name.as_ref(),
            false,
        );
        let stream_config = input
            .stream_config
            .take()
            .map(s2_api::v1::config::StreamConfig::from);
        let ack = self
            .client
            .append(
                &self.name,
                input.into(),
                self.encryption.as_ref(),
                stream_config.as_ref(),
                self.client.config.retry.append_retry_policy,
            )
            .await?;
        Ok(AppendAck::try_from_proto(ack, ctx)?)
    }

    /// Read records.
    pub async fn read(&self, input: ReadInput) -> Result<ReadBatch, ReadError> {
        let stream_config = input
            .stream_config
            .map(s2_api::v1::config::StreamConfig::from);
        let batch = self
            .client
            .read(
                &self.name,
                input.start.into(),
                input.stop.into(),
                self.encryption.as_ref(),
                stream_config.as_ref(),
            )
            .await?;
        Ok(ReadBatch::from_api(batch))
    }

    /// Create an append session for submitting [`AppendInput`]s.
    pub fn append_session(
        &self,
        config: AppendSessionConfig,
    ) -> Result<AppendSession, ClientClosedError> {
        if self.client.is_closed() {
            return Err(ClientClosedError::new(ErrorContext::stream(
                "append_session",
                self.client.name.as_ref(),
                self.name.as_ref(),
                false,
            )));
        }
        Ok(AppendSession::new(
            self.client.clone(),
            self.name.clone(),
            self.headers(config.stream_config()),
            config,
        ))
    }

    /// Create a producer for submitting individual [`AppendRecord`](crate::types::AppendRecord)s.
    pub fn producer(&self, config: ProducerConfig) -> Result<Producer, ClientClosedError> {
        if self.client.is_closed() {
            return Err(ClientClosedError::new(ErrorContext::stream(
                "producer",
                self.client.name.as_ref(),
                self.name.as_ref(),
                false,
            )));
        }
        Ok(Producer::new(
            self.client.clone(),
            self.name.clone(),
            self.headers(config.stream_config()),
            config,
        ))
    }

    /// Create a continuous read session yielding individual
    /// [`SequencedRecord`](crate::types::SequencedRecord)s (`R5`, `R6`).
    ///
    /// Initiates the first request immediately without waiting for a response; request errors
    /// surface through iteration.
    pub fn read_session(
        &self,
        input: ReadInput,
        config: ReadSessionConfig,
    ) -> Result<ReadSession, ClientClosedError> {
        if self.client.is_closed() {
            return Err(ClientClosedError::new(ErrorContext::stream(
                "read_session",
                self.client.name.as_ref(),
                self.name.as_ref(),
                true,
            )));
        }
        Ok(session::open_read_session(
            self.client.clone(),
            self.name.clone(),
            self.headers(input.stream_config.as_ref()),
            input,
            config,
        ))
    }

    /// Create a continuous read session yielding whole non-empty [`ReadBatch`]es (`R6a`).
    ///
    /// Initiates the first request immediately without waiting for a response; request errors
    /// surface through iteration.
    pub fn read_batch_session(
        &self,
        input: ReadInput,
        config: ReadSessionConfig,
    ) -> Result<ReadBatchSession, ClientClosedError> {
        if self.client.is_closed() {
            return Err(ClientClosedError::new(ErrorContext::stream(
                "read_batch_session",
                self.client.name.as_ref(),
                self.name.as_ref(),
                true,
            )));
        }
        Ok(session::open_read_batch_session(
            self.client.clone(),
            self.name.clone(),
            self.headers(input.stream_config.as_ref()),
            input,
            config,
        ))
    }
}
