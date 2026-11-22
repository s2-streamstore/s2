use http::HeaderValue;
use s2_api::v1 as api;

use crate::{
    api::{AccountClient, BaseClient, BasinClient},
    error::{AppendError, ClientClosedError, ErrorContext, ReadError, RequestError},
    producer::{Producer, ProducerConfig},
    session::{
        self, AppendSession, AppendSessionConfig, ReadBatchSession, ReadSession, ReadSessionConfig,
        StreamHeaders,
    },
    types::{
        AccessTokenId, AccessTokenInfo, AccountMetricSet, AppendAck, AppendInput, BasinConfig,
        BasinInfo, BasinMetricSet, BasinName, BasinReconfiguration, CreateBasinInput,
        CreateStreamInput, EncryptionKey, EnsureBasinInput, EnsureOutput, EnsureStreamInput,
        IssueAccessTokenInput, ListAccessTokensInput, ListAllAccessTokensInput, ListAllBasinsInput,
        ListAllNetworkPoliciesInput, ListAllStreamsInput, ListBasinsInput,
        ListNetworkPoliciesInput, ListStream, ListStreamsInput, LocationInfo, LocationName, Metric,
        NetworkPolicy, NetworkPolicyInfo, NetworkPolicySelector, NetworkPolicySlug, Page,
        ReadBatch, ReadInput, S2Config, StreamConfig, StreamInfo, StreamMetricSet, StreamName,
        StreamPosition, StreamReconfiguration, ValidationError, idempotency_token,
    },
};

fn init_error(err: ValidationError, op: &'static str) -> ValidationError {
    let ctx = ErrorContext::account(op, true);
    ValidationError(ctx.format_string(&err.0))
}

fn encode_stream_config(config: &StreamConfig) -> HeaderValue {
    api::config::StreamConfig::from(config.clone()).to_header_value()
}

#[derive(Debug, Clone)]
/// An S2 account.
pub struct S2 {
    client: AccountClient,
}

impl S2 {
    /// Create a new [`S2`].
    pub fn new(config: S2Config) -> Result<Self, ValidationError> {
        Self::init_with_op(config, "S2::new")
    }

    /// Create a new [`S2`] from environment variables.
    ///
    /// Reads `S2_ACCESS_TOKEN`, and optionally `S2_ACCOUNT_ENDPOINT` and `S2_BASIN_ENDPOINT`
    /// (empty endpoint variables are treated as unset; if one is set, both must be set).
    pub fn from_env() -> Result<Self, ValidationError> {
        let config = S2Config::from_env().map_err(|e| init_error(e, "S2::from_env"))?;
        Self::init_with_op(config, "S2::from_env")
    }

    fn init_with_op(config: S2Config, op: &'static str) -> Result<Self, ValidationError> {
        let base_client = BaseClient::init(&config).map_err(|e| init_error(e, op))?;
        Ok(Self {
            client: AccountClient::init(config, base_client),
        })
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub fn new_with_connector<C>(config: S2Config, connector: C) -> Result<Self, ValidationError>
    where
        C: tower_service::Service<http::Uri> + Clone + Send + Sync + 'static,
        C::Response: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
        C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        C::Future: Send + 'static,
    {
        let base_client = BaseClient::init_with_connector(&config, connector)
            .map_err(|e| init_error(e, "S2::new"))?;
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
    pub fn list_all_basins(&self, input: ListAllBasinsInput) -> ListStream<BasinInfo> {
        let s2 = self.clone();
        let prefix = input.prefix;
        let start_after = input.start_after;
        let include_deleted = input.include_deleted;
        let mut input = ListBasinsInput::new()
            .with_prefix(prefix)
            .with_start_after(start_after);
        ListStream::new(async_stream::try_stream! {
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
        let info = self
            .client
            .create_basin(input.into(), idempotency_token())
            .await?;
        Ok(info.into())
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
        let (name, request) = input.into();
        Ok(self
            .client
            .ensure_basin(name, request)
            .await?
            .map(BasinInfo::from)
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
    ) -> Result<api::config::BasinConfig, RequestError> {
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
        name: BasinName,
        config: BasinReconfiguration,
    ) -> Result<BasinConfig, RequestError> {
        let config = self.client.reconfigure_basin(name, config.into()).await?;
        Ok(config.into())
    }

    /// List a page of access tokens.
    ///
    /// See [`list_all_access_tokens`](crate::S2::list_all_access_tokens) for automatic pagination.
    pub async fn list_access_tokens(
        &self,
        input: ListAccessTokensInput,
    ) -> Result<Page<AccessTokenInfo>, RequestError> {
        let response = self.client.list_access_tokens(input.into()).await?;
        Ok(Page::new(
            response
                .access_tokens
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
            response.has_more,
        ))
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub async fn list_access_tokens_api(
        &self,
        input: ListAccessTokensInput,
    ) -> Result<api::access::ListAccessTokensResponse, RequestError> {
        Ok(self.client.list_access_tokens(input.into()).await?)
    }

    /// List all access tokens, paginating automatically.
    pub fn list_all_access_tokens(
        &self,
        input: ListAllAccessTokensInput,
    ) -> ListStream<AccessTokenInfo> {
        let s2 = self.clone();
        let prefix = input.prefix;
        let start_after = input.start_after;
        let mut input = ListAccessTokensInput::new()
            .with_prefix(prefix)
            .with_start_after(start_after);
        ListStream::new(async_stream::try_stream! {
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
        let response = self.client.issue_access_token(input.into()).await?;
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
        let response = self.client.list_network_policies(input.into()).await?;
        Ok(Page::new(
            response
                .network_policies
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
            response.has_more,
        ))
    }

    /// List all network policies, paginating automatically.
    pub fn list_all_network_policies(
        &self,
        input: ListAllNetworkPoliciesInput,
    ) -> ListStream<NetworkPolicyInfo> {
        let s2 = self.clone();
        let prefix = input.prefix;
        let start_after = input.start_after;
        let mut input = ListNetworkPoliciesInput::new()
            .with_prefix(prefix)
            .with_start_after(start_after);
        ListStream::new(async_stream::try_stream! {
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
        slug: NetworkPolicySlug,
        policy: NetworkPolicy,
    ) -> Result<NetworkPolicyInfo, RequestError> {
        let response = self
            .client
            .create_network_policy(api::network_policy::CreateNetworkPolicyRequest {
                slug,
                policy: policy.into(),
            })
            .await?;
        Ok(response.into())
    }

    /// Get a network policy by slug or full reference.
    pub async fn get_network_policy(
        &self,
        selector: NetworkPolicySelector,
    ) -> Result<NetworkPolicyInfo, RequestError> {
        let response = self.client.get_network_policy(selector).await?;
        Ok(response.into())
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
        set: AccountMetricSet,
    ) -> Result<Vec<Metric>, RequestError> {
        let response = self.client.get_account_metrics(set.into()).await?;
        Ok(response.values.into_iter().map(Into::into).collect())
    }

    /// Get basin metrics.
    pub async fn get_basin_metrics(
        &self,
        basin: BasinName,
        set: BasinMetricSet,
    ) -> Result<Vec<Metric>, RequestError> {
        let response = self.client.get_basin_metrics(basin, set.into()).await?;
        Ok(response.values.into_iter().map(Into::into).collect())
    }

    /// Get stream metrics.
    pub async fn get_stream_metrics(
        &self,
        basin: BasinName,
        stream: StreamName,
        set: StreamMetricSet,
    ) -> Result<Vec<Metric>, RequestError> {
        let response = self
            .client
            .get_stream_metrics(basin, stream, set.into())
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
    /// Return the name of this basin.
    pub fn name(&self) -> &BasinName {
        &self.client.name
    }

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
        let response = self.client.list_streams(input.into()).await?;
        Ok(Page::new(
            response
                .streams
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
            response.has_more,
        ))
    }

    /// List all streams, paginating automatically.
    pub fn list_all_streams(&self, input: ListAllStreamsInput) -> ListStream<StreamInfo> {
        let basin = self.clone();
        let prefix = input.prefix;
        let start_after = input.start_after;
        let include_deleted = input.include_deleted;
        let mut input = ListStreamsInput::new()
            .with_prefix(prefix)
            .with_start_after(start_after);
        ListStream::new(async_stream::try_stream! {
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
        let info = self
            .client
            .create_stream(input.into(), idempotency_token())
            .await?;
        Ok(info.into())
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
        let (name, config) = input.into();
        Ok(self
            .client
            .ensure_stream(name, config)
            .await?
            .map(StreamInfo::from)
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
    ) -> Result<api::config::StreamConfig, RequestError> {
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
        name: StreamName,
        config: StreamReconfiguration,
    ) -> Result<StreamConfig, RequestError> {
        let config = self.client.reconfigure_stream(name, config.into()).await?;
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
    encryption: Option<HeaderValue>,
}

impl S2Stream {
    /// Return the name of this stream.
    pub fn name(&self) -> &StreamName {
        &self.name
    }

    /// Return the name of the basin containing this stream.
    pub fn basin(&self) -> &BasinName {
        &self.client.name
    }

    /// Set the encryption key for this stream handle.
    pub fn with_encryption_key(self, encryption: EncryptionKey) -> Self {
        Self {
            encryption: Some(encryption.to_header_value()),
            ..self
        }
    }

    fn headers(&self, stream_config: Option<&StreamConfig>) -> StreamHeaders {
        StreamHeaders {
            encryption: self.encryption.clone(),
            stream_config: stream_config.map(encode_stream_config),
        }
    }

    /// Check tail position.
    pub async fn check_tail(&self) -> Result<StreamPosition, ReadError> {
        let response = self.client.check_tail(&self.name).await?;
        Ok(response.tail.into())
    }

    /// Append records.
    ///
    /// Accepts an [`AppendInput`], [`AppendRecordBatch`](crate::types::AppendRecordBatch),
    /// [`AppendRecord`](crate::types::AppendRecord), or
    /// [`CommandRecord`](crate::types::CommandRecord).
    ///
    /// To supply a [`StreamConfig`] to apply if the stream is created on append, use
    /// [`append_with_stream_config`](Self::append_with_stream_config).
    pub async fn append(&self, input: impl Into<AppendInput>) -> Result<AppendAck, AppendError> {
        self.append_inner(input.into(), None).await
    }

    /// Append records, supplying a [`StreamConfig`] to apply if the stream is created on append.
    ///
    /// Unset fields inherit the basin's default stream configuration. Ignored if the stream
    /// already exists.
    pub async fn append_with_stream_config(
        &self,
        input: impl Into<AppendInput>,
        stream_config: StreamConfig,
    ) -> Result<AppendAck, AppendError> {
        let header = encode_stream_config(&stream_config);
        self.append_inner(input.into(), Some(&header)).await
    }

    async fn append_inner(
        &self,
        input: AppendInput,
        stream_config: Option<&HeaderValue>,
    ) -> Result<AppendAck, AppendError> {
        let ctx = ErrorContext::stream(
            "append",
            self.client.name.as_ref(),
            self.name.as_ref(),
            false,
        );
        let expected_records = input.records.len() as u64;
        let ack = self
            .client
            .append(
                &self.name,
                input.into(),
                self.encryption.as_ref(),
                stream_config,
                self.client.config.retry.append_retry_policy,
            )
            .await?;
        let ack = AppendAck::try_from_proto(ack, ctx.clone())?;
        ack.validate_record_count(expected_records, &ctx)?;
        Ok(ack)
    }

    /// Read records.
    pub async fn read(&self, input: ReadInput) -> Result<ReadBatch, ReadError> {
        let (start, end, stream_config) = input.into_api_parts();
        let stream_config = stream_config.as_ref().map(encode_stream_config);
        let batch = self
            .client
            .read(
                &self.name,
                start,
                end,
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
        let headers = self.headers(input.stream_config());
        Ok(session::open_read_session(
            self.client.clone(),
            self.name.clone(),
            headers,
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
        let headers = self.headers(input.stream_config());
        Ok(session::open_read_batch_session(
            self.client.clone(),
            self.name.clone(),
            headers,
            input,
            config,
        ))
    }
}
