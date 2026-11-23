use std::{fmt, future::Future, sync::Arc, time::Duration};

use http::{
    HeaderValue, Uri,
    header::{ACCEPT, CONTENT_TYPE},
};
use s2_api::v1::{self as api, config::STREAM_CONFIG_HEADER};
use s2_common::encryption::S2_ENCRYPTION_KEY_HEADER;

use crate::{
    api::{
        APPLICATION_PROTOBUF, BaseClient, BasinClient, S2_REQUEST_TOKEN, basin_path,
        network_policy_path, set_header_opt, stream_path, stream_records_path, token_path,
    },
    client,
    error::{
        AppendError, ClientClosedError, ErrorCode, ErrorContext, OpScope, ReadError, RequestError,
        ValidationError,
    },
    producer::{Producer, ProducerConfig},
    session::{
        AppendSession, AppendSessionConfig, ReadBatchSession, ReadSession, ReadSessionConfig,
        StreamHeaders,
    },
    types::{
        AccessTokenId, AccessTokenInfo, AccountMetricSet, AppendAck, AppendInput, BasinConfig,
        BasinInfo, BasinMetricSet, BasinName, BasinReconfiguration, CreateBasinInput,
        CreateNetworkPolicyInput, CreateStreamInput, EncryptionKey, EnsureBasinInput, EnsureOutput,
        EnsureStreamInput, IssueAccessTokenInput, ListAccessTokensInput, ListAllAccessTokensInput,
        ListAllBasinsInput, ListAllNetworkPoliciesInput, ListAllStreamsInput, ListBasinsInput,
        ListNetworkPoliciesInput, ListStream, ListStreamsInput, LocationInfo, LocationName, Metric,
        NetworkPolicyInfo, NetworkPolicySelector, Page, ReadBatch, ReadInput, S2Config,
        StreamConfig, StreamInfo, StreamMetricSet, StreamName, StreamPosition,
        StreamReconfiguration, request_token,
    },
};

fn init_error(err: ValidationError, op: &'static str) -> ValidationError {
    ValidationError(format!("{op}: {}", err.0))
}

fn encode_stream_config(config: &StreamConfig) -> HeaderValue {
    config.clone().into_api().to_header_value()
}

fn paginate_list<Item, Cursor, Fetch, Fut, Advance, Keep>(
    mut cursor: Cursor,
    fetch: Fetch,
    advance: Advance,
    keep: Keep,
) -> ListStream<Item>
where
    Item: Send + 'static,
    Cursor: Clone + Send + 'static,
    Fetch: Fn(Cursor) -> Fut + Send + 'static,
    Fut: Future<Output = Result<Page<Item>, RequestError>> + Send + 'static,
    Advance: Fn(&mut Cursor, &Item) + Send + 'static,
    Keep: Fn(&Item) -> bool + Send + 'static,
{
    ListStream::new(async_stream::try_stream! {
        loop {
            let page = fetch(cursor.clone()).await?;
            let has_last = if let Some(last) = page.values.last() {
                advance(&mut cursor, last);
                true
            } else {
                false
            };

            for item in page.values {
                if keep(&item) {
                    yield item;
                }
            }

            if !page.has_more || !has_last {
                break;
            }
        }
    })
}

#[derive(Clone)]
/// An S2 account.
pub struct S2 {
    base: BaseClient,
    config: Arc<S2Config>,
    base_url: Uri,
}

impl fmt::Debug for S2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S2")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
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
        let base = BaseClient::init(&config).map_err(|e| init_error(e, op))?;
        Ok(Self::from_parts(config, base))
    }

    fn from_parts(config: S2Config, base: BaseClient) -> Self {
        let base_url = config
            .endpoints
            .account_origin()
            .parse()
            .expect("valid account URI");
        Self {
            base,
            config: Arc::new(config),
            base_url,
        }
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
        let base = BaseClient::init_with_connector(&config, connector)
            .map_err(|e| init_error(e, "S2::new_with_connector"))?;
        Ok(Self::from_parts(config, base))
    }

    fn uri(&self, path: impl AsRef<str>) -> Uri {
        client::uri_with_path(&self.base_url, path)
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
        self.base.close();
    }

    /// Get an [`S2Basin`].
    #[must_use]
    pub fn basin(&self, name: BasinName) -> S2Basin {
        S2Basin {
            client: BasinClient::init(name, self.config.clone(), self.base.clone()),
        }
    }

    /// List a page of basins.
    ///
    /// See [`list_all_basins`](crate::S2::list_all_basins) for automatic pagination.
    pub async fn list_basins(
        &self,
        input: ListBasinsInput,
    ) -> Result<Page<BasinInfo>, RequestError> {
        let req = input.into_api();
        let response: api::basin::ListBasinsResponse = self
            .base
            .unary(
                self.base.get(self.uri("v1/basins")).query(&req).build(),
                OpScope::account("list_basins", true),
            )
            .send_json()
            .await?;
        Ok(Page::from_api(
            response.basins,
            response.has_more,
            BasinInfo::from_api,
        ))
    }

    /// List all basins, paginating automatically.
    pub fn list_all_basins(&self, input: ListAllBasinsInput) -> ListStream<BasinInfo> {
        let s2 = self.clone();
        let (initial, include_deleted) = input.into_parts();
        paginate_list(
            initial,
            move |req| {
                let s2 = s2.clone();
                async move { s2.list_basins(req).await }
            },
            |req, last| req.set_start_after(last.name.clone().into()),
            move |info| include_deleted || info.deleted_at.is_none(),
        )
    }

    /// Create a basin.
    pub async fn create_basin(&self, input: CreateBasinInput) -> Result<BasinInfo, RequestError> {
        let req = input.into_api();
        let basin_name = req.basin.clone();
        let info: api::basin::BasinInfo = self
            .base
            .unary(
                self.base
                    .post(self.uri("v1/basins"))
                    .header(S2_REQUEST_TOKEN, request_token())
                    .json(&req)
                    .build(),
                OpScope::basin("create_basin", basin_name.as_ref(), false),
            )
            .send_json()
            .await?;
        Ok(BasinInfo::from_api(info))
    }

    /// Ensure a basin exists with the specified configuration.
    ///
    /// If the basin does not exist, creates it with the specified configuration.
    ///
    /// If the basin already exists, replaces its configuration with the specified configuration
    /// (**omitted fields are reset to defaults**; use
    /// [`reconfigure_basin`](Self::reconfigure_basin) for partial updates) and reports
    /// [`EnsureOutput::Updated`] or [`EnsureOutput::Noop`].
    ///
    /// Because this operation is retried idempotently, a retried creation whose first attempt
    /// succeeded on the server may report [`EnsureOutput::Updated`] or [`EnsureOutput::Noop`].
    pub async fn ensure_basin(
        &self,
        input: EnsureBasinInput,
    ) -> Result<EnsureOutput<BasinInfo>, RequestError> {
        let (name, body) = input.into_parts();
        let url = self.uri(basin_path(&name));
        let req = match body {
            Some(body) => self.base.put(url).json(&body).build(),
            None => self.base.put(url).build(),
        };
        let result = self
            .base
            .unary(req, OpScope::basin("ensure_basin", name.as_ref(), false))
            .send_ensure::<api::basin::BasinInfo>()
            .await?;
        Ok(result.map(BasinInfo::from_api))
    }

    async fn get_basin_config_raw(
        &self,
        name: BasinName,
    ) -> Result<api::config::BasinConfig, RequestError> {
        let url = self.uri(basin_path(&name));
        self.base
            .unary(
                self.base.get(url).build(),
                OpScope::basin("get_basin_config", name.as_ref(), true),
            )
            .send_json()
            .await
    }

    /// Get basin configuration.
    pub async fn get_basin_config(&self, name: BasinName) -> Result<BasinConfig, RequestError> {
        Ok(BasinConfig::from_api(
            self.get_basin_config_raw(name).await?,
        ))
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub async fn get_basin_config_api(
        &self,
        name: BasinName,
    ) -> Result<api::config::BasinConfig, RequestError> {
        self.get_basin_config_raw(name).await
    }

    /// Delete a basin.
    ///
    /// Succeeds if the basin is already being deleted or does not exist.
    pub async fn delete_basin(&self, name: BasinName) -> Result<(), RequestError> {
        let url = self.uri(basin_path(&name));
        self.base
            .unary(
                self.base.delete(url).build(),
                OpScope::basin("delete_basin", name.as_ref(), false),
            )
            .send_delete(ErrorCode::BasinNotFound)
            .await
    }

    /// Reconfigure a basin.
    pub async fn reconfigure_basin(
        &self,
        name: BasinName,
        config: BasinReconfiguration,
    ) -> Result<BasinConfig, RequestError> {
        let req = config.into_api();
        let url = self.uri(basin_path(&name));
        let config: api::config::BasinConfig = self
            .base
            .unary(
                self.base.patch(url).json(&req).build(),
                OpScope::basin("reconfigure_basin", name.as_ref(), false),
            )
            .send_json()
            .await?;
        Ok(BasinConfig::from_api(config))
    }

    async fn list_access_tokens_raw(
        &self,
        input: ListAccessTokensInput,
    ) -> Result<api::access::ListAccessTokensResponse, RequestError> {
        let req = input.into_api();
        self.base
            .unary(
                self.base
                    .get(self.uri("v1/access-tokens"))
                    .query(&req)
                    .build(),
                OpScope::account("list_access_tokens", true),
            )
            .send_json()
            .await
    }

    /// List a page of access tokens.
    ///
    /// See [`list_all_access_tokens`](crate::S2::list_all_access_tokens) for automatic pagination.
    pub async fn list_access_tokens(
        &self,
        input: ListAccessTokensInput,
    ) -> Result<Page<AccessTokenInfo>, RequestError> {
        let response = self.list_access_tokens_raw(input).await?;
        Ok(Page::from_api(
            response.access_tokens,
            response.has_more,
            AccessTokenInfo::from_api,
        ))
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub async fn list_access_tokens_api(
        &self,
        input: ListAccessTokensInput,
    ) -> Result<api::access::ListAccessTokensResponse, RequestError> {
        self.list_access_tokens_raw(input).await
    }

    /// List all access tokens, paginating automatically.
    pub fn list_all_access_tokens(
        &self,
        input: ListAllAccessTokensInput,
    ) -> ListStream<AccessTokenInfo> {
        let s2 = self.clone();
        let initial = input.into_list_input();
        paginate_list(
            initial,
            move |req| {
                let s2 = s2.clone();
                async move { s2.list_access_tokens(req).await }
            },
            |req, last| req.set_start_after(last.id.clone().into()),
            |_| true,
        )
    }

    /// Issue an access token.
    pub async fn issue_access_token(
        &self,
        input: IssueAccessTokenInput,
    ) -> Result<String, RequestError> {
        let req = input.into_api();
        let response: api::access::IssueAccessTokenResponse = self
            .base
            .unary(
                self.base
                    .post(self.uri("v1/access-tokens"))
                    .json(&req)
                    .build(),
                OpScope::account("issue_access_token", false),
            )
            .definite_retries_only()
            .send_json()
            .await?;
        Ok(response.access_token)
    }

    /// Revoke an access token.
    ///
    /// Succeeds if the access token does not exist.
    pub async fn revoke_access_token(&self, id: AccessTokenId) -> Result<(), RequestError> {
        let url = self.uri(token_path(&id));
        self.base
            .unary(
                self.base.delete(url).build(),
                OpScope::account("revoke_access_token", false),
            )
            .send_delete(ErrorCode::AccessTokenNotFound)
            .await
    }

    /// List a page of network policies.
    ///
    /// See [`list_all_network_policies`](crate::S2::list_all_network_policies) for automatic
    /// pagination.
    pub async fn list_network_policies(
        &self,
        input: ListNetworkPoliciesInput,
    ) -> Result<Page<NetworkPolicyInfo>, RequestError> {
        let req = input.into_api();
        let response: api::network_policy::ListNetworkPoliciesResponse = self
            .base
            .unary(
                self.base
                    .get(self.uri("v1/network-policies"))
                    .query(&req)
                    .build(),
                OpScope::account("list_network_policies", true),
            )
            .send_json()
            .await?;
        Ok(Page::from_api(
            response.network_policies,
            response.has_more,
            NetworkPolicyInfo::from_api,
        ))
    }

    /// List all network policies, paginating automatically.
    pub fn list_all_network_policies(
        &self,
        input: ListAllNetworkPoliciesInput,
    ) -> ListStream<NetworkPolicyInfo> {
        let s2 = self.clone();
        let initial = input.into_list_input();
        paginate_list(
            initial,
            move |req| {
                let s2 = s2.clone();
                async move { s2.list_network_policies(req).await }
            },
            |req, last| req.set_start_after(last.id.slug().clone().into()),
            |_| true,
        )
    }

    /// Create a network policy.
    pub async fn create_network_policy(
        &self,
        input: CreateNetworkPolicyInput,
    ) -> Result<NetworkPolicyInfo, RequestError> {
        let req = input.into_api();
        let response: api::network_policy::NetworkPolicyInfo = self
            .base
            .unary(
                self.base
                    .post(self.uri("v1/network-policies"))
                    .json(&req)
                    .build(),
                OpScope::account("create_network_policy", false),
            )
            .definite_retries_only()
            .send_json()
            .await?;
        Ok(NetworkPolicyInfo::from_api(response))
    }

    /// Get a network policy by slug or full reference.
    ///
    /// Accepts a [`NetworkPolicySelector`], [`NetworkPolicySlug`](crate::types::NetworkPolicySlug),
    /// or [`NetworkPolicyRef`](crate::types::NetworkPolicyRef).
    pub async fn get_network_policy(
        &self,
        selector: impl Into<NetworkPolicySelector>,
    ) -> Result<NetworkPolicyInfo, RequestError> {
        let selector = selector.into();
        let url = self.uri(network_policy_path(&selector));
        let response: api::network_policy::NetworkPolicyInfo = self
            .base
            .unary(
                self.base.get(url).build(),
                OpScope::account("get_network_policy", true),
            )
            .send_json()
            .await?;
        Ok(NetworkPolicyInfo::from_api(response))
    }

    /// Delete a network policy by slug or full reference. It must not be bound to any access
    /// token.
    ///
    /// Accepts a [`NetworkPolicySelector`], [`NetworkPolicySlug`](crate::types::NetworkPolicySlug),
    /// or [`NetworkPolicyRef`](crate::types::NetworkPolicyRef).
    ///
    /// Succeeds if the network policy does not exist.
    pub async fn delete_network_policy(
        &self,
        selector: impl Into<NetworkPolicySelector>,
    ) -> Result<(), RequestError> {
        let selector = selector.into();
        let url = self.uri(network_policy_path(&selector));
        self.base
            .unary(
                self.base.delete(url).build(),
                OpScope::account("delete_network_policy", false),
            )
            .send_delete(ErrorCode::NetworkPolicyNotFound)
            .await
    }

    /// List locations.
    pub async fn list_locations(&self) -> Result<Vec<LocationInfo>, RequestError> {
        let response: Vec<api::location::LocationInfo> = self
            .base
            .unary(
                self.base.get(self.uri("v1/locations")).build(),
                OpScope::account("list_locations", true),
            )
            .send_json()
            .await?;
        Ok(response.into_iter().map(LocationInfo::from_api).collect())
    }

    /// Get the default location.
    pub async fn get_default_location(&self) -> Result<LocationInfo, RequestError> {
        let response: api::location::LocationInfo = self
            .base
            .unary(
                self.base.get(self.uri("v1/locations/default")).build(),
                OpScope::account("get_default_location", true),
            )
            .send_json()
            .await?;
        Ok(LocationInfo::from_api(response))
    }

    /// Set the default location.
    pub async fn set_default_location(
        &self,
        location: LocationName,
    ) -> Result<LocationInfo, RequestError> {
        let response: api::location::LocationInfo = self
            .base
            .unary(
                self.base
                    .put(self.uri("v1/locations/default"))
                    .json(&location)
                    .build(),
                OpScope::account("set_default_location", false),
            )
            .send_json()
            .await?;
        Ok(LocationInfo::from_api(response))
    }

    /// Get account metrics.
    pub async fn get_account_metrics(
        &self,
        set: AccountMetricSet,
    ) -> Result<Vec<Metric>, RequestError> {
        let req = set.into_api();
        let response: api::metrics::MetricSetResponse = self
            .base
            .unary(
                self.base.get(self.uri("v1/metrics")).query(&req).build(),
                OpScope::account("get_account_metrics", true),
            )
            .send_json()
            .await?;
        Ok(response.values.into_iter().map(Metric::from_api).collect())
    }

    /// Get basin metrics.
    pub async fn get_basin_metrics(
        &self,
        basin: BasinName,
        set: BasinMetricSet,
    ) -> Result<Vec<Metric>, RequestError> {
        let req = set.into_api();
        let url = self.uri(format!("v1/metrics/{basin}"));
        let response: api::metrics::MetricSetResponse = self
            .base
            .unary(
                self.base.get(url).query(&req).build(),
                OpScope::basin("get_basin_metrics", basin.as_ref(), true),
            )
            .send_json()
            .await?;
        Ok(response.values.into_iter().map(Metric::from_api).collect())
    }

    /// Get stream metrics.
    pub async fn get_stream_metrics(
        &self,
        basin: BasinName,
        stream: StreamName,
        set: StreamMetricSet,
    ) -> Result<Vec<Metric>, RequestError> {
        let req = set.into_api();
        let url = self.uri(format!(
            "v1/metrics/{basin}/{}",
            urlencoding::encode(&stream)
        ));
        let response: api::metrics::MetricSetResponse = self
            .base
            .unary(
                self.base.get(url).query(&req).build(),
                OpScope::stream("get_stream_metrics", basin.as_ref(), stream.as_ref(), true),
            )
            .send_json()
            .await?;
        Ok(response.values.into_iter().map(Metric::from_api).collect())
    }
}

#[derive(Clone)]
/// A basin in an S2 account.
///
/// See [`S2::basin`].
pub struct S2Basin {
    client: BasinClient,
}

impl fmt::Debug for S2Basin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S2Basin")
            .field("name", &self.client.name)
            .finish_non_exhaustive()
    }
}

impl S2Basin {
    /// Return the name of this basin.
    #[must_use]
    pub fn name(&self) -> &BasinName {
        &self.client.name
    }

    /// Get an [`S2Stream`].
    #[must_use]
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
        let req = input.into_api();
        let response: api::stream::ListStreamsResponse = self
            .client
            .unary(
                self.client.get("v1/streams").query(&req).build(),
                self.client.basin_scope("list_streams", true),
            )
            .send_json()
            .await?;
        Ok(Page::from_api(
            response.streams,
            response.has_more,
            StreamInfo::from_api,
        ))
    }

    /// List all streams, paginating automatically.
    pub fn list_all_streams(&self, input: ListAllStreamsInput) -> ListStream<StreamInfo> {
        let basin = self.clone();
        let (initial, include_deleted) = input.into_parts();
        paginate_list(
            initial,
            move |req| {
                let basin = basin.clone();
                async move { basin.list_streams(req).await }
            },
            |req, last| req.set_start_after(last.name.clone().into()),
            move |info| include_deleted || info.deleted_at.is_none(),
        )
    }

    /// Create a stream.
    pub async fn create_stream(
        &self,
        input: CreateStreamInput,
    ) -> Result<StreamInfo, RequestError> {
        let req = input.into_api();
        let stream_name = req.stream.clone();
        let info: api::stream::StreamInfo = self
            .client
            .unary(
                self.client
                    .post("v1/streams")
                    .header(S2_REQUEST_TOKEN, request_token())
                    .json(&req)
                    .build(),
                self.client
                    .stream_scope("create_stream", &stream_name, false),
            )
            .send_json()
            .await?;
        Ok(StreamInfo::from_api(info))
    }

    /// Ensure a stream exists with the specified configuration.
    ///
    /// If the stream does not exist, creates it with the specified configuration.
    ///
    /// If the stream already exists, replaces its configuration with the specified configuration
    /// (**omitted fields are reset to defaults**; use
    /// [`reconfigure_stream`](Self::reconfigure_stream) for partial updates) and reports
    /// [`EnsureOutput::Updated`] or [`EnsureOutput::Noop`].
    ///
    /// Because this operation is retried idempotently, a retried creation whose first attempt
    /// succeeded on the server may report [`EnsureOutput::Updated`] or [`EnsureOutput::Noop`].
    pub async fn ensure_stream(
        &self,
        input: EnsureStreamInput,
    ) -> Result<EnsureOutput<StreamInfo>, RequestError> {
        let (name, config) = input.into_parts();
        let path = stream_path(&name);
        let req = match config {
            Some(body) => self.client.put(path).json(&body).build(),
            None => self.client.put(path).build(),
        };
        let result = self
            .client
            .unary(req, self.client.stream_scope("ensure_stream", &name, false))
            .send_ensure::<api::stream::StreamInfo>()
            .await?;
        Ok(result.map(StreamInfo::from_api))
    }

    async fn get_stream_config_raw(
        &self,
        name: StreamName,
    ) -> Result<api::config::StreamConfig, RequestError> {
        self.client
            .unary(
                self.client.get(stream_path(&name)).build(),
                self.client.stream_scope("get_stream_config", &name, true),
            )
            .send_json()
            .await
    }

    /// Get stream configuration.
    pub async fn get_stream_config(&self, name: StreamName) -> Result<StreamConfig, RequestError> {
        Ok(StreamConfig::from_api(
            self.get_stream_config_raw(name).await?,
        ))
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub async fn get_stream_config_api(
        &self,
        name: StreamName,
    ) -> Result<api::config::StreamConfig, RequestError> {
        self.get_stream_config_raw(name).await
    }

    /// Delete a stream.
    ///
    /// Succeeds if the stream is already being deleted or does not exist.
    pub async fn delete_stream(&self, name: StreamName) -> Result<(), RequestError> {
        self.client
            .unary(
                self.client.delete(stream_path(&name)).build(),
                self.client.stream_scope("delete_stream", &name, false),
            )
            .send_delete(ErrorCode::StreamNotFound)
            .await
    }

    /// Reconfigure a stream.
    pub async fn reconfigure_stream(
        &self,
        name: StreamName,
        config: StreamReconfiguration,
    ) -> Result<StreamConfig, RequestError> {
        let req = config.into_api();
        let config: api::config::StreamConfig = self
            .client
            .unary(
                self.client.patch(stream_path(&name)).json(&req).build(),
                self.client.stream_scope("reconfigure_stream", &name, false),
            )
            .send_json()
            .await?;
        Ok(StreamConfig::from_api(config))
    }
}

#[derive(Clone)]
/// A stream in an S2 basin.
///
/// See [`S2Basin::stream`].
pub struct S2Stream {
    client: BasinClient,
    name: StreamName,
    encryption: Option<HeaderValue>,
}

impl fmt::Debug for S2Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S2Stream")
            .field("basin", &self.client.name)
            .field("name", &self.name)
            .field("encrypted", &self.encryption.is_some())
            .finish_non_exhaustive()
    }
}

impl S2Stream {
    /// Return the name of this stream.
    #[must_use]
    pub fn name(&self) -> &StreamName {
        &self.name
    }

    /// Return the name of the basin containing this stream.
    #[must_use]
    pub fn basin_name(&self) -> &BasinName {
        &self.client.name
    }

    /// Set the encryption key for this stream handle.
    #[must_use]
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

    fn ensure_open(&self, op: &'static str, read_only: bool) -> Result<(), ClientClosedError> {
        if self.client.is_closed() {
            return Err(ClientClosedError::new(ErrorContext::stream(
                op,
                self.client.name.as_ref(),
                self.name.as_ref(),
                read_only,
            )));
        }
        Ok(())
    }

    /// Check tail position.
    pub async fn check_tail(&self) -> Result<StreamPosition, ReadError> {
        let response: api::stream::TailResponse = self
            .client
            .unary(
                self.client
                    .get(format!("{}/tail", stream_records_path(&self.name)))
                    .build(),
                self.client.stream_scope("check_tail", &self.name, true),
            )
            .send_json_as::<_, ReadError>()
            .await?;
        Ok(StreamPosition::from_api(response.tail))
    }

    /// Append records.
    ///
    /// Accepts an [`AppendInput`], [`AppendRecordBatch`](crate::types::AppendRecordBatch),
    /// [`AppendRecord`](crate::types::AppendRecord), or
    /// [`CommandRecord`](crate::types::CommandRecord).
    ///
    /// To supply a [`StreamConfig`] to apply if the stream is created on append, use
    /// [`append_with_stream_config`](Self::append_with_stream_config). (`stream_config` is kept
    /// off [`AppendInput`] because [`AppendInput`] is also submitted to
    /// [`AppendSession::submit`], where `stream_config` is configured once per session on
    /// [`AppendSessionConfig`].)
    pub async fn append(&self, input: impl Into<AppendInput>) -> Result<AppendAck, AppendError> {
        self.append_inner(input.into(), None).await
    }

    /// Append records, supplying a [`StreamConfig`] to apply if the stream is created on append.
    ///
    /// Unset fields inherit the basin's default stream configuration. Ignored if the stream
    /// already exists. For append sessions and producers, pass `stream_config` on
    /// [`AppendSessionConfig::with_stream_config`] or [`ProducerConfig::with_stream_config`]
    /// instead.
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
        use prost::Message as _;

        let scope = self.client.stream_scope("append", &self.name, false);
        let expected_records = input.records().len() as u64;
        let proto_input = input.into_proto();
        let req = self
            .client
            .post(stream_records_path(&self.name))
            .header(CONTENT_TYPE, APPLICATION_PROTOBUF)
            .header(ACCEPT, APPLICATION_PROTOBUF)
            .body(proto_input.encode_to_vec())
            .build()
            .map(|mut req| {
                set_header_opt(
                    &mut req,
                    &S2_ENCRYPTION_KEY_HEADER,
                    self.encryption.as_ref(),
                );
                set_header_opt(&mut req, &STREAM_CONFIG_HEADER, stream_config);
                req
            });
        let (ack, attempts): (api::stream::proto::AppendAck, u32) = self
            .client
            .unary(req, scope)
            .append_retry_policy(self.client.config().retry.append_retry_policy)
            .send_proto::<_, AppendError>()
            .await?;
        Ok(AppendAck::try_from_proto(
            ack,
            expected_records,
            scope.context(attempts),
        )?)
    }

    /// Read records.
    ///
    /// Accepts a [`ReadInput`] or a [`ReadStart`](crate::types::ReadStart).
    pub async fn read(&self, input: impl Into<ReadInput>) -> Result<ReadBatch, ReadError> {
        let (start, end, stream_config) = input.into().into_api_parts();
        let stream_config = stream_config.as_ref().map(encode_stream_config);
        let scope = self.client.stream_scope("read", &self.name, true);
        let mut builder = self
            .client
            .get(stream_records_path(&self.name))
            .header(ACCEPT, APPLICATION_PROTOBUF)
            .query(&start)
            .query(&end);
        if let Some(wait) = end.wait {
            builder = builder.timeout(
                self.client
                    .base()
                    .request_timeout()
                    .saturating_add(Duration::from_secs(wait.into())),
            );
        }
        let req = builder.build().map(|mut req| {
            set_header_opt(
                &mut req,
                &S2_ENCRYPTION_KEY_HEADER,
                self.encryption.as_ref(),
            );
            set_header_opt(&mut req, &STREAM_CONFIG_HEADER, stream_config.as_ref());
            req
        });
        let (batch, _): (api::stream::proto::ReadBatch, u32) = self
            .client
            .unary(req, scope)
            .send_proto::<_, ReadError>()
            .await?;
        Ok(ReadBatch::from_proto(batch))
    }

    /// Create an append session for submitting [`AppendInput`]s.
    ///
    /// # Errors
    ///
    /// Returns [`ClientClosedError`] if [`S2::close`] has already been called.
    ///
    /// # Panics
    ///
    /// Panics if called outside the context of a Tokio runtime.
    pub fn append_session(
        &self,
        config: AppendSessionConfig,
    ) -> Result<AppendSession, ClientClosedError> {
        self.ensure_open("append_session", false)?;
        Ok(AppendSession::new(
            self.client.clone(),
            self.name.clone(),
            self.headers(config.stream_config()),
            config,
        ))
    }

    /// Create a producer for submitting individual [`AppendRecord`](crate::types::AppendRecord)s.
    ///
    /// # Errors
    ///
    /// Returns [`ClientClosedError`] if [`S2::close`] has already been called.
    ///
    /// # Panics
    ///
    /// Panics if called outside the context of a Tokio runtime.
    pub fn producer(&self, config: ProducerConfig) -> Result<Producer, ClientClosedError> {
        self.ensure_open("producer", false)?;
        Ok(Producer::new(
            self.client.clone(),
            self.name.clone(),
            self.headers(config.stream_config()),
            config,
        ))
    }

    /// Create a continuous read session yielding individual
    /// [`SequencedRecord`](crate::types::SequencedRecord)s.
    ///
    /// Accepts a [`ReadInput`] or a [`ReadStart`](crate::types::ReadStart).
    /// Initiates the first request immediately without waiting for a response; request errors
    /// surface through iteration.
    ///
    /// # Errors
    ///
    /// Returns [`ClientClosedError`] if [`S2::close`] has already been called.
    ///
    /// # Panics
    ///
    /// Panics if called outside the context of a Tokio runtime.
    pub fn read_session(
        &self,
        input: impl Into<ReadInput>,
        config: ReadSessionConfig,
    ) -> Result<ReadSession, ClientClosedError> {
        self.ensure_open("read_session", true)?;
        let input = input.into();
        let headers = self.headers(input.stream_config());
        Ok(ReadSession::open(
            self.client.clone(),
            self.name.clone(),
            headers,
            input,
            config,
        ))
    }

    /// Create a continuous read session yielding whole non-empty [`ReadBatch`]es.
    ///
    /// Accepts a [`ReadInput`] or a [`ReadStart`](crate::types::ReadStart).
    /// Initiates the first request immediately without waiting for a response; request errors
    /// surface through iteration.
    ///
    /// # Errors
    ///
    /// Returns [`ClientClosedError`] if [`S2::close`] has already been called.
    ///
    /// # Panics
    ///
    /// Panics if called outside the context of a Tokio runtime.
    pub fn read_batch_session(
        &self,
        input: impl Into<ReadInput>,
        config: ReadSessionConfig,
    ) -> Result<ReadBatchSession, ClientClosedError> {
        self.ensure_open("read_batch_session", true)?;
        let input = input.into();
        let headers = self.headers(input.stream_config());
        Ok(ReadBatchSession::open(
            self.client.clone(),
            self.name.clone(),
            headers,
            input,
            config,
        ))
    }
}
