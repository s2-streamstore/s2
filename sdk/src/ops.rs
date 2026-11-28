use std::{fmt, future::Future, sync::Arc, time::Duration};

use http::{
    HeaderValue, Uri,
    header::{ACCEPT, CONTENT_TYPE},
};
use s2_api::v1 as api;
use s2_common::resources::REQUEST_TOKEN_HEADER;

use crate::{
    api::{
        APPLICATION_PROTOBUF, BaseClient, BasinClient, basin_path, metrics_basin_path,
        metrics_stream_path, network_policy_path, stream_path, stream_records_path,
        stream_tail_path, token_path,
    },
    client,
    error::{
        AppendError, AppendSessionError, ClientClosedError, ErrorCode, ErrorContext, OpScope,
        ReadError, ReadSessionError, RequestError, ValidationError,
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
        NetworkPolicyInfo, NetworkPolicySelector, Page, ReadBatch, ReadInput, RetryConfig,
        S2Config, S2Endpoints, StreamConfig, StreamInfo, StreamMetricSet, StreamName,
        StreamPosition, StreamReconfiguration, request_token,
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
    Advance: Fn(&mut Cursor, &Page<Item>) -> bool + Send + 'static,
    Keep: Fn(&Item) -> bool + Send + 'static,
{
    ListStream::new(async_stream::try_stream! {
        loop {
            let page = fetch(cursor.clone()).await?;
            let continue_paging = page.has_more && advance(&mut cursor, &page);

            for item in page.values {
                if keep(&item) {
                    yield item;
                }
            }

            if !continue_paging {
                break;
            }
        }
    })
}

#[derive(Clone)]
/// An S2 account.
pub struct S2 {
    base: BaseClient,
    endpoints: Arc<S2Endpoints>,
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
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if the configuration (such as the access token, timeouts,
    /// retry settings, HTTP/2 settings, headers, user agent, or TLS setup) is invalid.
    pub fn new(config: S2Config) -> Result<Self, ValidationError> {
        Self::init_with_op(config, "S2::new")
    }

    /// Create a new [`S2`] from environment variables.
    ///
    /// Reads `S2_ACCESS_TOKEN`, and optionally `S2_ACCOUNT_ENDPOINT` and `S2_BASIN_ENDPOINT`
    /// (empty endpoint variables are treated as unset; if one is set, both must be set).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `S2_ACCESS_TOKEN` is missing/invalid, only one endpoint
    /// variable is set, an endpoint is malformed, or TLS initialization fails.
    pub fn from_env() -> Result<Self, ValidationError> {
        let config = S2Config::from_env().map_err(|e| init_error(e, "S2::from_env"))?;
        Self::init_with_op(config, "S2::from_env")
    }

    fn init_with_op(config: S2Config, op: &'static str) -> Result<Self, ValidationError> {
        let base = BaseClient::init(&config).map_err(|e| init_error(e, op))?;
        Ok(Self::from_parts(config.endpoints, base))
    }

    fn from_parts(endpoints: S2Endpoints, base: BaseClient) -> Self {
        let base_url = endpoints
            .account_origin()
            .parse()
            .expect("valid account URI");
        Self {
            base,
            endpoints: Arc::new(endpoints),
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
        Ok(Self::from_parts(config.endpoints, base))
    }

    fn uri(&self, path: impl AsRef<str>) -> Uri {
        client::uri_with_path(&self.base_url, path)
    }

    fn get(&self, path: impl AsRef<str>) -> client::RequestBuilder {
        self.base.get(self.uri(path))
    }

    fn post(&self, path: impl AsRef<str>) -> client::RequestBuilder {
        self.base.post(self.uri(path))
    }

    fn put(&self, path: impl AsRef<str>) -> client::RequestBuilder {
        self.base.put(self.uri(path))
    }

    fn patch(&self, path: impl AsRef<str>) -> client::RequestBuilder {
        self.base.patch(self.uri(path))
    }

    fn delete(&self, path: impl AsRef<str>) -> client::RequestBuilder {
        self.base.delete(self.uri(path))
    }

    /// Return this client configured with a different [`RetryConfig`] while sharing the same
    /// underlying connection pool and [`close`](Self::close) lifecycle.
    ///
    /// Handles and sessions subsequently opened from the returned client inherit `retry`; sibling
    /// handles and already-opened sessions keep their own retry settings.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `retry.max_attempts() == 0` or
    /// `retry.min_base_delay() > retry.max_base_delay()`.
    pub fn with_retry(self, retry: RetryConfig) -> Result<Self, ValidationError> {
        let base = self
            .base
            .with_retry(retry)
            .map_err(|e| init_error(e, "S2::with_retry"))?;
        Ok(Self { base, ..self })
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
            client: BasinClient::init(name, &self.endpoints, self.base.clone()),
        }
    }

    /// List a page of basins.
    ///
    /// See [`list_all_basins`](Self::list_all_basins) for automatic pagination.
    pub async fn list_basins(
        &self,
        input: ListBasinsInput,
    ) -> Result<Page<BasinInfo>, RequestError> {
        let req = input.into_api();
        let response: api::basin::ListBasinsResponse = self
            .base
            .unary(
                self.get("/v1/basins").query(&req).build(),
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
    ///
    /// Excludes basins that are pending deletion unless
    /// [`ListAllBasinsInput::with_include_deleted`] is set to `true`.
    pub fn list_all_basins(&self, input: ListAllBasinsInput) -> ListStream<BasinInfo> {
        let s2 = self.clone();
        let (initial, include_deleted) = input.into_parts();
        paginate_list(
            initial,
            move |req| {
                let s2 = s2.clone();
                async move { s2.list_basins(req).await }
            },
            |req, page| {
                if let Some(next) = page.next_start_after() {
                    req.set_start_after(next);
                    true
                } else {
                    false
                }
            },
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
                self.post("/v1/basins")
                    .header(REQUEST_TOKEN_HEADER.clone(), request_token())
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
        let path = basin_path(&name);
        let req = match body {
            Some(body) => self.put(path).json(&body).build(),
            None => self.put(path).build(),
        };
        let result = self
            .base
            .unary(req, OpScope::basin("ensure_basin", name.as_ref(), false))
            .send_ensure::<api::basin::BasinInfo>()
            .await?;
        Ok(result.map(BasinInfo::from_api))
    }

    /// Get basin configuration.
    pub async fn get_basin_config(&self, name: BasinName) -> Result<BasinConfig, RequestError> {
        let config: api::config::BasinConfig = self
            .base
            .unary(
                self.get(basin_path(&name)).build(),
                OpScope::basin("get_basin_config", name.as_ref(), true),
            )
            .send_json()
            .await?;
        Ok(BasinConfig::from_api(config))
    }

    /// Delete a basin.
    ///
    /// Succeeds if the basin is already being deleted or does not exist.
    pub async fn delete_basin(&self, name: BasinName) -> Result<(), RequestError> {
        self.base
            .unary(
                self.delete(basin_path(&name)).build(),
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
        let config: api::config::BasinConfig = self
            .base
            .unary(
                self.patch(basin_path(&name)).json(&req).build(),
                OpScope::basin("reconfigure_basin", name.as_ref(), false),
            )
            .send_json()
            .await?;
        Ok(BasinConfig::from_api(config))
    }

    /// List a page of access tokens.
    ///
    /// See [`list_all_access_tokens`](Self::list_all_access_tokens) for automatic pagination.
    pub async fn list_access_tokens(
        &self,
        input: ListAccessTokensInput,
    ) -> Result<Page<AccessTokenInfo>, RequestError> {
        let req = input.into_api();
        let response: api::access::ListAccessTokensResponse = self
            .base
            .unary(
                self.get("/v1/access-tokens").query(&req).build(),
                OpScope::account("list_access_tokens", true),
            )
            .send_json()
            .await?;
        Ok(Page::from_api(
            response.access_tokens,
            response.has_more,
            AccessTokenInfo::from_api,
        ))
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
            |req, page| {
                if let Some(next) = page.next_start_after() {
                    req.set_start_after(next);
                    true
                } else {
                    false
                }
            },
            |_| true,
        )
    }

    /// Issue an access token.
    pub async fn issue_access_token(
        &self,
        input: IssueAccessTokenInput,
    ) -> Result<String, RequestError> {
        let scope = OpScope::account("issue_access_token", false);
        let req = input
            .try_into_api()
            .map_err(|e| scope.context(1).format_validation(e))?;
        let response: api::access::IssueAccessTokenResponse = self
            .base
            .unary(self.post("/v1/access-tokens").json(&req).build(), scope)
            .definite_retries_only()
            .send_json()
            .await?;
        Ok(response.access_token)
    }

    /// Revoke an access token.
    ///
    /// Succeeds if the access token does not exist.
    pub async fn revoke_access_token(&self, id: AccessTokenId) -> Result<(), RequestError> {
        self.base
            .unary(
                self.delete(token_path(&id)).build(),
                OpScope::account("revoke_access_token", false),
            )
            .send_delete(ErrorCode::AccessTokenNotFound)
            .await
    }

    /// List a page of network policies.
    ///
    /// See [`list_all_network_policies`](Self::list_all_network_policies) for automatic
    /// pagination.
    pub async fn list_network_policies(
        &self,
        input: ListNetworkPoliciesInput,
    ) -> Result<Page<NetworkPolicyInfo>, RequestError> {
        let req = input.into_api();
        let response: api::network_policy::ListNetworkPoliciesResponse = self
            .base
            .unary(
                self.get("/v1/network-policies").query(&req).build(),
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
            |req, page| {
                if let Some(next) = page.next_start_after() {
                    req.set_start_after(next);
                    true
                } else {
                    false
                }
            },
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
                self.post("/v1/network-policies").json(&req).build(),
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
        let response: api::network_policy::NetworkPolicyInfo = self
            .base
            .unary(
                self.get(network_policy_path(&selector)).build(),
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
        self.base
            .unary(
                self.delete(network_policy_path(&selector)).build(),
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
                self.get("/v1/locations").build(),
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
                self.get("/v1/locations/default").build(),
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
                self.put("/v1/locations/default").json(&location).build(),
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
                self.get("/v1/metrics").query(&req).build(),
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
        let response: api::metrics::MetricSetResponse = self
            .base
            .unary(
                self.get(metrics_basin_path(&basin)).query(&req).build(),
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
        let response: api::metrics::MetricSetResponse = self
            .base
            .unary(
                self.get(metrics_stream_path(&basin, &stream))
                    .query(&req)
                    .build(),
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
            .field("base_url", self.client.base_url())
            .finish_non_exhaustive()
    }
}

impl S2Basin {
    /// Return the name of this basin.
    #[must_use]
    pub fn name(&self) -> &BasinName {
        &self.client.name
    }

    /// Return this basin handle configured with a different [`RetryConfig`] while sharing the same
    /// underlying connection pool and [`S2::close`] lifecycle.
    ///
    /// Stream handles and sessions subsequently opened from the returned handle inherit `retry`;
    /// sibling handles and already-opened sessions keep their own retry settings.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `retry.max_attempts() == 0` or
    /// `retry.min_base_delay() > retry.max_base_delay()`.
    pub fn with_retry(self, retry: RetryConfig) -> Result<Self, ValidationError> {
        if let Err(err) = retry.validate() {
            return Err(self
                .client
                .basin_scope("S2Basin::with_retry", true)
                .context(1)
                .format_validation(err));
        }
        let client = self.client.with_retry(retry)?;
        Ok(Self { client })
    }

    /// Get an [`S2Stream`].
    #[must_use]
    pub fn stream(&self, name: StreamName) -> S2Stream {
        let records_uri = self.client.uri(stream_records_path(&name));
        S2Stream {
            client: self.client.clone(),
            name,
            records_uri,
            encryption: None,
        }
    }

    /// List a page of streams.
    ///
    /// See [`list_all_streams`](Self::list_all_streams) for automatic pagination.
    pub async fn list_streams(
        &self,
        input: ListStreamsInput,
    ) -> Result<Page<StreamInfo>, RequestError> {
        let req = input.into_api();
        let response: api::stream::ListStreamsResponse = self
            .client
            .unary(
                self.client.get("/v1/streams").query(&req).build(),
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
    ///
    /// Excludes streams that are pending deletion unless
    /// [`ListAllStreamsInput::with_include_deleted`] is set to `true`.
    pub fn list_all_streams(&self, input: ListAllStreamsInput) -> ListStream<StreamInfo> {
        let basin = self.clone();
        let (initial, include_deleted) = input.into_parts();
        paginate_list(
            initial,
            move |req| {
                let basin = basin.clone();
                async move { basin.list_streams(req).await }
            },
            |req, page| {
                if let Some(next) = page.next_start_after() {
                    req.set_start_after(next);
                    true
                } else {
                    false
                }
            },
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
                    .post("/v1/streams")
                    .header(REQUEST_TOKEN_HEADER.clone(), request_token())
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

    /// Get stream configuration.
    pub async fn get_stream_config(&self, name: StreamName) -> Result<StreamConfig, RequestError> {
        let config: api::config::StreamConfig = self
            .client
            .unary(
                self.client.get(stream_path(&name)).build(),
                self.client.stream_scope("get_stream_config", &name, true),
            )
            .send_json()
            .await?;
        Ok(StreamConfig::from_api(config))
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
    records_uri: http::Uri,
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

    /// Return this stream handle configured with an [`EncryptionKey`] for record data-plane calls
    /// (`append`, `append_with_stream_config`, `read`, and sessions opened from this handle).
    ///
    /// Sibling handles and already-opened sessions are unaffected. `check_tail` never sends an
    /// encryption key header.
    #[must_use]
    pub fn with_encryption_key(self, encryption: EncryptionKey) -> Self {
        Self {
            encryption: Some(encryption.to_header_value()),
            ..self
        }
    }

    /// Return this stream handle configured with a different [`RetryConfig`] while sharing the
    /// same underlying connection pool and [`S2::close`] lifecycle.
    ///
    /// Operations and sessions subsequently opened from the returned handle use `retry`; sibling
    /// handles and already-opened sessions keep their own retry settings.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `retry.max_attempts() == 0` or
    /// `retry.min_base_delay() > retry.max_base_delay()`.
    pub fn with_retry(self, retry: RetryConfig) -> Result<Self, ValidationError> {
        if let Err(err) = retry.validate() {
            return Err(self
                .client
                .stream_scope("S2Stream::with_retry", &self.name, true)
                .context(1)
                .format_validation(err));
        }
        let client = self.client.with_retry(retry)?;
        Ok(Self { client, ..self })
    }

    fn headers(&self, stream_config: Option<&StreamConfig>) -> StreamHeaders {
        StreamHeaders {
            encryption: self.encryption.clone(),
            stream_config: stream_config.map(encode_stream_config),
        }
    }

    fn ensure_open(&self, op: &'static str, read_only: bool) -> Result<(), ClientClosedError> {
        if self.client.is_closed() {
            return Err(ClientClosedError::new_with_context(ErrorContext::stream(
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
                self.client.get(stream_tail_path(&self.name)).build(),
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
    /// [`AppendSessionConfig::with_stream_config`].)
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
        self.append_inner(input.into(), Some(&stream_config)).await
    }

    async fn append_inner(
        &self,
        input: AppendInput,
        stream_config: Option<&StreamConfig>,
    ) -> Result<AppendAck, AppendError> {
        use prost::Message as _;

        let scope = self.client.stream_scope("append", &self.name, false);
        input
            .validate_for_write()
            .map_err(|e| scope.context(1).format_validation(e))?;
        let expected_records = input.records().len() as u64;
        let proto_input = input.into_proto();
        let headers = self.headers(stream_config);
        let req = self
            .client
            .base()
            .post(self.records_uri.clone())
            .header(CONTENT_TYPE, APPLICATION_PROTOBUF)
            .header(ACCEPT, APPLICATION_PROTOBUF)
            .body(proto_input.encode_to_vec())
            .build()
            .map(|mut req| {
                headers.apply(&mut req);
                req
            });
        let (ack, attempts): (api::stream::proto::AppendAck, u32) = self
            .client
            .unary(req, scope)
            .append_retry_policy()
            .send_proto::<_, AppendError>()
            .await?;
        Ok(AppendAck::try_from_proto(ack, expected_records)
            .map_err(|e| e.with_context(&scope.context(attempts)))?)
    }

    /// Read records.
    ///
    /// Accepts a [`ReadInput`] or a [`ReadStart`](crate::types::ReadStart).
    pub async fn read(&self, input: impl Into<ReadInput>) -> Result<ReadBatch, ReadError> {
        let (start, end, stream_config) = input.into().into_api_parts();
        let headers = self.headers(stream_config.as_ref());
        let scope = self.client.stream_scope("read", &self.name, true);
        let mut builder = self
            .client
            .base()
            .get(self.records_uri.clone())
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
            headers.apply(&mut req);
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
    /// Returns [`AppendSessionError::ClientClosed`] if [`S2::close`] has already been called, or
    /// [`AppendSessionError::Validation`] if `config` is invalid.
    ///
    /// # Panics
    ///
    /// Panics if called outside the context of a Tokio runtime.
    pub fn append_session(
        &self,
        config: AppendSessionConfig,
    ) -> Result<AppendSession, AppendSessionError> {
        self.ensure_open("append_session", false)?;
        let scope = self
            .client
            .stream_scope("append_session", &self.name, false);
        config
            .validate()
            .map_err(|e| scope.context(1).format_validation(e))?;
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
    /// Returns [`AppendSessionError::ClientClosed`] if [`S2::close`] has already been called, or
    /// [`AppendSessionError::Validation`] if `config` is invalid.
    ///
    /// # Panics
    ///
    /// Panics if called outside the context of a Tokio runtime.
    pub fn producer(&self, config: ProducerConfig) -> Result<Producer, AppendSessionError> {
        self.ensure_open("producer", false)?;
        let scope = self.client.stream_scope("producer", &self.name, false);
        config
            .validate()
            .map_err(|e| scope.context(1).format_validation(e))?;
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
    /// Reading is on-demand (no session-level read-ahead): opening validates options and sends no
    /// request, and the first request initiates on the first pull. Request errors surface through
    /// iteration.
    ///
    /// # Errors
    ///
    /// Returns [`ReadSessionError::ClientClosed`] if [`S2::close`] has already been called, or
    /// [`ReadSessionError::Validation`] if `input.count() == Some(0)` or
    /// `input.bytes() == Some(0)`.
    pub fn read_session(
        &self,
        input: impl Into<ReadInput>,
        config: ReadSessionConfig,
    ) -> Result<ReadSession, ReadSessionError> {
        self.ensure_open("read_session", true)?;
        let scope = self.client.stream_scope("read_session", &self.name, true);
        let input = input.into();
        input
            .validate_for_session()
            .map_err(|e| scope.context(1).format_validation(e))?;
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
    /// Reading is on-demand (no session-level read-ahead): opening validates options and sends no
    /// request, and the first request initiates on the first pull. Request errors surface through
    /// iteration.
    ///
    /// # Errors
    ///
    /// Returns [`ReadSessionError::ClientClosed`] if [`S2::close`] has already been called, or
    /// [`ReadSessionError::Validation`] if `input.count() == Some(0)` or
    /// `input.bytes() == Some(0)`.
    pub fn read_batch_session(
        &self,
        input: impl Into<ReadInput>,
        config: ReadSessionConfig,
    ) -> Result<ReadBatchSession, ReadSessionError> {
        self.ensure_open("read_batch_session", true)?;
        let scope = self
            .client
            .stream_scope("read_batch_session", &self.name, true);
        let input = input.into();
        input
            .validate_for_session()
            .map_err(|e| scope.context(1).format_validation(e))?;
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
