use std::{ops::Deref, pin::Pin, sync::Arc, time::Duration};

use async_stream::try_stream;
use async_trait::async_trait;
use bytes::BytesMut;
use futures_core::Stream;
use futures_util::StreamExt;
use http::{
    HeaderMap, HeaderName, HeaderValue, StatusCode, Uri,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
};
use prost::{self, Message};
use s2_api::v1::{
    access::{
        IssueAccessTokenRequest, IssueAccessTokenResponse, ListAccessTokensRequest,
        ListAccessTokensResponse,
    },
    basin::{
        BasinInfo, CreateBasinRequest, EnsureBasinRequest, ListBasinsRequest, ListBasinsResponse,
    },
    config::{
        BasinConfig, BasinReconfiguration, STREAM_CONFIG_HEADER, StreamConfig,
        StreamReconfiguration,
    },
    location::LocationInfo,
    metrics::{
        AccountMetricSetRequest, BasinMetricSetRequest, MetricSetResponse, StreamMetricSetRequest,
    },
    network_policy::{
        CreateNetworkPolicyRequest, ListNetworkPoliciesRequest, ListNetworkPoliciesResponse,
        NetworkPolicyInfo,
    },
    stream::{
        CreateStreamRequest, ListStreamsRequest, ListStreamsResponse, ReadEnd, ReadStart,
        StreamInfo, TailResponse,
        proto::{AppendAck, AppendInput, ReadBatch},
        s2s::{FrameDecoder, SessionMessage, TerminalMessage},
    },
};
use s2_common::{
    encryption::S2_ENCRYPTION_KEY_HEADER,
    resources::{PROVISION_RESULT_HEADER, ProvisionResult},
};
use secrecy::ExposeSecret;
use tokio_util::codec::Decoder;
use tracing::debug;

use crate::{
    client::{self, ShutdownSignal, StreamingResponse, UnaryResponse},
    error::{
        AbortedError, ClientClosedError, ConnectError, ConnectionLostError, ErrorContext,
        FencingTokenMismatchError, OpScope, ProtocolError, ReadUnwrittenError, SeqNumMismatchError,
        ServerError, TimeoutError, classify_http_error,
    },
    frame_signal::FrameSignal,
    reconnect::ReconnectAdvice,
    retry::{AppendRetryError, RetryBackoff, RetryBackoffBuilder},
    types::{
        AccessToken, AccessTokenId, AccessTokenMode, AppendRetryPolicy, BasinAuthority, BasinName,
        Compression, FencingToken, LocationName, NetworkPolicySelector, RetryConfig, S2Config,
        S2Endpoints, StreamName, ValidationError,
    },
};

const CONTENT_TYPE_S2S: &str = "s2s/proto";
const CONTENT_TYPE_PROTO: &str = "application/protobuf";
const ACCEPT_PROTO: &str = "application/protobuf";
const S2_REQUEST_TOKEN: &str = "s2-request-token";
const S2_ATTEMPT: HeaderName = HeaderName::from_static("s2-attempt");
const S2_BASIN: HeaderName = HeaderName::from_static("s2-basin");
const RETRY_AFTER_MS_HEADER: &str = "retry-after-ms";

#[derive(Debug, Clone)]
pub struct AccountClient {
    pub client: BaseClient,
    pub config: Arc<S2Config>,
    pub base_url: Uri,
}

impl AccountClient {
    pub fn init(config: S2Config, client: BaseClient) -> Self {
        let base_url = base_url(&config.endpoints, ClientKind::Account);
        Self {
            client,
            config: Arc::new(config),
            base_url,
        }
    }

    pub fn basin_client(&self, name: BasinName) -> BasinClient {
        BasinClient::init(name, self.config.clone(), self.client.clone())
    }

    fn uri(&self, path: impl AsRef<str>) -> Uri {
        client::uri_with_path(&self.base_url, path)
    }

    pub async fn list_access_tokens(
        &self,
        request: ListAccessTokensRequest,
    ) -> Result<ListAccessTokensResponse, ApiError> {
        let scope = OpScope::account("list_access_tokens", true);
        let url = self.uri("v1/access-tokens");
        let request = self
            .get(url)
            .query(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<ListAccessTokensResponse>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn issue_access_token(
        &self,
        request: IssueAccessTokenRequest,
    ) -> Result<IssueAccessTokenResponse, ApiError> {
        let scope = OpScope::account("issue_access_token", false);
        let url = self.uri("v1/access-tokens");
        let request = self
            .post(url)
            .json(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self
            .request(request, scope)
            .with_definite_retries_only()
            .send()
            .await?;
        response
            .json::<IssueAccessTokenResponse>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn revoke_access_token(&self, id: AccessTokenId) -> Result<(), ApiError> {
        let scope = OpScope::account("revoke_access_token", false);
        let url = self.uri(format!("v1/access-tokens/{}", urlencoding::encode(&id)));
        let request = self
            .delete(url)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        self.request(request, scope)
            .send()
            .await
            .ignore_not_found_code("access_token_not_found")?;
        Ok(())
    }

    pub async fn list_network_policies(
        &self,
        request: ListNetworkPoliciesRequest,
    ) -> Result<ListNetworkPoliciesResponse, ApiError> {
        let scope = OpScope::account("list_network_policies", true);
        let url = self.uri("v1/network-policies");
        let request = self
            .get(url)
            .query(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<ListNetworkPoliciesResponse>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn create_network_policy(
        &self,
        request: CreateNetworkPolicyRequest,
    ) -> Result<NetworkPolicyInfo, ApiError> {
        let scope = OpScope::account("create_network_policy", false);
        let url = self.uri("v1/network-policies");
        let request = self
            .post(url)
            .json(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self
            .request(request, scope)
            .with_definite_retries_only()
            .send()
            .await?;
        response
            .json::<NetworkPolicyInfo>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn get_network_policy(
        &self,
        selector: NetworkPolicySelector,
    ) -> Result<NetworkPolicyInfo, ApiError> {
        let scope = OpScope::account("get_network_policy", true);
        let url = self.uri(format!(
            "v1/network-policies/{}",
            urlencoding::encode(&selector.to_string())
        ));
        let request = self
            .get(url)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<NetworkPolicyInfo>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn delete_network_policy(
        &self,
        selector: NetworkPolicySelector,
    ) -> Result<(), ApiError> {
        let scope = OpScope::account("delete_network_policy", false);
        let url = self.uri(format!(
            "v1/network-policies/{}",
            urlencoding::encode(&selector.to_string())
        ));
        let request = self
            .delete(url)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        self.request(request, scope)
            .send()
            .await
            .ignore_not_found_code("network_policy_not_found")?;
        Ok(())
    }

    pub async fn list_locations(&self) -> Result<Vec<LocationInfo>, ApiError> {
        let scope = OpScope::account("list_locations", true);
        let url = self.uri("v1/locations");
        let request = self
            .get(url)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<Vec<LocationInfo>>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn get_default_location(&self) -> Result<LocationInfo, ApiError> {
        let scope = OpScope::account("get_default_location", true);
        let url = self.uri("v1/locations/default");
        let request = self
            .get(url)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<LocationInfo>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn set_default_location(
        &self,
        location: LocationName,
    ) -> Result<LocationInfo, ApiError> {
        let scope = OpScope::account("set_default_location", false);
        let url = self.uri("v1/locations/default");
        let request = self
            .put(url)
            .json(&location)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<LocationInfo>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn list_basins(
        &self,
        request: ListBasinsRequest,
    ) -> Result<ListBasinsResponse, ApiError> {
        let scope = OpScope::account("list_basins", true);
        let url = self.uri("v1/basins");
        let request = self
            .get(url)
            .query(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<ListBasinsResponse>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn create_basin(
        &self,
        request: CreateBasinRequest,
        idempotency_token: String,
    ) -> Result<BasinInfo, ApiError> {
        let basin_name = request.basin.clone();
        let scope = OpScope::basin("create_basin", basin_name.as_ref(), false);
        let url = self.uri("v1/basins");
        let request = self
            .post(url)
            .header(S2_REQUEST_TOKEN, idempotency_token)
            .json(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<BasinInfo>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn get_basin_config(&self, name: BasinName) -> Result<BasinConfig, ApiError> {
        let scope = OpScope::basin("get_basin_config", name.as_ref(), true);
        let url = self.uri(format!("v1/basins/{name}"));
        let request = self
            .get(url)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<BasinConfig>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn reconfigure_basin(
        &self,
        name: BasinName,
        config: BasinReconfiguration,
    ) -> Result<BasinConfig, ApiError> {
        let scope = OpScope::basin("reconfigure_basin", name.as_ref(), false);
        let url = self.uri(format!("v1/basins/{name}"));
        let request = self
            .patch(url)
            .json(&config)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<BasinConfig>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn ensure_basin(
        &self,
        name: BasinName,
        request: Option<EnsureBasinRequest>,
    ) -> Result<ProvisionResult<BasinInfo>, ApiError> {
        let scope = OpScope::basin("ensure_basin", name.as_ref(), false);
        let url = self.uri(format!("v1/basins/{name}"));
        let request = match request {
            Some(body) => self.put(url).json(&body).build(),
            None => self.put(url).build(),
        }
        .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        let status = response.status();
        let provision_result_header_value = provision_result_header_value(&response);
        let info = response
            .json::<BasinInfo>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        Ok(provision_result_from_parts(
            status,
            provision_result_header_value.as_deref(),
            info,
        ))
    }

    pub async fn delete_basin(&self, name: BasinName) -> Result<(), ApiError> {
        let scope = OpScope::basin("delete_basin", name.as_ref(), false);
        let url = self.uri(format!("v1/basins/{name}"));
        let request = self
            .delete(url)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        self.request(request, scope)
            .send()
            .await
            .ignore_not_found_code("basin_not_found")?;
        Ok(())
    }

    pub async fn get_account_metrics(
        &self,
        request: AccountMetricSetRequest,
    ) -> Result<MetricSetResponse, ApiError> {
        let scope = OpScope::account("get_account_metrics", true);
        let url = self.uri("v1/metrics");
        let request = self
            .get(url)
            .query(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<MetricSetResponse>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn get_basin_metrics(
        &self,
        name: BasinName,
        request: BasinMetricSetRequest,
    ) -> Result<MetricSetResponse, ApiError> {
        let scope = OpScope::basin("get_basin_metrics", name.as_ref(), true);
        let url = self.uri(format!("v1/metrics/{name}"));
        let request = self
            .get(url)
            .query(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<MetricSetResponse>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn get_stream_metrics(
        &self,
        basin_name: BasinName,
        stream_name: StreamName,
        request: StreamMetricSetRequest,
    ) -> Result<MetricSetResponse, ApiError> {
        let scope = OpScope::stream(
            "get_stream_metrics",
            basin_name.as_ref(),
            stream_name.as_ref(),
            true,
        );
        let url = self.uri(format!(
            "v1/metrics/{basin_name}/{}",
            urlencoding::encode(&stream_name)
        ));
        let request = self
            .get(url)
            .query(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<MetricSetResponse>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }
}

impl Deref for AccountClient {
    type Target = BaseClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

#[derive(Debug, Clone)]
pub struct BasinClient {
    pub name: BasinName,
    pub client: BaseClient,
    pub config: Arc<S2Config>,
    pub base_url: Uri,
    basin_header: Option<HeaderValue>,
}

impl BasinClient {
    pub fn init(name: BasinName, config: Arc<S2Config>, client: BaseClient) -> Self {
        let base_url = base_url(&config.endpoints, ClientKind::Basin(name.clone()));
        let basin_header = matches!(config.endpoints.basin_authority, BasinAuthority::Direct(_))
            .then(|| HeaderValue::from_str(&name).expect("valid header value"));
        Self {
            name,
            client,
            config,
            base_url,
            basin_header,
        }
    }

    fn uri(&self, path: impl AsRef<str>) -> Uri {
        client::uri_with_path(&self.base_url, path)
    }

    fn apply_basin_header(&self, request: &mut client::Request) {
        if let Some(ref header) = self.basin_header {
            request.headers_mut().insert(S2_BASIN, header.clone());
        }
    }

    fn request<'a>(&'a self, mut request: client::Request, scope: OpScope<'a>) -> RequestBuilder<'a> {
        self.apply_basin_header(&mut request);
        self.client.request(request, scope)
    }

    pub async fn list_streams(
        &self,
        request: ListStreamsRequest,
    ) -> Result<ListStreamsResponse, ApiError> {
        let scope = OpScope::basin("list_streams", self.name.as_ref(), true);
        let url = self.uri("v1/streams");
        let request = self
            .get(url)
            .query(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<ListStreamsResponse>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn create_stream(
        &self,
        request: CreateStreamRequest,
        idempotency_token: String,
    ) -> Result<StreamInfo, ApiError> {
        let stream_name = request.stream.clone();
        let scope = OpScope::stream(
            "create_stream",
            self.name.as_ref(),
            stream_name.as_ref(),
            false,
        );
        let url = self.uri("v1/streams");
        let request = self
            .post(url)
            .header(S2_REQUEST_TOKEN, idempotency_token)
            .json(&request)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<StreamInfo>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn get_stream_config(&self, name: StreamName) -> Result<StreamConfig, ApiError> {
        let scope = OpScope::stream("get_stream_config", self.name.as_ref(), name.as_ref(), true);
        let url = self.uri(format!("v1/streams/{}", urlencoding::encode(&name)));
        let request = self
            .get(url)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<StreamConfig>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn reconfigure_stream(
        &self,
        name: StreamName,
        config: StreamReconfiguration,
    ) -> Result<StreamConfig, ApiError> {
        let scope = OpScope::stream(
            "reconfigure_stream",
            self.name.as_ref(),
            name.as_ref(),
            false,
        );
        let url = self.uri(format!("v1/streams/{}", urlencoding::encode(&name)));
        let request = self
            .patch(url)
            .json(&config)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<StreamConfig>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn ensure_stream(
        &self,
        name: StreamName,
        config: Option<StreamConfig>,
    ) -> Result<ProvisionResult<StreamInfo>, ApiError> {
        let scope = OpScope::stream("ensure_stream", self.name.as_ref(), name.as_ref(), false);
        let url = self.uri(format!("v1/streams/{}", urlencoding::encode(&name)));
        let request = match config {
            Some(body) => self.put(url).json(&body).build(),
            None => self.put(url).build(),
        }
        .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        let status = response.status();
        let provision_result_header_value = provision_result_header_value(&response);
        let info = response
            .json::<StreamInfo>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        Ok(provision_result_from_parts(
            status,
            provision_result_header_value.as_deref(),
            info,
        ))
    }

    pub async fn delete_stream(&self, name: StreamName) -> Result<(), ApiError> {
        let scope = OpScope::stream("delete_stream", self.name.as_ref(), name.as_ref(), false);
        let url = self.uri(format!("v1/streams/{}", urlencoding::encode(&name)));
        let request = self
            .delete(url)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        self.request(request, scope)
            .send()
            .await
            .ignore_not_found_code("stream_not_found")?;
        Ok(())
    }

    pub async fn check_tail(&self, name: &StreamName) -> Result<TailResponse, ApiError> {
        let scope = OpScope::stream("check_tail", self.name.as_ref(), name.as_ref(), true);
        let url = self.uri(format!(
            "v1/streams/{}/records/tail",
            urlencoding::encode(name)
        ));
        let request = self
            .get(url)
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        let response = self.request(request, scope).send().await?;
        response
            .json::<TailResponse>()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))
    }

    pub async fn append(
        &self,
        name: &StreamName,
        input: AppendInput,
        encryption: Option<&HeaderValue>,
        stream_config: Option<&HeaderValue>,
        append_retry_policy: AppendRetryPolicy,
    ) -> Result<AppendAck, ApiError> {
        let scope = OpScope::stream("append", self.name.as_ref(), name.as_ref(), false);
        let url = self.uri(format!("v1/streams/{}/records", urlencoding::encode(name)));
        let mut request = self
            .post(url)
            .header(CONTENT_TYPE, CONTENT_TYPE_PROTO)
            .header(ACCEPT, ACCEPT_PROTO)
            .body(input.encode_to_vec())
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        set_header_opt(&mut request, &S2_ENCRYPTION_KEY_HEADER, encryption);
        set_header_opt(&mut request, &STREAM_CONFIG_HEADER, stream_config);
        let response = self
            .request(request, scope)
            .with_append_retry_policy(append_retry_policy)
            .error_handler(|status, response, ctx| {
                Err(parse_append_error_response(
                    status,
                    &response.into_bytes(),
                    ctx,
                ))
            })
            .send()
            .await?;
        AppendAck::decode(response.into_bytes()).map_err(|e| {
            ApiError::Protocol(ProtocolError::new(
                format!("protobuf decode: {e}"),
                scope.context(1),
            ))
        })
    }

    pub async fn read(
        &self,
        name: &StreamName,
        start: ReadStart,
        end: ReadEnd,
        encryption: Option<&HeaderValue>,
        stream_config: Option<&HeaderValue>,
    ) -> Result<ReadBatch, ApiError> {
        let scope = OpScope::stream("read", self.name.as_ref(), name.as_ref(), true);
        let url = self.uri(format!("v1/streams/{}/records", urlencoding::encode(name)));
        let mut builder = self
            .get(url)
            .header(ACCEPT, ACCEPT_PROTO)
            .query(&start)
            .query(&end);
        if let Some(wait) = end.wait {
            builder = builder.timeout(
                self.client
                    .request_timeout
                    .saturating_add(Duration::from_secs(wait.into())),
            );
        }
        let mut request = builder
            .build()
            .map_err(|e| ApiError::from_http(e, scope.context(1)))?;
        set_header_opt(&mut request, &S2_ENCRYPTION_KEY_HEADER, encryption);
        set_header_opt(&mut request, &STREAM_CONFIG_HEADER, stream_config);
        let response = self
            .request(request, scope)
            .error_handler(|status, response, ctx| {
                Err(parse_read_error_response(
                    status,
                    &response.into_bytes(),
                    ctx,
                ))
            })
            .send()
            .await?;
        ReadBatch::decode(response.into_bytes()).map_err(|e| {
            ApiError::Protocol(ProtocolError::new(
                format!("protobuf decode: {e}"),
                scope.context(1),
            ))
        })
    }

    async fn open_s2s<T: Message + Default + 'static>(
        &self,
        mut request: client::Request,
        encryption: Option<&HeaderValue>,
        stream_config: Option<&HeaderValue>,
        reconnect: ReconnectAdvice,
        kind: TerminalKind,
        ctx: ErrorContext,
    ) -> Result<Streaming<T>, ApiError> {
        self.apply_basin_header(&mut request);
        set_header_opt(&mut request, &S2_ENCRYPTION_KEY_HEADER, encryption);
        set_header_opt(&mut request, &STREAM_CONFIG_HEADER, stream_config);

        let (response, access_token) = self
            .client
            .init_streaming_authorized(request, ctx.clone())
            .await?;
        let response = match response.into_result(kind, ctx.clone()).await {
            Ok(response) => response,
            Err(error) => {
                self.client
                    .invalidate_access_token_if_rejected(&error, access_token.as_deref());
                return Err(error);
            }
        };
        let (mut bytes_stream, poison_handle) = response.into_stream();
        let auth_client = self.client.clone();

        let mut buffer = BytesMut::new();
        let mut decoder = FrameDecoder;

        Ok(Box::pin(try_stream! {
            let mut advice_seen = false;

            while let Some(chunk) = bytes_stream.next().await {
                let chunk = chunk.map_err(|e| ApiError::from_http(e, ctx.clone()))?;
                buffer.extend_from_slice(&chunk);

                loop {
                    match decoder.decode(&mut buffer) {
                        Ok(Some(SessionMessage::Regular(msg))) => {
                            if !advice_seen && msg.reconnect_advised() {
                                advice_seen = true;
                                poison_handle.poison();
                                reconnect.advise();
                            }
                            yield msg.try_into_proto().map_err(|e| {
                                ApiError::Protocol(ProtocolError::new(
                                    format!("protobuf decode: {e}"),
                                    ctx.clone(),
                                ))
                            })?;
                        }
                        Ok(Some(SessionMessage::Terminal(msg))) => {
                            let error = ApiError::from_terminal_message(msg, kind, ctx.clone());
                            if error.should_retire_connection() {
                                poison_handle.poison();
                            }
                            auth_client.invalidate_access_token_if_rejected(
                                &error,
                                access_token.as_deref(),
                            );
                            Err::<(), ApiError>(error)?;
                        }
                        Ok(None) => break,
                        Err(err) => Err(ApiError::Protocol(ProtocolError::new(
                            format!("s2s frame decode: {err}"),
                            ctx.clone(),
                        )))?,
                    }
                }
            }
            if !buffer.is_empty() {
                Err(ApiError::ConnectionLost(ConnectionLostError::new(
                    format!(
                        "truncated s2s frame at end of stream ({} bytes remaining)",
                        buffer.len()
                    ),
                    false,
                    ctx.clone(),
                )))?;
            }
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn append_session<I>(
        &self,
        name: &StreamName,
        encoded_chunks: I,
        encryption: Option<&HeaderValue>,
        stream_config: Option<&HeaderValue>,
        reconnect: ReconnectAdvice,
        attempt: u32,
    ) -> Result<Streaming<AppendAck>, ApiError>
    where
        I: Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static,
    {
        let ctx = ErrorContext::stream("append_session", self.name.as_ref(), name.as_ref(), false);
        if self.client.is_closed() {
            return Err(ApiError::ClientClosed(ClientClosedError::new(ctx)));
        }
        let url = self.uri(format!("v1/streams/{}/records", urlencoding::encode(name)));
        let request = self
            .client
            .post(url)
            .header(CONTENT_TYPE, CONTENT_TYPE_S2S)
            .header(S2_ATTEMPT, HeaderValue::from(attempt))
            .body(client::Body::wrap_stream(encoded_chunks))
            .timeout(self.client.request_timeout)
            .build()
            .map_err(|e| ApiError::from_http(e, ctx.clone()))?;
        self.open_s2s(
            request,
            encryption,
            stream_config,
            reconnect,
            TerminalKind::Append,
            ctx,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn read_session(
        &self,
        name: &StreamName,
        start: ReadStart,
        end: ReadEnd,
        encryption: Option<&HeaderValue>,
        stream_config: Option<&HeaderValue>,
        reconnect: ReconnectAdvice,
        attempt: u32,
    ) -> Result<Streaming<ReadBatch>, ApiError> {
        let ctx = ErrorContext::stream("read_session", self.name.as_ref(), name.as_ref(), true);
        if self.client.is_closed() {
            return Err(ApiError::ClientClosed(ClientClosedError::new(ctx)));
        }
        let url = self.uri(format!("v1/streams/{}/records", urlencoding::encode(name)));
        let request = self
            .client
            .get(url)
            .header(CONTENT_TYPE, CONTENT_TYPE_S2S)
            .header(S2_ATTEMPT, HeaderValue::from(attempt))
            .query(&start)
            .query(&end)
            .timeout(self.client.request_timeout)
            .build()
            .map_err(|e| ApiError::from_http(e, ctx.clone()))?;
        self.open_s2s(
            request,
            encryption,
            stream_config,
            reconnect,
            TerminalKind::Read,
            ctx,
        )
        .await
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TerminalKind {
    Append,
    Read,
}

#[derive(serde::Deserialize)]
struct AppendConditionFailedBody {
    seq_num_mismatch: Option<u64>,
    fencing_token_mismatch: Option<String>,
}

pub(crate) fn parse_append_error_response(
    status: StatusCode,
    body: &[u8],
    context: ErrorContext,
) -> ApiError {
    if status == StatusCode::PRECONDITION_FAILED
        && let Ok(parsed) = serde_json::from_slice::<AppendConditionFailedBody>(body)
    {
        match (parsed.seq_num_mismatch, parsed.fencing_token_mismatch) {
            (Some(assignable_seq_num), None) => {
                let server = ServerError::from_response(status, body, context);
                return ApiError::SeqNumMismatch(SeqNumMismatchError::new(
                    assignable_seq_num,
                    server,
                ));
            }
            (None, Some(token)) => {
                let server = ServerError::from_response(status, body, context);
                return ApiError::FencingTokenMismatch(FencingTokenMismatchError::new(
                    FencingToken::from_server(token),
                    server,
                ));
            }
            _ => {}
        }
    }
    ApiError::Server(ServerError::from_response(status, body, context))
}

pub(crate) fn parse_read_error_response(
    status: StatusCode,
    body: &[u8],
    context: ErrorContext,
) -> ApiError {
    let context = context.into_read_only();
    if status == StatusCode::RANGE_NOT_SATISFIABLE
        && let Ok(tail) = serde_json::from_slice::<TailResponse>(body)
    {
        let server = ServerError::from_response(status, body, context);
        return ApiError::ReadUnwritten(ReadUnwrittenError::new(tail.tail.into(), server));
    }
    ApiError::Server(ServerError::from_response(status, body, context))
}

impl Deref for BasinClient {
    type Target = BaseClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

#[derive(Debug, thiserror::Error, serde::Deserialize)]
#[error("{code}: {message}")]
pub(crate) struct ServerErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error(transparent)]
    Server(#[from] ServerError),
    #[error(transparent)]
    SeqNumMismatch(#[from] SeqNumMismatchError),
    #[error(transparent)]
    FencingTokenMismatch(#[from] FencingTokenMismatchError),
    #[error(transparent)]
    ReadUnwritten(#[from] ReadUnwrittenError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error(transparent)]
    ConnectionLost(#[from] ConnectionLostError),
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    ClientClosed(#[from] ClientClosedError),
    #[error(transparent)]
    Aborted(#[from] AbortedError),
    #[cfg(feature = "_hidden")]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(crate::types::AccessTokenProviderError),
    #[error(
        "append may have taken effect in an earlier attempt; final attempt failed: {final_attempt_error}"
    )]
    IndefiniteAppend {
        #[source]
        final_attempt_error: Box<Self>,
    },
}

impl ApiError {
    pub(crate) fn from_http(err: client::HttpError, context: ErrorContext) -> Self {
        classify_http_error(err, context)
    }

    pub(crate) fn from_terminal_message(
        msg: TerminalMessage,
        kind: TerminalKind,
        context: ErrorContext,
    ) -> Self {
        let status = match StatusCode::from_u16(msg.status) {
            Ok(status) if (300..600).contains(&status.as_u16()) => status,
            Ok(status) => {
                return Self::Protocol(ProtocolError::new(
                    format!("unexpected non-error status code in terminal frame: {status}"),
                    context,
                ));
            }
            Err(err) => {
                return Self::Protocol(ProtocolError::new(
                    format!("invalid status code in terminal frame: {err}"),
                    context,
                ));
            }
        };
        match kind {
            TerminalKind::Append => parse_append_error_response(status, &msg.body, context),
            TerminalKind::Read => parse_read_error_response(status, &msg.body, context),
        }
    }

    pub(crate) fn with_context(self, context: &ErrorContext) -> Self {
        match self {
            Self::Server(e) => Self::Server(e.with_context(context)),
            Self::SeqNumMismatch(e) => Self::SeqNumMismatch(e.with_context(context)),
            Self::FencingTokenMismatch(e) => Self::FencingTokenMismatch(e.with_context(context)),
            Self::ReadUnwritten(e) => Self::ReadUnwritten(e.with_context(context)),
            Self::Validation(e) => Self::Validation(e),
            Self::Connect(e) => Self::Connect(e.with_context(context)),
            Self::ConnectionLost(e) => Self::ConnectionLost(e.with_context(context)),
            Self::Timeout(e) => Self::Timeout(e.with_context(context)),
            Self::Protocol(e) => Self::Protocol(e.with_context(context)),
            Self::ClientClosed(e) => Self::ClientClosed(e.with_context(context)),
            Self::Aborted(e) => Self::Aborted(e.with_context(context)),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
            Self::IndefiniteAppend {
                final_attempt_error,
            } => Self::IndefiniteAppend {
                final_attempt_error: Box::new(final_attempt_error.with_context(context)),
            },
        }
    }

    pub(crate) fn into_read_only(self) -> Self {
        match self {
            Self::Server(e) => Self::Server(e.into_read_only()),
            Self::SeqNumMismatch(e) => Self::SeqNumMismatch(e),
            Self::FencingTokenMismatch(e) => Self::FencingTokenMismatch(e),
            Self::ReadUnwritten(e) => Self::ReadUnwritten(e),
            Self::Validation(e) => Self::Validation(e),
            Self::Connect(e) => Self::Connect(e.into_read_only()),
            Self::ConnectionLost(e) => Self::ConnectionLost(e.into_read_only()),
            Self::Timeout(e) => Self::Timeout(e.into_read_only()),
            Self::Protocol(e) => Self::Protocol(e.into_read_only()),
            Self::ClientClosed(e) => Self::ClientClosed(e),
            Self::Aborted(e) => Self::Aborted(e.into_read_only()),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(e) => Self::AccessTokenProvider(e),
            Self::IndefiniteAppend {
                final_attempt_error,
            } => Self::IndefiniteAppend {
                final_attempt_error: Box::new(final_attempt_error.into_read_only()),
            },
        }
    }

    pub(crate) fn mark_unsent_connection_lost(self, unsent: bool) -> Self {
        if !unsent {
            return self;
        }
        match self {
            Self::ConnectionLost(e) => Self::ConnectionLost(e.with_no_side_effects(true)),
            other => other,
        }
    }

    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Server(e) => e.is_retryable(),
            Self::SeqNumMismatch(e) => e.is_retryable(),
            Self::FencingTokenMismatch(e) => e.is_retryable(),
            Self::ReadUnwritten(e) => e.is_retryable(),
            Self::Validation(_) => false,
            Self::Connect(e) => e.is_retryable(),
            Self::ConnectionLost(e) => e.is_retryable(),
            Self::Timeout(e) => e.is_retryable(),
            Self::Protocol(e) => e.is_retryable(),
            Self::ClientClosed(e) => e.is_retryable(),
            Self::Aborted(e) => e.is_retryable(),
            Self::IndefiniteAppend {
                final_attempt_error,
            } => final_attempt_error.is_retryable(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(error) => error.is_retryable(),
        }
    }

    pub(crate) fn is_server_draining(&self) -> bool {
        matches!(self, Self::Server(e) if e.is_server_draining())
    }

    pub(crate) fn should_retire_connection(&self) -> bool {
        matches!(self, Self::Server(e) if e.should_retire_connection())
    }

    pub(crate) fn is_authentication_error(&self) -> bool {
        matches!(self, Self::Server(e) if e.is_authentication_error())
    }
}

impl AppendRetryError for ApiError {
    fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Server(e) => e.has_no_side_effects(),
            Self::SeqNumMismatch(e) => e.has_no_side_effects(),
            Self::FencingTokenMismatch(e) => e.has_no_side_effects(),
            Self::ReadUnwritten(e) => e.has_no_side_effects(),
            Self::Validation(_) => true,
            Self::Connect(e) => e.has_no_side_effects(),
            Self::ConnectionLost(e) => e.has_no_side_effects(),
            Self::Timeout(e) => e.has_no_side_effects(),
            Self::Protocol(e) => e.has_no_side_effects(),
            Self::ClientClosed(e) => e.has_no_side_effects(),
            Self::Aborted(e) => e.has_no_side_effects(),
            Self::IndefiniteAppend { .. } => false,
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(_) => true,
        }
    }

    fn into_indefinite_failure(self) -> Self {
        Self::IndefiniteAppend {
            final_attempt_error: Box::new(self),
        }
    }
}

pub type Streaming<R> = Pin<Box<dyn Send + Stream<Item = Result<R, ApiError>>>>;

pub(crate) fn authorization_header(access_token: &str) -> Result<HeaderValue, ValidationError> {
    if access_token.is_empty() {
        return Err(ValidationError(
            "invalid access token: must not be empty".into(),
        ));
    }
    let mut header = HeaderValue::try_from(format!("Bearer {access_token}"))
        .map_err(|error| ValidationError(format!("invalid access token: {error}")))?;
    header.set_sensitive(true);
    Ok(header)
}

struct PreparedClientConfig {
    default_headers: HeaderMap,
    access_token_mode: AccessTokenMode,
    #[cfg(feature = "_hidden")]
    access_token_provider: Option<Arc<dyn crate::types::AccessTokenProvider>>,
}

#[derive(Clone)]
pub struct BaseClient {
    client: Arc<dyn client::RequestExecutor>,
    shutdown: ShutdownSignal,
    default_headers: HeaderMap,
    access_token_mode: AccessTokenMode,
    #[cfg(feature = "_hidden")]
    access_token_provider: Option<Arc<dyn crate::types::AccessTokenProvider>>,
    request_timeout: Duration,
    retry_builder: RetryBackoffBuilder,
    compression: Compression,
}

impl std::fmt::Debug for BaseClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BaseClient").finish_non_exhaustive()
    }
}

impl BaseClient {
    pub fn init(config: &S2Config) -> Result<Self, ValidationError> {
        // Validate config and static token BEFORE initializing TLS so invalid configs never get
        // masked by missing TLS providers or native CA errors.
        let prepared = Self::prepare(config)?;
        let shutdown = ShutdownSignal::new();
        if config.endpoints.scheme == http::uri::Scheme::HTTP {
            let connector = client::default_http_connector(Some(config.connection_timeout));
            Ok(Self::from_prepared(config, prepared, connector, shutdown))
        } else {
            let connector = client::default_connector(
                Some(config.connection_timeout),
                config.insecure_skip_cert_verification,
                config.rustls_crypto_provider.clone(),
            )
            .map_err(|e| ValidationError(format!("failed to initialize TLS connector: {e}")))?;
            Ok(Self::from_prepared(config, prepared, connector, shutdown))
        }
    }

    #[cfg(feature = "_hidden")]
    pub fn init_with_connector<C>(config: &S2Config, connector: C) -> Result<Self, ValidationError>
    where
        C: client::Connect,
    {
        let prepared = Self::prepare(config)?;
        Ok(Self::from_prepared(
            config,
            prepared,
            connector,
            ShutdownSignal::new(),
        ))
    }

    fn prepare(config: &S2Config) -> Result<PreparedClientConfig, ValidationError> {
        config.validate()?;
        let access_token_mode = config.access_token.mode();
        let mut default_headers = config.default_headers.clone();
        // Authorization belongs to the configured token, including when a
        // refreshable provider supplies it immediately before each attempt.
        default_headers.remove(AUTHORIZATION);
        #[cfg(feature = "_hidden")]
        let mut access_token_provider = None;
        match &config.access_token {
            AccessToken::Static(access_token) => {
                default_headers.insert(
                    AUTHORIZATION,
                    authorization_header(access_token.expose_secret())?,
                );
            }
            #[cfg(feature = "_hidden")]
            AccessToken::Provider(provider) => {
                access_token_provider = Some(provider.clone());
            }
        }
        default_headers.insert(http::header::USER_AGENT, config.user_agent.clone());
        match config.compression {
            Compression::Gzip => {
                default_headers.insert(
                    http::header::ACCEPT_ENCODING,
                    HeaderValue::from_static("gzip"),
                );
            }
            Compression::Zstd => {
                default_headers.insert(
                    http::header::ACCEPT_ENCODING,
                    HeaderValue::from_static("zstd"),
                );
            }
            Compression::None => {}
        }

        Ok(PreparedClientConfig {
            default_headers,
            access_token_mode,
            #[cfg(feature = "_hidden")]
            access_token_provider,
        })
    }

    fn from_prepared<C>(
        config: &S2Config,
        prepared: PreparedClientConfig,
        connector: C,
        shutdown: ShutdownSignal,
    ) -> Self
    where
        C: client::Connect,
    {
        let client = client::Pool::new(
            connector,
            config.connection_timeout,
            config.http2,
            shutdown.clone(),
        );

        Self {
            client: Arc::new(client),
            shutdown,
            default_headers: prepared.default_headers,
            access_token_mode: prepared.access_token_mode,
            #[cfg(feature = "_hidden")]
            access_token_provider: prepared.access_token_provider,
            request_timeout: config.request_timeout,
            retry_builder: retry_builder(&config.retry),
            compression: config.compression,
        }
    }

    pub fn close(&self) {
        self.shutdown.close();
        self.client.close();
    }

    pub fn is_closed(&self) -> bool {
        self.shutdown.is_closed()
    }

    pub(crate) fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown.clone()
    }

    pub fn get(&self, uri: Uri) -> client::RequestBuilder {
        client::RequestBuilder::get(uri)
            .timeout(self.request_timeout)
            .headers(&self.default_headers)
    }

    pub fn post(&self, uri: Uri) -> client::RequestBuilder {
        client::RequestBuilder::post(uri)
            .timeout(self.request_timeout)
            .headers(&self.default_headers)
            .compression(self.compression)
    }

    pub fn patch(&self, uri: Uri) -> client::RequestBuilder {
        client::RequestBuilder::patch(uri)
            .timeout(self.request_timeout)
            .headers(&self.default_headers)
            .compression(self.compression)
    }

    pub fn put(&self, uri: Uri) -> client::RequestBuilder {
        client::RequestBuilder::put(uri)
            .timeout(self.request_timeout)
            .headers(&self.default_headers)
            .compression(self.compression)
    }

    pub fn delete(&self, uri: Uri) -> client::RequestBuilder {
        client::RequestBuilder::delete(uri)
            .timeout(self.request_timeout)
            .headers(&self.default_headers)
    }

    pub async fn init_streaming(
        &self,
        request: client::Request,
    ) -> Result<StreamingResponse, client::HttpError> {
        self.client.init_streaming(request).await
    }

    #[cfg(not(feature = "_hidden"))]
    async fn init_streaming_authorized(
        &self,
        request: client::Request,
        context: ErrorContext,
    ) -> Result<(StreamingResponse, Option<String>), ApiError> {
        self.init_streaming(request)
            .await
            .map(|response| (response, None))
            .map_err(|e| ApiError::from_http(e, context))
    }

    #[cfg(feature = "_hidden")]
    async fn init_streaming_authorized(
        &self,
        mut request: client::Request,
        context: ErrorContext,
    ) -> Result<(StreamingResponse, Option<String>), ApiError> {
        let access_token = self.authorize(&mut request).await?;
        let response = self
            .init_streaming(request)
            .await
            .map_err(|e| ApiError::from_http(e, context))?;
        Ok((response, access_token))
    }

    async fn execute_unary_in_flight(
        &self,
        mut request: client::Request,
        scope: OpScope<'_>,
        attempts: u32,
    ) -> Result<(UnaryResponse, Option<String>), ApiError> {
        let shutdown = self.shutdown.clone();
        let access_token = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                return Err(ApiError::Aborted(AbortedError::new(
                    "client closed",
                    scope.context(attempts),
                )));
            }
            res = self.authorize(&mut request) => res?,
        };
        let response = self.client.execute_unary(request).await.map_err(|e| {
            let ctx = scope.context(attempts);
            match e {
                // Once a unary call passed entry-time closed check, closing the client aborts it
                // rather than returning ClientClosedError (`C12`).
                client::HttpError::ClientClosed => {
                    ApiError::Aborted(AbortedError::new("client closed", ctx))
                }
                other => ApiError::from_http(other, ctx),
            }
        })?;
        Ok((response, access_token))
    }

    async fn authorize(&self, _request: &mut client::Request) -> Result<Option<String>, ApiError> {
        #[cfg(feature = "_hidden")]
        if let Some(provider) = self.access_token_provider.as_ref() {
            let access_token = provider
                .access_token()
                .await
                .map_err(ApiError::AccessTokenProvider)?;
            _request
                .headers_mut()
                .insert(AUTHORIZATION, authorization_header(&access_token)?);
            return Ok(Some(access_token));
        }
        Ok(None)
    }

    fn invalidate_access_token(&self, _access_token: Option<&str>) {
        #[cfg(feature = "_hidden")]
        if let (Some(provider), Some(access_token)) =
            (self.access_token_provider.as_ref(), _access_token)
        {
            provider.invalidate_access_token(access_token);
        }
    }

    fn invalidate_access_token_if_rejected(&self, error: &ApiError, access_token: Option<&str>) {
        if error.is_authentication_error() {
            self.invalidate_access_token(access_token);
        }
    }

    fn request<'a>(&'a self, request: client::Request, scope: OpScope<'a>) -> RequestBuilder<'a> {
        RequestBuilder {
            client: self,
            request,
            scope,
            retry_enabled: true,
            append_retry_policy: None,
            definite_retries_only: false,
            frame_signal: None,
            error_handler: None,
        }
    }
}

fn set_header_opt(request: &mut client::Request, name: &HeaderName, value: Option<&HeaderValue>) {
    if let Some(value) = value {
        request.headers_mut().insert(name.clone(), value.clone());
    }
}

pub fn retry_builder(config: &RetryConfig) -> RetryBackoffBuilder {
    RetryBackoffBuilder::default()
        .with_min_base_delay(config.min_base_delay)
        .with_max_base_delay(config.max_base_delay)
        .with_max_retries(config.max_retries())
}

type ErrorHandlerFn = Box<
    dyn Fn(StatusCode, UnaryResponse, ErrorContext) -> Result<UnaryResponse, ApiError>
        + Send
        + Sync,
>;

struct RequestBuilder<'a> {
    client: &'a BaseClient,
    request: client::Request,
    scope: OpScope<'a>,
    retry_enabled: bool,
    append_retry_policy: Option<AppendRetryPolicy>,
    definite_retries_only: bool,
    frame_signal: Option<FrameSignal>,
    error_handler: Option<ErrorHandlerFn>,
}

impl<'a> RequestBuilder<'a> {
    fn with_append_retry_policy(self, policy: AppendRetryPolicy) -> Self {
        Self {
            append_retry_policy: Some(policy),
            frame_signal: Some(FrameSignal::new()),
            ..self
        }
    }

    fn with_definite_retries_only(self) -> Self {
        Self {
            definite_retries_only: true,
            frame_signal: Some(FrameSignal::new()),
            ..self
        }
    }

    fn error_handler<F>(self, handler: F) -> Self
    where
        F: Fn(StatusCode, UnaryResponse, ErrorContext) -> Result<UnaryResponse, ApiError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            error_handler: Some(Box::new(handler)),
            ..self
        }
    }

    async fn send(self) -> Result<UnaryResponse, ApiError> {
        if self.client.is_closed() {
            return Err(ApiError::ClientClosed(ClientClosedError::new(
                self.scope.context(1),
            )));
        }

        // Compress the unary request body once before the retry loop so retries clone O(1)
        // `Bytes` without re-compressing.
        let shutdown = self.client.shutdown_signal();
        let request = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                return Err(ApiError::Aborted(AbortedError::new(
                    "client closed",
                    self.scope.context(1),
                )));
            }
            res = self.request.compress() => {
                res.map_err(|e| ApiError::from_http(e, self.scope.context(1)))?
            }
        };

        let mut retry_backoff: Option<RetryBackoff> = self
            .retry_enabled
            .then(|| self.client.retry_builder.build());
        let mut prior_uncertainty = false;
        let mut attempts: u32 = 0;

        loop {
            attempts += 1;

            if let Some(ref signal) = self.frame_signal {
                signal.reset();
            }

            let attempt_request = {
                let mut r = request.try_clone().expect("body should not be a stream");
                r.headers_mut().insert(S2_ATTEMPT, HeaderValue::from(attempts));
                if let Some(ref signal) = self.frame_signal {
                    r = r.with_monitored_body(signal.clone());
                }
                r
            };

            let response = self
                .client
                .execute_unary_in_flight(attempt_request, self.scope, attempts)
                .await;

            let (err, retry_after, access_token) = match response {
                Ok((mut resp, access_token)) => {
                    if resp.status().is_success() {
                        return Ok(resp);
                    }
                    let retry_after = parse_retry_after_ms(resp.headers());
                    let poison_handle = resp.take_poison_handle();
                    let attempt_ctx = self.scope.context(attempts);
                    let result = if let Some(ref handler) = self.error_handler {
                        resp.into_result_with_handler(attempt_ctx, handler)
                    } else {
                        resp.into_result(attempt_ctx)
                    };

                    match result {
                        Ok(resp) => return Ok(resp),
                        Err(err) => {
                            if err.should_retire_connection()
                                && let Some(handle) = poison_handle
                            {
                                handle.poison();
                            }
                            (err, retry_after, access_token)
                        }
                    }
                }
                Err(err) => (err, None, None),
            };

            let unsent = self.frame_signal.as_ref().is_some_and(|s| !s.is_signalled());
            let err = err.mark_unsent_connection_lost(unsent);

            let refreshable_authentication_error =
                self.client.access_token_mode.is_refreshable() && err.is_authentication_error();
            if refreshable_authentication_error {
                self.client.invalidate_access_token(access_token.as_deref());
            }

            if is_safe_to_retry(
                &err,
                self.append_retry_policy,
                self.definite_retries_only,
                self.frame_signal.as_ref(),
                self.client.access_token_mode,
            ) && let Some(backoff) = retry_backoff.as_mut().and_then(|b| b.next())
            {
                let backoff = retry_after.map_or(backoff, |ra| ra.max(backoff));
                debug!(
                    %err,
                    ?backoff,
                    num_retries_remaining = retry_backoff.as_ref().map(|b| b.remaining()).unwrap_or(0),
                    "retrying request"
                );
                if self.append_retry_policy.is_some()
                    && err.attempt_may_have_side_effects(self.frame_signal.as_ref())
                {
                    prior_uncertainty = true;
                }
                let shutdown = self.client.shutdown_signal();
                let aborted = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => true,
                    _ = tokio::time::sleep(backoff) => false,
                };
                if aborted {
                    return Err(ApiError::Aborted(AbortedError::new(
                        "client closed",
                        self.scope.context(attempts),
                    )));
                }
            } else {
                debug!(
                    %err,
                    is_retryable = err.is_retryable() || refreshable_authentication_error,
                    retry_enabled = self.retry_enabled,
                    retries_exhausted = retry_backoff.as_ref().is_none_or(|b| b.is_exhausted()),
                    "not retrying request"
                );
                let attempt_ctx = self.scope.context(attempts);
                let err = err.with_context(&attempt_ctx);
                return Err(err.with_prior_uncertainty(prior_uncertainty));
            }
        }
    }
}

fn is_safe_to_retry(
    err: &ApiError,
    policy: Option<AppendRetryPolicy>,
    definite_retries_only: bool,
    frame_signal: Option<&FrameSignal>,
    access_token_mode: AccessTokenMode,
) -> bool {
    let policy_compliant = if definite_retries_only {
        // T2d: non-idempotent ops without a request token retry only after a definite error.
        // (`ConnectionLostError` occurring before sending was already marked definite above.)
        err.has_no_side_effects()
    } else {
        match policy {
            None | Some(AppendRetryPolicy::All) => true,
            Some(AppendRetryPolicy::NoSideEffects) => {
                !err.attempt_may_have_side_effects(frame_signal)
            }
        }
    };
    policy_compliant
        && (err.is_retryable()
            || (access_token_mode.is_refreshable() && err.is_authentication_error()))
}

#[derive(Debug, Clone)]
enum ClientKind {
    Account,
    Basin(BasinName),
}

fn base_url(endpoints: &S2Endpoints, kind: ClientKind) -> Uri {
    let authority = match kind {
        ClientKind::Account => endpoints.account_authority.clone(),
        ClientKind::Basin(basin) => match &endpoints.basin_authority {
            BasinAuthority::ParentZone(zone) => format!("{basin}.{zone}")
                .try_into()
                .expect("valid authority as basin pre-validated"),
            BasinAuthority::Direct(endpoint) => endpoint.clone(),
        },
    };
    let scheme = &endpoints.scheme;
    format!("{scheme}://{authority}")
        .parse()
        .expect("valid URI")
}

trait UnaryResult {
    fn into_result(self, context: ErrorContext) -> Result<UnaryResponse, ApiError>;
    fn into_result_with_handler<F>(
        self,
        context: ErrorContext,
        handler: F,
    ) -> Result<UnaryResponse, ApiError>
    where
        F: FnOnce(StatusCode, UnaryResponse, ErrorContext) -> Result<UnaryResponse, ApiError>;
}

impl UnaryResult for UnaryResponse {
    fn into_result(self, context: ErrorContext) -> Result<UnaryResponse, ApiError> {
        let status = self.status();
        if status.is_success() {
            Ok(self)
        } else {
            Err(ApiError::Server(ServerError::from_response(
                status,
                &self.into_bytes(),
                context,
            )))
        }
    }

    fn into_result_with_handler<F>(
        self,
        context: ErrorContext,
        handler: F,
    ) -> Result<UnaryResponse, ApiError>
    where
        F: FnOnce(StatusCode, UnaryResponse, ErrorContext) -> Result<UnaryResponse, ApiError>,
    {
        let status = self.status();
        if status.is_success() {
            Ok(self)
        } else {
            handler(status, self, context)
        }
    }
}

#[async_trait]
trait StreamingResult {
    async fn into_result(
        self,
        kind: TerminalKind,
        context: ErrorContext,
    ) -> Result<StreamingResponse, ApiError>;
}

#[async_trait]
impl StreamingResult for StreamingResponse {
    async fn into_result(
        self,
        kind: TerminalKind,
        context: ErrorContext,
    ) -> Result<StreamingResponse, ApiError> {
        if self.status().is_success() {
            return Ok(self);
        }

        let status = self.status();
        let (bytes, poison_handle) = self.into_bytes_with_poison_handle().await;
        let error = match kind {
            TerminalKind::Append => parse_append_error_response(status, &bytes, context),
            TerminalKind::Read => parse_read_error_response(status, &bytes, context),
        };
        if error.should_retire_connection() {
            poison_handle.poison();
        }
        Err(error)
    }
}

fn parse_retry_after_ms(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER_MS_HEADER)?;
    let raw = match value.to_str() {
        Ok(s) => s,
        Err(e) => {
            debug!(?e, "ignoring non-UTF-8 {RETRY_AFTER_MS_HEADER} header");
            return None;
        }
    };
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        debug!(value = raw, "ignoring malformed {RETRY_AFTER_MS_HEADER} header");
        return None;
    }
    match raw.parse::<u64>() {
        Ok(ms) => Some(Duration::from_millis(ms)),
        Err(e) => {
            debug!(?e, value = raw, "ignoring out-of-range {RETRY_AFTER_MS_HEADER} header");
            None
        }
    }
}

trait IgnoreNotFoundCode {
    fn ignore_not_found_code(self, expected_code: &str) -> Result<(), ApiError>;
}

impl IgnoreNotFoundCode for Result<UnaryResponse, ApiError> {
    fn ignore_not_found_code(self, expected_code: &str) -> Result<(), ApiError> {
        match self {
            Ok(_) => Ok(()),
            Err(ApiError::Server(ref server))
                if server.status == StatusCode::NOT_FOUND
                    && server.code.as_deref() == Some(expected_code) =>
            {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

fn provision_result_header_value(response: &UnaryResponse) -> Option<String> {
    response
        .headers()
        .get(&PROVISION_RESULT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn provision_result_from_parts<T>(
    status: StatusCode,
    header_value: Option<&str>,
    info: T,
) -> ProvisionResult<T> {
    match header_value {
        Some("created") => ProvisionResult::Created(info),
        Some("noop") => ProvisionResult::Noop(info),
        Some("updated") => ProvisionResult::Updated(info),
        _ if status == StatusCode::CREATED => ProvisionResult::Created(info),
        _ => ProvisionResult::Updated(info),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    #[cfg(feature = "_hidden")]
    use std::sync::Mutex;
    #[cfg(feature = "_hidden")]
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[cfg(feature = "_hidden")]
    use async_trait::async_trait;
    #[cfg(feature = "_hidden")]
    use hyper_util::client::legacy::connect::HttpConnector;

    use super::*;
    use crate::error::AppendError;

    #[cfg(feature = "_hidden")]
    #[derive(Default)]
    struct HeaderCapture {
        unary: Mutex<Vec<HeaderMap>>,
        streaming: Mutex<Vec<HeaderMap>>,
    }

    #[cfg(feature = "_hidden")]
    #[async_trait]
    impl client::RequestExecutor for HeaderCapture {
        async fn execute_unary(
            &self,
            mut request: client::Request,
        ) -> Result<UnaryResponse, client::HttpError> {
            let mut headers = self.unary.lock().unwrap();
            headers.push(request.headers_mut().clone());
            // Exercise a real retry through RequestBuilder::send.
            Ok(if headers.len() == 1 {
                UnaryResponse::new_for_test(
                    StatusCode::SERVICE_UNAVAILABLE,
                    br#"{"code":"unavailable","message":"retry"}"#.to_vec(),
                )
            } else {
                UnaryResponse::new_for_test(
                    StatusCode::OK,
                    br#"{"basins":[],"streams":[],"has_more":false}"#.to_vec(),
                )
            })
        }

        async fn init_streaming(
            &self,
            mut request: client::Request,
        ) -> Result<StreamingResponse, client::HttpError> {
            self.streaming
                .lock()
                .unwrap()
                .push(request.headers_mut().clone());
            // Capturing initiation is sufficient: do not construct a response body.
            Err(client::HttpError::Timeout)
        }
    }

    #[cfg(feature = "_hidden")]
    #[tokio::test]
    async fn default_headers_reach_account_basin_streaming_and_retry_requests() {
        let mut session = HeaderValue::from_static("session-1");
        session.set_sensitive(true);
        let headers = HeaderMap::from_iter([
            (
                http::header::HeaderName::from_static("x-origin-session"),
                session,
            ),
            (
                AUTHORIZATION,
                HeaderValue::from_static("Bearer wrong-token"),
            ),
            (
                http::header::USER_AGENT,
                HeaderValue::from_static("wrong-agent"),
            ),
            (
                http::header::ACCEPT_ENCODING,
                HeaderValue::from_static("wrong-encoding"),
            ),
            (S2_BASIN, HeaderValue::from_static("wrong-basin")),
        ]);
        let config = S2Config::new("actual-token")
            .with_endpoints(S2Endpoints::for_endpoint("http://example.test").unwrap())
            .with_compression(Compression::Gzip)
            .with_default_headers(headers)
            .unwrap();
        let executor = Arc::new(HeaderCapture::default());
        let mut base = BaseClient::init_with_connector(&config, HttpConnector::new()).unwrap();
        base.client = executor.clone();
        base.retry_builder = RetryBackoffBuilder::default()
            .with_min_base_delay(Duration::ZERO)
            .with_max_base_delay(Duration::ZERO)
            .with_max_retries(1);
        let account = AccountClient::init(config.clone(), base);
        account
            .list_basins(ListBasinsRequest {
                prefix: None,
                start_after: None,
                limit: None,
            })
            .await
            .unwrap();
        let basin = account.basin_client("test-basin".parse().unwrap());
        basin
            .list_streams(ListStreamsRequest {
                prefix: None,
                start_after: None,
                limit: None,
            })
            .await
            .unwrap();

        let stream = "test-stream".parse().unwrap();
        assert!(
            basin
                .read_session(
                    &stream,
                    ReadStart {
                        seq_num: None,
                        timestamp: None,
                        tail_offset: None,
                        clamp: None
                    },
                    ReadEnd {
                        count: None,
                        bytes: None,
                        until: None,
                        wait: None
                    },
                    None,
                    None,
                    ReconnectAdvice::default(),
                    1,
                )
                .await
                .is_err()
        );
        assert!(
            basin
                .append_session(
                    &stream,
                    futures_util::stream::empty(),
                    None,
                    None,
                    ReconnectAdvice::default(),
                    1,
                )
                .await
                .is_err()
        );

        let unary = executor.unary.lock().unwrap();
        let streaming = executor.streaming.lock().unwrap();
        assert_eq!(unary.len(), 3); // account, account retry, basin
        assert_eq!(streaming.len(), 2); // read and append
        assert_eq!(unary[0][S2_ATTEMPT], "1");
        assert_eq!(unary[1][S2_ATTEMPT], "2");
        assert_eq!(unary[2][S2_ATTEMPT], "1");
        assert_eq!(streaming[0][S2_ATTEMPT], "1");
        assert_eq!(streaming[1][S2_ATTEMPT], "1");
        for headers in unary.iter().chain(streaming.iter()) {
            assert_eq!(headers["x-origin-session"], "session-1");
            assert!(headers["x-origin-session"].is_sensitive());
            assert_eq!(headers[AUTHORIZATION], "Bearer actual-token");
            assert!(headers[AUTHORIZATION].is_sensitive());
            assert_eq!(headers[http::header::USER_AGENT], config.user_agent);
            assert_eq!(headers[http::header::ACCEPT_ENCODING], "gzip");
            assert!(!headers.contains_key(http::header::CONTENT_ENCODING));
        }
        assert_eq!(unary[2][S2_BASIN], "test-basin");
        for headers in streaming.iter() {
            assert_eq!(headers[S2_BASIN], "test-basin");
            assert_eq!(headers[CONTENT_TYPE], CONTENT_TYPE_S2S);
        }
    }

    #[cfg(feature = "_hidden")]
    #[rstest::rstest]
    #[case::none(Compression::None, None, "gzip, zstd")]
    #[case::gzip(Compression::Gzip, Some("gzip"), "gzip")]
    #[case::zstd(Compression::Zstd, Some("zstd"), "zstd")]
    #[tokio::test]
    async fn default_accept_encoding_respects_configured_compression(
        #[case] compression: Compression,
        #[case] content_encoding: Option<&str>,
        #[case] accept_encoding: &str,
    ) {
        let config = S2Config::new("token")
            .with_compression(compression)
            .with_default_headers(HeaderMap::from_iter([(
                http::header::ACCEPT_ENCODING,
                HeaderValue::from_static("gzip, zstd"),
            )]))
            .unwrap();
        let client = BaseClient::init_with_connector(&config, HttpConnector::new()).unwrap();
        let mut request = client
            .post("http://example.test/v1/basins".parse().unwrap())
            .json(&serde_json::json!({"name": "test-basin"}))
            .build()
            .unwrap()
            .compress()
            .await
            .unwrap();
        let headers = request.headers_mut();
        assert_eq!(
            headers
                .get(http::header::CONTENT_ENCODING)
                .map(|value| value.to_str().unwrap()),
            content_encoding
        );
        assert_eq!(headers[http::header::ACCEPT_ENCODING], accept_encoding);
    }

    #[cfg(feature = "_hidden")]
    #[tokio::test]
    async fn default_headers_are_replaced_and_isolated_between_clients() {
        let first_headers = HeaderMap::from_iter([
            (
                http::header::HeaderName::from_static("x-origin-session"),
                HeaderValue::from_static("first"),
            ),
            (
                http::header::HeaderName::from_static("x-first-only"),
                HeaderValue::from_static("present"),
            ),
        ]);
        let first = S2Config::new("token")
            .with_default_headers(first_headers)
            .unwrap();
        let second = first
            .clone()
            .with_default_headers(HeaderMap::from_iter([(
                http::header::HeaderName::from_static("x-origin-session"),
                HeaderValue::from_static("second"),
            )]))
            .unwrap();
        for (config, session) in [(&first, "first"), (&second, "second")] {
            let client = BaseClient::init_with_connector(config, HttpConnector::new()).unwrap();
            let mut request = client
                .get("http://example.test".parse().unwrap())
                .build()
                .unwrap();
            assert_eq!(request.headers_mut()["x-origin-session"], session);
            assert_eq!(
                request.headers_mut().contains_key("x-first-only"),
                session == "first"
            );
        }
        let cleared = second.with_default_headers(HeaderMap::new()).unwrap();
        assert!(cleared.default_headers.is_empty());
        assert!(S2Config::new("token").default_headers.is_empty());
    }

    #[cfg(feature = "_hidden")]
    #[derive(Debug)]
    struct RotatingTokenProvider {
        generation: AtomicUsize,
    }

    #[cfg(feature = "_hidden")]
    #[async_trait]
    impl crate::types::AccessTokenProvider for RotatingTokenProvider {
        async fn access_token(&self) -> Result<String, crate::types::AccessTokenProviderError> {
            let generation = self.generation.fetch_add(1, Ordering::Relaxed);
            Ok(format!("token-{generation}"))
        }
    }

    #[cfg(feature = "_hidden")]
    #[derive(Debug)]
    struct RejectAwareTokenProvider {
        invalidated: AtomicBool,
        rejected: Mutex<Vec<String>>,
    }

    #[cfg(feature = "_hidden")]
    #[async_trait]
    impl crate::types::AccessTokenProvider for RejectAwareTokenProvider {
        async fn access_token(&self) -> Result<String, crate::types::AccessTokenProviderError> {
            Ok(if self.invalidated.load(Ordering::Acquire) {
                "new-token"
            } else {
                "old-token"
            }
            .to_owned())
        }

        fn invalidate_access_token(&self, rejected_access_token: &str) {
            self.rejected
                .lock()
                .expect("rejected token mutex poisoned")
                .push(rejected_access_token.to_owned());
            self.invalidated.store(true, Ordering::Release);
        }
    }

    #[cfg(feature = "_hidden")]
    #[derive(Debug, Default)]
    struct RejectOldTokenExecutor {
        authorization_headers: Mutex<Vec<String>>,
    }

    #[cfg(feature = "_hidden")]
    #[async_trait]
    impl client::RequestExecutor for RejectOldTokenExecutor {
        async fn execute_unary(
            &self,
            mut request: client::Request,
        ) -> Result<UnaryResponse, client::HttpError> {
            let authorization = request
                .headers_mut()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            self.authorization_headers
                .lock()
                .expect("authorization header mutex poisoned")
                .push(authorization.clone());

            if authorization == "Bearer old-token" {
                Ok(UnaryResponse::new_for_test(
                    StatusCode::UNAUTHORIZED,
                    br#"{"code":"authn","message":"rejected"}"#.to_vec(),
                ))
            } else {
                Ok(UnaryResponse::new_for_test(StatusCode::OK, "ok"))
            }
        }

        async fn init_streaming(
            &self,
            _request: client::Request,
        ) -> Result<StreamingResponse, client::HttpError> {
            unreachable!("unary retry test does not initialize a stream")
        }
    }

    #[rstest::rstest]
    #[case(StatusCode::FORBIDDEN, "permission_denied", false, false)]
    #[case(StatusCode::FORBIDDEN, "permission_denied", true, true)]
    #[case(StatusCode::SERVICE_UNAVAILABLE, "unavailable", false, false)]
    #[case(StatusCode::SERVICE_UNAVAILABLE, "unavailable", true, false)]
    #[case(StatusCode::TOO_MANY_REQUESTS, "rate_limited", true, true)]
    #[test]
    fn unary_append_failure_preserves_uncertainty_and_final_error(
        #[case] status: StatusCode,
        #[case] code: &str,
        #[case] prior_uncertainty: bool,
        #[case] wrapped: bool,
    ) {
        let error =
            AppendError::from(server_error(status, code).with_prior_uncertainty(prior_uncertainty));
        assert_eq!(
            matches!(error, AppendError::IndefiniteAppend(_)),
            wrapped
        );
        if wrapped {
            assert!(error.server_error().is_none());
            assert!(!error.has_no_side_effects());
            let latest = error
                .source()
                .unwrap()
                .downcast_ref::<AppendError>()
                .unwrap();
            assert!(latest.has_no_side_effects());
            let server = latest.server_error().unwrap();
            assert_eq!((server.status, server.code.as_deref()), (status, Some(code)));
            assert_eq!(server.message, "test");
            assert_eq!(error.is_retryable(), server.is_retryable());
            assert_eq!(
                error.to_string(),
                format!(
                    "append may have taken effect in an earlier attempt; final attempt failed: {latest}"
                )
            );
        } else {
            let server = error.server_error().unwrap();
            assert_eq!((server.status, server.code.as_deref()), (status, Some(code)));
            assert_eq!(server.message, "test");
            assert_eq!(error.is_retryable(), server.is_retryable());
            assert_eq!(error.has_no_side_effects(), server.has_no_side_effects());
        }
    }

    #[rstest::rstest]
    #[case::condition_failed(
        parse_append_error_response(
            StatusCode::PRECONDITION_FAILED,
            br#"{"seq_num_mismatch":42}"#,
            ErrorContext::default(),
        ),
        "assignable_seq_num=42"
    )]
    #[case::unrecognized_condition(
        ApiError::from_terminal_message(
            TerminalMessage {
                status: 412,
                body: bytes::Bytes::from_static(br#"{"some_future_mismatch":7}"#),
            },
            TerminalKind::Append,
            ErrorContext::default(),
        ),
        r#"{"some_future_mismatch":7}"#
    )]
    #[case::invalid_access_token(
        ApiError::Validation(ValidationError("invalid access token: invalid header".to_owned())),
        "invalid access token: invalid header"
    )]
    #[test]
    fn unary_append_wraps_definite_terminal_errors(
        #[case] error: ApiError,
        #[case] expected_substr: &str,
    ) {
        assert!(error.has_no_side_effects());
        let error = AppendError::from(error.with_prior_uncertainty(true));
        assert!(matches!(error, AppendError::IndefiniteAppend(_)));
        assert!(!error.has_no_side_effects());
        assert!(!error.is_retryable());
        assert!(error.server_error().is_none());
        let latest = error
            .source()
            .unwrap()
            .downcast_ref::<AppendError>()
            .unwrap();
        assert!(latest.has_no_side_effects());
        assert!(
            latest.to_string().contains(expected_substr),
            "got: {latest}"
        );
    }

    fn server_error(status: StatusCode, code: &str) -> ApiError {
        ApiError::Server(ServerError::new_for_test(status, Some(code), "test"))
    }

    #[test]
    fn safe_to_retry_unary_no_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");
        let mode = AccessTokenMode::Static;

        // Non-append requests (no policy) — retry if retryable.
        assert!(is_safe_to_retry(&retryable, None, false, None, mode));
        assert!(!is_safe_to_retry(&non_retryable, None, false, None, mode));
    }

    #[test]
    fn safe_to_retry_unary_all_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");
        let policy = Some(AppendRetryPolicy::All);
        let mode = AccessTokenMode::Static;

        // All policy — retry if retryable, no frame signal checks.
        assert!(is_safe_to_retry(&retryable, policy, false, None, mode));
        assert!(!is_safe_to_retry(&non_retryable, policy, false, None, mode));
    }

    #[test]
    fn safe_to_retry_unary_no_side_effects_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");
        let no_side_effect = server_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        let transaction_conflict = server_error(StatusCode::CONFLICT, "transaction_conflict");
        let policy = Some(AppendRetryPolicy::NoSideEffects);
        let signal = FrameSignal::new();
        let mode = AccessTokenMode::Static;

        // Signal not set — safe to retry under NoSideEffects (T2c).
        assert!(is_safe_to_retry(
            &retryable,
            policy,
            false,
            Some(&signal),
            mode,
        ));

        // T2d (definite_retries_only): indefinite 500 is NOT retried even if signal wasn't set.
        assert!(!is_safe_to_retry(
            &retryable,
            None,
            true,
            Some(&signal),
            mode,
        ));

        // Signal set + error with possible side effects — not safe.
        signal.signal();
        assert!(!is_safe_to_retry(
            &retryable,
            policy,
            false,
            Some(&signal),
            mode,
        ));

        // Signal set + no-side-effect error — safe.
        assert!(is_safe_to_retry(
            &no_side_effect,
            policy,
            false,
            Some(&signal),
            mode,
        ));
        assert!(is_safe_to_retry(
            &transaction_conflict,
            policy,
            false,
            Some(&signal),
            mode,
        ));

        // Signal set + non-retryable — never safe.
        assert!(!is_safe_to_retry(
            &non_retryable,
            policy,
            false,
            Some(&signal),
            mode,
        ));

        // Definite-only non-append ops (T2d: issue_access_token, create_network_policy).
        assert!(!is_safe_to_retry(
            &retryable,
            None,
            true,
            Some(&signal),
            mode,
        ));
        assert!(is_safe_to_retry(
            &no_side_effect,
            None,
            true,
            Some(&signal),
            mode,
        ));
    }

    #[cfg(feature = "_hidden")]
    #[tokio::test]
    async fn dynamic_access_token_is_loaded_for_each_attempt_and_marked_sensitive() {
        let config = S2Config::new("unused")
            .with_default_headers(HeaderMap::from_iter([(
                AUTHORIZATION,
                HeaderValue::from_static("Bearer wrong-token"),
            )]))
            .unwrap()
            .with_access_token_provider(RotatingTokenProvider {
                generation: AtomicUsize::new(1),
            });
        let client = BaseClient::init_with_connector(&config, HttpConnector::new()).unwrap();
        let uri = "http://example.test/v1/basins".parse().unwrap();
        let mut request = client.get(uri).build().unwrap();

        assert!(request.headers_mut().get(AUTHORIZATION).is_none());

        client.authorize(&mut request).await.unwrap();
        let first = request.headers_mut().get(AUTHORIZATION).unwrap();
        assert_eq!(first, "Bearer token-1");
        assert!(first.is_sensitive());

        client.authorize(&mut request).await.unwrap();
        let second = request.headers_mut().get(AUTHORIZATION).unwrap();
        assert_eq!(second, "Bearer token-2");
        assert!(second.is_sensitive());
    }

    #[cfg(feature = "_hidden")]
    #[tokio::test]
    async fn rejected_token_is_invalidated_and_replaced_on_unary_retry() {
        let provider = Arc::new(RejectAwareTokenProvider {
            invalidated: AtomicBool::new(false),
            rejected: Mutex::new(Vec::new()),
        });
        let executor = Arc::new(RejectOldTokenExecutor::default());
        let client = BaseClient {
            client: executor.clone(),
            shutdown: ShutdownSignal::new(),
            default_headers: HeaderMap::new(),
            access_token_mode: AccessTokenMode::Refreshable,
            access_token_provider: Some(provider.clone()),
            request_timeout: Duration::from_secs(1),
            retry_builder: RetryBackoffBuilder::default()
                .with_min_base_delay(Duration::ZERO)
                .with_max_base_delay(Duration::ZERO)
                .with_max_retries(1),
            compression: Compression::None,
        };
        let request = client
            .get("http://example.test/v1/basins".parse().unwrap())
            .build()
            .unwrap();

        let response = client
            .request(request, OpScope::account("list_basins", true))
            .send()
            .await
            .unwrap();

        assert_eq!(response.into_bytes(), bytes::Bytes::from_static(b"ok"));
        assert_eq!(
            executor
                .authorization_headers
                .lock()
                .expect("authorization header mutex poisoned")
                .as_slice(),
            ["Bearer old-token", "Bearer new-token"]
        );
        assert_eq!(
            provider
                .rejected
                .lock()
                .expect("rejected token mutex poisoned")
                .as_slice(),
            ["old-token"]
        );
    }

    #[cfg(feature = "_hidden")]
    #[test]
    fn transient_provider_failures_are_retryable_without_side_effects() {
        let transient = ApiError::AccessTokenProvider(
            crate::types::AccessTokenProviderError::transient("temporarily unavailable"),
        );
        assert!(transient.is_retryable());
        assert!(transient.has_no_side_effects());

        let permanent = ApiError::AccessTokenProvider(
            crate::types::AccessTokenProviderError::permanent("login required"),
        );
        assert!(!permanent.is_retryable());
        assert!(permanent.has_no_side_effects());
    }

    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[tokio::test]
    async fn dns_errors_are_classified_as_connect() {
        let config = crate::types::S2Config::new("test-token".to_owned())
            .with_endpoints(
                crate::types::S2Endpoints::new(
                    "https://no-such-basin.invalid".parse().unwrap(),
                    "https://no-such-basin.invalid".parse().unwrap(),
                )
                .unwrap(),
            )
            // Skip native root CA loading so the test works in sandboxed
            // CI environments without keychain access.
            .with_insecure_skip_cert_verification(true);
        let client = BaseClient::init(&config).expect("client init");
        let url = "https://no-such-basin.invalid/v1/streams"
            .parse::<Uri>()
            .unwrap();
        let request = client.get(url).build().unwrap();
        let err: ApiError = match client
            .request(request, OpScope::account("list_streams", true))
            .send()
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("should fail with DNS error"),
        };
        assert!(
            matches!(&err, ApiError::Connect(c) if c.message.contains("dns")),
            "expected a connect error with dns cause, got: {err}"
        );
    }

    #[test]
    fn account_metrics_query_repeats_token_id() {
        let request = AccountMetricSetRequest {
            set: s2_api::v1::metrics::AccountMetricSet::TokenActivity,
            start: None,
            end: None,
            interval: None,
            token_ids: vec!["a,b".parse().unwrap(), "c&d".parse().unwrap()],
        };

        let query = serde_urlencoded::to_string(&request).unwrap();
        assert_eq!(query, "set=token-activity&token_id=a%2Cb&token_id=c%26d");

        let parsed: AccountMetricSetRequest = serde_urlencoded::from_str(&query).unwrap();
        assert_eq!(parsed.token_ids, request.token_ids);
        assert!(
            serde_urlencoded::from_str::<AccountMetricSetRequest>(
                "set=token-activity&set=account-ops"
            )
            .is_err()
        );
    }

    // spec: r1 T3, L2
    #[test]
    fn parse_retry_after_ms_accepts_only_unsigned_ascii_digits() {
        let headers = HeaderMap::new();
        assert_eq!(parse_retry_after_ms(&headers), None);

        for (raw, expected) in [
            ("0", Some(Duration::ZERO)),
            ("1500", Some(Duration::from_millis(1500))),
            ("18446744073709551615", Some(Duration::from_millis(u64::MAX))),
            ("", None),
            ("+100", None),
            ("-1", None),
            ("100 ", None),
            (" 100", None),
            ("1.5", None),
            ("abc", None),
            ("18446744073709551616", None),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                RETRY_AFTER_MS_HEADER,
                HeaderValue::from_str(raw).unwrap(),
            );
            assert_eq!(parse_retry_after_ms(&headers), expected, "raw={raw:?}");
        }

        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert(
            RETRY_AFTER_MS_HEADER,
            HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        assert_eq!(parse_retry_after_ms(&non_utf8), None);
    }

    // spec: r1 M4
    #[test]
    fn ignore_not_found_code_matches_only_expected_404_code() {
        let matching: Result<UnaryResponse, ApiError> =
            Err(server_error(StatusCode::NOT_FOUND, "stream_not_found"));
        assert!(matching.ignore_not_found_code("stream_not_found").is_ok());

        let wrong_code: Result<UnaryResponse, ApiError> =
            Err(server_error(StatusCode::NOT_FOUND, "basin_not_found"));
        assert!(matches!(
            wrong_code.ignore_not_found_code("stream_not_found"),
            Err(ApiError::Server(server))
                if server.status == StatusCode::NOT_FOUND
                    && server.code.as_deref() == Some("basin_not_found")
        ));

        let wrong_status: Result<UnaryResponse, ApiError> =
            Err(server_error(StatusCode::CONFLICT, "stream_not_found"));
        assert!(matches!(
            wrong_status.ignore_not_found_code("stream_not_found"),
            Err(ApiError::Server(server)) if server.status == StatusCode::CONFLICT
        ));

        let server_err: Result<UnaryResponse, ApiError> =
            Err(server_error(StatusCode::INTERNAL_SERVER_ERROR, "unavailable"));
        assert!(matches!(
            server_err.ignore_not_found_code("stream_not_found"),
            Err(ApiError::Server(server)) if server.status == StatusCode::INTERNAL_SERVER_ERROR
        ));
    }

    // spec: r1 C1, L3
    #[test]
    fn authorization_header_rejects_empty_and_invalid_and_marks_sensitive() {
        assert!(authorization_header("").is_err());
        assert!(authorization_header("bad\ntoken").is_err());
        assert!(authorization_header("bad\rtoken").is_err());

        let valid = authorization_header("secret-token").unwrap();
        assert_eq!(valid, "Bearer secret-token");
        assert!(valid.is_sensitive());
    }

    // spec: r1 C6, E2, F1, T9
    #[test]
    fn spec_vectors_s2s_frames_through_api_error() {
        use std::path::Path;

        use bytes::BytesMut;
        use serde::Deserialize;
        use tokio_util::codec::Decoder as _;

        #[derive(Deserialize)]
        struct File {
            cases: Vec<Case>,
        }
        #[derive(Deserialize)]
        struct Case {
            rule: String,
            name: String,
            bytes: Vec<Piece>,
            expect: Expect,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Piece {
            Hex { hex: String },
            Zeros { zeros: usize },
        }
        #[derive(Deserialize)]
        struct Expect {
            messages: Vec<serde_json::Value>,
            end: End,
        }
        #[derive(Deserialize)]
        struct End {
            #[serde(rename = "type")]
            kind: String,
            status: Option<u16>,
            code: Option<String>,
            message: Option<String>,
        }

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../api/specs/sdk/vectors/s2s-frames.json");
        let raw = std::fs::read_to_string(&path).expect("read s2s-frames.json");
        let file: File = serde_json::from_str(&raw).expect("parse s2s-frames.json");
        assert!(!file.cases.is_empty());

        for case in &file.cases {
            let label = format!("[{}] {}", case.rule, case.name);
            let mut wire = Vec::new();
            for piece in &case.bytes {
                match piece {
                    Piece::Hex { hex } => {
                        for i in (0..hex.len()).step_by(2) {
                            wire.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
                        }
                    }
                    Piece::Zeros { zeros } => wire.resize(wire.len() + *zeros, 0),
                }
            }

            let mut decoder = FrameDecoder;
            let mut buf = BytesMut::from(wire.as_slice());
            let mut regular_count = 0usize;
            let end_err: Option<ApiError> = loop {
                match decoder.decode(&mut buf) {
                    Ok(Some(SessionMessage::Regular(data))) => match data.decompressed() {
                        Ok(_) => regular_count += 1,
                        Err(err) => {
                            break Some(ApiError::Protocol(ProtocolError::new(
                                err.to_string(),
                                ErrorContext::default(),
                            )));
                        }
                    },
                    Ok(Some(SessionMessage::Terminal(term))) => {
                        break Some(ApiError::from_terminal_message(
                            term,
                            TerminalKind::Read,
                            ErrorContext::default(),
                        ));
                    }
                    Ok(None) => {
                        if !buf.is_empty() {
                            break Some(ApiError::ConnectionLost(ConnectionLostError::new(
                                "truncated s2s frame",
                                true,
                                ErrorContext::default(),
                            )));
                        }
                        break None;
                    }
                    Err(err) => {
                        break Some(ApiError::Protocol(ProtocolError::new(
                            err.to_string(),
                            ErrorContext::default(),
                        )));
                    }
                }
            };

            assert_eq!(regular_count, case.expect.messages.len(), "{label}");
            match case.expect.end.kind.as_str() {
                "clean" => assert!(end_err.is_none(), "{label}: expected clean, got {end_err:?}"),
                "ServerError" => match end_err {
                    Some(ApiError::Server(s)) => {
                        assert_eq!(Some(s.status.as_u16()), case.expect.end.status, "{label}");
                        assert_eq!(s.code, case.expect.end.code, "{label}");
                        if let Some(expected_msg) = &case.expect.end.message {
                            assert_eq!(&s.message, expected_msg, "{label}");
                        }
                    }
                    other => panic!("{label}: expected ServerError, got {other:?}"),
                },
                "ProtocolError" => assert!(
                    matches!(end_err, Some(ApiError::Protocol(_))),
                    "{label}: expected ProtocolError, got {end_err:?}"
                ),
                "ConnectionLostError" => assert!(
                    matches!(end_err, Some(ApiError::ConnectionLost(_))),
                    "{label}: expected ConnectionLostError, got {end_err:?}"
                ),
                other => panic!("{label}: unknown end type {other:?}"),
            }
        }
    }
}
