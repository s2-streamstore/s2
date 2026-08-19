use std::{ops::Deref, pin::Pin, sync::Arc, time::Duration};

use async_stream::try_stream;
use async_trait::async_trait;
use bytes::BytesMut;
use futures_core::Stream;
use futures_util::StreamExt;
use http::{
    HeaderMap, HeaderValue, StatusCode, Uri,
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
    config::{BasinConfig, BasinReconfiguration, StreamConfig, StreamReconfiguration},
    location::LocationInfo,
    metrics::{
        AccountMetricSetRequest, BasinMetricSetRequest, MetricSetResponse, StreamMetricSetRequest,
    },
    stream::{
        AppendConditionFailed, CreateStreamRequest, ListStreamsRequest, ListStreamsResponse,
        ReadEnd, ReadStart, StreamInfo, TailResponse,
        proto::{AppendAck, AppendInput, ReadBatch},
        s2s::{self, FrameDecoder, SessionMessage, TerminalMessage},
    },
};
use s2_common::{
    encryption::S2_ENCRYPTION_KEY_HEADER,
    resources::{PROVISION_RESULT_HEADER, ProvisionResult},
};
use secrecy::ExposeSecret;
use tokio_util::codec::Decoder;
use tracing::{debug, warn};

use crate::{
    client::{self, StreamingResponse, UnaryResponse},
    error::{ClientError, server_error_has_no_side_effects, server_error_is_retryable},
    frame_signal::FrameSignal,
    reconnect::ReconnectAdvice,
    retry::{RetryBackoff, RetryBackoffBuilder},
    types::{
        AccessToken, AccessTokenId, AccessTokenMode, AppendRetryPolicy, BasinAuthority, BasinName,
        Compression, EncryptionKey, LocationName, RetryConfig, S2Config, S2Endpoints, StreamName,
    },
};
const CONTENT_TYPE_S2S: &str = "s2s/proto";
const CONTENT_TYPE_PROTO: &str = "application/protobuf";
const ACCEPT_PROTO: &str = "application/protobuf";
const S2_REQUEST_TOKEN: &str = "s2-request-token";
const S2_BASIN: &str = "s2-basin";
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
        let url = self.uri("v1/access-tokens");
        let request = self.get(url).query(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<ListAccessTokensResponse>()?)
    }

    pub async fn issue_access_token(
        &self,
        request: IssueAccessTokenRequest,
    ) -> Result<IssueAccessTokenResponse, ApiError> {
        let url = self.uri("v1/access-tokens");
        let request = self.post(url).json(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<IssueAccessTokenResponse>()?)
    }

    pub async fn revoke_access_token(&self, id: AccessTokenId) -> Result<(), ApiError> {
        let url = self.uri(format!("v1/access-tokens/{}", urlencoding::encode(&id)));
        let request = self.delete(url).build()?;
        let _response = self.request(request).send().await?;
        Ok(())
    }

    pub async fn list_locations(&self) -> Result<Vec<LocationInfo>, ApiError> {
        let url = self.uri("v1/locations");
        let request = self.get(url).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<Vec<LocationInfo>>()?)
    }

    pub async fn get_default_location(&self) -> Result<LocationInfo, ApiError> {
        let url = self.uri("v1/locations/default");
        let request = self.get(url).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<LocationInfo>()?)
    }

    pub async fn set_default_location(
        &self,
        location: LocationName,
    ) -> Result<LocationInfo, ApiError> {
        let url = self.uri("v1/locations/default");
        let request = self.put(url).json(&location).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<LocationInfo>()?)
    }

    pub async fn list_basins(
        &self,
        request: ListBasinsRequest,
    ) -> Result<ListBasinsResponse, ApiError> {
        let url = self.uri("v1/basins");
        let request = self.get(url).query(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<ListBasinsResponse>()?)
    }

    pub async fn create_basin(
        &self,
        request: CreateBasinRequest,
        idempotency_token: String,
    ) -> Result<BasinInfo, ApiError> {
        let url = self.uri("v1/basins");
        let request = self
            .post(url)
            .header(S2_REQUEST_TOKEN, idempotency_token)
            .json(&request)
            .build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<BasinInfo>()?)
    }

    pub async fn get_basin_config(&self, name: BasinName) -> Result<BasinConfig, ApiError> {
        let url = self.uri(format!("v1/basins/{name}"));
        let request = self.get(url).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<BasinConfig>()?)
    }

    pub async fn reconfigure_basin(
        &self,
        name: BasinName,
        config: BasinReconfiguration,
    ) -> Result<BasinConfig, ApiError> {
        let url = self.uri(format!("v1/basins/{name}"));
        let request = self.patch(url).json(&config).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<BasinConfig>()?)
    }

    pub async fn ensure_basin(
        &self,
        name: BasinName,
        request: Option<EnsureBasinRequest>,
    ) -> Result<ProvisionResult<BasinInfo>, ApiError> {
        let url = self.uri(format!("v1/basins/{name}"));
        let request = match request {
            Some(body) => self.put(url).json(&body).build()?,
            None => self.put(url).build()?,
        };
        let response = self.request(request).send().await?;
        let status = response.status();
        let provision_result_header_value = provision_result_header_value(&response);
        let info = response.json::<BasinInfo>()?;
        Ok(provision_result_from_parts(
            status,
            provision_result_header_value.as_deref(),
            info,
        ))
    }

    pub async fn delete_basin(
        &self,
        name: BasinName,
        ignore_not_found: bool,
    ) -> Result<(), ApiError> {
        let url = self.uri(format!("v1/basins/{name}"));
        let request = self.delete(url).build()?;
        self.request(request)
            .send()
            .await
            .ignore_not_found(ignore_not_found)?;
        Ok(())
    }

    pub async fn get_account_metrics(
        &self,
        request: AccountMetricSetRequest,
    ) -> Result<MetricSetResponse, ApiError> {
        let url = self.uri("v1/metrics");
        let request = self.get(url).query(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<MetricSetResponse>()?)
    }

    pub async fn get_basin_metrics(
        &self,
        name: BasinName,
        request: BasinMetricSetRequest,
    ) -> Result<MetricSetResponse, ApiError> {
        let url = self.uri(format!("v1/metrics/{name}"));
        let request = self.get(url).query(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<MetricSetResponse>()?)
    }

    pub async fn get_stream_metrics(
        &self,
        basin_name: BasinName,
        stream_name: StreamName,
        request: StreamMetricSetRequest,
    ) -> Result<MetricSetResponse, ApiError> {
        let url = self.uri(format!(
            "v1/metrics/{basin_name}/{}",
            urlencoding::encode(&stream_name)
        ));
        let request = self.get(url).query(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<MetricSetResponse>()?)
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
}

impl BasinClient {
    pub fn init(name: BasinName, config: Arc<S2Config>, client: BaseClient) -> Self {
        let base_url = base_url(&config.endpoints, ClientKind::Basin(name.clone()));
        Self {
            name,
            client,
            config,
            base_url,
        }
    }

    fn uri(&self, path: impl AsRef<str>) -> Uri {
        client::uri_with_path(&self.base_url, path)
    }

    fn request(&self, mut request: client::Request) -> RequestBuilder<'_> {
        if matches!(
            self.config.endpoints.basin_authority,
            BasinAuthority::Direct(_)
        ) {
            request.headers_mut().insert(
                S2_BASIN,
                HeaderValue::from_str(&self.name).expect("valid header value"),
            );
        }
        self.client.request(request)
    }

    pub async fn list_streams(
        &self,
        request: ListStreamsRequest,
    ) -> Result<ListStreamsResponse, ApiError> {
        let url = self.uri("v1/streams");
        let request = self.get(url).query(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<ListStreamsResponse>()?)
    }

    pub async fn create_stream(
        &self,
        request: CreateStreamRequest,
        idempotency_token: String,
    ) -> Result<StreamInfo, ApiError> {
        let url = self.uri("v1/streams");
        let request = self
            .post(url)
            .header(S2_REQUEST_TOKEN, idempotency_token)
            .json(&request)
            .build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<StreamInfo>()?)
    }

    pub async fn get_stream_config(&self, name: StreamName) -> Result<StreamConfig, ApiError> {
        let url = self.uri(format!("v1/streams/{}", urlencoding::encode(&name)));
        let request = self.get(url).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<StreamConfig>()?)
    }

    pub async fn reconfigure_stream(
        &self,
        name: StreamName,
        config: StreamReconfiguration,
    ) -> Result<StreamConfig, ApiError> {
        let url = self.uri(format!("v1/streams/{}", urlencoding::encode(&name)));
        let request = self.patch(url).json(&config).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<StreamConfig>()?)
    }

    pub async fn ensure_stream(
        &self,
        name: StreamName,
        config: Option<StreamConfig>,
    ) -> Result<ProvisionResult<StreamInfo>, ApiError> {
        let url = self.uri(format!("v1/streams/{}", urlencoding::encode(&name)));
        let request = match config {
            Some(body) => self.put(url).json(&body).build()?,
            None => self.put(url).build()?,
        };
        let response = self.request(request).send().await?;
        let status = response.status();
        let provision_result_header_value = provision_result_header_value(&response);
        let info = response.json::<StreamInfo>()?;
        Ok(provision_result_from_parts(
            status,
            provision_result_header_value.as_deref(),
            info,
        ))
    }

    pub async fn delete_stream(
        &self,
        name: StreamName,
        ignore_not_found: bool,
    ) -> Result<(), ApiError> {
        let url = self.uri(format!("v1/streams/{}", urlencoding::encode(&name)));
        let request = self.delete(url).build()?;
        self.request(request)
            .send()
            .await
            .ignore_not_found(ignore_not_found)?;
        Ok(())
    }

    pub async fn check_tail(&self, name: &StreamName) -> Result<TailResponse, ApiError> {
        let url = self.uri(format!(
            "v1/streams/{}/records/tail",
            urlencoding::encode(name)
        ));
        let request = self.get(url).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<TailResponse>()?)
    }

    pub async fn append(
        &self,
        name: &StreamName,
        input: AppendInput,
        encryption: Option<&EncryptionKey>,
        append_retry_policy: AppendRetryPolicy,
    ) -> Result<AppendAck, ApiError> {
        let url = self.uri(format!("v1/streams/{}/records", urlencoding::encode(name)));
        let mut request = self
            .post(url)
            .header(CONTENT_TYPE, CONTENT_TYPE_PROTO)
            .header(ACCEPT, ACCEPT_PROTO)
            .body(input.encode_to_vec())
            .build()?;
        set_encryption_header(&mut request, encryption);
        let response = self
            .request(request)
            .with_append_retry_policy(append_retry_policy)
            .error_handler(|status, response| {
                if status == StatusCode::PRECONDITION_FAILED {
                    Err(ApiError::AppendConditionFailed(
                        response.json::<AppendConditionFailed>()?,
                    ))
                } else {
                    Err(ApiError::Server(
                        status,
                        response.json::<ServerErrorBody>()?,
                    ))
                }
            })
            .send()
            .await?;
        Ok(AppendAck::decode(response.into_bytes())?)
    }

    pub async fn read(
        &self,
        name: &StreamName,
        start: ReadStart,
        end: ReadEnd,
        encryption: Option<&EncryptionKey>,
    ) -> Result<ReadBatch, ApiError> {
        let url = self.uri(format!("v1/streams/{}/records", urlencoding::encode(name)));
        let mut builder = self
            .get(url)
            .header(ACCEPT, ACCEPT_PROTO)
            .query(&start)
            .query(&end);
        if let Some(wait) = end.wait {
            builder =
                builder.timeout(self.client.request_timeout + Duration::from_secs(wait.into()));
        }
        let mut request = builder.build()?;
        set_encryption_header(&mut request, encryption);
        let response = self
            .request(request)
            .error_handler(read_response_error_handler)
            .send()
            .await?;
        Ok(ReadBatch::decode(response.into_bytes())?)
    }

    pub async fn append_session<I>(
        &self,
        name: &StreamName,
        inputs: I,
        encryption: Option<&EncryptionKey>,
        frame_signal: Option<FrameSignal>,
        reconnect: ReconnectAdvice,
    ) -> Result<Streaming<AppendAck>, ApiError>
    where
        I: Stream<Item = AppendInput> + Send + 'static,
    {
        let url = self.uri(format!("v1/streams/{}/records", urlencoding::encode(name)));

        let compression = self.config.compression.into();

        let encoded_stream = inputs.map(move |input| {
            s2s::SessionMessage::regular(compression, &input).map(|msg| msg.encode())
        });

        let body = client::Body::wrap_stream(encoded_stream);
        let body = match frame_signal {
            Some(signal) => body.monitored(signal),
            None => body,
        };

        let mut request_builder = self
            .client
            .post(url)
            .header(CONTENT_TYPE, CONTENT_TYPE_S2S)
            .body(body)
            .timeout(self.client.request_timeout);
        request_builder =
            add_basin_header_if_required(request_builder, &self.config.endpoints, &self.name);
        let mut request = request_builder.build()?;
        set_encryption_header(&mut request, encryption);
        let (response, access_token) = self.client.init_streaming_authorized(request).await?;
        let response = match response.into_result().await {
            Ok(response) => response,
            Err(error) => {
                self.client
                    .invalidate_access_token_if_rejected(&error, access_token.as_deref());
                return Err(error);
            }
        };
        let mut bytes_stream = response.stream();
        let auth_client = self.client.clone();

        let mut buffer = BytesMut::new();
        let mut decoder = FrameDecoder;

        Ok(Box::pin(try_stream! {
            while let Some(chunk) = bytes_stream.next().await {
                let chunk = chunk?;
                buffer.extend_from_slice(&chunk);

                loop {
                    match decoder.decode(&mut buffer) {
                        Ok(Some(SessionMessage::Regular(msg))) => {
                            if msg.reconnect_advised() {
                                reconnect.advise();
                            }
                            yield msg.try_into_proto()?;
                        }
                        Ok(Some(SessionMessage::Terminal(msg))) => {
                            let error: ApiError = msg.into();
                            auth_client.invalidate_access_token_if_rejected(
                                &error,
                                access_token.as_deref(),
                            );
                            Err::<(), ApiError>(error)?;
                        }
                        Ok(None) => break,
                        Err(err) => Err(err)?,
                    }
                }
            }
            if !buffer.is_empty() {
                Err(ClientError::UnexpectedEof(
                    format!("not all bytes were consumed from the buffer, {} remaining", buffer.len()),
                ))?;
            }
        }))
    }

    pub async fn read_session(
        &self,
        name: &StreamName,
        start: ReadStart,
        end: ReadEnd,
        encryption: Option<&EncryptionKey>,
        reconnect: ReconnectAdvice,
    ) -> Result<Streaming<ReadBatch>, ApiError> {
        let url = self.uri(format!("v1/streams/{}/records", urlencoding::encode(name)));

        let mut request_builder = self
            .client
            .get(url)
            .header(CONTENT_TYPE, CONTENT_TYPE_S2S)
            .query(&start)
            .query(&end)
            .timeout(self.client.request_timeout);
        request_builder =
            add_basin_header_if_required(request_builder, &self.config.endpoints, &self.name);
        let mut request = request_builder.build()?;
        set_encryption_header(&mut request, encryption);
        let (response, access_token) = self.client.init_streaming_authorized(request).await?;
        let response = match response.into_result().await {
            Ok(response) => response,
            Err(error) => {
                self.client
                    .invalidate_access_token_if_rejected(&error, access_token.as_deref());
                return Err(error);
            }
        };
        let mut bytes_stream = response.stream();
        let auth_client = self.client.clone();

        let mut buffer = BytesMut::new();
        let mut decoder = FrameDecoder;

        Ok(Box::pin(try_stream! {
            while let Some(chunk) = bytes_stream.next().await {
                let chunk = chunk?;
                buffer.extend_from_slice(&chunk);

                loop {
                    match decoder.decode(&mut buffer) {
                        Ok(Some(SessionMessage::Regular(msg))) => {
                            if msg.reconnect_advised() {
                                reconnect.advise();
                            }
                            yield msg.try_into_proto()?;
                        }
                        Ok(Some(SessionMessage::Terminal(msg))) => {
                            let error: ApiError = msg.into();
                            auth_client.invalidate_access_token_if_rejected(
                                &error,
                                access_token.as_deref(),
                            );
                            Err::<(), ApiError>(error)?;
                        }
                        Ok(None) => break,
                        Err(err) => Err(err)?,
                    }
                }
            }
            if !buffer.is_empty() {
                Err(ClientError::UnexpectedEof(
                    format!("not all bytes were consumed from the buffer, {} remaining", buffer.len()),
                ))?;
            }
        }))
    }
}

fn read_response_error_handler(
    status: StatusCode,
    response: UnaryResponse,
) -> Result<UnaryResponse, ApiError> {
    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        Err(ApiError::ReadUnwritten(response.json::<TailResponse>()?))
    } else {
        Err(ApiError::Server(
            status,
            response.json::<ServerErrorBody>()?,
        ))
    }
}

impl BasinClient {
    /// Drop pooled connections to the basin endpoint, so the next request
    /// opens a fresh connection instead of reusing one pinned to a draining
    /// server. In flight requests keep their connection.
    pub(crate) async fn rotate_transport(&self) {
        if let Some(authority) = self.base_url.authority() {
            self.client.client.rotate(authority.as_str()).await;
        }
    }
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
    Client(#[from] ClientError),
    #[error(transparent)]
    ProtoDecode(#[from] prost::DecodeError),
    #[error(transparent)]
    TerminalDecode(#[from] TerminalDecodeError),
    #[error("malformed access token: {0}")]
    MalformedAccessToken(String),
    #[cfg(feature = "_hidden")]
    #[error("access token provider failed: {0}")]
    AccessTokenProvider(crate::types::AccessTokenProviderError),
    #[error(transparent)]
    Compression(#[from] std::io::Error),
    #[error("append condition check failed")]
    AppendConditionFailed(AppendConditionFailed),
    #[error("read from an unwritten position")]
    ReadUnwritten(TailResponse),
    #[error("{1}")]
    Server(StatusCode, ServerErrorBody),
}

impl ApiError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Server(status, err_resp) => server_error_is_retryable(*status, &err_resp.code),
            Self::Client(err) => err.is_retryable(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(error) => error.is_retryable(),
            _ => false,
        }
    }

    pub(crate) fn is_authentication_error(&self) -> bool {
        matches!(
            self,
            Self::Server(StatusCode::UNAUTHORIZED, response) if response.code == "authn"
        )
    }

    pub fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Server(status, err_resp) => {
                server_error_has_no_side_effects(*status, &err_resp.code)
            }
            Self::Client(err) => err.has_no_side_effects(),
            #[cfg(feature = "_hidden")]
            Self::AccessTokenProvider(_) => true,
            _ => false,
        }
    }
}

impl From<client::HttpError> for ApiError {
    fn from(err: client::HttpError) -> Self {
        ClientError::from(err).into()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TerminalDecodeError {
    #[error("invalid status code: {0}")]
    InvalidStatusCode(#[from] http::status::InvalidStatusCode),
    #[error("failed to parse error response: {0}")]
    JsonDecode(#[from] serde_json::Error),
}

impl From<TerminalMessage> for ApiError {
    fn from(msg: TerminalMessage) -> Self {
        let status = match StatusCode::from_u16(msg.status) {
            Ok(status) => status,
            Err(err) => return ApiError::TerminalDecode(err.into()),
        };
        if status == StatusCode::PRECONDITION_FAILED {
            let condition_failed = match serde_json::from_str::<AppendConditionFailed>(&msg.body) {
                Ok(condition_failed) => condition_failed,
                Err(err) => {
                    return ApiError::TerminalDecode(err.into());
                }
            };
            ApiError::AppendConditionFailed(condition_failed)
        } else if status == StatusCode::RANGE_NOT_SATISFIABLE {
            let tail = match serde_json::from_str::<TailResponse>(&msg.body) {
                Ok(tail) => tail,
                Err(err) => {
                    return ApiError::TerminalDecode(err.into());
                }
            };
            ApiError::ReadUnwritten(tail)
        } else {
            let response = match serde_json::from_str::<ServerErrorBody>(&msg.body) {
                Ok(response) => response,
                Err(err) => {
                    return ApiError::TerminalDecode(err.into());
                }
            };
            ApiError::Server(status, response)
        }
    }
}

pub type Streaming<R> = Pin<Box<dyn Send + Stream<Item = Result<R, ApiError>>>>;

fn authorization_header(access_token: &str) -> Result<HeaderValue, ApiError> {
    let mut header = HeaderValue::try_from(format!("Bearer {access_token}"))
        .map_err(|error| ApiError::MalformedAccessToken(error.to_string()))?;
    header.set_sensitive(true);
    Ok(header)
}

#[derive(Clone)]
pub struct BaseClient {
    client: Arc<dyn client::RequestExecutor>,
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
    pub fn init(config: &S2Config) -> Result<Self, ApiError> {
        let connector = client::default_connector(
            Some(config.connection_timeout),
            config.insecure_skip_cert_verification,
            config.rustls_crypto_provider.clone(),
        )
        .map_err(|e| {
            ClientError::Configuration(format!("failed to initialize TLS connector: {e}"))
        })?;
        Self::init_with_connector(config, connector)
    }

    pub fn init_with_connector<C>(config: &S2Config, connector: C) -> Result<Self, ApiError>
    where
        C: client::Connect + Clone + Send + Sync + 'static,
    {
        let access_token_mode = config.access_token.mode();
        let mut default_headers = HeaderMap::new();
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

        let client = client::Pool::new(connector);

        Ok(Self {
            client: Arc::new(client),
            default_headers,
            access_token_mode,
            #[cfg(feature = "_hidden")]
            access_token_provider,
            request_timeout: config.request_timeout,
            retry_builder: retry_builder(&config.retry),
            compression: config.compression,
        })
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
    ) -> Result<(StreamingResponse, Option<String>), ApiError> {
        self.init_streaming(request)
            .await
            .map(|response| (response, None))
            .map_err(ApiError::from)
    }

    #[cfg(feature = "_hidden")]
    async fn init_streaming_authorized(
        &self,
        mut request: client::Request,
    ) -> Result<(StreamingResponse, Option<String>), ApiError> {
        let access_token = self.authorize(&mut request).await?;
        let response = self.init_streaming(request).await.map_err(ApiError::from)?;
        Ok((response, access_token))
    }

    async fn execute_unary(
        &self,
        mut request: client::Request,
    ) -> Result<(UnaryResponse, Option<String>), ApiError> {
        let access_token = self.authorize(&mut request).await?;
        let response = self
            .client
            .execute_unary(request)
            .await
            .map_err(ApiError::from)?;
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

    fn request(&self, request: client::Request) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            request,
            retry_enabled: true,
            append_retry_policy: None,
            frame_signal: None,
            error_handler: None,
        }
    }
}

fn set_encryption_header(request: &mut client::Request, encryption: Option<&EncryptionKey>) {
    if let Some(encryption) = encryption {
        request.headers_mut().insert(
            S2_ENCRYPTION_KEY_HEADER.clone(),
            encryption.to_header_value(),
        );
    }
}

pub fn retry_builder(config: &RetryConfig) -> RetryBackoffBuilder {
    RetryBackoffBuilder::default()
        .with_min_base_delay(config.min_base_delay)
        .with_max_base_delay(config.max_base_delay)
        .with_max_retries(config.max_retries())
}

type ErrorHandlerFn =
    Box<dyn Fn(StatusCode, UnaryResponse) -> Result<UnaryResponse, ApiError> + Send + Sync>;

struct RequestBuilder<'a> {
    client: &'a BaseClient,
    request: client::Request,
    retry_enabled: bool,
    append_retry_policy: Option<AppendRetryPolicy>,
    frame_signal: Option<FrameSignal>,
    error_handler: Option<ErrorHandlerFn>,
}

impl<'a> RequestBuilder<'a> {
    fn with_append_retry_policy(self, policy: AppendRetryPolicy) -> Self {
        let frame_signal = match policy {
            AppendRetryPolicy::NoSideEffects => Some(FrameSignal::new()),
            AppendRetryPolicy::All => None,
        };
        Self {
            append_retry_policy: Some(policy),
            frame_signal,
            ..self
        }
    }

    fn error_handler<F>(self, handler: F) -> Self
    where
        F: Fn(StatusCode, UnaryResponse) -> Result<UnaryResponse, ApiError> + Send + Sync + 'static,
    {
        Self {
            error_handler: Some(Box::new(handler)),
            ..self
        }
    }

    async fn send(self) -> Result<UnaryResponse, ApiError> {
        let request = self.request;

        let mut retry_backoff: Option<RetryBackoff> = self
            .retry_enabled
            .then(|| self.client.retry_builder.build());

        loop {
            if let Some(ref signal) = self.frame_signal {
                signal.reset();
            }

            let attempt_request = {
                let mut r = request.try_clone().expect("body should not be a stream");
                if let Some(ref signal) = self.frame_signal {
                    r = r.compress().await.map_err(ApiError::from)?;
                    r = r.with_monitored_body(signal.clone());
                }
                r
            };

            let response = self.client.execute_unary(attempt_request).await;

            let (err, retry_after, access_token) = match response {
                Ok((resp, access_token)) => {
                    let retry_after: Option<Duration> = resp
                        .headers()
                        .get(RETRY_AFTER_MS_HEADER)
                        .and_then(|v| match v.to_str() {
                            Ok(s) => Some(s),
                            Err(e) => {
                                warn!(
                                    ?e,
                                    "failed to parse {RETRY_AFTER_MS_HEADER} header as string"
                                );
                                None
                            }
                        })
                        .and_then(|v| match v.parse::<u64>() {
                            Ok(ms) => Some(ms),
                            Err(e) => {
                                warn!(?e, "failed to parse {RETRY_AFTER_MS_HEADER} header as u64");
                                None
                            }
                        })
                        .map(Duration::from_millis);

                    let result = if let Some(ref handler) = self.error_handler {
                        resp.into_result_with_handler(handler)
                    } else {
                        resp.into_result()
                    };

                    match result {
                        Ok(resp) => {
                            return Ok(resp);
                        }
                        Err(err) => (err, retry_after, access_token),
                    }
                }
                Err(err) => (err, None, None),
            };

            let refreshable_authentication_error =
                self.client.access_token_mode.is_refreshable() && err.is_authentication_error();
            if refreshable_authentication_error {
                self.client.invalidate_access_token(access_token.as_deref());
            }

            if is_safe_to_retry(
                &err,
                self.append_retry_policy,
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
                tokio::time::sleep(backoff).await;
            } else {
                debug!(
                    %err,
                    is_retryable = err.is_retryable() || refreshable_authentication_error,
                    retry_enabled = self.retry_enabled,
                    retries_exhausted = retry_backoff.as_ref().is_none_or(|b| b.is_exhausted()),
                    "not retrying request"
                );
                return Err(err);
            }
        }
    }
}

fn is_safe_to_retry(
    err: &ApiError,
    policy: Option<AppendRetryPolicy>,
    frame_signal: Option<&FrameSignal>,
    access_token_mode: AccessTokenMode,
) -> bool {
    let policy_compliant = match policy {
        None | Some(AppendRetryPolicy::All) => true,
        Some(AppendRetryPolicy::NoSideEffects) => {
            !frame_signal.is_none_or(|s| s.is_signalled()) || err.has_no_side_effects()
        }
    };
    policy_compliant
        && (err.is_retryable()
            || (access_token_mode.is_refreshable() && err.is_authentication_error()))
}

fn add_basin_header_if_required(
    request: client::RequestBuilder,
    endpoints: &S2Endpoints,
    name: &BasinName,
) -> client::RequestBuilder {
    if matches!(endpoints.basin_authority, BasinAuthority::Direct(_)) {
        return request.header(
            S2_BASIN,
            HeaderValue::from_str(name).expect("valid header value"),
        );
    }
    request
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
    fn into_result(self) -> Result<UnaryResponse, ApiError>;
    fn into_result_with_handler<F>(self, handler: F) -> Result<UnaryResponse, ApiError>
    where
        F: FnOnce(StatusCode, UnaryResponse) -> Result<UnaryResponse, ApiError>;
}

impl UnaryResult for UnaryResponse {
    fn into_result(self) -> Result<UnaryResponse, ApiError> {
        let status = self.status();
        if status.is_success() {
            Ok(self)
        } else {
            Err(ApiError::Server(status, self.json::<ServerErrorBody>()?))
        }
    }

    fn into_result_with_handler<F>(self, handler: F) -> Result<UnaryResponse, ApiError>
    where
        F: FnOnce(StatusCode, UnaryResponse) -> Result<UnaryResponse, ApiError>,
    {
        let status = self.status();
        if status.is_success() {
            Ok(self)
        } else {
            handler(status, self)
        }
    }
}

#[async_trait]
trait StreamingResult {
    async fn into_result(self) -> Result<StreamingResponse, ApiError>;
}

#[async_trait]
impl StreamingResult for StreamingResponse {
    async fn into_result(self) -> Result<StreamingResponse, ApiError> {
        if self.status().is_success() {
            return Ok(self);
        }

        let status = self.status();
        let bytes = self.into_bytes().await?;
        if status == StatusCode::RANGE_NOT_SATISFIABLE
            && let Ok(tail) = serde_json::from_slice::<TailResponse>(&bytes)
        {
            return Err(ApiError::ReadUnwritten(tail));
        }
        match serde_json::from_slice::<ServerErrorBody>(&bytes) {
            Ok(response) => Err(ApiError::Server(status, response)),
            Err(error) => Err(ApiError::Client(ClientError::ResponseDecode(format!(
                "could not decode server error {status}: {error}; body: {}",
                String::from_utf8_lossy(&bytes),
            )))),
        }
    }
}

trait IgnoreNotFound {
    fn ignore_not_found(self, enabled: bool) -> Result<(), ApiError>;
}

impl IgnoreNotFound for Result<UnaryResponse, ApiError> {
    fn ignore_not_found(self, enabled: bool) -> Result<(), ApiError> {
        match self {
            Ok(_) => Ok(()),
            Err(ApiError::Server(StatusCode::NOT_FOUND, _)) if enabled => Ok(()),
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
    #[cfg(feature = "_hidden")]
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[cfg(feature = "_hidden")]
    use async_trait::async_trait;
    #[cfg(feature = "_hidden")]
    use hyper_util::client::legacy::connect::HttpConnector;

    use super::*;

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

    fn server_error(status: StatusCode, code: &str) -> ApiError {
        ApiError::Server(
            status,
            ServerErrorBody {
                code: code.to_owned(),
                message: "test".to_owned(),
            },
        )
    }

    #[test]
    fn safe_to_retry_unary_no_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");
        let mode = AccessTokenMode::Static;

        // Non-append requests (no policy) — retry if retryable.
        assert!(is_safe_to_retry(&retryable, None, None, mode));
        assert!(!is_safe_to_retry(&non_retryable, None, None, mode));
    }

    #[test]
    fn safe_to_retry_unary_all_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");
        let policy = Some(AppendRetryPolicy::All);
        let mode = AccessTokenMode::Static;

        // All policy — retry if retryable, no frame signal checks.
        assert!(is_safe_to_retry(&retryable, policy, None, mode));
        assert!(!is_safe_to_retry(&non_retryable, policy, None, mode));
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

        // Signal not set — safe to retry.
        assert!(is_safe_to_retry(&retryable, policy, Some(&signal), mode));

        // Signal set + error with possible side effects — not safe.
        signal.signal();
        assert!(!is_safe_to_retry(&retryable, policy, Some(&signal), mode));

        // Signal set + no-side-effect error — safe.
        assert!(is_safe_to_retry(
            &no_side_effect,
            policy,
            Some(&signal),
            mode,
        ));
        assert!(is_safe_to_retry(
            &transaction_conflict,
            policy,
            Some(&signal),
            mode,
        ));

        // Signal set + non-retryable — never safe.
        assert!(!is_safe_to_retry(
            &non_retryable,
            policy,
            Some(&signal),
            mode,
        ));
    }

    #[cfg(feature = "_hidden")]
    #[tokio::test]
    async fn dynamic_access_token_is_loaded_for_each_attempt_and_marked_sensitive() {
        let config = S2Config::new("unused").with_access_token_provider(RotatingTokenProvider {
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

        let response = client.request(request).send().await.unwrap();

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
        let err: ApiError = match client.request(request).send().await {
            Err(e) => e,
            Ok(_) => panic!("should fail with DNS error"),
        };
        assert!(
            matches!(&err, ApiError::Client(ClientError::Connect(_))),
            "expected a connect error, got: {err}"
        );
    }
}
