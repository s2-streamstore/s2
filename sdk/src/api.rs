use crate::client::{self, StreamingResponse, UnaryResponse};
use crate::retry::{RetryBackoff, RetryBackoffBuilder};
use crate::types::{
    AccessTokenId, BasinAuthority, BasinName, Compression, RetryConfig, S2Config, S2Endpoints,
    StreamName,
};
use async_stream::try_stream;
use async_trait::async_trait;
use bytes::BytesMut;
use futures::{Stream, StreamExt};
use http::header::InvalidHeaderValue;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, StatusCode};
use prost::{self, Message};
use s2_api::v1::access::{
    AccessTokenInfo, IssueAccessTokenResponse, ListAccessTokensRequest, ListAccessTokensResponse,
};
use s2_api::v1::basin::{BasinInfo, CreateBasinRequest, ListBasinsRequest, ListBasinsResponse};
use s2_api::v1::config::{BasinConfig, BasinReconfiguration, StreamConfig, StreamReconfiguration};
use s2_api::v1::metrics::{
    AccountMetricSetRequest, BasinMetricSetRequest, MetricSetResponse, StreamMetricSetRequest,
};
use s2_api::v1::stream::s2s::{self, FrameDecoder, SessionMessage, TerminalMessage};
use s2_api::v1::stream::{
    AppendConditionFailed, CreateStreamRequest, ListStreamsRequest, ListStreamsResponse, ReadEnd,
    ReadStart, StreamInfo, TailResponse,
    proto::{AppendAck, AppendInput, ReadBatch},
};
use secrecy::ExposeSecret;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::codec::Decoder;
use tracing::{debug, warn};
use url::Url;

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
    pub base_url: Url,
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

    pub async fn list_access_tokens(
        &self,
        request: ListAccessTokensRequest,
    ) -> Result<ListAccessTokensResponse, ApiError> {
        let url = self.base_url.join("v1/access-tokens")?;
        let request = self.get(url).query(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<ListAccessTokensResponse>()?)
    }

    pub async fn issue_access_token(
        &self,
        info: AccessTokenInfo,
    ) -> Result<IssueAccessTokenResponse, ApiError> {
        let url = self.base_url.join("v1/access-tokens")?;
        let request = self.post(url).json(&info).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<IssueAccessTokenResponse>()?)
    }

    pub async fn revoke_access_token(&self, id: AccessTokenId) -> Result<(), ApiError> {
        let url = self
            .base_url
            .join(&format!("v1/access-tokens/{}", urlencoding::encode(&id)))?;
        let request = self.delete(url).build()?;
        let _response = self.request(request).send().await?;
        Ok(())
    }

    pub async fn list_basins(
        &self,
        request: ListBasinsRequest,
    ) -> Result<ListBasinsResponse, ApiError> {
        let url = self.base_url.join("v1/basins")?;
        let request = self.get(url).query(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<ListBasinsResponse>()?)
    }

    pub async fn create_basin(
        &self,
        request: CreateBasinRequest,
        idempotency_token: String,
    ) -> Result<BasinInfo, ApiError> {
        let url = self.base_url.join("v1/basins")?;
        let request = self
            .post(url)
            .header(S2_REQUEST_TOKEN, idempotency_token)
            .json(&request)
            .build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<BasinInfo>()?)
    }

    pub async fn get_basin_config(&self, name: BasinName) -> Result<BasinConfig, ApiError> {
        let url = self.base_url.join(&format!("v1/basins/{name}"))?;
        let request = self.get(url).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<BasinConfig>()?)
    }

    pub async fn reconfigure_basin(
        &self,
        name: BasinName,
        config: BasinReconfiguration,
    ) -> Result<BasinConfig, ApiError> {
        let url = self.base_url.join(&format!("v1/basins/{name}"))?;
        let request = self.patch(url).json(&config).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<BasinConfig>()?)
    }

    pub async fn delete_basin(
        &self,
        name: BasinName,
        ignore_not_found: bool,
    ) -> Result<(), ApiError> {
        let url = self.base_url.join(&format!("v1/basins/{name}"))?;
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
        let url = self.base_url.join("v1/metrics")?;
        let request = self.get(url).query(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<MetricSetResponse>()?)
    }

    pub async fn get_basin_metrics(
        &self,
        name: BasinName,
        request: BasinMetricSetRequest,
    ) -> Result<MetricSetResponse, ApiError> {
        let url = self.base_url.join(&format!("v1/metrics/{name}"))?;
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
        let url = self.base_url.join(&format!(
            "v1/metrics/{basin_name}/{}",
            urlencoding::encode(&stream_name)
        ))?;
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
    pub base_url: Url,
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
        let url = self.base_url.join("v1/streams")?;
        let request = self.get(url).query(&request).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<ListStreamsResponse>()?)
    }

    pub async fn create_stream(
        &self,
        request: CreateStreamRequest,
        idempotency_token: String,
    ) -> Result<StreamInfo, ApiError> {
        let url = self.base_url.join("v1/streams")?;
        let request = self
            .post(url)
            .header(S2_REQUEST_TOKEN, idempotency_token)
            .json(&request)
            .build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<StreamInfo>()?)
    }

    pub async fn get_stream_config(&self, name: StreamName) -> Result<StreamConfig, ApiError> {
        let url = self
            .base_url
            .join(&format!("v1/streams/{}", urlencoding::encode(&name)))?;
        let request = self.get(url).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<StreamConfig>()?)
    }

    pub async fn reconfigure_stream(
        &self,
        name: StreamName,
        config: StreamReconfiguration,
    ) -> Result<StreamConfig, ApiError> {
        let url = self
            .base_url
            .join(&format!("v1/streams/{}", urlencoding::encode(&name)))?;
        let request = self.patch(url).json(&config).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<StreamConfig>()?)
    }

    pub async fn delete_stream(
        &self,
        name: StreamName,
        ignore_not_found: bool,
    ) -> Result<(), ApiError> {
        let url = self
            .base_url
            .join(&format!("v1/streams/{}", urlencoding::encode(&name)))?;
        let request = self.delete(url).build()?;
        self.request(request)
            .send()
            .await
            .ignore_not_found(ignore_not_found)?;
        Ok(())
    }

    pub async fn check_tail(&self, name: &StreamName) -> Result<TailResponse, ApiError> {
        let url = self.base_url.join(&format!(
            "v1/streams/{}/records/tail",
            urlencoding::encode(name)
        ))?;
        let request = self.get(url).build()?;
        let response = self.request(request).send().await?;
        Ok(response.json::<TailResponse>()?)
    }

    pub async fn append(
        &self,
        name: &StreamName,
        input: AppendInput,
        retry_enabled: bool,
    ) -> Result<AppendAck, ApiError> {
        let url = self
            .base_url
            .join(&format!("v1/streams/{}/records", urlencoding::encode(name)))?;
        let request = self
            .post(url)
            .header(CONTENT_TYPE, CONTENT_TYPE_PROTO)
            .header(ACCEPT, ACCEPT_PROTO)
            .body(input.encode_to_vec())
            .build()?;
        let response = self
            .request(request)
            .with_retry_enabled(retry_enabled)
            .error_handler(|status, response| {
                if status == StatusCode::PRECONDITION_FAILED {
                    Err(ApiError::AppendConditionFailed(
                        response.json::<AppendConditionFailed>()?,
                    ))
                } else {
                    Err(ApiError::Server(
                        status,
                        response.json::<ApiErrorResponse>()?,
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
    ) -> Result<ReadBatch, ApiError> {
        let url = self
            .base_url
            .join(&format!("v1/streams/{}/records", urlencoding::encode(name)))?;
        let request = self
            .get(url)
            .header(ACCEPT, ACCEPT_PROTO)
            .query(&start)
            .query(&end)
            .build()?;
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
    ) -> Result<Streaming<AppendAck>, ApiError>
    where
        I: Stream<Item = AppendInput> + Send + 'static,
    {
        let url = self
            .base_url
            .join(&format!("v1/streams/{}/records", urlencoding::encode(name)))?;

        let compression = self.config.compression.into();

        let encoded_stream = inputs.map(move |input| {
            s2s::SessionMessage::regular(compression, &input).map(|msg| msg.encode())
        });

        let mut request_builder = self
            .client
            .post(url)
            .header(CONTENT_TYPE, CONTENT_TYPE_S2S)
            .body(client::Body::wrap_stream(encoded_stream))
            .timeout(self.client.request_timeout);
        request_builder =
            add_basin_header_if_required(request_builder, &self.config.endpoints, &self.name);
        let response = self
            .client
            .init_streaming(request_builder.build()?)
            .await?
            .into_result()
            .await?;
        let mut bytes_stream = response.stream();

        let mut buffer = BytesMut::new();
        let mut decoder = FrameDecoder;

        Ok(Box::pin(try_stream! {
            while let Some(chunk) = bytes_stream.next().await {
                let chunk = chunk?;
                buffer.extend_from_slice(&chunk);

                loop {
                    match decoder.decode(&mut buffer) {
                        Ok(Some(SessionMessage::Regular(msg))) => {
                            yield msg.try_into_proto()?;
                        }
                        Ok(Some(SessionMessage::Terminal(msg))) => {
                            Err::<(), ApiError>(msg.into())?;
                        }
                        Ok(None) => break,
                        Err(err) => Err(err)?,
                    }
                }
            }
        }))
    }

    pub async fn read_session(
        &self,
        name: &StreamName,
        start: ReadStart,
        end: ReadEnd,
    ) -> Result<Streaming<ReadBatch>, ApiError> {
        let url = self
            .base_url
            .join(&format!("v1/streams/{}/records", urlencoding::encode(name)))?;

        let mut request_builder = self
            .client
            .get(url)
            .header(CONTENT_TYPE, CONTENT_TYPE_S2S)
            .query(&start)
            .query(&end)
            .timeout(self.client.request_timeout);
        request_builder =
            add_basin_header_if_required(request_builder, &self.config.endpoints, &self.name);
        let response = self
            .client
            .init_streaming(request_builder.build()?)
            .await?
            .into_result()
            .await?;
        let mut bytes_stream = response.stream();

        let mut buffer = BytesMut::new();
        let mut decoder = FrameDecoder;

        Ok(Box::pin(try_stream! {
            while let Some(chunk) = bytes_stream.next().await {
                let chunk = chunk?;
                buffer.extend_from_slice(&chunk);

                loop {
                    match decoder.decode(&mut buffer) {
                        Ok(Some(SessionMessage::Regular(msg))) => {
                            yield msg.try_into_proto()?;
                        }
                        Ok(Some(SessionMessage::Terminal(msg))) => {
                            Err::<(), ApiError>(msg.into())?;
                        }
                        Ok(None) => break,
                        Err(err) => Err(err)?,
                    }
                }
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
            response.json::<ApiErrorResponse>()?,
        ))
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
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    ProtoDecode(#[from] prost::DecodeError),
    #[error(transparent)]
    S2STerminalDecode(#[from] S2STerminalDecodeError),
    #[error(transparent)]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error(transparent)]
    Compression(#[from] std::io::Error),
    #[error("append condition check failed")]
    AppendConditionFailed(AppendConditionFailed),
    #[error("read from an unwritten position")]
    ReadUnwritten(TailResponse),
    #[error("{1}")]
    Server(StatusCode, ApiErrorResponse),
}

impl ApiError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Server(status, err_resp) => {
                matches!(
                    *status,
                    StatusCode::REQUEST_TIMEOUT
                        | StatusCode::TOO_MANY_REQUESTS
                        | StatusCode::INTERNAL_SERVER_ERROR
                        | StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT
                ) || (*status == StatusCode::CONFLICT && err_resp.code == "transaction_conflict")
            }
            Self::Client(err) => err.is_retryable(),
            _ => false,
        }
    }
}

impl From<client::Error> for ApiError {
    fn from(err: client::Error) -> Self {
        ClientError::from(err).into()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connect: {0}")]
    Connect(String),
    #[error("timeout")]
    Timeout,
    #[error("connection closed early: {0}")]
    ConnectionClosedEarly(String),
    #[error("request canceled: {0}")]
    RequestCanceled(String),
    #[error("unexpected eof: {0}")]
    UnexpectedEof(String),
    #[error("connection reset: {0}")]
    ConnectionReset(String),
    #[error("connection aborted: {0}")]
    ConnectionAborted(String),
    #[error("connection refused: {0}")]
    ConnectionRefused(String),
    #[error("{0}")]
    Others(String),
}

impl ClientError {
    pub fn is_retryable(&self) -> bool {
        !matches!(self, ClientError::Others(_))
    }
}

impl From<client::Error> for ClientError {
    fn from(err: client::Error) -> Self {
        let err_msg = err.to_string();
        match err {
            client::Error::Send(ref send_err) if send_err.is_connect() => {
                classify_io_source(&err, &err_msg).unwrap_or(Self::Connect(err_msg))
            }
            client::Error::Send(_) | client::Error::Receive(_) => {
                classify_hyper_source(&err, &err_msg)
                    .or_else(|| classify_io_source(&err, &err_msg))
                    .unwrap_or(Self::Others(err_msg))
            }
            client::Error::Timeout => Self::Timeout,
            _ => Self::Others(err_msg),
        }
    }
}

fn classify_hyper_source(err: &client::Error, err_msg: &str) -> Option<ClientError> {
    let hyper_err = source_err::<hyper::Error>(err)?;
    let err_msg = format!("{hyper_err} -> {err_msg}");
    if hyper_err.is_incomplete_message() {
        Some(ClientError::ConnectionClosedEarly(err_msg))
    } else if hyper_err.is_canceled() {
        Some(ClientError::RequestCanceled(err_msg))
    } else {
        None
    }
}

fn classify_io_source(err: &client::Error, err_msg: &str) -> Option<ClientError> {
    let io_err = source_err::<std::io::Error>(err)?;
    let err_msg = format!("{io_err} -> {err_msg}");
    Some(match io_err.kind() {
        std::io::ErrorKind::UnexpectedEof => ClientError::UnexpectedEof(err_msg),
        std::io::ErrorKind::ConnectionReset => ClientError::ConnectionReset(err_msg),
        std::io::ErrorKind::ConnectionAborted => ClientError::ConnectionAborted(err_msg),
        std::io::ErrorKind::ConnectionRefused => ClientError::ConnectionRefused(err_msg),
        _ => return None,
    })
}

fn source_err<T: std::error::Error + 'static>(err: &dyn std::error::Error) -> Option<&T> {
    let mut source = err.source();

    while let Some(err) = source {
        if let Some(err) = err.downcast_ref::<T>() {
            return Some(err);
        }

        source = err.source();
    }
    None
}

#[derive(Debug, thiserror::Error)]
pub enum S2STerminalDecodeError {
    #[error("invalid status code: {0}")]
    InvalidStatusCode(#[from] http::status::InvalidStatusCode),
    #[error("failed to parse error response: {0}")]
    JsonDecode(#[from] serde_json::Error),
}

impl From<TerminalMessage> for ApiError {
    fn from(msg: TerminalMessage) -> Self {
        let status = match StatusCode::from_u16(msg.status) {
            Ok(status) => status,
            Err(err) => return ApiError::S2STerminalDecode(err.into()),
        };
        if status == StatusCode::PRECONDITION_FAILED {
            let condition_failed = match serde_json::from_str::<AppendConditionFailed>(&msg.body) {
                Ok(condition_failed) => condition_failed,
                Err(err) => {
                    return ApiError::S2STerminalDecode(err.into());
                }
            };
            ApiError::AppendConditionFailed(condition_failed)
        } else if status == StatusCode::RANGE_NOT_SATISFIABLE {
            let tail = match serde_json::from_str::<TailResponse>(&msg.body) {
                Ok(tail) => tail,
                Err(err) => {
                    return ApiError::S2STerminalDecode(err.into());
                }
            };
            ApiError::ReadUnwritten(tail)
        } else {
            let response = match serde_json::from_str::<ApiErrorResponse>(&msg.body) {
                Ok(response) => response,
                Err(err) => {
                    return ApiError::S2STerminalDecode(err.into());
                }
            };
            ApiError::Server(status, response)
        }
    }
}

pub type Streaming<R> = Pin<Box<dyn Send + Stream<Item = Result<R, ApiError>>>>;

#[derive(Clone)]
pub struct BaseClient {
    client: Arc<dyn client::RequestExecutor>,
    default_headers: HeaderMap,
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
        )
        .map_err(|e| ClientError::Others(format!("failed to load TLS certificates: {e}")))?;
        Self::init_with_connector(config, connector)
    }

    pub fn init_with_connector<C>(config: &S2Config, connector: C) -> Result<Self, ApiError>
    where
        C: client::Connect + Clone + Send + Sync + 'static,
    {
        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", config.access_token.expose_secret()).try_into()?,
        );
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
            request_timeout: config.request_timeout,
            retry_builder: retry_builder(&config.retry),
            compression: config.compression,
        })
    }

    pub fn get(&self, url: Url) -> client::RequestBuilder {
        client::RequestBuilder::get(url)
            .timeout(self.request_timeout)
            .headers(&self.default_headers)
    }

    pub fn post(&self, url: Url) -> client::RequestBuilder {
        client::RequestBuilder::post(url)
            .timeout(self.request_timeout)
            .headers(&self.default_headers)
            .compression(self.compression)
    }

    pub fn patch(&self, url: Url) -> client::RequestBuilder {
        client::RequestBuilder::patch(url)
            .timeout(self.request_timeout)
            .headers(&self.default_headers)
            .compression(self.compression)
    }

    pub fn delete(&self, url: Url) -> client::RequestBuilder {
        client::RequestBuilder::delete(url)
            .timeout(self.request_timeout)
            .headers(&self.default_headers)
    }

    pub async fn init_streaming(
        &self,
        request: client::Request,
    ) -> Result<StreamingResponse, client::Error> {
        self.client.init_streaming(request).await
    }

    async fn execute_unary(
        &self,
        request: client::Request,
    ) -> Result<UnaryResponse, client::Error> {
        self.client.execute_unary(request).await
    }

    fn request(&self, request: client::Request) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            request,
            retry_enabled: true,
            error_handler: None,
        }
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
    error_handler: Option<ErrorHandlerFn>,
}

impl<'a> RequestBuilder<'a> {
    fn with_retry_enabled(self, retry_enabled: bool) -> Self {
        Self {
            retry_enabled,
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
            let response = self
                .client
                .execute_unary(request.try_clone().expect("body should not be a stream"))
                .await;

            let (err, retry_after) = match response {
                Ok(resp) => {
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
                        Err(err) if err.is_retryable() => (err, retry_after),
                        Err(err) => return Err(err),
                    }
                }
                Err(err) => (ApiError::from(err), None),
            };

            if err.is_retryable()
                && let Some(backoff) = retry_backoff.as_mut().and_then(|b| b.next())
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
                    is_retryable = err.is_retryable(),
                    retry_enabled = self.retry_enabled,
                    retries_exhausted = retry_backoff.as_ref().is_none_or(|b| b.is_exhausted()),
                    "not retrying request"
                );
                return Err(err);
            }
        }
    }
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

fn base_url(endpoints: &S2Endpoints, kind: ClientKind) -> Url {
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
    Url::parse(&format!("{scheme}://{authority}")).expect("valid url")
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
            Err(ApiError::Server(status, self.json::<ApiErrorResponse>()?))
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
        match serde_json::from_slice::<ApiErrorResponse>(&bytes) {
            Ok(response) => Err(ApiError::Server(status, response)),
            Err(_) => Err(ApiError::Client(ClientError::Others(format!(
                "server error {status}: {}",
                String::from_utf8_lossy(&bytes)
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
