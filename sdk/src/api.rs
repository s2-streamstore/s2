use std::{ops::Deref, pin::Pin, sync::Arc, time::Duration};

use async_stream::try_stream;
use async_trait::async_trait;
use bytes::BytesMut;
use futures::{Stream, StreamExt};
use http::{
    HeaderMap, HeaderValue, StatusCode,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, InvalidHeaderValue},
};
use prost::{self, Message};
#[cfg(feature = "_hidden")]
use s2_api::v1::basin::CreateOrReconfigureBasinRequest;
use s2_api::v1::{
    access::{
        AccessTokenInfo, IssueAccessTokenResponse, ListAccessTokensRequest,
        ListAccessTokensResponse,
    },
    basin::{BasinInfo, CreateBasinRequest, ListBasinsRequest, ListBasinsResponse},
    config::{BasinConfig, BasinReconfiguration, StreamConfig, StreamReconfiguration},
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
use s2_common::encryption::S2_ENCRYPTION_KEY_HEADER;
use secrecy::ExposeSecret;
use tokio_util::codec::Decoder;
use tracing::{debug, warn};
use url::Url;

use crate::{
    client::{self, StreamingResponse, UnaryResponse},
    frame_signal::FrameSignal,
    retry::{RetryBackoff, RetryBackoffBuilder},
    types::{
        AccessTokenId, AppendRetryPolicy, BasinAuthority, BasinName, Compression, EncryptionKey,
        RetryConfig, S2Config, S2Endpoints, StreamName,
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

    #[cfg(feature = "_hidden")]
    pub async fn create_or_reconfigure_basin(
        &self,
        name: BasinName,
        request: Option<CreateOrReconfigureBasinRequest>,
    ) -> Result<(bool, BasinInfo), ApiError> {
        let url = self.base_url.join(&format!("v1/basins/{name}"))?;
        let request = match request {
            Some(body) => self.put(url).json(&body).build()?,
            None => self.put(url).build()?,
        };
        let response = self.request(request).send().await?;
        let was_created = response.status() == StatusCode::CREATED;
        Ok((was_created, response.json::<BasinInfo>()?))
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

    #[cfg(feature = "_hidden")]
    pub async fn create_or_reconfigure_stream(
        &self,
        name: StreamName,
        config: Option<StreamReconfiguration>,
    ) -> Result<(bool, StreamInfo), ApiError> {
        let url = self
            .base_url
            .join(&format!("v1/streams/{}", urlencoding::encode(&name)))?;
        let request = match config {
            Some(body) => self.put(url).json(&body).build()?,
            None => self.put(url).build()?,
        };
        let response = self.request(request).send().await?;
        let was_created = response.status() == StatusCode::CREATED;
        Ok((was_created, response.json::<StreamInfo>()?))
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
        encryption: Option<&EncryptionKey>,
        append_retry_policy: AppendRetryPolicy,
    ) -> Result<AppendAck, ApiError> {
        let url = self
            .base_url
            .join(&format!("v1/streams/{}/records", urlencoding::encode(name)))?;
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
        encryption: Option<&EncryptionKey>,
    ) -> Result<ReadBatch, ApiError> {
        let url = self
            .base_url
            .join(&format!("v1/streams/{}/records", urlencoding::encode(name)))?;
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
        let response = self
            .client
            .init_streaming(request)
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
        let mut request = request_builder.build()?;
        set_encryption_header(&mut request, encryption);
        let response = self
            .client
            .init_streaming(request)
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

    pub fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Server(status, err_resp) => matches!(
                (*status, err_resp.code.as_str()),
                (StatusCode::TOO_MANY_REQUESTS, "rate_limited")
                    | (StatusCode::BAD_GATEWAY, "hot_server")
            ),
            Self::Client(err) => err.has_no_side_effects(),
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

    pub fn has_no_side_effects(&self) -> bool {
        match self {
            ClientError::Connect(_)
            | ClientError::Timeout
            | ClientError::ConnectionClosedEarly(_)
            | ClientError::RequestCanceled(_)
            | ClientError::UnexpectedEof(_)
            | ClientError::ConnectionReset(_)
            | ClientError::ConnectionAborted(_)
            | ClientError::Others(_) => false,
            ClientError::ConnectionRefused(_) => true,
        }
    }
}

impl From<client::Error> for ClientError {
    fn from(err: client::Error) -> Self {
        let err_msg = err.to_string();
        match err {
            client::Error::Send(ref send_err) if send_err.is_connect() => {
                classify_io_source(&err, &err_msg)
                    .or_else(|| classify_dns_source(&err, &err_msg))
                    .unwrap_or(Self::Connect(err_msg))
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

/// Walk the error source chain looking for a "dns error" tag.
///
/// hyper-util's `ConnectError` (not publicly exported, so we can't downcast)
/// tags DNS failures with the static string "dns error" via `ConnectError::dns()`.
/// This is not a platform-specific message — it's a structural tag from the
/// Rust library. If the HTTP client changes, this will harmlessly stop matching
/// and DNS errors will fall through to the generic `Connect` variant.
fn classify_dns_source(err: &client::Error, _err_msg: &str) -> Option<ClientError> {
    let mut source = Some(err as &dyn std::error::Error);
    while let Some(err) = source {
        if err.to_string() == "dns error" {
            // Build the message from the DNS error's source (the actual
            // resolver error) rather than the top-level hyper wrapper.
            let detail = match err.source() {
                Some(cause) => format!("dns resolution: {cause}"),
                None => "dns resolution failed".to_owned(),
            };
            return Some(ClientError::Connect(detail));
        }
        source = err.source();
    }
    None
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

    #[cfg(feature = "_hidden")]
    pub fn put(&self, url: Url) -> client::RequestBuilder {
        client::RequestBuilder::put(url)
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

            if is_safe_to_retry(&err, self.append_retry_policy, self.frame_signal.as_ref())
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

fn is_safe_to_retry(
    err: &ApiError,
    policy: Option<AppendRetryPolicy>,
    frame_signal: Option<&FrameSignal>,
) -> bool {
    let policy_compliant = match policy {
        None | Some(AppendRetryPolicy::All) => true,
        Some(AppendRetryPolicy::NoSideEffects) => {
            !frame_signal.is_none_or(|s| s.is_signalled()) || err.has_no_side_effects()
        }
    };
    policy_compliant && err.is_retryable()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that DNS resolution failures produce a clear error message
    /// containing "dns resolution" rather than the opaque hyper wrapper.
    /// This also serves as a regression test: if hyper-util changes its
    /// internal "dns error" tag, this test will fail, signaling that
    /// `classify_dns_source` needs updating.
    fn server_error(status: StatusCode, code: &str) -> ApiError {
        ApiError::Server(
            status,
            ApiErrorResponse {
                code: code.to_owned(),
                message: "test".to_owned(),
            },
        )
    }

    #[test]
    fn api_error_has_no_side_effects() {
        // Server errors that guarantee no mutation.
        assert!(server_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited").has_no_side_effects());
        assert!(server_error(StatusCode::BAD_GATEWAY, "hot_server").has_no_side_effects());

        // Server errors that do NOT guarantee no mutation.
        assert!(!server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal").has_no_side_effects());
        assert!(!server_error(StatusCode::BAD_GATEWAY, "other").has_no_side_effects());
        assert!(
            !server_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable").has_no_side_effects()
        );
    }

    #[test]
    fn client_error_has_no_side_effects() {
        // Connection was never established.
        assert!(ClientError::ConnectionRefused("test".into()).has_no_side_effects());

        // May have side effects — data could have been sent/processed.
        assert!(!ClientError::Connect("test".into()).has_no_side_effects());
        assert!(!ClientError::Timeout.has_no_side_effects());
        assert!(!ClientError::ConnectionClosedEarly("test".into()).has_no_side_effects());
        assert!(!ClientError::RequestCanceled("test".into()).has_no_side_effects());
        assert!(!ClientError::UnexpectedEof("test".into()).has_no_side_effects());
        assert!(!ClientError::ConnectionReset("test".into()).has_no_side_effects());
        assert!(!ClientError::ConnectionAborted("test".into()).has_no_side_effects());
        assert!(!ClientError::Others("test".into()).has_no_side_effects());
    }

    #[test]
    fn safe_to_retry_unary_no_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");

        // Non-append requests (no policy) — retry if retryable.
        assert!(is_safe_to_retry(&retryable, None, None));
        assert!(!is_safe_to_retry(&non_retryable, None, None));
    }

    #[test]
    fn safe_to_retry_unary_all_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");
        let policy = Some(AppendRetryPolicy::All);

        // All policy — retry if retryable, no frame signal checks.
        assert!(is_safe_to_retry(&retryable, policy, None));
        assert!(!is_safe_to_retry(&non_retryable, policy, None));
    }

    #[test]
    fn safe_to_retry_unary_no_side_effects_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");
        let no_side_effect = server_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        let policy = Some(AppendRetryPolicy::NoSideEffects);
        let signal = FrameSignal::new();

        // Signal not set — safe to retry.
        assert!(is_safe_to_retry(&retryable, policy, Some(&signal)));

        // Signal set + error with possible side effects — not safe.
        signal.signal();
        assert!(!is_safe_to_retry(&retryable, policy, Some(&signal)));

        // Signal set + no-side-effect error — safe.
        assert!(is_safe_to_retry(&no_side_effect, policy, Some(&signal)));

        // Signal set + non-retryable — never safe.
        assert!(!is_safe_to_retry(&non_retryable, policy, Some(&signal)));
    }

    #[tokio::test]
    async fn dns_error_message_is_clear() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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
            .parse::<url::Url>()
            .unwrap();
        let request = client.get(url).build().unwrap();
        let err: ApiError = match client.request(request).send().await {
            Err(e) => e,
            Ok(_) => panic!("should fail with DNS error"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("dns resolution"),
            "expected 'dns resolution' in error, got: {msg}"
        );
    }
}
