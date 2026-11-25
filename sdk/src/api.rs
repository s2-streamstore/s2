use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_stream::try_stream;
use bytes::BytesMut;
use futures_core::Stream;
use futures_util::StreamExt;
use http::{
    HeaderMap, HeaderName, HeaderValue, StatusCode, Uri,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use prost::Message;
use s2_api::v1::stream::{
    ReadEnd, ReadStart,
    proto::{AppendAck, ReadBatch},
    s2s::{FrameDecoder, SessionMessage},
};
use s2_common::{basin::BASIN_HEADER, resources::PROVISION_RESULT_HEADER};
use secrecy::ExposeSecret;
use serde::de::DeserializeOwned;
use tokio_util::codec::Decoder;
use tracing::{Instrument, debug, debug_span};

use crate::{
    client::{self, CancellationToken, StreamingResponse, UnaryResponse},
    error::{
        AbortedError, AppendSessionError, ClientClosedError, ConnectionLostError, ErrorCode,
        ErrorContext, OpScope, ProtocolError, ReadSessionError, TransportError, ValidationError,
    },
    retry::RetryBackoff,
    send_gate::SendGate,
    session::StreamHeaders,
    types::{
        AccessToken, AccessTokenId, AppendRetryPolicy, BasinName, Compression, EnsureOutput,
        NetworkPolicySelector, RetryConfig, S2Config, S2Endpoints, StreamName,
    },
};

const CONTENT_TYPE_S2S: HeaderValue = HeaderValue::from_static("s2s/proto");
pub(crate) const APPLICATION_PROTOBUF: HeaderValue =
    HeaderValue::from_static("application/protobuf");
const S2_ATTEMPT: HeaderName = HeaderName::from_static("s2-attempt");
const RETRY_AFTER_MS_HEADER: HeaderName = HeaderName::from_static("retry-after-ms");
/// Maximum idle backing allocation retained by an empty S2S frame decode buffer.
///
/// Matches the default HTTP/2 `SETTINGS_MAX_FRAME_SIZE` (16 KiB) so small frames reuse their
/// buffer without reallocating while large frames (up to 2.5 MiB) do not remain pinned across
/// idle or parked sessions after `BytesMut::split_to`.
const S2S_READ_BUFFER_MAX_IDLE_CAPACITY: usize = 16 * 1024;

fn attempt_header_value(attempt: u32) -> HeaderValue {
    match attempt {
        1 => HeaderValue::from_static("1"),
        2 => HeaderValue::from_static("2"),
        3 => HeaderValue::from_static("3"),
        4 => HeaderValue::from_static("4"),
        5 => HeaderValue::from_static("5"),
        6 => HeaderValue::from_static("6"),
        7 => HeaderValue::from_static("7"),
        8 => HeaderValue::from_static("8"),
        9 => HeaderValue::from_static("9"),
        10 => HeaderValue::from_static("10"),
        n => HeaderValue::from(n),
    }
}

pub(crate) struct S2sFrame<T> {
    pub(crate) msg: T,
    pub(crate) reconnect_advised: bool,
}

pub(crate) struct Streaming<R, E> {
    stream: Pin<Box<dyn Send + Stream<Item = Result<S2sFrame<R>, E>>>>,
    retire_handle: client::RetireHandle,
    chunks_received: Arc<AtomicU64>,
}

impl<R, E> Streaming<R, E> {
    pub(crate) fn retire_connection(&self) {
        self.retire_handle.retire();
    }

    pub(crate) fn chunks_received(&self) -> u64 {
        self.chunks_received.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn from_stream_for_test<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<S2sFrame<R>, E>> + Send + 'static,
    {
        Self {
            stream: Box::pin(stream),
            retire_handle: client::RetireHandle::noop(),
            chunks_received: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl<R, E> Stream for Streaming<R, E> {
    type Item = Result<S2sFrame<R>, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.as_mut().poll_next(cx)
    }
}

pub(crate) fn basin_path(name: &BasinName) -> String {
    format!("/v1/basins/{}", urlencoding::encode(name))
}

pub(crate) fn stream_path(name: &StreamName) -> String {
    format!("/v1/streams/{}", urlencoding::encode(name))
}

pub(crate) fn stream_records_path(name: &StreamName) -> String {
    format!("/v1/streams/{}/records", urlencoding::encode(name))
}

pub(crate) fn stream_tail_path(name: &StreamName) -> String {
    format!("/v1/streams/{}/records/tail", urlencoding::encode(name))
}

pub(crate) fn token_path(id: &AccessTokenId) -> String {
    format!("/v1/access-tokens/{}", urlencoding::encode(id))
}

pub(crate) fn network_policy_path(selector: &NetworkPolicySelector) -> String {
    format!(
        "/v1/network-policies/{}",
        urlencoding::encode(&selector.to_string())
    )
}

pub(crate) fn metrics_basin_path(basin: &BasinName) -> String {
    format!("/v1/metrics/{}", urlencoding::encode(basin))
}

pub(crate) fn metrics_stream_path(basin: &BasinName, stream: &StreamName) -> String {
    format!(
        "/v1/metrics/{}/{}",
        urlencoding::encode(basin),
        urlencoding::encode(stream)
    )
}

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

struct BaseClientInner {
    client: Arc<dyn client::RequestExecutor>,
    shutdown: CancellationToken,
    default_headers: HeaderMap,
    #[cfg(feature = "_hidden")]
    access_token_provider: Option<Arc<dyn crate::types::AccessTokenProvider>>,
    request_timeout: Duration,
    compression: Compression,
}

#[derive(Clone)]
pub(crate) struct BaseClient {
    inner: Arc<BaseClientInner>,
    retry: RetryConfig,
}

impl std::fmt::Debug for BaseClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BaseClient").finish_non_exhaustive()
    }
}

impl BaseClient {
    pub(crate) fn init(config: &S2Config) -> Result<Self, ValidationError> {
        // Validate config and static token BEFORE initializing TLS so invalid configs never get
        // masked by missing TLS providers or native CA errors.
        let (default_headers, provider) = Self::prepare(config)?;
        let shutdown = CancellationToken::new();
        if config.endpoints.scheme == http::uri::Scheme::HTTP {
            let connector = client::default_http_connector(Some(config.connection_timeout));
            Ok(Self::from_parts(
                config,
                default_headers,
                provider,
                connector,
                shutdown,
            ))
        } else {
            let connector = client::default_connector(
                Some(config.connection_timeout),
                config.insecure_skip_cert_verification,
                config.rustls_crypto_provider.clone(),
            )
            .map_err(|e| ValidationError(format!("failed to initialize TLS connector: {e}")))?;
            Ok(Self::from_parts(
                config,
                default_headers,
                provider,
                connector,
                shutdown,
            ))
        }
    }

    #[cfg(feature = "_hidden")]
    pub(crate) fn init_with_connector<C>(
        config: &S2Config,
        connector: C,
    ) -> Result<Self, ValidationError>
    where
        C: client::Connect,
    {
        let (default_headers, provider) = Self::prepare(config)?;
        Ok(Self::from_parts(
            config,
            default_headers,
            provider,
            connector,
            CancellationToken::new(),
        ))
    }

    fn prepare(config: &S2Config) -> Result<(HeaderMap, PreparedTokenProvider), ValidationError> {
        config.validate()?;
        let mut default_headers = config.default_headers.clone();
        // `Authorization` and `s2-basin` are SDK-managed headers; never let caller-supplied
        // defaults leak onto account or Cloud basin requests (`C3`).
        default_headers.remove(AUTHORIZATION);
        default_headers.remove(&BASIN_HEADER);
        let provider = match &config.access_token {
            AccessToken::Static(access_token) => {
                default_headers.insert(
                    AUTHORIZATION,
                    authorization_header(access_token.expose_secret())?,
                );
                PreparedTokenProvider {
                    #[cfg(feature = "_hidden")]
                    provider: None,
                }
            }
            #[cfg(feature = "_hidden")]
            AccessToken::Provider(provider) => PreparedTokenProvider {
                provider: Some(provider.clone()),
            },
        };
        apply_standard_default_headers(&mut default_headers, config);
        Ok((default_headers, provider))
    }

    fn from_parts<C: client::Connect>(
        config: &S2Config,
        default_headers: HeaderMap,
        access_token_provider: PreparedTokenProvider,
        connector: C,
        shutdown: CancellationToken,
    ) -> Self {
        let pool = client::Pool::new(
            connector,
            config.connection_timeout,
            config.http2,
            shutdown.clone(),
        );
        #[cfg(not(feature = "_hidden"))]
        let _ = access_token_provider;
        Self {
            inner: Arc::new(BaseClientInner {
                client: Arc::new(pool),
                shutdown,
                default_headers,
                #[cfg(feature = "_hidden")]
                access_token_provider: access_token_provider.provider,
                request_timeout: config.request_timeout,
                compression: config.compression,
            }),
            retry: config.retry,
        }
    }

    pub(crate) fn with_retry(self, retry: RetryConfig) -> Result<Self, ValidationError> {
        retry.validate()?;
        Ok(Self { retry, ..self })
    }

    pub(crate) fn close(&self) {
        self.inner.shutdown.cancel();
        self.inner.client.close();
    }

    fn is_closed(&self) -> bool {
        self.inner.shutdown.is_cancelled()
    }

    fn shutdown_token(&self) -> CancellationToken {
        self.inner.shutdown.clone()
    }

    pub(crate) fn refreshes_tokens(&self) -> bool {
        #[cfg(feature = "_hidden")]
        {
            self.inner.access_token_provider.is_some()
        }
        #[cfg(not(feature = "_hidden"))]
        {
            false
        }
    }

    pub(crate) fn request_timeout(&self) -> Duration {
        self.inner.request_timeout
    }

    pub(crate) fn compression(&self) -> Compression {
        self.inner.compression
    }

    pub(crate) fn retry_config(&self) -> RetryConfig {
        self.retry
    }

    pub(crate) fn get(&self, uri: Uri) -> client::RequestBuilder {
        client::RequestBuilder::get(uri)
            .timeout(self.inner.request_timeout)
            .headers(&self.inner.default_headers)
    }

    pub(crate) fn post(&self, uri: Uri) -> client::RequestBuilder {
        client::RequestBuilder::post(uri)
            .timeout(self.inner.request_timeout)
            .headers(&self.inner.default_headers)
    }

    pub(crate) fn patch(&self, uri: Uri) -> client::RequestBuilder {
        client::RequestBuilder::patch(uri)
            .timeout(self.inner.request_timeout)
            .headers(&self.inner.default_headers)
    }

    pub(crate) fn put(&self, uri: Uri) -> client::RequestBuilder {
        client::RequestBuilder::put(uri)
            .timeout(self.inner.request_timeout)
            .headers(&self.inner.default_headers)
    }

    pub(crate) fn delete(&self, uri: Uri) -> client::RequestBuilder {
        client::RequestBuilder::delete(uri)
            .timeout(self.inner.request_timeout)
            .headers(&self.inner.default_headers)
    }

    pub(crate) fn unary<'a>(
        &'a self,
        request: Result<client::Request, client::HttpError>,
        scope: OpScope<'a>,
    ) -> UnaryCall<'a> {
        UnaryCall {
            client: self,
            request,
            scope,
            retry_safety: RetrySafety::All,
        }
    }

    async fn init_streaming_authorized<E: TransportError>(
        &self,
        mut request: client::Request,
        context: ErrorContext,
    ) -> Result<(StreamingResponse, Option<String>), E> {
        let access_token = if self.refreshes_tokens() {
            tokio::select! {
                biased;
                _ = self.inner.shutdown.cancelled() => {
                    return Err(AbortedError::new_with_context("client closed", context).into());
                }
                res = self.authorize::<E>(&mut request, || context.clone()) => res?,
            }
        } else {
            if self.is_closed() {
                return Err(AbortedError::new_with_context("client closed", context).into());
            }
            None
        };
        let response = self
            .inner
            .client
            .init_streaming(request)
            .await
            .map_err(|e| E::from_http(e, context))?;
        Ok((response, access_token))
    }

    async fn send_attempt<E: TransportError>(
        &self,
        mut request: client::Request,
        scope: OpScope<'_>,
        attempts: u32,
    ) -> Result<(UnaryResponse, Option<String>), E> {
        let access_token = if self.refreshes_tokens() {
            tokio::select! {
                biased;
                _ = self.inner.shutdown.cancelled() => {
                    return Err(AbortedError::new_with_context("client closed", scope.context(attempts)).into());
                }
                res = self.authorize::<E>(&mut request, || scope.context(attempts)) => res?,
            }
        } else {
            if self.is_closed() {
                return Err(AbortedError::new_with_context(
                    "client closed",
                    scope.context(attempts),
                )
                .into());
            }
            None
        };
        let response = self
            .inner
            .client
            .execute_unary(request)
            .await
            .map_err(|e| E::from_http(e, scope.context(attempts)))?;
        Ok((response, access_token))
    }

    async fn authorize<E: TransportError>(
        &self,
        _request: &mut client::Request,
        _make_context: impl FnOnce() -> ErrorContext,
    ) -> Result<Option<String>, E> {
        #[cfg(feature = "_hidden")]
        if let Some(provider) = self.inner.access_token_provider.as_ref() {
            let access_token = provider
                .access_token()
                .await
                .map_err(E::from_access_token_provider)?;
            let header = authorization_header(&access_token)
                .map_err(|e| _make_context().format_validation(e))?;
            _request.headers_mut().insert(AUTHORIZATION, header);
            return Ok(Some(access_token));
        }
        Ok(None)
    }

    fn invalidate_access_token(&self, _access_token: Option<&str>) {
        #[cfg(feature = "_hidden")]
        if let (Some(provider), Some(access_token)) =
            (self.inner.access_token_provider.as_ref(), _access_token)
        {
            provider.invalidate_access_token(access_token);
        }
    }

    fn invalidate_access_token_if_rejected<E: TransportError>(
        &self,
        error: &E,
        access_token: Option<&str>,
    ) {
        if error.is_authentication_error() {
            self.invalidate_access_token(access_token);
        }
    }
}

struct PreparedTokenProvider {
    #[cfg(feature = "_hidden")]
    provider: Option<Arc<dyn crate::types::AccessTokenProvider>>,
}

fn apply_standard_default_headers(default_headers: &mut HeaderMap, config: &S2Config) {
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
}

#[derive(Debug, Clone, Copy)]
enum RetrySafety {
    /// Safe to retry any retryable error (reads, idempotent ops, or request-token ops).
    All,
    /// Non-idempotent op without a request token (`T2d`): retry only definite errors.
    DefiniteOnly,
    /// Unary append (`T2c`): obeys `AppendRetryPolicy` and tracks prior uncertainty.
    Append(AppendRetryPolicy),
}

pub(crate) struct UnaryCall<'a> {
    client: &'a BaseClient,
    request: Result<client::Request, client::HttpError>,
    scope: OpScope<'a>,
    retry_safety: RetrySafety,
}

impl<'a> UnaryCall<'a> {
    pub(crate) fn definite_retries_only(mut self) -> Self {
        self.retry_safety = RetrySafety::DefiniteOnly;
        self
    }

    pub(crate) fn append_retry_policy(mut self) -> Self {
        self.retry_safety = RetrySafety::Append(self.client.retry_config().append_retry_policy);
        self
    }

    async fn send_raw<E: TransportError>(self) -> Result<(UnaryResponse, u32), E> {
        let span = debug_span!(
            "unary",
            op = self.scope.operation,
            basin = self.scope.basin,
            stream = self.scope.stream,
        );
        self.send_raw_inner::<E>().instrument(span).await
    }

    async fn send_raw_inner<E: TransportError>(self) -> Result<(UnaryResponse, u32), E> {
        if self.client.is_closed() {
            return Err(ClientClosedError::new_with_context(self.scope.context(1)).into());
        }

        // Compress the unary request body once before the retry loop so retries clone O(1)
        // `Bytes` without re-compressing.
        let compression = self.client.compression();
        let request = self
            .request
            .and_then(|req| req.compress(compression))
            .map_err(|e| E::from_http(e, self.scope.context(1)))?;

        struct StopOnDrop<'a>(Option<&'a SendGate>);
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                if let Some(gate) = self.0 {
                    gate.stop();
                }
            }
        }

        // Gate any non-read-only unary request with a non-empty body so pre-send
        // `ConnectionLostError` is accurately classified as definite (`E3`) and ended attempts
        // cannot transmit bytes after error/cancellation (`T10`).
        let gate_body = !self.scope.read_only && request.has_non_empty_body();

        let mut retry_backoff = RetryBackoff::from_config(&self.client.retry_config());
        let mut prior_uncertainty = false;
        let mut request = Some(request);

        loop {
            let attempts = retry_backoff.attempt_number();
            // Fresh per-attempt gate so an ended/timed-out attempt cannot send frames after
            // error classification or taint the next attempt (`T10`).
            let send_gate = gate_body.then(SendGate::new);

            let attempt_request = {
                let mut r = if retry_backoff.is_exhausted() {
                    request.take().expect("request available on final attempt")
                } else {
                    request
                        .as_ref()
                        .expect("request available before final attempt")
                        .try_clone()
                        .expect("body should not be a stream")
                };
                r.headers_mut()
                    .insert(S2_ATTEMPT, attempt_header_value(attempts));
                if let Some(ref gate) = send_gate {
                    r = r.with_gated_body(gate.clone());
                }
                r
            };

            let response = {
                let _stop_on_drop = StopOnDrop(send_gate.as_ref());
                self.client
                    .send_attempt::<E>(attempt_request, self.scope, attempts)
                    .await
            };

            let (err, retry_after, access_token) = match response {
                Ok((mut resp, access_token)) => {
                    if resp.status().is_success() {
                        return Ok((resp, attempts));
                    }
                    let retry_after = parse_retry_after_ms(resp.headers());
                    let retire_handle = resp.take_retire_handle();
                    let status = resp.status();
                    let err = E::from_http_response(
                        status,
                        &resp.into_bytes(),
                        self.scope.context(attempts),
                    );
                    if err.should_retire_connection()
                        && let Some(handle) = retire_handle
                    {
                        handle.retire();
                    }
                    (err, retry_after, access_token)
                }
                Err(err) => (err, None, None),
            };

            // Atomically seal the send gate before checking unsent/retry predicates so a parked
            // hyper body task cannot emit frames after this point (`T10`, `Terms: Sent`).
            let unsent = send_gate.as_ref().is_some_and(SendGate::stop);
            let err = err.mark_unsent_connection_lost(unsent);

            self.client
                .invalidate_access_token_if_rejected(&err, access_token.as_deref());
            let is_retryable = err.is_retryable_or_auth_refresh(self.client.refreshes_tokens());

            if is_retryable
                && is_safe_to_retry(&err, self.retry_safety, send_gate.as_ref())
                && let Some(backoff) = retry_backoff.next()
            {
                let delay = retry_after.map_or(backoff, |ra| ra.max(backoff));
                debug!(
                    err = %err,
                    attempt = attempts,
                    ?delay,
                    ?retry_after,
                    retries_remaining = retry_backoff.remaining(),
                    "retrying request"
                );
                if matches!(self.retry_safety, RetrySafety::Append(_))
                    && attempt_may_have_side_effects(&err, send_gate.as_ref())
                {
                    prior_uncertainty = true;
                }
                let shutdown = self.client.shutdown_token();
                let aborted = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => true,
                    _ = tokio::time::sleep(delay) => false,
                };
                if aborted {
                    return Err(AbortedError::new_with_context(
                        "client closed",
                        self.scope.context(attempts),
                    )
                    .into());
                }
            } else {
                debug!(
                    err = %err,
                    attempt = attempts,
                    is_retryable,
                    retries_exhausted = retry_backoff.is_exhausted(),
                    "not retrying request"
                );
                return Err(err.with_prior_uncertainty(prior_uncertainty));
            }
        }
    }

    pub(crate) async fn send_json<T: DeserializeOwned>(
        self,
    ) -> Result<T, crate::error::RequestError> {
        self.send_json_as().await
    }

    pub(crate) async fn send_json_as<T: DeserializeOwned, E: TransportError>(self) -> Result<T, E> {
        let scope = self.scope;
        let (response, attempts) = self.send_raw::<E>().await?;
        response
            .json::<T>()
            .map_err(|e| E::from_http(e, scope.context(attempts)))
    }

    pub(crate) async fn send_proto<T: Message + Default, E: TransportError>(
        self,
    ) -> Result<(T, u32), E> {
        let scope = self.scope;
        let (response, attempts) = self.send_raw::<E>().await?;
        let decoded = T::decode(response.into_bytes()).map_err(|e| {
            E::from(ProtocolError::new_with_context(
                format!("protobuf decode: {e}"),
                scope.context(attempts),
            ))
        })?;
        Ok((decoded, attempts))
    }

    pub(crate) async fn send_ensure<T: DeserializeOwned>(
        self,
    ) -> Result<EnsureOutput<T>, crate::error::RequestError> {
        let scope = self.scope;
        let (response, attempts) = self.send_raw::<crate::error::RequestError>().await?;
        let status = response.status();
        let header_value = response
            .headers()
            .get(&PROVISION_RESULT_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let info = response
            .json::<T>()
            .map_err(|e| crate::error::RequestError::from_http(e, scope.context(attempts)))?;
        Ok(ensure_output_from_parts(
            status,
            header_value.as_deref(),
            info,
        ))
    }

    pub(crate) async fn send_delete(
        self,
        ignore_not_found: ErrorCode,
    ) -> Result<(), crate::error::RequestError> {
        match self.send_raw::<crate::error::RequestError>().await {
            Ok(_) => Ok(()),
            Err(err) if err.has_error_code(ignore_not_found) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

fn attempt_may_have_side_effects<E: TransportError>(err: &E, send_gate: Option<&SendGate>) -> bool {
    !err.has_no_side_effects() && send_gate.is_none_or(SendGate::was_sent)
}

fn is_safe_to_retry<E: TransportError>(
    err: &E,
    safety: RetrySafety,
    send_gate: Option<&SendGate>,
) -> bool {
    match safety {
        RetrySafety::All | RetrySafety::Append(AppendRetryPolicy::All) => true,
        RetrySafety::DefiniteOnly => {
            // T2d: non-idempotent ops without a request token retry only after a definite error.
            // (`ConnectionLostError` occurring before sending was already marked definite above.)
            err.has_no_side_effects()
        }
        RetrySafety::Append(AppendRetryPolicy::NoSideEffects) => {
            !attempt_may_have_side_effects(err, send_gate)
        }
    }
}

#[derive(Clone)]
pub(crate) struct BasinClient {
    pub(crate) name: BasinName,
    base: BaseClient,
    base_url: Uri,
    basin_header: Option<HeaderValue>,
}

impl std::fmt::Debug for BasinClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasinClient")
            .field("name", &self.name)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl BasinClient {
    pub(crate) fn init(name: BasinName, endpoints: &S2Endpoints, base: BaseClient) -> Self {
        let base_url = endpoints
            .basin_origin(&name)
            .parse()
            .expect("valid basin URI");
        let basin_header = endpoints
            .uses_basin_header()
            .then(|| HeaderValue::from_str(&name).expect("valid basin header value"));
        Self {
            name,
            base,
            base_url,
            basin_header,
        }
    }

    pub(crate) fn base(&self) -> &BaseClient {
        &self.base
    }

    pub(crate) fn base_url(&self) -> &Uri {
        &self.base_url
    }

    pub(crate) fn with_retry(self, retry: RetryConfig) -> Result<Self, ValidationError> {
        let base = self.base.with_retry(retry)?;
        Ok(Self { base, ..self })
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.base.is_closed()
    }

    pub(crate) fn shutdown_token(&self) -> CancellationToken {
        self.base.shutdown_token()
    }

    pub(crate) fn uri(&self, path: impl AsRef<str>) -> Uri {
        client::uri_with_path(&self.base_url, path)
    }

    pub(crate) fn get(&self, path: impl AsRef<str>) -> client::RequestBuilder {
        self.base.get(self.uri(path))
    }

    pub(crate) fn post(&self, path: impl AsRef<str>) -> client::RequestBuilder {
        self.base.post(self.uri(path))
    }

    pub(crate) fn put(&self, path: impl AsRef<str>) -> client::RequestBuilder {
        self.base.put(self.uri(path))
    }

    pub(crate) fn patch(&self, path: impl AsRef<str>) -> client::RequestBuilder {
        self.base.patch(self.uri(path))
    }

    pub(crate) fn delete(&self, path: impl AsRef<str>) -> client::RequestBuilder {
        self.base.delete(self.uri(path))
    }

    pub(crate) fn basin_scope(&self, op: &'static str, read_only: bool) -> OpScope<'_> {
        OpScope::basin(op, self.name.as_ref(), read_only)
    }

    pub(crate) fn stream_scope<'a>(
        &'a self,
        op: &'static str,
        stream: &'a StreamName,
        read_only: bool,
    ) -> OpScope<'a> {
        OpScope::stream(op, self.name.as_ref(), stream.as_ref(), read_only)
    }

    fn apply_basin_header(&self, request: &mut client::Request) {
        if let Some(ref header) = self.basin_header {
            request
                .headers_mut()
                .insert(BASIN_HEADER.clone(), header.clone());
        }
    }

    pub(crate) fn unary<'a>(
        &'a self,
        request: Result<client::Request, client::HttpError>,
        scope: OpScope<'a>,
    ) -> UnaryCall<'a> {
        let request = request.map(|mut req| {
            self.apply_basin_header(&mut req);
            req
        });
        self.base.unary(request, scope)
    }

    async fn open_s2s<T, E>(
        &self,
        builder: client::RequestBuilder,
        headers: &StreamHeaders,
        attempt: u32,
        ctx: ErrorContext,
    ) -> Result<Streaming<T, E>, E>
    where
        T: Message + Default + 'static,
        E: TransportError + Send + 'static,
    {
        let mut request = builder
            .header(CONTENT_TYPE, CONTENT_TYPE_S2S)
            .header(S2_ATTEMPT, attempt_header_value(attempt))
            .build()
            .map_err(|e| E::from_http(e, ctx.clone()))?;
        self.apply_basin_header(&mut request);
        headers.apply(&mut request);

        let (response, access_token) = self
            .base
            .init_streaming_authorized::<E>(request, ctx.clone())
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let (bytes, retire_handle) = response.into_bytes_with_retire_handle().await;
            let error = E::from_http_response(status, &bytes, ctx);
            if error.should_retire_connection() {
                retire_handle.retire();
            }
            self.base
                .invalidate_access_token_if_rejected(&error, access_token.as_deref());
            return Err(error);
        }

        let (mut bytes_stream, retire_handle) = response.into_stream();
        let stream_retire = retire_handle.clone();
        let auth_client = self.base.clone();
        let chunks_received = Arc::new(AtomicU64::new(0));
        let stream_chunks = chunks_received.clone();

        let mut buffer = BytesMut::new();
        let mut buffer_peak_bytes: usize = 0;
        let mut decoder = FrameDecoder;

        let stream = Box::pin(try_stream! {
            while let Some(chunk) = bytes_stream.next().await {
                let chunk = chunk.map_err(|e| E::from_http(e, ctx.clone()))?;
                if !chunk.is_empty() {
                    stream_chunks.fetch_add(1, Ordering::Relaxed);
                }
                buffer.extend_from_slice(&chunk);
                buffer_peak_bytes = buffer_peak_bytes.max(buffer.len()).max(buffer.capacity());

                loop {
                    match decoder.decode(&mut buffer) {
                        Ok(Some(SessionMessage::Regular(msg))) => {
                            let reconnect_advised = msg.reconnect_advised();
                            if reconnect_advised {
                                stream_retire.retire();
                            }
                            let decoded = msg.try_into_proto().map_err(|e| {
                                E::from(ProtocolError::new_with_context(
                                    format!("protobuf decode: {e}"),
                                    ctx.clone(),
                                ))
                            })?;
                            // Release any oversized backing allocation before yielding so a
                            // parked session does not pin a 1–2.5 MiB BytesMut allocation
                            // (even when `split_to` left `buffer.capacity() == 0`).
                            release_excess_s2s_buffer(&mut buffer, &mut buffer_peak_bytes);
                            yield S2sFrame {
                                msg: decoded,
                                reconnect_advised,
                            };
                        }
                        Ok(Some(SessionMessage::Terminal(msg))) => {
                            let error = E::from_terminal_message(msg, ctx.clone());
                            if error.should_retire_connection() {
                                stream_retire.retire();
                            }
                            auth_client.invalidate_access_token_if_rejected(
                                &error,
                                access_token.as_deref(),
                            );
                            Err::<(), E>(error)?;
                        }
                        Ok(None) => {
                            release_excess_s2s_buffer(&mut buffer, &mut buffer_peak_bytes);
                            break;
                        }
                        Err(err) => Err(E::from(ProtocolError::new_with_context(
                            format!("s2s frame decode: {err}"),
                            ctx.clone(),
                        )))?,
                    }
                }
            }
            if !buffer.is_empty() {
                Err(E::from(ConnectionLostError::new_with_context(
                    format!(
                        "truncated s2s frame at end of stream ({} bytes remaining)",
                        buffer.len()
                    ),
                    false,
                    ctx.clone(),
                )))?;
            }
        });
        Ok(Streaming {
            stream,
            retire_handle,
            chunks_received,
        })
    }

    pub(crate) async fn append_session<I>(
        &self,
        op: &'static str,
        name: &StreamName,
        encoded_chunks: I,
        headers: &StreamHeaders,
        attempt: u32,
    ) -> Result<Streaming<AppendAck, AppendSessionError>, AppendSessionError>
    where
        I: Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static,
    {
        // Keep attempts at 1 here; the session task owns retry accounting across budget resets
        // (`T5a`) and attaches the real attempt count when settling an error (`E7`).
        let ctx = self.stream_scope(op, name, false).context(1);
        let builder = self
            .post(stream_records_path(name))
            .body(client::Body::wrap_stream(encoded_chunks));
        self.open_s2s(builder, headers, attempt, ctx).await
    }

    pub(crate) async fn read_session(
        &self,
        op: &'static str,
        name: &StreamName,
        start: ReadStart,
        end: ReadEnd,
        headers: &StreamHeaders,
        attempt: u32,
    ) -> Result<Streaming<ReadBatch, ReadSessionError>, ReadSessionError> {
        let ctx = self.stream_scope(op, name, true).context(1);
        let builder = self
            .get(stream_records_path(name))
            .query(&start)
            .query(&end);
        self.open_s2s(builder, headers, attempt, ctx).await
    }
}

fn release_excess_s2s_buffer(buffer: &mut BytesMut, peak_bytes: &mut usize) {
    if buffer.is_empty() && *peak_bytes > S2S_READ_BUFFER_MAX_IDLE_CAPACITY {
        *buffer = BytesMut::new();
        *peak_bytes = 0;
    }
}

fn parse_retry_after_ms(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(&RETRY_AFTER_MS_HEADER)?;
    let raw = match value.to_str() {
        Ok(s) => s,
        Err(err) => {
            debug!(%err, "ignoring non-UTF-8 {RETRY_AFTER_MS_HEADER} header");
            return None;
        }
    };
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        debug!(
            value = raw,
            "ignoring malformed {RETRY_AFTER_MS_HEADER} header"
        );
        return None;
    }
    match raw.parse::<u64>() {
        Ok(ms) => Some(Duration::from_millis(ms)),
        Err(err) => {
            debug!(
                %err,
                value = raw,
                "ignoring out-of-range {RETRY_AFTER_MS_HEADER} header"
            );
            None
        }
    }
}

fn ensure_output_from_parts<T>(
    status: StatusCode,
    header_value: Option<&str>,
    info: T,
) -> EnsureOutput<T> {
    match header_value {
        Some("created") => EnsureOutput::Created(info),
        Some("noop") => EnsureOutput::Noop(info),
        Some("updated") => EnsureOutput::Updated(info),
        _ if status == StatusCode::CREATED => EnsureOutput::Created(info),
        _ => EnsureOutput::Updated(info),
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
    #[cfg(any(
        feature = "_hidden",
        feature = "rustls-aws-lc-rs",
        feature = "rustls-ring"
    ))]
    use crate::error::RequestError;
    use crate::error::{AppendError, ServerError};

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
            // Exercise a real retry through UnaryCall::send_raw.
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
    fn base_with_executor(
        config: &S2Config,
        executor: Arc<dyn client::RequestExecutor>,
        retry: RetryConfig,
    ) -> BaseClient {
        let (default_headers, access_token_provider) = BaseClient::prepare(config).unwrap();
        BaseClient {
            inner: Arc::new(BaseClientInner {
                client: executor,
                shutdown: CancellationToken::new(),
                default_headers,
                access_token_provider: access_token_provider.provider,
                request_timeout: config.request_timeout,
                compression: config.compression,
            }),
            retry,
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
            (
                BASIN_HEADER.clone(),
                HeaderValue::from_static("wrong-basin"),
            ),
        ]);
        let config = S2Config::new("actual-token")
            .with_endpoints(crate::types::S2Endpoints::for_endpoint("http://example.test").unwrap())
            .with_compression(Compression::Gzip)
            .with_default_headers(headers)
            .unwrap();
        let executor = Arc::new(HeaderCapture::default());
        let retry = RetryConfig::new()
            .with_min_base_delay(Duration::ZERO)
            .with_max_base_delay(Duration::ZERO)
            .with_max_attempts(2);
        let base = base_with_executor(&config, executor.clone(), retry);

        let account_uri: Uri = "http://example.test/v1/basins".parse().unwrap();
        let _: s2_api::v1::basin::ListBasinsResponse = base
            .unary(
                base.get(account_uri).build(),
                OpScope::account("list_basins", true),
            )
            .send_json()
            .await
            .unwrap();

        let basin = BasinClient::init("test-basin".parse().unwrap(), &config.endpoints, base);
        let _: s2_api::v1::stream::ListStreamsResponse = basin
            .unary(
                basin.get("v1/streams").build(),
                OpScope::basin("list_streams", basin.name.as_ref(), true),
            )
            .send_json()
            .await
            .unwrap();

        let stream = "test-stream".parse().unwrap();
        let stream_headers = StreamHeaders::default();
        assert!(
            basin
                .read_session(
                    "read_session",
                    &stream,
                    ReadStart {
                        seq_num: None,
                        timestamp: None,
                        tail_offset: None,
                        clamp: None,
                    },
                    ReadEnd {
                        count: None,
                        bytes: None,
                        until: None,
                        wait: None,
                    },
                    &stream_headers,
                    1,
                )
                .await
                .is_err()
        );
        assert!(
            basin
                .append_session(
                    "append_session",
                    &stream,
                    futures_util::stream::empty(),
                    &stream_headers,
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
        assert!(!unary[0].contains_key(&BASIN_HEADER));
        assert!(!unary[1].contains_key(&BASIN_HEADER));
        assert_eq!(unary[2][&BASIN_HEADER], "test-basin");
        for headers in streaming.iter() {
            assert_eq!(headers[&BASIN_HEADER], "test-basin");
            assert_eq!(headers[CONTENT_TYPE], CONTENT_TYPE_S2S);
        }
    }

    #[cfg(feature = "_hidden")]
    #[rstest::rstest]
    #[case::none(Compression::None, None, "gzip, zstd")]
    #[case::gzip(Compression::Gzip, Some("gzip"), "gzip")]
    #[case::zstd(Compression::Zstd, Some("zstd"), "zstd")]
    #[test]
    fn default_accept_encoding_respects_configured_compression(
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
            .compress(client.compression())
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

    fn append_server_error(status: StatusCode, code: &str) -> AppendError {
        AppendError::Server(ServerError::new(status, "test").with_code(code))
    }

    #[test]
    fn safe_to_retry_matrix() {
        let indefinite = append_server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let definite = append_server_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        let gate = SendGate::new();

        assert!(is_safe_to_retry(&indefinite, RetrySafety::All, None));
        assert!(is_safe_to_retry(
            &indefinite,
            RetrySafety::Append(AppendRetryPolicy::All),
            None
        ));
        // Unsent body: safe under Append(NoSideEffects), still unsafe under DefiniteOnly.
        assert!(is_safe_to_retry(
            &indefinite,
            RetrySafety::Append(AppendRetryPolicy::NoSideEffects),
            Some(&gate)
        ));
        assert!(!is_safe_to_retry(
            &indefinite,
            RetrySafety::DefiniteOnly,
            Some(&gate)
        ));

        // Sent body: only definite errors remain safe.
        assert!(gate.try_mark_sent());
        assert!(!is_safe_to_retry(
            &indefinite,
            RetrySafety::Append(AppendRetryPolicy::NoSideEffects),
            Some(&gate)
        ));
        assert!(is_safe_to_retry(
            &definite,
            RetrySafety::Append(AppendRetryPolicy::NoSideEffects),
            Some(&gate)
        ));
        assert!(is_safe_to_retry(
            &definite,
            RetrySafety::DefiniteOnly,
            Some(&gate)
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

        client
            .authorize::<RequestError>(&mut request, ErrorContext::default)
            .await
            .unwrap();
        let first = request.headers_mut().get(AUTHORIZATION).unwrap();
        assert_eq!(first, "Bearer token-1");
        assert!(first.is_sensitive());

        client
            .authorize::<RequestError>(&mut request, ErrorContext::default)
            .await
            .unwrap();
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
        let retry = RetryConfig::new()
            .with_min_base_delay(Duration::ZERO)
            .with_max_base_delay(Duration::ZERO)
            .with_max_attempts(2);
        let client = BaseClient {
            inner: Arc::new(BaseClientInner {
                client: executor.clone(),
                shutdown: CancellationToken::new(),
                default_headers: HeaderMap::new(),
                access_token_provider: Some(provider.clone()),
                request_timeout: Duration::from_secs(1),
                compression: Compression::None,
            }),
            retry,
        };
        let request = client
            .get("http://example.test/v1/basins".parse().unwrap())
            .build();

        let (response, _) = client
            .unary(request, OpScope::account("list_basins", true))
            .send_raw::<RequestError>()
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
        let transient = RequestError::AccessTokenProvider(
            crate::types::AccessTokenProviderError::transient("temporarily unavailable"),
        );
        assert!(transient.is_retryable());
        assert!(transient.has_no_side_effects());

        let permanent = RequestError::AccessTokenProvider(
            crate::types::AccessTokenProviderError::permanent("login required"),
        );
        assert!(!permanent.is_retryable());
        assert!(permanent.has_no_side_effects());
    }

    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[tokio::test]
    async fn dns_errors_are_classified_as_connect() {
        let config = S2Config::new("test-token".to_owned())
            .with_endpoints(
                crate::types::S2Endpoints::for_endpoint("https://no-such-basin.invalid").unwrap(),
            )
            // Skip native root CA loading so the test works in sandboxed
            // CI environments without keychain access.
            .with_insecure_skip_cert_verification(true);
        let client = BaseClient::init(&config).expect("client init");
        let url = "https://no-such-basin.invalid/v1/streams"
            .parse::<Uri>()
            .unwrap();
        let err: RequestError = match client
            .unary(
                client.get(url).build(),
                OpScope::account("list_streams", true),
            )
            .send_raw::<RequestError>()
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("should fail with DNS error"),
        };
        assert!(
            matches!(&err, RequestError::Connect(c) if c.message.contains("dns")),
            "expected a connect error with dns cause, got: {err}"
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
            (
                "18446744073709551615",
                Some(Duration::from_millis(u64::MAX)),
            ),
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
            headers.insert(&RETRY_AFTER_MS_HEADER, HeaderValue::from_str(raw).unwrap());
            assert_eq!(parse_retry_after_ms(&headers), expected, "raw={raw:?}");
        }

        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert(
            &RETRY_AFTER_MS_HEADER,
            HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        assert_eq!(parse_retry_after_ms(&non_utf8), None);
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

    #[test]
    fn release_excess_s2s_buffer_drops_large_backing_even_when_split_to_leaves_zero_capacity() {
        // Exact-size split_to leaves `buffer.capacity() == 0` while still pinning the backing
        // allocation via `BytesMut`'s `Shared` Arc; tracking peak size guarantees it is released.
        let mut buf = BytesMut::with_capacity(256 * 1024);
        buf.resize(256 * 1024, 0xAB);
        let mut peak = buf.len().max(buf.capacity());
        let frame = buf.split_to(256 * 1024);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 0);
        drop(frame);

        release_excess_s2s_buffer(&mut buf, &mut peak);
        assert_eq!(peak, 0);
        assert_eq!(buf.capacity(), 0);
        // Appending 1 byte after release allocates a small buffer, NOT the reclaimed 256 KiB one!
        buf.extend_from_slice(&[1]);
        assert!(
            buf.capacity() <= S2S_READ_BUFFER_MAX_IDLE_CAPACITY,
            "expected small buffer after release, got capacity {}",
            buf.capacity()
        );

        // Small buffers within the idle threshold stay reusable without resetting.
        let mut small = BytesMut::with_capacity(1024);
        small.resize(512, 0xCD);
        let mut small_peak = small.len().max(small.capacity());
        let _ = small.split_to(512);
        release_excess_s2s_buffer(&mut small, &mut small_peak);
        assert!(small.capacity() >= 512);
    }
}
