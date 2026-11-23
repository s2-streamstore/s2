use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    io::{Read as _, Write as _},
    pin::pin,
    sync::{
        Arc, Mutex, OnceLock, RwLock as StdRwLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use flate2::{Compression as FlateCompression, read::MultiGzDecoder, write::GzEncoder};
use futures_core::Stream;
use futures_util::StreamExt;
use http::{
    HeaderMap, Method, StatusCode, Uri,
    header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderName, HeaderValue},
};
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    body::{Frame, Incoming},
    client::conn::http2,
    rt::{Read as HyperRead, Write as HyperWrite},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::connect::HttpConnector,
    rt::{TokioExecutor, TokioTimer},
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    sync::{Notify, watch},
    time::{Instant, timeout, timeout_at},
};
pub(crate) use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use tower_service::Service;

use crate::{
    frame_signal::{FrameSignal, RequestFrameMonitorBody},
    types::{Compression, Http2Config},
};

const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");
const DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CONNECTION: usize = 50;
const DEFAULT_STREAM_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
const DEFAULT_CONNECTION_RECEIVE_WINDOW: u32 = 32 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(20);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ERROR_RESPONSE_BYTES: usize = 1024 * 1024;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = UnsyncBoxBody<Bytes, BoxError>;

pub(crate) fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cur) = source {
        let part = cur.to_string();
        if !part.is_empty() && !out.contains(&part) {
            out.push_str(": ");
            out.push_str(&part);
        }
        source = cur.source();
    }
    out
}

/// Connector bound for establishing raw HTTP/2 transports (TCP, TLS, or simulated streams).
pub(crate) trait Connect:
    Service<Uri, Response = Self::Io, Error = Self::Err, Future = Self::Fut>
    + Clone
    + Send
    + Sync
    + 'static
{
    type Io: HyperRead + HyperWrite + Unpin + Send + 'static;
    type Err: Into<BoxError>;
    type Fut: Future<Output = Result<Self::Io, Self::Err>> + Send + 'static;
}

impl<C> Connect for C
where
    C: Service<Uri> + Clone + Send + Sync + 'static,
    C::Response: HyperRead + HyperWrite + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Send + 'static,
{
    type Io = C::Response;
    type Err = C::Error;
    type Fut = C::Future;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpError {
    #[error("connect error: {0}")]
    Connect(String),
    #[error("transport error: {0}")]
    Transport(#[from] hyper::Error),
    #[error("request build error: {0}")]
    RequestBuild(String),
    #[error("response decode error: {0}")]
    ResponseDecode(#[source] serde_json::Error),
    #[error("timeout")]
    Timeout,
    #[error("client closed")]
    Closed,
    #[error("request compression error: {0}")]
    RequestCompression(String),
    #[error("response compression error: {0}")]
    ResponseCompression(String),
    #[error("response exceeded {0} byte limit")]
    ResponseTooLarge(usize),
}

enum BodyInner {
    Empty,
    Full(Bytes),
    Streaming(BoxBody),
}

pub(crate) struct Body(BodyInner);

impl Body {
    fn empty() -> Self {
        Self(BodyInner::Empty)
    }

    pub(crate) fn wrap_stream<S, E>(stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, E>> + Send + 'static,
        E: Into<BoxError> + 'static,
    {
        let stream_body = StreamBody::new(stream.map(|r| r.map(Frame::data).map_err(Into::into)));
        Self(BodyInner::Streaming(BoxBody::new(stream_body)))
    }

    pub(crate) fn monitored(self, signal: FrameSignal) -> Self {
        let boxed = match self.0 {
            BodyInner::Empty => {
                debug_assert!(
                    false,
                    "monitored body should be non-empty so FrameSignal can observe frames"
                );
                BoxBody::new(RequestFrameMonitorBody::new(
                    Empty::new().map_err(|e: Infallible| match e {}),
                    signal,
                ))
            }
            BodyInner::Full(bytes) => BoxBody::new(RequestFrameMonitorBody::new(
                Full::new(bytes).map_err(|e: Infallible| match e {}),
                signal,
            )),
            BodyInner::Streaming(stream) => {
                BoxBody::new(RequestFrameMonitorBody::new(stream, signal))
            }
        };
        Self(BodyInner::Streaming(boxed))
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        match &self.0 {
            BodyInner::Empty => Some(&[]),
            BodyInner::Full(bytes) => Some(bytes),
            BodyInner::Streaming(_) => None,
        }
    }

    fn into_http_body(self) -> BoxBody {
        match self.0 {
            BodyInner::Empty => BoxBody::new(Empty::new().map_err(|e: Infallible| match e {})),
            BodyInner::Full(bytes) => {
                BoxBody::new(Full::new(bytes).map_err(|e: Infallible| match e {}))
            }
            BodyInner::Streaming(stream) => stream,
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<u8>> for Body {
    fn from(data: Vec<u8>) -> Self {
        Self(BodyInner::Full(Bytes::from(data)))
    }
}

pub(crate) struct Request {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
    timeout: Option<Duration>,
    compression: Compression,
}

impl Request {
    pub(crate) fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub(crate) fn with_monitored_body(self, signal: FrameSignal) -> Self {
        Self {
            body: self.body.monitored(signal),
            ..self
        }
    }

    pub(crate) fn compress(self) -> Result<Self, HttpError> {
        let (body, content_encoding) = compress_body(self.body, self.compression)?;
        let mut headers = self.headers;
        if let Some(encoding) = content_encoding {
            headers.insert(CONTENT_ENCODING, encoding);
        }
        Ok(Self {
            body,
            headers,
            compression: Compression::None,
            ..self
        })
    }

    pub(crate) fn origin(&self) -> String {
        let scheme = self
            .uri
            .scheme_str()
            .unwrap_or("https")
            .to_ascii_lowercase();
        let host = self.uri.host().unwrap_or("").to_ascii_lowercase();
        let port = self
            .uri
            .port_u16()
            .filter(|&p| !((scheme == "http" && p == 80) || (scheme == "https" && p == 443)));
        match port {
            Some(port) => format!("{scheme}://{host}:{port}"),
            None => format!("{scheme}://{host}"),
        }
    }

    pub(crate) fn try_clone(&self) -> Option<Self> {
        let body = match &self.body.0 {
            BodyInner::Empty => Body::empty(),
            BodyInner::Full(bytes) => Body(BodyInner::Full(bytes.clone())),
            BodyInner::Streaming(_) => return None,
        };

        Some(Self {
            method: self.method.clone(),
            uri: self.uri.clone(),
            headers: self.headers.clone(),
            body,
            timeout: self.timeout,
            compression: self.compression,
        })
    }
}

pub(crate) struct RequestBuilder {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Option<Body>,
    timeout: Option<Duration>,
    compression: Compression,
    error: Option<HttpError>,
}

impl RequestBuilder {
    pub(crate) fn new(method: Method, uri: Uri) -> Self {
        Self {
            method,
            uri,
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
            compression: Compression::None,
            error: None,
        }
    }

    pub(crate) fn get(uri: Uri) -> Self {
        Self::new(Method::GET, uri)
    }

    pub(crate) fn post(uri: Uri) -> Self {
        Self::new(Method::POST, uri)
    }

    pub(crate) fn patch(uri: Uri) -> Self {
        Self::new(Method::PATCH, uri)
    }

    pub(crate) fn put(uri: Uri) -> Self {
        Self::new(Method::PUT, uri)
    }

    pub(crate) fn delete(uri: Uri) -> Self {
        Self::new(Method::DELETE, uri)
    }

    pub(crate) fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Self {
        if self.error.is_some() {
            return self;
        }

        match serde_urlencoded::to_string(query) {
            Ok(query_string) => {
                if !query_string.is_empty() {
                    self.uri = match uri_with_query(&self.uri, &query_string) {
                        Ok(uri) => uri,
                        Err(e) => {
                            self.error = Some(HttpError::RequestBuild(e.to_string()));
                            return self;
                        }
                    };
                }
            }
            Err(e) => self.error = Some(HttpError::RequestBuild(e.to_string())),
        }
        self
    }

    pub(crate) fn json<T: Serialize + ?Sized>(mut self, json: &T) -> Self {
        if self.error.is_some() {
            return self;
        }

        match serde_json::to_vec(json) {
            Ok(data) => {
                self.headers.insert(CONTENT_TYPE, APPLICATION_JSON);
                self.body = Some(Body::from(data));
            }
            Err(e) => self.error = Some(HttpError::RequestBuild(e.to_string())),
        }
        self
    }

    pub(crate) fn body<B: Into<Body>>(mut self, body: B) -> Self {
        self.body = Some(body.into());
        self
    }

    pub(crate) fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        K::Error: Into<http::Error>,
        V: TryInto<HeaderValue>,
        V::Error: Into<http::Error>,
    {
        if self.error.is_some() {
            return self;
        }
        match (key.try_into(), value.try_into()) {
            (Ok(name), Ok(value)) => {
                self.headers.insert(name, value);
            }
            (Err(e), _) => self.error = Some(HttpError::RequestBuild(e.into().to_string())),
            (_, Err(e)) => self.error = Some(HttpError::RequestBuild(e.into().to_string())),
        }
        self
    }

    pub(crate) fn headers(mut self, headers: &HeaderMap) -> Self {
        if self.headers.is_empty() {
            self.headers = headers.clone();
        } else {
            // An owned HeaderMap replaces each key's existing values while preserving duplicates.
            self.headers.extend(headers.clone());
        }
        self
    }

    pub(crate) fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub(crate) fn compression(mut self, compression: Compression) -> Self {
        self.compression = compression;
        self
    }

    pub(crate) fn build(self) -> Result<Request, HttpError> {
        if let Some(e) = self.error {
            return Err(e);
        }

        Ok(Request {
            method: self.method,
            uri: self.uri,
            headers: self.headers,
            body: self.body.unwrap_or_default(),
            timeout: self.timeout,
            compression: self.compression,
        })
    }
}

pub(crate) struct UnaryResponse {
    status: StatusCode,
    headers: HeaderMap,
    bytes: Bytes,
    poison_handle: Option<PoisonHandle>,
}

impl UnaryResponse {
    #[cfg(all(test, feature = "_hidden"))]
    pub(crate) fn new_for_test(status: StatusCode, bytes: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            bytes: bytes.into(),
            poison_handle: None,
        }
    }

    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub(crate) fn take_poison_handle(&mut self) -> Option<PoisonHandle> {
        self.poison_handle.take()
    }

    pub(crate) fn into_bytes(self) -> Bytes {
        self.bytes
    }

    pub(crate) fn json<T: DeserializeOwned>(self) -> Result<T, HttpError> {
        serde_json::from_slice(&self.bytes).map_err(HttpError::ResponseDecode)
    }
}

/// Identifies a pooled HTTP/2 connection within its origin pool, so retiring or
/// evicting it drops only that TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionId(u64);

impl ConnectionId {
    fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

trait PoisonTarget: Send + Sync {
    fn poison(&self, id: ConnectionId);
}

/// Grants its holder the ability to retire the pooled HTTP/2 connection a response
/// arrived on so no new request reuses it while in-flight requests finish (`T6`, `C13`).
///
/// Poisoning is idempotent and allocates nothing per request.
#[derive(Clone)]
pub(crate) struct PoisonHandle {
    target: Weak<dyn PoisonTarget>,
    id: ConnectionId,
}

impl PoisonHandle {
    fn new(target: Weak<dyn PoisonTarget>, id: ConnectionId) -> Self {
        Self { target, id }
    }

    pub(crate) fn poison(&self) {
        if let Some(target) = self.target.upgrade() {
            target.poison(self.id);
        }
    }
}

fn is_dead_connection_hyper_error(err: &hyper::Error) -> bool {
    if err.is_timeout() || err.is_closed() {
        return true;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(cur) = source {
        if let Some(h2_err) = cur.downcast_ref::<h2::Error>() {
            return h2_err.is_io() || h2_err.is_go_away();
        }
        source = cur.source();
    }
    false
}

pub(crate) struct StreamingResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Incoming,
    permit: RequestPermit,
    poison_handle: PoisonHandle,
    deadline: Option<Instant>,
}

impl StreamingResponse {
    fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Incoming,
        permit: RequestPermit,
        poison_handle: PoisonHandle,
        deadline: Option<Instant>,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            permit,
            poison_handle,
            deadline,
        }
    }

    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    /// Collect the body of a non-2xx streaming response (`E2`).
    ///
    /// Once non-2xx headers have arrived, a timeout or body read/decompression failure poisons
    /// the connection/stream and falls back to empty bytes so
    /// [`ServerError`](crate::error::ServerError) preserves the HTTP status instead of turning e.g.
    /// `404` or `412` into a retryable timeout.
    pub(crate) async fn into_bytes_with_poison_handle(self) -> (Bytes, PoisonHandle) {
        let Self {
            status,
            headers,
            body,
            permit,
            poison_handle,
            deadline,
        } = self;
        let bytes =
            collect_and_decompress_error_body(status, &headers, body, deadline, &poison_handle)
                .await;
        drop(permit);
        (bytes, poison_handle)
    }

    pub(crate) fn into_stream(
        self,
    ) -> (impl Stream<Item = Result<Bytes, HttpError>>, PoisonHandle) {
        let Self {
            body,
            permit,
            poison_handle,
            ..
        } = self;
        let stream_poison = poison_handle.clone();
        let stream = http_body_util::BodyStream::new(body).filter_map(move |result| {
            let _ = &permit;
            std::future::ready(match result {
                Ok(frame) => frame.into_data().ok().map(Ok),
                Err(e) => {
                    if is_dead_connection_hyper_error(&e) {
                        stream_poison.poison();
                    }
                    Some(Err(HttpError::Transport(e)))
                }
            })
        });
        (stream, poison_handle)
    }
}

enum CollectBodyError<E> {
    Timeout,
    TooLarge,
    Transport(E),
}

async fn collect_bounded_body<B>(
    mut body: B,
    limit: usize,
    deadline: Option<Instant>,
) -> Result<Bytes, CollectBodyError<B::Error>>
where
    B: http_body::Body<Data = Bytes> + Unpin,
{
    if body.size_hint().lower() > limit as u64 {
        return Err(CollectBodyError::TooLarge);
    }

    let collect = async {
        let mut first: Option<Bytes> = None;
        let mut buf: Option<BytesMut> = None;
        let mut total: usize = 0;

        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(CollectBodyError::Transport)?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            if data.len() > limit - total {
                return Err(CollectBodyError::TooLarge);
            }
            total += data.len();
            if let Some(buf) = buf.as_mut() {
                buf.extend_from_slice(&data);
            } else if let Some(prev) = first.take() {
                let mut combined = BytesMut::with_capacity(total);
                combined.extend_from_slice(&prev);
                combined.extend_from_slice(&data);
                buf = Some(combined);
            } else {
                first = Some(data);
            }
        }

        Ok(match buf {
            Some(buf) => buf.freeze(),
            None => first.unwrap_or_default(),
        })
    };

    match deadline {
        Some(dl) => timeout_at(dl, collect)
            .await
            .unwrap_or(Err(CollectBodyError::Timeout)),
        None => collect.await,
    }
}

async fn collect_and_decompress_error_body(
    status: StatusCode,
    headers: &HeaderMap,
    body: Incoming,
    deadline: Option<Instant>,
    poison_handle: &PoisonHandle,
) -> Bytes {
    let bytes = match collect_bounded_body(body, MAX_ERROR_RESPONSE_BYTES, deadline).await {
        Ok(bytes) => bytes,
        Err(CollectBodyError::Timeout) => {
            // Dropping `body` resets the HTTP/2 stream; retiring the connection prevents
            // reusing a stalled peer while preserving the already-received HTTP status.
            tracing::debug!(
                status = status.as_u16(),
                "timed out reading non-2xx error body; preserving HTTP status"
            );
            poison_handle.poison();
            return Bytes::new();
        }
        Err(CollectBodyError::TooLarge) => {
            tracing::debug!(
                status = status.as_u16(),
                limit = MAX_ERROR_RESPONSE_BYTES,
                "non-2xx error body exceeded size limit; preserving HTTP status"
            );
            return Bytes::new();
        }
        Err(CollectBodyError::Transport(err)) => {
            tracing::debug!(
                status = status.as_u16(),
                error = %format_error_chain(&err),
                "failed reading non-2xx error body; preserving HTTP status"
            );
            if is_dead_connection_hyper_error(&err) {
                poison_handle.poison();
            }
            return Bytes::new();
        }
    };
    match decompress_body(headers, bytes, MAX_ERROR_RESPONSE_BYTES) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::debug!(
                status = status.as_u16(),
                %err,
                "failed decompressing non-2xx error body; preserving HTTP status"
            );
            Bytes::new()
        }
    }
}

#[async_trait]
pub(crate) trait RequestExecutor: Send + Sync {
    async fn execute_unary(&self, request: Request) -> Result<UnaryResponse, HttpError>;
    async fn init_streaming(&self, request: Request) -> Result<StreamingResponse, HttpError>;
    fn close(&self) {}
}

pub(crate) fn default_http_connector(connect_timeout: Option<Duration>) -> HttpConnector {
    let mut connector = HttpConnector::new();
    connector.enforce_http(true);
    connector.set_nodelay(true);
    if let Some(timeout) = connect_timeout {
        connector.set_connect_timeout(Some(timeout));
    }
    connector
}

pub(crate) fn default_connector(
    connect_timeout: Option<Duration>,
    insecure_skip_cert_verification: bool,
    rustls_crypto_provider: Option<Arc<rustls::crypto::CryptoProvider>>,
) -> Result<HttpsConnector<HttpConnector>, std::io::Error> {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    connector.set_nodelay(true);
    if let Some(timeout) = connect_timeout {
        connector.set_connect_timeout(Some(timeout));
    }
    let rustls_crypto_provider = resolve_rustls_crypto_provider(rustls_crypto_provider)?;

    if insecure_skip_cert_verification {
        let builder = HttpsConnectorBuilder::new().with_tls_config(
            rustls::ClientConfig::builder_with_provider(rustls_crypto_provider.clone())
                .with_safe_default_protocol_versions()
                .map_err(std::io::Error::other)?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier {
                    rustls_crypto_provider,
                }))
                .with_no_client_auth(),
        );
        return Ok(builder
            .https_or_http()
            .enable_http2()
            .wrap_connector(connector));
    }

    build_https_connector_with_roots(rustls_crypto_provider, connector)
}

fn build_https_connector_with_roots(
    rustls_crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    connector: HttpConnector,
) -> Result<HttpsConnector<HttpConnector>, std::io::Error> {
    #[cfg(all(feature = "rustls-native-roots", feature = "rustls-webpki-roots"))]
    let builder = match HttpsConnectorBuilder::new()
        .with_provider_and_native_roots(rustls_crypto_provider.clone())
    {
        Ok(builder) => builder,
        Err(native_err) => {
            tracing::debug!(
                error = %native_err,
                "native root certificates unavailable; falling back to webpki-roots"
            );
            HttpsConnectorBuilder::new()
                .with_provider_and_webpki_roots(rustls_crypto_provider)
                .map_err(std::io::Error::other)?
        }
    };

    #[cfg(all(feature = "rustls-native-roots", not(feature = "rustls-webpki-roots")))]
    let builder =
        HttpsConnectorBuilder::new().with_provider_and_native_roots(rustls_crypto_provider)?;

    #[cfg(all(not(feature = "rustls-native-roots"), feature = "rustls-webpki-roots"))]
    let builder = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(rustls_crypto_provider)
        .map_err(std::io::Error::other)?;

    #[cfg(all(
        not(feature = "rustls-native-roots"),
        not(feature = "rustls-webpki-roots")
    ))]
    {
        let _ = (rustls_crypto_provider, connector);
        Err(std::io::Error::other(
            "no TLS root certificates configured; enable the `rustls-native-roots` or \
             `rustls-webpki-roots` feature on `s2-sdk`",
        ))
    }

    #[cfg(any(feature = "rustls-native-roots", feature = "rustls-webpki-roots"))]
    Ok(builder
        .https_or_http()
        .enable_http2()
        .wrap_connector(connector))
}

fn resolve_rustls_crypto_provider(
    provider: Option<Arc<rustls::crypto::CryptoProvider>>,
) -> Result<Arc<rustls::crypto::CryptoProvider>, std::io::Error> {
    provider
        .or_else(|| rustls::crypto::CryptoProvider::get_default().cloned())
        .ok_or_else(|| {
            std::io::Error::other(
                "no rustls crypto provider configured; configure \
                 S2Config::with_rustls_crypto_provider(...) or install a \
                 process-global provider with \
                 rustls::crypto::CryptoProvider::install_default()",
            )
        })
}

#[derive(Debug)]
struct NoVerifier {
    rustls_crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.rustls_crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_http_request(
    method: Method,
    uri: &Uri,
    headers: HeaderMap,
    body: BoxBody,
) -> Result<http::Request<BoxBody>, HttpError> {
    let mut builder = http::Request::builder().method(method).uri(uri.clone());

    if let Some(req_headers) = builder.headers_mut() {
        *req_headers = headers;
    }

    builder
        .body(body)
        .map_err(|error| HttpError::RequestBuild(error.to_string()))
}

/// Builds a URI from `base`'s scheme and authority, replacing any path/query.
pub(crate) fn uri_with_path(base: &Uri, path: impl AsRef<str>) -> Uri {
    let path = path.as_ref().trim_start_matches('/');
    uri_with_path_and_query(base, &format!("/{path}")).expect("SDK-generated path is a valid URI")
}

fn uri_with_query(uri: &Uri, query: &str) -> Result<Uri, http::uri::InvalidUri> {
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let (path, existing_query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(path, query)| (path, query));
    let path_and_query = if existing_query.is_empty() {
        format!("{path}?{query}")
    } else {
        format!("{path}?{existing_query}&{query}")
    };
    uri_with_path_and_query(uri, &path_and_query)
}

fn uri_with_path_and_query(uri: &Uri, path_and_query: &str) -> Result<Uri, http::uri::InvalidUri> {
    let scheme = uri.scheme_str().unwrap_or("https");
    let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
    format!("{scheme}://{authority}{path_and_query}").parse()
}

fn compress_body(
    body: Body,
    compression: Compression,
) -> Result<(Body, Option<HeaderValue>), HttpError> {
    if matches!(body.0, BodyInner::Empty) || matches!(compression, Compression::None) {
        return Ok((body, None));
    }
    let Some(data) = body.as_bytes() else {
        return Err(HttpError::RequestCompression(
            "streaming request bodies cannot be compressed".into(),
        ));
    };
    match compression {
        Compression::None => unreachable!(),
        Compression::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), FlateCompression::fast());
            encoder
                .write_all(data)
                .map_err(|e| HttpError::RequestCompression(e.to_string()))?;
            let compressed = encoder
                .finish()
                .map_err(|e| HttpError::RequestCompression(e.to_string()))?;
            Ok((
                Body::from(compressed),
                Some(HeaderValue::from_static("gzip")),
            ))
        }
        Compression::Zstd => {
            let compressed = zstd::stream::encode_all(data, 1)
                .map_err(|e| HttpError::RequestCompression(e.to_string()))?;
            Ok((
                Body::from(compressed),
                Some(HeaderValue::from_static("zstd")),
            ))
        }
    }
}

fn read_bounded(reader: impl std::io::Read, max_bytes: usize) -> Result<Bytes, HttpError> {
    let limit = (max_bytes as u64) + 1;
    let mut decompressed = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut decompressed)
        .map_err(|e| HttpError::ResponseCompression(e.to_string()))?;
    if decompressed.len() > max_bytes {
        return Err(HttpError::ResponseTooLarge(max_bytes));
    }
    Ok(Bytes::from(decompressed))
}

fn decompress_single(encoding: &str, bytes: Bytes, max_bytes: usize) -> Result<Bytes, HttpError> {
    match encoding {
        "" | "identity" => Ok(bytes),
        "gzip" => read_bounded(MultiGzDecoder::new(bytes.as_ref()), max_bytes),
        "zstd" => {
            let decoder = zstd::stream::Decoder::new(bytes.as_ref())
                .map_err(|e| HttpError::ResponseCompression(e.to_string()))?;
            read_bounded(decoder, max_bytes)
        }
        other => Err(HttpError::ResponseCompression(format!(
            "unsupported content-encoding: {other}"
        ))),
    }
}

fn decompress_body(
    headers: &HeaderMap,
    mut bytes: Bytes,
    max_bytes: usize,
) -> Result<Bytes, HttpError> {
    let mut encodings = Vec::new();
    for raw in headers.get_all(CONTENT_ENCODING) {
        let s = raw.to_str().map_err(|e| {
            HttpError::ResponseCompression(format!("invalid content-encoding: {e}"))
        })?;
        for part in s.split(',') {
            let token = part.trim().to_ascii_lowercase();
            if !token.is_empty() && token != "identity" {
                encodings.push(token);
            }
        }
    }
    for encoding in encodings.into_iter().rev() {
        bytes = decompress_single(&encoding, bytes, max_bytes)?;
    }
    Ok(bytes)
}

struct PermitState {
    active_requests: usize,
    idle_since: Option<Instant>,
}

struct RequestPermit {
    state: Arc<Mutex<PermitState>>,
    reaper_notify: Arc<Notify>,
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        let became_idle = {
            let mut state = self.state.lock().unwrap();
            state.active_requests = state.active_requests.saturating_sub(1);
            if state.active_requests == 0 {
                state.idle_since = Some(Instant::now());
                true
            } else {
                false
            }
        };
        if became_idle {
            self.reaper_notify.notify_one();
        }
    }
}

#[derive(Clone)]
enum DialOutcome {
    Pending,
    Ready(http2::SendRequest<BoxBody>),
    Failed(Arc<String>),
    Aborted,
}

enum DialError {
    Connect(String),
    Aborted,
}

enum ConnectionState {
    Connecting(watch::Receiver<DialOutcome>),
    Ready(http2::SendRequest<BoxBody>),
}

struct PooledConnection {
    id: ConnectionId,
    max_concurrent_requests: usize,
    state: Arc<Mutex<PermitState>>,
    reaper_notify: Arc<Notify>,
    conn: ConnectionState,
}

impl PooledConnection {
    fn new_connecting(
        id: ConnectionId,
        max_concurrent_requests: usize,
        rx: watch::Receiver<DialOutcome>,
        reaper_notify: Arc<Notify>,
    ) -> (Self, RequestPermit) {
        let state = Arc::new(Mutex::new(PermitState {
            active_requests: 1,
            idle_since: None,
        }));
        let permit = RequestPermit {
            state: state.clone(),
            reaper_notify: reaper_notify.clone(),
        };
        (
            Self {
                id,
                max_concurrent_requests,
                state,
                reaper_notify,
                conn: ConnectionState::Connecting(rx),
            },
            permit,
        )
    }

    fn is_live(&self) -> bool {
        match &self.conn {
            ConnectionState::Ready(sender) => !sender.is_closed(),
            ConnectionState::Connecting(rx) => match &*rx.borrow() {
                DialOutcome::Pending => true,
                DialOutcome::Ready(sender) => !sender.is_closed(),
                DialOutcome::Failed(_) | DialOutcome::Aborted => false,
            },
        }
    }

    fn try_acquire_permit(&self) -> Option<RequestPermit> {
        let mut state = self.state.lock().unwrap();
        if state.active_requests >= self.max_concurrent_requests {
            return None;
        }
        state.active_requests += 1;
        state.idle_since = None;
        Some(RequestPermit {
            state: self.state.clone(),
            reaper_notify: self.reaper_notify.clone(),
        })
    }

    fn idle_deadline(&self, idle_timeout: Duration) -> Option<Instant> {
        let state = self.state.lock().unwrap();
        if state.active_requests == 0 {
            state.idle_since.map(|since| since + idle_timeout)
        } else {
            None
        }
    }
}

enum Checkout {
    Ready {
        id: ConnectionId,
        sender: http2::SendRequest<BoxBody>,
        permit: RequestPermit,
    },
    Connecting {
        id: ConnectionId,
        rx: watch::Receiver<DialOutcome>,
        permit: RequestPermit,
    },
}

struct CheckedOutSender {
    sender: http2::SendRequest<BoxBody>,
    permit: RequestPermit,
    poison_handle: PoisonHandle,
    deadline: Option<Instant>,
}

struct HostPoolState {
    connections: Vec<PooledConnection>,
    detached: bool,
}

struct HostPool<C> {
    origin: String,
    origin_uri: Uri,
    connection_timeout: Duration,
    http2: Http2Config,
    state: StdRwLock<HostPoolState>,
    connector: C,
    shutdown: CancellationToken,
    reaper_notify: Arc<Notify>,
}

impl<C> PoisonTarget for HostPool<C>
where
    C: Send + Sync,
{
    fn poison(&self, id: ConnectionId) {
        let removed = {
            let mut state = self.state.write().unwrap();
            let before = state.connections.len();
            state.connections.retain(|conn| conn.id != id);
            before - state.connections.len()
        };
        if removed > 0 {
            tracing::debug!(
                origin = %self.origin,
                connection = ?id,
                "retired pooled connection"
            );
        }
    }
}

impl<C> HostPool<C>
where
    C: Connect,
{
    fn new(
        origin: String,
        origin_uri: Uri,
        connector: C,
        connection_timeout: Duration,
        http2: Http2Config,
        shutdown: CancellationToken,
        reaper_notify: Arc<Notify>,
    ) -> Self {
        Self {
            origin,
            origin_uri,
            connection_timeout,
            http2,
            state: StdRwLock::new(HostPoolState {
                connections: Vec::new(),
                detached: false,
            }),
            connector,
            shutdown,
            reaper_notify,
        }
    }

    fn max_concurrent_requests(&self) -> usize {
        self.http2
            .max_concurrent_requests
            .unwrap_or(DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CONNECTION)
    }

    fn try_checkout_existing(connections: &[PooledConnection]) -> Option<Checkout> {
        for pooled in connections {
            if !pooled.is_live() {
                continue;
            }
            if let Some(permit) = pooled.try_acquire_permit() {
                return Some(match &pooled.conn {
                    ConnectionState::Ready(sender) => Checkout::Ready {
                        id: pooled.id,
                        sender: sender.clone(),
                        permit,
                    },
                    ConnectionState::Connecting(rx) => match &*rx.borrow() {
                        DialOutcome::Ready(sender) => Checkout::Ready {
                            id: pooled.id,
                            sender: sender.clone(),
                            permit,
                        },
                        _ => Checkout::Connecting {
                            id: pooled.id,
                            rx: rx.clone(),
                            permit,
                        },
                    },
                });
            }
        }
        None
    }

    fn checkout(self: &Arc<Self>) -> Option<Checkout> {
        {
            let state = self.state.read().unwrap();
            if state.detached {
                return None;
            }
            if let Some(checkout) = Self::try_checkout_existing(&state.connections) {
                return Some(checkout);
            }
        }

        let mut state = self.state.write().unwrap();
        if state.detached {
            return None;
        }
        // Evict closed/failed connections before checking capacity or dialing.
        state.connections.retain(PooledConnection::is_live);
        if let Some(checkout) = Self::try_checkout_existing(&state.connections) {
            return Some(checkout);
        }

        let id = ConnectionId::next();
        let (tx, rx) = watch::channel(DialOutcome::Pending);
        let (pooled, permit) = PooledConnection::new_connecting(
            id,
            self.max_concurrent_requests(),
            rx.clone(),
            self.reaper_notify.clone(),
        );
        state.connections.push(pooled);
        drop(state);

        self.spawn_connection(id, tx);

        Some(Checkout::Connecting { id, rx, permit })
    }

    fn spawn_connection(self: &Arc<Self>, id: ConnectionId, tx: watch::Sender<DialOutcome>) {
        let weak_pool = Arc::downgrade(self);
        let connector = self.connector.clone();
        let origin = self.origin.clone();
        let origin_uri = self.origin_uri.clone();
        let connection_timeout = self.connection_timeout;
        let http2 = self.http2;
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let (sender, conn) = match dial_http2(
                connector,
                origin_uri,
                connection_timeout,
                http2,
                shutdown.clone(),
            )
            .await
            {
                Ok(pair) => pair,
                Err(DialError::Aborted) => {
                    let _ = tx.send(DialOutcome::Aborted);
                    if let Some(pool) = weak_pool.upgrade() {
                        pool.remove(id);
                    }
                    return;
                }
                Err(DialError::Connect(msg)) => {
                    tracing::debug!(
                        origin = %origin,
                        connection = ?id,
                        error = %msg,
                        "HTTP/2 dial failed"
                    );
                    let _ = tx.send(DialOutcome::Failed(Arc::new(msg)));
                    if let Some(pool) = weak_pool.upgrade() {
                        pool.remove(id);
                    }
                    return;
                }
            };

            if let Some(pool) = weak_pool.upgrade() {
                pool.promote_ready(id, sender.clone());
            }
            let _ = tx.send(DialOutcome::Ready(sender));
            // Drop the watch sender immediately so its stored `SendRequest` is released once
            // waiting callers finish dialing; otherwise `conn` stays open after idle reaping
            // or connection retirement.
            drop(tx);

            // Drive the HTTP/2 connection until all handles close, an error occurs, or
            // client shutdown fires (`C12`, dropping `conn` and its socket immediately).
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {}
                res = conn => {
                    if let Err(err) = res {
                        tracing::debug!(
                            origin = %origin,
                            connection = ?id,
                            error = %format_error_chain(&err),
                            "HTTP/2 connection closed"
                        );
                    }
                }
            }

            if let Some(pool) = weak_pool.upgrade() {
                pool.remove(id);
            }
        });
    }

    fn promote_ready(&self, id: ConnectionId, sender: http2::SendRequest<BoxBody>) {
        let mut state = self.state.write().unwrap();
        if let Some(entry) = state.connections.iter_mut().find(|c| c.id == id) {
            entry.conn = ConnectionState::Ready(sender);
        }
    }

    fn remove(&self, id: ConnectionId) {
        let mut state = self.state.write().unwrap();
        state.connections.retain(|c| c.id != id);
    }

    fn clear_and_detach(&self) {
        let mut state = self.state.write().unwrap();
        state.connections.clear();
        state.detached = true;
    }

    /// Reap connections idle for at least `idle_timeout` and return the earliest
    /// future deadline among remaining idle connections (`C13c`).
    fn reap_idle(&self, now: Instant, idle_timeout: Duration) -> Option<Instant> {
        let mut state = self.state.write().unwrap();
        let before = state.connections.len();
        let mut next_deadline: Option<Instant> = None;
        state.connections.retain(|conn| {
            if !conn.is_live() {
                return false;
            }
            if let Some(deadline) = conn.idle_deadline(idle_timeout) {
                if deadline <= now {
                    return false;
                }
                next_deadline = Some(match next_deadline {
                    Some(earliest) => earliest.min(deadline),
                    None => deadline,
                });
            }
            true
        });
        let reaped = before - state.connections.len();
        if reaped > 0 {
            tracing::debug!(
                origin = %self.origin,
                reaped,
                remaining = state.connections.len(),
                "reaped idle HTTP/2 connections"
            );
        }
        next_deadline
    }

    /// Atomically detach this host pool if it currently has no pooled connections.
    fn detach_if_empty(&self) -> bool {
        let Ok(mut state) = self.state.try_write() else {
            return false;
        };
        if state.connections.is_empty() {
            state.detached = true;
            true
        } else {
            false
        }
    }
}

async fn dial_http2<C: Connect>(
    mut connector: C,
    origin_uri: Uri,
    connection_timeout: Duration,
    http2_config: Http2Config,
    shutdown: CancellationToken,
) -> Result<
    (
        http2::SendRequest<BoxBody>,
        http2::Connection<C::Io, BoxBody, TokioExecutor>,
    ),
    DialError,
> {
    let dial = async {
        futures_util::future::poll_fn(|cx| connector.poll_ready(cx))
            .await
            .map_err(|e| format_error_chain(e.into().as_ref()))?;
        let io = connector
            .call(origin_uri)
            .await
            .map_err(|e| format_error_chain(e.into().as_ref()))?;
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .keep_alive_interval(KEEP_ALIVE_INTERVAL)
            .keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
            .initial_stream_window_size(
                http2_config
                    .stream_receive_window
                    .unwrap_or(DEFAULT_STREAM_RECEIVE_WINDOW),
            )
            .initial_connection_window_size(
                http2_config
                    .connection_receive_window
                    .unwrap_or(DEFAULT_CONNECTION_RECEIVE_WINDOW),
            );
        builder
            .handshake(io)
            .await
            .map_err(|e| format_error_chain(&e))
    };

    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err(DialError::Aborted),
        res = timeout(connection_timeout, dial) => match res {
            Ok(Ok(pair)) => Ok(pair),
            Ok(Err(msg)) => Err(DialError::Connect(msg)),
            Err(_) => Err(DialError::Connect("connection timed out".to_owned())),
        },
    }
}

async fn wait_for_dial(
    rx: &mut watch::Receiver<DialOutcome>,
    shutdown: &CancellationToken,
) -> Result<http2::SendRequest<BoxBody>, HttpError> {
    loop {
        match &*rx.borrow_and_update() {
            DialOutcome::Pending => {}
            DialOutcome::Ready(sender) => return Ok(sender.clone()),
            DialOutcome::Failed(msg) => return Err(HttpError::Connect((**msg).clone())),
            DialOutcome::Aborted => return Err(HttpError::Closed),
        }
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Err(HttpError::Closed),
            changed = rx.changed() => {
                if changed.is_err() {
                    return match &*rx.borrow_and_update() {
                        DialOutcome::Ready(sender) => Ok(sender.clone()),
                        DialOutcome::Failed(msg) => Err(HttpError::Connect((**msg).clone())),
                        DialOutcome::Aborted => Err(HttpError::Closed),
                        DialOutcome::Pending => Err(HttpError::Connect("dial task ended".to_owned())),
                    };
                }
            }
        }
    }
}

struct PoolHosts<C> {
    closed: bool,
    map: HashMap<String, Arc<HostPool<C>>>,
}

pub(crate) struct Pool<C> {
    connection_timeout: Duration,
    http2: Http2Config,
    hosts: Arc<StdRwLock<PoolHosts<C>>>,
    connector: C,
    shutdown: CancellationToken,
    reaper_notify: Arc<Notify>,
    reaper: OnceLock<AbortOnDropHandle<()>>,
}

impl<C> Drop for Pool<C> {
    fn drop(&mut self) {
        // Cancel any in-flight dials or live connection tasks if the last client/handle is
        // dropped without calling `S2::close()`.
        self.shutdown.cancel();
    }
}

impl<C> Pool<C>
where
    C: Connect,
{
    pub(crate) fn new(
        connector: C,
        connection_timeout: Duration,
        http2: Http2Config,
        shutdown: CancellationToken,
    ) -> Self {
        let hosts = Arc::new(StdRwLock::new(PoolHosts {
            closed: false,
            map: HashMap::new(),
        }));

        Self {
            connection_timeout,
            http2,
            hosts,
            connector,
            shutdown,
            reaper_notify: Arc::new(Notify::new()),
            reaper: OnceLock::new(),
        }
    }

    fn ensure_reaper_started(&self) {
        self.reaper.get_or_init(|| {
            let hosts = self.hosts.clone();
            let shutdown = self.shutdown.clone();
            let notify = self.reaper_notify.clone();
            AbortOnDropHandle::new(tokio::spawn(async move {
                let mut shutdown_fut = pin!(shutdown.cancelled());
                loop {
                    let next_deadline = reap_idle_connections(&hosts, Instant::now(), IDLE_TIMEOUT);
                    match next_deadline {
                        Some(deadline) => {
                            // `IDLE_TIMEOUT` is uniform across all connections, so no newly-idle
                            // connection can expire earlier than `deadline`; sleep until then
                            // rather than waking on every request completion.
                            tokio::select! {
                                biased;
                                _ = &mut shutdown_fut => break,
                                _ = tokio::time::sleep_until(deadline) => {}
                            }
                        }
                        None => {
                            tokio::select! {
                                biased;
                                _ = &mut shutdown_fut => break,
                                _ = notify.notified() => {}
                            }
                        }
                    }
                }
            }))
        });
    }

    fn get_or_create_host_pool(
        &self,
        origin: &str,
        fallback_uri: &Uri,
    ) -> Result<Arc<HostPool<C>>, HttpError> {
        {
            let hosts = self.hosts.read().unwrap();
            if hosts.closed {
                return Err(HttpError::Closed);
            }
            if let Some(pool) = hosts.map.get(origin) {
                return Ok(pool.clone());
            }
        }
        let mut hosts = self.hosts.write().unwrap();
        if hosts.closed {
            return Err(HttpError::Closed);
        }
        Ok(hosts
            .map
            .entry(origin.to_owned())
            .or_insert_with(|| {
                let origin_uri = origin
                    .parse::<Uri>()
                    .unwrap_or_else(|_| fallback_uri.clone());
                Arc::new(HostPool::new(
                    origin.to_owned(),
                    origin_uri,
                    self.connector.clone(),
                    self.connection_timeout,
                    self.http2,
                    self.shutdown.clone(),
                    self.reaper_notify.clone(),
                ))
            })
            .clone())
    }

    fn checkout_for_origin(
        &self,
        origin: &str,
        fallback_uri: &Uri,
    ) -> Result<(Arc<HostPool<C>>, Checkout), HttpError> {
        loop {
            let pool = self.get_or_create_host_pool(origin, fallback_uri)?;
            if let Some(checkout) = pool.checkout() {
                return Ok((pool, checkout));
            }
            // The host pool was detached concurrently by the idle reaper or close(); loop to
            // re-check closed state or allocate a fresh host pool.
        }
    }

    /// Acquire a live, ready HTTP/2 `SendRequest` for `origin`.
    ///
    /// Phase 1 (`T7a`): connection establishment (DNS/TCP/TLS/H2 handshake) is bounded by
    /// `connection_timeout`, completely independent of `request_timeout`.
    /// Phase 2 (`T7b`): once the connection is dialed, a single `deadline` bounds `sender.ready()`,
    /// request headers/response headers, and unary body collection.
    /// If a reused idle connection closed right before `ready()`, transparently evict it and
    /// dial once so the caller sees no spurious error.
    async fn checkout_ready(
        &self,
        origin: &str,
        fallback_uri: &Uri,
        request_timeout: Option<Duration>,
    ) -> Result<CheckedOutSender, HttpError> {
        for attempt in 0..2 {
            let (pool, checkout) = self.checkout_for_origin(origin, fallback_uri)?;
            let (id, mut sender, permit, reused) = match checkout {
                Checkout::Ready { id, sender, permit } => (id, sender, permit, true),
                Checkout::Connecting { id, mut rx, permit } => {
                    let sender = wait_for_dial(&mut rx, &self.shutdown).await?;
                    (id, sender, permit, false)
                }
            };

            let deadline = request_timeout.map(|d| Instant::now() + d);
            let ready_res = match deadline {
                Some(dl) => match timeout_at(dl, sender.ready()).await {
                    Ok(res) => res,
                    Err(_) => {
                        pool.remove(id);
                        return Err(HttpError::Timeout);
                    }
                },
                None => sender.ready().await,
            };

            match ready_res {
                Ok(()) => {
                    let weak: Weak<dyn PoisonTarget> =
                        Arc::downgrade(&(pool as Arc<dyn PoisonTarget>));
                    let poison_handle = PoisonHandle::new(weak, id);
                    return Ok(CheckedOutSender {
                        sender,
                        permit,
                        poison_handle,
                        deadline,
                    });
                }
                Err(err) => {
                    pool.remove(id);
                    drop(permit);
                    if reused && attempt == 0 {
                        tracing::debug!(
                            origin = %origin,
                            connection = ?id,
                            error = %format_error_chain(&err),
                            "evicted stale pooled HTTP/2 connection; redialing"
                        );
                        continue;
                    }
                    return Err(HttpError::Transport(err));
                }
            }
        }
        unreachable!("at most two checkout attempts")
    }

    async fn send_with<T, F, Fut>(&self, request: Request, run: F) -> Result<T, HttpError>
    where
        F: FnOnce(CheckedOutSender, Request) -> Fut,
        Fut: Future<Output = Result<T, HttpError>>,
    {
        if self.shutdown.is_cancelled() {
            return Err(HttpError::Closed);
        }
        self.ensure_reaper_started();
        let origin = request.origin();
        let request_timeout = request.timeout;
        let shutdown = self.shutdown.clone();
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => Err(HttpError::Closed),
            res = async {
                let checked_out = self
                    .checkout_ready(&origin, &request.uri, request_timeout)
                    .await?;
                run(checked_out, request).await
            } => res,
        }
    }
}

fn reap_idle_connections<C: Connect>(
    hosts: &StdRwLock<PoolHosts<C>>,
    now: Instant,
    idle_timeout: Duration,
) -> Option<Instant> {
    let pools: Vec<Arc<HostPool<C>>> = {
        let hosts = hosts.read().unwrap();
        hosts.map.values().cloned().collect()
    };

    let mut next_deadline: Option<Instant> = None;
    for pool in &pools {
        if let Some(deadline) = pool.reap_idle(now, idle_timeout) {
            next_deadline = Some(match next_deadline {
                Some(earliest) => earliest.min(deadline),
                None => deadline,
            });
        }
    }

    hosts
        .write()
        .unwrap()
        .map
        .retain(|_, pool| !pool.detach_if_empty());

    next_deadline
}

async fn send_http_request(
    mut sender: http2::SendRequest<BoxBody>,
    request: Request,
    poison_handle: &PoisonHandle,
    deadline: Option<Instant>,
) -> Result<http::Response<Incoming>, HttpError> {
    let http_request = build_http_request(
        request.method,
        &request.uri,
        request.headers,
        request.body.into_http_body(),
    )?;

    let send_fut = sender.send_request(http_request);
    match deadline {
        Some(dl) => match timeout_at(dl, send_fut).await {
            Ok(res) => res,
            Err(_) => {
                poison_handle.poison();
                return Err(HttpError::Timeout);
            }
        },
        None => send_fut.await,
    }
    .map_err(|err| {
        if is_dead_connection_hyper_error(&err) {
            poison_handle.poison();
        }
        HttpError::Transport(err)
    })
}

async fn execute_unary_with(
    checked_out: CheckedOutSender,
    request: Request,
) -> Result<UnaryResponse, HttpError> {
    let CheckedOutSender {
        sender,
        permit: _permit,
        poison_handle,
        deadline,
    } = checked_out;
    let response = send_http_request(sender, request, &poison_handle, deadline).await?;

    let (parts, body) = response.into_parts();
    let bytes = if parts.status.is_success() {
        let bytes = collect_bounded_body(body, MAX_RESPONSE_BYTES, deadline)
            .await
            .map_err(|err| match err {
                CollectBodyError::Timeout => {
                    poison_handle.poison();
                    HttpError::Timeout
                }
                CollectBodyError::TooLarge => HttpError::ResponseTooLarge(MAX_RESPONSE_BYTES),
                CollectBodyError::Transport(hyper_err) => {
                    if is_dead_connection_hyper_error(&hyper_err) {
                        poison_handle.poison();
                    }
                    HttpError::Transport(hyper_err)
                }
            })?;
        decompress_body(&parts.headers, bytes, MAX_RESPONSE_BYTES)?
    } else {
        // Non-2xx headers already received (`E2`): preserve HTTP status even if collecting
        // or decompressing the error body stalls or fails.
        collect_and_decompress_error_body(
            parts.status,
            &parts.headers,
            body,
            deadline,
            &poison_handle,
        )
        .await
    };

    Ok(UnaryResponse {
        status: parts.status,
        headers: parts.headers,
        bytes,
        poison_handle: Some(poison_handle),
    })
}

async fn init_streaming_with(
    checked_out: CheckedOutSender,
    request: Request,
) -> Result<StreamingResponse, HttpError> {
    let CheckedOutSender {
        sender,
        permit,
        poison_handle,
        deadline,
    } = checked_out;
    let response = send_http_request(sender, request, &poison_handle, deadline).await?;

    let (parts, body) = response.into_parts();
    Ok(StreamingResponse::new(
        parts.status,
        parts.headers,
        body,
        permit,
        poison_handle,
        deadline,
    ))
}

#[async_trait]
impl<C> RequestExecutor for Pool<C>
where
    C: Connect,
{
    async fn execute_unary(&self, request: Request) -> Result<UnaryResponse, HttpError> {
        self.send_with(request, execute_unary_with).await
    }

    async fn init_streaming(&self, request: Request) -> Result<StreamingResponse, HttpError> {
        self.send_with(request, init_streaming_with).await
    }

    fn close(&self) {
        self.shutdown.cancel();
        let pools: Vec<_> = {
            let mut hosts = self.hosts.write().unwrap();
            hosts.closed = true;
            hosts.map.drain().map(|(_, pool)| pool).collect()
        };
        for pool in pools {
            pool.clear_and_detach();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
    };

    use hyper_util::rt::TokioIo;
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    use rustls::client::danger::ServerCertVerifier;
    use tokio::io::DuplexStream;

    use super::*;

    const TEST_ORIGIN: &str = "http://localhost:8080";

    #[derive(Clone)]
    struct DuplexH2Connector {
        dials: Arc<AtomicUsize>,
        active_connections: Arc<AtomicUsize>,
        conn_closed: Arc<Notify>,
        dial_delay: Duration,
        stall_error_body: bool,
    }

    impl DuplexH2Connector {
        fn new() -> Self {
            Self {
                dials: Arc::new(AtomicUsize::new(0)),
                active_connections: Arc::new(AtomicUsize::new(0)),
                conn_closed: Arc::new(Notify::new()),
                dial_delay: Duration::ZERO,
                stall_error_body: false,
            }
        }

        async fn wait_active_connections(&self, expected: usize) {
            while self.active_connections.load(Ordering::SeqCst) != expected {
                let notified = self.conn_closed.notified();
                if self.active_connections.load(Ordering::SeqCst) == expected {
                    break;
                }
                notified.await;
            }
        }
    }

    struct ActiveConnGuard {
        active: Arc<AtomicUsize>,
        closed: Arc<Notify>,
    }

    impl Drop for ActiveConnGuard {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
            self.closed.notify_waiters();
        }
    }

    impl Service<Uri> for DuplexH2Connector {
        type Response = TokioIo<DuplexStream>;
        type Error = std::io::Error;
        type Future =
            Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _dst: Uri) -> Self::Future {
            let dials = self.dials.clone();
            let active_connections = self.active_connections.clone();
            let conn_closed = self.conn_closed.clone();
            let dial_delay = self.dial_delay;
            let stall_error_body = self.stall_error_body;
            Box::pin(async move {
                dials.fetch_add(1, Ordering::SeqCst);
                if !dial_delay.is_zero() {
                    tokio::time::sleep(dial_delay).await;
                }
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let Ok(mut conn) = h2::server::handshake(server_io).await else {
                        return;
                    };
                    active_connections.fetch_add(1, Ordering::SeqCst);
                    let _guard = ActiveConnGuard {
                        active: active_connections,
                        closed: conn_closed,
                    };
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        let path = req.uri().path();
                        if stall_error_body {
                            let resp = http::Response::builder()
                                .status(StatusCode::PRECONDITION_FAILED)
                                .body(())
                                .unwrap();
                            if let Ok(mut send) = respond.send_response(resp, false) {
                                tokio::spawn(async move {
                                    let _ = std::future::poll_fn(|cx| send.poll_reset(cx)).await;
                                });
                            }
                        } else if path == "/stall-headers" {
                            // Never send response headers (simulates silent blackhole).
                            tokio::spawn(async move {
                                let _keep_open = respond;
                                std::future::pending::<()>().await;
                            });
                        } else if path == "/stall-ok-body" {
                            let resp = http::Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .unwrap();
                            if let Ok(mut send) = respond.send_response(resp, false) {
                                tokio::spawn(async move {
                                    let _ = std::future::poll_fn(|cx| send.poll_reset(cx)).await;
                                });
                            }
                        } else {
                            let resp = http::Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .unwrap();
                            if let Ok(mut send) = respond.send_response(resp, false) {
                                let _ = send.send_data(Bytes::from_static(b"ok"), true);
                            }
                        }
                    }
                });
                Ok(TokioIo::new(client_io))
            })
        }
    }

    fn test_pool_with(connector: DuplexH2Connector, http2: Http2Config) -> Pool<DuplexH2Connector> {
        Pool::new(
            connector,
            Duration::from_secs(3),
            http2,
            CancellationToken::new(),
        )
    }

    fn test_pool() -> Pool<DuplexH2Connector> {
        test_pool_with(DuplexH2Connector::new(), Http2Config::new())
    }

    fn host_connection_count<C: Connect>(pool: &Pool<C>, origin: &str) -> usize {
        let hosts = pool.hosts.read().unwrap();
        match hosts.map.get(origin) {
            Some(pool) => pool.state.read().unwrap().connections.len(),
            None => 0,
        }
    }

    async fn checkout_permit(
        pool: &Pool<DuplexH2Connector>,
        origin: &str,
    ) -> (ConnectionId, RequestPermit) {
        let uri: Uri = origin.parse().unwrap();
        let (_host_pool, checkout) = pool.checkout_for_origin(origin, &uri).unwrap();
        match checkout {
            Checkout::Ready { id, permit, .. } => (id, permit),
            Checkout::Connecting { id, mut rx, permit } => {
                wait_for_dial(&mut rx, &pool.shutdown).await.unwrap();
                (id, permit)
            }
        }
    }

    #[test]
    fn default_headers_preserve_multiple_values_and_sensitive_flags_on_wire_request() {
        let mut headers = HeaderMap::new();
        headers.append("x-tag", HeaderValue::from_static("first"));
        let mut second = HeaderValue::from_static("second");
        second.set_sensitive(true);
        headers.append("x-tag", second);
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));

        let request = RequestBuilder::get("http://example.test".parse().unwrap())
            .header("x-tag", "replaced")
            .headers(&headers)
            .build()
            .unwrap();
        let cloned = request.try_clone().unwrap();
        let http = build_http_request(
            cloned.method,
            &cloned.uri,
            cloned.headers,
            cloned.body.into_http_body(),
        )
        .unwrap();
        let values = http.headers().get_all("x-tag").iter().collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "first");
        assert_eq!(values[1], "second");
        assert!(values[1].is_sensitive());
        assert_eq!(http.headers()[CONTENT_ENCODING], "gzip");
    }

    #[test]
    fn uri_query_and_origin_normalization() {
        let base: Uri = "https://example.com".parse().unwrap();
        assert_eq!(
            uri_with_path(
                &base,
                format!("v1/access-tokens/{}", urlencoding::encode("a/b?c d")),
            ),
            "https://example.com/v1/access-tokens/a%2Fb%3Fc%20d"
        );

        #[derive(serde::Serialize)]
        struct Params<'a> {
            prefix: &'a str,
        }
        let req = RequestBuilder::get("https://example.com/v1/streams?limit=1".parse().unwrap())
            .query(&Params { prefix: "a/b c" })
            .build()
            .unwrap();
        assert_eq!(
            req.uri,
            "https://example.com/v1/streams?limit=1&prefix=a%2Fb+c"
        );

        for (raw, expected) in [
            ("HTTP://Example.COM:80/v1", "http://example.com"),
            ("http://example.com/v1", "http://example.com"),
            ("HTTPS://A.S2.DEV:443/v1", "https://a.s2.dev"),
            ("https://a.s2.dev:8443/v1", "https://a.s2.dev:8443"),
        ] {
            let r = RequestBuilder::get(raw.parse().unwrap()).build().unwrap();
            assert_eq!(r.origin(), expected);
        }
    }

    #[cfg(feature = "rustls-aws-lc-rs")]
    fn test_rustls_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    #[cfg(all(not(feature = "rustls-aws-lc-rs"), feature = "rustls-ring"))]
    fn test_rustls_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[test]
    fn default_connector_accepts_explicit_crypto_provider_for_insecure_tls() {
        let connector = default_connector(None, true, Some(test_rustls_crypto_provider()));
        assert!(connector.is_ok());
    }

    #[cfg(all(
        any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"),
        any(feature = "rustls-native-roots", feature = "rustls-webpki-roots"),
    ))]
    #[test]
    fn default_connector_builds_verified_tls_connector() {
        let connector = default_connector(None, false, Some(test_rustls_crypto_provider()));
        assert!(connector.is_ok());
    }

    #[cfg(all(
        any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"),
        not(feature = "rustls-native-roots"),
        not(feature = "rustls-webpki-roots"),
    ))]
    #[test]
    fn default_connector_errors_without_any_root_store_feature() {
        let err = default_connector(None, false, Some(test_rustls_crypto_provider()))
            .err()
            .unwrap();
        assert!(
            err.to_string()
                .contains("no TLS root certificates configured"),
            "unexpected error: {err}"
        );
    }

    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[test]
    fn no_verifier_uses_configured_provider_signature_schemes() {
        let provider = test_rustls_crypto_provider();
        let verifier = NoVerifier {
            rustls_crypto_provider: provider.clone(),
        };

        assert_eq!(
            verifier.supported_verify_schemes(),
            provider
                .signature_verification_algorithms
                .supported_schemes()
        );
    }

    // spec: r1 C13, C13a
    #[tokio::test]
    async fn pool_capacity_spillover_release_and_host_isolation() {
        assert_eq!(DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CONNECTION, 50);
        let pool = test_pool();
        let mut permits = Vec::new();
        for _ in 0..DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CONNECTION {
            permits.push(checkout_permit(&pool, TEST_ORIGIN).await.1);
        }
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 1);

        // Releasing one permit frees capacity on the existing connection without dialing.
        permits.pop();
        permits.push(checkout_permit(&pool, TEST_ORIGIN).await.1);
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 1);

        // Exceeding capacity spills over onto a second connection.
        permits.push(checkout_permit(&pool, TEST_ORIGIN).await.1);
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 2);

        // Separate origins maintain independent pools.
        let other_origin = "https://other-host";
        let _other = checkout_permit(&pool, other_origin).await.1;
        assert_eq!(host_connection_count(&pool, other_origin), 1);
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 2);
    }

    // spec: r1 C13
    #[tokio::test]
    async fn poison_evicts_only_targeted_connection_preserving_siblings() {
        let http2 = Http2Config::new().with_max_concurrent_requests(1).unwrap();
        let connector = DuplexH2Connector::new();
        let pool = test_pool_with(connector.clone(), http2);
        let (id1, p1) = checkout_permit(&pool, TEST_ORIGIN).await;
        let (id2, p2) = checkout_permit(&pool, TEST_ORIGIN).await;
        assert_ne!(id1, id2);
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 2);
        assert_eq!(connector.active_connections.load(Ordering::SeqCst), 2);

        let uri: Uri = TEST_ORIGIN.parse().unwrap();
        let host_pool = pool.get_or_create_host_pool(TEST_ORIGIN, &uri).unwrap();
        host_pool.poison(id1);
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 1);

        // Dropping the retired connection's last permit/sender closes its underlying socket.
        drop(p1);
        connector.wait_active_connections(1).await;

        // Freeing the healthy sibling's permit allows reusing it rather than dialing a new one.
        drop(p2);
        let (id3, p3) = checkout_permit(&pool, TEST_ORIGIN).await;
        assert_eq!(id3, id2);
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 1);
        drop(p3);
    }

    // spec: r1 C13c
    #[tokio::test(start_paused = true)]
    async fn reaper_removes_idle_connections_at_90s() {
        let connector = DuplexH2Connector::new();
        let pool = test_pool_with(connector.clone(), Http2Config::new());
        let req = RequestBuilder::get("http://localhost:8080/test".parse().unwrap())
            .build()
            .unwrap();
        let resp = pool.execute_unary(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 1);
        assert_eq!(connector.active_connections.load(Ordering::SeqCst), 1);

        // Just before 90s: still pooled and open.
        tokio::time::advance(IDLE_TIMEOUT - Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 1);
        assert_eq!(connector.active_connections.load(Ordering::SeqCst), 1);

        // At 90s: reaped promptly and the underlying connection closes.
        tokio::time::advance(Duration::from_secs(2)).await;
        connector.wait_active_connections(0).await;
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 0);
        assert!(!pool.hosts.read().unwrap().map.contains_key(TEST_ORIGIN));
    }

    // spec: r1 T7a, T7b
    #[tokio::test(start_paused = true)]
    async fn connection_timeout_is_separate_from_request_timeout() {
        let mut connector = DuplexH2Connector::new();
        connector.dial_delay = Duration::from_millis(300);
        // connection_timeout (1s) > dial_delay (300ms) > request_timeout (100ms):
        // Phase 1 dial must NOT trigger request_timeout.
        let pool = Pool::new(
            connector,
            Duration::from_secs(1),
            Http2Config::new(),
            CancellationToken::new(),
        );
        let req = RequestBuilder::get("http://localhost:8080/test".parse().unwrap())
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let resp = pool.execute_unary(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Now dial_delay (500ms) > connection_timeout (100ms) with huge request_timeout (10s):
        // must fail with HttpError::Connect (not HttpError::Timeout).
        let mut slow_connector = DuplexH2Connector::new();
        slow_connector.dial_delay = Duration::from_millis(500);
        let pool = Pool::new(
            slow_connector,
            Duration::from_millis(100),
            Http2Config::new(),
            CancellationToken::new(),
        );
        let req = RequestBuilder::get("http://localhost:8080/test".parse().unwrap())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let err = pool.execute_unary(req).await.err().unwrap();
        assert!(
            matches!(err, HttpError::Connect(ref m) if m.contains("timed out")),
            "expected Connect timeout, got {err:?}"
        );
    }

    // spec: r1 E2
    #[tokio::test(start_paused = true)]
    async fn stalled_non_2xx_error_body_preserves_status_for_unary_and_streaming() {
        let mut connector = DuplexH2Connector::new();
        connector.stall_error_body = true;
        let pool = test_pool_with(connector, Http2Config::new());

        // Unary: 412 headers arrive, body stalls past request_timeout -> preserves 412 with empty
        // body.
        let unary_req = RequestBuilder::post("http://localhost:8080/append".parse().unwrap())
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        let unary_resp = pool.execute_unary(unary_req).await.unwrap();
        assert_eq!(unary_resp.status(), StatusCode::PRECONDITION_FAILED);
        assert!(unary_resp.into_bytes().is_empty());

        // Streaming: 412 headers arrive, error-body collection stalls -> preserves 412 with empty
        // body.
        let stream_req = RequestBuilder::post("http://localhost:8080/append".parse().unwrap())
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        let stream_resp = pool.init_streaming(stream_req).await.unwrap();
        assert_eq!(stream_resp.status(), StatusCode::PRECONDITION_FAILED);
        let (bytes, _poison) = stream_resp.into_bytes_with_poison_handle().await;
        assert!(bytes.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn request_timeout_retires_stalled_connection_so_next_request_redials() {
        for stall_path in ["/stall-headers", "/stall-ok-body"] {
            let connector = DuplexH2Connector::new();
            let pool = test_pool_with(connector.clone(), Http2Config::new());

            // Warm connection #1.
            let ok_req = RequestBuilder::get("http://localhost:8080/ok".parse().unwrap())
                .timeout(Duration::from_millis(50))
                .build()
                .unwrap();
            assert_eq!(
                pool.execute_unary(ok_req).await.unwrap().status(),
                StatusCode::OK
            );
            assert_eq!(connector.dials.load(Ordering::SeqCst), 1);
            assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 1);

            // Timed-out request on connection #1 must retire it from the pool.
            let stalled_req = RequestBuilder::get(
                format!("http://localhost:8080{stall_path}")
                    .parse()
                    .unwrap(),
            )
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
            let err = pool.execute_unary(stalled_req).await.err().unwrap();
            assert!(matches!(err, HttpError::Timeout), "{stall_path}: {err:?}");
            assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 0);

            // Subsequent request must dial a fresh connection (#2) instead of reusing #1.
            let retry_req = RequestBuilder::get("http://localhost:8080/ok".parse().unwrap())
                .timeout(Duration::from_millis(50))
                .build()
                .unwrap();
            assert_eq!(
                pool.execute_unary(retry_req).await.unwrap().status(),
                StatusCode::OK
            );
            assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
            pool.close();
        }
    }

    #[tokio::test]
    async fn dropping_pool_cancels_in_flight_dial() {
        #[derive(Clone)]
        struct HangingDialConnector {
            started: Arc<Notify>,
            dropped: Arc<Notify>,
        }

        struct DropSignal(Arc<Notify>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }

        impl tower_service::Service<Uri> for HangingDialConnector {
            type Response = TokioIo<DuplexStream>;
            type Error = std::io::Error;
            type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _uri: Uri) -> Self::Future {
                let started = self.started.clone();
                let dropped = self.dropped.clone();
                Box::pin(async move {
                    let _guard = DropSignal(dropped);
                    started.notify_one();
                    std::future::pending().await
                })
            }
        }

        let started = Arc::new(Notify::new());
        let dropped = Arc::new(Notify::new());
        let connector = HangingDialConnector {
            started: started.clone(),
            dropped: dropped.clone(),
        };
        let pool = Pool::new(
            connector,
            Duration::from_secs(30),
            Http2Config::new(),
            CancellationToken::new(),
        );
        let req = RequestBuilder::get("http://localhost:8080/ok".parse().unwrap())
            .build()
            .unwrap();
        {
            let req_fut = pool.execute_unary(req);
            tokio::pin!(req_fut);

            tokio::select! {
                _ = &mut req_fut => unreachable!("hanging dial should not finish"),
                _ = started.notified() => {}
            }
        }

        // Drop the pool without calling `close()`.
        let dropped_fut = dropped.notified();
        tokio::pin!(dropped_fut);
        dropped_fut.as_mut().enable();
        drop(pool);

        timeout(Duration::from_secs(1), dropped_fut)
            .await
            .expect("in-flight dial should be cancelled immediately when Pool drops");
    }

    #[test]
    fn compress_body_skips_empty_body_and_roundtrips() {
        for compression in [Compression::Gzip, Compression::Zstd] {
            let (body, enc) = compress_body(Body::empty(), compression).unwrap();
            assert!(enc.is_none());
            assert!(matches!(body.0, BodyInner::Empty));

            let payload = b"hello world hello world hello world".to_vec();
            let (compressed, enc) =
                compress_body(Body::from(payload.clone()), compression).unwrap();
            let enc = enc.expect("encoding header");
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_ENCODING, enc);
            let raw = Bytes::copy_from_slice(compressed.as_bytes().unwrap());
            let decoded = decompress_body(&headers, raw.clone(), MAX_RESPONSE_BYTES).unwrap();
            assert_eq!(decoded.as_ref(), payload.as_slice());

            let err = decompress_body(&headers, raw, payload.len() - 1).unwrap_err();
            assert!(matches!(err, HttpError::ResponseTooLarge(n) if n == payload.len() - 1));
        }
    }

    #[tokio::test]
    async fn collect_bounded_body_enforces_limit_across_single_and_multiple_frames() {
        // Empty body.
        let empty = collect_bounded_body(Empty::<Bytes>::new(), 8, None)
            .await
            .ok()
            .unwrap();
        assert!(empty.is_empty());

        // Single-frame exact boundary succeeds; one byte over fails immediately via size_hint.
        let exact = collect_bounded_body(Full::new(Bytes::from_static(b"12345678")), 8, None)
            .await
            .ok()
            .unwrap();
        assert_eq!(exact.as_ref(), b"12345678");
        assert!(matches!(
            collect_bounded_body(Full::new(Bytes::from_static(b"123456789")), 8, None).await,
            Err(CollectBodyError::TooLarge)
        ));

        // Multi-frame stream with unknown size_hint: exact limit succeeds, +1 byte fails.
        let ok_stream = StreamBody::new(futures_util::stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"abcd"))),
            Ok(Frame::data(Bytes::new())),
            Ok(Frame::data(Bytes::from_static(b"efgh"))),
        ]));
        let combined = collect_bounded_body(ok_stream, 8, None).await.ok().unwrap();
        assert_eq!(combined.as_ref(), b"abcdefgh");

        let over_stream = StreamBody::new(futures_util::stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"abcd"))),
            Ok(Frame::data(Bytes::from_static(b"efghi"))),
        ]));
        assert!(matches!(
            collect_bounded_body(over_stream, 8, None).await,
            Err(CollectBodyError::TooLarge)
        ));
    }
}
