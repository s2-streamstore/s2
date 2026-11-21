use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock, RwLock as StdRwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_compression::{
    Level,
    tokio::{
        bufread::{GzipDecoder, ZstdDecoder},
        write::{GzipEncoder, ZstdEncoder},
    },
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use http::{
    HeaderMap, Method, StatusCode, Uri,
    header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderName, HeaderValue},
};
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    body::{Frame, Incoming},
    rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
pub use hyper_util::client::legacy::connect::Connect;
use hyper_util::{
    client::legacy::{
        Client as HyperClient,
        connect::{Connected, Connection, HttpConnector},
    },
    rt::{TokioExecutor, TokioTimer},
};
use pin_project_lite::pin_project;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
    time::timeout,
};
use tokio_util::task::AbortOnDropHandle;
use tower_service::Service;

use crate::{
    frame_signal::{FrameSignal, RequestFrameMonitorBody},
    types::Http2Config,
};

const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");
const MAX_CONCURRENT_REQUESTS_PER_CLIENT: usize = 50;
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const REAPER_INTERVAL: Duration = Duration::from_secs(30);

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = UnsyncBoxBody<Bytes, BoxError>;

#[derive(Debug, Clone, Copy, Default)]
pub enum Compression {
    #[default]
    None,
    Gzip,
    Zstd,
}

impl From<crate::types::Compression> for Compression {
    fn from(c: crate::types::Compression) -> Self {
        match c {
            crate::types::Compression::None => Compression::None,
            crate::types::Compression::Gzip => Compression::Gzip,
            crate::types::Compression::Zstd => Compression::Zstd,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ShutdownSignal {
    tx: Arc<watch::Sender<bool>>,
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownSignal {
    pub(crate) fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self { tx: Arc::new(tx) }
    }

    pub(crate) fn close(&self) {
        self.tx.send_replace(true);
    }

    pub(crate) fn is_closed(&self) -> bool {
        *self.tx.borrow()
    }

    pub(crate) fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let mut rx = self.tx.subscribe();
        Box::pin(async move {
            if *rx.borrow_and_update() {
                return;
            }
            let _ = rx.wait_for(|closed| *closed).await;
        })
    }
}

pin_project! {
    /// Connection wrapper that immediately drops the underlying transport when [`ShutdownSignal`]
    /// triggers (`C12`), terminating established connections without waiting for the server.
    pub(crate) struct AbortableIo<T> {
        #[pin]
        inner: Option<T>,
        shutdown_fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    }
}

impl<T> AbortableIo<T> {
    fn new(inner: T, shutdown: ShutdownSignal) -> Self {
        Self {
            inner: Some(inner),
            shutdown_fut: shutdown.cancelled(),
        }
    }

    fn poll_not_closed(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> io::Result<()> {
        let mut this = self.as_mut().project();
        if this.inner.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "client closed",
            ));
        }
        if this.shutdown_fut.as_mut().poll(cx).is_ready() {
            this.inner.set(None);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "client closed",
            ));
        }
        Ok(())
    }
}

impl<T: HyperRead> HyperRead for AbortableIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(err) = self.as_mut().poll_not_closed(cx) {
            return Poll::Ready(Err(err));
        }
        match self.project().inner.as_pin_mut() {
            Some(inner) => inner.poll_read(cx, buf),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "client closed",
            ))),
        }
    }
}

impl<T: HyperWrite> HyperWrite for AbortableIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(err) = self.as_mut().poll_not_closed(cx) {
            return Poll::Ready(Err(err));
        }
        match self.project().inner.as_pin_mut() {
            Some(inner) => inner.poll_write(cx, buf),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "client closed",
            ))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(err) = self.as_mut().poll_not_closed(cx) {
            return Poll::Ready(Err(err));
        }
        match self.project().inner.as_pin_mut() {
            Some(inner) => inner.poll_flush(cx),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "client closed",
            ))),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(HyperWrite::is_write_vectored)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if let Err(err) = self.as_mut().poll_not_closed(cx) {
            return Poll::Ready(Err(err));
        }
        match self.project().inner.as_pin_mut() {
            Some(inner) => inner.poll_write_vectored(cx, bufs),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "client closed",
            ))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(err) = self.as_mut().poll_not_closed(cx) {
            return Poll::Ready(Err(err));
        }
        match self.project().inner.as_pin_mut() {
            Some(inner) => inner.poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl<T: Connection> Connection for AbortableIo<T> {
    fn connected(&self) -> Connected {
        self.inner
            .as_ref()
            .map_or_else(Connected::new, Connection::connected)
    }
}

/// Connector wrapper enforcing `connection_timeout` across TCP + TLS (`T7a`) and aborting
/// in-progress dials immediately on client close (`C12`).
#[derive(Clone)]
pub(crate) struct ManagedConnector<C> {
    inner: C,
    connect_timeout: Option<Duration>,
    shutdown: ShutdownSignal,
}

impl<C> ManagedConnector<C> {
    pub(crate) fn new(
        inner: C,
        connect_timeout: Option<Duration>,
        shutdown: ShutdownSignal,
    ) -> Self {
        Self {
            inner,
            connect_timeout,
            shutdown,
        }
    }
}

impl<C> Service<Uri> for ManagedConnector<C>
where
    C: Service<Uri> + Clone + Send + Sync + 'static,
    C::Response: HyperRead + HyperWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Send + 'static,
{
    type Response = AbortableIo<C::Response>;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let connect_timeout = self.connect_timeout;
        let shutdown = self.shutdown.clone();
        if shutdown.is_closed() {
            return Box::pin(async {
                Err(Box::new(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "client closed",
                )) as BoxError)
            });
        }
        let inner_fut = self.inner.call(dst);
        Box::pin(async move {
            let connect_fut = async {
                if let Some(dur) = connect_timeout {
                    timeout(dur, inner_fut)
                        .await
                        .map_err(|_| -> BoxError {
                            Box::new(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "connection timed out",
                            ))
                        })?
                        .map_err(Into::into)
                } else {
                    inner_fut.await.map_err(Into::into)
                }
            };

            let io = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    return Err(Box::new(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "client closed",
                    )) as BoxError);
                }
                res = connect_fut => res?,
            };

            if shutdown.is_closed() {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "client closed",
                )) as BoxError);
            }

            Ok(AbortableIo::new(io, shutdown))
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpError {
    #[error("send error: {0}")]
    Send(#[from] hyper_util::client::legacy::Error),
    #[error("receive error: {0}")]
    Receive(#[from] hyper::Error),
    #[error("request build error: {0}")]
    RequestBuild(String),
    #[error("response decode error: {0}")]
    ResponseDecode(#[source] serde_json::Error),
    #[error("timeout")]
    Timeout,
    #[error("client closed")]
    ClientClosed,
    #[error("aborted")]
    Aborted,
    #[error("request compression error: {0}")]
    RequestCompression(String),
    #[error("response compression error: {0}")]
    ResponseCompression(String),
}

enum BodyInner {
    Empty,
    Full(Bytes),
    Streaming(BoxBody),
}

pub struct Body(BodyInner);

impl Body {
    fn empty() -> Self {
        Self(BodyInner::Empty)
    }

    pub fn wrap_stream<S, E>(stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, E>> + Send + 'static,
        E: Into<BoxError> + 'static,
    {
        let stream_body = StreamBody::new(stream.map(|r| r.map(Frame::data).map_err(Into::into)));
        Self(BodyInner::Streaming(BoxBody::new(stream_body)))
    }

    pub(crate) fn monitored(self, signal: FrameSignal) -> Self {
        Self(BodyInner::Streaming(BoxBody::new(
            RequestFrameMonitorBody::new(self.into_http_body(), signal),
        )))
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

pub struct Request {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
    timeout: Option<Duration>,
    compression: Compression,
}

impl Request {
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub fn with_monitored_body(self, signal: FrameSignal) -> Self {
        Self {
            body: self.body.monitored(signal),
            ..self
        }
    }

    pub async fn compress(self) -> Result<Self, HttpError> {
        let (body, content_encoding) = compress_body(self.body, self.compression).await?;
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

    pub fn origin(&self) -> String {
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

    pub fn try_clone(&self) -> Option<Self> {
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

pub struct RequestBuilder {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Option<Body>,
    timeout: Option<Duration>,
    compression: Compression,
    error: Option<HttpError>,
}

impl RequestBuilder {
    pub fn new(method: Method, uri: Uri) -> Self {
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

    pub fn get(uri: Uri) -> Self {
        Self::new(Method::GET, uri)
    }

    pub fn post(uri: Uri) -> Self {
        Self::new(Method::POST, uri)
    }

    pub fn patch(uri: Uri) -> Self {
        Self::new(Method::PATCH, uri)
    }

    pub fn put(uri: Uri) -> Self {
        Self::new(Method::PUT, uri)
    }

    pub fn delete(uri: Uri) -> Self {
        Self::new(Method::DELETE, uri)
    }

    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Self {
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

    pub fn json<T: Serialize + ?Sized>(mut self, json: &T) -> Self {
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

    pub fn body<B: Into<Body>>(mut self, body: B) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        K::Error: Into<http::Error>,
        V: TryInto<HeaderValue>,
        V::Error: Into<http::Error>,
    {
        match (key.try_into(), value.try_into()) {
            (Ok(name), Ok(value)) => {
                self.headers.insert(name, value);
            }
            (Err(e), _) => self.error = Some(HttpError::RequestBuild(e.into().to_string())),
            (_, Err(e)) => self.error = Some(HttpError::RequestBuild(e.into().to_string())),
        }
        self
    }

    pub fn headers(mut self, headers: &HeaderMap) -> Self {
        // An owned HeaderMap replaces each key's existing values while preserving duplicates.
        self.headers.extend(headers.clone());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn compression(mut self, compression: impl Into<Compression>) -> Self {
        self.compression = compression.into();
        self
    }

    pub fn build(self) -> Result<Request, HttpError> {
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

pub struct UnaryResponse {
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

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub(crate) fn take_poison_handle(&mut self) -> Option<PoisonHandle> {
        self.poison_handle.take()
    }

    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    pub fn json<T: DeserializeOwned>(self) -> Result<T, HttpError> {
        serde_json::from_slice(&self.bytes).map_err(HttpError::ResponseDecode)
    }
}

/// Identifies a pooled connection within its host pool, so poisoning drops
/// just the connection reconnect advice arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionId(u64);

impl ConnectionId {
    fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// Grants its holder the ability to poison the pooled connection a streaming
/// response was served on, dropping it from the pool so no new request reuses
/// it. Requests already in flight keep the connection.
///
/// Poisoning is idempotent: the connection is identified by its
/// [`ConnectionId`], so poisoning it again — including from another session
/// sharing the connection — is a no-op.
#[derive(Clone)]
pub struct PoisonHandle {
    poison: Arc<dyn Fn() + Send + Sync>,
}

impl PoisonHandle {
    fn new(poison: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            poison: Arc::new(poison),
        }
    }

    pub(crate) fn poison(&self) {
        (self.poison)();
    }
}

fn is_dead_connection_hyper_error(err: &hyper::Error) -> bool {
    if err.is_timeout() {
        return true;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(cur) = source {
        if let Some(h2_err) = cur.downcast_ref::<h2::Error>() {
            return h2_err.is_io() || h2_err.is_go_away();
        }
        source = cur.source();
    }
    err.is_closed()
}

fn is_dead_connection_legacy_error(err: &hyper_util::client::legacy::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(cur) = source {
        if let Some(hyper_err) = cur.downcast_ref::<hyper::Error>() {
            return is_dead_connection_hyper_error(hyper_err);
        }
        source = cur.source();
    }
    false
}

pub struct StreamingResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Incoming,
    permit: RequestPermit,
    poison_handle: PoisonHandle,
    timeout: Option<Duration>,
}

impl StreamingResponse {
    fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Incoming,
        permit: RequestPermit,
        poison_handle: PoisonHandle,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            permit,
            poison_handle,
            timeout,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) async fn into_bytes_with_poison_handle(
        self,
    ) -> Result<(Bytes, PoisonHandle), HttpError> {
        let Self {
            headers,
            body,
            permit,
            poison_handle,
            timeout: body_timeout,
            ..
        } = self;
        let collect_res = if let Some(duration) = body_timeout {
            match timeout(duration, body.collect()).await {
                Ok(res) => res,
                Err(_) => {
                    poison_handle.poison();
                    drop(permit);
                    return Err(HttpError::Timeout);
                }
            }
        } else {
            body.collect().await
        };
        let bytes = match collect_res {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                poison_handle.poison();
                Bytes::new()
            }
        };
        let bytes = match decompress_body(&headers, bytes).await {
            Ok(bytes) => bytes,
            Err(_) => Bytes::new(),
        };
        drop(permit);
        Ok((bytes, poison_handle))
    }

    pub fn into_stream(self) -> (impl Stream<Item = Result<Bytes, HttpError>>, PoisonHandle) {
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
                    Some(Err(HttpError::Receive(e)))
                }
            })
        });
        (stream, poison_handle)
    }
}

#[async_trait]
pub trait RequestExecutor: Send + Sync {
    async fn execute_unary(&self, request: Request) -> Result<UnaryResponse, HttpError>;
    async fn init_streaming(&self, request: Request) -> Result<StreamingResponse, HttpError>;
    fn close(&self) {}
}

pub fn default_http_connector(connect_timeout: Option<Duration>) -> HttpConnector {
    let mut connector = HttpConnector::new();
    connector.enforce_http(true);
    connector.set_nodelay(true);
    if let Some(timeout) = connect_timeout {
        connector.set_connect_timeout(Some(timeout));
    }
    connector
}

pub fn default_connector(
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

    let builder = if insecure_skip_cert_verification {
        HttpsConnectorBuilder::new().with_tls_config(
            rustls::ClientConfig::builder_with_provider(rustls_crypto_provider.clone())
                .with_safe_default_protocol_versions()
                .map_err(std::io::Error::other)?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier {
                    rustls_crypto_provider,
                }))
                .with_no_client_auth(),
        )
    } else {
        HttpsConnectorBuilder::new().with_provider_and_native_roots(rustls_crypto_provider)?
    };

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
    content_encoding: Option<HeaderValue>,
) -> Result<http::Request<BoxBody>, HttpError> {
    let mut builder = http::Request::builder().method(method).uri(uri.clone());

    if let Some(req_headers) = builder.headers_mut() {
        *req_headers = headers;
        if let Some(encoding) = content_encoding {
            req_headers.insert(CONTENT_ENCODING, encoding);
        }
    }

    builder
        .body(body)
        .map_err(|error| HttpError::RequestBuild(error.to_string()))
}

async fn execute_unary_with<C>(
    client: &HyperClient<C, BoxBody>,
    request: Request,
    poison_handle: PoisonHandle,
) -> Result<UnaryResponse, HttpError>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    let request_timeout = request.timeout;

    let (body, content_encoding) = compress_body(request.body, request.compression).await?;

    let http_request = build_http_request(
        request.method,
        &request.uri,
        request.headers,
        body.into_http_body(),
        content_encoding,
    )?;

    let operation = async {
        let response = client.request(http_request).await.inspect_err(|e| {
            if is_dead_connection_legacy_error(e) {
                poison_handle.poison();
            }
        })?;
        let (parts, body) = response.into_parts();
        let bytes = if parts.status.is_success() {
            body.collect()
                .await
                .inspect_err(|e| {
                    if is_dead_connection_hyper_error(e) {
                        poison_handle.poison();
                    }
                })?
                .to_bytes()
        } else {
            match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    poison_handle.poison();
                    Bytes::new()
                }
            }
        };

        Ok::<_, HttpError>((parts.status, parts.headers, bytes))
    };

    let (status, headers, bytes) = if let Some(timeout_duration) = request_timeout {
        timeout(timeout_duration, operation)
            .await
            .map_err(|_| HttpError::Timeout)??
    } else {
        operation.await?
    };

    let bytes = if status.is_success() {
        decompress_body(&headers, bytes).await?
    } else {
        match decompress_body(&headers, bytes).await {
            Ok(bytes) => bytes,
            Err(_) => Bytes::new(),
        }
    };

    Ok(UnaryResponse {
        status,
        headers,
        bytes,
        poison_handle: Some(poison_handle),
    })
}

async fn init_streaming_with<C>(
    client: &HyperClient<C, BoxBody>,
    request: Request,
    permit: RequestPermit,
    poison_handle: PoisonHandle,
) -> Result<StreamingResponse, HttpError>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    let request_timeout = request.timeout;

    let http_request = build_http_request(
        request.method,
        &request.uri,
        request.headers,
        request.body.into_http_body(),
        None,
    )?;

    let started = Instant::now();
    let operation = async {
        let response = client.request(http_request).await.inspect_err(|e| {
            if is_dead_connection_legacy_error(e) {
                poison_handle.poison();
            }
        })?;
        let (parts, body) = response.into_parts();
        let remaining_timeout = request_timeout.map(|d| {
            d.saturating_sub(started.elapsed())
                .max(Duration::from_millis(1))
        });

        Ok::<_, HttpError>(StreamingResponse::new(
            parts.status,
            parts.headers,
            body,
            permit,
            poison_handle,
            remaining_timeout,
        ))
    };

    if let Some(duration) = request_timeout {
        timeout(duration, operation)
            .await
            .map_err(|_| HttpError::Timeout)?
    } else {
        operation.await
    }
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

async fn compress_body(
    body: Body,
    compression: Compression,
) -> Result<(Body, Option<HeaderValue>), HttpError> {
    if matches!(body.0, BodyInner::Empty) {
        return Ok((body, None));
    }
    match compression {
        Compression::None => Ok((body, None)),
        Compression::Gzip => {
            let Some(data) = body.as_bytes() else {
                return Err(HttpError::RequestCompression(
                    "streaming request bodies cannot be compressed".into(),
                ));
            };
            let mut encoder = GzipEncoder::with_quality(Vec::new(), Level::Fastest);
            encoder
                .write_all(data)
                .await
                .map_err(|e| HttpError::RequestCompression(e.to_string()))?;
            encoder
                .shutdown()
                .await
                .map_err(|e| HttpError::RequestCompression(e.to_string()))?;
            let compressed = encoder.into_inner();
            Ok((
                Body::from(compressed),
                Some(HeaderValue::from_static("gzip")),
            ))
        }
        Compression::Zstd => {
            let Some(data) = body.as_bytes() else {
                return Err(HttpError::RequestCompression(
                    "streaming request bodies cannot be compressed".into(),
                ));
            };
            let mut encoder = ZstdEncoder::with_quality(Vec::new(), Level::Fastest);
            encoder
                .write_all(data)
                .await
                .map_err(|e| HttpError::RequestCompression(e.to_string()))?;
            encoder
                .shutdown()
                .await
                .map_err(|e| HttpError::RequestCompression(e.to_string()))?;
            let compressed = encoder.into_inner();
            Ok((
                Body::from(compressed),
                Some(HeaderValue::from_static("zstd")),
            ))
        }
    }
}

const MAX_DECOMPRESSED_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

async fn decompress_single(encoding: &str, bytes: Bytes) -> Result<Bytes, HttpError> {
    let limit = (MAX_DECOMPRESSED_RESPONSE_BYTES as u64) + 1;
    match encoding {
        "" | "identity" => Ok(bytes),
        "gzip" => {
            let mut decoder = GzipDecoder::new(bytes.as_ref());
            decoder.multiple_members(true);
            let mut decompressed = Vec::new();
            decoder
                .take(limit)
                .read_to_end(&mut decompressed)
                .await
                .map_err(|e| HttpError::ResponseCompression(e.to_string()))?;
            if decompressed.len() > MAX_DECOMPRESSED_RESPONSE_BYTES {
                return Err(HttpError::ResponseCompression(format!(
                    "decompressed response exceeds {MAX_DECOMPRESSED_RESPONSE_BYTES} byte limit"
                )));
            }
            Ok(Bytes::from(decompressed))
        }
        "zstd" => {
            let decoder = ZstdDecoder::new(bytes.as_ref());
            let mut decompressed = Vec::new();
            decoder
                .take(limit)
                .read_to_end(&mut decompressed)
                .await
                .map_err(|e| HttpError::ResponseCompression(e.to_string()))?;
            if decompressed.len() > MAX_DECOMPRESSED_RESPONSE_BYTES {
                return Err(HttpError::ResponseCompression(format!(
                    "decompressed response exceeds {MAX_DECOMPRESSED_RESPONSE_BYTES} byte limit"
                )));
            }
            Ok(Bytes::from(decompressed))
        }
        other => Err(HttpError::ResponseCompression(format!(
            "unsupported content-encoding: {other}"
        ))),
    }
}

async fn decompress_body(headers: &HeaderMap, mut bytes: Bytes) -> Result<Bytes, HttpError> {
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
        bytes = decompress_single(&encoding, bytes).await?;
    }
    Ok(bytes)
}

struct PermitState {
    active_requests: usize,
    idle_since: Option<Instant>,
}

struct RequestPermit {
    state: Arc<Mutex<PermitState>>,
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.active_requests = state.active_requests.saturating_sub(1);
        if state.active_requests == 0 {
            state.idle_since = Some(Instant::now());
        }
    }
}

struct PooledClient<C> {
    max_concurrent_requests: usize,
    id: ConnectionId,
    client: Arc<HyperClient<C, BoxBody>>,
    state: Arc<Mutex<PermitState>>,
}

impl<C> PooledClient<C> {
    fn new(client: HyperClient<C, BoxBody>, max_concurrent_requests: usize) -> Self {
        Self {
            max_concurrent_requests,
            id: ConnectionId::next(),
            client: Arc::new(client),
            state: Arc::new(Mutex::new(PermitState {
                active_requests: 0,
                idle_since: Some(Instant::now()),
            })),
        }
    }

    fn request_permit(&self) -> Option<RequestPermit> {
        let mut state = self.state.lock().unwrap();
        if state.active_requests >= self.max_concurrent_requests {
            return None;
        }
        state.active_requests += 1;
        state.idle_since = None;
        Some(RequestPermit {
            state: self.state.clone(),
        })
    }

    fn should_reap(&self, idle_timeout: Duration) -> bool {
        let state = self.state.lock().unwrap();
        state.active_requests == 0
            && state
                .idle_since
                .is_some_and(|idle_since| idle_since.elapsed() >= idle_timeout)
    }
}

struct CheckedOutClient<C> {
    client: Arc<HyperClient<C, BoxBody>>,
    permit: RequestPermit,
    id: ConnectionId,
}

struct HostPoolState<C> {
    clients: Vec<PooledClient<C>>,
    detached: bool,
}

struct HostPool<C> {
    http2: Http2Config,
    state: StdRwLock<HostPoolState<C>>,
    connector: C,
}

impl<C> HostPool<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    fn new(connector: C, http2: Http2Config) -> Self {
        Self {
            http2,
            state: StdRwLock::new(HostPoolState {
                clients: Vec::new(),
                detached: false,
            }),
            connector,
        }
    }

    fn create_client(&self) -> PooledClient<C> {
        let mut builder = HyperClient::builder(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .http2_only(true)
            .http2_keep_alive_interval(Duration::from_secs(20))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_initial_stream_window_size(self.http2.stream_receive_window)
            .http2_initial_connection_window_size(self.http2.connection_receive_window);
        let max_concurrent_requests = self
            .http2
            .max_concurrent_requests
            .unwrap_or(MAX_CONCURRENT_REQUESTS_PER_CLIENT);
        PooledClient::new(
            builder.build(self.connector.clone()),
            max_concurrent_requests,
        )
    }

    fn checkout(&self) -> Option<CheckedOutClient<C>> {
        {
            let state = self.state.read().unwrap();
            if state.detached {
                return None;
            }
            for pooled in &state.clients {
                if let Some(permit) = pooled.request_permit() {
                    return Some(CheckedOutClient {
                        client: pooled.client.clone(),
                        permit,
                        id: pooled.id,
                    });
                }
            }
        }
        let mut state = self.state.write().unwrap();
        if state.detached {
            return None;
        }
        for pooled in &state.clients {
            if let Some(permit) = pooled.request_permit() {
                return Some(CheckedOutClient {
                    client: pooled.client.clone(),
                    permit,
                    id: pooled.id,
                });
            }
        }
        let new_client = self.create_client();
        let permit = new_client
            .request_permit()
            .expect("new client must have a permit");
        let client = new_client.client.clone();
        let id = new_client.id;
        state.clients.push(new_client);
        Some(CheckedOutClient { client, permit, id })
    }

    /// Drop the pooled client identified by `id` so no new request reuses it.
    /// Clients pinned to servers that are not going away stay pooled, requests
    /// already in flight keep their connection, and poisoning the same
    /// connection again is a no-op.
    fn poison(&self, host: &str, id: ConnectionId) {
        let mut state = self.state.write().unwrap();
        let pooled = state.clients.len();
        state.clients.retain(|pooled| pooled.id != id);
        let removed = pooled - state.clients.len();
        tracing::debug!(host, connection = ?id, removed, "poisoned pooled connections");
    }

    fn clear_and_detach(&self) {
        let mut state = self.state.write().unwrap();
        state.clients.clear();
        state.detached = true;
    }

    fn reap_idle_clients(&self) {
        let mut state = self.state.write().unwrap();
        state
            .clients
            .retain(|pooled| !pooled.should_reap(IDLE_TIMEOUT));
    }

    /// Atomically detach this host pool if it currently has no pooled clients.
    fn detach_if_empty(&self) -> bool {
        let Ok(mut state) = self.state.try_write() else {
            return false;
        };
        if state.clients.is_empty() {
            state.detached = true;
            true
        } else {
            false
        }
    }
}

struct PoolHosts<C> {
    closed: bool,
    map: HashMap<String, Arc<HostPool<C>>>,
}

pub struct Pool<C> {
    http2: Http2Config,
    hosts: Arc<StdRwLock<PoolHosts<C>>>,
    connector: C,
    shutdown: ShutdownSignal,
    reaper: OnceLock<AbortOnDropHandle<()>>,
}

impl<C> Pool<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(connector: C, http2: Http2Config, shutdown: ShutdownSignal) -> Self {
        let hosts = Arc::new(StdRwLock::new(PoolHosts {
            closed: false,
            map: HashMap::new(),
        }));

        Self {
            http2,
            hosts,
            connector,
            shutdown,
            reaper: OnceLock::new(),
        }
    }

    fn ensure_reaper_started(&self) {
        self.reaper.get_or_init(|| {
            let hosts = self.hosts.clone();
            let shutdown = self.shutdown.clone();
            AbortOnDropHandle::new(tokio::spawn(async move {
                let mut interval = tokio::time::interval(REAPER_INTERVAL);
                let mut shutdown_fut = shutdown.cancelled();
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut shutdown_fut => break,
                        _ = interval.tick() => {
                            reap_idle_clients(&hosts);
                        }
                    }
                }
            }))
        });
    }

    fn get_or_create_host_pool(&self, host: &str) -> Result<Arc<HostPool<C>>, HttpError> {
        {
            let hosts = self.hosts.read().unwrap();
            if hosts.closed {
                return Err(HttpError::ClientClosed);
            }
            if let Some(pool) = hosts.map.get(host) {
                return Ok(pool.clone());
            }
        }
        let mut hosts = self.hosts.write().unwrap();
        if hosts.closed {
            return Err(HttpError::ClientClosed);
        }
        Ok(hosts
            .map
            .entry(host.to_owned())
            .or_insert_with(|| Arc::new(HostPool::new(self.connector.clone(), self.http2)))
            .clone())
    }

    fn checkout_for_host(
        &self,
        host: &str,
    ) -> Result<(Arc<HostPool<C>>, CheckedOutClient<C>), HttpError> {
        loop {
            let pool = self.get_or_create_host_pool(host)?;
            if let Some(checked_out) = pool.checkout() {
                return Ok((pool, checked_out));
            }
            // The host pool was detached concurrently by the idle reaper or close(); loop to
            // re-check closed state or allocate a fresh host pool.
        }
    }

    #[cfg(test)]
    fn checkout(&self, host: &str) -> (Arc<HyperClient<C, BoxBody>>, RequestPermit, ConnectionId) {
        let (_pool, checked_out) = self.checkout_for_host(host).expect("pool open");
        (checked_out.client, checked_out.permit, checked_out.id)
    }

    fn make_poison_handle(pool: &Arc<HostPool<C>>, host: String, id: ConnectionId) -> PoisonHandle {
        // Weak: the handle can outlive the pool (a session holds it for the
        // connection's lifetime) and must not keep a reaped pool alive.
        let weak = Arc::downgrade(pool);
        PoisonHandle::new(move || {
            if let Some(pool) = weak.upgrade() {
                pool.poison(&host, id);
            }
        })
    }
}

fn reap_idle_clients<C: Connect + Clone + Send + Sync + 'static>(hosts: &StdRwLock<PoolHosts<C>>) {
    let pools: Vec<Arc<HostPool<C>>> = {
        let hosts = hosts.read().unwrap();
        hosts.map.values().cloned().collect()
    };

    for pool in &pools {
        pool.reap_idle_clients();
    }

    hosts
        .write()
        .unwrap()
        .map
        .retain(|_, pool| !pool.detach_if_empty());
}

#[async_trait]
impl<C> RequestExecutor for Pool<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    async fn execute_unary(&self, request: Request) -> Result<UnaryResponse, HttpError> {
        if self.shutdown.is_closed() {
            return Err(HttpError::ClientClosed);
        }
        self.ensure_reaper_started();
        let origin = request.origin();
        let (
            pool,
            CheckedOutClient {
                client,
                permit: _permit,
                id,
            },
        ) = self.checkout_for_host(&origin)?;
        let poison_handle = Self::make_poison_handle(&pool, origin, id);
        let shutdown = self.shutdown.clone();
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => Err(HttpError::Aborted),
            res = execute_unary_with(&client, request, poison_handle) => res,
        }
    }

    async fn init_streaming(&self, request: Request) -> Result<StreamingResponse, HttpError> {
        if self.shutdown.is_closed() {
            return Err(HttpError::ClientClosed);
        }
        self.ensure_reaper_started();
        let origin = request.origin();
        let (pool, CheckedOutClient { client, permit, id }) = self.checkout_for_host(&origin)?;
        let poison_handle = Self::make_poison_handle(&pool, origin, id);
        let shutdown = self.shutdown.clone();
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => Err(HttpError::Aborted),
            res = init_streaming_with(&client, request, permit, poison_handle) => res,
        }
    }

    fn close(&self) {
        self.shutdown.close();
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
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    use rustls::client::danger::ServerCertVerifier;

    use super::*;

    const TEST_HOST: &str = "localhost:8080";

    fn test_pool() -> Pool<HttpConnector> {
        Pool::new(
            HttpConnector::new(),
            Http2Config::new(),
            ShutdownSignal::new(),
        )
    }

    #[test]
    fn default_headers_preserve_multiple_values_and_sensitive_flags_on_wire_request() {
        let mut headers = HeaderMap::new();
        headers.append("x-tag", HeaderValue::from_static("first"));
        let mut second = HeaderValue::from_static("second");
        second.set_sensitive(true);
        headers.append("x-tag", second);
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("wrong-encoding"));

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
            Some(HeaderValue::from_static("gzip")),
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
    fn uri_with_path_percent_encoded_segment() {
        let base: Uri = "https://example.com".parse().unwrap();

        let uri = uri_with_path(
            &base,
            format!("v1/access-tokens/{}", urlencoding::encode("a/b?c d")),
        );

        assert_eq!(uri, "https://example.com/v1/access-tokens/a%2Fb%3Fc%20d");
    }

    #[test]
    fn query_appends_to_existing_query() {
        #[derive(serde::Serialize)]
        struct Params<'a> {
            prefix: &'a str,
        }

        let uri: Uri = "https://example.com/v1/streams?limit=1".parse().unwrap();
        let request = RequestBuilder::get(uri)
            .query(&Params { prefix: "a/b c" })
            .build()
            .unwrap();

        assert_eq!(
            request.uri,
            "https://example.com/v1/streams?limit=1&prefix=a%2Fb+c"
        );
    }

    fn host_client_count(pool: &Pool<HttpConnector>, host: &str) -> usize {
        let hosts = pool.hosts.read().unwrap();
        match hosts.map.get(host) {
            Some(pool) => pool.state.read().unwrap().clients.len(),
            None => 0,
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

    // spec: r1 C13a
    #[tokio::test]
    async fn checkout_within_capacity() {
        assert_eq!(MAX_CONCURRENT_REQUESTS_PER_CLIENT, 50);
        let pool = test_pool();
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS_PER_CLIENT {
            let (_client, permit, _) = pool.checkout(TEST_HOST);
            permits.push(permit);
        }
        assert_eq!(host_client_count(&pool, TEST_HOST), 1);
    }

    // spec: r1 C13a
    #[tokio::test]
    async fn overflow_creates_new_client() {
        let pool = test_pool();
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS_PER_CLIENT {
            let (_client, permit, _) = pool.checkout(TEST_HOST);
            permits.push(permit);
        }
        assert_eq!(host_client_count(&pool, TEST_HOST), 1);

        let (_client, permit, _) = pool.checkout(TEST_HOST);
        permits.push(permit);
        assert_eq!(host_client_count(&pool, TEST_HOST), 2);
    }

    // spec: r1 C13
    #[tokio::test]
    async fn poison_evicts_only_targeted_connection_preserving_siblings() {
        let http2 = Http2Config::new().with_max_concurrent_requests(1).unwrap();
        let pool = Pool::new(HttpConnector::new(), http2, ShutdownSignal::new());
        let (_c1, p1, id1) = pool.checkout(TEST_HOST);
        let (_c2, p2, id2) = pool.checkout(TEST_HOST);
        assert_ne!(id1, id2);
        assert_eq!(host_client_count(&pool, TEST_HOST), 2);

        let host_pool = pool.get_or_create_host_pool(TEST_HOST).unwrap();
        host_pool.poison(TEST_HOST, id1);
        assert_eq!(host_client_count(&pool, TEST_HOST), 1);

        // Freeing the healthy sibling's permit allows reusing it rather than dialing a new one.
        drop(p2);
        let (_c3, p3, id3) = pool.checkout(TEST_HOST);
        assert_eq!(id3, id2);
        assert_eq!(host_client_count(&pool, TEST_HOST), 1);
        drop((p1, p3));
    }

    // spec: r1 C13a
    #[tokio::test]
    async fn custom_request_cap_bounds_client() {
        let http2 = Http2Config::new().with_max_concurrent_requests(2).unwrap();
        let pool = Pool::new(HttpConnector::new(), http2, ShutdownSignal::new());
        let mut permits = Vec::new();
        for _ in 0..2 {
            let (_client, permit, _) = pool.checkout(TEST_HOST);
            permits.push(permit);
        }
        assert_eq!(host_client_count(&pool, TEST_HOST), 1);

        let (_client, permit, _) = pool.checkout(TEST_HOST);
        permits.push(permit);
        assert_eq!(host_client_count(&pool, TEST_HOST), 2);
    }

    // spec: r1 C13a
    #[tokio::test]
    async fn permit_drop_frees_capacity() {
        let pool = test_pool();
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS_PER_CLIENT {
            let (_client, permit, _) = pool.checkout(TEST_HOST);
            permits.push(permit);
        }
        permits.pop();

        let (_client, permit, _) = pool.checkout(TEST_HOST);
        permits.push(permit);
        assert_eq!(host_client_count(&pool, TEST_HOST), 1);
    }

    // spec: r1 C13c
    #[tokio::test]
    async fn reaper_removes_idle_clients() {
        let pool = test_pool();
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS_PER_CLIENT {
            let (_client, permit, _) = pool.checkout(TEST_HOST);
            permits.push(permit);
        }
        let (_client, permit, _) = pool.checkout(TEST_HOST);
        permits.push(permit);
        assert_eq!(host_client_count(&pool, TEST_HOST), 2);

        permits.clear();
        {
            let hosts = pool.hosts.read().unwrap();
            let pool = hosts.map.get(TEST_HOST).unwrap();
            let state = pool.state.read().unwrap();
            for pooled in &state.clients {
                pooled.state.lock().unwrap().idle_since =
                    Some(Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1));
            }
        }

        reap_idle_clients(&pool.hosts);
        assert_eq!(host_client_count(&pool, TEST_HOST), 0);
        assert!(!pool.hosts.read().unwrap().map.contains_key(TEST_HOST));
    }

    // spec: r1 C13
    #[tokio::test]
    async fn different_hosts_get_independent_pools() {
        let pool = test_pool();
        let host_a = "https://host-a:443";
        let host_b = "https://host-b:443";

        let mut permits_a = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS_PER_CLIENT {
            let (_client, permit, _) = pool.checkout(host_a);
            permits_a.push(permit);
        }
        assert_eq!(host_client_count(&pool, host_a), 1);

        let (_client, permit_b, _) = pool.checkout(host_b);
        assert_eq!(host_client_count(&pool, host_b), 1);
        assert_eq!(host_client_count(&pool, host_a), 1);

        drop(permit_b);
        drop(permits_a);
    }

    // spec: r1 C13c
    #[tokio::test]
    async fn reaper_removes_empty_host_entries() {
        let pool = test_pool();

        let (_client, permit_a, _) = pool.checkout("https://host-a");
        let (_client, permit_b, _) = pool.checkout("https://host-b");
        assert_eq!(pool.hosts.read().unwrap().map.len(), 2);

        drop(permit_a);
        {
            let hosts = pool.hosts.read().unwrap();
            let pool_a = hosts.map.get("https://host-a").unwrap();
            let state = pool_a.state.read().unwrap();
            for pooled in &state.clients {
                pooled.state.lock().unwrap().idle_since =
                    Some(Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1));
            }
        }

        reap_idle_clients(&pool.hosts);

        let hosts = pool.hosts.read().unwrap();
        assert!(!hosts.map.contains_key("https://host-a"));
        assert!(hosts.map.contains_key("https://host-b"));

        drop(permit_b);
    }

    #[test]
    fn shutdown_signal_close_updates_state_with_zero_receivers() {
        let signal = ShutdownSignal::new();
        assert!(!signal.is_closed());
        signal.close();
        assert!(signal.is_closed());
    }

    #[test]
    fn pool_construction_does_not_require_tokio_runtime() {
        let pool = test_pool();
        pool.close();
    }

    #[test]
    fn request_origin_normalizes_case_and_default_ports() {
        let r1 = RequestBuilder::get("HTTP://Example.COM:80/v1".parse().unwrap())
            .build()
            .unwrap();
        let r2 = RequestBuilder::get("http://example.com/v1".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(r1.origin(), "http://example.com");
        assert_eq!(r1.origin(), r2.origin());

        let r3 = RequestBuilder::get("HTTPS://A.S2.DEV:443/v1".parse().unwrap())
            .build()
            .unwrap();
        let r4 = RequestBuilder::get("https://a.s2.dev/v1".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(r3.origin(), "https://a.s2.dev");
        assert_eq!(r3.origin(), r4.origin());

        let r5 = RequestBuilder::get("https://a.s2.dev:8443/v1".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(r5.origin(), "https://a.s2.dev:8443");
    }

    #[tokio::test]
    async fn compress_body_skips_empty_body() {
        for compression in [Compression::Gzip, Compression::Zstd] {
            let (body, enc) = compress_body(Body::empty(), compression).await.unwrap();
            assert!(enc.is_none());
            assert!(matches!(body.0, BodyInner::Empty));
        }
    }
}
