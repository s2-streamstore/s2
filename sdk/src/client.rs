use std::{
    cell::RefCell,
    collections::HashMap,
    future::Future,
    io::{Read as _, Write as _},
    pin::{Pin, pin},
    sync::{
        Arc, RwLock as StdRwLock, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

#[cfg(feature = "_hidden")]
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use flate2::{Compression as FlateCompression, bufread::MultiGzDecoder, write::GzEncoder};
use futures_core::Stream;
use futures_util::StreamExt;
use http::{
    HeaderMap, Method, StatusCode, Uri,
    header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderName, HeaderValue},
    uri::PathAndQuery,
};
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    body::{Frame, Incoming},
    client::conn::http2,
    rt::{Read as HyperRead, Write as HyperWrite},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioTimer};
use pin_project_lite::pin_project;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    sync::{Notify, watch},
    time::{Instant, Sleep, timeout},
};
pub(crate) use tokio_util::sync::CancellationToken;
use tower_service::Service;

use crate::{
    error::find_source_err,
    send_gate::{GatedRequestBody, SendGate},
    types::{Compression, Http2Config},
};

const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");
const DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CONNECTION: usize = 50;
// 50 concurrent streams × 4 MiB = 200 MiB < 256 MiB, so paused read sessions on a shared
// connection cannot exhaust the connection-level flow-control window and stall sibling appends
// or unary calls.
pub(crate) const DEFAULT_STREAM_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;
const DEFAULT_CONNECTION_RECEIVE_WINDOW: u32 = 256 * 1024 * 1024;
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

pin_project! {
    #[project = HttpBodyProj]
    pub(crate) enum HttpBody {
        Empty,
        Full {
            #[pin]
            inner: Full<Bytes>,
        },
        GatedFull {
            #[pin]
            inner: GatedRequestBody<Full<Bytes>>,
        },
        Streaming {
            #[pin]
            inner: BoxBody,
        },
    }
}

impl http_body::Body for HttpBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            HttpBodyProj::Empty => Poll::Ready(None),
            HttpBodyProj::Full { inner } => match inner.poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
                Poll::Ready(Some(Err(never))) => match never {},
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            HttpBodyProj::GatedFull { inner } => inner.poll_frame(cx),
            HttpBodyProj::Streaming { inner } => inner.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Full { inner } => inner.is_end_stream(),
            Self::GatedFull { inner } => inner.is_end_stream(),
            Self::Streaming { inner } => inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Empty => http_body::SizeHint::with_exact(0),
            Self::Full { inner } => inner.size_hint(),
            Self::GatedFull { inner } => inner.size_hint(),
            Self::Streaming { inner } => inner.size_hint(),
        }
    }
}

enum BodyInner {
    Empty,
    Full(Bytes),
    GatedFull(Bytes, SendGate),
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

    fn gated(self, gate: SendGate) -> Self {
        match self.0 {
            BodyInner::Full(bytes) => {
                debug_assert!(
                    !bytes.is_empty(),
                    "gated body should be non-empty so SendGate can observe frames"
                );
                Self(BodyInner::GatedFull(bytes, gate))
            }
            other => {
                debug_assert!(
                    false,
                    "gated body is only used for non-empty unary full bodies"
                );
                Self(other)
            }
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        match &self.0 {
            BodyInner::Empty => Some(&[]),
            BodyInner::Full(bytes) => Some(bytes),
            BodyInner::GatedFull(_, _) | BodyInner::Streaming(_) => None,
        }
    }

    fn into_http_body(self) -> HttpBody {
        match self.0 {
            BodyInner::Empty => HttpBody::Empty,
            BodyInner::Full(bytes) => HttpBody::Full {
                inner: Full::new(bytes),
            },
            BodyInner::GatedFull(bytes, gate) => HttpBody::GatedFull {
                inner: GatedRequestBody::new(Full::new(bytes), gate),
            },
            BodyInner::Streaming(inner) => HttpBody::Streaming { inner },
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

fn with_origin_key<R>(uri: &Uri, f: impl FnOnce(&str) -> R) -> R {
    let scheme = uri.scheme_str().unwrap_or("https");
    let host = uri.host().unwrap_or("");
    let port = uri.port_u16().filter(|&p| {
        !((scheme.eq_ignore_ascii_case("http") && p == 80)
            || (scheme.eq_ignore_ascii_case("https") && p == 443))
    });

    let mut port_buf = [0u8; 6];
    let port_bytes: &[u8] = if let Some(mut n) = port {
        let mut pos = port_buf.len();
        if n == 0 {
            pos -= 1;
            port_buf[pos] = b'0';
        } else {
            while n > 0 {
                pos -= 1;
                port_buf[pos] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        pos -= 1;
        port_buf[pos] = b':';
        &port_buf[pos..]
    } else {
        &[]
    };

    let total_len = scheme.len() + 3 + host.len() + port_bytes.len();
    let mut stack = [0u8; 280];
    if total_len <= stack.len() {
        let mut offset = 0;
        for &b in scheme.as_bytes() {
            stack[offset] = b.to_ascii_lowercase();
            offset += 1;
        }
        stack[offset..offset + 3].copy_from_slice(b"://");
        offset += 3;
        for &b in host.as_bytes() {
            stack[offset] = b.to_ascii_lowercase();
            offset += 1;
        }
        stack[offset..offset + port_bytes.len()].copy_from_slice(port_bytes);
        offset += port_bytes.len();
        let key = std::str::from_utf8(&stack[..offset])
            .expect("ASCII-lowercased URI origin is valid UTF-8");
        return f(key);
    }

    let mut owned = String::with_capacity(total_len);
    for b in scheme.bytes() {
        owned.push(char::from(b.to_ascii_lowercase()));
    }
    owned.push_str("://");
    for c in host.chars() {
        owned.push(c.to_ascii_lowercase());
    }
    owned.push_str(std::str::from_utf8(port_bytes).expect("ASCII port"));
    f(&owned)
}

pub(crate) struct Request {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
    timeout: Option<Duration>,
}

impl Request {
    pub(crate) fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub(crate) fn has_non_empty_body(&self) -> bool {
        matches!(&self.body.0, BodyInner::Full(bytes) if !bytes.is_empty())
    }

    pub(crate) fn with_gated_body(self, gate: SendGate) -> Self {
        Self {
            body: self.body.gated(gate),
            ..self
        }
    }

    pub(crate) fn compress(self, compression: Compression) -> Result<Self, HttpError> {
        let (body, content_encoding) = compress_body(self.body, compression)?;
        let mut headers = self.headers;
        if let Some(encoding) = content_encoding {
            headers
                .try_insert(CONTENT_ENCODING, encoding)
                .map_err(|e| HttpError::RequestBuild(e.to_string()))?;
        }
        Ok(Self {
            body,
            headers,
            ..self
        })
    }

    #[cfg(test)]
    fn origin(&self) -> String {
        with_origin_key(&self.uri, str::to_owned)
    }

    pub(crate) fn try_clone(&self) -> Option<Self> {
        let body = match &self.body.0 {
            BodyInner::Empty => Body::empty(),
            BodyInner::Full(bytes) => Body(BodyInner::Full(bytes.clone())),
            BodyInner::GatedFull(_, _) | BodyInner::Streaming(_) => return None,
        };

        Some(Self {
            method: self.method.clone(),
            uri: self.uri.clone(),
            headers: self.headers.clone(),
            body,
            timeout: self.timeout,
        })
    }
}

pub(crate) struct RequestBuilder {
    method: Method,
    uri: Uri,
    query: String,
    headers: HeaderMap,
    body: Option<Body>,
    timeout: Option<Duration>,
    error: Option<HttpError>,
}

impl RequestBuilder {
    fn new(method: Method, uri: Uri) -> Self {
        Self {
            method,
            uri,
            query: String::new(),
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
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
                    if self.query.is_empty() {
                        self.query = query_string;
                    } else {
                        self.query.push('&');
                        self.query.push_str(&query_string);
                    }
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
                if let Err(e) = self.headers.try_insert(CONTENT_TYPE, APPLICATION_JSON) {
                    self.error = Some(HttpError::RequestBuild(e.to_string()));
                } else {
                    self.body = Some(Body::from(data));
                }
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
                if let Err(e) = self.headers.try_insert(name, value) {
                    self.error = Some(HttpError::RequestBuild(e.to_string()));
                }
            }
            (Err(e), _) => self.error = Some(HttpError::RequestBuild(e.into().to_string())),
            (_, Err(e)) => self.error = Some(HttpError::RequestBuild(e.into().to_string())),
        }
        self
    }

    pub(crate) fn headers(mut self, headers: &HeaderMap) -> Self {
        if self.error.is_some() {
            return self;
        }
        if self.headers.is_empty() {
            self.headers = headers.clone();
        } else {
            // Preserve replacement semantics for existing keys while remaining fallible near
            // `HeaderMap`'s capacity limit.
            for key in headers.keys() {
                self.headers.remove(key);
            }
            for (key, value) in headers {
                if let Err(e) = self.headers.try_append(key.clone(), value.clone()) {
                    self.error = Some(HttpError::RequestBuild(e.to_string()));
                    break;
                }
            }
        }
        self
    }

    pub(crate) fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub(crate) fn build(mut self) -> Result<Request, HttpError> {
        if let Some(e) = self.error {
            return Err(e);
        }

        if !self.query.is_empty() {
            self.uri = uri_with_query(&self.uri, &self.query)
                .map_err(|e| HttpError::RequestBuild(e.to_string()))?;
        }

        Ok(Request {
            method: self.method,
            uri: self.uri,
            headers: self.headers,
            body: self.body.unwrap_or_default(),
            timeout: self.timeout,
        })
    }
}

pub(crate) struct UnaryResponse {
    status: StatusCode,
    headers: HeaderMap,
    bytes: Bytes,
    retire_handle: Option<RetireHandle>,
}

impl UnaryResponse {
    #[cfg(all(test, feature = "_hidden"))]
    pub(crate) fn new_for_test(status: StatusCode, bytes: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            bytes: bytes.into(),
            retire_handle: None,
        }
    }

    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub(crate) fn take_retire_handle(&mut self) -> Option<RetireHandle> {
        self.retire_handle.take()
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

trait RetireTarget: Send + Sync {
    fn retire(&self, id: ConnectionId);
}

/// Grants its holder the ability to retire the pooled HTTP/2 connection a response
/// arrived on so no new request reuses it while in-flight requests finish (`T6`, `C13`).
///
/// Retirement is idempotent and allocates nothing per request.
#[derive(Clone)]
pub(crate) struct RetireHandle {
    target: Weak<dyn RetireTarget>,
    id: ConnectionId,
}

impl RetireHandle {
    fn new(target: Weak<dyn RetireTarget>, id: ConnectionId) -> Self {
        Self { target, id }
    }

    pub(crate) fn retire(&self) {
        if let Some(target) = self.target.upgrade() {
            target.retire(self.id);
        }
    }
}

fn is_dead_connection_hyper_error(err: &hyper::Error) -> bool {
    err.is_timeout()
        || err.is_closed()
        || find_source_err::<h2::Error>(err)
            .is_some_and(|h2_err| h2_err.is_io() || h2_err.is_go_away())
}

pub(crate) struct StreamingResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Incoming,
    permit: RequestPermit,
    retire_handle: RetireHandle,
    deadline: Option<Instant>,
}

impl StreamingResponse {
    fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Incoming,
        permit: RequestPermit,
        retire_handle: RetireHandle,
        deadline: Option<Instant>,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            permit,
            retire_handle,
            deadline,
        }
    }

    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    /// Collect the body of a non-2xx streaming response (`E2`).
    ///
    /// Once non-2xx headers have arrived, a timeout or body read/decompression failure retires
    /// the connection and falls back to empty bytes so
    /// [`ServerError`](crate::error::ServerError) preserves the HTTP status instead of turning e.g.
    /// `404` or `412` into a retryable timeout.
    pub(crate) async fn into_bytes_with_retire_handle(self) -> (Bytes, RetireHandle) {
        let Self {
            status,
            headers,
            body,
            permit,
            retire_handle,
            deadline,
        } = self;
        let mut sleep = pin!(deadline.map(tokio::time::sleep_until));
        let bytes = collect_and_decompress_error_body(
            status,
            &headers,
            body,
            sleep.as_mut().as_pin_mut(),
            &retire_handle,
        )
        .await;
        drop(permit);
        (bytes, retire_handle)
    }

    pub(crate) fn into_stream(
        self,
    ) -> (impl Stream<Item = Result<Bytes, HttpError>>, RetireHandle) {
        let Self {
            body,
            permit,
            retire_handle,
            ..
        } = self;
        let stream_retire = retire_handle.clone();
        let stream = http_body_util::BodyStream::new(body).filter_map(move |result| {
            let _ = &permit;
            std::future::ready(match result {
                Ok(frame) => frame.into_data().ok().map(Ok),
                Err(e) => {
                    if is_dead_connection_hyper_error(&e) {
                        stream_retire.retire();
                    }
                    Some(Err(HttpError::Transport(e)))
                }
            })
        });
        (stream, retire_handle)
    }
}

/// Poll `fut` racing an optional pinned `Sleep` deadline, polling `fut` first so already-ready
/// futures never register on the Tokio timer wheel.
async fn race_deadline<F: Future>(
    fut: F,
    mut sleep: Option<Pin<&mut Sleep>>,
) -> Result<F::Output, ()> {
    let mut fut = pin!(fut);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(out) = fut.as_mut().poll(cx) {
            return Poll::Ready(Ok(out));
        }
        if let Some(sleep) = sleep.as_mut()
            && Pin::new(&mut tokio::task::coop::unconstrained(sleep.as_mut()))
                .poll(cx)
                .is_ready()
        {
            return Poll::Ready(Err(()));
        }
        Poll::Pending
    })
    .await
}

enum CollectBodyError<E> {
    Timeout,
    TooLarge,
    Transport(E),
}

async fn collect_bounded_body<B>(
    mut body: B,
    limit: usize,
    sleep: Option<Pin<&mut Sleep>>,
) -> Result<Bytes, CollectBodyError<B::Error>>
where
    B: http_body::Body<Data = Bytes> + Unpin,
{
    let lower_hint = body.size_hint().lower();
    if lower_hint > limit as u64 {
        return Err(CollectBodyError::TooLarge);
    }
    let prealloc_hint = usize::try_from(lower_hint)
        .unwrap_or(limit)
        .min(limit)
        .min(2 * 1024 * 1024);

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
                let mut combined = BytesMut::with_capacity(total.max(prealloc_hint));
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

    race_deadline(collect, sleep)
        .await
        .unwrap_or(Err(CollectBodyError::Timeout))
}

async fn collect_and_decompress_error_body(
    status: StatusCode,
    headers: &HeaderMap,
    body: Incoming,
    sleep: Option<Pin<&mut Sleep>>,
    retire_handle: &RetireHandle,
) -> Bytes {
    let bytes = match collect_bounded_body(body, MAX_ERROR_RESPONSE_BYTES, sleep).await {
        Ok(bytes) => bytes,
        Err(CollectBodyError::Timeout) => {
            // Dropping `body` resets the HTTP/2 stream; retiring the connection prevents
            // reusing a stalled peer while preserving the already-received HTTP status.
            tracing::debug!(
                status = status.as_u16(),
                "timed out reading non-2xx error body; preserving HTTP status"
            );
            retire_handle.retire();
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
                err = %format_error_chain(&err),
                "failed reading non-2xx error body; preserving HTTP status"
            );
            if is_dead_connection_hyper_error(&err) {
                retire_handle.retire();
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

#[cfg(feature = "_hidden")]
#[async_trait]
pub(crate) trait RequestExecutor: Send + Sync {
    async fn execute_unary(&self, request: Request) -> Result<UnaryResponse, HttpError>;
    async fn init_streaming(&self, request: Request) -> Result<StreamingResponse, HttpError>;
    fn close(&self) {}
}

pub(crate) enum ClientTransport {
    Http(Pool<HttpConnector>),
    Https(Pool<HttpsConnector<HttpConnector>>),
    #[cfg(feature = "_hidden")]
    Custom(Arc<dyn RequestExecutor>),
}

impl ClientTransport {
    pub(crate) async fn execute_unary(&self, request: Request) -> Result<UnaryResponse, HttpError> {
        match self {
            Self::Http(pool) => pool.execute_unary(request).await,
            Self::Https(pool) => pool.execute_unary(request).await,
            #[cfg(feature = "_hidden")]
            Self::Custom(exec) => exec.execute_unary(request).await,
        }
    }

    pub(crate) async fn init_streaming(
        &self,
        request: Request,
    ) -> Result<StreamingResponse, HttpError> {
        match self {
            Self::Http(pool) => pool.init_streaming(request).await,
            Self::Https(pool) => pool.init_streaming(request).await,
            #[cfg(feature = "_hidden")]
            Self::Custom(exec) => exec.init_streaming(request).await,
        }
    }

    pub(crate) fn close(&self) {
        match self {
            Self::Http(pool) => pool.close(),
            Self::Https(pool) => pool.close(),
            #[cfg(feature = "_hidden")]
            Self::Custom(exec) => exec.close(),
        }
    }
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
            .https_only()
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
                err = %native_err,
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
        .https_only()
        .enable_http2()
        .wrap_connector(connector))
}

#[cfg(feature = "rustls-aws-lc-rs")]
fn feature_default_rustls_crypto_provider() -> Option<Arc<rustls::crypto::CryptoProvider>> {
    Some(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

#[cfg(all(not(feature = "rustls-aws-lc-rs"), feature = "rustls-ring"))]
fn feature_default_rustls_crypto_provider() -> Option<Arc<rustls::crypto::CryptoProvider>> {
    Some(Arc::new(rustls::crypto::ring::default_provider()))
}

#[cfg(all(not(feature = "rustls-aws-lc-rs"), not(feature = "rustls-ring")))]
fn feature_default_rustls_crypto_provider() -> Option<Arc<rustls::crypto::CryptoProvider>> {
    None
}

fn resolve_rustls_crypto_provider_with(
    explicit: Option<Arc<rustls::crypto::CryptoProvider>>,
    process_default: Option<Arc<rustls::crypto::CryptoProvider>>,
    feature_default: Option<Arc<rustls::crypto::CryptoProvider>>,
) -> Result<Arc<rustls::crypto::CryptoProvider>, std::io::Error> {
    explicit
        .or(process_default)
        .or(feature_default)
        .ok_or_else(|| {
            std::io::Error::other(
                "no rustls crypto provider configured; configure \
                 S2Config::with_rustls_crypto_provider(...) or install a \
                 process-global provider with \
                 rustls::crypto::CryptoProvider::install_default()",
            )
        })
}

fn resolve_rustls_crypto_provider(
    provider: Option<Arc<rustls::crypto::CryptoProvider>>,
) -> Result<Arc<rustls::crypto::CryptoProvider>, std::io::Error> {
    resolve_rustls_crypto_provider_with(
        provider,
        rustls::crypto::CryptoProvider::get_default().cloned(),
        feature_default_rustls_crypto_provider(),
    )
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
    uri: Uri,
    headers: HeaderMap,
    body: HttpBody,
) -> Result<http::Request<HttpBody>, HttpError> {
    let mut builder = http::Request::builder().method(method).uri(uri);

    if let Some(req_headers) = builder.headers_mut() {
        *req_headers = headers;
    }

    builder
        .body(body)
        .map_err(|error| HttpError::RequestBuild(error.to_string()))
}

/// Builds a URI from `base`'s scheme and authority, replacing any path/query.
pub(crate) fn uri_with_path(base: &Uri, path: impl AsRef<str>) -> Uri {
    let path = path.as_ref();
    let pq = if path.starts_with('/') {
        PathAndQuery::try_from(path)
    } else {
        let mut prefixed = String::with_capacity(1 + path.len());
        prefixed.push('/');
        prefixed.push_str(path);
        PathAndQuery::try_from(prefixed)
    }
    .expect("SDK-generated path is a valid PathAndQuery");
    uri_with_path_and_query(base, pq).expect("SDK-generated path is a valid URI")
}

fn uri_with_query(uri: &Uri, query: &str) -> Result<Uri, http::Error> {
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let (path, existing_query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(path, query)| (path, query));
    let combined = if existing_query.is_empty() {
        let mut s = String::with_capacity(path.len() + 1 + query.len());
        s.push_str(path);
        s.push('?');
        s.push_str(query);
        s
    } else {
        let mut s = String::with_capacity(path.len() + 1 + existing_query.len() + 1 + query.len());
        s.push_str(path);
        s.push('?');
        s.push_str(existing_query);
        s.push('&');
        s.push_str(query);
        s
    };
    let pq = PathAndQuery::try_from(combined)?;
    uri_with_path_and_query(uri, pq)
}

fn uri_with_path_and_query(uri: &Uri, path_and_query: PathAndQuery) -> Result<Uri, http::Error> {
    let mut parts = http::uri::Parts::default();
    parts.scheme = uri.scheme().cloned().or_else(|| {
        uri.authority()
            .is_some()
            .then_some(http::uri::Scheme::HTTPS)
    });
    parts.authority = uri.authority().cloned();
    parts.path_and_query = Some(path_and_query);
    Ok(Uri::from_parts(parts)?)
}

const UNARY_ZSTD_ONE_SHOT_MAX_BYTES: usize = 4 * 1024 * 1024;

thread_local! {
    static UNARY_ZSTD_COMPRESSOR: RefCell<Option<zstd::bulk::Compressor<'static>>> =
        const { RefCell::new(None) };
    static UNARY_ZSTD_DCTX: RefCell<Option<zstd::zstd_safe::DCtx<'static>>> =
        const { RefCell::new(None) };
}

fn compress_zstd_unary(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(zstd::compress_bound(data.len()));
    let result = UNARY_ZSTD_COMPRESSOR.try_with(|cell| {
        let Ok(mut slot) = cell.try_borrow_mut() else {
            return None;
        };
        let compressor = match slot.as_mut() {
            Some(c) => c,
            None => match zstd::bulk::Compressor::new(1) {
                Ok(c) => slot.insert(c),
                Err(err) => return Some(Err(err)),
            },
        };
        Some(compressor.compress_to_buffer(data, &mut out))
    });
    if let Ok(Some(res)) = result {
        res?;
        return Ok(out);
    }
    let mut compressor = zstd::bulk::Compressor::new(1)?;
    compressor.compress_to_buffer(data, &mut out)?;
    Ok(out)
}

fn create_unary_dctx() -> std::io::Result<zstd::zstd_safe::DCtx<'static>> {
    // Use libzstd's default window limit (matching `zstd::stream::read::Decoder::new`) while
    // `read_bounded` / `exact_size` enforce `max_bytes` on decompressed output.
    zstd::zstd_safe::DCtx::try_create()
        .ok_or_else(|| std::io::Error::other("zstd could not allocate a decompression context"))
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
            let mut encoder =
                GzEncoder::new(Vec::with_capacity(data.len()), FlateCompression::fast());
            encoder
                .write_all(data)
                .map_err(|e| HttpError::RequestCompression(e.to_string()))?;
            let mut compressed = encoder
                .finish()
                .map_err(|e| HttpError::RequestCompression(e.to_string()))?;
            maybe_shrink_vec(&mut compressed, 4096);
            Ok((
                Body::from(compressed),
                Some(HeaderValue::from_static("gzip")),
            ))
        }
        Compression::Zstd => {
            let mut compressed = compress_zstd_unary(data)
                .map_err(|e| HttpError::RequestCompression(e.to_string()))?;
            maybe_shrink_vec(&mut compressed, 4096);
            Ok((
                Body::from(compressed),
                Some(HeaderValue::from_static("zstd")),
            ))
        }
    }
}

fn maybe_shrink_vec(buf: &mut Vec<u8>, min_slack: usize) {
    if buf.capacity() > buf.len().saturating_mul(2) && buf.capacity() - buf.len() > min_slack {
        buf.shrink_to_fit();
    }
}

fn read_bounded(
    reader: impl std::io::Read,
    initial_capacity: usize,
    max_bytes: usize,
) -> Result<Bytes, HttpError> {
    let limit = (max_bytes as u64) + 1;
    let mut decompressed = Vec::with_capacity(initial_capacity);
    reader
        .take(limit)
        .read_to_end(&mut decompressed)
        .map_err(|e| HttpError::ResponseCompression(e.to_string()))?;
    if decompressed.len() > max_bytes {
        return Err(HttpError::ResponseTooLarge(max_bytes));
    }
    maybe_shrink_vec(&mut decompressed, 16 * 1024);
    Ok(Bytes::from(decompressed))
}

fn decompress_gzip(bytes: Bytes, max_bytes: usize) -> Result<Bytes, HttpError> {
    let initial_capacity = bytes.len().saturating_mul(2).max(1024).min(max_bytes);
    read_bounded(
        MultiGzDecoder::new(bytes.as_ref()),
        initial_capacity,
        max_bytes,
    )
}

fn decompress_zstd_with_dctx(
    dctx: &mut zstd::zstd_safe::DCtx<'static>,
    src: &[u8],
    exact_size: Option<usize>,
    fallback_capacity: usize,
    max_bytes: usize,
) -> Result<Bytes, HttpError> {
    // Explicit session reset keeps DCtx reuse safe across all zstd 0.14.x patch versions.
    dctx.reset(zstd::zstd_safe::ResetDirective::SessionOnly)
        .map_err(|code| {
            HttpError::ResponseCompression(zstd::zstd_safe::get_error_name(code).to_owned())
        })?;

    if let Some(exact) = exact_size
        && !src.is_empty()
        && exact <= UNARY_ZSTD_ONE_SHOT_MAX_BYTES
    {
        let mut buf = Vec::with_capacity(exact);
        dctx.decompress(&mut buf, src).map_err(|code| {
            HttpError::ResponseCompression(zstd::zstd_safe::get_error_name(code).to_owned())
        })?;
        debug_assert!(buf.len() <= max_bytes);
        maybe_shrink_vec(&mut buf, 16 * 1024);
        return Ok(Bytes::from(buf));
    }

    let decoder = zstd::stream::read::Decoder::with_context(src, dctx);
    read_bounded(decoder, fallback_capacity, max_bytes)
}

/// Returns the exact total decompressed size when every frame in `data` declares its
/// `Frame_Content_Size` (stepping over skippable frames). Returns `None` if any frame omits its
/// content size, if `data` is malformed, or if the total overflows `usize`.
///
/// Unlike `zstd::bulk::Decompressor::upper_bound`, this never falls back to `ZSTD_decompressBound`
/// when a downstream crate enables `zstd/experimental`, so conservative block-size bounds can never
/// falsely reject valid below-limit streaming responses.
fn exact_zstd_decompressed_size(mut data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    let mut total = 0u64;
    while !data.is_empty() {
        let frame_len = zstd::zstd_safe::find_frame_compressed_size(data).ok()?;
        let content = zstd::zstd_safe::get_frame_content_size(data).ok()??;
        total = total.checked_add(content)?;
        data = data.get(frame_len..)?;
    }
    usize::try_from(total).ok()
}

fn decompress_zstd(bytes: Bytes, max_bytes: usize) -> Result<Bytes, HttpError> {
    let fallback_capacity = bytes.len().saturating_mul(2).max(1024).min(max_bytes);
    let exact_size = match exact_zstd_decompressed_size(bytes.as_ref()) {
        Some(exact) if exact > max_bytes => return Err(HttpError::ResponseTooLarge(max_bytes)),
        other => other,
    };

    let result = UNARY_ZSTD_DCTX.try_with(|cell| {
        let Ok(mut slot) = cell.try_borrow_mut() else {
            return None;
        };
        let dctx = match slot.as_mut() {
            Some(d) => d,
            None => match create_unary_dctx() {
                Ok(d) => slot.insert(d),
                Err(err) => {
                    return Some(Err(HttpError::ResponseCompression(err.to_string())));
                }
            },
        };
        Some(decompress_zstd_with_dctx(
            dctx,
            bytes.as_ref(),
            exact_size,
            fallback_capacity,
            max_bytes,
        ))
    });
    if let Ok(Some(res)) = result {
        return res;
    }

    let mut dctx =
        create_unary_dctx().map_err(|e| HttpError::ResponseCompression(e.to_string()))?;
    decompress_zstd_with_dctx(
        &mut dctx,
        bytes.as_ref(),
        exact_size,
        fallback_capacity,
        max_bytes,
    )
}

fn decompress_single(encoding: &str, bytes: Bytes, max_bytes: usize) -> Result<Bytes, HttpError> {
    if encoding.is_empty() || encoding.eq_ignore_ascii_case("identity") {
        Ok(bytes)
    } else if encoding.eq_ignore_ascii_case("gzip") {
        decompress_gzip(bytes, max_bytes)
    } else if encoding.eq_ignore_ascii_case("zstd") {
        decompress_zstd(bytes, max_bytes)
    } else {
        Err(HttpError::ResponseCompression(format!(
            "unsupported content-encoding: {}",
            encoding.to_ascii_lowercase()
        )))
    }
}

fn decompress_body(
    headers: &HeaderMap,
    mut bytes: Bytes,
    max_bytes: usize,
) -> Result<Bytes, HttpError> {
    let mut header_iter = headers.get_all(CONTENT_ENCODING).iter();
    let Some(first) = header_iter.next() else {
        return Ok(bytes);
    };
    if header_iter.next().is_none() {
        let s = first.to_str().map_err(|e| {
            HttpError::ResponseCompression(format!("invalid content-encoding: {e}"))
        })?;
        if !s.contains(',') {
            return decompress_single(s.trim(), bytes, max_bytes);
        }
    }

    let mut encodings = Vec::new();
    for raw in headers.get_all(CONTENT_ENCODING) {
        let s = raw.to_str().map_err(|e| {
            HttpError::ResponseCompression(format!("invalid content-encoding: {e}"))
        })?;
        for part in s.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("identity") {
                encodings.push(trimmed);
            }
        }
    }
    for encoding in encodings.into_iter().rev() {
        bytes = decompress_single(encoding, bytes, max_bytes)?;
    }
    Ok(bytes)
}

/// Bit 63 clear: active request count in bits `0..63`.
/// Bit 63 set: connection is idle; bits `0..63` hold nanoseconds since `epoch` on `owner_handle`'s
/// Tokio clock, or `PERMIT_IDLE_NEEDS_STAMP` when the last permit dropped during TLS teardown and
/// the owner task must stamp the idle time on its own clock.
const PERMIT_IDLE_BIT: u64 = 1 << 63;
const PERMIT_IDLE_NEEDS_STAMP: u64 = u64::MAX;
const PERMIT_MAX_ELAPSED_NANOS: u64 = (PERMIT_IDLE_NEEDS_STAMP & !PERMIT_IDLE_BIT) - 1;

struct PermitState {
    /// Owning Tokio runtime handle (captured when the connection is spawned). Sampling
    /// `epoch.elapsed()` on `owner_handle`'s clock keeps idle deadlines accurate across paused
    /// runtimes, while falling back to `PERMIT_IDLE_NEEDS_STAMP` during thread-local teardown so
    /// `RequestPermit::drop` never panics or aborts.
    owner_handle: Option<tokio::runtime::Handle>,
    epoch: Instant,
    packed: AtomicU64,
    idle_notify: Notify,
}

impl PermitState {
    fn new() -> Self {
        let owner_handle = tokio::runtime::Handle::try_current().ok();
        Self {
            owner_handle,
            epoch: Instant::now(),
            packed: AtomicU64::new(1),
            idle_notify: Notify::new(),
        }
    }

    #[cfg(test)]
    fn active_requests(&self) -> usize {
        let cur = self.packed.load(Ordering::Acquire);
        if cur & PERMIT_IDLE_BIT != 0 {
            0
        } else {
            cur as usize
        }
    }

    fn try_acquire(self: &Arc<Self>, effective_limit: usize) -> Option<RequestPermit> {
        let mut cur = self.packed.load(Ordering::Acquire);
        loop {
            let active = if cur & PERMIT_IDLE_BIT != 0 {
                0
            } else {
                cur as usize
            };
            if active >= effective_limit {
                return None;
            }
            let next = (active + 1) as u64;
            match self
                .packed
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(RequestPermit {
                        state: self.clone(),
                    });
                }
                Err(actual) => cur = actual,
            }
        }
    }

    fn decode_deadline(&self, raw: u64, idle_timeout: Duration) -> Option<Instant> {
        if raw & PERMIT_IDLE_BIT != 0 && raw != PERMIT_IDLE_NEEDS_STAMP {
            let elapsed_nanos = raw & !PERMIT_IDLE_BIT;
            Some(self.epoch + Duration::from_nanos(elapsed_nanos) + idle_timeout)
        } else {
            None
        }
    }

    /// Return the connection's idle expiry deadline on the owning runtime's clock.
    ///
    /// Called exclusively on the connection owner task (or unit tests on a live runtime). If the
    /// last permit dropped during TLS teardown (`PERMIT_IDLE_NEEDS_STAMP`), atomically stamps the
    /// idle transition on the owner clock now.
    fn idle_deadline(&self, idle_timeout: Duration) -> Option<Instant> {
        let mut cur = self.packed.load(Ordering::Acquire);
        loop {
            if cur == PERMIT_IDLE_NEEDS_STAMP {
                let elapsed_nanos =
                    self.epoch
                        .elapsed()
                        .as_nanos()
                        .min(u128::from(PERMIT_MAX_ELAPSED_NANOS)) as u64;
                let stamped = PERMIT_IDLE_BIT | elapsed_nanos;
                match self.packed.compare_exchange_weak(
                    cur,
                    stamped,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        return Some(
                            self.epoch + Duration::from_nanos(elapsed_nanos) + idle_timeout,
                        );
                    }
                    Err(actual) => cur = actual,
                }
            } else {
                return self.decode_deadline(cur, idle_timeout);
            }
        }
    }
}

struct RequestPermit {
    state: Arc<PermitState>,
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        let mut cur = self.state.packed.load(Ordering::Acquire);
        loop {
            debug_assert!(cur & PERMIT_IDLE_BIT == 0 && cur > 0);
            if cur > 1 {
                match self.state.packed.compare_exchange_weak(
                    cur,
                    cur - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return,
                    Err(actual) => cur = actual,
                }
            } else {
                let next = match crate::session::try_elapsed_on_runtime(
                    self.state.owner_handle.as_ref(),
                    self.state.epoch,
                ) {
                    Some(elapsed) => {
                        let elapsed_nanos =
                            elapsed.as_nanos().min(u128::from(PERMIT_MAX_ELAPSED_NANOS)) as u64;
                        PERMIT_IDLE_BIT | elapsed_nanos
                    }
                    None => PERMIT_IDLE_NEEDS_STAMP,
                };
                match self.state.packed.compare_exchange_weak(
                    cur,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        self.state.idle_notify.notify_one();
                        return;
                    }
                    Err(actual) => cur = actual,
                }
            }
        }
    }
}

#[derive(Clone)]
enum DialOutcome {
    Pending,
    Ready(http2::SendRequest<HttpBody>),
    Failed(Arc<String>),
    Aborted,
}

enum DialError {
    Connect(String),
    Aborted,
}

enum ConnectionState {
    Connecting(watch::Receiver<DialOutcome>),
    Ready(http2::SendRequest<HttpBody>),
}

struct PooledConnection {
    id: ConnectionId,
    max_concurrent_requests: usize,
    peer_max_streams: Arc<AtomicUsize>,
    state: Arc<PermitState>,
    conn: ConnectionState,
}

impl PooledConnection {
    fn new_connecting(
        id: ConnectionId,
        max_concurrent_requests: usize,
        rx: watch::Receiver<DialOutcome>,
    ) -> (Self, RequestPermit) {
        let state = Arc::new(PermitState::new());
        let permit = RequestPermit {
            state: state.clone(),
        };
        (
            Self {
                id,
                max_concurrent_requests,
                peer_max_streams: Arc::new(AtomicUsize::new(usize::MAX)),
                state,
                conn: ConnectionState::Connecting(rx),
            },
            permit,
        )
    }

    fn is_live(&self) -> bool {
        match &self.conn {
            ConnectionState::Ready(sender) => !sender.is_closed(),
            ConnectionState::Connecting(rx) => match &*rx.borrow() {
                DialOutcome::Pending => rx.has_changed().is_ok(),
                DialOutcome::Ready(sender) => !sender.is_closed(),
                DialOutcome::Failed(_) | DialOutcome::Aborted => false,
            },
        }
    }

    fn try_acquire_permit(&self) -> Option<RequestPermit> {
        let effective_limit = self
            .max_concurrent_requests
            .min(self.peer_max_streams.load(Ordering::Relaxed));
        self.state.try_acquire(effective_limit)
    }

    fn idle_deadline(&self, idle_timeout: Duration) -> Option<Instant> {
        self.state.idle_deadline(idle_timeout)
    }
}

enum Checkout {
    Ready {
        id: ConnectionId,
        sender: http2::SendRequest<HttpBody>,
        permit: RequestPermit,
    },
    Connecting {
        id: ConnectionId,
        rx: watch::Receiver<DialOutcome>,
        permit: RequestPermit,
    },
}

struct CheckedOutSender {
    sender: http2::SendRequest<HttpBody>,
    permit: RequestPermit,
    retire_handle: RetireHandle,
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
    hosts: Weak<StdRwLock<PoolHosts<C>>>,
}

impl<C> RetireTarget for HostPool<C>
where
    C: Send + Sync,
{
    fn retire(&self, id: ConnectionId) {
        if self.remove(id) {
            tracing::debug!(
                origin = %self.origin,
                connection = id.0,
                "retired pooled connection"
            );
        }
    }
}

impl<C> HostPool<C> {
    fn remove(&self, id: ConnectionId) -> bool {
        let mut state = self.state.write().unwrap();
        let before = state.connections.len();
        state.connections.retain(|conn| conn.id != id);
        state.connections.len() < before
    }

    fn remove_and_is_empty(&self, id: ConnectionId) -> bool {
        let mut state = self.state.write().unwrap();
        state.connections.retain(|conn| conn.id != id);
        state.connections.is_empty()
    }

    /// Evict connection `id` if it is no longer live or has been idle for at least `idle_timeout`,
    /// returning `(evicted, pool_is_now_empty)` (`C13c`).
    fn evict_if_idle(
        &self,
        id: ConnectionId,
        now: Instant,
        idle_timeout: Duration,
    ) -> (bool, bool) {
        let mut state = self.state.write().unwrap();
        let Some(pos) = state.connections.iter().position(|c| c.id == id) else {
            return (true, state.connections.is_empty());
        };
        let expired = !state.connections[pos].is_live()
            || state.connections[pos]
                .idle_deadline(idle_timeout)
                .is_some_and(|deadline| deadline <= now);
        if !expired {
            return (false, false);
        }
        state.connections.swap_remove(pos);
        (true, state.connections.is_empty())
    }

    /// Atomically detach and remove this host pool from `Pool::hosts` if it has no connections.
    fn prune_if_empty(self: &Arc<Self>) {
        if let Some(hosts) = self.hosts.upgrade() {
            let mut hosts = hosts.write().unwrap();
            if let Some(entry) = hosts.map.get(&self.origin)
                && Arc::ptr_eq(entry, self)
                && self.detach_if_empty()
            {
                hosts.map.remove(&self.origin);
            }
        }
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
        hosts: Weak<StdRwLock<PoolHosts<C>>>,
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
            hosts,
        }
    }

    fn max_concurrent_requests(&self) -> usize {
        effective_max_concurrent_requests(self.http2)
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
        let (pooled, permit) =
            PooledConnection::new_connecting(id, self.max_concurrent_requests(), rx.clone());
        let peer_max_streams = pooled.peer_max_streams.clone();
        let permit_state = pooled.state.clone();
        state.connections.push(pooled);
        drop(state);

        self.spawn_connection(id, tx, peer_max_streams, permit_state);

        Some(Checkout::Connecting { id, rx, permit })
    }

    fn spawn_connection(
        self: &Arc<Self>,
        id: ConnectionId,
        tx: watch::Sender<DialOutcome>,
        peer_max_streams: Arc<AtomicUsize>,
        permit_state: Arc<PermitState>,
    ) {
        struct RemoveOnDrop<C: Connect> {
            pool: Weak<HostPool<C>>,
            id: ConnectionId,
        }
        impl<C: Connect> Drop for RemoveOnDrop<C> {
            fn drop(&mut self) {
                if let Some(pool) = self.pool.upgrade()
                    && pool.remove_and_is_empty(self.id)
                {
                    pool.prune_if_empty();
                }
            }
        }

        let weak_pool = Arc::downgrade(self);
        // Construct before `tokio::spawn` so even an unpolled drop (or panic when polled outside
        // a Tokio runtime) removes the connection entry and prunes an empty host pool.
        let remove_guard = RemoveOnDrop {
            pool: weak_pool.clone(),
            id,
        };
        let connector = self.connector.clone();
        let origin = self.origin.clone();
        let origin_uri = self.origin_uri.clone();
        let connection_timeout = self.connection_timeout;
        let http2 = self.http2;
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let _remove_guard = remove_guard;

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
                    return;
                }
                Err(DialError::Connect(msg)) => {
                    tracing::debug!(
                        origin = %origin,
                        connection = id.0,
                        err = %msg,
                        "HTTP/2 dial failed"
                    );
                    let _ = tx.send(DialOutcome::Failed(Arc::new(msg)));
                    return;
                }
            };

            let mut last_peer_max_streams = conn.current_max_send_streams();
            peer_max_streams.store(last_peer_max_streams, Ordering::Relaxed);
            if let Some(pool) = weak_pool.upgrade() {
                pool.promote_ready(id, sender.clone());
            }
            let _ = tx.send(DialOutcome::Ready(sender));
            // Drop the watch sender immediately so its stored `SendRequest` is released once
            // waiting callers finish dialing; otherwise `conn` stays open after idle reaping
            // or connection retirement.
            drop(tx);

            // Drive the HTTP/2 connection AND its per-connection idle timer on the connection's
            // own Tokio runtime until all handles close, an error occurs, idle timeout evicts it
            // (`C13c`), or client shutdown fires (`C12`, dropping `conn` and its socket).
            // Refresh the peer's advertised `SETTINGS_MAX_CONCURRENT_STREAMS` after each poll so
            // checkout spills over to a new connection when the peer advertises a lower cap
            // (`C13a`).
            let mut conn = pin!(conn);
            let mut idle_sleep = pin!(tokio::time::sleep(IDLE_TIMEOUT));
            let mut idle_armed = false;
            let mut evicted_idle = false;
            let mut idle_notified = pin!(permit_state.idle_notify.notified());

            loop {
                if !evicted_idle
                    && !idle_armed
                    && let Some(deadline) = permit_state.idle_deadline(IDLE_TIMEOUT)
                {
                    idle_sleep.as_mut().reset(deadline);
                    idle_armed = true;
                }

                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => break,
                    res = std::future::poll_fn(|cx| {
                        let poll = conn.as_mut().poll(cx);
                        let current = conn.current_max_send_streams();
                        if current != last_peer_max_streams {
                            last_peer_max_streams = current;
                            peer_max_streams.store(current, Ordering::Relaxed);
                        }
                        poll
                    }) => {
                        if let Err(err) = res {
                            tracing::debug!(
                                origin = %origin,
                                connection = id.0,
                                err = %format_error_chain(&err),
                                "HTTP/2 connection closed"
                            );
                        }
                        break;
                    }
                    _ = idle_sleep.as_mut(), if idle_armed && !evicted_idle => {
                        idle_armed = false;
                        let now = Instant::now();
                        match permit_state.idle_deadline(IDLE_TIMEOUT) {
                            Some(deadline) if deadline > now => {
                                idle_sleep.as_mut().reset(deadline);
                                idle_armed = true;
                            }
                            Some(_) => {
                                if let Some(pool) = weak_pool.upgrade() {
                                    let (evicted, is_empty) =
                                        pool.evict_if_idle(id, now, IDLE_TIMEOUT);
                                    if evicted {
                                        evicted_idle = true;
                                        tracing::debug!(
                                            origin = %origin,
                                            connection = id.0,
                                            "reaped idle HTTP/2 connection"
                                        );
                                        if is_empty {
                                            pool.prune_if_empty();
                                        }
                                    } else if let Some(deadline) =
                                        permit_state.idle_deadline(IDLE_TIMEOUT)
                                    {
                                        idle_sleep.as_mut().reset(deadline);
                                        idle_armed = true;
                                    }
                                } else {
                                    evicted_idle = true;
                                }
                            }
                            None => {}
                        }
                    }
                    _ = idle_notified.as_mut(), if !idle_armed && !evicted_idle => {
                        idle_notified.set(permit_state.idle_notify.notified());
                        if let Some(deadline) = permit_state.idle_deadline(IDLE_TIMEOUT) {
                            idle_sleep.as_mut().reset(deadline);
                            idle_armed = true;
                        }
                    }
                }
            }
        });
    }

    fn promote_ready(&self, id: ConnectionId, sender: http2::SendRequest<HttpBody>) {
        let mut state = self.state.write().unwrap();
        if let Some(entry) = state.connections.iter_mut().find(|c| c.id == id) {
            entry.conn = ConnectionState::Ready(sender);
        }
    }

    fn clear_and_detach(&self) {
        let mut state = self.state.write().unwrap();
        state.connections.clear();
        state.detached = true;
    }
}

/// Hyper executor that aborts every spawned HTTP/2 connection and body-pumping task immediately
/// when client shutdown fires (`C12`), so sockets and flow-control-blocked streams do not outlive
/// `S2::close()`.
#[derive(Clone)]
struct ShutdownExecutor(CancellationToken);

impl<F> hyper::rt::Executor<F> for ShutdownExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        let shutdown = self.0.clone();
        tokio::spawn(async move {
            let mut fut = pin!(fut);
            let mut cancelled = pin!(shutdown.cancelled());
            std::future::poll_fn(|cx| {
                if shutdown.is_cancelled() {
                    return Poll::Ready(());
                }
                if fut.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(());
                }
                cancelled.as_mut().poll(cx)
            })
            .await;
        });
    }
}

fn effective_receive_windows(http2_config: Http2Config) -> (u32, u32) {
    let stream_window = http2_config
        .stream_receive_window
        .unwrap_or(DEFAULT_STREAM_RECEIVE_WINDOW);
    let max_concurrent = http2_config
        .max_concurrent_requests
        .unwrap_or(DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CONNECTION);
    let conn_window = http2_config.connection_receive_window.unwrap_or_else(|| {
        let min_for_streams = (max_concurrent as u64)
            .saturating_mul(u64::from(stream_window))
            .min(u64::from(Http2Config::MAX_RECEIVE_WINDOW)) as u32;
        DEFAULT_CONNECTION_RECEIVE_WINDOW.max(min_for_streams)
    });
    (stream_window, conn_window)
}

fn effective_max_concurrent_requests(http2_config: Http2Config) -> usize {
    let configured = http2_config
        .max_concurrent_requests
        .unwrap_or(DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CONNECTION);
    if http2_config.connection_receive_window.is_none() {
        let (stream_window, conn_window) = effective_receive_windows(http2_config);
        let window_fit = (conn_window / stream_window).max(1) as usize;
        configured.min(window_fit)
    } else {
        configured
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
        http2::SendRequest<HttpBody>,
        http2::Connection<C::Io, HttpBody, ShutdownExecutor>,
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
        let (stream_window, conn_window) = effective_receive_windows(http2_config);
        let mut builder = http2::Builder::new(ShutdownExecutor(shutdown.clone()));
        builder
            .timer(TokioTimer::new())
            .keep_alive_interval(KEEP_ALIVE_INTERVAL)
            .keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
            .initial_stream_window_size(stream_window)
            .initial_connection_window_size(conn_window);
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
) -> Result<http2::SendRequest<HttpBody>, HttpError> {
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
        }
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
        let weak_hosts = Arc::downgrade(&self.hosts);
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
                    weak_hosts,
                ))
            })
            .clone())
    }

    fn checkout_for_origin(&self, uri: &Uri) -> Result<(Arc<HostPool<C>>, Checkout), HttpError> {
        with_origin_key(uri, |origin| {
            loop {
                let pool = self.get_or_create_host_pool(origin, uri)?;
                if let Some(checkout) = pool.checkout() {
                    return Ok((pool, checkout));
                }
                // The host pool was detached concurrently by the idle reaper or close(); loop to
                // re-check closed state or allocate a fresh host pool.
            }
        })
    }

    /// Acquire a live, ready HTTP/2 `SendRequest` for `uri`'s origin.
    ///
    /// Phase 1 (`T7a`): connection establishment (DNS/TCP/TLS/H2 handshake) is bounded by
    /// `connection_timeout`, completely independent of `request_timeout`.
    /// Phase 2 (`T7b`): once the connection is dialed, a single `deadline` bounds `sender.ready()`,
    /// request headers/response headers, and unary body collection.
    /// If any reused idle connections closed right before `ready()`, transparently evict them and
    /// dial a fresh connection so the caller sees no spurious error.
    async fn checkout_ready(
        &self,
        uri: &Uri,
        request_timeout: Option<Duration>,
    ) -> Result<CheckedOutSender, HttpError> {
        loop {
            if self.shutdown.is_cancelled() {
                return Err(HttpError::Closed);
            }
            let (pool, checkout) = self.checkout_for_origin(uri)?;
            let (id, mut sender, permit, reused) = match checkout {
                Checkout::Ready { id, sender, permit } => (id, sender, permit, true),
                Checkout::Connecting { id, mut rx, permit } => {
                    let sender = match wait_for_dial(&mut rx, &self.shutdown).await {
                        Ok(sender) => sender,
                        Err(err) => {
                            pool.remove(id);
                            return Err(err);
                        }
                    };
                    (id, sender, permit, false)
                }
            };

            let deadline = request_timeout.and_then(|d| Instant::now().checked_add(d));
            let mut ready_sleep = pin!(deadline.map(tokio::time::sleep_until));
            let ready_res =
                match race_deadline(sender.ready(), ready_sleep.as_mut().as_pin_mut()).await {
                    Ok(res) => res,
                    Err(()) => {
                        pool.retire(id);
                        return Err(HttpError::Timeout);
                    }
                };

            match ready_res {
                Ok(()) => {
                    let weak: Weak<dyn RetireTarget> =
                        Arc::downgrade(&(pool as Arc<dyn RetireTarget>));
                    let retire_handle = RetireHandle::new(weak, id);
                    return Ok(CheckedOutSender {
                        sender,
                        permit,
                        retire_handle,
                        deadline,
                    });
                }
                Err(err) => {
                    pool.remove(id);
                    drop(permit);
                    if reused {
                        tracing::debug!(
                            origin = %pool.origin,
                            connection = id.0,
                            err = %format_error_chain(&err),
                            "evicted stale pooled HTTP/2 connection; redialing"
                        );
                        continue;
                    }
                    return Err(HttpError::Transport(err));
                }
            }
        }
    }

    async fn send_with<T, F, Fut>(&self, request: Request, run: F) -> Result<T, HttpError>
    where
        F: FnOnce(CheckedOutSender, Request) -> Fut,
        Fut: Future<Output = Result<T, HttpError>>,
    {
        if self.shutdown.is_cancelled() {
            return Err(HttpError::Closed);
        }
        let request_timeout = request.timeout;
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => Err(HttpError::Closed),
            res = async {
                let checked_out = self
                    .checkout_ready(&request.uri, request_timeout)
                    .await?;
                run(checked_out, request).await
            } => res,
        }
    }

    pub(crate) async fn execute_unary(&self, request: Request) -> Result<UnaryResponse, HttpError> {
        self.send_with(request, execute_unary_with).await
    }

    pub(crate) async fn init_streaming(
        &self,
        request: Request,
    ) -> Result<StreamingResponse, HttpError> {
        self.send_with(request, init_streaming_with).await
    }

    pub(crate) fn close(&self) {
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

async fn send_http_request(
    mut sender: http2::SendRequest<HttpBody>,
    request: Request,
    retire_handle: &RetireHandle,
    sleep: Option<Pin<&mut Sleep>>,
) -> Result<http::Response<Incoming>, HttpError> {
    let http_request = build_http_request(
        request.method,
        request.uri,
        request.headers,
        request.body.into_http_body(),
    )?;

    let send_fut = sender.send_request(http_request);
    match race_deadline(send_fut, sleep).await {
        Ok(res) => res,
        Err(()) => {
            retire_handle.retire();
            return Err(HttpError::Timeout);
        }
    }
    .map_err(|err| {
        if is_dead_connection_hyper_error(&err) {
            retire_handle.retire();
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
        retire_handle,
        deadline,
    } = checked_out;
    let mut sleep = pin!(deadline.map(tokio::time::sleep_until));
    let response =
        send_http_request(sender, request, &retire_handle, sleep.as_mut().as_pin_mut()).await?;

    let (parts, body) = response.into_parts();
    let bytes = if parts.status.is_success() {
        let bytes = collect_bounded_body(body, MAX_RESPONSE_BYTES, sleep.as_mut().as_pin_mut())
            .await
            .map_err(|err| match err {
                CollectBodyError::Timeout => {
                    retire_handle.retire();
                    HttpError::Timeout
                }
                CollectBodyError::TooLarge => HttpError::ResponseTooLarge(MAX_RESPONSE_BYTES),
                CollectBodyError::Transport(hyper_err) => {
                    if is_dead_connection_hyper_error(&hyper_err) {
                        retire_handle.retire();
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
            sleep.as_mut().as_pin_mut(),
            &retire_handle,
        )
        .await
    };

    Ok(UnaryResponse {
        status: parts.status,
        headers: parts.headers,
        bytes,
        retire_handle: Some(retire_handle),
    })
}

async fn init_streaming_with(
    checked_out: CheckedOutSender,
    request: Request,
) -> Result<StreamingResponse, HttpError> {
    let CheckedOutSender {
        sender,
        permit,
        retire_handle,
        deadline,
    } = checked_out;
    let mut sleep = pin!(deadline.map(tokio::time::sleep_until));
    let response =
        send_http_request(sender, request, &retire_handle, sleep.as_mut().as_pin_mut()).await?;

    let (parts, body) = response.into_parts();
    Ok(StreamingResponse::new(
        parts.status,
        parts.headers,
        body,
        permit,
        retire_handle,
        deadline,
    ))
}

#[cfg(feature = "_hidden")]
#[async_trait]
impl<C> RequestExecutor for Pool<C>
where
    C: Connect,
{
    async fn execute_unary(&self, request: Request) -> Result<UnaryResponse, HttpError> {
        Pool::execute_unary(self, request).await
    }

    async fn init_streaming(&self, request: Request) -> Result<StreamingResponse, HttpError> {
        Pool::init_streaming(self, request).await
    }

    fn close(&self) {
        Pool::close(self);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        pin::Pin,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use http_body_util::Empty;
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
        server_handles: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
        dial_delay: Duration,
        stall_error_body: bool,
        max_concurrent_streams: Option<u32>,
    }

    impl DuplexH2Connector {
        fn new() -> Self {
            Self {
                dials: Arc::new(AtomicUsize::new(0)),
                active_connections: Arc::new(AtomicUsize::new(0)),
                conn_closed: Arc::new(Notify::new()),
                server_handles: Arc::new(Mutex::new(Vec::new())),
                dial_delay: Duration::ZERO,
                stall_error_body: false,
                max_concurrent_streams: None,
            }
        }

        fn abort_servers(&self) {
            for handle in self.server_handles.lock().unwrap().drain(..) {
                handle.abort();
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
            let server_handles = self.server_handles.clone();
            let dial_delay = self.dial_delay;
            let stall_error_body = self.stall_error_body;
            let max_concurrent_streams = self.max_concurrent_streams;
            Box::pin(async move {
                dials.fetch_add(1, Ordering::SeqCst);
                if !dial_delay.is_zero() {
                    tokio::time::sleep(dial_delay).await;
                }
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                let task = tokio::spawn(async move {
                    let mut builder = h2::server::Builder::new();
                    if let Some(limit) = max_concurrent_streams {
                        builder.max_concurrent_streams(limit);
                    }
                    let Ok(mut conn) = builder.handshake(server_io).await else {
                        return;
                    };
                    active_connections.fetch_add(1, Ordering::SeqCst);
                    conn_closed.notify_waiters();
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
                server_handles.lock().unwrap().push(task.abort_handle());
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
        let (_host_pool, checkout) = pool.checkout_for_origin(&uri).unwrap();
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
            cloned.uri,
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
    async fn retire_evicts_only_targeted_connection_preserving_siblings() {
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
        host_pool.retire(id1);
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
        let (bytes, _retire) = stream_resp.into_bytes_with_retire_handle().await;
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

    #[test]
    fn resolve_rustls_crypto_provider_errors_when_all_sources_missing() {
        let err = resolve_rustls_crypto_provider_with(None, None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("no rustls crypto provider configured"),
            "unexpected error: {err}"
        );
        assert!(
            crate::types::S2Config::new("test-token")
                .rustls_crypto_provider
                .is_none()
        );
    }

    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[test]
    fn resolve_rustls_crypto_provider_precedence_order() {
        let explicit = test_rustls_crypto_provider();
        let process = test_rustls_crypto_provider();
        let feature = test_rustls_crypto_provider();

        // 1. Explicit S2Config provider wins over process default and feature fallback.
        let chosen = resolve_rustls_crypto_provider_with(
            Some(explicit.clone()),
            Some(process.clone()),
            Some(feature.clone()),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&chosen, &explicit));

        // 2. Process-global default wins over compile-time feature fallback.
        let chosen =
            resolve_rustls_crypto_provider_with(None, Some(process.clone()), Some(feature.clone()))
                .unwrap();
        assert!(Arc::ptr_eq(&chosen, &process));

        // 3. Compile-time feature fallback is used when neither explicit nor process default is
        //    set.
        let chosen =
            resolve_rustls_crypto_provider_with(None, None, Some(feature.clone())).unwrap();
        assert!(Arc::ptr_eq(&chosen, &feature));

        // S2Config::new leaves the explicit provider unset so process defaults are honored, while
        // still resolving cleanly via the compile-time feature fallback.
        let config = crate::types::S2Config::new("test-token");
        assert!(config.rustls_crypto_provider.is_none());
        assert!(resolve_rustls_crypto_provider(config.rustls_crypto_provider).is_ok());
    }

    // spec: r1 C13d
    #[test]
    fn effective_receive_windows_auto_scale_unset_connection_window() {
        const MIB: u32 = 1024 * 1024;

        // Defaults stay 4 MiB stream / 256 MiB connection.
        assert_eq!(
            effective_receive_windows(Http2Config::new()),
            (4 * MIB, 256 * MIB)
        );

        // Raising max_concurrent_requests without setting connection_receive_window scales up.
        let cfg = Http2Config::new()
            .with_max_concurrent_requests(100)
            .unwrap();
        assert_eq!(effective_receive_windows(cfg), (4 * MIB, 400 * MIB));

        // Raising stream_receive_window without setting connection_receive_window scales up.
        let cfg = Http2Config::new()
            .with_stream_receive_window(16 * MIB)
            .unwrap();
        assert_eq!(effective_receive_windows(cfg), (16 * MIB, 800 * MIB));

        // Scaling clamps to HTTP/2's 2^31 - 1 ceiling without overflowing, and effective
        // per-connection concurrency clamps to keep auto-sized windows isolated (`C13d`).
        let cfg = Http2Config::new()
            .with_max_concurrent_requests(100)
            .unwrap()
            .with_stream_receive_window(64 * MIB)
            .unwrap();
        assert_eq!(
            effective_receive_windows(cfg),
            (64 * MIB, Http2Config::MAX_RECEIVE_WINDOW)
        );
        assert_eq!(effective_max_concurrent_requests(cfg), 31);

        // Explicit connection_receive_window override is always honored verbatim.
        let cfg = Http2Config::new()
            .with_max_concurrent_requests(100)
            .unwrap()
            .with_connection_receive_window(64 * MIB)
            .unwrap();
        assert_eq!(effective_receive_windows(cfg), (4 * MIB, 64 * MIB));
        assert_eq!(effective_max_concurrent_requests(cfg), 100);
    }

    // spec: r1 C13a
    #[tokio::test]
    async fn pool_spills_over_when_peer_advertises_lower_max_concurrent_streams() {
        let mut connector = DuplexH2Connector::new();
        connector.max_concurrent_streams = Some(1);
        let pool = Arc::new(test_pool_with(
            connector.clone(),
            Http2Config::new().with_max_concurrent_requests(50).unwrap(),
        ));

        // Complete one fast request so the first connection processes the server's initial
        // SETTINGS(MAX_CONCURRENT_STREAMS = 1) frame.
        let warmup = RequestBuilder::get("http://localhost:8080/test".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(
            pool.execute_unary(warmup).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(connector.dials.load(Ordering::SeqCst), 1);

        // Wait until the connection driver publishes peer_max_streams == 1.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let observed = {
                    let hosts = pool.hosts.read().unwrap();
                    hosts.map.get(TEST_ORIGIN).and_then(|host| {
                        host.state
                            .read()
                            .unwrap()
                            .connections
                            .first()
                            .map(|c| c.peer_max_streams.load(Ordering::Relaxed))
                    })
                };
                if observed == Some(1) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connection driver should observe peer SETTINGS_MAX_CONCURRENT_STREAMS=1");

        // Occupy the single stream on connection 1 with a stalled request.
        let stalled_pool = pool.clone();
        let stalled_task = tokio::spawn(async move {
            let req = RequestBuilder::get("http://localhost:8080/stall-headers".parse().unwrap())
                .build()
                .unwrap();
            let _ = stalled_pool.execute_unary(req).await;
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let active = {
                    let hosts = pool.hosts.read().unwrap();
                    hosts.map.get(TEST_ORIGIN).and_then(|host| {
                        host.state
                            .read()
                            .unwrap()
                            .connections
                            .first()
                            .map(|c| c.state.active_requests())
                    })
                };
                if active == Some(1) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stalled request should occupy connection 1");

        // A second concurrent request must spill over to a 2nd connection and succeed immediately.
        let req2 = RequestBuilder::get("http://localhost:8080/test".parse().unwrap())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let resp2 = pool.execute_unary(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        assert_eq!(connector.dials.load(Ordering::SeqCst), 2);

        stalled_task.abort();
        pool.close();
    }

    #[test]
    fn connecting_entry_is_not_live_after_dial_sender_dropped() {
        let (tx, rx) = watch::channel(DialOutcome::Pending);
        let (pooled, _permit) = PooledConnection::new_connecting(ConnectionId::next(), 10, rx);
        assert!(pooled.is_live());
        drop(tx);
        assert!(!pooled.is_live());
    }

    #[tokio::test]
    async fn large_request_timeout_does_not_panic_and_evicts_multiple_stale_connections() {
        // 1. `Duration::MAX` request_timeout must not panic on `Instant::now() + d`.
        let connector = DuplexH2Connector::new();
        let pool = test_pool_with(connector.clone(), Http2Config::new());
        let req = RequestBuilder::get("http://localhost:8080/test".parse().unwrap())
            .timeout(Duration::MAX)
            .build()
            .unwrap();
        let resp = pool.execute_unary(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        pool.close();

        // 2. When multiple idle pooled connections die on the server side, the pool evicts all of
        //    them and dials a fresh healthy connection for the next request.
        let connector = DuplexH2Connector::new();
        let pool = test_pool_with(
            connector.clone(),
            Http2Config::new().with_max_concurrent_requests(1).unwrap(),
        );

        let (id1, p1) = checkout_permit(&pool, TEST_ORIGIN).await;
        let (id2, p2) = checkout_permit(&pool, TEST_ORIGIN).await;
        assert_ne!(id1, id2);
        drop(p1);
        drop(p2);
        assert_eq!(host_connection_count(&pool, TEST_ORIGIN), 2);
        connector.wait_active_connections(2).await;

        connector.abort_servers();
        connector.wait_active_connections(0).await;
        while host_connection_count(&pool, TEST_ORIGIN) > 0 {
            tokio::task::yield_now().await;
        }

        let req = RequestBuilder::get("http://localhost:8080/test".parse().unwrap())
            .build()
            .unwrap();
        let resp = pool.execute_unary(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(connector.dials.load(Ordering::SeqCst), 3);
        pool.close();
    }

    #[test]
    fn permit_state_active_idle_transitions_and_reaper_check() {
        let state = Arc::new(PermitState::new());
        let p1 = RequestPermit {
            state: state.clone(),
        };
        assert_eq!(state.active_requests(), 1);
        assert!(state.idle_deadline(Duration::ZERO).is_none());

        let p2 = state.try_acquire(2).expect("second permit");
        assert_eq!(state.active_requests(), 2);
        assert!(state.try_acquire(2).is_none());

        drop(p2);
        assert_eq!(state.active_requests(), 1);
        assert!(state.idle_deadline(Duration::ZERO).is_none());

        drop(p1);
        assert_eq!(state.active_requests(), 0);
        let deadline = state
            .idle_deadline(Duration::ZERO)
            .expect("idle deadline set on last permit drop");
        assert!(deadline <= Instant::now());
        assert!(
            state
                .idle_deadline(Duration::from_secs(60))
                .expect("idle deadline")
                > Instant::now()
        );

        // Re-acquiring from idle clears the idle marker.
        let p3 = state.try_acquire(1).expect("re-acquire from idle");
        assert_eq!(state.active_requests(), 1);
        assert!(state.idle_deadline(Duration::ZERO).is_none());
        drop(p3);
    }

    #[test]
    fn unary_zstd_decompress_recovers_after_bad_frames_and_handles_multiframe() {
        let payload = b"hello world repeated payload ".repeat(512);
        let compressed = compress_zstd_unary(&payload).unwrap();

        // Truncated frame fails cleanly without poisoning thread-local DCtx.
        assert!(matches!(
            decompress_zstd(
                Bytes::copy_from_slice(&compressed[..compressed.len() / 2]),
                1024 * 1024
            ),
            Err(HttpError::ResponseCompression(_))
        ));
        assert_eq!(
            decompress_zstd(Bytes::from(compressed.clone()), 1024 * 1024).unwrap(),
            payload
        );

        // Oversized streaming frame fails with ResponseTooLarge and leaves DCtx reusable.
        let oversized = vec![0xAAu8; 64 * 1024];
        let streaming_oversized = zstd::stream::encode_all(&oversized[..], 1).unwrap();
        assert!(matches!(
            decompress_zstd(Bytes::from(streaming_oversized), 1024),
            Err(HttpError::ResponseTooLarge(1024))
        ));
        assert_eq!(
            decompress_zstd(Bytes::from(compressed), 1024 * 1024).unwrap(),
            payload
        );

        // Multi-frame concatenated zstd payload round-trips cleanly.
        let mut multi = compress_zstd_unary(b"part-one-").unwrap();
        multi.extend_from_slice(&compress_zstd_unary(b"part-two").unwrap());
        assert_eq!(
            decompress_zstd(Bytes::from(multi), 1024).unwrap(),
            Bytes::from_static(b"part-one-part-two")
        );

        // Streaming zstd frame with many flushed tiny chunks (no declared content size) decodes.
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        for b in 0u8..24 {
            enc.write_all(&[b]).unwrap();
            enc.flush().unwrap();
        }
        let flushed = enc.finish().unwrap();
        assert_eq!(exact_zstd_decompressed_size(&flushed), None);
        assert_eq!(
            decompress_zstd(Bytes::from(flushed), 1024)
                .unwrap()
                .as_ref(),
            &(0u8..24).collect::<Vec<_>>()[..]
        );

        // Streaming zstd frame with window_log=25 (32 MiB window) and unknown content size
        // must still be accepted by the unary decoder while enforcing `max_bytes`.
        let mut enc25 = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        enc25.window_log(25).unwrap();
        enc25.write_all(b"window-log-25-ok").unwrap();
        enc25.flush().unwrap();
        let win25 = enc25.finish().unwrap();
        assert_eq!(exact_zstd_decompressed_size(&win25), None);
        assert_eq!(
            decompress_zstd(Bytes::from(win25), 1024).unwrap().as_ref(),
            b"window-log-25-ok"
        );
    }

    #[tokio::test]
    async fn race_deadline_fires_even_when_inner_exhausts_coop_budget() {
        // Yield repeatedly using Tokio's cooperative yield so the task budget is depleted before
        // returning Pending, against an already-expired deadline.
        let busy = async {
            for _ in 0..512 {
                tokio::task::yield_now().await;
            }
            42usize
        };
        let mut sleep = pin!(tokio::time::sleep_until(Instant::now()));
        let res = race_deadline(busy, Some(sleep.as_mut())).await;
        assert!(
            res.is_err(),
            "expired deadline must fire even when inner future exhausts coop budget"
        );
    }

    #[test]
    fn pool_reaps_idle_connections_across_overlapping_runtimes() {
        let connector = DuplexH2Connector::new();
        let pool = test_pool_with(connector.clone(), Http2Config::new());

        let rt_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let rt_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();

        // Runtime A dials origin A; while A is still alive, runtime B dials origin B.
        rt_a.block_on(async {
            let req = RequestBuilder::get("http://origin-a:8080/a".parse().unwrap())
                .build()
                .unwrap();
            let resp = pool.execute_unary(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
        rt_b.block_on(async {
            let req = RequestBuilder::get("http://origin-b:8080/b".parse().unwrap())
                .build()
                .unwrap();
            let resp = pool.execute_unary(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
        assert_eq!(host_connection_count(&pool, "http://origin-a:8080"), 1);
        assert_eq!(host_connection_count(&pool, "http://origin-b:8080"), 1);

        // Shut down runtime A while runtime B remains alive and quiet (no further requests).
        drop(rt_a);
        assert_eq!(host_connection_count(&pool, "http://origin-a:8080"), 0);
        assert_eq!(host_connection_count(&pool, "http://origin-b:8080"), 1);

        rt_b.block_on(async {
            tokio::time::advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                host_connection_count(&pool, "http://origin-b:8080"),
                0,
                "idle connection on runtime B must still be reaped after runtime A exits"
            );
            assert!(
                !pool
                    .hosts
                    .read()
                    .unwrap()
                    .map
                    .contains_key("http://origin-b:8080")
            );
            pool.close();
        });
    }

    #[test]
    fn pool_poll_outside_tokio_runtime_does_not_brick_subsequent_requests() {
        let connector = DuplexH2Connector::new();
        let pool = test_pool_with(connector, Http2Config::new());

        // Polling outside any Tokio runtime panics in `tokio::spawn` but must NOT poison any pool
        // lock or leave behind a wedged entry.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let req = RequestBuilder::get("http://localhost:8080/bare".parse().unwrap())
                .build()
                .unwrap();
            let mut fut = Box::pin(pool.execute_unary(req));
            let waker = std::task::Waker::noop();
            let mut cx = Context::from_waker(waker);
            let _ = fut.as_mut().poll(&mut cx);
        }));
        assert!(panicked.is_err());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let req = RequestBuilder::get("http://localhost:8080/ok".parse().unwrap())
                .build()
                .unwrap();
            let resp = pool.execute_unary(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            pool.close();
        });
    }

    #[test]
    fn pool_idle_reaping_uses_owner_clock_when_permit_dropped_on_advanced_runtime() {
        let connector = DuplexH2Connector::new();
        let pool = test_pool_with(connector.clone(), Http2Config::new());

        let rt_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let rt_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();

        // Dial and hold a streaming response (holding the connection's sole RequestPermit) on
        // paused runtime A.
        let resp = rt_a.block_on(async {
            let req = RequestBuilder::get("http://origin-clock:8080/stream".parse().unwrap())
                .build()
                .unwrap();
            pool.init_streaming(req).await.unwrap()
        });
        assert_eq!(host_connection_count(&pool, "http://origin-clock:8080"), 1);

        // Advance paused runtime B by one full day, then drop the response/permit on runtime B.
        rt_b.block_on(async {
            tokio::time::advance(Duration::from_secs(86_400)).await;
            drop(resp);
        });

        // Advancing runtime A by IDLE_TIMEOUT + 1s (even without yielding beforehand) must still
        // reap the connection promptly on A's clock.
        let resp2 = rt_a.block_on(async {
            tokio::time::advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                host_connection_count(&pool, "http://origin-clock:8080"),
                0,
                "idle connection must be reaped using owner runtime A's clock"
            );
            assert_eq!(connector.active_connections.load(Ordering::SeqCst), 0);

            // Also verify dropping the owning runtime while a permit is still held on another
            // runtime neither blocks shutdown nor panics when the permit later drops.
            let req2 = RequestBuilder::get("http://origin-clock:8080/stream2".parse().unwrap())
                .build()
                .unwrap();
            pool.init_streaming(req2).await.unwrap()
        });
        drop(rt_a);
        assert_eq!(host_connection_count(&pool, "http://origin-clock:8080"), 0);
        rt_b.block_on(async {
            drop(resp2);
            pool.close();
        });
    }

    #[test]
    fn request_permit_dropped_during_tls_teardown_does_not_panic_and_still_reaps() {
        let connector = DuplexH2Connector::new();
        let pool = test_pool_with(connector.clone(), Http2Config::new());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();

        let resp = rt.block_on(async {
            let req = RequestBuilder::get("http://origin-tls:8080/stream".parse().unwrap())
                .build()
                .unwrap();
            pool.init_streaming(req).await.unwrap()
        });
        assert_eq!(host_connection_count(&pool, "http://origin-tls:8080"), 1);

        // Drop the response (and its last RequestPermit) inside a thread-local destructor after
        // touching Tokio's context TLS on that thread so Tokio's TLS can tear down first.
        let handle = std::thread::spawn(move || {
            thread_local! {
                static HELD: std::cell::RefCell<Option<StreamingResponse>> =
                    const { std::cell::RefCell::new(None) };
            }
            let _ = tokio::runtime::Handle::try_current();
            HELD.with(|slot| *slot.borrow_mut() = Some(resp));
            let _ = tokio::runtime::Handle::try_current();
        });
        handle
            .join()
            .expect("TLS destructor thread must exit cleanly without panicking or aborting");

        // Owner runtime still observes the idle transition and reaps after IDLE_TIMEOUT.
        rt.block_on(async {
            tokio::task::yield_now().await;
            tokio::time::advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert_eq!(host_connection_count(&pool, "http://origin-tls:8080"), 0);
            assert_eq!(connector.active_connections.load(Ordering::SeqCst), 0);
            pool.close();
        });

        // Also test a `thread_local!` current-thread Tokio runtime dropping a live task holding
        // the last `RequestPermit` during TLS destruction without firing any panic.
        let handle2 = std::thread::spawn(move || {
            thread_local! {
                static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
            }
            RT.with(|rt| {
                rt.block_on(async {
                    let conn = DuplexH2Connector::new();
                    let p = test_pool_with(conn, Http2Config::new());
                    let req = RequestBuilder::get("http://origin-tls2:8080/s".parse().unwrap())
                        .build()
                        .unwrap();
                    let resp = p.init_streaming(req).await.unwrap();
                    tokio::spawn(async move {
                        let _hold = resp;
                        std::future::pending::<()>().await;
                    });
                    tokio::task::yield_now().await;
                });
            });
        });
        handle2
            .join()
            .expect("thread-local Runtime teardown must not panic in RequestPermit::drop");
    }
}
