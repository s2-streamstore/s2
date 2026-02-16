use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
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
use futures::{Stream, StreamExt};
use http::{
    HeaderMap, Method, StatusCode,
    header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderName, HeaderValue},
};
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::{Frame, Incoming};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
pub use hyper_util::client::legacy::connect::Connect;
use hyper_util::{
    client::legacy::{Client as HyperClient, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
    time::timeout,
};
use tokio_util::task::AbortOnDropHandle;
use url::Url;

const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");
const MAX_CONCURRENT_REQUESTS_PER_CLIENT: usize = 90;
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("send error: {0}")]
    Send(#[from] hyper_util::client::legacy::Error),
    #[error("receive error: {0}")]
    Receive(#[from] hyper::Error),
    #[error("http error: {0}")]
    Http(#[from] http::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("url encoding error: {0}")]
    UrlEncoded(#[from] serde_urlencoded::ser::Error),
    #[error("timeout")]
    Timeout,
    #[error("compression error: {0}")]
    Compression(String),
}

impl Error {
    pub fn is_connect(&self) -> bool {
        matches!(self, Error::Send(e) if e.is_connect())
    }
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
    url: Url,
    headers: HeaderMap,
    body: Body,
    timeout: Option<Duration>,
    compression: Compression,
}

impl Request {
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub fn authority(&self) -> &str {
        self.url.authority()
    }

    pub fn try_clone(&self) -> Option<Self> {
        let body = match &self.body.0 {
            BodyInner::Empty => Body::empty(),
            BodyInner::Full(bytes) => Body(BodyInner::Full(bytes.clone())),
            BodyInner::Streaming(_) => return None,
        };

        Some(Self {
            method: self.method.clone(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            body,
            timeout: self.timeout,
            compression: self.compression,
        })
    }
}

pub struct RequestBuilder {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Body>,
    timeout: Option<Duration>,
    compression: Compression,
    error: Option<Error>,
}

impl RequestBuilder {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
            compression: Compression::None,
            error: None,
        }
    }

    pub fn get(url: Url) -> Self {
        Self::new(Method::GET, url)
    }

    pub fn post(url: Url) -> Self {
        Self::new(Method::POST, url)
    }

    pub fn patch(url: Url) -> Self {
        Self::new(Method::PATCH, url)
    }

    pub fn delete(url: Url) -> Self {
        Self::new(Method::DELETE, url)
    }

    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Self {
        if self.error.is_some() {
            return self;
        }

        match serde_urlencoded::to_string(query) {
            Ok(query_string) => {
                if !query_string.is_empty() {
                    let existing = self.url.query().unwrap_or("");
                    if existing.is_empty() {
                        self.url.set_query(Some(&query_string));
                    } else {
                        self.url
                            .set_query(Some(&format!("{existing}&{query_string}")));
                    }
                }
            }
            Err(e) => self.error = Some(Error::UrlEncoded(e)),
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
            Err(e) => self.error = Some(Error::Json(e)),
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
            (Err(e), _) => self.error = Some(Error::Http(e.into())),
            (_, Err(e)) => self.error = Some(Error::Http(e.into())),
        }
        self
    }

    pub fn headers(mut self, headers: &HeaderMap) -> Self {
        for (key, value) in headers {
            self.headers.insert(key.clone(), value.clone());
        }
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

    pub fn build(self) -> Result<Request, Error> {
        if let Some(e) = self.error {
            return Err(e);
        }

        Ok(Request {
            method: self.method,
            url: self.url,
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
}

impl UnaryResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    pub fn json<T: DeserializeOwned>(self) -> Result<T, Error> {
        Ok(serde_json::from_slice(&self.bytes)?)
    }
}

pub struct StreamingResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Incoming,
    permit: RequestPermit,
}

impl StreamingResponse {
    fn new(status: StatusCode, headers: HeaderMap, body: Incoming, permit: RequestPermit) -> Self {
        Self {
            status,
            headers,
            body,
            permit,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub async fn into_bytes(self) -> Result<Bytes, Error> {
        let bytes = self.body.collect().await?.to_bytes();
        decompress_body(&self.headers, bytes).await
    }

    pub fn stream(self) -> impl Stream<Item = Result<Bytes, Error>> {
        let permit = self.permit;
        http_body_util::BodyStream::new(self.body).filter_map(move |result| {
            let _ = &permit;
            std::future::ready(match result {
                Ok(frame) => frame.into_data().ok().map(Ok),
                Err(e) => Some(Err(Error::Receive(e))),
            })
        })
    }
}

#[async_trait]
pub trait RequestExecutor: Send + Sync {
    async fn execute_unary(&self, request: Request) -> Result<UnaryResponse, Error>;
    async fn init_streaming(&self, request: Request) -> Result<StreamingResponse, Error>;
}

pub fn default_connector(
    connect_timeout: Option<Duration>,
    insecure_skip_cert_verification: bool,
) -> Result<HttpsConnector<HttpConnector>, std::io::Error> {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    if let Some(timeout) = connect_timeout {
        connector.set_connect_timeout(Some(timeout));
    }

    let builder = if insecure_skip_cert_verification {
        HttpsConnectorBuilder::new().with_tls_config(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth(),
        )
    } else {
        HttpsConnectorBuilder::new().with_native_roots()?
    };

    Ok(builder
        .https_or_http()
        .enable_http2()
        .wrap_connector(connector))
}

#[derive(Debug)]
struct NoVerifier;

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
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_http_request(
    method: Method,
    url: &Url,
    headers: HeaderMap,
    body: BoxBody,
    content_encoding: Option<HeaderValue>,
) -> Result<http::Request<BoxBody>, Error> {
    let uri: http::Uri = url
        .as_str()
        .parse()
        .map_err(|e: http::uri::InvalidUri| Error::Http(e.into()))?;

    let mut builder = http::Request::builder().method(method).uri(uri);

    if let Some(req_headers) = builder.headers_mut() {
        for (key, value) in headers {
            if let Some(key) = key {
                req_headers.insert(key, value);
            }
        }
        if let Some(encoding) = content_encoding {
            req_headers.insert(CONTENT_ENCODING, encoding);
        }
    }

    Ok(builder.body(body)?)
}

async fn execute_unary_with<C>(
    client: &HyperClient<C, BoxBody>,
    request: Request,
) -> Result<UnaryResponse, Error>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    let request_timeout = request.timeout;

    let (body, content_encoding) = compress_body(request.body, request.compression).await?;

    let http_request = build_http_request(
        request.method,
        &request.url,
        request.headers,
        body.into_http_body(),
        content_encoding,
    )?;

    let operation = async {
        let response = client.request(http_request).await?;
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await?.to_bytes();

        Ok::<_, Error>((parts.status, parts.headers, bytes))
    };

    let (status, headers, bytes) = if let Some(timeout_duration) = request_timeout {
        timeout(timeout_duration, operation)
            .await
            .map_err(|_| Error::Timeout)??
    } else {
        operation.await?
    };

    let bytes = decompress_body(&headers, bytes).await?;

    Ok(UnaryResponse {
        status,
        headers,
        bytes,
    })
}

async fn init_streaming_with<C>(
    client: &HyperClient<C, BoxBody>,
    request: Request,
    permit: RequestPermit,
) -> Result<StreamingResponse, Error>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    let request_timeout = request.timeout;

    let http_request = build_http_request(
        request.method,
        &request.url,
        request.headers,
        request.body.into_http_body(),
        None,
    )?;

    let operation = async {
        let response = client.request(http_request).await?;
        let (parts, body) = response.into_parts();

        Ok::<_, Error>(StreamingResponse::new(
            parts.status,
            parts.headers,
            body,
            permit,
        ))
    };

    if let Some(duration) = request_timeout {
        timeout(duration, operation)
            .await
            .map_err(|_| Error::Timeout)?
    } else {
        operation.await
    }
}

async fn compress_body(
    body: Body,
    compression: Compression,
) -> Result<(Body, Option<HeaderValue>), Error> {
    match compression {
        Compression::None => Ok((body, None)),
        Compression::Gzip => {
            let Some(data) = body.as_bytes() else {
                return Err(Error::Compression(
                    "streaming request bodies cannot be compressed".into(),
                ));
            };
            let mut encoder = GzipEncoder::with_quality(Vec::new(), Level::Fastest);
            encoder
                .write_all(data)
                .await
                .map_err(|e| Error::Compression(e.to_string()))?;
            encoder
                .shutdown()
                .await
                .map_err(|e| Error::Compression(e.to_string()))?;
            let compressed = encoder.into_inner();
            Ok((
                Body::from(compressed),
                Some(HeaderValue::from_static("gzip")),
            ))
        }
        Compression::Zstd => {
            let Some(data) = body.as_bytes() else {
                return Err(Error::Compression(
                    "streaming request bodies cannot be compressed".into(),
                ));
            };
            let mut encoder = ZstdEncoder::with_quality(Vec::new(), Level::Fastest);
            encoder
                .write_all(data)
                .await
                .map_err(|e| Error::Compression(e.to_string()))?;
            encoder
                .shutdown()
                .await
                .map_err(|e| Error::Compression(e.to_string()))?;
            let compressed = encoder.into_inner();
            Ok((
                Body::from(compressed),
                Some(HeaderValue::from_static("zstd")),
            ))
        }
    }
}

async fn decompress_body(headers: &HeaderMap, bytes: Bytes) -> Result<Bytes, Error> {
    let content_encoding = headers.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok());

    match content_encoding {
        Some("gzip") => {
            let mut decoder = GzipDecoder::new(bytes.as_ref());
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .await
                .map_err(|e| Error::Compression(e.to_string()))?;
            Ok(Bytes::from(decompressed))
        }
        Some("zstd") => {
            let mut decoder = ZstdDecoder::new(bytes.as_ref());
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .await
                .map_err(|e| Error::Compression(e.to_string()))?;
            Ok(Bytes::from(decompressed))
        }
        _ => Ok(bytes),
    }
}

struct RequestPermit {
    active_requests: Arc<AtomicUsize>,
    idle_since: Arc<Mutex<Option<Instant>>>,
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        let prev = self.active_requests.fetch_sub(1, Ordering::Relaxed);
        if prev == 1 {
            *self.idle_since.lock().unwrap() = Some(Instant::now());
        }
    }
}

struct PooledClient<C> {
    client: Arc<HyperClient<C, BoxBody>>,
    active_requests: Arc<AtomicUsize>,
    idle_since: Arc<Mutex<Option<Instant>>>,
}

impl<C> PooledClient<C> {
    fn new(client: HyperClient<C, BoxBody>) -> Self {
        Self {
            client: Arc::new(client),
            active_requests: Arc::new(AtomicUsize::new(0)),
            idle_since: Arc::new(Mutex::new(Some(Instant::now()))),
        }
    }

    fn request_permit(&self) -> Option<RequestPermit> {
        self.active_requests
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |ar| {
                (ar < MAX_CONCURRENT_REQUESTS_PER_CLIENT).then_some(ar + 1)
            })
            .ok()?;
        *self.idle_since.lock().unwrap() = None;
        Some(RequestPermit {
            active_requests: self.active_requests.clone(),
            idle_since: self.idle_since.clone(),
        })
    }

    fn should_reap(&self, idle_timeout: Duration) -> bool {
        if self.active_requests.load(Ordering::Relaxed) != 0 {
            return false;
        }
        if let Some(idle_since) = *self.idle_since.lock().unwrap() {
            return idle_since.elapsed() > idle_timeout;
        }
        false
    }
}

struct HostPool<C> {
    clients: RwLock<Vec<PooledClient<C>>>,
    connector: C,
}

impl<C> HostPool<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    fn new(connector: C) -> Self {
        Self {
            clients: RwLock::new(Vec::new()),
            connector,
        }
    }

    fn create_client(&self) -> PooledClient<C> {
        let client = HyperClient::builder(TokioExecutor::new()).build(self.connector.clone());
        PooledClient::new(client)
    }

    async fn checkout(&self) -> (Arc<HyperClient<C, BoxBody>>, RequestPermit) {
        {
            let clients = self.clients.read().await;
            for pooled in clients.iter() {
                if let Some(permit) = pooled.request_permit() {
                    return (pooled.client.clone(), permit);
                }
            }
        }
        let mut clients = self.clients.write().await;
        for pooled in clients.iter() {
            if let Some(permit) = pooled.request_permit() {
                return (pooled.client.clone(), permit);
            }
        }
        let new_client = self.create_client();
        let permit = new_client
            .request_permit()
            .expect("new client must have a permit");
        let client = new_client.client.clone();
        clients.push(new_client);
        (client, permit)
    }

    async fn reap_idle_clients(&self) {
        self.clients
            .write()
            .await
            .retain(|pooled| !pooled.should_reap(IDLE_TIMEOUT));
    }

    fn is_empty(&self) -> bool {
        self.clients
            .try_read()
            .map(|clients| clients.is_empty())
            .unwrap_or(false)
    }
}

pub struct Pool<C> {
    hosts: Arc<RwLock<HashMap<String, Arc<HostPool<C>>>>>,
    connector: C,
    _reaper: AbortOnDropHandle<()>,
}

impl<C> Pool<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    pub fn new(connector: C) -> Self {
        let hosts = Arc::new(RwLock::new(HashMap::new()));

        let _reaper = AbortOnDropHandle::new(tokio::spawn({
            let hosts = hosts.clone();
            async move {
                let mut interval = tokio::time::interval(REAPER_INTERVAL);
                loop {
                    interval.tick().await;
                    reap_idle_clients(&hosts).await;
                }
            }
        }));

        Self {
            hosts,
            connector,
            _reaper,
        }
    }

    async fn get_or_create_host_pool(&self, host: &str) -> Arc<HostPool<C>> {
        {
            let hosts = self.hosts.read().await;
            if let Some(pool) = hosts.get(host) {
                return pool.clone();
            }
        }
        let mut hosts = self.hosts.write().await;
        hosts
            .entry(host.to_owned())
            .or_insert_with(|| Arc::new(HostPool::new(self.connector.clone())))
            .clone()
    }

    async fn checkout(&self, host: &str) -> (Arc<HyperClient<C, BoxBody>>, RequestPermit) {
        self.get_or_create_host_pool(host).await.checkout().await
    }
}

async fn reap_idle_clients<C: Connect + Clone + Send + Sync + 'static>(
    hosts: &RwLock<HashMap<String, Arc<HostPool<C>>>>,
) {
    let pools: Vec<Arc<HostPool<C>>> = {
        let hosts = hosts.read().await;
        hosts.values().cloned().collect()
    };

    for pool in &pools {
        pool.reap_idle_clients().await;
    }

    hosts.write().await.retain(|_, pool| !pool.is_empty());
}

#[async_trait]
impl<C> RequestExecutor for Pool<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    async fn execute_unary(&self, request: Request) -> Result<UnaryResponse, Error> {
        let (client, _permit) = self.checkout(request.authority()).await;
        execute_unary_with(&client, request).await
    }

    async fn init_streaming(&self, request: Request) -> Result<StreamingResponse, Error> {
        let (client, permit) = self.checkout(request.authority()).await;
        init_streaming_with(&client, request, permit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HOST: &str = "localhost:8080";

    fn test_pool() -> Pool<HttpConnector> {
        Pool::new(HttpConnector::new())
    }

    async fn host_client_count(pool: &Pool<HttpConnector>, host: &str) -> usize {
        let hosts = pool.hosts.read().await;
        match hosts.get(host) {
            Some(pool) => pool.clients.read().await.len(),
            None => 0,
        }
    }

    #[tokio::test]
    async fn checkout_within_capacity() {
        let pool = test_pool();
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS_PER_CLIENT {
            let (_client, permit) = pool.checkout(TEST_HOST).await;
            permits.push(permit);
        }
        assert_eq!(host_client_count(&pool, TEST_HOST).await, 1);
    }

    #[tokio::test]
    async fn overflow_creates_new_client() {
        let pool = test_pool();
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS_PER_CLIENT {
            let (_client, permit) = pool.checkout(TEST_HOST).await;
            permits.push(permit);
        }
        assert_eq!(host_client_count(&pool, TEST_HOST).await, 1);

        let (_client, permit) = pool.checkout(TEST_HOST).await;
        permits.push(permit);
        assert_eq!(host_client_count(&pool, TEST_HOST).await, 2);
    }

    #[tokio::test]
    async fn permit_drop_frees_capacity() {
        let pool = test_pool();
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS_PER_CLIENT {
            let (_client, permit) = pool.checkout(TEST_HOST).await;
            permits.push(permit);
        }
        permits.pop();

        let (_client, permit) = pool.checkout(TEST_HOST).await;
        permits.push(permit);
        assert_eq!(host_client_count(&pool, TEST_HOST).await, 1);
    }

    #[tokio::test]
    async fn reaper_removes_idle_clients() {
        let pool = test_pool();
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS_PER_CLIENT {
            let (_client, permit) = pool.checkout(TEST_HOST).await;
            permits.push(permit);
        }
        let (_client, permit) = pool.checkout(TEST_HOST).await;
        permits.push(permit);
        assert_eq!(host_client_count(&pool, TEST_HOST).await, 2);

        permits.clear();
        {
            let hosts = pool.hosts.read().await;
            let pool = hosts.get(TEST_HOST).unwrap();
            let clients = pool.clients.read().await;
            for pooled in clients.iter() {
                *pooled.idle_since.lock().unwrap() =
                    Some(Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1));
            }
        }

        reap_idle_clients(&pool.hosts).await;
        assert_eq!(host_client_count(&pool, TEST_HOST).await, 0);
        assert!(pool.hosts.read().await.get(TEST_HOST).is_none());
    }

    #[tokio::test]
    async fn different_hosts_get_independent_pools() {
        let pool = test_pool();
        let host_a = "host-a:443";
        let host_b = "host-b:443";

        let mut permits_a = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS_PER_CLIENT {
            let (_client, permit) = pool.checkout(host_a).await;
            permits_a.push(permit);
        }
        assert_eq!(host_client_count(&pool, host_a).await, 1);

        let (_client, permit_b) = pool.checkout(host_b).await;
        assert_eq!(host_client_count(&pool, host_b).await, 1);
        assert_eq!(host_client_count(&pool, host_a).await, 1);

        drop(permit_b);
        drop(permits_a);
    }

    #[tokio::test]
    async fn reaper_removes_empty_host_entries() {
        let pool = test_pool();

        let (_client, permit_a) = pool.checkout("host-a:443").await;
        let (_client, permit_b) = pool.checkout("host-b:443").await;
        assert_eq!(pool.hosts.read().await.len(), 2);

        drop(permit_a);
        {
            let hosts = pool.hosts.read().await;
            let pool_a = hosts.get("host-a:443").unwrap();
            let clients = pool_a.clients.read().await;
            for pooled in clients.iter() {
                *pooled.idle_since.lock().unwrap() =
                    Some(Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1));
            }
        }

        reap_idle_clients(&pool.hosts).await;

        let hosts = pool.hosts.read().await;
        assert!(hosts.get("host-a:443").is_none());
        assert!(hosts.get("host-b:443").is_some());

        drop(permit_b);
    }
}
