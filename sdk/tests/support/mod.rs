#![allow(dead_code)]

use std::{
    collections::VecDeque,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_compression::tokio::write::{GzipEncoder, ZstdEncoder};
use bytes::Bytes;
use h2::server::SendResponse;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use s2_sdk::{
    S2,
    types::{AccountEndpoint, BasinEndpoint, RetryConfig, S2Config, S2Endpoints},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle};

pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
pub type RequestHandler =
    Arc<dyn Fn(usize, Request<h2::RecvStream>, SendResponse<Bytes>) -> BoxFuture + Send + Sync>;

/// Canned unary HTTP response served by [`MockH2Server::from_responses`].
#[derive(Debug, Clone)]
pub struct CannedResponse {
    pub status: StatusCode,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
}

impl CannedResponse {
    pub fn new(status: u16, body: impl Into<Bytes>) -> Self {
        Self {
            status: StatusCode::from_u16(status).expect("valid HTTP status"),
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn with_header(
        mut self,
        name: impl TryInto<HeaderName, Error: std::fmt::Debug>,
        value: impl TryInto<HeaderValue, Error: std::fmt::Debug>,
    ) -> Self {
        self.headers
            .push((name.try_into().unwrap(), value.try_into().unwrap()));
        self
    }
}

/// Loopback HTTP/2 (h2c) mock server for SDK conformance tests.
pub struct MockH2Server {
    addr: SocketAddr,
    connection_count: Arc<AtomicUsize>,
    request_count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl MockH2Server {
    /// Start a mock HTTP/2 server with a custom per-request handler.
    pub async fn start<F, Fut>(handler: F) -> Self
    where
        F: Fn(usize, Request<h2::RecvStream>, SendResponse<Bytes>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handler: RequestHandler =
            Arc::new(move |conn_id, req, respond| Box::pin(handler(conn_id, req, respond)));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local_addr");
        let connection_count = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::new(AtomicUsize::new(0));

        let conn_counter = connection_count.clone();
        let req_counter = request_count.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let _ = socket.set_nodelay(true);
                let conn_id = conn_counter.fetch_add(1, Ordering::SeqCst);
                let handler = handler.clone();
                let req_counter = req_counter.clone();
                tokio::spawn(async move {
                    let Ok(mut conn) = h2::server::handshake(socket).await else {
                        return;
                    };
                    while let Some(Ok((req, respond))) = conn.accept().await {
                        req_counter.fetch_add(1, Ordering::SeqCst);
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            handler(conn_id, req, respond).await;
                        });
                    }
                });
            }
        });

        Self {
            addr,
            connection_count,
            request_count,
            task,
        }
    }

    /// Start a mock server that pops responses in FIFO order (repeating the last response if
    /// more requests arrive than configured).
    pub async fn from_responses(responses: impl IntoIterator<Item = CannedResponse>) -> Self {
        let queue = Arc::new(Mutex::new(responses.into_iter().collect::<VecDeque<_>>()));
        Self::start(move |_conn_id, req, mut respond| {
            let queue = queue.clone();
            async move {
                let mut body = req.into_body();
                while let Some(Ok(chunk)) = body.data().await {
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
                let canned = {
                    let mut guard = queue.lock().expect("lock queue");
                    if guard.len() > 1 {
                        guard.pop_front().expect("non-empty queue")
                    } else {
                        guard
                            .front()
                            .cloned()
                            .unwrap_or_else(|| CannedResponse::new(500, "exhausted mock queue"))
                    }
                };
                let mut resp = Response::builder().status(canned.status);
                for (k, v) in canned.headers {
                    resp = resp.header(k, v);
                }
                let resp = resp.body(()).expect("valid response");
                if canned.body.is_empty() {
                    let _ = respond.send_response(resp, true);
                } else if let Ok(mut send_stream) = respond.send_response(resp, false) {
                    let _ = send_stream.send_data(canned.body, true);
                }
            }
        })
        .await
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn endpoint_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn connection_count(&self) -> usize {
        self.connection_count.load(Ordering::SeqCst)
    }

    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }

    pub fn client(&self, retry: RetryConfig) -> S2 {
        let ep = self.endpoint_url();
        let endpoints = S2Endpoints::new(
            AccountEndpoint::new(&ep).expect("valid account endpoint"),
            BasinEndpoint::new(&ep).expect("valid basin endpoint"),
        )
        .expect("valid endpoints");
        S2::new(
            S2Config::new("test-token")
                .with_endpoints(endpoints)
                .with_retry(retry),
        )
        .expect("valid S2 client")
    }
}

impl Drop for MockH2Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn gzip_bytes(input: &[u8]) -> Bytes {
    let mut enc = GzipEncoder::new(Vec::new());
    enc.write_all(input).await.expect("gzip write");
    enc.shutdown().await.expect("gzip shutdown");
    Bytes::from(enc.into_inner())
}

pub async fn zstd_bytes(input: &[u8]) -> Bytes {
    let mut enc = ZstdEncoder::new(Vec::new());
    enc.write_all(input).await.expect("zstd write");
    enc.shutdown().await.expect("zstd shutdown");
    Bytes::from(enc.into_inner())
}
