use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use flate2::{Compression as GzCompression, write::GzEncoder};
use h2::server::SendResponse;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use prost::Message as _;
use s2_api::v1::stream::{
    proto::{
        AppendAck as ProtoAppendAck, ReadBatch as ProtoReadBatch,
        SequencedRecord as ProtoSequencedRecord, StreamPosition as ProtoStreamPosition,
    },
    s2s::{FrameDecoder, SessionMessage},
};
use s2_sdk::{
    S2, S2Stream,
    types::{
        AppendInput, AppendRecord, AppendRecordBatch, BasinName, RetryConfig, S2Config,
        S2Endpoints, StreamName,
    },
};
use serde::Deserialize;
use tokio::{net::TcpListener, sync::Notify, task::JoinHandle};
use tokio_util::codec::Decoder;

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
                let _ = drain_body(&mut req.into_body()).await;
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
        self.client_with(|cfg| cfg.with_retry(retry))
    }

    pub fn client_with(&self, configure: impl FnOnce(S2Config) -> S2Config) -> S2 {
        let endpoints = S2Endpoints::for_endpoint(self.endpoint_url()).expect("valid endpoints");
        let config = configure(S2Config::new("test-token").with_endpoints(endpoints));
        S2::new(config).expect("valid S2 client")
    }

    pub fn stream(&self, retry: RetryConfig) -> S2Stream {
        self.stream_with(|cfg| cfg.with_retry(retry))
    }

    pub fn stream_with(&self, configure: impl FnOnce(S2Config) -> S2Config) -> S2Stream {
        let (basin_name, stream_name) = test_basin_and_stream();
        self.client_with(configure)
            .basin(basin_name)
            .stream(stream_name)
    }
}

impl Drop for MockH2Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Raw TCP listener that accepts connections and never sends a TLS ServerHello.
pub struct StallingTlsServer {
    addr: SocketAddr,
    accepted: Arc<Notify>,
    task: JoinHandle<()>,
}

impl StallingTlsServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalling listener");
        let addr = listener.local_addr().expect("stalling local_addr");
        let accepted = Arc::new(Notify::new());
        let accepted_tx = accepted.clone();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
                accepted_tx.notify_waiters();
            }
        });
        Self {
            addr,
            accepted,
            task,
        }
    }

    pub fn endpoint_url(&self) -> String {
        format!("https://{}", self.addr)
    }

    pub async fn wait_accepted(&self) {
        self.accepted.notified().await;
    }

    pub fn client_with(&self, configure: impl FnOnce(S2Config) -> S2Config) -> S2 {
        let endpoints = S2Endpoints::for_endpoint(self.endpoint_url()).expect("valid endpoints");
        let config = configure(
            S2Config::new("test-token")
                .with_endpoints(endpoints)
                .with_insecure_skip_cert_verification(true),
        );
        S2::new(config).expect("valid S2 client")
    }
}

impl Drop for StallingTlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Ergonomic wrapper around an open `s2s/proto` HTTP/2 response stream.
pub struct S2sResponder(h2::SendStream<Bytes>);

impl S2sResponder {
    pub fn open(mut respond: SendResponse<Bytes>) -> Option<Self> {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .expect("valid s2s response");
        respond.send_response(resp, false).ok().map(Self)
    }

    pub fn send_regular(&mut self, payload: &[u8], reconnect_advised: bool, end_stream: bool) {
        let _ = self.0.send_data(
            encode_s2s_regular_frame(payload, reconnect_advised),
            end_stream,
        );
    }

    pub fn send_ack(&mut self, start: u64, end: u64, reconnect_advised: bool, end_stream: bool) {
        self.send_regular(&proto_append_ack(start, end), reconnect_advised, end_stream);
    }

    pub fn send_raw(&mut self, bytes: Bytes, end_stream: bool) {
        let _ = self.0.send_data(bytes, end_stream);
    }

    pub fn send_terminal(&mut self, status: u16, body: &[u8]) {
        let _ = self
            .0
            .send_data(encode_s2s_terminal_frame(status, body), true);
    }

    pub fn send_eof(&mut self) {
        let _ = self.0.send_data(Bytes::new(), true);
    }

    pub fn reset(&mut self, reason: h2::Reason) {
        self.0.send_reset(reason);
    }

    /// Push `frame` chunks using HTTP/2 send flow control until the stream receive window is
    /// completely exhausted (`capacity() == 0` and `poll_capacity` returns `Poll::Pending`),
    /// proving the peer has buffered the full window without releasing credit. Returns the total
    /// number of bytes pushed before exhaustion.
    pub async fn saturate_stream_window(&mut self, frame: &Bytes) -> usize {
        let mut total_sent = 0;
        loop {
            self.0.reserve_capacity(frame.len());
            let poll_cap =
                std::future::poll_fn(|cx| std::task::Poll::Ready(self.0.poll_capacity(cx)));
            match poll_cap.await {
                std::task::Poll::Ready(Some(Ok(cap))) if cap > 0 => {
                    let n = cap.min(frame.len());
                    let _ = self.0.send_data(frame.slice(..n), false);
                    total_sent += n;
                    // Yield so the h2 connection driver can flush DATA frames to the socket.
                    tokio::task::yield_now().await;
                }
                std::task::Poll::Pending => {
                    // Window is genuinely exhausted: 0 stream credit remaining.
                    return total_sent;
                }
                _ => return total_sent,
            }
        }
    }
}

pub fn send_json(mut respond: SendResponse<Bytes>, status: u16, body: impl Into<Bytes>) {
    let body = body.into();
    let resp = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(())
        .expect("valid json response");
    if body.is_empty() {
        let _ = respond.send_response(resp, true);
    } else if let Ok(mut send) = respond.send_response(resp, false) {
        let _ = send.send_data(body, true);
    }
}

pub fn send_proto(mut respond: SendResponse<Bytes>, body: impl Into<Bytes>) {
    let resp = Response::builder()
        .status(200)
        .header("content-type", "application/protobuf")
        .body(())
        .expect("valid proto response");
    if let Ok(mut send) = respond.send_response(resp, false) {
        let _ = send.send_data(body.into(), true);
    }
}

pub fn send_tail_json(respond: SendResponse<Bytes>, status: u16, seq_num: u64, timestamp: u64) {
    send_json(
        respond,
        status,
        format!(r#"{{"tail":{{"seq_num":{seq_num},"timestamp":{timestamp}}}}}"#),
    );
}

pub async fn advance_virtual_time(duration: Duration) {
    tokio::time::pause();
    tokio::time::advance(duration).await;
    tokio::time::resume();
}

pub async fn read_append_input(
    body: &mut h2::RecvStream,
    buf: &mut BytesMut,
) -> Option<s2_api::v1::stream::proto::AppendInput> {
    match read_one_s2s_frame(body, buf, true).await? {
        SessionMessage::Regular(regular) => {
            let payload = regular.decompressed().expect("valid compressed s2s frame");
            Some(
                s2_api::v1::stream::proto::AppendInput::decode(payload)
                    .expect("valid AppendInput protobuf"),
            )
        }
        SessionMessage::Terminal(_) => None,
    }
}

pub async fn drain_body(body: &mut h2::RecvStream) -> Bytes {
    let mut out = BytesMut::new();
    while let Some(Ok(chunk)) = body.data().await {
        let len = chunk.len();
        out.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(len);
    }
    out.freeze()
}

pub fn header_str<'a>(req: &'a Request<h2::RecvStream>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

pub fn query_pairs(uri: &http::Uri) -> BTreeMap<String, String> {
    uri.query()
        .and_then(|q| serde_urlencoded::from_str::<Vec<(String, String)>>(q).ok())
        .map(|pairs| pairs.into_iter().collect())
        .unwrap_or_default()
}

pub fn no_retry_config() -> RetryConfig {
    RetryConfig::new().with_max_attempts(1)
}

pub fn fast_retry_config(max_attempts: u32) -> RetryConfig {
    RetryConfig::new()
        .with_max_attempts(max_attempts)
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO)
}

pub fn test_basin_and_stream() -> (BasinName, StreamName) {
    (
        "test-basin".parse().expect("valid basin"),
        "test-stream".parse().expect("valid stream"),
    )
}

pub fn sample_append_input() -> AppendInput {
    AppendInput::new(
        AppendRecordBatch::try_from_iter([AppendRecord::new("payload").expect("valid record")])
            .expect("valid batch"),
    )
}

pub fn sized_append_input(body_len: usize) -> AppendInput {
    AppendInput::new(
        AppendRecordBatch::try_from_iter([AppendRecord::new(vec![b'x'; body_len]).unwrap()])
            .unwrap(),
    )
}

pub fn encode_s2s_terminal_frame(status: u16, body: &[u8]) -> Bytes {
    let frame_len = 1 + 2 + body.len();
    let mut out = Vec::with_capacity(3 + frame_len);
    out.push(((frame_len >> 16) & 0xff) as u8);
    out.push(((frame_len >> 8) & 0xff) as u8);
    out.push((frame_len & 0xff) as u8);
    out.push(0x80); // terminal, uncompressed
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(body);
    Bytes::from(out)
}

pub fn encode_s2s_regular_frame(payload: &[u8], reconnect_advised: bool) -> Bytes {
    let frame_len = 1 + payload.len();
    let mut out = Vec::with_capacity(3 + frame_len);
    out.push(((frame_len >> 16) & 0xff) as u8);
    out.push(((frame_len >> 8) & 0xff) as u8);
    out.push((frame_len & 0xff) as u8);
    out.push(if reconnect_advised { 0x10 } else { 0x00 });
    out.extend_from_slice(payload);
    Bytes::from(out)
}

pub fn proto_append_ack(start: u64, end: u64) -> Vec<u8> {
    ProtoAppendAck {
        start: Some(ProtoStreamPosition {
            seq_num: start,
            timestamp: 1000,
        }),
        end: Some(ProtoStreamPosition {
            seq_num: end,
            timestamp: 1000,
        }),
        tail: Some(ProtoStreamPosition {
            seq_num: end,
            timestamp: 1000,
        }),
    }
    .encode_to_vec()
}

pub fn proto_read_batch(seq_num: u64, tail_seq: u64) -> Vec<u8> {
    ProtoReadBatch {
        records: vec![ProtoSequencedRecord {
            seq_num,
            timestamp: 1000,
            headers: vec![],
            body: Bytes::from_static(b"rec"),
        }],
        tail: Some(ProtoStreamPosition {
            seq_num: tail_seq,
            timestamp: 1000,
        }),
    }
    .encode_to_vec()
}

pub fn proto_read_batch_records(seq_nums: &[u64], tail_seq: Option<u64>) -> Vec<u8> {
    ProtoReadBatch {
        records: seq_nums
            .iter()
            .map(|&seq_num| ProtoSequencedRecord {
                seq_num,
                timestamp: 1000u64.saturating_add(seq_num),
                headers: vec![],
                body: Bytes::from(format!("rec-{seq_num}")),
            })
            .collect(),
        tail: tail_seq.map(|seq_num| ProtoStreamPosition {
            seq_num,
            timestamp: 1000u64.saturating_add(seq_num),
        }),
    }
    .encode_to_vec()
}

pub fn proto_heartbeat(tail_seq: u64) -> Vec<u8> {
    proto_read_batch_records(&[], Some(tail_seq))
}

pub fn proto_heartbeat_at(tail_seq: u64, timestamp: u64) -> Vec<u8> {
    ProtoReadBatch {
        records: vec![],
        tail: Some(ProtoStreamPosition {
            seq_num: tail_seq,
            timestamp,
        }),
    }
    .encode_to_vec()
}

pub async fn read_exact_h2_bytes(body: &mut h2::RecvStream, min_bytes: usize) -> usize {
    let mut total = 0;
    while total < min_bytes {
        match body.data().await {
            Some(Ok(chunk)) => total += chunk.len(),
            _ => break,
        }
    }
    total
}

pub async fn read_one_s2s_frame(
    body: &mut h2::RecvStream,
    buf: &mut BytesMut,
    release_flow_control: bool,
) -> Option<SessionMessage> {
    let mut decoder = FrameDecoder;
    loop {
        if let Ok(Some(msg)) = decoder.decode(buf) {
            return Some(msg);
        }
        match body.data().await {
            Some(Ok(chunk)) => {
                let len = chunk.len();
                buf.extend_from_slice(&chunk);
                if release_flow_control {
                    let _ = body.flow_control().release_capacity(len);
                }
            }
            _ => return None,
        }
    }
}

pub fn gzip_bytes(input: &[u8]) -> Bytes {
    let mut enc = GzEncoder::new(Vec::new(), GzCompression::default());
    enc.write_all(input).expect("gzip write");
    Bytes::from(enc.finish().expect("gzip finish"))
}

pub fn zstd_bytes(input: &[u8]) -> Bytes {
    Bytes::from(zstd::bulk::compress(input, 0).expect("zstd compress"))
}

pub fn specs_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../api/specs")
        .join(rel)
}

pub fn read_json<T: for<'de> Deserialize<'de>>(rel: &str) -> T {
    let path = specs_path(rel);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

pub fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd hex length: {hex}");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").unwrap();
    }
    out
}
