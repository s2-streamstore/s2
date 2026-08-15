//! Session behavior when a server advises reconnecting before it terminates.
//!
//! Each test drives a real session against a scripted transport, so the whole
//! path is exercised: the decoder observing the `0x10` flag, the session loop
//! reacting to it, and the resulting second connection.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::StreamExt;
use http::{HeaderMap, StatusCode};
use s2_api::v1::stream::{
    proto::{AppendAck, AppendInput, ReadBatch, SequencedRecord, StreamPosition},
    s2s::{self, CompressionAlgorithm, FrameDecoder, SessionMessage},
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::codec::Decoder;

use crate::{
    api::{BaseClient, BasinClient},
    client::{self, HttpError, StreamingResponse, UnaryResponse},
    session::{
        append::{AppendSession, AppendSessionConfig},
        read::read_session,
    },
    types::{AppendRecord, AppendRecordBatch, ReadInput, ReadSessionConfig, S2Config, S2Endpoints},
};

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn basin_client(executor: Arc<dyn client::RequestExecutor>) -> BasinClient {
    let config = S2Config::new("test-token")
        .with_endpoints(S2Endpoints::for_endpoint("http://server.test").expect("valid endpoint"));
    BasinClient::init(
        "test-basin".parse().expect("valid basin name"),
        Arc::new(config),
        BaseClient::new_for_test(executor, REQUEST_TIMEOUT),
    )
}

fn position(seq_num: u64) -> StreamPosition {
    StreamPosition {
        seq_num,
        timestamp: seq_num,
    }
}

fn encode(proto: &impl prost::Message, advise: bool) -> bytes::Bytes {
    let frame = SessionMessage::regular(CompressionAlgorithm::None, proto)
        .expect("encodable frame")
        .encode();
    if advise {
        s2s::advise_reconnect(frame)
    } else {
        frame
    }
}

/// A server that acknowledges every input it reads, and ends the response
/// once the client half-closes the request.
struct AppendServer {
    /// Record bodies received, per connection in connection order.
    connections: Arc<Mutex<Vec<Vec<String>>>>,
    /// Connection whose acknowledgements carry the reconnect-advised flag.
    advise_on: usize,
    next_seq_num: Arc<AtomicU64>,
}

impl AppendServer {
    fn new(advise_on: usize) -> Arc<Self> {
        Arc::new(Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            advise_on,
            next_seq_num: Arc::new(AtomicU64::new(0)),
        })
    }

    fn connections(&self) -> Vec<Vec<String>> {
        self.connections.lock().expect("server lock").clone()
    }
}

#[async_trait]
impl client::RequestExecutor for AppendServer {
    async fn execute_unary(&self, _request: client::Request) -> Result<UnaryResponse, HttpError> {
        unreachable!("append session issues no unary requests")
    }

    async fn init_streaming(
        &self,
        request: client::Request,
    ) -> Result<StreamingResponse, HttpError> {
        let index = {
            let mut connections = self.connections.lock().expect("server lock");
            connections.push(Vec::new());
            connections.len() - 1
        };
        let advise = index == self.advise_on;
        let connections = self.connections.clone();
        let next_seq_num = self.next_seq_num.clone();
        let (ack_tx, ack_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            let mut inputs = Box::pin(request.into_body_stream());
            let mut buffer = BytesMut::new();
            let mut decoder = FrameDecoder;

            while let Some(Ok(chunk)) = inputs.next().await {
                buffer.extend_from_slice(&chunk);
                while let Some(message) = decoder.decode(&mut buffer).expect("decodable frame") {
                    let SessionMessage::Regular(message) = message else {
                        panic!("client should not send terminal frames");
                    };
                    let input: AppendInput = message.try_into_proto().expect("valid append input");

                    let count = input.records.len() as u64;
                    let start = next_seq_num.fetch_add(count, Ordering::SeqCst);
                    connections.lock().expect("server lock")[index].extend(
                        input
                            .records
                            .iter()
                            .map(|record| String::from_utf8_lossy(&record.body).into_owned()),
                    );

                    let ack = AppendAck {
                        start: Some(position(start)),
                        end: Some(position(start + count)),
                        tail: Some(position(start + count)),
                    };
                    if ack_tx.send(encode(&ack, advise)).is_err() {
                        return;
                    }
                }
            }
            // The request body ended, so the client half-closed. Dropping the
            // sender ends the response cleanly.
        });

        Ok(StreamingResponse::new_for_test(
            StatusCode::OK,
            HeaderMap::new(),
            UnboundedReceiverStream::new(ack_rx),
        ))
    }
}

/// A server that replays one scripted batch per connection.
struct ReadServer {
    /// Query string of each read request, in connection order.
    requests: Arc<Mutex<Vec<String>>>,
    /// Batch to serve per connection, and whether it carries the flag.
    script: Mutex<Vec<(ReadBatch, bool)>>,
}

impl ReadServer {
    fn new(script: Vec<(ReadBatch, bool)>) -> Arc<Self> {
        Arc::new(Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            script: Mutex::new(script),
        })
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("server lock").clone()
    }
}

#[async_trait]
impl client::RequestExecutor for ReadServer {
    async fn execute_unary(&self, _request: client::Request) -> Result<UnaryResponse, HttpError> {
        unreachable!("read session issues no unary requests")
    }

    async fn init_streaming(
        &self,
        request: client::Request,
    ) -> Result<StreamingResponse, HttpError> {
        self.requests
            .lock()
            .expect("server lock")
            .push(request.uri().query().unwrap_or_default().to_owned());

        let mut script = self.script.lock().expect("server lock");
        let scripted = (!script.is_empty()).then(|| script.remove(0));
        drop(script);

        let (batch_tx, batch_rx) = mpsc::unbounded_channel();
        if let Some((batch, advise)) = scripted {
            let _ = batch_tx.send(encode(&batch, advise));
        }

        Ok(StreamingResponse::new_for_test(
            StatusCode::OK,
            HeaderMap::new(),
            UnboundedReceiverStream::new(batch_rx),
        ))
    }
}

fn append_input(body: &'static str) -> crate::types::AppendInput {
    crate::types::AppendInput::new(
        AppendRecordBatch::try_from_iter([AppendRecord::new(body).expect("valid record")])
            .expect("valid batch"),
    )
}

fn read_batch(seq_nums: impl IntoIterator<Item = u64>, tail: u64) -> ReadBatch {
    ReadBatch {
        records: seq_nums
            .into_iter()
            .map(|seq_num| SequencedRecord {
                seq_num,
                timestamp: seq_num,
                headers: Vec::new(),
                body: bytes::Bytes::from_static(b"x"),
            })
            .collect(),
        tail: Some(position(tail)),
    }
}

#[tokio::test]
async fn append_session_moves_to_a_new_connection_on_advice() {
    let server = AppendServer::new(0);
    let session = AppendSession::new(
        basin_client(server.clone()),
        "test-stream".parse().expect("valid stream name"),
        None,
        AppendSessionConfig::default(),
    );

    // The acknowledgement for this input carries the advice, so the session
    // half-closes and reconnects before the next submission is sent.
    let first = session
        .submit(append_input("a"))
        .await
        .expect("submit accepted")
        .await
        .expect("first append acknowledged");
    assert_eq!(first.start.seq_num, 0);
    assert_eq!(first.end.seq_num, 1);

    let second = session
        .submit(append_input("b"))
        .await
        .expect("submit accepted")
        .await
        .expect("second append acknowledged");
    assert_eq!(second.start.seq_num, 1);
    assert_eq!(second.end.seq_num, 2);

    session.close().await.expect("session closed cleanly");

    // Reaching here at all proves the client half-closed the advised
    // connection: the server only ends a response once its request body does.
    assert_eq!(server.connections(), vec![vec!["a"], vec!["b"]]);
}

#[tokio::test]
async fn append_session_stays_put_without_advice() {
    let server = AppendServer::new(usize::MAX);
    let session = AppendSession::new(
        basin_client(server.clone()),
        "test-stream".parse().expect("valid stream name"),
        None,
        AppendSessionConfig::default(),
    );

    for body in ["a", "b", "c"] {
        session
            .submit(append_input(body))
            .await
            .expect("submit accepted")
            .await
            .expect("append acknowledged");
    }
    session.close().await.expect("session closed cleanly");

    assert_eq!(server.connections(), vec![vec!["a", "b", "c"]]);
}

#[tokio::test]
async fn read_session_resumes_after_advice_without_replaying_records() {
    let server = ReadServer::new(vec![
        (read_batch([0, 1], 2), true),
        (read_batch([2], 3), false),
    ]);
    let mut session = read_session(
        basin_client(server.clone()),
        "test-stream".parse().expect("valid stream name"),
        None,
        ReadInput::new(),
        ReadSessionConfig::default(),
    )
    .await
    .expect("read session established");

    let first = session
        .next()
        .await
        .expect("first batch")
        .expect("first batch is ok");
    assert_eq!(
        first.records.iter().map(|r| r.seq_num).collect::<Vec<_>>(),
        vec![0, 1]
    );

    let second = session
        .next()
        .await
        .expect("second batch")
        .expect("second batch is ok");
    assert_eq!(
        second.records.iter().map(|r| r.seq_num).collect::<Vec<_>>(),
        vec![2]
    );

    assert!(session.next().await.is_none());

    let requests = server.requests();
    assert_eq!(requests.len(), 2, "advice should open exactly one new read");
    // The reconnect resumes after the records already delivered.
    assert!(
        requests[1].contains("seq_num=2"),
        "unexpected resume query: {}",
        requests[1]
    );
}

#[tokio::test]
async fn read_session_ends_without_advice() {
    let server = ReadServer::new(vec![(read_batch([0, 1], 2), false)]);
    let mut session = read_session(
        basin_client(server.clone()),
        "test-stream".parse().expect("valid stream name"),
        None,
        ReadInput::new(),
        ReadSessionConfig::default(),
    )
    .await
    .expect("read session established");

    let batch = session
        .next()
        .await
        .expect("first batch")
        .expect("first batch is ok");
    assert_eq!(batch.records.len(), 2);
    assert!(session.next().await.is_none());

    assert_eq!(server.requests().len(), 1);
}
