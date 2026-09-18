//! Retry behavior when the server resets a request's HTTP/2 stream.
//!
//! Runs a bare h2 server that answers the first request of each connection
//! with `RST_STREAM` and serves the retry normally.

use std::{
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Response, header::CONTENT_TYPE};
use prost::Message;
use s2_api::v1::stream::proto;
use s2_sdk::{
    S2,
    error::{AppendError, ClientError, RequestError},
    types::{
        AppendInput, AppendRecord, AppendRecordBatch, AppendRetryPolicy, BasinName,
        ListBasinsInput, RetryConfig, S2Config, S2Endpoints, StreamName,
    },
};
use tokio::net::TcpListener;

#[derive(Clone, Copy)]
enum ResetAt {
    /// Reset before sending any response headers.
    BeforeResponse,
    /// Reset after response headers and a partial body.
    MidResponse,
}

struct ResettingServer {
    endpoint: String,
    requests: Arc<AtomicUsize>,
}

async fn start_server(reset_at: ResetAt) -> ResettingServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let served = requests.clone();

    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let served = served.clone();
            tokio::spawn(async move {
                let mut conn = h2::server::handshake(socket).await.unwrap();
                while let Some(Ok((request, mut respond))) = conn.accept().await {
                    let n = served.fetch_add(1, Ordering::SeqCst);
                    let (parts, mut body) = request.into_parts();
                    // Consume the request body so any frames the client sent
                    // are acknowledged before the stream is reset.
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                    }
                    if n == 0 {
                        match reset_at {
                            ResetAt::BeforeResponse => {
                                respond.send_reset(h2::Reason::INTERNAL_ERROR);
                            }
                            ResetAt::MidResponse => {
                                let response = Response::builder().status(200).body(()).unwrap();
                                let mut stream = respond.send_response(response, false).unwrap();
                                stream.send_data(Bytes::from_static(b"{"), false).unwrap();
                                stream.send_reset(h2::Reason::INTERNAL_ERROR);
                            }
                        }
                        continue;
                    }
                    let (content_type, payload): (&str, Vec<u8>) =
                        if parts.uri.path().ends_with("/records") {
                            let position = proto::StreamPosition {
                                seq_num: 0,
                                timestamp: 0,
                            };
                            let ack = proto::AppendAck {
                                start: Some(position),
                                end: Some(proto::StreamPosition {
                                    seq_num: 1,
                                    timestamp: 0,
                                }),
                                tail: Some(proto::StreamPosition {
                                    seq_num: 1,
                                    timestamp: 0,
                                }),
                            };
                            ("application/protobuf", ack.encode_to_vec())
                        } else {
                            (
                                "application/json",
                                br#"{"basins":[],"has_more":false}"#.to_vec(),
                            )
                        };
                    let response = Response::builder()
                        .status(200)
                        .header(CONTENT_TYPE, content_type)
                        .body(())
                        .unwrap();
                    let mut stream = respond.send_response(response, false).unwrap();
                    stream.send_data(Bytes::from(payload), true).unwrap();
                }
            });
        }
    });

    ResettingServer { endpoint, requests }
}

fn config(server: &ResettingServer, retry: RetryConfig) -> S2Config {
    S2Config::new("token")
        .with_endpoints(S2Endpoints::for_endpoint(&server.endpoint).unwrap())
        .with_request_timeout(Duration::from_secs(5))
        .with_retry(
            retry
                .with_min_base_delay(Duration::from_millis(1))
                .with_max_base_delay(Duration::from_millis(10)),
        )
}

fn append_input() -> AppendInput {
    let record = AppendRecord::new("hello").unwrap();
    AppendInput::new(AppendRecordBatch::try_from_iter([record]).unwrap())
}

async fn list_basins_retries(reset_at: ResetAt) {
    let server = start_server(reset_at).await;
    let s2 = S2::new(config(&server, RetryConfig::new())).unwrap();

    let page = s2.list_basins(ListBasinsInput::new()).await.unwrap();

    assert!(page.values.is_empty());
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn list_basins_retries_reset_before_response() {
    list_basins_retries(ResetAt::BeforeResponse).await;
}

#[tokio::test]
async fn list_basins_retries_reset_mid_response() {
    list_basins_retries(ResetAt::MidResponse).await;
}

#[tokio::test]
async fn reset_without_retries_is_a_stream_reset() {
    let server = start_server(ResetAt::BeforeResponse).await;
    let retry = RetryConfig::new().with_max_attempts(NonZeroU32::new(1).unwrap());
    let s2 = S2::new(config(&server, retry)).unwrap();

    let err = s2.list_basins(ListBasinsInput::new()).await.unwrap_err();

    let RequestError::Client(client) = err else {
        panic!("unexpected error: {err:?}");
    };
    assert!(matches!(client, ClientError::StreamReset(_)), "{client:?}");
    assert!(client.is_retryable());
    assert!(!client.has_no_side_effects());
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
}

fn stream(s2: &S2) -> s2_sdk::S2Stream {
    let basin: BasinName = "reset-basin".parse().unwrap();
    let name: StreamName = "reset-stream".parse().unwrap();
    s2.basin(basin).stream(name)
}

#[tokio::test]
async fn append_retries_reset_when_all_appends_retry() {
    let server = start_server(ResetAt::BeforeResponse).await;
    let retry = RetryConfig::new().with_append_retry_policy(AppendRetryPolicy::All);
    let s2 = S2::new(config(&server, retry)).unwrap();

    let ack = stream(&s2).append(append_input()).await.unwrap();

    assert_eq!(ack.end.seq_num, 1);
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn append_does_not_retry_reset_when_side_effects_are_possible() {
    let server = start_server(ResetAt::BeforeResponse).await;
    let retry = RetryConfig::new().with_append_retry_policy(AppendRetryPolicy::NoSideEffects);
    let s2 = S2::new(config(&server, retry)).unwrap();

    let err = stream(&s2).append(append_input()).await.unwrap_err();

    let AppendError::Request(RequestError::Client(client)) = err else {
        panic!("unexpected error: {err:?}");
    };
    assert!(matches!(client, ClientError::StreamReset(_)), "{client:?}");
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
}
