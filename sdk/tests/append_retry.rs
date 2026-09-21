use std::{
    collections::VecDeque,
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use h2::{RecvStream, server::SendResponse};
use http::{Request, Response, StatusCode};
use prost::Message;
use rstest::rstest;
use s2_api::v1::stream::{
    proto,
    s2s::{CompressionAlgorithm, FrameDecoder, SessionMessage, TerminalMessage},
};
use s2_sdk::{
    S2, S2Stream,
    append_session::AppendSessionConfig,
    error::{AppendConditionFailed, AppendError, AppendSessionError, ErrorCode},
    producer::ProducerConfig,
    types::{
        AppendInput, AppendRecord, AppendRecordBatch, AppendRetryPolicy, RetryConfig, S2Config,
        S2Endpoints,
    },
};
use tokio::{net::TcpListener, task::JoinSet, time::timeout};
use tokio_util::{codec::Decoder, task::AbortOnDropHandle};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug)]
enum Reply {
    Error(ErrorCode),
    ConditionFailed,
    Ack,
    RejectRequest(ErrorCode),
}

impl Reply {
    fn error(self) -> Option<(StatusCode, String)> {
        match self {
            Self::Error(code) | Self::RejectRequest(code) => Some((
                code.status(),
                serde_json::json!({"code": code.to_string(), "message": "test"}).to_string(),
            )),
            Self::ConditionFailed => Some((
                StatusCode::PRECONDITION_FAILED,
                r#"{"seq_num_mismatch":1}"#.to_owned(),
            )),
            Self::Ack => None,
        }
    }
}

struct TestServer {
    stream: S2Stream,
    attempts: Arc<AtomicUsize>,
    _task: AbortOnDropHandle<()>,
}

impl TestServer {
    async fn new(scripts: Vec<Vec<Reply>>, policy: AppendRetryPolicy) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        let max_attempts = NonZeroU32::new(scripts.len() as u32).unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            let mut scripts = VecDeque::from(scripts);
            let mut handlers = JoinSet::new();
            loop {
                tokio::select! {
                    request = connection.accept() => {
                        let Some(request) = request else { break };
                        let (request, response) = request.unwrap();
                        count.fetch_add(1, Ordering::Relaxed);
                        let script = scripts.pop_front().expect("unexpected retry");
                        handlers.spawn(serve(request, response, script));
                    }
                    result = handlers.join_next(), if !handlers.is_empty() => {
                        result.unwrap().unwrap();
                    }
                }
            }
        });
        let stream = S2::new(
            S2Config::new("test-token")
                .with_endpoints(S2Endpoints::for_endpoint(&endpoint).unwrap())
                .with_retry(
                    RetryConfig::new()
                        .with_max_attempts(max_attempts)
                        .with_min_base_delay(Duration::ZERO)
                        .with_max_base_delay(Duration::ZERO)
                        .with_append_retry_policy(policy),
                ),
        )
        .unwrap()
        .basin("test-basin".parse().unwrap())
        .stream("test-stream".parse().unwrap());
        Self {
            stream,
            attempts,
            _task: AbortOnDropHandle::new(task),
        }
    }
}

fn ack() -> proto::AppendAck {
    let start = proto::StreamPosition {
        seq_num: 0,
        timestamp: 0,
    };
    let end = proto::StreamPosition {
        seq_num: 1,
        timestamp: 0,
    };
    proto::AppendAck {
        start: Some(start),
        end: Some(end),
        tail: Some(end),
    }
}

async fn serve(
    request: Request<RecvStream>,
    mut response: SendResponse<Bytes>,
    script: Vec<Reply>,
) {
    if let Reply::RejectRequest(_) = script[0] {
        let (status, body) = script[0].error().unwrap();
        response
            .send_response(Response::builder().status(status).body(()).unwrap(), false)
            .unwrap()
            .send_data(body.into(), true)
            .unwrap();
        return;
    }
    let streaming = request.headers()[http::header::CONTENT_TYPE] == "s2s/proto";
    let mut body = request.into_body();
    if !streaming {
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        let (status, payload) = match script[0].error() {
            Some((status, body)) => (status, Bytes::from(body)),
            None => (StatusCode::OK, Bytes::from(ack().encode_to_vec())),
        };
        response
            .send_response(Response::builder().status(status).body(()).unwrap(), false)
            .unwrap()
            .send_data(payload, true)
            .unwrap();
        return;
    }

    let mut response = response.send_response(Response::new(()), false).unwrap();
    let mut buffer = BytesMut::new();
    let mut decoder = FrameDecoder;
    let mut replies = VecDeque::from(script);
    while let Some(Ok(chunk)) = body.data().await {
        body.flow_control().release_capacity(chunk.len()).unwrap();
        buffer.extend_from_slice(&chunk);
        while decoder.decode(&mut buffer).unwrap().is_some() {
            let reply = replies.pop_front().expect("unexpected append");
            if let Some((status, body)) = reply.error() {
                let message = SessionMessage::from(TerminalMessage {
                    status: status.as_u16(),
                    body,
                });
                response.send_data(message.encode(), true).unwrap();
                return;
            }
            let message = SessionMessage::regular(CompressionAlgorithm::None, &ack()).unwrap();
            response.send_data(message.encode(), false).unwrap();
        }
    }
    let _ = response.send_data(Bytes::new(), true);
}

fn input() -> AppendInput {
    AppendInput::new(
        AppendRecordBatch::try_from_iter([AppendRecord::new("record").unwrap()]).unwrap(),
    )
    .with_match_seq_num(0)
}

async fn append(server: &TestServer, streaming: bool) -> Result<(), AppendSessionError> {
    timeout(TEST_TIMEOUT, async {
        if streaming {
            let session = server.stream.append_session(AppendSessionConfig::new());
            session.submit(input()).await?.await?;
            session.close().await?;
        } else {
            server.stream.append(input()).await?;
        }
        Ok(())
    })
    .await
    .expect("append timed out")
}

fn assert_server_error(error: &AppendSessionError, code: ErrorCode) {
    let cause = error.request_error().unwrap().server_error().unwrap();
    assert_eq!(cause.known_code(), Some(code));
    assert_eq!(error.is_retryable(), code.is_retryable());
    assert_eq!(error.has_no_side_effects(), code.has_no_side_effects());
}

#[rstest]
#[case::permission_denied(Reply::Error(ErrorCode::PermissionDenied))]
#[case::condition_failed(Reply::ConditionFailed)]
#[case::retry_budget_exhausted(Reply::Error(ErrorCode::RateLimited))]
#[case::reconnect_rejected(Reply::RejectRequest(ErrorCode::PermissionDenied))]
#[case::later_indefinite_failure(Reply::Error(ErrorCode::Storage))]
#[tokio::test]
async fn first_indefinite_error_is_returned(
    #[values(false, true)] streaming: bool,
    #[case] last: Reply,
) {
    let server = TestServer::new(
        vec![vec![Reply::Error(ErrorCode::Unavailable)], vec![last]],
        AppendRetryPolicy::All,
    )
    .await;
    let error = append(&server, streaming).await.unwrap_err();
    assert_server_error(&error, ErrorCode::Unavailable);
    assert_eq!(server.attempts.load(Ordering::Relaxed), 2);
}

#[rstest]
#[tokio::test]
async fn first_indefinite_error_survives_other_failures(
    #[values(false, true)] streaming: bool,
    #[values(ErrorCode::RateLimited, ErrorCode::Storage)] intermediate: ErrorCode,
) {
    let server = TestServer::new(
        vec![
            vec![Reply::Error(ErrorCode::RateLimited)],
            vec![Reply::Error(ErrorCode::Unavailable)],
            vec![Reply::Error(intermediate)],
            vec![Reply::Error(ErrorCode::PermissionDenied)],
            vec![Reply::Ack],
        ],
        AppendRetryPolicy::All,
    )
    .await;
    let error = append(&server, streaming).await.unwrap_err();
    assert_server_error(&error, ErrorCode::Unavailable);
    assert_eq!(server.attempts.load(Ordering::Relaxed), 4);
}

#[rstest]
#[case::permission_denied(Reply::Error(ErrorCode::PermissionDenied))]
#[case::condition_failed(Reply::ConditionFailed)]
#[tokio::test]
async fn definite_failures_remain_definite(
    #[values(false, true)] streaming: bool,
    #[case] last: Reply,
) {
    let server = TestServer::new(
        vec![vec![Reply::Error(ErrorCode::RateLimited)], vec![last]],
        AppendRetryPolicy::All,
    )
    .await;
    let error = append(&server, streaming).await.unwrap_err();
    assert!(error.has_no_side_effects());
    assert!(!error.is_retryable());
    match last {
        Reply::ConditionFailed => assert!(matches!(
            error,
            AppendSessionError::Append(AppendError::ConditionFailed(
                AppendConditionFailed::SeqNumMismatch(1)
            ))
        )),
        Reply::Error(code) => assert_server_error(&error, code),
        _ => unreachable!(),
    }
    assert_eq!(server.attempts.load(Ordering::Relaxed), 2);
}

#[rstest]
#[tokio::test]
async fn successful_retry_returns_ack(#[values(false, true)] streaming: bool) {
    let server = TestServer::new(
        vec![vec![Reply::Error(ErrorCode::Unavailable)], vec![Reply::Ack]],
        AppendRetryPolicy::All,
    )
    .await;
    append(&server, streaming).await.unwrap();
    assert_eq!(server.attempts.load(Ordering::Relaxed), 2);
}

#[rstest]
#[tokio::test]
async fn no_side_effects_policy_does_not_retry_ambiguous_append(
    #[values(false, true)] streaming: bool,
) {
    let server = TestServer::new(
        vec![
            vec![Reply::Error(ErrorCode::Unavailable)],
            vec![Reply::Error(ErrorCode::PermissionDenied)],
        ],
        AppendRetryPolicy::NoSideEffects,
    )
    .await;
    let error = append(&server, streaming).await.unwrap_err();
    assert_server_error(&error, ErrorCode::Unavailable);
    assert_eq!(server.attempts.load(Ordering::Relaxed), 1);
}

#[rstest]
#[tokio::test]
async fn session_close_returns_original_indefinite_error(
    #[values(false, true)] close_before_ack: bool,
) {
    let server = TestServer::new(
        vec![
            vec![Reply::Error(ErrorCode::Unavailable)],
            vec![Reply::Error(ErrorCode::PermissionDenied)],
            vec![Reply::Ack],
        ],
        AppendRetryPolicy::All,
    )
    .await;
    timeout(TEST_TIMEOUT, async {
        let session = server.stream.append_session(AppendSessionConfig::new());
        let ticket = session.submit(input()).await.unwrap();
        let (append_result, close_result) = if close_before_ack {
            tokio::join!(ticket, session.close())
        } else {
            (ticket.await, session.close().await)
        };
        assert_server_error(&append_result.unwrap_err(), ErrorCode::Unavailable);
        assert_server_error(&close_result.unwrap_err(), ErrorCode::Unavailable);
        assert_eq!(server.attempts.load(Ordering::Relaxed), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn acknowledged_batch_does_not_taint_later_batch() {
    let server = TestServer::new(
        vec![
            vec![Reply::Error(ErrorCode::Unavailable)],
            vec![Reply::Ack, Reply::Error(ErrorCode::PermissionDenied)],
        ],
        AppendRetryPolicy::All,
    )
    .await;
    timeout(TEST_TIMEOUT, async {
        let session = server.stream.append_session(AppendSessionConfig::new());
        session.submit(input()).await.unwrap().await.unwrap();
        let error = session.submit(input()).await.unwrap().await.unwrap_err();
        assert_server_error(&error, ErrorCode::PermissionDenied);
        assert_server_error(
            &session.close().await.unwrap_err(),
            ErrorCode::PermissionDenied,
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn producer_preserves_batch_uncertainty() {
    let server = TestServer::new(
        vec![
            vec![Reply::Error(ErrorCode::Unavailable)],
            vec![Reply::RejectRequest(ErrorCode::PermissionDenied)],
        ],
        AppendRetryPolicy::All,
    )
    .await;
    timeout(TEST_TIMEOUT, async {
        let producer = server.stream.producer(ProducerConfig::new());
        let error = producer
            .submit(AppendRecord::new("record").unwrap())
            .await
            .unwrap()
            .await
            .unwrap_err();
        assert!(!error.has_no_side_effects());
        assert!(error.is_retryable());
        assert_eq!(
            error
                .request_error()
                .unwrap()
                .server_error()
                .unwrap()
                .known_code(),
            Some(ErrorCode::Unavailable),
        );
        let close_error = producer.close().await.unwrap_err();
        assert!(!close_error.has_no_side_effects());
        assert_eq!(
            close_error
                .request_error()
                .unwrap()
                .server_error()
                .unwrap()
                .known_code(),
            Some(ErrorCode::Unavailable),
        );
    })
    .await
    .unwrap();
}
