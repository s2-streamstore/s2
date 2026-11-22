use std::{
    error::Error as StdError,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use base64ct::Encoding as _;
use bytes::{Bytes, BytesMut};
use http::Response;
use prost::Message as _;
use s2_api::v1::{
    self as api,
    stream::{
        proto::{
            ReadBatch as ProtoReadBatch, SequencedRecord as ProtoSequencedRecord,
            StreamPosition as ProtoStreamPosition,
        },
        s2s::SessionMessage,
    },
};
use s2_sdk::{
    S2, S2Basin, S2Stream,
    append_session::{AppendSession, AppendSessionConfig},
    error::{AppendError, AppendSessionError, ReadError, ReadSessionError, RequestError, S2Error},
    producer::{Producer, ProducerConfig},
    read_session::{ReadBatchSession, ReadSession, ReadSessionConfig, ReadSessionState},
    types::{
        AccessTokenScopeInput, AccountEndpoint, AppendInput, AppendRecord, AppendRecordBatch,
        AppendRetryPolicy, BasinEndpoint, Compression, CreateBasinInput, CreateStreamInput,
        EncryptionKey, Header, Http2Config, IssueAccessTokenInput, ListBasinsInput, Operation,
        ReadFrom, ReadInput, RetryConfig, S2Config, S2Endpoints,
    },
};

use crate::support::*;

// spec: r1 C8
#[tokio::test]
async fn spec_c8_redirects_are_never_followed() {
    let target = MockH2Server::from_responses([CannedResponse::new(200, "ok")]).await;
    let location = format!("{}/v1/streams/test-stream/records", target.endpoint_url());
    let (basin_name, stream_name) = test_basin_and_stream();

    for status in [301u16, 302, 307, 308] {
        let origin = MockH2Server::from_responses([
            CannedResponse::new(status, "").with_header("location", location.as_str()),
            CannedResponse::new(status, "").with_header("location", location.as_str()),
        ])
        .await;
        let s2 = origin.client(no_retry_config());
        let stream = s2.basin(basin_name.clone()).stream(stream_name.clone());

        let append_err = stream
            .append(sample_append_input())
            .await
            .expect_err("redirect must fail append");
        let AppendError::Server(se) = &append_err else {
            panic!("expected ServerError for {status}, got {append_err:?}");
        };
        assert_eq!(se.status.as_u16(), status);
        assert_eq!(se.code, None);
        assert_eq!(se.message, status.to_string());
        assert!(!append_err.is_retryable());
        assert!(!append_err.has_no_side_effects());

        let read_err = stream
            .read(ReadInput::new())
            .await
            .expect_err("redirect must fail read");
        let ReadError::Server(se) = &read_err else {
            panic!("expected ServerError for {status}, got {read_err:?}");
        };
        assert_eq!(se.status.as_u16(), status);
        assert!(!read_err.is_retryable());
        assert!(read_err.has_no_side_effects());
    }

    assert_eq!(
        target.request_count(),
        0,
        "redirect target server must never be contacted"
    );
}

// spec: r1 C6, E2
#[tokio::test]
async fn spec_c6_e2_compressed_and_corrupt_error_bodies() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let gzip_body = gzip_bytes(br#"{"code":"server_draining","message":"draining"}"#);
    let zstd_body = zstd_bytes(br#"{"code":"unavailable","message":"busy"}"#);

    let server = MockH2Server::from_responses([
        CannedResponse::new(503, gzip_body).with_header("content-encoding", "gzip"),
        CannedResponse::new(503, zstd_body).with_header("content-encoding", "zstd"),
        CannedResponse::new(500, Bytes::from_static(b"not valid gzip bytes"))
            .with_header("content-encoding", "gzip"),
        CannedResponse::new(502, Bytes::from_static(b"brotli bytes"))
            .with_header("content-encoding", "br"),
    ])
    .await;
    let s2 = server.client(no_retry_config());
    let stream = s2.basin(basin_name).stream(stream_name);

    // 1. gzip error body decompressed
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::Server(se) = &err else {
        panic!("expected ServerError, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 503);
    assert_eq!(se.code.as_deref(), Some("server_draining"));
    assert_eq!(se.message, "draining");
    assert!(err.is_retryable());
    assert!(err.has_no_side_effects());

    // 2. zstd error body decompressed
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::Server(se) = &err else {
        panic!("expected ServerError, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 503);
    assert_eq!(se.code.as_deref(), Some("unavailable"));
    assert_eq!(se.message, "busy");
    assert!(err.is_retryable());
    assert!(!err.has_no_side_effects());

    // 3. corrupt gzip body on non-2xx still produces ServerError (not ProtocolError)
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::Server(se) = &err else {
        panic!("expected ServerError on corrupt gzip error body, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 500);
    assert_eq!(se.code, None);
    assert_eq!(se.message, "500");
    assert!(err.is_retryable());
    assert!(!err.has_no_side_effects());

    // 4. unsupported content-encoding on non-2xx still produces ServerError
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::Server(se) = &err else {
        panic!("expected ServerError on unsupported encoding error body, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 502);
    assert_eq!(se.code, None);
    assert_eq!(se.message, "502");
    assert!(err.is_retryable());
    assert!(!err.has_no_side_effects());

    // 5. C6: Unary requests compress with configured encoding & advertise only that encoding;
    //    session frames compress only when payload >= 1 KiB.
    let seen_unary = Arc::new(Mutex::new(Vec::<(Option<String>, Option<String>)>::new()));
    let seen_session_compressions = Arc::new(Mutex::new(Vec::<u8>::new()));
    let comp_server = MockH2Server::start({
        let seen_unary = seen_unary.clone();
        let seen_session_compressions = seen_session_compressions.clone();
        move |_conn_id, req, mut respond| {
            let seen_unary = seen_unary.clone();
            let seen_session_compressions = seen_session_compressions.clone();
            async move {
                let is_s2s = req
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    == Some("s2s/proto");
                if is_s2s {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "s2s/proto")
                        .body(())
                        .unwrap();
                    let Ok(mut send) = respond.send_response(resp, false) else {
                        return;
                    };
                    let mut body = req.into_body();
                    let mut buf = BytesMut::new();
                    let mut next_seq = 0u64;
                    while let Some(msg @ SessionMessage::Regular(_)) =
                        read_one_s2s_frame(&mut body, &mut buf, true).await
                    {
                        let comp_bits = (msg.encode()[3] & 0b0110_0000) >> 5;
                        seen_session_compressions.lock().unwrap().push(comp_bits);
                        let _ = send.send_data(
                            encode_s2s_regular_frame(
                                &proto_append_ack(next_seq, next_seq + 1),
                                false,
                            ),
                            false,
                        );
                        next_seq += 1;
                    }
                    let _ = send.send_data(Bytes::new(), true);
                } else {
                    let ce = req
                        .headers()
                        .get("content-encoding")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    let ae = req
                        .headers()
                        .get("accept-encoding")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    seen_unary.lock().unwrap().push((ce, ae));
                    let mut body = req.into_body();
                    while let Some(Ok(_)) = body.data().await {}
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(proto_append_ack(0, 1)), true);
                    }
                }
            }
        }
    })
    .await;

    let ep = comp_server.endpoint_url();
    let make_compressed_stream = |compression: Compression| {
        let endpoints = S2Endpoints::new(
            AccountEndpoint::new(&ep).unwrap(),
            BasinEndpoint::new(&ep).unwrap(),
        )
        .unwrap();
        let (b, s) = test_basin_and_stream();
        S2::new(
            S2Config::new("test-token")
                .with_endpoints(endpoints)
                .with_compression(compression)
                .with_retry(no_retry_config()),
        )
        .unwrap()
        .basin(b)
        .stream(s)
    };
    let large_input = AppendInput::new(
        AppendRecordBatch::try_from_iter([AppendRecord::new(vec![b'x'; 2048]).unwrap()]).unwrap(),
    );

    make_compressed_stream(Compression::None)
        .append(sample_append_input())
        .await
        .unwrap();
    let gzip_stream = make_compressed_stream(Compression::Gzip);
    gzip_stream.append(sample_append_input()).await.unwrap();
    let zstd_stream = make_compressed_stream(Compression::Zstd);
    zstd_stream.append(sample_append_input()).await.unwrap();

    assert_eq!(
        *seen_unary.lock().unwrap(),
        vec![
            (None, None),
            (Some("gzip".to_owned()), Some("gzip".to_owned())),
            (Some("zstd".to_owned()), Some("zstd".to_owned())),
        ],
        "C6: unary requests compress and advertise only the configured algorithm"
    );

    // Session frames: < 1 KiB stays uncompressed; >= 1 KiB uses configured algorithm.
    let gzip_session = gzip_stream
        .append_session(AppendSessionConfig::new())
        .unwrap();
    gzip_session
        .submit(sample_append_input())
        .await
        .unwrap()
        .await
        .unwrap();
    gzip_session
        .submit(large_input.clone())
        .await
        .unwrap()
        .await
        .unwrap();
    gzip_session.close().await.unwrap();

    let zstd_session = zstd_stream
        .append_session(AppendSessionConfig::new())
        .unwrap();
    zstd_session
        .submit(sample_append_input())
        .await
        .unwrap()
        .await
        .unwrap();
    zstd_session
        .submit(large_input)
        .await
        .unwrap()
        .await
        .unwrap();
    zstd_session.close().await.unwrap();

    // S2S wire compression bits: 0 = None, 1 = Zstd, 2 = Gzip.
    assert_eq!(
        *seen_session_compressions.lock().unwrap(),
        vec![0, 2, 0, 1],
        "C6: session frames < 1 KiB stay uncompressed; >= 1 KiB use configured encoding"
    );
}

// spec: r1 E2, E2a, E2b, E4e, F1
#[tokio::test]
async fn spec_e2_typed_412_416_extra_fields_and_fallbacks() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let server = MockH2Server::from_responses([
        CannedResponse::new(412, r#"{"seq_num_mismatch": 7, "future_field": true}"#),
        CannedResponse::new(412, r#"{"fencing_token_mismatch": "tok", "extra": 123}"#),
        CannedResponse::new(412, r#"{"seq_num_mismatch": 18446744073709551616}"#),
        CannedResponse::new(
            416,
            r#"{"tail": {"seq_num": 9, "timestamp": 1000, "extra": "ok"}, "other": 1}"#,
        ),
        CannedResponse::new(416, r#"{"tail": "not-an-object"}"#),
    ])
    .await;
    let s2 = server.client(no_retry_config());
    let stream = s2.basin(basin_name).stream(stream_name);

    // 1. 412 seq_num_mismatch with unknown field
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::SeqNumMismatch(e) = &err else {
        panic!("expected SeqNumMismatch, got {err:?}");
    };
    assert_eq!(e.assignable_seq_num, 7);
    assert_eq!(e.server.status.as_u16(), 412);
    assert!(!err.is_retryable());
    assert!(err.has_no_side_effects());

    // 2. 412 fencing_token_mismatch with unknown field
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::FencingTokenMismatch(e) = &err else {
        panic!("expected FencingTokenMismatch, got {err:?}");
    };
    assert_eq!(&*e.current_fencing_token, "tok");
    assert_eq!(e.server.status.as_u16(), 412);

    // 3. 412 out-of-range u64 falls back to plain ServerError, still definite & non-retryable (E4e)
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let AppendError::Server(se) = &err else {
        panic!("expected plain ServerError on u64 overflow 412, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 412);
    assert!(!err.is_retryable());
    assert!(err.has_no_side_effects());

    // 4. 416 with extra fields still produces ReadUnwrittenError
    let err = stream.read(ReadInput::new()).await.unwrap_err();
    let ReadError::ReadUnwritten(e) = &err else {
        panic!("expected ReadUnwritten, got {err:?}");
    };
    assert_eq!(e.tail.seq_num, 9);
    assert_eq!(e.tail.timestamp, 1000);
    assert_eq!(e.server.status.as_u16(), 416);

    // 5. 416 malformed body falls back to plain ServerError, still definite on read
    let err = stream.read(ReadInput::new()).await.unwrap_err();
    let ReadError::Server(se) = &err else {
        panic!("expected plain ServerError on malformed 416, got {err:?}");
    };
    assert_eq!(se.status.as_u16(), 416);
    assert!(!err.is_retryable());
    assert!(err.has_no_side_effects());
}

// spec: r1 E1, E5, E5a, E5b, E7
#[tokio::test]
async fn spec_e5_e7_indefinite_append_wrapping_and_context() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_all = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO)
        .with_append_retry_policy(AppendRetryPolicy::All);

    // Case 1: indefinite attempt 1 + definite attempt 2 -> wrapped in IndefiniteAppendError
    let server = MockH2Server::from_responses([
        CannedResponse::new(503, r#"{"code":"unavailable","message":"busy"}"#),
        CannedResponse::new(412, r#"{"seq_num_mismatch":5}"#),
    ])
    .await;
    let stream = server
        .client(fast_retry_all)
        .basin(basin_name.clone())
        .stream(stream_name.clone());

    let err = stream.append(sample_append_input()).await.unwrap_err();
    assert!(!err.is_retryable());
    assert!(!err.has_no_side_effects());
    assert!(
        err.server_error().is_none(),
        "E5a: wrapper hides ServerError"
    );
    let display = err.to_string();
    assert!(display.contains("append"), "E7: {display}");
    assert!(display.contains("test-basin"), "E7: {display}");
    assert!(display.contains("test-stream"), "E7: {display}");
    assert!(display.contains("after 2 attempts"), "E7: {display}");

    let AppendError::IndefiniteAppend(wrapped) = &err else {
        panic!("expected IndefiniteAppend, got {err:?}");
    };
    assert!(matches!(
        wrapped.final_attempt_error(),
        AppendError::SeqNumMismatch(e) if e.assignable_seq_num == 5
    ));
    let source = wrapped
        .source()
        .expect("E5b: IndefiniteAppendError sets source");
    assert!(
        source.downcast_ref::<AppendError>().is_some(),
        "E5b: source must downcast directly to AppendError"
    );

    let base: S2Error = err.into();
    assert!(base.server_error().is_none(), "E1/E5a: S2Error wrapper");
    assert!(!base.has_no_side_effects());
    assert!(!base.is_retryable());

    // Case 2: indefinite attempt 1 + indefinite attempt 2 -> NOT wrapped
    let server = MockH2Server::from_responses([
        CannedResponse::new(503, r#"{"code":"unavailable","message":"busy 1"}"#),
        CannedResponse::new(503, r#"{"code":"unavailable","message":"busy 2"}"#),
    ])
    .await;
    let stream = server
        .client(fast_retry_all)
        .basin(basin_name.clone())
        .stream(stream_name.clone());
    let err = stream.append(sample_append_input()).await.unwrap_err();
    assert!(
        matches!(err, AppendError::Server(ref se) if se.message == "busy 2"),
        "indefinite final error must not be wrapped: {err:?}"
    );
    assert!(err.to_string().contains("after 2 attempts"));

    // Case 3: definite attempt 1 + definite attempt 2 -> NOT wrapped
    let server = MockH2Server::from_responses([
        CannedResponse::new(503, r#"{"code":"server_draining","message":"draining"}"#),
        CannedResponse::new(404, r#"{"code":"stream_not_found","message":"missing"}"#),
    ])
    .await;
    let stream = server
        .client(fast_retry_all)
        .basin(basin_name.clone())
        .stream(stream_name.clone());
    let err = stream.append(sample_append_input()).await.unwrap_err();
    assert!(
        matches!(err, AppendError::Server(ref se) if se.code.as_deref() == Some("stream_not_found")),
        "definite earlier attempt must not trigger IndefiniteAppend: {err:?}"
    );
    assert!(err.has_no_side_effects());
    assert!(err.to_string().contains("after 2 attempts"));

    // Case 4: single attempt omits attempt count from Display (E7)
    let server = MockH2Server::from_responses([CannedResponse::new(
        404,
        r#"{"code":"stream_not_found","message":"missing"}"#,
    )])
    .await;
    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);
    let err = stream.append(sample_append_input()).await.unwrap_err();
    let display = err.to_string();
    assert!(display.contains("append"), "E7: {display}");
    assert!(display.contains("test-basin"), "E7: {display}");
    assert!(display.contains("test-stream"), "E7: {display}");
    assert!(!display.contains("attempts"), "E7: {display}");
}

// spec: r1 E2, E2a, E2b, E5a, E5b, E6, T9
#[tokio::test]
async fn spec_e2_e6_s2s_terminal_frames_end_to_end() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. Append session receiving 412 seq_num_mismatch terminal frame.
    let append_terminal = encode_s2s_terminal_frame(412, br#"{"seq_num_mismatch":12}"#);
    let server = MockH2Server::start(move |_conn_id, req, mut respond| {
        let frame = append_terminal.clone();
        async move {
            let resp = Response::builder()
                .status(200)
                .header("content-type", "s2s/proto")
                .body(())
                .unwrap();
            let Ok(mut send) = respond.send_response(resp, false) else {
                return;
            };
            let mut body = req.into_body();
            let _ = body.data().await;
            let _ = send.send_data(frame, true);
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone());
    let session = stream.append_session(AppendSessionConfig::new()).unwrap();

    let ticket = session
        .submit(sample_append_input())
        .await
        .expect("initial submit accepted");
    let err = ticket.await.expect_err("terminal frame must fail ticket");
    let AppendSessionError::SeqNumMismatch(e) = &err else {
        panic!("expected AppendSessionError::SeqNumMismatch, got {err:?}");
    };
    assert_eq!(e.assignable_seq_num, 12);
    assert_eq!(e.server.status.as_u16(), 412);
    assert!(!err.is_retryable());
    assert!(err.has_no_side_effects());

    // E6: subsequent submit after terminal failure fails with SessionClosedError carrying failure.
    let closed_err = match session.submit(sample_append_input()).await {
        Err(e) => e,
        Ok(t) => t.await.expect_err("failed session must fail"),
    };
    let AppendSessionError::SessionClosed(closed) = &closed_err else {
        panic!("expected SessionClosedError on closed session, got {closed_err:?}");
    };
    assert!(closed_err.has_no_side_effects());
    assert!(!closed_err.is_retryable());
    assert!(
        closed_err.server_error().is_none(),
        "E5a: SessionClosedError must not match as inner ServerError"
    );
    assert!(matches!(
        closed.failure(),
        Some(AppendSessionError::SeqNumMismatch(inner)) if inner.assignable_seq_num == 12
    ));
    let source = closed
        .source()
        .expect("E5b: SessionClosedError sets source");
    assert!(
        source.downcast_ref::<AppendSessionError>().is_some(),
        "E5b: source must downcast directly to AppendSessionError"
    );
    assert!(
        closed.to_string().contains("12"),
        "E6: message includes failure message: {}",
        closed
    );

    // 2. Read session receiving 416 tail terminal frame.
    let read_terminal =
        encode_s2s_terminal_frame(416, br#"{"tail":{"seq_num":5,"timestamp":1234}}"#);
    let read_server = MockH2Server::start(move |_conn_id, _req, mut respond| {
        let frame = read_terminal.clone();
        async move {
            let resp = Response::builder()
                .status(200)
                .header("content-type", "s2s/proto")
                .body(())
                .unwrap();
            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send.send_data(frame, true);
            }
        }
    })
    .await;

    let read_stream = read_server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);
    let mut sess = read_stream
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .expect("open read session");
    let read_err = sess
        .next()
        .await
        .expect("expected terminal error item")
        .expect_err("expected terminal error");
    let ReadSessionError::ReadUnwritten(e) = &read_err else {
        panic!("expected ReadSessionError::ReadUnwritten, got {read_err:?}");
    };
    assert_eq!(e.tail.seq_num, 5);
    assert_eq!(e.tail.timestamp, 1234);
    assert_eq!(e.server.status.as_u16(), 416);
    assert!(!read_err.is_retryable());
    assert!(read_err.has_no_side_effects());
}

// spec: r1 C12
#[tokio::test]
async fn spec_c12_client_close_aborts_inflight_and_sessions_and_rejects_new_calls() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // Server holds all requests open indefinitely (except GET /records s2s sends 200 headers
    // immediately so ReadSession enters its active streaming state) and signals when all 4
    // expected requests have arrived so close() deterministically aborts in-flight calls.
    let arrived = Arc::new(AtomicUsize::new(0));
    let all_arrived = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let arrived = arrived.clone();
        let all_arrived = all_arrived.clone();
        move |_conn_id, req, respond| {
            let arrived = arrived.clone();
            let all_arrived = all_arrived.clone();
            async move {
                let is_s2s = header_str(&req, "content-type") == Some("s2s/proto");
                let is_post = req.method() == http::Method::POST;
                let mut body = req.into_body();
                let _hold_send = if is_s2s {
                    let Some(s2s) = S2sResponder::open(respond) else {
                        return;
                    };
                    if is_post {
                        // Wait until the append session's batch frame actually arrives on the wire
                        // so `append_ticket` is guaranteed `sent` (`A6a`, `C12`).
                        let mut buf = BytesMut::new();
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    }
                    Some(s2s)
                } else {
                    let _keep_respond = respond;
                    if arrived.fetch_add(1, Ordering::SeqCst) + 1 >= 4 {
                        all_arrived.notify_waiters();
                    }
                    std::future::pending::<()>().await;
                    unreachable!()
                };
                if arrived.fetch_add(1, Ordering::SeqCst) + 1 >= 4 {
                    all_arrived.notify_waiters();
                }
                let _keep = (body, _hold_send);
                std::future::pending::<()>().await;
            }
        }
    })
    .await;

    let s2 = server.client(no_retry_config());
    let basin = s2.basin(basin_name.clone());
    let stream = basin.stream(stream_name.clone());

    let append_session = stream
        .append_session(AppendSessionConfig::new())
        .expect("open append session");
    let producer = stream
        .producer(ProducerConfig::new().with_linger(Duration::from_secs(60)))
        .expect("open producer");
    let mut read_session = stream
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .expect("open read session");
    let caught_up = read_session.caught_up();

    let append_ticket = append_session
        .submit(sample_append_input())
        .await
        .expect("submit batch");
    let producer_ticket = producer
        .submit(AppendRecord::new("rec").unwrap())
        .await
        .expect("submit record");

    let unary_append = tokio::spawn({
        let stream = stream.clone();
        async move { stream.append(sample_append_input()).await }
    });
    let unary_read = tokio::spawn({
        let stream = stream.clone();
        async move { stream.read(ReadInput::new()).await }
    });
    let read_next = tokio::spawn(async move { read_session.next().await });

    // Wait deterministically until all 4 HTTP requests (append session, read session, unary
    // append, unary read) have reached the server.
    if arrived.load(Ordering::SeqCst) < 4 {
        tokio::time::timeout(Duration::from_secs(2), all_arrived.notified())
            .await
            .expect("all 4 in-flight requests must reach mock server");
    }

    // Close is synchronous, does not wait for the server, and is idempotent.
    s2.close();
    s2.close();

    // All in-flight calls and sessions fail immediately with AbortedError (well before 5s timeout).
    let append_err = tokio::time::timeout(Duration::from_secs(1), unary_append)
        .await
        .expect("unary append must abort promptly")
        .unwrap()
        .expect_err("unary append must fail");
    assert!(
        matches!(append_err, AppendError::Aborted(_)),
        "{append_err:?}"
    );
    assert!(!append_err.has_no_side_effects());
    assert!(!append_err.is_retryable());

    let read_err = tokio::time::timeout(Duration::from_secs(1), unary_read)
        .await
        .expect("unary read must abort promptly")
        .unwrap()
        .expect_err("unary read must fail");
    assert!(matches!(read_err, ReadError::Aborted(_)), "{read_err:?}");
    assert!(read_err.has_no_side_effects());

    let ticket_err = tokio::time::timeout(Duration::from_secs(1), append_ticket)
        .await
        .expect("append session ticket must abort promptly")
        .expect_err("append session ticket must fail");
    assert!(
        matches!(ticket_err, AppendSessionError::Aborted(_)),
        "sent append batch must resolve to AbortedError, got {ticket_err:?}"
    );
    let append_close_err = tokio::time::timeout(Duration::from_secs(1), append_session.close())
        .await
        .expect("append session close must resolve promptly")
        .expect_err("append session close must report AbortedError");
    assert!(
        matches!(append_close_err, AppendSessionError::Aborted(_)),
        "append session close must report AbortedError, got {append_close_err:?}"
    );

    let prod_err = tokio::time::timeout(Duration::from_secs(1), producer_ticket)
        .await
        .expect("producer ticket must abort promptly")
        .expect_err("producer ticket must fail");
    assert!(
        matches!(
            prod_err,
            AppendSessionError::SessionClosed(ref e)
                if matches!(e.failure(), Some(AppendSessionError::Aborted(_)))
        ),
        "unsent producer record must resolve to SessionClosedError(Some(Aborted)), got {prod_err:?}"
    );
    let prod_close_err = tokio::time::timeout(Duration::from_secs(1), producer.close())
        .await
        .expect("producer close must resolve promptly")
        .expect_err("producer close must report AbortedError");
    assert!(
        matches!(prod_close_err, AppendSessionError::Aborted(_)),
        "producer close must report AbortedError, got {prod_close_err:?}"
    );

    let read_item = tokio::time::timeout(Duration::from_secs(1), read_next)
        .await
        .expect("read session must abort promptly")
        .unwrap()
        .expect("read session yields AbortedError");
    assert!(
        matches!(read_item, Err(ReadSessionError::Aborted(_))),
        "{read_item:?}"
    );
    let cu_err = tokio::time::timeout(Duration::from_secs(1), caught_up)
        .await
        .expect("caught_up must fail promptly")
        .expect_err("caught_up must fail");
    assert!(matches!(cu_err, ReadSessionError::Aborted(_)), "{cu_err:?}");

    // New calls on closed client or handles fail immediately with ClientClosedError.
    assert!(matches!(
        s2.list_basins(ListBasinsInput::new()).await,
        Err(RequestError::ClientClosed(_))
    ));
    assert!(matches!(
        stream.read(ReadInput::new()).await,
        Err(ReadError::ClientClosed(_))
    ));
    assert!(matches!(
        stream.append(sample_append_input()).await,
        Err(AppendError::ClientClosed(_))
    ));
    assert!(stream.append_session(AppendSessionConfig::new()).is_err());
    assert!(stream.producer(ProducerConfig::new()).is_err());
    assert!(
        stream
            .read_session(ReadInput::new(), ReadSessionConfig::default())
            .is_err()
    );
    assert!(
        stream
            .read_batch_session(ReadInput::new(), ReadSessionConfig::default())
            .is_err()
    );

    // Dropping S2 without calling close() keeps sessions alive.
    let ack_server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let mut body = req.into_body();
        if let Some(Ok(_)) = body.data().await {
            let ack = encode_s2s_regular_frame(&proto_append_ack(0, 1), false);
            let _ = send.send_data(ack, true);
        }
    })
    .await;
    let s2_drop = ack_server.client(no_retry_config());
    let live_session = s2_drop
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .append_session(AppendSessionConfig::new())
        .expect("open session");
    drop(s2_drop);
    let ack = live_session
        .submit(sample_append_input())
        .await
        .expect("submit after dropping S2")
        .await
        .expect("ack after dropping S2");
    assert_eq!(ack.end.seq_num, 1);

    // C12: closing client aborts a connection still being established (TLS handshake stall).
    let stall = StallingTlsServer::start().await;
    let stall_s2 = stall.client_with(|cfg| {
        cfg.with_connection_timeout(Duration::from_secs(10))
            .unwrap()
            .with_request_timeout(Duration::from_secs(10))
            .unwrap()
            .with_retry(no_retry_config())
    });
    let accepted = stall.wait_accepted();
    let dial_task = tokio::spawn({
        let s2 = stall_s2.clone();
        async move { s2.list_basins(ListBasinsInput::new()).await }
    });
    tokio::time::timeout(Duration::from_secs(2), accepted)
        .await
        .expect("TCP connection must be accepted before close()");
    stall_s2.close();
    let dial_err = tokio::time::timeout(Duration::from_secs(1), dial_task)
        .await
        .expect("in-progress connect must abort promptly on close()")
        .unwrap()
        .expect_err("must fail with Aborted");
    assert!(matches!(dial_err, RequestError::Aborted(_)), "{dial_err:?}");
}

// spec: r1 T7a
#[tokio::test]
async fn spec_t7a_connection_timeout_bounds_tls_handshake() {
    let stall = StallingTlsServer::start().await;
    let s2 = stall.client_with(|cfg| {
        cfg.with_connection_timeout(Duration::from_millis(150))
            .unwrap()
            .with_request_timeout(Duration::from_secs(5))
            .unwrap()
            .with_retry(no_retry_config())
    });

    let start = tokio::time::Instant::now();
    let err = s2
        .list_basins(ListBasinsInput::new())
        .await
        .expect_err("stalled TLS handshake must time out");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "TLS handshake must be bounded by connection_timeout (150ms), took {elapsed:?}"
    );
    assert!(
        matches!(err, RequestError::Connect(_)),
        "T7a: connection_timeout must fail with ConnectError, got {err:?}"
    );
    assert!(err.is_retryable());
    assert!(err.has_no_side_effects());
}

// spec: r1 T4, T5a, T6
#[tokio::test]
async fn spec_t4_s2_attempt_header_unary_and_sessions() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_3 = RetryConfig::new()
        .with_max_attempts(3)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // 1. Unary s2-attempt header: 1, 2, 3
    let unary_attempts = Arc::new(Mutex::new(Vec::<String>::new()));
    let unary_server = MockH2Server::start({
        let attempts = unary_attempts.clone();
        move |_conn_id, req, mut respond| {
            let attempts = attempts.clone();
            async move {
                let hdr = req
                    .headers()
                    .get("s2-attempt")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let idx = {
                    let mut guard = attempts.lock().unwrap();
                    guard.push(hdr);
                    guard.len()
                };
                if idx < 3 {
                    let resp = Response::builder().status(503).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"code":"unavailable","message":"busy"}"#),
                            true,
                        );
                    }
                } else {
                    let resp = Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"basins":[],"has_more":false}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    unary_server
        .client(fast_retry_3)
        .list_basins(ListBasinsInput::new())
        .await
        .expect("unary succeeds on attempt 3");
    assert_eq!(
        *unary_attempts.lock().unwrap(),
        vec!["1", "2", "3"],
        "T4: unary s2-attempt header"
    );

    // 2. AppendSession s2-attempt header across progress, retries, handover, and immediate drain
    let append_attempts = Arc::new(Mutex::new(Vec::<String>::new()));
    let append_server = MockH2Server::start({
        let attempts = append_attempts.clone();
        move |_conn_id, req, mut respond| {
            let attempts = attempts.clone();
            async move {
                let hdr = req
                    .headers()
                    .get("s2-attempt")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let idx = {
                    let mut guard = attempts.lock().unwrap();
                    guard.push(hdr);
                    guard.len()
                };
                match idx {
                    1 => {
                        // Ack batch 1, then drop connection when batch 2 arrives.
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "s2s/proto")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(resp, false) else {
                            return;
                        };
                        let mut body = req.into_body();
                        let _ = body.data().await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
                            false,
                        );
                        let _ = body.data().await;
                        // Close cleanly while batch 2 is unacked -> ConnectionLost -> retry 0.
                        let _ = send.send_data(Bytes::new(), true);
                    }
                    2 => {
                        // Retry 0: fail immediately with 503 unavailable -> retry 1.
                        let resp = Response::builder().status(503).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(
                                Bytes::from_static(br#"{"code":"unavailable","message":"busy"}"#),
                                true,
                            );
                        }
                    }
                    3 => {
                        // Retry 1: ack batch 2 with reconnect-advised bit -> handover (attempt 1).
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "s2s/proto")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(resp, false) else {
                            return;
                        };
                        let mut body = req.into_body();
                        let _ = body.data().await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(1, 2), true),
                            true,
                        );
                    }
                    4 => {
                        // Handover request ends immediately with server_draining before any ack ->
                        // counts as retry 0 (T6) -> next request sends s2-attempt: 2.
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "s2s/proto")
                            .body(())
                            .unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(
                                encode_s2s_terminal_frame(
                                    503,
                                    br#"{"code":"server_draining","message":"draining"}"#,
                                ),
                                true,
                            );
                        }
                    }
                    _ => {
                        // Attempt 2: ack batch 3 and close cleanly when client finishes.
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "s2s/proto")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(resp, false) else {
                            return;
                        };
                        let mut body = req.into_body();
                        let _ = body.data().await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(2, 3), false),
                            false,
                        );
                        while let Some(Ok(_)) = body.data().await {}
                        let _ = send.send_data(Bytes::new(), true);
                    }
                }
            }
        }
    })
    .await;

    let append_stream = append_server
        .client(fast_retry_3.with_append_retry_policy(AppendRetryPolicy::All))
        .basin(basin_name.clone())
        .stream(stream_name.clone());
    let session = append_stream
        .append_session(AppendSessionConfig::new())
        .expect("open session");

    let ack1 = tokio::time::timeout(Duration::from_secs(3), async {
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "ack1 timed out; attempts={:?}",
            *append_attempts.lock().unwrap()
        )
    });
    assert_eq!(ack1.end.seq_num, 1);
    let ack2 = tokio::time::timeout(Duration::from_secs(3), async {
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "ack2 timed out; attempts={:?}",
            *append_attempts.lock().unwrap()
        )
    });
    assert_eq!(ack2.end.seq_num, 2);
    let ack3 = tokio::time::timeout(Duration::from_secs(3), async {
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "ack3 timed out; attempts={:?}",
            *append_attempts.lock().unwrap()
        )
    });
    assert_eq!(ack3.end.seq_num, 3);
    tokio::time::timeout(Duration::from_secs(3), session.close())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "close timed out; attempts={:?}",
                *append_attempts.lock().unwrap()
            )
        })
        .unwrap();

    assert_eq!(
        *append_attempts.lock().unwrap(),
        vec!["1", "2", "3", "1", "2"],
        "T4/T5a/T6: append session s2-attempt header sequence"
    );

    // 3. ReadSession s2-attempt header + T6 immediate server_draining exhaustion
    let read_attempts = Arc::new(Mutex::new(Vec::<String>::new()));
    let read_server = MockH2Server::start({
        let attempts = read_attempts.clone();
        move |_conn_id, req, mut respond| {
            let attempts = attempts.clone();
            async move {
                let hdr = req
                    .headers()
                    .get("s2-attempt")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let idx = {
                    let mut guard = attempts.lock().unwrap();
                    guard.push(hdr);
                    guard.len()
                };
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                if idx == 1 {
                    // Progress (batch 0), then server_draining -> handover (attempt 1, no budget
                    // used).
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(0, 1), false),
                        false,
                    );
                }
                let _ = send.send_data(
                    encode_s2s_terminal_frame(
                        503,
                        br#"{"code":"server_draining","message":"draining"}"#,
                    ),
                    true,
                );
            }
        }
    })
    .await;

    let mut read_session = read_server
        .client(fast_retry_3)
        .basin(basin_name)
        .stream(stream_name)
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .expect("open read session");
    let first = tokio::time::timeout(Duration::from_secs(3), read_session.next())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "read first timed out; attempts={:?}",
                *read_attempts.lock().unwrap()
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(first.seq_num, 0);
    let err = tokio::time::timeout(Duration::from_secs(3), read_session.next())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "read err timed out; attempts={:?}",
                *read_attempts.lock().unwrap()
            )
        })
        .expect("should terminate with server_draining")
        .expect_err("must exhaust budget on immediate server_draining");
    assert!(
        matches!(err, ReadSessionError::Server(ref se) if se.code.as_deref() == Some("server_draining")),
        "{err:?}"
    );
    assert_eq!(
        *read_attempts.lock().unwrap(),
        vec!["1", "1", "2", "3"],
        "T4/T6: read session handover then budgeted retries on immediate server_draining"
    );
}

// spec: r1 T6, T6c
#[tokio::test]
async fn spec_t6_connection_retirement_on_server_draining_and_hot_server() {
    let fast_retry_2 = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // Helper: serve first status+body, then 200 empty basins list, recording conn_id per request.
    async fn run_unary_retirement_case(
        retry: RetryConfig,
        first_status: u16,
        first_body: &'static [u8],
    ) -> Vec<usize> {
        let seen_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
        let count = Arc::new(AtomicUsize::new(0));
        let server = MockH2Server::start({
            let seen_conns = seen_conns.clone();
            let count = count.clone();
            move |conn_id, _req, mut respond| {
                let seen_conns = seen_conns.clone();
                let count = count.clone();
                async move {
                    seen_conns.lock().unwrap().push(conn_id);
                    let n = count.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        let resp = Response::builder().status(first_status).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(Bytes::from_static(first_body), true);
                        }
                    } else {
                        let resp = Response::builder().status(200).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(
                                Bytes::from_static(br#"{"basins":[],"has_more":false}"#),
                                true,
                            );
                        }
                    }
                }
            }
        })
        .await;

        server
            .client(retry)
            .list_basins(ListBasinsInput::new())
            .await
            .expect("retry must succeed");
        seen_conns.lock().unwrap().clone()
    }

    // 1. Unary server_draining retires connection -> retry opens a new connection.
    let conns = run_unary_retirement_case(
        fast_retry_2,
        503,
        br#"{"code":"server_draining","message":"draining"}"#,
    )
    .await;
    assert_eq!(conns.len(), 2);
    assert_ne!(
        conns[0], conns[1],
        "T6/T6c: unary server_draining must retire connection"
    );

    // 2. Unary hot_server retires connection -> retry opens a new connection.
    let conns = run_unary_retirement_case(
        fast_retry_2,
        502,
        br#"{"code":"hot_server","message":"hot"}"#,
    )
    .await;
    assert_eq!(conns.len(), 2);
    assert_ne!(
        conns[0], conns[1],
        "T6/T6c: unary hot_server must retire connection"
    );

    // 3. Ordinary retryable 503 unavailable keeps using the same pooled connection.
    let conns = run_unary_retirement_case(
        fast_retry_2,
        503,
        br#"{"code":"unavailable","message":"busy"}"#,
    )
    .await;
    assert_eq!(conns.len(), 2);
    assert_eq!(
        conns[0], conns[1],
        "ordinary 503 unavailable should reuse pooled connection"
    );

    // 4. Session hot_server retires connection AND consumes retry budget even after progress (T6c).
    let (basin_name, stream_name) = test_basin_and_stream();
    let session_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let session_server = MockH2Server::start({
        let session_conns = session_conns.clone();
        move |conn_id, _req, mut respond| {
            let session_conns = session_conns.clone();
            async move {
                let idx = {
                    let mut guard = session_conns.lock().unwrap();
                    guard.push(conn_id);
                    guard.len()
                };
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                if idx == 1 {
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(0, 1), false),
                        false,
                    );
                }
                let _ = send.send_data(
                    encode_s2s_terminal_frame(502, br#"{"code":"hot_server","message":"hot"}"#),
                    true,
                );
            }
        }
    })
    .await;

    let mut read_session = session_server
        .client(fast_retry_2)
        .basin(basin_name)
        .stream(stream_name)
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .expect("open read session");
    let _ = read_session.next().await.unwrap().unwrap();
    let err = read_session
        .next()
        .await
        .expect("must fail after hot_server consumes budget")
        .expect_err("hot_server must exhaust budget");
    assert!(
        matches!(err, ReadSessionError::Server(ref se) if se.code.as_deref() == Some("hot_server")),
        "{err:?}"
    );
    let conns = session_conns.lock().unwrap().clone();
    assert_eq!(conns.len(), 2, "T6c: hot_server consumes retry budget");
    assert_ne!(
        conns[0], conns[1],
        "T6c: session hot_server must retire connection"
    );
}

// spec: r1 E3, E4d, T1, T2c
#[tokio::test]
async fn spec_refused_stream_classified_as_definite_and_retried_under_no_side_effects() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. With max_attempts = 1: REFUSED_STREAM is ConnectionLostError with has_no_side_effects =
    //    true.
    let server = MockH2Server::start(|_conn_id, _req, mut respond| async move {
        respond.send_reset(h2::Reason::REFUSED_STREAM);
    })
    .await;
    let stream = server
        .client(no_retry_config().with_append_retry_policy(AppendRetryPolicy::NoSideEffects))
        .basin(basin_name.clone())
        .stream(stream_name.clone());
    let err = stream
        .append(sample_append_input())
        .await
        .expect_err("REFUSED_STREAM must fail with max_attempts = 1");
    assert!(
        matches!(err, AppendError::ConnectionLost(_)),
        "expected ConnectionLost, got {err:?}"
    );
    assert!(err.is_retryable());
    assert!(
        err.has_no_side_effects(),
        "REFUSED_STREAM must be definite (has_no_side_effects == true)"
    );

    // 2. With max_attempts = 2 + AppendRetryPolicy::NoSideEffects: REFUSED_STREAM is retried!
    let count = Arc::new(AtomicUsize::new(0));
    let server = MockH2Server::start({
        let count = count.clone();
        move |_conn_id, _req, mut respond| {
            let count = count.clone();
            async move {
                let n = count.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                } else {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(proto_append_ack(0, 1)), true);
                    }
                }
            }
        }
    })
    .await;
    let retry = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO)
        .with_append_retry_policy(AppendRetryPolicy::NoSideEffects);
    let ack = server
        .client(retry)
        .basin(basin_name)
        .stream(stream_name)
        .append(sample_append_input())
        .await
        .expect("NoSideEffects must retry definite REFUSED_STREAM");
    assert_eq!(ack.end.seq_num, 1);
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

// spec: r1 C5, C7, C10, C11, D1, A1
#[tokio::test]
async fn spec_c5_c7_c10_c11_d1_a1_transport_user_agent_inputs_concurrency_and_binary_records() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}

    assert_send_sync::<S2>();
    assert_send_sync::<S2Basin>();
    assert_send_sync::<S2Stream>();
    assert_send_sync::<AppendSession>();
    assert_send_sync::<Producer>();
    assert_send_sync::<ReadSessionState>();
    assert_send::<ReadSession>();
    assert_send::<ReadBatchSession>();

    let (basin_name, stream_name) = test_basin_and_stream();
    let seen_user_agents = Arc::new(Mutex::new(Vec::<String>::new()));
    let stored = Arc::new(Mutex::new(Vec::<api::stream::proto::AppendRecord>::new()));

    let server = MockH2Server::start({
        let seen_user_agents = seen_user_agents.clone();
        let stored = stored.clone();
        move |_conn_id, req, mut respond| {
            let seen_user_agents = seen_user_agents.clone();
            let stored = stored.clone();
            async move {
                if let Some(ua) = req
                    .headers()
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                {
                    seen_user_agents.lock().unwrap().push(ua.to_owned());
                }
                let method = req.method().clone();
                let path = req.uri().path().to_owned();
                let mut body = req.into_body();
                let mut req_bytes = BytesMut::new();
                while let Some(Ok(chunk)) = body.data().await {
                    req_bytes.extend_from_slice(&chunk);
                    let _ = body.flow_control().release_capacity(chunk.len());
                }

                if method == http::Method::POST && path.ends_with("/records") {
                    let input =
                        api::stream::proto::AppendInput::decode(req_bytes.freeze()).unwrap();
                    let count = input.records.len() as u64;
                    *stored.lock().unwrap() = input.records;
                    let ack = proto_append_ack(0, count);
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(ack), true);
                    }
                } else if method == http::Method::GET && path.ends_with("/records") {
                    let records: Vec<ProtoSequencedRecord> = stored
                        .lock()
                        .unwrap()
                        .iter()
                        .enumerate()
                        .map(|(i, r)| ProtoSequencedRecord {
                            seq_num: i as u64,
                            timestamp: r.timestamp.unwrap_or(500),
                            headers: r.headers.clone(),
                            body: r.body.clone(),
                        })
                        .collect();
                    let batch = ProtoReadBatch {
                        tail: Some(ProtoStreamPosition {
                            seq_num: records.len() as u64,
                            timestamp: 500,
                        }),
                        records,
                    }
                    .encode_to_vec();
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(batch), true);
                    }
                } else {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":1,"timestamp":500}}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let s2 = server.client(no_retry_config());
    let stream = s2.basin(basin_name).stream(stream_name);

    // D1 + A1 + C10: arbitrary non-UTF-8 binary body and ordered duplicate binary headers.
    let mut raw_body = vec![0x00, 0xff, 0xfe, 0x80, 0x42];
    let headers = vec![
        Header::new(
            Bytes::from_static(&[0x01, 0xff]),
            Bytes::from_static(b"first"),
        ),
        Header::new(
            Bytes::from_static(&[0x01, 0xff]),
            Bytes::from_static(&[0x00, 0xab]),
        ),
    ];
    let rec = AppendRecord::new(raw_body.clone())
        .unwrap()
        .with_headers(headers.clone())
        .unwrap()
        .with_timestamp(777);
    // Mutating caller's original Vec after constructing the record has no effect (C10).
    raw_body.fill(0x99);
    let batch = AppendRecordBatch::try_from_iter([rec]).unwrap();
    let ack = stream.append(AppendInput::new(batch)).await.unwrap();
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);
    assert_eq!(ack.tail.seq_num, 1);

    let read_batch = stream
        .read(ReadInput::new().with_start(ReadFrom::SeqNum(0)))
        .await
        .unwrap();
    assert_eq!(read_batch.records.len(), 1);
    let got = &read_batch.records[0];
    assert_eq!(got.body.as_ref(), &[0x00, 0xff, 0xfe, 0x80, 0x42]);
    assert_eq!(got.headers.len(), 2);
    assert_eq!(got.headers[0].name.as_ref(), &[0x01, 0xff]);
    assert_eq!(got.headers[0].value.as_ref(), b"first");
    assert_eq!(got.headers[1].name.as_ref(), &[0x01, 0xff]);
    assert_eq!(got.headers[1].value.as_ref(), &[0x00, 0xab]);
    assert_eq!(got.timestamp, 777);

    // C11: concurrent calls on cloned handles across tasks succeed cleanly.
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let s = stream.clone();
        tasks.push(tokio::spawn(async move { s.check_tail().await.unwrap() }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().seq_num, 1);
    }

    // C7: user-agent matches s2-sdk-rust/<version>.
    let expected_ua = concat!("s2-sdk-rust/", env!("CARGO_PKG_VERSION"));
    let uas = seen_user_agents.lock().unwrap();
    assert!(!uas.is_empty());
    assert!(uas.iter().all(|ua| ua == expected_ua), "{uas:?}");
}

// spec: r1 C13, C13a, C13b
#[tokio::test]
async fn spec_c13b_http2_keepalive_ping_timeout_maps_to_connection_lost_and_spills_over() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. C13 + C13a: verify real pooled connection reuse & spillover when cap is reached.
    let release_first = Arc::new(tokio::sync::Notify::new());
    let first_arrived = Arc::new(tokio::sync::Notify::new());
    let req_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let pool_server = MockH2Server::start({
        let release_first = release_first.clone();
        let first_arrived = first_arrived.clone();
        let req_conns = req_conns.clone();
        move |conn_id, _req, mut respond| {
            let release_first = release_first.clone();
            let first_arrived = first_arrived.clone();
            let req_conns = req_conns.clone();
            async move {
                let idx = {
                    let mut guard = req_conns.lock().unwrap();
                    guard.push(conn_id);
                    guard.len()
                };
                if idx == 1 {
                    first_arrived.notify_one();
                    release_first.notified().await;
                }
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(())
                    .unwrap();
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(
                        Bytes::from_static(br#"{"tail":{"seq_num":0,"timestamp":0}}"#),
                        true,
                    );
                }
            }
        }
    })
    .await;

    let ep = pool_server.endpoint_url();
    let endpoints = S2Endpoints::new(
        AccountEndpoint::new(&ep).unwrap(),
        BasinEndpoint::new(&ep).unwrap(),
    )
    .unwrap();
    let s2 = S2::new(
        S2Config::new("test-token")
            .with_endpoints(endpoints)
            .with_http2(Http2Config::new().with_max_concurrent_requests(1).unwrap())
            .with_retry(no_retry_config()),
    )
    .unwrap();
    let stream = s2.basin(basin_name.clone()).stream(stream_name.clone());

    let req1 = tokio::spawn({
        let stream = stream.clone();
        async move { stream.check_tail().await }
    });
    first_arrived.notified().await;
    // While req1 holds the sole slot on connection 0, req2 must spill over to connection 1.
    let tail2 = stream.check_tail().await.unwrap();
    assert_eq!(tail2.seq_num, 0);
    release_first.notify_one();
    assert_eq!(req1.await.unwrap().unwrap().seq_num, 0);
    let conns = req_conns.lock().unwrap().clone();
    assert_eq!(conns.len(), 2);
    assert_ne!(
        conns[0], conns[1],
        "C13a: spillover must open a 2nd connection"
    );

    // Sequential request reuses an existing pooled connection instead of opening a 3rd.
    assert_eq!(stream.check_tail().await.unwrap().seq_num, 0);
    assert_eq!(pool_server.connection_count(), 2);

    // 2. C13b: Raw HTTP/2 peer completes handshake and accepts request HEADERS, then ignores
    //    keep-alive PING frames. After 20s (PING sent) + 10s (PING timeout), hyper closes the
    //    connection and the SDK MUST classify it as ConnectionLostError (not TimeoutError).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let saw_headers = Arc::new(tokio::sync::Notify::new());
    let saw_ping = Arc::new(tokio::sync::Notify::new());
    let saw_ping_count = Arc::new(AtomicUsize::new(0));
    let raw_server = tokio::spawn({
        let saw_headers = saw_headers.clone();
        let saw_ping = saw_ping.clone();
        let saw_ping_count = saw_ping_count.clone();
        async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // Read client HTTP/2 connection preface (24 bytes).
            let mut preface = [0u8; 24];
            if sock.read_exact(&mut preface).await.is_err() {
                return;
            }
            // Send empty server SETTINGS frame (9 bytes: len=0, type=0x04, flags=0, stream=0).
            let _ = sock
                .write_all(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await;
            let _ = sock.flush().await;

            // Read incoming frames: ACK client SETTINGS, signal HEADERS, ignore PING!
            let mut hdr = [0u8; 9];
            while sock.read_exact(&mut hdr).await.is_ok() {
                let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
                let frame_type = hdr[3];
                let flags = hdr[4];
                let mut payload = vec![0u8; len];
                if len > 0 && sock.read_exact(&mut payload).await.is_err() {
                    break;
                }
                if frame_type == 0x04 && (flags & 0x01) == 0 {
                    // Send SETTINGS ACK (len=0, type=0x04, flags=0x01, stream=0).
                    let _ = sock
                        .write_all(&[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00])
                        .await;
                    let _ = sock.flush().await;
                } else if frame_type == 0x01 {
                    saw_headers.notify_waiters();
                } else if frame_type == 0x06 && (flags & 0x01) == 0 {
                    // Observed client HTTP/2 keep-alive PING; intentionally do NOT ACK!
                    saw_ping_count.fetch_add(1, Ordering::SeqCst);
                    saw_ping.notify_waiters();
                }
            }
        }
    });

    let raw_ep = format!("http://{addr}");
    let raw_endpoints = S2Endpoints::new(
        AccountEndpoint::new(&raw_ep).unwrap(),
        BasinEndpoint::new(&raw_ep).unwrap(),
    )
    .unwrap();
    let ping_client = S2::new(
        S2Config::new("test-token")
            .with_endpoints(raw_endpoints)
            .with_request_timeout(Duration::from_secs(120))
            .unwrap()
            .with_retry(no_retry_config()),
    )
    .unwrap();
    let ping_stream = ping_client.basin(basin_name).stream(stream_name);

    let call = tokio::spawn(async move { ping_stream.check_tail().await });
    // Wait until the real HTTP/2 handshake + request HEADERS actually arrive on the socket!
    tokio::time::timeout(Duration::from_secs(3), saw_headers.notified())
        .await
        .expect("client must complete HTTP/2 handshake and send HEADERS");

    // Advance Tokio's clock past hyper's 20s keep-alive PING interval (C13b), then resume so
    // real TCP I/O delivers the PING frame without auto-advance interference.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(21)).await;
    tokio::time::resume();

    if saw_ping_count.load(Ordering::SeqCst) == 0 {
        tokio::time::timeout(Duration::from_secs(3), saw_ping.notified())
            .await
            .expect("C13b: client must send HTTP/2 keep-alive PING within 20s");
    }
    assert!(
        saw_ping_count.load(Ordering::SeqCst) >= 1,
        "C13b: client must send HTTP/2 keep-alive PING within 20s"
    );

    // Advance Tokio's clock past the 10s keep-alive PING timeout (C13b).
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::resume();

    let err = tokio::time::timeout(Duration::from_secs(3), call)
        .await
        .expect("keep-alive PING timeout must fail active request promptly")
        .unwrap()
        .expect_err("keep-alive PING timeout must fail active request");
    assert!(
        matches!(err, ReadError::ConnectionLost(_)),
        "C13b: HTTP/2 keep-alive PING timeout must classify as ConnectionLostError, got {err:?}"
    );
    assert!(err.is_retryable());
    raw_server.abort();
}

// spec: r1 T2, T2a, T2b, T7, T7b, M1
#[tokio::test]
async fn spec_t2_t7_t7b_m1_retry_safety_request_tokens_and_timeouts() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_3 = RetryConfig::new()
        .with_max_attempts(3)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // 1. T2b + M1: create_basin and create_stream reuse identical s2-request-token across retries;
    //    T2a: check_tail and delete_stream retry indefinite 503.
    let basin_tokens = Arc::new(Mutex::new(Vec::<String>::new()));
    let stream_tokens = Arc::new(Mutex::new(Vec::<String>::new()));
    let delete_attempts = Arc::new(AtomicUsize::new(0));
    let tail_attempts = Arc::new(AtomicUsize::new(0));

    let server = MockH2Server::start({
        let basin_tokens = basin_tokens.clone();
        let stream_tokens = stream_tokens.clone();
        let delete_attempts = delete_attempts.clone();
        let tail_attempts = tail_attempts.clone();
        move |_conn_id, req, mut respond| {
            let basin_tokens = basin_tokens.clone();
            let stream_tokens = stream_tokens.clone();
            let delete_attempts = delete_attempts.clone();
            let tail_attempts = tail_attempts.clone();
            async move {
                let method = req.method().clone();
                let path = req.uri().path().to_owned();
                let req_token = req
                    .headers()
                    .get("s2-request-token")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let mut body = req.into_body();
                while let Some(Ok(chunk)) = body.data().await {
                    let _ = body.flow_control().release_capacity(chunk.len());
                }

                let (status, payload): (u16, &[u8]) = if method == http::Method::POST
                    && path == "/v1/basins"
                {
                    let mut guard = basin_tokens.lock().unwrap();
                    guard.push(req_token.unwrap_or_default());
                    if guard.len() == 1 {
                        (503, br#"{"code":"unavailable","message":"retry"}"#)
                    } else {
                        (
                            201,
                            br#"{"name":"test-basin","created_at":"2026-01-01T00:00:00Z"}"#,
                        )
                    }
                } else if method == http::Method::POST && path == "/v1/streams" {
                    let mut guard = stream_tokens.lock().unwrap();
                    guard.push(req_token.unwrap_or_default());
                    if guard.len() == 1 {
                        (503, br#"{"code":"unavailable","message":"retry"}"#)
                    } else {
                        (
                            201,
                            br#"{"name":"test-stream","created_at":"2026-01-01T00:00:00Z","deleted_at":null}"#,
                        )
                    }
                } else if method == http::Method::DELETE && path.starts_with("/v1/streams/") {
                    if delete_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        (503, br#"{"code":"unavailable","message":"retry"}"#)
                    } else {
                        (202, b"")
                    }
                } else if method == http::Method::GET && path.ends_with("/records/tail") {
                    if tail_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        (503, br#"{"code":"unavailable","message":"retry"}"#)
                    } else {
                        (200, br#"{"tail":{"seq_num":7,"timestamp":700}}"#)
                    }
                } else {
                    (404, br#"{"code":"not_found","message":"unexpected"}"#)
                };

                let resp = Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(())
                    .unwrap();
                if payload.is_empty() {
                    let _ = respond.send_response(resp, true);
                } else if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(Bytes::copy_from_slice(payload), true);
                }
            }
        }
    })
    .await;

    let s2 = server.client(fast_retry_3);
    let created_basin = s2
        .create_basin(CreateBasinInput::new(basin_name.clone()))
        .await
        .unwrap();
    assert_eq!(created_basin.name, basin_name);
    let bt = basin_tokens.lock().unwrap().clone();
    assert_eq!(bt.len(), 2);
    assert!(!bt[0].is_empty());
    assert_eq!(
        bt[0], bt[1],
        "T2b: create_basin must reuse s2-request-token"
    );

    let basin = s2.basin(basin_name.clone());
    let created_stream = basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await
        .unwrap();
    assert_eq!(created_stream.name, stream_name);
    let st = stream_tokens.lock().unwrap().clone();
    assert_eq!(st.len(), 2);
    assert!(!st[0].is_empty());
    assert_eq!(
        st[0], st[1],
        "T2b: create_stream must reuse s2-request-token"
    );

    assert_eq!(
        basin
            .stream(stream_name.clone())
            .check_tail()
            .await
            .unwrap()
            .seq_num,
        7
    );
    assert_eq!(tail_attempts.load(Ordering::SeqCst), 2);
    basin.delete_stream(stream_name.clone()).await.unwrap();
    assert_eq!(delete_attempts.load(Ordering::SeqCst), 2);

    // 2. T7 + T7b: per-attempt request_timeout (unary succeeds on retry when attempt 1 times out,
    //    unary read with `wait` uses `request_timeout + wait`, session times out if headers stall).
    let attempt_counter = Arc::new(AtomicUsize::new(0));
    let timeout_server = MockH2Server::start({
        let attempt_counter = attempt_counter.clone();
        move |_conn_id, req, mut respond| {
            let attempt_counter = attempt_counter.clone();
            async move {
                let path = req.uri().path().to_owned();
                let is_s2s = req
                    .headers()
                    .get("content-type")
                    .is_some_and(|v| v == "s2s/proto");
                let params = query_pairs(req.uri());
                if is_s2s {
                    // Stall response headers so ReadSession hits T7b request_timeout.
                    let _keep = respond;
                    std::future::pending::<()>().await;
                } else if path.ends_with("/records/tail") {
                    if attempt_counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        // Stall attempt 1 past request_timeout (150ms).
                        let _keep = respond;
                        std::future::pending::<()>().await;
                    } else {
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(())
                            .unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(
                                Bytes::from_static(br#"{"tail":{"seq_num":9,"timestamp":900}}"#),
                                true,
                            );
                        }
                    }
                } else if params.get("wait").map(String::as_str) == Some("1") {
                    // Respond at 350ms: exceeds request_timeout (150ms) alone, but well within
                    // request_timeout + wait (1150ms)!
                    tokio::time::sleep(Duration::from_millis(350)).await;
                    let batch = proto_read_batch_records(&[0], Some(1));
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(batch), true);
                    }
                }
            }
        }
    })
    .await;

    let ep = timeout_server.endpoint_url();
    let endpoints = S2Endpoints::new(
        AccountEndpoint::new(&ep).unwrap(),
        BasinEndpoint::new(&ep).unwrap(),
    )
    .unwrap();
    let s2_t = S2::new(
        S2Config::new("test-token")
            .with_endpoints(endpoints.clone())
            .with_request_timeout(Duration::from_millis(150))
            .unwrap()
            .with_retry(fast_retry_3),
    )
    .unwrap();
    let stream_t = s2_t.basin(basin_name.clone()).stream(stream_name.clone());

    // Attempt 1 times out, attempt 2 succeeds -> proves timeout is per-attempt (T7).
    assert_eq!(stream_t.check_tail().await.unwrap().seq_num, 9);
    assert_eq!(attempt_counter.load(Ordering::SeqCst), 2);

    // Unary read with wait=1s succeeds when response arrives at 350ms > 150ms request_timeout.
    let batch = stream_t
        .read(
            ReadInput::new()
                .with_start(ReadFrom::SeqNum(0))
                .with_wait(Duration::from_secs(1))
                .unwrap(),
        )
        .await
        .expect("T7b: unary read timeout must be request_timeout + wait");
    assert_eq!(batch.records.len(), 1);

    // Session open headers stall past request_timeout -> fails with TimeoutError (T7b).
    let s2_no_retry = S2::new(
        S2Config::new("test-token")
            .with_endpoints(endpoints)
            .with_request_timeout(Duration::from_millis(150))
            .unwrap()
            .with_retry(no_retry_config()),
    )
    .unwrap();
    let mut sess = s2_no_retry
        .basin(basin_name)
        .stream(stream_name)
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .unwrap();
    let err = sess.next().await.unwrap().unwrap_err();
    assert!(matches!(err, ReadSessionError::Timeout(_)), "{err:?}");
    assert!(err.is_retryable());
}

// spec: r1 E4, E8, L1, L2, L3
#[tokio::test(flavor = "current_thread")]
async fn spec_e4_e8_l1_l2_l3_logging_levels_secret_redaction_and_unobserved_errors() {
    use std::sync::atomic::AtomicU64;

    use tracing::{
        Event, Id, Level, Metadata, Subscriber,
        field::{Field, Visit},
        span::{Attributes, Record},
    };

    #[derive(Clone, Default)]
    struct CaptureSubscriber {
        next_id: Arc<AtomicU64>,
        events: Arc<Mutex<Vec<(String, Level, String)>>>,
    }

    struct StringVisitor(String);
    impl Visit for StringVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={:?} ", field.name(), value);
        }
    }

    impl Subscriber for CaptureSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(self.next_id.fetch_add(1, Ordering::Relaxed) + 1)
        }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let meta = event.metadata();
            let mut visitor = StringVisitor(String::new());
            event.record(&mut visitor);
            self.events
                .lock()
                .unwrap()
                .push((meta.target().to_owned(), *meta.level(), visitor.0));
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    let capture = CaptureSubscriber::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    const CLIENT_TOKEN: &str = "tok_SUPER_SECRET_CLIENT_TOKEN_98765";
    const RAW_ENC_KEY: &[u8; 32] = b"KEY_SUPER_SECRET_ENC_KEY_67890!!";
    const RAW_ENC_KEY_STR: &str = "KEY_SUPER_SECRET_ENC_KEY_67890!!";
    const ISSUED_TOKEN: &str = "tok_SUPER_SECRET_ISSUED_TOKEN_43210";
    const SECRET_BODY: &str = "BODY_SUPER_SECRET_RECORD_PAYLOAD_55555";

    let enc_key = EncryptionKey::new(RAW_ENC_KEY).unwrap();
    let enc_key_b64 = base64ct::Base64::encode_string(RAW_ENC_KEY);

    let (basin_name, stream_name) = test_basin_and_stream();
    let server = MockH2Server::start(|_conn_id, req, mut respond| async move {
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let is_s2s = req
            .headers()
            .get("content-type")
            .is_some_and(|v| v == "s2s/proto");
        let mut body = req.into_body();
        if !is_s2s {
            while let Some(Ok(chunk)) = body.data().await {
                let _ = body.flow_control().release_capacity(chunk.len());
            }
        }
        if method == http::Method::POST && path == "/v1/access-tokens" {
            let resp = Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(())
                .unwrap();
            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send.send_data(
                    Bytes::from(format!(r#"{{"access_token":"{ISSUED_TOKEN}"}}"#)),
                    true,
                );
            }
            return;
        }
        // Fail everything else with 503 so retries + terminal errors exercise SDK debug logging.
        let resp = Response::builder()
            .status(503)
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        if let Ok(mut send) = respond.send_response(resp, false) {
            let _ = send.send_data(
                Bytes::from_static(br#"{"code":"unavailable","message":"transient"}"#),
                true,
            );
        }
    })
    .await;

    let ep = server.endpoint_url();
    let endpoints = S2Endpoints::new(
        AccountEndpoint::new(&ep).unwrap(),
        BasinEndpoint::new(&ep).unwrap(),
    )
    .unwrap();
    let config = S2Config::new(CLIENT_TOKEN)
        .with_endpoints(endpoints)
        .with_retry(
            RetryConfig::new()
                .with_max_attempts(2)
                .unwrap()
                .with_min_base_delay(Duration::ZERO)
                .with_max_base_delay(Duration::ZERO),
        );
    let s2 = S2::new(config.clone()).unwrap();
    let basin = s2.basin(basin_name);
    let stream = basin
        .stream(stream_name)
        .with_encryption_key(enc_key.clone());

    // L3: formatted/debug representations of settings, client, handles, and key redact secrets.
    let formatted_objects = vec![
        format!("{config:?}"),
        format!("{s2:?}"),
        format!("{basin:?}"),
        format!("{stream:?}"),
        format!("{enc_key:?}"),
    ];
    for text in &formatted_objects {
        assert!(
            !text.contains(CLIENT_TOKEN),
            "L3: token leaked in Debug: {text}"
        );
        assert!(
            !text.contains(RAW_ENC_KEY_STR),
            "L3: raw key leaked in Debug: {text}"
        );
        assert!(
            !text.contains(&enc_key_b64),
            "L3: base64 key leaked in Debug: {text}"
        );
    }

    // M5 + L3: issue_access_token returns secret without logging it.
    let issued = s2
        .issue_access_token(IssueAccessTokenInput::new(
            "l3-tok".parse().unwrap(),
            AccessTokenScopeInput::from_ops([Operation::ListBasins]),
        ))
        .await
        .unwrap();
    assert_eq!(issued, ISSUED_TOKEN);

    // Unary append failure + E4 predicates + L3 error message check.
    let secret_record = AppendRecord::new(SECRET_BODY).unwrap();
    let append_err = stream
        .append(AppendInput::new(
            AppendRecordBatch::try_from_iter([secret_record.clone()]).unwrap(),
        ))
        .await
        .unwrap_err();
    assert!(append_err.is_retryable());
    assert!(!append_err.has_no_side_effects());
    let s2_err: S2Error = append_err.clone().into();
    assert!(s2_err.is_retryable());
    assert!(!s2_err.has_no_side_effects());

    // E8: AppendSession ticket dropped unawaited, plus ReadSession caught_up dropped unawaited.
    let append_sess = stream.append_session(AppendSessionConfig::new()).unwrap();
    let unawaited_ticket = append_sess
        .submit(AppendInput::new(
            AppendRecordBatch::try_from_iter([secret_record]).unwrap(),
        ))
        .await
        .unwrap();
    drop(unawaited_ticket);
    let close_err = append_sess.close().await.unwrap_err();
    assert!(close_err.is_retryable());

    let mut read_sess = stream
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .unwrap();
    let unawaited_cu = read_sess.caught_up();
    drop(unawaited_cu);
    let read_err = read_sess.next().await.unwrap().unwrap_err();
    assert!(read_err.is_retryable());
    assert!(read_err.has_no_side_effects());

    // L3: check error messages contain no secrets.
    let error_texts = [
        format!("{append_err}"),
        format!("{append_err:?}"),
        format!("{close_err}"),
        format!("{close_err:?}"),
        format!("{read_err}"),
        format!("{read_err:?}"),
    ];
    for text in &error_texts {
        for secret in [
            CLIENT_TOKEN,
            RAW_ENC_KEY_STR,
            &enc_key_b64,
            ISSUED_TOKEN,
            SECRET_BODY,
        ] {
            assert!(
                !text.contains(secret),
                "L3: secret `{secret}` leaked in error: {text}"
            );
        }
    }

    // L1 + L2 + L3: All s2_sdk tracing events are DEBUG or TRACE (never INFO/WARN/ERROR),
    // and no event contains any secret!
    let events = capture.events.lock().unwrap();
    let sdk_events: Vec<_> = events
        .iter()
        .filter(|(target, _, _)| target.starts_with("s2_sdk"))
        .collect();
    assert!(
        !sdk_events.is_empty(),
        "expected SDK debug events during retries"
    );
    for (target, level, msg) in &sdk_events {
        assert!(
            *level == Level::DEBUG || *level == Level::TRACE,
            "L1/L2: SDK emitted log above debug level: {level} {target}: {msg}"
        );
        for secret in [
            CLIENT_TOKEN,
            RAW_ENC_KEY_STR,
            &enc_key_b64,
            ISSUED_TOKEN,
            SECRET_BODY,
        ] {
            assert!(
                !msg.contains(secret),
                "L3: secret `{secret}` leaked in log ({target}): {msg}"
            );
        }
    }
}

// spec: r1 T3
#[tokio::test]
async fn spec_t3_retry_backoff_delivers_bounded_exponential_delay() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let attempt_times = Arc::new(Mutex::new(Vec::<std::time::Instant>::new()));
    let server = MockH2Server::start({
        let attempt_times = attempt_times.clone();
        move |_conn_id, _req, mut respond| {
            let attempt_times = attempt_times.clone();
            async move {
                let n = {
                    let mut times = attempt_times.lock().unwrap();
                    times.push(std::time::Instant::now());
                    times.len()
                };
                if n < 3 {
                    let resp = Response::builder()
                        .status(503)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"code":"unavailable","message":"busy"}"#),
                            true,
                        );
                    }
                } else {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":0,"timestamp":0}}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let retry = RetryConfig::new()
        .with_max_attempts(3)
        .unwrap()
        .with_min_base_delay(Duration::from_millis(40))
        .with_max_base_delay(Duration::from_millis(200));
    server
        .client(retry)
        .basin(basin_name)
        .stream(stream_name)
        .check_tail()
        .await
        .unwrap();

    let times = attempt_times.lock().unwrap().clone();
    assert_eq!(times.len(), 3);
    let d1 = times[1].duration_since(times[0]);
    let d2 = times[2].duration_since(times[1]);
    // Full-base + [0, base] jitter: delay 1 in [40ms, 80ms], delay 2 in [80ms, 160ms] (with CI
    // scheduling slack on upper bound).
    assert!(d1 >= Duration::from_millis(35), "delay 1 too short: {d1:?}");
    assert!(d2 >= Duration::from_millis(70), "delay 2 too short: {d2:?}");
}

// spec: r1 A4c, A8c, A9, C12, E6
#[tokio::test]
async fn producer_client_close_during_cut_or_reserve_wait_reports_aborted() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let server = MockH2Server::start(|_conn_id, req, respond| async move {
        let Some(s2s) = S2sResponder::open(respond) else {
            return;
        };
        let _keep = (req, s2s);
        std::future::pending::<()>().await;
    })
    .await;

    // 1. Concurrent client.close() + producer.close() with linger = 0 (exercises the race where the
    //    idle owned session closes cleanly on client close right as ProducerTask cuts a batch).
    for _ in 0..8 {
        let s2 = server.client(no_retry_config());
        let stream = s2.basin(basin_name.clone()).stream(stream_name.clone());
        let producer = stream
            .producer(ProducerConfig::new().with_linger(Duration::ZERO))
            .expect("open producer");
        let ticket = producer
            .submit(AppendRecord::new("r").unwrap())
            .await
            .expect("submit record");
        s2.close();

        let close_err = tokio::time::timeout(Duration::from_secs(1), producer.close())
            .await
            .expect("producer close must resolve promptly")
            .expect_err("aborted producer with unacked record must fail close");
        assert!(
            matches!(close_err, AppendSessionError::Aborted(_)),
            "producer.close() must report AbortedError (never SessionClosedError), got {close_err:?}"
        );

        let ticket_err = tokio::time::timeout(Duration::from_secs(1), ticket)
            .await
            .expect("ticket must resolve promptly")
            .expect_err("ticket must fail");
        assert!(
            matches!(ticket_err, AppendSessionError::Aborted(_))
                || matches!(
                    ticket_err,
                    AppendSessionError::SessionClosed(ref e)
                        if matches!(e.failure(), Some(AppendSessionError::Aborted(_)))
                ),
            "ticket must report Aborted or SessionClosed(Some(Aborted)), got {ticket_err:?}"
        );
    }

    // 2. Producer::reserve() blocked on capacity while owned session is idle (only a partial batch
    //    is buffered) and client.close() fires -> reserve() MUST return
    //    SessionClosed(Some(Aborted)), never SessionClosed(None)!
    let s2 = server.client(no_retry_config());
    let stream = s2.basin(basin_name).stream(stream_name);
    let max_unacked = 1024 * 1024u32;
    let producer = stream
        .producer(
            ProducerConfig::new()
                .with_max_unacked_bytes(max_unacked)
                .unwrap()
                .with_linger(Duration::from_secs(60)),
        )
        .expect("open producer");

    // Fill almost all capacity with a single partial batch (not full, so owned session stays idle)
    // and reserve the remaining slack so the next reserve() blocks without flushing.
    let fill = producer
        .submit(AppendRecord::new(vec![b'a'; 500 * 1024]).unwrap())
        .await
        .expect("submit partial record");
    let hold_permit = producer
        .reserve(500 * 1024)
        .await
        .expect("reserve remaining capacity");

    let mut blocked_reserve = Box::pin(producer.reserve(100 * 1024));
    assert!(futures_util::poll!(blocked_reserve.as_mut()).is_pending());

    s2.close();

    let reserve_err = tokio::time::timeout(Duration::from_secs(1), blocked_reserve)
        .await
        .expect("blocked reserve must wake promptly")
        .expect_err("blocked reserve must fail on client close");
    assert!(
        matches!(
            reserve_err,
            AppendSessionError::SessionClosed(ref e)
                if matches!(e.failure(), Some(AppendSessionError::Aborted(_)))
        ),
        "reserve() woken by client close with partial batch must report SessionClosed(Some(Aborted)), got {reserve_err:?}"
    );

    drop(hold_permit);
    let fill_err = tokio::time::timeout(Duration::from_secs(1), fill)
        .await
        .expect("fill ticket must resolve")
        .expect_err("fill ticket must fail");
    assert!(
        matches!(fill_err, AppendSessionError::Aborted(_))
            || matches!(
                fill_err,
                AppendSessionError::SessionClosed(ref e)
                    if matches!(e.failure(), Some(AppendSessionError::Aborted(_)))
            ),
        "{fill_err:?}"
    );
    assert!(matches!(
        producer.close().await,
        Err(AppendSessionError::Aborted(_))
    ));
}
