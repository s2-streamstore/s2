use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::Response;
use prost::Message as _;
use s2_api::v1::stream::proto::{
    ReadBatch as ProtoReadBatch, StreamPosition as ProtoStreamPosition,
};
use s2_sdk::{
    error::{ReadError, ReadSessionError},
    read_session::{ReadSession, ReadSessionConfig, ReadSessionRetryPolicy},
    types::{EncryptionKey, ReadFrom, ReadInput, RetryConfig},
};

use crate::support::*;

// spec: r1 R1, R2, R3, R4
#[tokio::test]
async fn spec_r2_r3_r4_unary_read_stop_options_empty_batch_416_and_check_tail() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let captured = Arc::new(Mutex::new(Vec::<(
        String,
        BTreeMap<String, String>,
        bool,
        bool,
    )>::new()));

    let server = MockH2Server::start({
        let captured = captured.clone();
        move |_conn_id, req, mut respond| {
            let captured = captured.clone();
            async move {
                let path = req.uri().path().to_owned();
                let params = query_pairs(req.uri());
                let has_enc = req.headers().contains_key("s2-encryption-key");
                let has_cfg = req.headers().contains_key("s2-stream-config");
                let idx = {
                    let mut guard = captured.lock().unwrap();
                    guard.push((path.clone(), params.clone(), has_enc, has_cfg));
                    guard.len()
                };
                if path.ends_with("/records/tail") {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":42,"timestamp":4200}}"#),
                            true,
                        );
                    }
                } else if idx == 2 {
                    // Empty batch when stop condition met before any record (R3).
                    let empty = proto_read_batch_records(&[], Some(42));
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "application/protobuf")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(empty), true);
                    }
                } else {
                    // wait=0 at tail returns 416 ReadUnwrittenError (R3).
                    let resp = Response::builder()
                        .status(416)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":42,"timestamp":4200}}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let key = EncryptionKey::new([0x11u8; 32]).unwrap();
    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .with_encryption_key(key);

    // R4 + C4: check_tail returns tail position and omits s2-encryption-key / s2-stream-config.
    let tail = stream.check_tail().await.unwrap();
    assert_eq!(tail.seq_num, 42);
    assert_eq!(tail.timestamp, 4200);

    // R2 + R3: unary read with omitted stop options sends none of count/bytes/until/wait and
    // returns empty server batch verbatim.
    let empty_batch = stream.read(ReadInput::new()).await.unwrap();
    assert!(empty_batch.records.is_empty());
    assert_eq!(empty_batch.tail.unwrap().seq_num, 42);

    // R2 + R3: explicit count/bytes/until/wait=0 serialized; 416 surfaces as ReadUnwrittenError.
    let err = stream
        .read(
            ReadInput::new()
                .with_count(10)
                .with_bytes(1024)
                .with_until(9999)
                .with_wait(Duration::ZERO)
                .unwrap(),
        )
        .await
        .unwrap_err();
    let ReadError::ReadUnwritten(unwritten) = err else {
        panic!("expected ReadError::ReadUnwritten, got {err:?}");
    };
    assert_eq!(unwritten.tail.seq_num, 42);

    let log = captured.lock().unwrap();
    // Call 1: check_tail -> no encryption key header
    assert!(
        !log[0].2,
        "R4/C4: check_tail must not send s2-encryption-key"
    );
    assert!(
        !log[0].3,
        "R4/C4: check_tail must not send s2-stream-config"
    );
    // Call 2: ReadInput::new() -> omitted stop params left unset
    assert!(
        log[1].1.is_empty(),
        "R2: omitted options must be unset: {:?}",
        log[1].1
    );
    assert!(log[1].2, "C4: read must send s2-encryption-key");
    // Call 3: explicit stop params
    assert_eq!(log[2].1.get("count").map(String::as_str), Some("10"));
    assert_eq!(log[2].1.get("bytes").map(String::as_str), Some("1024"));
    assert_eq!(log[2].1.get("until").map(String::as_str), Some("9999"));
    assert_eq!(log[2].1.get("wait").map(String::as_str), Some("0"));
}

// spec: r1 R5, R6, R6a, R6b, R6c, R7, R7a, R7b, R7c, R8, R8a, R8b, R8c, R8d
#[tokio::test]
async fn spec_r5_r6_r7_r8_read_session_records_batches_readahead_state_and_caught_up() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry = RetryConfig::new()
        .with_max_attempts(3)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // 1. R5 + R6 + R6c + R7 + R7a + R7b + R7c + R8 + R8a-R8d: Walk the exact spec Example table
    //    over loopback HTTP/2 with a concurrent observer task!
    let opened_notify = Arc::new(tokio::sync::Notify::new());
    let send_step4_hb = Arc::new(tokio::sync::Notify::new());
    let send_step5_rec5 = Arc::new(tokio::sync::Notify::new());
    let break_conn = Arc::new(tokio::sync::Notify::new());
    let allow_reconnect_hb = Arc::new(tokio::sync::Notify::new());
    let attempt_num = Arc::new(AtomicUsize::new(0));

    let server = MockH2Server::start({
        let opened_notify = opened_notify.clone();
        let send_step4_hb = send_step4_hb.clone();
        let send_step5_rec5 = send_step5_rec5.clone();
        let break_conn = break_conn.clone();
        let allow_reconnect_hb = allow_reconnect_hb.clone();
        let attempt_num = attempt_num.clone();
        move |_conn_id, _req, respond| {
            let opened_notify = opened_notify.clone();
            let send_step4_hb = send_step4_hb.clone();
            let send_step5_rec5 = send_step5_rec5.clone();
            let break_conn = break_conn.clone();
            let allow_reconnect_hb = allow_reconnect_hb.clone();
            let attempt_num = attempt_num.clone();
            async move {
                let idx = attempt_num.fetch_add(1, Ordering::SeqCst) + 1;
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                if idx == 1 {
                    opened_notify.notify_one();
                    // Records 0-4 with tail 5
                    s2s.send_regular(
                        &proto_read_batch_records(&[0, 1, 2, 3, 4], Some(5)),
                        false,
                        false,
                    );
                    send_step4_hb.notified().await;
                    // Distinct timestamp lets the test verify step 4's heartbeat was received.
                    s2s.send_regular(&proto_heartbeat_at(5, 2000), false, false);
                    send_step5_rec5.notified().await;
                    s2s.send_regular(&proto_read_batch_records(&[5], Some(6)), false, false);
                    break_conn.notified().await;
                    // Break active request with RST_STREAM
                    s2s.reset(h2::Reason::INTERNAL_ERROR);
                } else {
                    allow_reconnect_hb.notified().await;
                    s2s.send_regular(&proto_heartbeat(6), false, false);
                    std::future::pending::<()>().await;
                }
            }
        }
    })
    .await;

    let stream = server
        .client(fast_retry)
        .basin(basin_name.clone())
        .stream(stream_name.clone());

    let mut session = stream
        .read_session(
            ReadInput::new().with_start(ReadFrom::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .expect("R5: sync open succeeds");
    // R5: request initiates immediately WITHOUT polling session.next()!
    tokio::time::timeout(Duration::from_secs(2), opened_notify.notified())
        .await
        .expect("R5: read_session must initiate first request immediately on open");

    // R6c: concurrent ReadSessionState handle observed from another task while iterating.
    let state = session.state();
    assert_eq!(state.next_seq_num(), Some(0));
    assert!(!state.is_caught_up());
    let cu1 = state.caught_up();

    // Deliver record 0 -> next_seq_num=1, last_observed_tail=5, is_caught_up=false
    let r0 = session.next().await.unwrap().unwrap();
    assert_eq!(r0.seq_num, 0);
    assert_eq!(state.next_seq_num(), Some(1));
    assert_eq!(state.last_observed_tail().unwrap().seq_num, 5);
    assert!(!state.is_caught_up());

    // Deliver records 1..=4 -> next_seq_num=5, last_observed_tail=5, is_caught_up=true
    for expected in 1..=4 {
        let rec = session.next().await.unwrap().unwrap();
        assert_eq!(rec.seq_num, expected);
    }
    let concurrent_check = tokio::spawn({
        let state = state.clone();
        async move {
            (
                state.next_seq_num(),
                state.last_observed_tail(),
                state.is_caught_up(),
            )
        }
    })
    .await
    .unwrap();
    assert_eq!(concurrent_check.0, Some(5));
    assert_eq!(concurrent_check.1.unwrap().seq_num, 5);
    assert!(concurrent_check.2);
    assert_eq!(cu1.await.unwrap().seq_num, 5);
    let pinned_cu = state.caught_up();
    assert_eq!(pinned_cu.clone().await.unwrap().seq_num, 5);

    // Heartbeat tail=5 (ts=2000) -> observed and still caught up
    send_step4_hb.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state
                .last_observed_tail()
                .is_some_and(|t| t.seq_num == 5 && t.timestamp == 2000)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("driver should observe step 4 heartbeat");
    assert!(state.is_caught_up());

    // Record 5 fetched with tail=6 BEFORE delivery -> next_seq_num=5, last_observed_tail=6,
    // is_caught_up=false!
    send_step5_rec5.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.last_observed_tail().is_some_and(|t| t.seq_num == 6) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("driver should fetch record 5 and update last_observed_tail");
    assert_eq!(state.next_seq_num(), Some(5));
    assert!(!state.is_caught_up());
    // R8a: already-resolved caught_up future never changes!
    assert_eq!(pinned_cu.await.unwrap().seq_num, 5);

    // Record 5 delivered -> next_seq_num=6, is_caught_up=true
    let r5 = session.next().await.unwrap().unwrap();
    assert_eq!(r5.seq_num, 5);
    assert_eq!(state.next_seq_num(), Some(6));
    assert!(state.is_caught_up());

    // Active request breaks -> is_caught_up=false; caught_up() stays pending across retry (R8c)
    break_conn.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !state.is_caught_up() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("is_caught_up must clear on disconnect");
    assert_eq!(state.next_seq_num(), Some(6));
    assert_eq!(state.last_observed_tail().unwrap().seq_num, 6);
    let cu_across_retry = state.caught_up();

    // Reconnected; heartbeat with tail=6 -> is_caught_up=true and cu_across_retry resolves!
    allow_reconnect_hb.notify_one();
    let tail = tokio::time::timeout(Duration::from_secs(2), cu_across_retry)
        .await
        .expect("R8c: caught_up must resolve after reconnect")
        .unwrap();
    assert_eq!(tail.seq_num, 6);
    assert!(state.is_caught_up());

    // Dropping session rejects new caught_up with SessionClosedError (R8d)
    drop(session);
    assert!(!state.is_caught_up());
    assert!(matches!(
        state.caught_up().await,
        Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
    ));

    // 2. R6a: ReadBatchSession delivers whole non-empty batches and skips empty heartbeats.
    let batch_server = MockH2Server::start(|_conn_id, _req, respond| async move {
        let Some(mut s2s) = S2sResponder::open(respond) else {
            return;
        };
        s2s.send_regular(&proto_heartbeat(0), false, false);
        s2s.send_regular(&proto_read_batch_records(&[0, 1], Some(2)), false, false);
        s2s.send_regular(&proto_heartbeat(2), false, true);
    })
    .await;

    let mut batch_session = batch_server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_batch_session(
            ReadInput::new()
                .with_start(ReadFrom::SeqNum(0))
                .with_count(2),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let b = batch_session.next().await.unwrap().unwrap();
    assert_eq!(b.records.len(), 2);
    assert_eq!(batch_session.next_seq_num(), Some(2));
    assert!(batch_session.is_caught_up());
    assert!(batch_session.next().await.is_none());
    assert!(!batch_session.is_caught_up());

    // 3. R6b: At most 1 batch decoded ahead of the batch currently being delivered!
    let readahead_server = MockH2Server::start(|_conn_id, _req, respond| async move {
        let Some(mut s2s) = S2sResponder::open(respond) else {
            return;
        };
        for b_idx in 0u64..4 {
            let s0 = b_idx * 2;
            let s1 = s0 + 1;
            s2s.send_regular(
                &proto_read_batch_records(&[s0, s1], Some(s1 + 1)),
                false,
                false,
            );
        }
        std::future::pending::<()>().await;
    })
    .await;

    let mut ra_session = readahead_server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new().with_start(ReadFrom::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();

    async fn wait_and_assert_tail(session: &ReadSession, expected: u64, msg: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while session.last_observed_tail().map(|t| t.seq_num) != Some(expected) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{msg}: timed out waiting for tail {expected}, got {:?}",
                session.last_observed_tail()
            )
        });
        // Settle briefly to verify the driver does not decode past the 1-batch-ahead cap.
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            session.last_observed_tail().map(|t| t.seq_num),
            Some(expected),
            "{msg}"
        );
    }

    // Before consuming anything, at most B0 (tail=2) is decoded into the 1-slot buffer.
    wait_and_assert_tail(
        &ra_session,
        2,
        "R6b: before consumer pulls B0, driver must decode at most 1 batch (B0)",
    )
    .await;

    // Pull record 0 of B0 -> now B0 is being delivered, so driver may decode at most B1 (tail=4),
    // NEVER B2 (tail=6) or B3 (tail=8)!
    assert_eq!(ra_session.next().await.unwrap().unwrap().seq_num, 0);
    wait_and_assert_tail(
        &ra_session,
        4,
        "R6b: while delivering B0, driver must decode at most 1 batch ahead (B1)",
    )
    .await;

    // Finish B0 (record 1) and pull record 2 of B1 -> driver decodes B2 (tail=6), NOT B3 (tail=8)!
    assert_eq!(ra_session.next().await.unwrap().unwrap().seq_num, 1);
    assert_eq!(ra_session.next().await.unwrap().unwrap().seq_num, 2);
    wait_and_assert_tail(
        &ra_session,
        6,
        "R6b: while delivering B1, driver must decode at most 1 batch ahead (B2)",
    )
    .await;
}

// spec: r1 R9, R9a, R9b, R9c, R9d, R10
#[tokio::test]
async fn spec_r9_r10_read_session_closing_buffered_delivery_and_abort() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_2 = fast_retry_config(2);

    // 1. R9a + T9: Clean EOF WITHOUT any stop option is ConnectionLostError (retried!), whereas
    //    clean EOF WITH a stop option finishes cleanly.
    let eof_attempts = Arc::new(AtomicUsize::new(0));
    let eof_server = MockH2Server::start({
        let eof_attempts = eof_attempts.clone();
        move |_conn_id, _req, mut respond| {
            let eof_attempts = eof_attempts.clone();
            async move {
                eof_attempts.fetch_add(1, Ordering::SeqCst);
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
            }
        }
    })
    .await;

    let stream = eof_server
        .client(fast_retry_2)
        .basin(basin_name.clone())
        .stream(stream_name.clone());

    // Without stop option -> retried (2 attempts) then fails with ConnectionLostError.
    let mut no_stop = stream
        .read_session(ReadInput::new(), ReadSessionConfig::default())
        .unwrap();
    let err = no_stop.next().await.unwrap().unwrap_err();
    assert!(
        matches!(err, ReadSessionError::ConnectionLost(_)),
        "T9: clean EOF without stop option must fail with ConnectionLostError, got {err:?}"
    );
    assert!(err.has_no_side_effects());
    assert!(err.is_retryable());
    assert_eq!(eof_attempts.load(Ordering::SeqCst), 2);
    assert!(no_stop.next().await.is_none());

    // With stop option -> ends cleanly (None).
    let mut with_stop = stream
        .read_session(ReadInput::new().with_count(5), ReadSessionConfig::default())
        .unwrap();
    assert!(with_stop.next().await.is_none());

    // 2. R9c + R10: Terminal failure delivers all already-fetched records FIRST, then yields the
    //    unwrapped failure once, then None!
    let fail_server = MockH2Server::start(|_conn_id, _req, mut respond| async move {
        let resp = Response::builder()
            .status(200)
            .header("content-type", "s2s/proto")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let _ = send.send_data(
            encode_s2s_regular_frame(&proto_read_batch_records(&[0, 1], None), false),
            false,
        );
        let _ = send.send_data(
            encode_s2s_terminal_frame(404, br#"{"code":"stream_not_found","message":"deleted"}"#),
            true,
        );
    })
    .await;

    let mut fail_sess = fail_server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_session(
            ReadInput::new().with_start(ReadFrom::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();
    assert_eq!(fail_sess.next().await.unwrap().unwrap().seq_num, 0);
    assert_eq!(fail_sess.next().await.unwrap().unwrap().seq_num, 1);
    let err = fail_sess.next().await.unwrap().unwrap_err();
    assert!(
        matches!(err, ReadSessionError::Server(ref s) if s.code.as_deref() == Some("stream_not_found")),
        "R9c/R10: expected unwrapped ServerError after buffered records, got {err:?}"
    );
    assert!(err.has_no_side_effects());
    assert!(fail_sess.next().await.is_none());

    // 3. R9b: Dropping a pending next() future cancels only the wait without losing records;
    //    dropping the session rejects pending caught_up with SessionClosedError(None).
    let delayed_connected = Arc::new(tokio::sync::Notify::new());
    let delayed_release = Arc::new(tokio::sync::Notify::new());
    let delayed_server = MockH2Server::start({
        let delayed_connected = delayed_connected.clone();
        let delayed_release = delayed_release.clone();
        move |_conn_id, _req, mut respond| {
            let delayed_connected = delayed_connected.clone();
            let delayed_release = delayed_release.clone();
            async move {
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                delayed_connected.notify_one();
                delayed_release.notified().await;
                let _ = send.send_data(
                    encode_s2s_regular_frame(&proto_read_batch_records(&[0, 1], Some(2)), false),
                    false,
                );
                std::future::pending::<()>().await;
            }
        }
    })
    .await;

    let s2_abort = delayed_server.client(no_retry_config());
    let mut sess = s2_abort
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new().with_start(ReadFrom::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Wait for stream open, then cancel a pending next() future -> session stays alive and
    // delivers record 0 next!
    tokio::time::timeout(Duration::from_secs(2), delayed_connected.notified())
        .await
        .expect("read session must connect");
    {
        let mut pending_next = Box::pin(sess.next());
        assert!(futures_util::poll!(pending_next.as_mut()).is_pending());
        drop(pending_next);
    }
    delayed_release.notify_one();
    assert_eq!(sess.next().await.unwrap().unwrap().seq_num, 0);

    // 4. R9d: Record 1 is STILL buffered in current_batch when s2.close() aborts the session;
    //    record 1 MUST be dropped and iteration MUST yield AbortedError immediately, then None!
    s2_abort.close();
    let abort_err = sess.next().await.unwrap().unwrap_err();
    assert!(
        matches!(abort_err, ReadSessionError::Aborted(_)),
        "R9d: client close must drop buffered records and yield AbortedError, got {abort_err:?}"
    );
    assert!(sess.next().await.is_none());
}

// spec: r1 T7d
#[tokio::test]
async fn spec_t7d_read_session_heartbeat_timeout_and_backpressure_pause() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_2 = fast_retry_config(2);

    let attempts = Arc::new(AtomicUsize::new(0));
    let server = MockH2Server::start({
        let attempts = attempts.clone();
        move |_conn_id, _req, respond| {
            let attempts = attempts.clone();
            async move {
                let idx = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                if idx == 1 {
                    // Send two batches immediately so B0 is delivered and B1 (with tail=3) fills
                    // the 1-slot read-ahead channel; then go silent!
                    s2s.send_regular(&proto_read_batch_records(&[0, 1], None), false, false);
                    s2s.send_regular(&proto_read_batch_records(&[2], Some(3)), false, false);
                    std::future::pending::<()>().await;
                } else {
                    // On retry after heartbeat timeout, deliver record 3 and end cleanly.
                    s2s.send_regular(&proto_read_batch_records(&[3], Some(4)), false, false);
                    std::future::pending::<()>().await;
                }
            }
        }
    })
    .await;

    let mut session = server
        .client(fast_retry_2)
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new().with_start(ReadFrom::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Pull record 0 (record 1 stays in current_batch, record 2 fills the 1-slot channel).
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);
    // Deterministically wait until the driver has decoded B1 into the bounded 1-slot channel and
    // is parked on `tx.reserve()` before pausing the Tokio clock.
    tokio::time::timeout(Duration::from_secs(2), async {
        while session.last_observed_tail().map(|t| t.seq_num) != Some(3) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("driver must decode B1 into the bounded channel");
    tokio::task::yield_now().await;

    // Advance 60s (> 20s heartbeat timeout!) while caller has NOT consumed buffered records.
    // T7d: backpressure time MUST NOT count toward the 20s heartbeat timeout!
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60)).await;
    tokio::time::resume();
    tokio::task::yield_now().await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "T7d: heartbeat timer must not fire while caller has not consumed buffered records"
    );

    // Drain remaining buffered records 1 and 2 on the SAME attempt!
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 1);
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 2);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);

    // Now actively waiting for next server message -> after 20s silent, heartbeat timeout fires
    // and retries onto attempt 2, which delivers record 3!
    let mut next_rec = Box::pin(session.next());
    assert!(futures_util::poll!(next_rec.as_mut()).is_pending());
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(21)).await;
    tokio::time::resume();
    let rec3 = tokio::time::timeout(Duration::from_secs(3), next_rec)
        .await
        .expect("heartbeat timeout must trigger retry")
        .unwrap()
        .unwrap();
    assert_eq!(rec3.seq_num, 3);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

// spec: r1 R11, R11a, R11b, R11c, R11d, T5, T5b
#[tokio::test]
async fn spec_r11_t5_t5b_read_session_resume_clamp_wait_416_and_unbounded() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let fast_retry_2 = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);

    // 1. R11 + R11a + R11b + R11c + R11d: Start with TailOffset(2), clamp=true, count=5, wait=10s:
    //    - Attempt 1: sends heartbeat tail=10 -> resolves start to 10 & starts wait clock (t=0). At
    //      t=3s: sends 2nd heartbeat tail=10 (MUST NOT restart wait clock!). At t=5.1s: breaks
    //      connection!
    //    - Attempt 2: MUST send seq_num=10, NO tail_offset, NO clamp, count=5, wait=5 (ceil(4.9))!
    //      Sends records [10, 11] (restarts wait clock at t=5.1s, decrements count to 3!). At
    //      t=16.5s (11.4s elapsed since records): breaks connection!
    //    - Attempt 3: MUST send seq_num=12, count=3, wait=0 (R11c reached 0; SDK does not close
    //      locally)! Server replies 416 (tail=12) -> R11d closes cleanly (None), NOT an error!
    let seen_queries = Arc::new(Mutex::new(Vec::<BTreeMap<String, String>>::new()));
    let attempt_ctr = Arc::new(AtomicUsize::new(0));
    let send_hb2 = Arc::new(tokio::sync::Notify::new());
    let break_a1 = Arc::new(tokio::sync::Notify::new());
    let break_a2 = Arc::new(tokio::sync::Notify::new());
    let a1_hb1_sent = Arc::new(tokio::sync::Notify::new());

    let server = MockH2Server::start({
        let seen_queries = seen_queries.clone();
        let attempt_ctr = attempt_ctr.clone();
        let send_hb2 = send_hb2.clone();
        let break_a1 = break_a1.clone();
        let break_a2 = break_a2.clone();
        let a1_hb1_sent = a1_hb1_sent.clone();
        move |_conn_id, req, mut respond| {
            let seen_queries = seen_queries.clone();
            let attempt_ctr = attempt_ctr.clone();
            let send_hb2 = send_hb2.clone();
            let break_a1 = break_a1.clone();
            let break_a2 = break_a2.clone();
            let a1_hb1_sent = a1_hb1_sent.clone();
            async move {
                let idx = attempt_ctr.fetch_add(1, Ordering::SeqCst) + 1;
                seen_queries.lock().unwrap().push(query_pairs(req.uri()));
                if idx == 3 {
                    let resp = Response::builder()
                        .status(416)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":12,"timestamp":1200}}"#),
                            true,
                        );
                    }
                    return;
                }
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                if idx == 1 {
                    let _ = send
                        .send_data(encode_s2s_regular_frame(&proto_heartbeat(10), false), false);
                    a1_hb1_sent.notify_one();
                    send_hb2.notified().await;
                    let _ = send
                        .send_data(encode_s2s_regular_frame(&proto_heartbeat(10), false), false);
                    break_a1.notified().await;
                    send.send_reset(h2::Reason::INTERNAL_ERROR);
                } else {
                    let _ = send.send_data(
                        encode_s2s_regular_frame(
                            &proto_read_batch_records(&[10, 11], Some(12)),
                            false,
                        ),
                        false,
                    );
                    break_a2.notified().await;
                    send.send_reset(h2::Reason::INTERNAL_ERROR);
                }
            }
        }
    })
    .await;

    let mut session = server
        .client(fast_retry_2)
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_session(
            ReadInput::new()
                .with_start(ReadFrom::TailOffset(2))
                .with_clamp(true)
                .with_count(5)
                .with_wait(Duration::from_secs(10))
                .unwrap(),
            ReadSessionConfig::default(),
        )
        .unwrap();

    tokio::time::timeout(Duration::from_secs(3), a1_hb1_sent.notified())
        .await
        .expect("hb1 sent");
    // Wait until the client driver has actually decoded hb1 and resolved next_seq_num to 10!
    tokio::time::timeout(Duration::from_secs(3), async {
        while session.next_seq_num() != Some(10) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("client must resolve start from hb1");
    // Wait 3s, send 2nd heartbeat (must NOT reset clock), wait 2.1s more (5.1s total elapsed).
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::time::resume();
    send_hb2.notify_one();
    tokio::time::sleep(Duration::from_millis(30)).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(2_100)).await;
    tokio::time::resume();
    break_a1.notify_one();

    // Attempt 2 delivers records 10 and 11 (restarting wait clock!).
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 10);
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 11);

    // Wait 11.4s (> 10s wait) -> break attempt 2 -> Attempt 3 sends wait=0, gets 416 -> clean end!
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(11_400)).await;
    tokio::time::resume();
    break_a2.notify_one();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), session.next())
            .await
            .expect("R11d must terminate promptly")
            .is_none(),
        "R11d: 416 on resumed request with 0 remaining wait must end cleanly"
    );

    let qs = seen_queries.lock().unwrap().clone();
    assert_eq!(qs.len(), 3, "{qs:?}");
    // Attempt 1: original relative start + clamp=true + count=5 + wait=10
    assert_eq!(qs[0].get("tail_offset").map(String::as_str), Some("2"));
    assert_eq!(qs[0].get("clamp").map(String::as_str), Some("true"));
    assert_eq!(qs[0].get("count").map(String::as_str), Some("5"));
    assert_eq!(qs[0].get("wait").map(String::as_str), Some("10"));
    // Attempt 2: R11b resolved seq_num=10, clamp OMITTED, R11c wait=ceil(4.9)=5
    assert_eq!(qs[1].get("seq_num").map(String::as_str), Some("10"));
    assert!(!qs[1].contains_key("tail_offset"), "R11b: {:?}", qs[1]);
    assert!(
        !qs[1].contains_key("clamp"),
        "R11b: clamp must be cleared: {:?}",
        qs[1]
    );
    assert_eq!(qs[1].get("count").map(String::as_str), Some("5"));
    assert_eq!(qs[1].get("wait").map(String::as_str), Some("5"));
    // Attempt 3: R11a seq_num=12, R11c count=3, wait=0
    assert_eq!(qs[2].get("seq_num").map(String::as_str), Some("12"));
    assert_eq!(qs[2].get("count").map(String::as_str), Some("3"));
    assert_eq!(qs[2].get("wait").map(String::as_str), Some("0"));

    // 2. R11d negative check: 416 on resumed request while wait > 0 STILL fails with ReadUnwritten!
    let r11d_neg_attempts = Arc::new(AtomicUsize::new(0));
    let r11d_break = Arc::new(tokio::sync::Notify::new());
    let r11d_neg_server = MockH2Server::start({
        let r11d_neg_attempts = r11d_neg_attempts.clone();
        let r11d_break = r11d_break.clone();
        move |_conn_id, _req, mut respond| {
            let r11d_neg_attempts = r11d_neg_attempts.clone();
            let r11d_break = r11d_break.clone();
            async move {
                let idx = r11d_neg_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if idx == 1 {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "s2s/proto")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            encode_s2s_regular_frame(
                                &proto_read_batch_records(&[0], Some(1)),
                                false,
                            ),
                            false,
                        );
                        r11d_break.notified().await;
                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                    }
                } else {
                    let resp = Response::builder()
                        .status(416)
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

    let mut neg_sess = r11d_neg_server
        .client(fast_retry_2)
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_session(
            ReadInput::new()
                .with_start(ReadFrom::SeqNum(0))
                .with_wait(Duration::from_secs(30))
                .unwrap(),
            ReadSessionConfig::default(),
        )
        .unwrap();
    assert_eq!(neg_sess.next().await.unwrap().unwrap().seq_num, 0);
    r11d_break.notify_one();
    let err = neg_sess.next().await.unwrap().unwrap_err();
    assert!(
        matches!(err, ReadSessionError::ReadUnwritten(_)),
        "R11d: 416 while wait > 0 must still fail with ReadUnwrittenError, got {err:?}"
    );

    // 3. T5 + T5b: ReadSessionRetryPolicy::Unbounded retries past max_attempts (2) and succeeds!
    let unbounded_attempts = Arc::new(AtomicUsize::new(0));
    let unbounded_server = MockH2Server::start({
        let unbounded_attempts = unbounded_attempts.clone();
        move |_conn_id, _req, mut respond| {
            let unbounded_attempts = unbounded_attempts.clone();
            async move {
                let idx = unbounded_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if idx <= 5 {
                    let resp = Response::builder()
                        .status(503)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"code":"unavailable","message":"retry"}"#),
                            true,
                        );
                    }
                } else {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "s2s/proto")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            encode_s2s_regular_frame(
                                &proto_read_batch_records(&[0], Some(1)),
                                false,
                            ),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let mut unbounded_sess = unbounded_server
        .client(fast_retry_2)
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new()
                .with_start(ReadFrom::SeqNum(0))
                .with_count(1),
            ReadSessionConfig::new().with_retry_policy(ReadSessionRetryPolicy::Unbounded),
        )
        .unwrap();
    assert_eq!(unbounded_sess.next().await.unwrap().unwrap().seq_num, 0);
    assert!(unbounded_sess.next().await.is_none());
    assert_eq!(unbounded_attempts.load(Ordering::SeqCst), 6);
}

// spec: r1 T6a
#[tokio::test]
async fn spec_t6a_read_session_reconnect_advice_cooldown() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let seen_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let req_idx = Arc::new(AtomicUsize::new(0));
    let server = MockH2Server::start({
        let seen_conns = seen_conns.clone();
        let req_idx = req_idx.clone();
        move |conn_id, _req, mut respond| {
            let seen_conns = seen_conns.clone();
            let req_idx = req_idx.clone();
            async move {
                let n = req_idx.fetch_add(1, Ordering::SeqCst);
                seen_conns.lock().unwrap().push(conn_id);
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                if n == 0 {
                    // Record 0 with reconnect-advised bit -> client reconnects on a new connection.
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(0, 1), true),
                        false,
                    );
                    std::future::pending::<()>().await;
                } else {
                    // Request 2: Record 1 WITH reconnect-advised bit (ignored within 60 s
                    // cooldown!), then Record 2 on the SAME request before clean EOF.
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(1, 2), true),
                        false,
                    );
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(2, 3), false),
                        true,
                    );
                }
            }
        }
    })
    .await;

    let mut session = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new()
                .with_start(ReadFrom::SeqNum(0))
                .with_count(3),
            ReadSessionConfig::default(),
        )
        .unwrap();

    let mut seqs = Vec::new();
    while let Some(res) = session.next().await {
        seqs.push(res.unwrap().seq_num);
    }
    assert_eq!(seqs, vec![0, 1, 2]);
    let conns = seen_conns.lock().unwrap().clone();
    assert_eq!(
        conns.len(),
        2,
        "T6a: second reconnect advice within 60 s must be ignored"
    );
    assert_ne!(
        conns[0], conns[1],
        "T6a: first reconnect advice must move to a different connection"
    );
}

// spec: r1 R11c
// Regression: ReadSession R11c reduced-wait after fetching a new record must reconnect with
// refreshed remaining wait instead of prematurely terminating on the server's shorter timer.
#[tokio::test]
async fn regression_read_session_r11c_reduced_wait_refreshes_after_record() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // Baseline wait = 4s.
    // - Attempt 1 sends heartbeat (starts idle clock), waits for virtual time advance (1.2s), then
    //   resets connection.
    // - Attempt 2 arrives with reduced wait (< 4s), delivers a new record (restarts idle clock to
    //   full 4s!), then server closes cleanly -> client MUST reconnect (Attempt 3) with refreshed
    //   wait!
    let observed_waits = Arc::new(Mutex::new(Vec::<Option<u32>>::new()));
    let attempt_idx = Arc::new(AtomicUsize::new(0));
    let trigger_reset = Arc::new(tokio::sync::Notify::new());
    let r11c_server = MockH2Server::start({
        let observed_waits = observed_waits.clone();
        let attempt_idx = attempt_idx.clone();
        let trigger_reset = trigger_reset.clone();
        move |_conn_id, req, mut respond| {
            let observed_waits = observed_waits.clone();
            let attempt_idx = attempt_idx.clone();
            let trigger_reset = trigger_reset.clone();
            async move {
                let wait_param = query_pairs(req.uri())
                    .get("wait")
                    .and_then(|v| v.parse::<u32>().ok());
                observed_waits.lock().unwrap().push(wait_param);
                let n = attempt_idx.fetch_add(1, Ordering::SeqCst);
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(resp, false) else {
                    return;
                };
                match n {
                    0 => {
                        let hb = ProtoReadBatch {
                            records: vec![],
                            tail: Some(ProtoStreamPosition {
                                seq_num: 0,
                                timestamp: 1000,
                            }),
                        }
                        .encode_to_vec();
                        let _ = send.send_data(encode_s2s_regular_frame(&hb, false), false);
                        trigger_reset.notified().await;
                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                    }
                    1 => {
                        // Deliver record 0 on the reduced-wait attempt, then clean EOF immediately.
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_read_batch(0, 1), false),
                            true,
                        );
                    }
                    _ => {
                        // Attempt 3: deliver record 1 and end cleanly.
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_read_batch(1, 2), false),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let mut sess = r11c_server
        .client(fast_retry_config(3))
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new()
                .with_start(ReadFrom::SeqNum(0))
                .with_wait(Duration::from_secs(4))
                .unwrap()
                .with_count(2),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Wait for Attempt 1's heartbeat (which initializes `idle_since` before resolving caught_up).
    let caught = tokio::time::timeout(Duration::from_secs(2), sess.caught_up())
        .await
        .expect("heartbeat must resolve caught_up")
        .unwrap();
    assert_eq!(caught.seq_num, 0);

    // Advance virtual clock past 1s so remaining_wait drops from 4s to 3s, then reset Attempt 1.
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(1200)).await;
    tokio::time::resume();
    trigger_reset.notify_one();

    let mut seqs = Vec::new();
    while let Some(res) = sess.next().await {
        seqs.push(res.unwrap().seq_num);
    }
    assert_eq!(seqs, vec![0, 1]);
    let waits = observed_waits.lock().unwrap().clone();
    assert_eq!(waits.len(), 3, "must reconnect after reduced-wait attempt");
    assert_eq!(waits[0], Some(4));
    assert!(
        waits[1].unwrap() < 4,
        "attempt 2 should have reduced wait: {waits:?}"
    );
    assert_eq!(
        waits[2],
        Some(4),
        "attempt 3 should refresh wait after new record: {waits:?}"
    );
}

// spec: r1 R11d
// Regression: R11d zero-wait 416 must resolve caught_up() across a trimmed gap, and count=0
// disconnect must stop cleanly instead of sending count=0.
#[tokio::test]
async fn regression_read_session_r11d_caught_up_and_count_exhausted() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. R11d: resumed zero-wait 416 resolves caught_up() and advances next_seq_num across trimmed
    //    gap (record 0 has tail=3 so session is not yet caught up, then attempt 2 gets 416
    //    {tail:5}).
    let r11d_attempt = Arc::new(AtomicUsize::new(0));
    let r11d_reset_gate = Arc::new(tokio::sync::Notify::new());
    let r11d_server = MockH2Server::start({
        let r11d_attempt = r11d_attempt.clone();
        let r11d_reset_gate = r11d_reset_gate.clone();
        move |_conn_id, _req, mut respond| {
            let r11d_attempt = r11d_attempt.clone();
            let r11d_reset_gate = r11d_reset_gate.clone();
            async move {
                let n = r11d_attempt.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "s2s/proto")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        // Record 0 with tail=3 so session is still behind tail after delivering 0.
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_read_batch(0, 3), false),
                            false,
                        );
                        // Wait until client receives record 0 before resetting so h2 does not
                        // drop the buffered DATA frame on RST_STREAM.
                        r11d_reset_gate.notified().await;
                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                    }
                } else {
                    // Resumed with wait=0 -> 416 with tail jumped to seq 5 (trimmed gap).
                    let resp = Response::builder()
                        .status(416)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":5,"timestamp":5000}}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let mut r11d_sess = r11d_server
        .client(
            RetryConfig::new()
                .with_max_attempts(2)
                .unwrap()
                .with_min_base_delay(Duration::ZERO)
                .with_max_base_delay(Duration::ZERO),
        )
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_session(
            ReadInput::new()
                .with_start(ReadFrom::SeqNum(0))
                .with_wait(Duration::ZERO)
                .unwrap(),
            ReadSessionConfig::default(),
        )
        .unwrap();

    let cu = r11d_sess.caught_up();
    assert_eq!(r11d_sess.next().await.unwrap().unwrap().seq_num, 0);
    assert!(!r11d_sess.is_caught_up());
    r11d_reset_gate.notify_one();
    assert!(r11d_sess.next().await.is_none());
    assert_eq!(r11d_sess.next_seq_num(), Some(5));
    assert_eq!(r11d_sess.last_observed_tail().unwrap().seq_num, 5);
    assert_eq!(cu.await.unwrap().seq_num, 5);

    // 2b. R11d recreated-stream guard: resumed zero-wait 416 whose tail.seq_num < resume_seq_num
    //     MUST surface ReadUnwrittenError (not silently stop cleanly!).
    let recreated_attempt = Arc::new(AtomicUsize::new(0));
    let recreated_reset_gate = Arc::new(tokio::sync::Notify::new());
    let recreated_server = MockH2Server::start({
        let recreated_attempt = recreated_attempt.clone();
        let recreated_reset_gate = recreated_reset_gate.clone();
        move |_conn_id, _req, mut respond| {
            let recreated_attempt = recreated_attempt.clone();
            let recreated_reset_gate = recreated_reset_gate.clone();
            async move {
                let n = recreated_attempt.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    let resp = Response::builder()
                        .status(200)
                        .header("content-type", "s2s/proto")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            encode_s2s_regular_frame(
                                &proto_read_batch_records(&[0, 1, 2, 3, 4], Some(5)),
                                false,
                            ),
                            false,
                        );
                        recreated_reset_gate.notified().await;
                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                    }
                } else {
                    // Stream was deleted & recreated with tail.seq_num = 1 (< resume_seq_num = 5).
                    let resp = Response::builder()
                        .status(416)
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(
                            Bytes::from_static(br#"{"tail":{"seq_num":1,"timestamp":100}}"#),
                            true,
                        );
                    }
                }
            }
        }
    })
    .await;

    let mut recreated_sess = recreated_server
        .client(
            RetryConfig::new()
                .with_max_attempts(2)
                .unwrap()
                .with_min_base_delay(Duration::ZERO)
                .with_max_base_delay(Duration::ZERO),
        )
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .read_session(
            ReadInput::new()
                .with_start(ReadFrom::SeqNum(0))
                .with_wait(Duration::ZERO)
                .unwrap(),
            ReadSessionConfig::default(),
        )
        .unwrap();
    for expected in 0..5 {
        assert_eq!(
            recreated_sess.next().await.unwrap().unwrap().seq_num,
            expected
        );
    }
    recreated_reset_gate.notify_one();
    let recreated_err = recreated_sess
        .next()
        .await
        .expect("R11d: tail < resume_seq_num must yield error")
        .expect_err("must be ReadUnwritten");
    assert!(
        matches!(recreated_err, ReadSessionError::ReadUnwritten(ref e) if e.tail.seq_num == 1),
        "R11d: recreated stream 416 must surface ReadUnwrittenError, got {recreated_err:?}"
    );

    // 3. Count exhausted + transport reset ends cleanly without retrying with count=0.
    let count_reqs = Arc::new(AtomicUsize::new(0));
    let count_reset_gate = Arc::new(tokio::sync::Notify::new());
    let count_server = MockH2Server::start({
        let count_reqs = count_reqs.clone();
        let count_reset_gate = count_reset_gate.clone();
        move |_conn_id, _req, mut respond| {
            let count_reqs = count_reqs.clone();
            let count_reset_gate = count_reset_gate.clone();
            async move {
                count_reqs.fetch_add(1, Ordering::SeqCst);
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "s2s/proto")
                    .body(())
                    .unwrap();
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_read_batch(0, 1), false),
                        false,
                    );
                    count_reset_gate.notified().await;
                    send.send_reset(h2::Reason::INTERNAL_ERROR);
                }
            }
        }
    })
    .await;

    let mut count_sess = count_server
        .client(
            RetryConfig::new()
                .with_max_attempts(3)
                .unwrap()
                .with_min_base_delay(Duration::ZERO)
                .with_max_base_delay(Duration::ZERO),
        )
        .basin(basin_name)
        .stream(stream_name)
        .read_session(
            ReadInput::new()
                .with_start(ReadFrom::SeqNum(0))
                .with_count(1),
            ReadSessionConfig::default(),
        )
        .unwrap();

    assert_eq!(count_sess.next().await.unwrap().unwrap().seq_num, 0);
    count_reset_gate.notify_one();
    assert!(count_sess.next().await.is_none());
    assert_eq!(
        count_reqs.load(Ordering::SeqCst),
        1,
        "must not reconnect with count=0 after limit exhausted"
    );
}
