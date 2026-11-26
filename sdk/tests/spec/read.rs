use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use s2_sdk::{
    error::{ReadError, ReadSessionError},
    read_session::{ReadSessionConfig, ReadSessionRetryPolicy},
    types::{EncryptionKey, ReadInput, ReadStart},
};

use crate::support::*;

// spec: r1 R1, R2, R3, R4
#[tokio::test]
async fn spec_r2_r3_r4_unary_read_stop_options_empty_batch_416_and_check_tail() {
    let captured = Arc::new(Mutex::new(Vec::<(
        String,
        BTreeMap<String, String>,
        bool,
        bool,
    )>::new()));

    let server = MockH2Server::start({
        let captured = captured.clone();
        move |_conn_id, req, respond| {
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
                    send_tail_json(respond, 200, 42, 4200);
                } else if idx == 2 {
                    // Empty batch when stop condition met before any record (R3).
                    send_proto(respond, proto_read_batch_records(&[], Some(42)));
                } else {
                    // wait=0 at tail returns 416 ReadUnwrittenError (R3).
                    send_tail_json(respond, 416, 42, 4200);
                }
            }
        }
    })
    .await;

    let key = EncryptionKey::from_bytes(&[0x11u8; 32]).unwrap();
    let stream = server.stream(no_retry_config()).with_encryption_key(key);

    // R4 + C4: check_tail returns tail position and omits s2-encryption-key / s2-stream-config.
    let tail = stream.check_tail().await.unwrap();
    assert_eq!(tail.seq_num, 42);
    assert_eq!(tail.timestamp, 4200);

    // R2 + R3: unary read with omitted stop options sends none of count/bytes/until/wait and
    // returns empty server batch verbatim.
    let empty_batch = stream.read(ReadInput::new(ReadStart::TAIL)).await.unwrap();
    assert!(empty_batch.records.is_empty());
    assert_eq!(empty_batch.tail.unwrap().seq_num, 42);

    // R2 + R3: explicit count/bytes/until/wait=0 serialized; 416 surfaces as ReadUnwrittenError.
    let err = stream
        .read(
            ReadInput::new(ReadStart::TAIL)
                .with_count(10)
                .with_bytes(1024)
                .with_until(9999)
                .with_wait_secs(0),
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
    // Call 2: ReadInput::new(ReadStart::TAIL) -> tail_offset=0 elided (R1) and omitted stop params
    // left unset (R2).
    assert!(
        log[1].1.is_empty(),
        "R1/R2: tail_offset=0 and omitted stop options must be unset: {:?}",
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
    use futures_util::FutureExt as _;

    let fast_retry = fast_retry_config(3);

    // 1. R5 + R6 + R6c + R7 + R7a + R7b + R7c + R8 + R8a-R8d: Walk the exact on-demand spec Example
    //    table over loopback HTTP/2 with a concurrent observer task!
    let opened_notify = Arc::new(tokio::sync::Notify::new());
    let send_step4_hb = Arc::new(tokio::sync::Notify::new());
    let send_step5_rec5_6 = Arc::new(tokio::sync::Notify::new());
    let break_conn = Arc::new(tokio::sync::Notify::new());
    let allow_reconnect_hb = Arc::new(tokio::sync::Notify::new());
    let attempt_num = Arc::new(AtomicUsize::new(0));

    let server = MockH2Server::start({
        let opened_notify = opened_notify.clone();
        let send_step4_hb = send_step4_hb.clone();
        let send_step5_rec5_6 = send_step5_rec5_6.clone();
        let break_conn = break_conn.clone();
        let allow_reconnect_hb = allow_reconnect_hb.clone();
        let attempt_num = attempt_num.clone();
        move |_conn_id, _req, respond| {
            let opened_notify = opened_notify.clone();
            let send_step4_hb = send_step4_hb.clone();
            let send_step5_rec5_6 = send_step5_rec5_6.clone();
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
                    // Distinct timestamp lets the test verify step 4's heartbeat was decoded.
                    s2s.send_regular(&proto_heartbeat_at(5, 2000), false, false);
                    send_step5_rec5_6.notified().await;
                    s2s.send_regular(&proto_read_batch_records(&[5, 6], Some(7)), false, false);
                    break_conn.notified().await;
                    // Break active request with RST_STREAM
                    s2s.reset(h2::Reason::INTERNAL_ERROR);
                } else {
                    allow_reconnect_hb.notified().await;
                    s2s.send_regular(&proto_heartbeat(7), false, false);
                    std::future::pending::<()>().await;
                }
            }
        }
    })
    .await;

    let stream = server.stream(fast_retry);

    let mut session = stream
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .expect("R5: sync open succeeds");
    // R5: opening sends NO request until iteration first pulls!
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        attempt_num.load(Ordering::SeqCst),
        0,
        "R5: opening a read session must not send a request before the first pull"
    );

    // R6c: concurrent ReadSessionState handle observed from another task while iterating.
    let state = session.state();
    assert_eq!(state.next_seq_num(), Some(0));
    assert_eq!(state.last_observed_tail(), None);
    assert!(!state.is_caught_up());
    let cu1 = state.caught_up();

    // First pull initiates the request (`R5`) and delivers record 0 -> next_seq_num=1,
    // last_observed_tail=5, is_caught_up=false.
    let r0 = session.next().await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(2), opened_notify.notified())
        .await
        .expect("R5: first pull must initiate request");
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

    // Step 4: heartbeat tail=5 (ts=2000) is NOT decoded while parked, and IS decoded while
    // pulling at the tail (keeping is_caught_up=true).
    send_step4_hb.notify_one();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_ne!(
        state.last_observed_tail().map(|t| t.timestamp),
        Some(2000),
        "R6b: parked session must not decode heartbeats before pulling"
    );
    let hb_observed = tokio::time::timeout(Duration::from_secs(2), async {
        let mut pull = Box::pin(session.next());
        let mut tick = tokio::time::interval(Duration::from_millis(5));
        loop {
            tokio::select! {
                _ = &mut pull => panic!("heartbeat must not yield a record"),
                _ = tick.tick() => {
                    if state
                        .last_observed_tail()
                        .is_some_and(|t| t.seq_num == 5 && t.timestamp == 2000)
                    {
                        break;
                    }
                }
            }
        }
    })
    .await;
    hb_observed.expect("pulling at tail must decode heartbeat");
    assert!(state.is_caught_up());

    // Steps 5–6: server sends records [5, 6] with tail=7 -> pull delivers record 5 ->
    // next_seq_num=6, last_observed_tail=7, is_caught_up=false; pinned_cu stays 5 (R8a);
    // then record 6 delivers -> next_seq_num=7, is_caught_up=true.
    send_step5_rec5_6.notify_one();
    let r5 = session.next().await.unwrap().unwrap();
    assert_eq!(r5.seq_num, 5);
    assert_eq!(state.next_seq_num(), Some(6));
    assert_eq!(state.last_observed_tail().unwrap().seq_num, 7);
    assert!(!state.is_caught_up());
    assert_eq!(pinned_cu.await.unwrap().seq_num, 5);

    let r6 = session.next().await.unwrap().unwrap();
    assert_eq!(r6.seq_num, 6);
    assert_eq!(state.next_seq_num(), Some(7));
    assert!(state.is_caught_up());

    // Steps 7–8: active request breaks -> observed while pulling (is_caught_up=false),
    // caught_up() stays pending across retry (R8c), and resolves to 7 on reconnect heartbeat!
    break_conn.notify_one();
    // While parked, the session does NOT reconnect or mutate state (`R6b`, `R7`).
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        attempt_num.load(Ordering::SeqCst),
        1,
        "R6b: parked session must not reconnect on server reset until pulled"
    );
    assert!(state.is_caught_up());

    // Drive iteration in the background while observing disconnect and R8c reconnect catchup.
    let mut cu_across_retry = None;
    let disconnect_and_reconnect = tokio::time::timeout(Duration::from_secs(3), async {
        let mut pull = Box::pin(session.next());
        let mut tick = tokio::time::interval(Duration::from_millis(5));
        // Phase 1: wait for pull to observe disconnect and clear is_caught_up.
        loop {
            tokio::select! {
                res = &mut pull => panic!("unexpected terminal result during retry: {res:?}"),
                _ = tick.tick() => {
                    if !state.is_caught_up() {
                        assert_eq!(state.next_seq_num(), Some(7));
                        assert_eq!(state.last_observed_tail().unwrap().seq_num, 7);
                        cu_across_retry = Some(state.caught_up());
                        allow_reconnect_hb.notify_one();
                        break;
                    }
                }
            }
        }
        // Phase 2: keep driving `pull` while awaiting `cu_across_retry` (`R8b`, `R8c`).
        let mut cu = cu_across_retry.take().unwrap();
        tokio::select! {
            tail = &mut cu => tail.unwrap(),
            res = &mut pull => panic!("unexpected record/error before reconnect heartbeat: {res:?}"),
        }
    })
    .await
    .expect("R8c: caught_up must resolve after reconnect while iterating");
    assert_eq!(disconnect_and_reconnect.seq_num, 7);
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
        .stream(no_retry_config())
        .read_batch_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_count(2),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let b = batch_session.next().await.unwrap().unwrap();
    assert_eq!(b.records.len(), 2);
    assert_eq!(batch_session.next_seq_num(), Some(2));
    assert!(batch_session.is_caught_up());
    assert!(batch_session.next().await.is_none());
    assert!(!batch_session.is_caught_up());

    // 3. R6b: Zero decoded batches ahead + deterministic synchronous draining (`now_or_never`) of
    //    already-buffered frames! All 4 small S2S frames are coalesced into a single HTTP/2 DATA
    //    chunk so once batch 0 is decoded, batches 1..3 are guaranteed already buffered in the
    //    client without loopback timing dependence.
    let ra_reqs = Arc::new(AtomicUsize::new(0));
    let readahead_server = MockH2Server::start({
        let ra_reqs = ra_reqs.clone();
        move |_conn_id, _req, respond| {
            let ra_reqs = ra_reqs.clone();
            async move {
                ra_reqs.fetch_add(1, Ordering::SeqCst);
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                let mut coalesced = Vec::new();
                for b_idx in 0u64..4 {
                    let s0 = b_idx * 2;
                    let s1 = s0 + 1;
                    coalesced.extend_from_slice(&encode_s2s_regular_frame(
                        &proto_read_batch_records(&[s0, s1], Some(s1 + 1)),
                        false,
                    ));
                }
                s2s.send_raw(bytes::Bytes::from(coalesced), false);
                std::future::pending::<()>().await;
            }
        }
    })
    .await;

    let mut ra_session = readahead_server
        .stream(no_retry_config())
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Before pulling anything: 0 requests sent and 0 batches decoded.
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(ra_reqs.load(Ordering::SeqCst), 0);
    assert_eq!(ra_session.last_observed_tail(), None);

    // Pull record 0 of B0 -> ONLY B0 (tail=2) is decoded; B1..B3 remain undecoded even though
    // their bytes are already in the client decoder buffer!
    assert_eq!(ra_session.next().await.unwrap().unwrap().seq_num, 0);
    assert_eq!(
        ra_session.last_observed_tail().map(|t| t.seq_num),
        Some(2),
        "R6b: while delivering B0, session must decode 0 batches ahead"
    );

    // Finish B0 (record 1) -> STILL 0 batches decoded ahead (tail stays 2 until next pull)!
    assert_eq!(ra_session.next().await.unwrap().unwrap().seq_num, 1);
    assert_eq!(
        ra_session.last_observed_tail().map(|t| t.seq_num),
        Some(2),
        "R6b: between batches, session must decode 0 batches ahead"
    );

    // Pull record 2 of B1 -> decodes B1 (tail=4), NOT B2 (tail=6)!
    assert_eq!(ra_session.next().await.unwrap().unwrap().seq_num, 2);
    assert_eq!(
        ra_session.last_observed_tail().map(|t| t.seq_num),
        Some(4),
        "R6b: while delivering B1, session must decode 0 batches ahead"
    );

    // All remaining small batches (B1 tail, B2, B3) are already buffered in the client, so
    // `now_or_never()` deterministically drains records 3..=7 without a single Pending!
    let mut drained = Vec::new();
    while let Some(item) = ra_session.next().now_or_never() {
        drained.push(item.unwrap().unwrap().seq_num);
    }
    assert_eq!(
        drained,
        vec![3, 4, 5, 6, 7],
        "R6b: on-demand session must synchronously drain already-buffered batches via now_or_never"
    );
    assert_eq!(ra_session.last_observed_tail().map(|t| t.seq_num), Some(8));
    assert!(ra_session.is_caught_up());

    // 4. R6a + R6b: ReadBatchSession also decodes 0 batches ahead and deterministically drains
    //    already-buffered batches via `now_or_never()`.
    let mut ra_batch_session = readahead_server
        .stream(no_retry_config())
        .read_batch_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let b0 = ra_batch_session.next().await.unwrap().unwrap();
    assert_eq!(
        b0.records.iter().map(|r| r.seq_num).collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(
        ra_batch_session.last_observed_tail().map(|t| t.seq_num),
        Some(2),
        "R6b: ReadBatchSession must hold 0 decoded batches ahead between pulls"
    );
    let mut drained_batches = Vec::new();
    while let Some(item) = ra_batch_session.next().now_or_never() {
        drained_batches.push(
            item.unwrap()
                .unwrap()
                .records
                .into_iter()
                .map(|r| r.seq_num)
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(
        drained_batches,
        vec![vec![2, 3], vec![4, 5], vec![6, 7]],
        "R6b: ReadBatchSession must synchronously drain already-buffered batches via now_or_never"
    );
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
        move |_conn_id, _req, respond| {
            let eof_attempts = eof_attempts.clone();
            async move {
                eof_attempts.fetch_add(1, Ordering::SeqCst);
                if let Some(mut s2s) = S2sResponder::open(respond) {
                    s2s.send_eof();
                }
            }
        }
    })
    .await;

    let stream = eof_server.stream(fast_retry_2);

    // Without stop option -> retried (2 attempts) then fails with ConnectionLostError.
    let mut no_stop = stream
        .read_session(
            ReadInput::new(ReadStart::TAIL),
            ReadSessionConfig::default(),
        )
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
        .read_session(
            ReadInput::new(ReadStart::TAIL).with_count(5),
            ReadSessionConfig::default(),
        )
        .unwrap();
    assert!(with_stop.next().await.is_none());

    // 2. R9c + R10: Terminal failure delivers all already-fetched records FIRST, then yields the
    //    unwrapped failure once, then None!
    let fail_server = MockH2Server::start(|_conn_id, _req, respond| async move {
        let Some(mut s2s) = S2sResponder::open(respond) else {
            return;
        };
        s2s.send_regular(&proto_read_batch_records(&[0, 1], None), false, false);
        s2s.send_terminal(404, br#"{"code":"stream_not_found","message":"deleted"}"#);
    })
    .await;

    let mut fail_sess = fail_server
        .stream(no_retry_config())
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
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

    // 3. R9b: Dropping a pending next() future cancels only the wait without losing records.
    let delayed_connected = Arc::new(tokio::sync::Notify::new());
    let delayed_release = Arc::new(tokio::sync::Notify::new());
    let delayed_server = MockH2Server::start({
        let delayed_connected = delayed_connected.clone();
        let delayed_release = delayed_release.clone();
        move |_conn_id, _req, respond| {
            let delayed_connected = delayed_connected.clone();
            let delayed_release = delayed_release.clone();
            async move {
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                delayed_connected.notify_one();
                delayed_release.notified().await;
                s2s.send_regular(&proto_read_batch_records(&[0, 1], Some(2)), false, false);
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
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Start pulling so R5 opens the stream, wait until connected, then cancel the pending next()
    // future (`T8`/`R9b`) -> session stays alive and delivers record 0 on the next pull!
    {
        let mut pending_next = Box::pin(sess.next());
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                res = &mut pending_next => panic!("unexpected result before release: {res:?}"),
                _ = delayed_connected.notified() => {}
            }
        })
        .await
        .expect("read session must connect on first pull");
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
                    // Send a batch [0, 1] and then go silent!
                    s2s.send_regular(&proto_read_batch_records(&[0, 1], Some(2)), false, false);
                    std::future::pending::<()>().await;
                } else {
                    // On retry after heartbeat timeout, deliver record 2.
                    s2s.send_regular(&proto_read_batch_records(&[2], Some(3)), false, false);
                    std::future::pending::<()>().await;
                }
            }
        }
    })
    .await;

    let mut session = server
        .stream(fast_retry_2)
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Pull record 0 (record 1 stays in current_batch).
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 0);

    // Advance 60s (> 20s heartbeat timeout!) while caller has NOT consumed record 1.
    // T7d: time spent consuming current batch MUST NOT count toward the 20s heartbeat timeout!
    advance_virtual_time(Duration::from_secs(60)).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "T7d: heartbeat timer must not fire while consuming current batch"
    );

    // Deliver record 1 (draining current_batch), then park 60s without iterating!
    // T7d: time spent not iterating MUST NOT count toward the 20s heartbeat timeout!
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 1);
    advance_virtual_time(Duration::from_secs(60)).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "T7d: heartbeat timer must not fire while parked between pulls"
    );

    // Arm the 20s heartbeat timer by waiting on the transport (empty receive buffer), then
    // advance 21s while silent -> heartbeat timeout fires and retries onto attempt 2, delivering
    // record 2! (Deterministic buffered-frame, partial-chunk, and resume-after-cancel T7d cases
    // run with injected streams under `start_paused = true` in `sdk/src/session/read.rs`.)
    let mut next_rec = Box::pin(session.next());
    assert!(futures_util::poll!(next_rec.as_mut()).is_pending());
    advance_virtual_time(Duration::from_secs(21)).await;
    let rec2 = tokio::time::timeout(Duration::from_secs(3), next_rec)
        .await
        .expect("heartbeat timeout must trigger retry after 20s of waiting")
        .unwrap()
        .unwrap();
    assert_eq!(rec2.seq_num, 2);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

// spec: r1 R11, R11a, R11b, R11c, R11d, T5, T5b
#[tokio::test]
async fn spec_r11_t5_t5b_read_session_resume_clamp_wait_416_and_unbounded() {
    let fast_retry_2 = fast_retry_config(2);

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
        move |_conn_id, req, respond| {
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
                    send_tail_json(respond, 416, 12, 1200);
                    return;
                }
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                if idx == 1 {
                    s2s.send_regular(&proto_heartbeat(10), false, false);
                    a1_hb1_sent.notify_one();
                    send_hb2.notified().await;
                    s2s.send_regular(&proto_heartbeat_at(10, 2000), false, false);
                    break_a1.notified().await;
                    s2s.reset(h2::Reason::INTERNAL_ERROR);
                } else {
                    s2s.send_regular(&proto_read_batch_records(&[10, 11], Some(12)), false, false);
                    break_a2.notified().await;
                    s2s.reset(h2::Reason::INTERNAL_ERROR);
                }
            }
        }
    })
    .await;

    let mut session = server
        .stream(fast_retry_2)
        .read_session(
            ReadInput::new(ReadStart::TailOffset(2))
                .with_clamp(true)
                .with_count(5)
                .with_wait_secs(10),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Drive iteration while waiting for hb1 so the on-demand session connects and resolves start!
    let state = session.state();
    let mut cu = state.caught_up();
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            res = &mut cu => res.unwrap(),
            item = session.next() => panic!("unexpected item before hb1: {item:?}"),
        }
    })
    .await
    .expect("client must resolve start from hb1");
    assert_eq!(state.next_seq_num(), Some(10));
    let _ = a1_hb1_sent;

    // Wait 3s, send 2nd heartbeat (decoded while pulling; must NOT reset wait clock!), wait 2.1s
    // more (5.1s total elapsed).
    advance_virtual_time(Duration::from_secs(3)).await;
    send_hb2.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut pull = Box::pin(session.next());
        let mut tick = tokio::time::interval(Duration::from_millis(5));
        loop {
            tokio::select! {
                item = &mut pull => panic!("unexpected item during hb2: {item:?}"),
                _ = tick.tick() => {
                    if state
                        .last_observed_tail()
                        .is_some_and(|t| t.seq_num == 10 && t.timestamp == 2000)
                    {
                        break;
                    }
                }
            }
        }
    })
    .await
    .expect("client must decode hb2 while pulling");
    advance_virtual_time(Duration::from_millis(2_100)).await;
    break_a1.notify_one();

    // Attempt 2 delivers records 10 and 11 (restarting wait clock!).
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 10);
    assert_eq!(session.next().await.unwrap().unwrap().seq_num, 11);

    // Wait 11.4s (> 10s wait) -> break attempt 2 -> Attempt 3 sends wait=0, gets 416 -> clean end!
    advance_virtual_time(Duration::from_millis(11_400)).await;
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

    // 2. R11d negative check: 416 on resumed request while wait > 0 (with tail == resume_seq) STILL
    //    fails with ReadUnwritten!
    let r11d_neg_attempts = Arc::new(AtomicUsize::new(0));
    let r11d_break = Arc::new(tokio::sync::Notify::new());
    let r11d_neg_server = MockH2Server::start({
        let r11d_neg_attempts = r11d_neg_attempts.clone();
        let r11d_break = r11d_break.clone();
        move |_conn_id, _req, respond| {
            let r11d_neg_attempts = r11d_neg_attempts.clone();
            let r11d_break = r11d_break.clone();
            async move {
                let idx = r11d_neg_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if idx == 1 {
                    if let Some(mut s2s) = S2sResponder::open(respond) {
                        s2s.send_regular(&proto_read_batch_records(&[0], Some(1)), false, false);
                        r11d_break.notified().await;
                        s2s.reset(h2::Reason::INTERNAL_ERROR);
                    }
                } else {
                    // tail.seq_num == resume_seq_num (1) so only the wait > 0 check rejects it.
                    send_tail_json(respond, 416, 1, 100);
                }
            }
        }
    })
    .await;

    let mut neg_sess = r11d_neg_server
        .stream(fast_retry_2)
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_wait_secs(30),
            ReadSessionConfig::default(),
        )
        .unwrap();
    assert_eq!(neg_sess.next().await.unwrap().unwrap().seq_num, 0);
    r11d_break.notify_one();
    let err = neg_sess.next().await.unwrap().unwrap_err();
    assert!(
        matches!(err, ReadSessionError::ReadUnwritten(ref e) if e.tail.seq_num == 1),
        "R11d: 416 while wait > 0 must still fail with ReadUnwrittenError, got {err:?}"
    );

    // 3. T5 + T5b: ReadSessionRetryPolicy::Unbounded retries past max_attempts (2) and succeeds!
    let unbounded_attempts = Arc::new(AtomicUsize::new(0));
    let unbounded_server = MockH2Server::start({
        let unbounded_attempts = unbounded_attempts.clone();
        move |_conn_id, _req, respond| {
            let unbounded_attempts = unbounded_attempts.clone();
            async move {
                let idx = unbounded_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if idx <= 5 {
                    send_json(respond, 503, r#"{"code":"unavailable","message":"retry"}"#);
                } else if let Some(mut s2s) = S2sResponder::open(respond) {
                    s2s.send_regular(&proto_read_batch_records(&[0], Some(1)), false, true);
                }
            }
        }
    })
    .await;

    let mut unbounded_sess = unbounded_server
        .stream(fast_retry_2)
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_count(1),
            ReadSessionConfig::new().with_retry_policy(ReadSessionRetryPolicy::Unbounded),
        )
        .unwrap();
    assert_eq!(unbounded_sess.next().await.unwrap().unwrap().seq_num, 0);
    assert!(unbounded_sess.next().await.is_none());
    assert_eq!(unbounded_attempts.load(Ordering::SeqCst), 6);
}

// spec: r1 T6a, R7c, R8
#[tokio::test]
async fn spec_t6a_read_session_reconnect_advice_cooldown() {
    let seen_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let req_idx = Arc::new(AtomicUsize::new(0));
    let server = MockH2Server::start({
        let seen_conns = seen_conns.clone();
        let req_idx = req_idx.clone();
        move |conn_id, _req, respond| {
            let seen_conns = seen_conns.clone();
            let req_idx = req_idx.clone();
            async move {
                let n = req_idx.fetch_add(1, Ordering::SeqCst);
                seen_conns.lock().unwrap().push(conn_id);
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                if n == 0 {
                    // Multi-record batch `[0, 1]` with `tail = 2` and reconnect-advised bit ->
                    // catches up on final record 1 (`T6a`/`R7c`), drops `is_caught_up`, and opens
                    // the replacement request lazily on the next pull on a different connection.
                    s2s.send_regular(&proto_read_batch_records(&[0, 1], Some(2)), true, false);
                    std::future::pending::<()>().await;
                } else {
                    // Request 2: Record 2 WITH reconnect-advised bit (ignored within 60 s
                    // cooldown!), then Record 3 on the SAME request before clean EOF.
                    s2s.send_regular(&proto_read_batch(2, 3), true, false);
                    s2s.send_regular(&proto_read_batch(3, 4), false, true);
                }
            }
        }
    })
    .await;

    let mut session = server
        .stream(no_retry_config())
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_count(4),
            ReadSessionConfig::default(),
        )
        .unwrap();

    let mut cu = session.caught_up();

    // Record 0: still mid-batch, not yet caught up.
    let rec0 = session.next().await.unwrap().unwrap();
    assert_eq!(rec0.seq_num, 0);
    assert_eq!(session.next_seq_num(), Some(1));
    assert!(!session.is_caught_up());
    assert!(futures_util::poll!(std::pin::Pin::new(&mut cu)).is_pending());

    // Waiter created mid-batch also resolves when record 1 delivers the advised batch's tail.
    let mut mid_cu = session.caught_up();
    let rec1 = session.next().await.unwrap().unwrap();
    assert_eq!(rec1.seq_num, 1);
    assert_eq!(session.next_seq_num(), Some(2));
    assert!(matches!(
        futures_util::poll!(std::pin::Pin::new(&mut cu)),
        std::task::Poll::Ready(Ok(tail)) if tail.seq_num == 2
    ));
    assert!(matches!(
        futures_util::poll!(std::pin::Pin::new(&mut mid_cu)),
        std::task::Poll::Ready(Ok(tail)) if tail.seq_num == 2
    ));
    assert!(
        !session.is_caught_up(),
        "T6a/R7c: is_caught_up must be false once final advised record is returned"
    );
    assert_eq!(
        server.request_count(),
        1,
        "T6/R6b: replacement request must not open until iteration next pulls"
    );

    let mut seqs = vec![rec0.seq_num, rec1.seq_num];
    while let Some(res) = session.next().await {
        seqs.push(res.unwrap().seq_num);
    }
    assert_eq!(seqs, vec![0, 1, 2, 3]);
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
        move |_conn_id, req, respond| {
            let observed_waits = observed_waits.clone();
            let attempt_idx = attempt_idx.clone();
            let trigger_reset = trigger_reset.clone();
            async move {
                let wait_param = query_pairs(req.uri())
                    .get("wait")
                    .and_then(|v| v.parse::<u32>().ok());
                observed_waits.lock().unwrap().push(wait_param);
                let n = attempt_idx.fetch_add(1, Ordering::SeqCst);
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                match n {
                    0 => {
                        s2s.send_regular(&proto_heartbeat(0), false, false);
                        trigger_reset.notified().await;
                        s2s.reset(h2::Reason::INTERNAL_ERROR);
                    }
                    1 => {
                        // Deliver record 0 on the reduced-wait attempt, then clean EOF immediately.
                        s2s.send_regular(&proto_read_batch(0, 1), false, true);
                    }
                    _ => {
                        // Attempt 3: deliver record 1 and end cleanly.
                        s2s.send_regular(&proto_read_batch(1, 2), false, true);
                    }
                }
            }
        }
    })
    .await;

    let mut sess = r11c_server
        .stream(fast_retry_config(3))
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0))
                .with_wait_secs(4)
                .with_count(2),
            ReadSessionConfig::default(),
        )
        .unwrap();

    // Drive iteration while awaiting Attempt 1's heartbeat (`R8b`), which initializes `idle_since`
    // before resolving caught_up.
    let mut cu = sess.caught_up();
    let caught = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            res = &mut cu => res.unwrap(),
            item = sess.next() => panic!("unexpected item before heartbeat: {item:?}"),
        }
    })
    .await
    .expect("heartbeat must resolve caught_up while iterating");
    assert_eq!(caught.seq_num, 0);

    // Advance virtual clock past 1s so remaining_wait drops from 4s to 3s, then reset Attempt 1.
    advance_virtual_time(Duration::from_millis(1200)).await;
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
// Regression: R11d resumed 416 (both omitted-wait with a stop limit and zero-wait) resolves
// caught_up() across a trimmed gap, rejects tail regression (recreated stream), and stops cleanly
// when count is exhausted instead of sending count=0.
#[tokio::test]
async fn regression_read_session_r11d_caught_up_and_count_exhausted() {
    // 1. R11d (omitted wait + stop option): resumed 416 resolves caught_up() and advances
    //    next_seq_num across trimmed gap (record 0 has tail=3, then attempt 2 gets 416 {tail:5}).
    let r11d_attempt = Arc::new(AtomicUsize::new(0));
    let r11d_reset_gate = Arc::new(tokio::sync::Notify::new());
    let r11d_server = MockH2Server::start({
        let r11d_attempt = r11d_attempt.clone();
        let r11d_reset_gate = r11d_reset_gate.clone();
        move |_conn_id, _req, respond| {
            let r11d_attempt = r11d_attempt.clone();
            let r11d_reset_gate = r11d_reset_gate.clone();
            async move {
                let n = r11d_attempt.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    if let Some(mut s2s) = S2sResponder::open(respond) {
                        // Record 0 with tail=3 so session is still behind tail after delivering 0.
                        s2s.send_regular(&proto_read_batch(0, 3), false, false);
                        // Wait until client receives record 0 before resetting so h2 does not
                        // drop the buffered DATA frame on RST_STREAM.
                        r11d_reset_gate.notified().await;
                        s2s.reset(h2::Reason::INTERNAL_ERROR);
                    }
                } else {
                    // Resumed with omitted wait + count -> 416 with tail jumped to seq 5.
                    send_tail_json(respond, 416, 5, 5000);
                }
            }
        }
    })
    .await;

    let mut r11d_sess = r11d_server
        .stream(fast_retry_config(2))
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_count(10),
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

    // 2. R11d recreated-stream guard: resumed zero-wait 416 whose tail.seq_num < resume_seq_num
    //    MUST surface ReadUnwrittenError (not silently stop cleanly!).
    let recreated_attempt = Arc::new(AtomicUsize::new(0));
    let recreated_reset_gate = Arc::new(tokio::sync::Notify::new());
    let recreated_server = MockH2Server::start({
        let recreated_attempt = recreated_attempt.clone();
        let recreated_reset_gate = recreated_reset_gate.clone();
        move |_conn_id, _req, respond| {
            let recreated_attempt = recreated_attempt.clone();
            let recreated_reset_gate = recreated_reset_gate.clone();
            async move {
                let n = recreated_attempt.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    if let Some(mut s2s) = S2sResponder::open(respond) {
                        s2s.send_regular(
                            &proto_read_batch_records(&[0, 1, 2, 3, 4], Some(5)),
                            false,
                            false,
                        );
                        recreated_reset_gate.notified().await;
                        s2s.reset(h2::Reason::INTERNAL_ERROR);
                    }
                } else {
                    // Stream was deleted & recreated with tail.seq_num = 1 (< resume_seq_num = 5).
                    send_tail_json(respond, 416, 1, 100);
                }
            }
        }
    })
    .await;

    let mut recreated_sess = recreated_server
        .stream(fast_retry_config(2))
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_wait_secs(0),
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
        move |_conn_id, _req, respond| {
            let count_reqs = count_reqs.clone();
            let count_reset_gate = count_reset_gate.clone();
            async move {
                count_reqs.fetch_add(1, Ordering::SeqCst);
                if let Some(mut s2s) = S2sResponder::open(respond) {
                    s2s.send_regular(&proto_read_batch(0, 1), false, false);
                    count_reset_gate.notified().await;
                    s2s.reset(h2::Reason::INTERNAL_ERROR);
                }
            }
        }
    })
    .await;

    let mut count_sess = count_server
        .stream(fast_retry_config(3))
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_count(1),
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

// spec: r1 R11d
#[tokio::test]
async fn spec_r11d_416_after_retry_before_any_response_is_read_unwritten() {
    // R11d applies only after the session has decoded at least one record batch or heartbeat.
    // Starting at an unclamped unwritten seq_num with no wait remaining (either omitted wait with
    // `count` set or explicit `wait = 0`) that retries a transient 503 on attempt 1 and gets 416
    // (`tail.seq_num == sent_seq_num`) on attempt 2 must still fail with ReadUnwrittenError rather
    // than closing cleanly.
    for input in [
        ReadInput::new(ReadStart::SeqNum(5)).with_count(10),
        ReadInput::new(ReadStart::SeqNum(5)).with_wait_secs(0),
    ] {
        let attempts = Arc::new(AtomicUsize::new(0));
        let server = MockH2Server::start({
            let attempts = attempts.clone();
            move |_conn_id, _req, respond| {
                let attempts = attempts.clone();
                async move {
                    let n = attempts.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        send_json(respond, 503, r#"{"code":"unavailable","message":"retry"}"#);
                    } else {
                        send_tail_json(respond, 416, 5, 5000);
                    }
                }
            }
        })
        .await;

        let mut session = server
            .stream(fast_retry_config(2))
            .read_session(input, ReadSessionConfig::default())
            .unwrap();

        let err = session
            .next()
            .await
            .expect("R11d: 416 before any decoded response must yield an error, not clean end")
            .expect_err("expected ReadUnwrittenError");
        assert!(
            matches!(err, ReadSessionError::ReadUnwritten(ref e) if e.tail.seq_num == 5),
            "R11d: expected ReadUnwrittenError with tail=5, got {err:?}"
        );
        assert_eq!(server.request_count(), 2);
        assert!(session.next().await.is_none());
    }
}

// spec: r1 T5a, R9, R9a, R9c, R9d, R10
#[tokio::test]
async fn spec_t5a_empty_frame_does_not_reset_budget_and_r9_close_boundary() {
    // 1. T5a: an empty ReadBatch frame with no records and no tail is NOT a heartbeat and must NOT
    //    reset retry budget (so a budgeted session still gives up after max_attempts).
    let attempts = Arc::new(AtomicUsize::new(0));
    let empty_server = MockH2Server::start({
        let attempts = attempts.clone();
        move |_conn_id, _req, respond| {
            let attempts = attempts.clone();
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                if let Some(mut s2s) = S2sResponder::open(respond) {
                    // Empty frame: records=[], tail=None.
                    s2s.send_regular(&proto_read_batch_records(&[], None), false, false);
                    s2s.send_terminal(
                        503,
                        r#"{"code":"unavailable","message":"transient"}"#.as_bytes(),
                    );
                }
            }
        }
    })
    .await;

    let mut empty_sess = empty_server
        .stream(fast_retry_config(2))
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let err = empty_sess
        .next()
        .await
        .expect("must fail after budget exhausted")
        .unwrap_err();
    assert!(
        matches!(err, ReadSessionError::Server(ref e) if e.status == 503),
        "T5a: expected 503 after max_attempts=2, got {err:?}"
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "T5a: empty non-heartbeat frame must not reset retry budget"
    );

    // 1b. T6 / T6a + T5a: an empty frame with reconnect_advised=true still triggers handover
    //     (free after prior progress; counted as a retry and not resetting retry budget when no
    //     progress was made yet).
    let advised_empty_after_progress_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let advised_empty_after_progress_reqs = Arc::new(AtomicUsize::new(0));
    let advised_empty_after_progress_server = MockH2Server::start({
        let seen_conns = advised_empty_after_progress_conns.clone();
        let reqs = advised_empty_after_progress_reqs.clone();
        move |conn_id, _req, respond| {
            let seen_conns = seen_conns.clone();
            let reqs = reqs.clone();
            async move {
                let n = reqs.fetch_add(1, Ordering::SeqCst);
                seen_conns.lock().unwrap().push(conn_id);
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                if n == 0 {
                    // Deliver record 0 (progress!), then send an empty frame with reconnect advice
                    // and keep the stream open so the client must actively end the request.
                    s2s.send_regular(&proto_read_batch(0, 1), false, false);
                    s2s.send_regular(&proto_read_batch_records(&[], None), true, false);
                    std::future::pending::<()>().await;
                } else {
                    s2s.send_regular(&proto_read_batch(1, 2), false, true);
                }
            }
        }
    })
    .await;

    let mut advised_after_sess = advised_empty_after_progress_server
        .stream(no_retry_config())
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_count(2),
            ReadSessionConfig::default(),
        )
        .unwrap();
    assert_eq!(advised_after_sess.next().await.unwrap().unwrap().seq_num, 0);
    let rec1 = tokio::time::timeout(Duration::from_secs(2), advised_after_sess.next())
        .await
        .expect("T6: empty frame with reconnect_advised after progress must trigger handover")
        .unwrap()
        .unwrap();
    assert_eq!(rec1.seq_num, 1);
    assert!(advised_after_sess.next().await.is_none());
    let conns = advised_empty_after_progress_conns.lock().unwrap().clone();
    assert_eq!(conns.len(), 2);
    assert_ne!(
        conns[0], conns[1],
        "T6: empty frame handover must move to a fresh connection"
    );

    let advised_empty_before_progress_reqs = Arc::new(AtomicUsize::new(0));
    let advised_empty_before_progress_server = MockH2Server::start({
        let reqs = advised_empty_before_progress_reqs.clone();
        move |_conn_id, _req, respond| {
            let reqs = reqs.clone();
            async move {
                let n = reqs.fetch_add(1, Ordering::SeqCst);
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                if n == 0 {
                    // Empty frame with reconnect advice BEFORE any progress -> must consume retry
                    // budget (T6 / T5a) instead of resetting budget or hanging forever.
                    s2s.send_regular(&proto_read_batch_records(&[], None), true, false);
                    std::future::pending::<()>().await;
                } else {
                    s2s.send_terminal(
                        503,
                        r#"{"code":"unavailable","message":"transient"}"#.as_bytes(),
                    );
                }
            }
        }
    })
    .await;

    let mut advised_before_sess = advised_empty_before_progress_server
        .stream(fast_retry_config(2))
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let err = tokio::time::timeout(Duration::from_secs(2), advised_before_sess.next())
        .await
        .expect("T6: empty frame with reconnect_advised before progress must retry and finish")
        .expect("must fail after retry budget exhausted")
        .unwrap_err();
    assert!(
        matches!(err, ReadSessionError::Server(ref e) if e.status == 503),
        "T6/T5a: expected 503 on second attempt after empty-frame handover consumed attempt 1, got {err:?}"
    );
    assert_eq!(
        advised_empty_before_progress_reqs.load(Ordering::SeqCst),
        2,
        "T6/T5a: empty-frame handover before progress must count as a retry without resetting budget"
    );

    // 2. R9c with zero buffered records: iterating observes the terminal 404 and closes immediately
    //    (failing caught_up() with 404); a subsequent client.close() has no effect.
    let err_server = MockH2Server::start(|_conn_id, _req, respond| async move {
        if let Some(mut s2s) = S2sResponder::open(respond) {
            s2s.send_terminal(
                404,
                r#"{"code":"stream_not_found","message":"missing"}"#.as_bytes(),
            );
        }
    })
    .await;
    let err_client = err_server.client(no_retry_config());
    let (basin, stream) = test_basin_and_stream();
    let mut err_sess = err_client
        .basin(basin)
        .stream(stream)
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let cu = err_sess.caught_up();
    let next_err = err_sess
        .next()
        .await
        .expect("must yield terminal 404 once")
        .unwrap_err();
    assert!(
        matches!(next_err, ReadSessionError::Server(ref e) if e.status == 404),
        "R9c: expected 404 on next(), got {next_err:?}"
    );
    let cu_err = tokio::time::timeout(Duration::from_secs(2), cu)
        .await
        .expect("R9c: caught_up must fail immediately once terminal error is observed")
        .unwrap_err();
    assert!(
        matches!(cu_err, ReadSessionError::Server(ref e) if e.status == 404),
        "R9c: expected 404 on caught_up, got {cu_err:?}"
    );
    // Session already closed under R9c -> client.close() must have no effect.
    err_client.close();
    assert!(matches!(
        err_sess.caught_up().await,
        Err(ReadSessionError::Server(ref e)) if e.status == 404
    ));
    assert!(err_sess.next().await.is_none());

    // 3. R9a with zero buffered records: iterating observes clean EOF and closes immediately
    //    (failing caught_up() with SessionClosedError); a subsequent client.close() has no effect.
    let eof_server = MockH2Server::start(|_conn_id, _req, respond| async move {
        if let Some(mut s2s) = S2sResponder::open(respond) {
            s2s.send_eof();
        }
    })
    .await;
    let eof_client = eof_server.client(no_retry_config());
    let (basin, stream) = test_basin_and_stream();
    let mut eof_sess = eof_client
        .basin(basin)
        .stream(stream)
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_count(1),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let cu_eof_fut = eof_sess.caught_up();
    assert!(eof_sess.next().await.is_none());
    let cu_eof = tokio::time::timeout(Duration::from_secs(2), cu_eof_fut)
        .await
        .expect("R9a: caught_up must fail immediately when clean stop closes the session")
        .unwrap_err();
    assert!(
        matches!(cu_eof, ReadSessionError::SessionClosed(ref e) if e.failure().is_none()),
        "R9a: expected clean SessionClosedError on caught_up, got {cu_eof:?}"
    );
    eof_client.close();
    assert!(
        eof_sess.next().await.is_none(),
        "R9: post-close client.close() must not turn clean R9a close into AbortedError"
    );

    // 4. R9a/R9d with buffered records in the current batch (`count = 2`, batch `[0, 1]`, tail=5):
    //    4a: abort (`client.close()`) while record 1 is still buffered in `current_batch` and the
    //    session is parked IMMEDIATELY wakes `caught_up()` with AbortedError, drops record 1, and
    //    fails `next()` with AbortedError! 4b: draining both buffered records locks in `R9a`
    //    immediately (failing `caught_up()` with clean SessionClosedError); a subsequent
    //    `client.close()` is a no-op and `next()` returns `None`.
    let buffered_server = MockH2Server::start(|_conn_id, _req, respond| async move {
        if let Some(mut s2s) = S2sResponder::open(respond) {
            s2s.send_regular(&proto_read_batch_records(&[0, 1], Some(5)), false, true);
        }
    })
    .await;
    // 4a: abort while parked with record 1 still buffered -> both caught_up() and next() get
    // Aborted.
    let c1 = buffered_server.client(no_retry_config());
    let (basin, stream) = test_basin_and_stream();
    let mut s1 = c1
        .basin(basin)
        .stream(stream)
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_count(2),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let cu1 = s1.caught_up();
    assert_eq!(s1.next().await.unwrap().unwrap().seq_num, 0);
    // Park `cu1` on the shutdown future first (and do NOT poll s1.next()) — verify `c1.close()`
    // wakes the already-parked `cu1` immediately (`R8d`/`R9d`)!
    let cu1_polled = Arc::new(tokio::sync::Notify::new());
    let cu1_task = tokio::spawn({
        let cu1_polled = cu1_polled.clone();
        async move {
            let mut cu = Box::pin(cu1);
            assert!(futures_util::poll!(cu.as_mut()).is_pending());
            cu1_polled.notify_one();
            cu.await
        }
    });
    cu1_polled.notified().await;
    tokio::task::yield_now().await;
    c1.close();
    let cu1_err = tokio::time::timeout(Duration::from_secs(1), cu1_task)
        .await
        .expect("R8d/R9d: client.close() must wake parked caught_up immediately")
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(cu1_err, ReadSessionError::Aborted(_)),
        "R9d: abort while records remain buffered must fail caught_up with AbortedError, got {cu1_err:?}"
    );
    let next1 = s1
        .next()
        .await
        .expect("must yield AbortedError")
        .unwrap_err();
    assert!(
        matches!(next1, ReadSessionError::Aborted(_)),
        "R9d: abort while records remain buffered must fail next() with AbortedError, got {next1:?}"
    );
    assert!(s1.next().await.is_none());

    // 4b: drain both buffered records -> R9a locks in immediately, later client.close() is a no-op.
    let c2 = buffered_server.client(no_retry_config());
    let (basin, stream) = test_basin_and_stream();
    let mut s2 = c2
        .basin(basin)
        .stream(stream)
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_count(2),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let cu2 = s2.caught_up();
    assert_eq!(s2.next().await.unwrap().unwrap().seq_num, 0);
    assert_eq!(s2.next().await.unwrap().unwrap().seq_num, 1);
    let cu2_err = tokio::time::timeout(Duration::from_secs(2), cu2)
        .await
        .expect("R9a: caught_up must fail as soon as count-exhausted batch finishes draining")
        .unwrap_err();
    assert!(
        matches!(cu2_err, ReadSessionError::SessionClosed(ref e) if e.failure().is_none()),
        "R9a: expected clean SessionClosedError on caught_up after drain, got {cu2_err:?}"
    );
    c2.close();
    assert!(
        s2.next().await.is_none(),
        "R9: post-drain client.close() must not overwrite locked-in R9a clean stop"
    );
}

// spec: r1 R7a, R9a, R11c
#[tokio::test]
async fn regression_read_session_stops_on_exhausted_count_and_rejects_u64_max_seq_num() {
    // 1. R11c/R9a: When count=1 is exhausted on a server that keeps the stream open (sending a
    //    heartbeat or extra batch), the session immediately enters clean stop after delivering the
    //    requested record, preserving caught-up state and never yielding extra records.
    let server = MockH2Server::start(|_conn_id, _req, respond| async move {
        if let Some(mut s2s) = S2sResponder::open(respond) {
            s2s.send_regular(&proto_read_batch_records(&[0], Some(1)), false, false);
            // Keep the stream open and even send a heartbeat + an extra record past count=1.
            tokio::time::sleep(Duration::from_millis(50)).await;
            s2s.send_regular(&proto_heartbeat(1), false, false);
            s2s.send_regular(&proto_read_batch_records(&[1], Some(2)), false, false);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })
    .await;

    let mut sess = server
        .stream(no_retry_config())
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)).with_count(1),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let cu = sess.caught_up();
    let rec = sess.next().await.unwrap().unwrap();
    assert_eq!(rec.seq_num, 0);
    assert_eq!(cu.await.unwrap().seq_num, 1);
    let end = tokio::time::timeout(Duration::from_secs(2), sess.next())
        .await
        .expect("read session must close promptly once count=1 is exhausted");
    assert!(
        end.is_none(),
        "expected clean end after count=1, got {end:?}"
    );

    // 2. R7a + E7: A record at seq_num == u64::MAX has no representable successor `next_seq_num`,
    //    so the session fails with ProtocolError before delivering it — and if it arrived after a
    //    retry, the rendered ProtocolError reports the retry attempt count (`E7`).
    let overflow_attempts = Arc::new(AtomicUsize::new(0));
    let overflow_server = MockH2Server::start({
        let overflow_attempts = overflow_attempts.clone();
        move |_conn_id, _req, respond| {
            let overflow_attempts = overflow_attempts.clone();
            async move {
                let n = overflow_attempts.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    send_json(respond, 503, r#"{"code":"unavailable","message":"retry"}"#);
                } else if let Some(mut s2s) = S2sResponder::open(respond) {
                    s2s.send_regular(&proto_read_batch_records(&[u64::MAX], None), false, true);
                }
            }
        }
    })
    .await;

    let mut overflow_sess = overflow_server
        .stream(fast_retry_config(2))
        .read_session(
            ReadInput::new(ReadStart::SeqNum(u64::MAX)),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let err = overflow_sess
        .next()
        .await
        .expect("must yield ProtocolError")
        .unwrap_err();
    assert!(
        matches!(err, ReadSessionError::Protocol(_)),
        "expected ProtocolError on u64::MAX seq_num, got {err:?}"
    );
    let rendered = err.to_string();
    assert!(
        rendered.contains("after 2 attempts"),
        "E7: ProtocolError after retry must report attempt count, got: {rendered}"
    );
}

// spec: r1 C13d, R6b
#[tokio::test]
async fn spec_c13d_parked_reader_with_explicit_windows_does_not_stall_sibling_calls() {
    let reader_parked = Arc::new(tokio::sync::Notify::new());
    let window_exhausted = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let reader_parked = reader_parked.clone();
        let window_exhausted = window_exhausted.clone();
        move |_conn_id, req, respond| {
            let reader_parked = reader_parked.clone();
            let window_exhausted = window_exhausted.clone();
            async move {
                if req.uri().path().ends_with("/records/tail") {
                    send_tail_json(respond, 200, 42, 1000);
                    return;
                }
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                // Send record 0 and wait until the reader has consumed it and parked, then
                // saturate its 64 KiB stream receive window using flow-controlled writes until
                // `poll_capacity` returns `Pending`.
                s2s.send_regular(&proto_read_batch_records(&[0], Some(1)), false, false);
                reader_parked.notified().await;
                use prost::Message as _;
                use s2_api::v1::stream::proto::{
                    ReadBatch as ProtoReadBatch, SequencedRecord as ProtoSequencedRecord,
                    StreamPosition as ProtoStreamPosition,
                };
                let batch = ProtoReadBatch {
                    records: vec![ProtoSequencedRecord {
                        seq_num: 1,
                        timestamp: 1000,
                        headers: Vec::new(),
                        body: bytes::Bytes::from(vec![b'x'; 16 * 1024]),
                    }],
                    tail: Some(ProtoStreamPosition {
                        seq_num: 2,
                        timestamp: 1000,
                    }),
                }
                .encode_to_vec();
                let frame = encode_s2s_regular_frame(&batch, false);
                let pushed = s2s.saturate_stream_window(&frame).await;
                assert!(
                    pushed >= 60 * 1024,
                    "expected server to saturate parked reader's 64 KiB stream window, only pushed {pushed} bytes"
                );
                window_exhausted.notify_one();
                std::future::pending::<()>().await;
            }
        }
    })
    .await;

    let stream = server.stream_with(|cfg| {
        cfg.with_retry(no_retry_config())
            .with_request_timeout(Duration::from_secs(2))
            .with_http2(
                s2_sdk::types::Http2Config::new()
                    .with_max_concurrent_requests(2)
                    .with_stream_receive_window(64 * 1024)
                    .with_connection_receive_window(128 * 1024),
            )
    });

    let mut parked_reader = stream
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();
    assert_eq!(parked_reader.next().await.unwrap().unwrap().seq_num, 0);
    reader_parked.notify_one();
    tokio::time::timeout(Duration::from_secs(2), window_exhausted.notified())
        .await
        .expect("server must observe stream receive window exhaustion");

    // Sibling unary check_tail sharing the same connection must complete promptly without
    // stalling behind the parked reader's saturated 64 KiB stream window (`C13d`).
    let tail = tokio::time::timeout(Duration::from_secs(2), stream.check_tail())
        .await
        .expect("C13d: sibling check_tail must not stall behind parked reader")
        .unwrap();
    assert_eq!(tail.seq_num, 42);
    assert_eq!(
        server.connection_count(),
        1,
        "explicit C13d-valid 2-stream window must share one connection without stalling"
    );
    drop(parked_reader);
}

// spec: r1 T7b, R6b, E7, R9d
#[tokio::test]
async fn spec_t7b_parked_opening_request_timeout_and_e7_abort_attempt_count() {
    // 1. T7b: late 200 headers arriving AFTER request_timeout while the session is parked must fail
    //    with TimeoutError on resume (not be accepted as success).
    let req_seen = Arc::new(tokio::sync::Notify::new());
    let send_late_headers = Arc::new(tokio::sync::Notify::new());
    let late_server = MockH2Server::start({
        let req_seen = req_seen.clone();
        let send_late_headers = send_late_headers.clone();
        move |_conn_id, _req, respond| {
            let req_seen = req_seen.clone();
            let send_late_headers = send_late_headers.clone();
            async move {
                req_seen.notify_one();
                send_late_headers.notified().await;
                if let Some(mut s2s) = S2sResponder::open(respond) {
                    s2s.send_regular(&proto_read_batch_records(&[0], Some(1)), false, false);
                    std::future::pending::<()>().await;
                }
            }
        }
    })
    .await;

    let mut late_sess = late_server
        .stream_with(|cfg| {
            cfg.with_retry(no_retry_config())
                .with_request_timeout(Duration::from_millis(200))
        })
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();
    {
        let mut pull = Box::pin(late_sess.next());
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                res = &mut pull => panic!("unexpected result before headers: {res:?}"),
                _ = req_seen.notified() => {}
            }
        })
        .await
        .expect("server must receive initial read request");
        drop(pull);
    }
    // Park past the 200ms request_timeout, let server try sending 200 late, then resume.
    tokio::time::sleep(Duration::from_millis(350)).await;
    send_late_headers.notify_one();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let err = late_sess
        .next()
        .await
        .expect("must fail with TimeoutError")
        .unwrap_err();
    assert!(
        matches!(err, ReadSessionError::Timeout(_)),
        "T7b: late headers after request_timeout while parked must time out, got {err:?}"
    );

    // 2. T7b + R6b: on-time 200 headers arriving BEFORE request_timeout while parked must still be
    //    consumable when resuming past request_timeout, without decoding batches while parked.
    let on_time_seen = Arc::new(tokio::sync::Notify::new());
    let send_on_time = Arc::new(tokio::sync::Notify::new());
    let on_time_server = MockH2Server::start({
        let on_time_seen = on_time_seen.clone();
        let send_on_time = send_on_time.clone();
        move |_conn_id, _req, respond| {
            let on_time_seen = on_time_seen.clone();
            let send_on_time = send_on_time.clone();
            async move {
                on_time_seen.notify_one();
                send_on_time.notified().await;
                if let Some(mut s2s) = S2sResponder::open(respond) {
                    s2s.send_regular(&proto_read_batch_records(&[0], Some(1)), false, false);
                    std::future::pending::<()>().await;
                }
            }
        }
    })
    .await;

    let mut on_time_sess = on_time_server
        .stream_with(|cfg| {
            cfg.with_retry(no_retry_config())
                .with_request_timeout(Duration::from_millis(500))
        })
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();
    {
        let mut pull = Box::pin(on_time_sess.next());
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                res = &mut pull => panic!("unexpected result before headers: {res:?}"),
                _ = on_time_seen.notified() => {}
            }
        })
        .await
        .expect("server must receive request");
        drop(pull);
    }
    // Send 200 + record 0 well within 500ms, then stay parked past 500ms before resuming.
    send_on_time.notify_one();
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert_eq!(
        on_time_sess.last_observed_tail(),
        None,
        "R6b: on-time opening response must not decode body batches while parked"
    );
    let rec0 = on_time_sess
        .next()
        .await
        .expect("on-time response must still be consumable after parking")
        .unwrap();
    assert_eq!(rec0.seq_num, 0);

    // 3. E7 + R9d: aborting during retry attempt 2 reports "after 2 attempts" on both a parked
    //    caught_up() waiter and subsequent session.next().
    let retry_attempt = Arc::new(AtomicUsize::new(0));
    let attempt2_seen = Arc::new(tokio::sync::Notify::new());
    let retry_abort_server = MockH2Server::start({
        let retry_attempt = retry_attempt.clone();
        let attempt2_seen = attempt2_seen.clone();
        move |_conn_id, _req, respond| {
            let retry_attempt = retry_attempt.clone();
            let attempt2_seen = attempt2_seen.clone();
            async move {
                let n = retry_attempt.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    send_json(respond, 503, r#"{"code":"unavailable","message":"retry"}"#);
                } else {
                    attempt2_seen.notify_one();
                    std::future::pending::<()>().await;
                }
            }
        }
    })
    .await;

    let abort_client = retry_abort_server.client(fast_retry_config(3));
    let (basin, stream) = test_basin_and_stream();
    let mut abort_sess = abort_client
        .basin(basin)
        .stream(stream)
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();
    let cu = abort_sess.caught_up();
    {
        let mut pull = Box::pin(abort_sess.next());
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                res = &mut pull => panic!("unexpected result before attempt 2: {res:?}"),
                _ = attempt2_seen.notified() => {}
            }
        })
        .await
        .expect("retry attempt 2 must reach server");
        drop(pull);
    }
    // Park session on attempt 2, close client -> parked caught_up() commits AbortedError with
    // attempt count 2 (`E7`).
    abort_client.close();
    let cu_err = tokio::time::timeout(Duration::from_secs(2), cu)
        .await
        .expect("caught_up must wake on close")
        .unwrap_err();
    assert!(
        matches!(cu_err, ReadSessionError::Aborted(_)),
        "expected AbortedError, got {cu_err:?}"
    );
    assert!(
        cu_err.to_string().contains("after 2 attempts"),
        "E7: abort during attempt 2 must report attempt count on caught_up, got: {cu_err}"
    );
    let next_err = abort_sess.next().await.unwrap().unwrap_err();
    assert!(
        next_err.to_string().contains("after 2 attempts"),
        "E7: abort during attempt 2 must report attempt count on next(), got: {next_err}"
    );
    assert!(abort_sess.next().await.is_none());
}

// spec: r1 R6b, T8
#[tokio::test]
async fn spec_r6b_t8_partial_frame_survives_canceled_wait() {
    let frame0 = encode_s2s_regular_frame(&proto_read_batch_records(&[0], Some(1)), false);
    let frame1 = encode_s2s_regular_frame(&proto_read_batch_records(&[1], Some(2)), false);
    let frame2 = encode_s2s_regular_frame(&proto_read_batch_records(&[2], Some(3)), false);
    let mid1 = frame1.len() / 2;
    let mid2 = frame2.len() / 2;

    let send_rest_1 = Arc::new(tokio::sync::Notify::new());
    let send_rest_2 = Arc::new(tokio::sync::Notify::new());

    let server = MockH2Server::start({
        let send_rest_1 = send_rest_1.clone();
        let send_rest_2 = send_rest_2.clone();
        move |_conn_id, _req, respond| {
            let frame0 = frame0.clone();
            let frame1 = frame1.clone();
            let frame2 = frame2.clone();
            let send_rest_1 = send_rest_1.clone();
            let send_rest_2 = send_rest_2.clone();
            async move {
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                // Send frame0 plus the first half of frame1 in one HTTP/2 DATA chunk so decoding
                // frame0 deterministically leaves frame1's partial bytes in the decoder buffer
                // before the caller cancels the next wait.
                let mut chunk1 = Vec::with_capacity(frame0.len() + mid1);
                chunk1.extend_from_slice(&frame0);
                chunk1.extend_from_slice(&frame1[..mid1]);
                s2s.send_raw(bytes::Bytes::from(chunk1), false);

                // Likewise, send the remainder of frame1 together with the first half of frame2
                // so decoding frame1 leaves frame2's partial bytes buffered across a second
                // canceled wait.
                send_rest_1.notified().await;
                let mut chunk2 = Vec::with_capacity((frame1.len() - mid1) + mid2);
                chunk2.extend_from_slice(&frame1[mid1..]);
                chunk2.extend_from_slice(&frame2[..mid2]);
                s2s.send_raw(bytes::Bytes::from(chunk2), false);

                send_rest_2.notified().await;
                s2s.send_raw(frame2.slice(mid2..), false);
                std::future::pending::<()>().await;
            }
        }
    })
    .await;

    let mut session = server
        .stream(no_retry_config())
        .read_session(
            ReadInput::new(ReadStart::SeqNum(0)),
            ReadSessionConfig::default(),
        )
        .unwrap();

    let rec0 = session.next().await.unwrap().unwrap();
    assert_eq!(rec0.seq_num, 0);
    assert_eq!(rec0.body.as_ref(), b"rec-0");

    // Cancel a pending wait (`T8`) while the first half of frame1 is buffered in the decoder.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), session.next())
            .await
            .is_err()
    );
    send_rest_1.notify_one();
    let rec1 = tokio::time::timeout(Duration::from_secs(2), session.next())
        .await
        .expect("second half of frame1 must complete record 1")
        .unwrap()
        .unwrap();
    assert_eq!(rec1.seq_num, 1);
    assert_eq!(rec1.body.as_ref(), b"rec-1");

    // Cancel a second pending wait while the first half of frame2 is buffered, then complete it.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), session.next())
            .await
            .is_err()
    );
    send_rest_2.notify_one();
    let rec2 = tokio::time::timeout(Duration::from_secs(2), session.next())
        .await
        .expect("second half of frame2 must complete record 2")
        .unwrap()
        .unwrap();
    assert_eq!(rec2.seq_num, 2);
    assert_eq!(rec2.body.as_ref(), b"rec-2");
    assert_eq!(server.request_count(), 1);
}
