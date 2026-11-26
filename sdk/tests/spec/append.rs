use std::{
    error::Error as StdError,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use s2_sdk::{
    append_session::{AppendSession, AppendSessionConfig},
    error::{AppendError, AppendSessionError},
    producer::ProducerConfig,
    types::{
        AppendAck, AppendInput, AppendRecord, AppendRecordBatch, AppendRetryPolicy, RetryConfig,
    },
};

use crate::support::*;

async fn gated_ack_s2s_server(
    gate: Arc<tokio::sync::Notify>,
    on_frame: Option<Arc<tokio::sync::Notify>>,
) -> MockH2Server {
    MockH2Server::start(move |_conn_id, req, respond| {
        let gate = gate.clone();
        let on_frame = on_frame.clone();
        async move {
            let Some(mut s2s) = S2sResponder::open(respond) else {
                return;
            };
            let mut body = req.into_body();
            let mut buf = BytesMut::new();
            let mut seq = 0u64;
            while read_one_s2s_frame(&mut body, &mut buf, true)
                .await
                .is_some()
            {
                if let Some(ref notify) = on_frame {
                    notify.notify_one();
                }
                gate.notified().await;
                s2s.send_ack(seq, seq + 1, false, false);
                seq += 1;
            }
            s2s.send_eof();
        }
    })
    .await
}

async fn auto_ack_s2s_server() -> MockH2Server {
    MockH2Server::start(|_conn_id, req, respond| async move {
        let Some(mut s2s) = S2sResponder::open(respond) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let mut seq = 0u64;
        while read_one_s2s_frame(&mut body, &mut buf, true)
            .await
            .is_some()
        {
            s2s.send_ack(seq, seq + 1, false, false);
            seq += 1;
        }
        s2s.send_eof();
    })
    .await
}

async fn submit_and_ack(session: &AppendSession, input: AppendInput) -> AppendAck {
    session
        .submit(input)
        .await
        .expect("submit accepted")
        .await
        .expect("ack succeeded")
}

// spec: r1 A2, A2a, A2b, A2c, A2d, A5
#[tokio::test]
async fn spec_a2_validation_before_capacity_and_split_reserve_submit() {
    // Server holds the first batch unacked until released so capacity is full.
    let release = Arc::new(tokio::sync::Notify::new());
    let server = gated_ack_s2s_server(release.clone(), None).await;
    let stream = server.stream(no_retry_config());

    // 1. AppendSession: reserve() validates before waiting for capacity; permit.submit() rejects
    //    batches larger than reserved_bytes, releases reservation, and leaves session open.
    let session = stream
        .append_session(AppendSessionConfig::new().with_max_unacked_batches(1))
        .unwrap();

    // Invalid reserve sizes fail immediately with ValidationError.
    let err = session.reserve(0).await.expect_err("0 bytes invalid");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    assert!(err.has_no_side_effects());
    let err = session.reserve(7).await.expect_err("7 bytes invalid");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    let err = session
        .reserve(1024 * 1024 + 1)
        .await
        .expect_err("> 1 MiB invalid");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");

    // Split reserve + submit with batch larger than reservation fails with ValidationError,
    // releases reservation, and leaves session open!
    let permit = session.reserve(10).await.unwrap();
    let too_big = sized_append_input(100); // 108 metered bytes > 10 reserved
    let err = permit
        .submit(too_big)
        .expect_err("batch > reservation must fail Validation");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");

    // Reservation was released (max_unacked_batches == 1): another submit succeeds immediately!
    let t1 = session.submit(sample_append_input()).await.unwrap();
    // Capacity is now full (1/1). Invalid reserve() STILL fails immediately without blocking!
    let err = tokio::time::timeout(Duration::from_millis(200), session.reserve(1024 * 1024 + 1))
        .await
        .expect("validation must not wait for capacity")
        .unwrap_err();
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");

    release.notify_one();
    assert_eq!(t1.await.unwrap().end.seq_num, 1);
    session.close().await.unwrap();

    // 2. Producer: record > max_batch_bytes fails immediately before waiting, accepts nothing, and
    //    leaves producer open.
    let producer = stream
        .producer(
            ProducerConfig::new()
                .with_max_batch_bytes(64)
                .with_linger(Duration::from_secs(60)),
        )
        .unwrap();

    let oversized = AppendRecord::new(vec![b'a'; 100]).unwrap();
    let err = producer
        .submit(oversized)
        .await
        .expect_err("record > max_batch_bytes must fail");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    assert!(err.has_no_side_effects());

    // Split reserve + oversized submit releases reservation and leaves producer open.
    let r_permit = producer.reserve(16).await.unwrap();
    let err = r_permit
        .submit(AppendRecord::new(vec![b'b'; 20]).unwrap())
        .expect_err("record > reservation must fail");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");

    // Producer is still open and works normally.
    let t = producer
        .submit(AppendRecord::new("ok").unwrap())
        .await
        .unwrap();
    let close_fut = producer.close();
    release.notify_one();
    close_fut.await.unwrap();
    assert_eq!(t.await.unwrap().seq_num, 0);
    // 3. Invalid session/producer configs fail at open time with E7-contextualized ValidationError.
    let err = stream
        .append_session(AppendSessionConfig::new().with_max_unacked_batches(0))
        .expect_err("0 max_unacked_batches must fail");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    assert!(err.has_no_side_effects());
    assert!(!err.is_retryable());
    assert!(err.to_string().contains("append_session"), "{err}");
    assert!(err.to_string().contains("test-basin"), "{err}");
    assert!(err.to_string().contains("test-stream"), "{err}");

    let err = stream
        .producer(ProducerConfig::new().with_max_batch_records(0))
        .expect_err("0 max_batch_records must fail");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    assert!(err.has_no_side_effects());
    assert!(!err.is_retryable());
    assert!(err.to_string().contains("producer"), "{err}");
    assert!(err.to_string().contains("test-basin"), "{err}");
    assert!(err.to_string().contains("test-stream"), "{err}");
}

// spec: r1 A3, A3a, A3b, T9
#[tokio::test]
async fn spec_a3_t9_lazy_open_and_idle_disconnect_uses_no_budget() {
    let seen_attempts = Arc::new(Mutex::new(Vec::<String>::new()));
    let trigger_idle_reset = Arc::new(tokio::sync::Notify::new());
    let idle_reset_sent = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let seen_attempts = seen_attempts.clone();
        let trigger_idle_reset = trigger_idle_reset.clone();
        let idle_reset_sent = idle_reset_sent.clone();
        move |_conn_id, req, respond| {
            let seen_attempts = seen_attempts.clone();
            let trigger_idle_reset = trigger_idle_reset.clone();
            let idle_reset_sent = idle_reset_sent.clone();
            async move {
                let hdr = header_str(&req, "s2-attempt").unwrap_or("").to_owned();
                let idx = {
                    let mut g = seen_attempts.lock().unwrap();
                    g.push(hdr);
                    g.len()
                };
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                match idx {
                    1 => {
                        // Ack batch 0, then immediately close cleanly while idle (T9).
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                        s2s.send_ack(0, 1, false, true);
                    }
                    2 => {
                        // Ack batch 1, wait until caller observes idle state, then reset stream.
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                        s2s.send_ack(1, 2, false, false);
                        trigger_idle_reset.notified().await;
                        s2s.reset(h2::Reason::INTERNAL_ERROR);
                        idle_reset_sent.notify_one();
                    }
                    _ => {
                        // Ack batch 2 and wait for close.
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                        s2s.send_ack(2, 3, false, false);
                        let _ = drain_body(&mut body).await;
                        s2s.send_eof();
                    }
                }
            }
        }
    })
    .await;

    // max_attempts = 1: ANY budget consumption would immediately fail the session!
    let stream = server.stream(no_retry_config());

    // 1. Opening and closing idle AppendSession and Producer sends ZERO HTTP requests (A3).
    let idle_sess = stream.append_session(AppendSessionConfig::new()).unwrap();
    let idle_prod = stream.producer(ProducerConfig::new()).unwrap();
    tokio::task::yield_now().await;
    assert_eq!(
        server.request_count(),
        0,
        "A3: opening must send no request"
    );
    idle_sess.close().await.unwrap();
    idle_prod.close().await.unwrap();
    assert_eq!(
        server.request_count(),
        0,
        "A3: closing idle sessions must send no request"
    );

    // 2. Idle clean end and idle stream break cost zero budget and do not open a new request until
    //    the next batch arrives (A3, T9).
    let session = stream.append_session(AppendSessionConfig::new()).unwrap();
    assert_eq!(server.request_count(), 0);

    assert_eq!(
        submit_and_ack(&session, sample_append_input())
            .await
            .end
            .seq_num,
        1
    );
    // Allow the session task to process the clean EOF while idle; must NOT open request #2 yet.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        server.request_count(),
        1,
        "A3: idle clean end must not eagerly open a new request"
    );

    assert_eq!(
        submit_and_ack(&session, sample_append_input())
            .await
            .end
            .seq_num,
        2
    );
    // Trigger RST_STREAM while idle, allow loopback delivery to the client task, and confirm it
    // does not fail or eagerly reconnect.
    let reset_done = idle_reset_sent.notified();
    trigger_idle_reset.notify_one();
    reset_done.await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        server.request_count(),
        2,
        "A3/T9: idle break must not eagerly open a new request"
    );

    assert_eq!(
        submit_and_ack(&session, sample_append_input())
            .await
            .end
            .seq_num,
        3
    );
    session.close().await.unwrap();

    assert_eq!(
        *seen_attempts.lock().unwrap(),
        vec!["1", "1", "1"],
        "T9/T4: idle ends consume zero retry budget"
    );
}

// spec: r1 A4, A4a, A4b, A4c, T8
#[tokio::test]
async fn spec_a4_fifo_capacity_cancel_and_closing_wakes_waiters() {
    let ack_gate = Arc::new(tokio::sync::Notify::new());
    let server = gated_ack_s2s_server(ack_gate.clone(), None).await;
    let stream = server.stream(no_retry_config());

    // 1. FIFO capacity: max_unacked_bytes = 1 MiB. Batch 1 takes 700 KiB -> 324 KiB remaining.
    //    Waiter A requests 500 KiB (must wait). Waiter B requests 200 KiB (fits in 324 KiB, but
    //    MUST queue behind Waiter A!).
    let session = Arc::new(
        stream
            .append_session(AppendSessionConfig::new().with_max_unacked_bytes(1024 * 1024))
            .unwrap(),
    );

    let b1 = session
        .submit(sized_append_input(700 * 1024))
        .await
        .unwrap();

    // Poll Waiter A and Waiter B into the FIFO waiter queue deterministically before releasing B1.
    let mut waiter_a = Box::pin(session.reserve(500 * 1024));
    assert!(futures_util::poll!(waiter_a.as_mut()).is_pending());
    let mut waiter_b = Box::pin(session.reserve(200 * 1024));
    assert!(
        futures_util::poll!(waiter_b.as_mut()).is_pending(),
        "A4a: Waiter B must not overtake Waiter A even when 200 KiB fits"
    );

    // Cancel a third waiter before capacity frees (A4c, T8): accepts nothing, session unaffected.
    {
        let mut canceled = Box::pin(session.reserve(100 * 1024));
        assert!(futures_util::poll!(canceled.as_mut()).is_pending());
        drop(canceled);
    }

    // Ack Batch 1 -> Waiter A gets capacity first, then Waiter B!
    ack_gate.notify_one();
    assert_eq!(b1.await.unwrap().end.seq_num, 1);
    let permit_a = waiter_a.await.unwrap();
    let permit_b = waiter_b.await.unwrap();
    drop(permit_a);
    drop(permit_b);

    // 2. Waiting submit() fails immediately with SessionClosedError when close() begins (A4c), even
    //    while Batch 2 is still unacked!
    let b2 = session
        .submit(sized_append_input(700 * 1024))
        .await
        .unwrap();
    let mut blocked_submit = Box::pin(session.submit(sized_append_input(500 * 1024)));
    assert!(futures_util::poll!(blocked_submit.as_mut()).is_pending());

    let close_task = tokio::spawn({
        let session = session.clone();
        async move { session.close().await }
    });

    let err = tokio::time::timeout(Duration::from_secs(1), blocked_submit)
        .await
        .expect("A4c: waiting submit must wake immediately when close() begins")
        .expect_err("must fail with SessionClosed");
    assert!(
        matches!(err, AppendSessionError::SessionClosed(ref c) if c.failure().is_none()),
        "{err:?}"
    );
    assert!(err.has_no_side_effects());

    // Now let Batch 2 finish so close() completes cleanly.
    ack_gate.notify_one();
    assert_eq!(b2.await.unwrap().end.seq_num, 2);
    close_task.await.unwrap().unwrap();

    // 3. Producer rejects reserve()/submit() immediately once its owned AppendSession fails, even
    //    while permit capacity is still available (A4c/A9).
    let fail_server = MockH2Server::start(|_conn_id, req, respond| async move {
        let Some(mut s2s) = S2sResponder::open(respond) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        s2s.send_terminal(412, br#"{"seq_num_mismatch":99}"#);
    })
    .await;
    let producer = fail_server
        .stream(no_retry_config())
        .producer(ProducerConfig::new().with_max_batch_records(1))
        .unwrap();
    let t = producer
        .submit(AppendRecord::new("boom").unwrap())
        .await
        .unwrap();
    assert!(matches!(
        t.await.unwrap_err(),
        AppendSessionError::SeqNumMismatch(_)
    ));
    let reserve_err = producer.reserve(16).await.err().unwrap();
    assert!(
        matches!(
            reserve_err,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::SeqNumMismatch(_)))
        ),
        "A4c/A9: producer.reserve must reject immediately once owned session fails: {reserve_err:?}"
    );
    let submit_err = producer
        .submit(AppendRecord::new("after-fail").unwrap())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            submit_err,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::SeqNumMismatch(_)))
        ),
        "A4c/A9: producer.submit must reject immediately once owned session fails: {submit_err:?}"
    );
}

// spec: r1 A5
#[tokio::test]
async fn spec_a5_producer_match_seq_overflow() {
    // Producer match_seq_num overflow rejects submit() with ValidationError without accepting
    // and leaves the producer open to flush/close earlier accepted records (A5). Per A5, end =
    // match_seq_num + record_count <= u64::MAX:
    //   - match_seq_num = u64::MAX rejects even the first record;
    //   - match_seq_num = u64::MAX - 1 accepts 1 record (end = u64::MAX) and rejects the 2nd.
    let wire_match_seq = Arc::new(Mutex::new(None::<u64>));
    let wire_match_seq_srv = wire_match_seq.clone();
    let server = MockH2Server::start(move |_conn_id, req, respond| {
        let wire_match_seq_srv = wire_match_seq_srv.clone();
        async move {
            let Some(mut s2s) = S2sResponder::open(respond) else {
                return;
            };
            let mut body = req.into_body();
            let mut buf = BytesMut::new();
            if let Some(decoded) = read_append_input(&mut body, &mut buf).await {
                *wire_match_seq_srv.lock().unwrap() = decoded.match_seq_num;
                s2s.send_ack(u64::MAX - 1, u64::MAX, false, false);
            }
            let _ = drain_body(&mut body).await;
            s2s.send_eof();
        }
    })
    .await;

    let stream = server.stream(no_retry_config());

    // match_seq_num = u64::MAX cannot fit even a single record (end would overflow u64).
    let at_max = stream
        .producer(
            ProducerConfig::new()
                .with_match_seq_num(u64::MAX)
                .with_linger(Duration::from_secs(60)),
        )
        .unwrap();
    let err = at_max
        .submit(AppendRecord::new("too-far").unwrap())
        .await
        .expect_err("match_seq_num = u64::MAX must reject 1st record with ValidationError");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    assert!(err.has_no_side_effects());
    at_max.close().await.unwrap();

    // match_seq_num = u64::MAX - 1 accepts 1 record (end = u64::MAX) and rejects the 2nd.
    let producer = stream
        .producer(
            ProducerConfig::new()
                .with_match_seq_num(u64::MAX - 1)
                .with_linger(Duration::from_secs(60)),
        )
        .unwrap();

    let t_max = producer
        .submit(AppendRecord::new("last").unwrap())
        .await
        .unwrap();
    let err = producer
        .submit(AppendRecord::new("overflow").unwrap())
        .await
        .expect_err("overflowing match_seq_num must fail with ValidationError");
    assert!(matches!(err, AppendSessionError::Validation(_)), "{err:?}");
    assert!(err.has_no_side_effects());

    // Producer is still open and closes cleanly delivering the first record with exact wire seq!
    producer.close().await.unwrap();
    let ack = t_max.await.unwrap();
    assert_eq!(ack.seq_num, u64::MAX - 1);
    assert_eq!(*wire_match_seq.lock().unwrap(), Some(u64::MAX - 1));
}

// spec: r1 A5a
#[tokio::test]
async fn spec_a5a_producer_flush_partial_batch_on_backpressure() {
    // 1. Lost-wakeup / multi-task reserve() race: Task X acquires a 600 KiB permit first (nothing
    //    in batcher yet), then Task Y blocks in reserve(600 KiB) on a 1 MiB capacity budget while
    //    linger is 1 hour. When Task X submits its record into the partial batch, no other batch is
    //    in flight and Task Y is already waiting, so A5a MUST flush the partial batch immediately
    //    instead of deadlocking!
    let race_server = auto_ack_s2s_server().await;

    let prod_race = race_server
        .stream(no_retry_config())
        .producer(
            ProducerConfig::new()
                .with_max_unacked_bytes(1024 * 1024)
                .with_max_batch_bytes(1024 * 1024)
                .with_linger(Duration::MAX),
        )
        .unwrap();

    let rec_600k = AppendRecord::new(vec![b'x'; 600 * 1024]).unwrap();
    let size_600k = rec_600k.metered_bytes();
    let permit_x = prod_race.reserve(size_600k).await.unwrap();
    let mut reserve_y = Box::pin(prod_race.reserve(size_600k));
    assert!(futures_util::poll!(reserve_y.as_mut()).is_pending());

    let ticket_x = permit_x.submit(rec_600k.clone()).unwrap();
    let permit_y = tokio::time::timeout(Duration::from_secs(2), reserve_y)
        .await
        .expect("A5a: partial batch must flush immediately when another caller is waiting")
        .unwrap();
    assert_eq!(ticket_x.await.unwrap().seq_num, 0);
    let ticket_y = permit_y.submit(rec_600k).unwrap();
    prod_race.close().await.unwrap();
    assert_eq!(ticket_y.await.unwrap().seq_num, 1);

    // 2. Narrowed A5a (steady backpressure): When Batch 1 (300 KiB) IS in flight (unacked),
    //    buffering Record 2 (600 KiB) while Task Y blocks in reserve(500 KiB) MUST NOT cut the
    //    partial batch prematurely (Batch 1's ack will free capacity). Once Batch 1 acks, 424 KiB
    //    is still < 500 KiB and now no other batch is unacked — A5a cuts Batch 2 immediately
    //    without waiting for the 1-hour linger!
    let batch_received = Arc::new(AtomicUsize::new(0));
    let batch1_seen = Arc::new(tokio::sync::Notify::new());
    let allow_batch1_ack = Arc::new(tokio::sync::Notify::new());
    let batch2_seen = Arc::new(tokio::sync::Notify::new());
    let steady_server = MockH2Server::start({
        let batch_received = batch_received.clone();
        let batch1_seen = batch1_seen.clone();
        let allow_batch1_ack = allow_batch1_ack.clone();
        let batch2_seen = batch2_seen.clone();
        move |_conn_id, req, respond| {
            let batch_received = batch_received.clone();
            let batch1_seen = batch1_seen.clone();
            let allow_batch1_ack = allow_batch1_ack.clone();
            let batch2_seen = batch2_seen.clone();
            async move {
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                let mut seq = 0u64;
                while read_one_s2s_frame(&mut body, &mut buf, true)
                    .await
                    .is_some()
                {
                    let n = batch_received.fetch_add(1, Ordering::SeqCst) + 1;
                    if n == 1 {
                        batch1_seen.notify_one();
                        allow_batch1_ack.notified().await;
                    } else if n == 2 {
                        batch2_seen.notify_one();
                    }
                    s2s.send_ack(seq, seq + 1, false, false);
                    seq += 1;
                }
                s2s.send_eof();
            }
        }
    })
    .await;

    let prod_steady = Arc::new(
        steady_server
            .stream(no_retry_config())
            .producer(
                ProducerConfig::new()
                    .with_max_unacked_bytes(1024 * 1024)
                    .with_max_batch_bytes(1024 * 1024)
                    .with_linger(Duration::from_secs(3600)),
            )
            .unwrap(),
    );

    // Flush Batch 1 (300 KiB) so it is in flight and unacked.
    let t1 = prod_steady
        .submit(AppendRecord::new(vec![b'a'; 300 * 1024]).unwrap())
        .await
        .unwrap();
    let flush1 = tokio::spawn({
        let prod_steady = prod_steady.clone();
        async move { prod_steady.flush().await }
    });
    tokio::time::timeout(Duration::from_secs(2), batch1_seen.notified())
        .await
        .expect("Batch 1 must reach server");

    // Buffer Record 2 (600 KiB) in the partial batch and block Task Y on reserve(500 KiB).
    let t2 = prod_steady
        .submit(AppendRecord::new(vec![b'b'; 600 * 1024]).unwrap())
        .await
        .unwrap();
    let mut reserve_y = Box::pin(prod_steady.reserve(500 * 1024));
    assert!(futures_util::poll!(reserve_y.as_mut()).is_pending());

    // Give the producer task a chance to react: Batch 2 MUST NOT be cut while Batch 1 is in flight!
    assert!(
        tokio::time::timeout(Duration::from_millis(80), batch2_seen.notified())
            .await
            .is_err(),
        "A5a: must not cut partial batch while another batch is still in flight"
    );
    assert_eq!(batch_received.load(Ordering::SeqCst), 1);

    // Ack Batch 1 -> now no other batch is unacked while partial Batch 2 alone blocks reserve_y!
    allow_batch1_ack.notify_one();
    flush1.await.unwrap().unwrap();
    assert_eq!(t1.await.unwrap().seq_num, 0);

    tokio::time::timeout(Duration::from_secs(2), batch2_seen.notified())
        .await
        .expect("A5a: partial batch must flush immediately once no other batch is unacked");
    let permit_y = tokio::time::timeout(Duration::from_secs(2), reserve_y)
        .await
        .expect("A5a: waiting reserve must unblock after partial batch acks")
        .unwrap();
    assert_eq!(t2.await.unwrap().seq_num, 1);
    drop(permit_y);
    prod_steady.close().await.unwrap();
}

// spec: r1 A6, A6a, A6b, A6c, A6d, A8, A8b, A9, E5c, T10
#[tokio::test]
async fn spec_a6_a9_outcome_table_all_five_scenarios_and_producer_passthrough() {
    // Helper: runs the exact 3-batch scenario (A=40 KiB, B=40 KiB, C=1 KiB) where A and B fill
    // the 65535-byte HTTP/2 initial stream flow-control window so A and B are guaranteed sent while
    // C is guaranteed accepted but NEVER sent!
    #[derive(Clone, Copy)]
    enum Scenario {
        Reject412,
        FailStorage,
        ConnectionLost,
        RetryThen412,
        ClientClose,
    }

    async fn run_scenario(
        scenario: Scenario,
    ) -> (
        AppendSessionError,
        AppendSessionError,
        AppendSessionError,
        AppendSessionError,
    ) {
        let ab_sent = Arc::new(tokio::sync::Notify::new());
        let attempt_num = Arc::new(AtomicUsize::new(0));
        let is_retry = matches!(scenario, Scenario::RetryThen412);
        let is_close = matches!(scenario, Scenario::ClientClose);

        let server = MockH2Server::start({
            let ab_sent = ab_sent.clone();
            let attempt_num = attempt_num.clone();
            move |_conn_id, req, respond| {
                let ab_sent = ab_sent.clone();
                let attempt_num = attempt_num.clone();
                async move {
                    let n = attempt_num.fetch_add(1, Ordering::SeqCst);
                    let Some(mut s2s) = S2sResponder::open(respond) else {
                        return;
                    };
                    let mut body = req.into_body();
                    // Read > 42 KiB WITHOUT releasing flow-control capacity so A (40 KiB) and at
                    // least the first chunk of B (40 KiB) are guaranteed sent while the 65535-byte
                    // H2 window blocks C from ever leaving the SDK!
                    let _ = read_exact_h2_bytes(&mut body, 50 * 1024).await;
                    match scenario {
                        Scenario::Reject412 => {
                            s2s.send_terminal(412, br#"{"seq_num_mismatch":99}"#);
                        }
                        Scenario::FailStorage => {
                            s2s.send_terminal(500, br#"{"code":"storage","message":"disk err"}"#);
                        }
                        Scenario::ConnectionLost => {
                            s2s.send_eof();
                        }
                        Scenario::RetryThen412 => {
                            if n == 0 {
                                // Attempt 1: connection lost (indefinite) -> sets prior_uncertainty
                                // on A and B (not C!).
                                s2s.send_eof();
                            } else {
                                // Attempt 2: server rejects A with definite 412.
                                s2s.send_terminal(412, br#"{"seq_num_mismatch":99}"#);
                            }
                        }
                        Scenario::ClientClose => {
                            ab_sent.notify_one();
                            std::future::pending::<()>().await;
                        }
                    }
                }
            }
        })
        .await;

        let retry = if is_retry {
            fast_retry_config(2).with_append_retry_policy(AppendRetryPolicy::All)
        } else {
            no_retry_config()
        };
        let (basin_name, stream_name) = test_basin_and_stream();
        let s2 = server.client(retry);
        let session = s2
            .basin(basin_name)
            .stream(stream_name)
            .append_session(AppendSessionConfig::new())
            .unwrap();

        let ta = session.submit(sized_append_input(40 * 1024)).await.unwrap();
        let tb = session.submit(sized_append_input(40 * 1024)).await.unwrap();
        let tc = session.submit(sized_append_input(1024)).await.unwrap();

        if is_close {
            ab_sent.notified().await;
            s2.close();
        }

        let ea = ta.await.unwrap_err();
        let eb = tb.await.unwrap_err();
        let ec = tc.await.unwrap_err();
        let eclose = session.close().await.unwrap_err();
        (ea, eb, ec, eclose)
    }

    // Row 1: Server rejects A with 412 -> A=412, B=SessionClosed(412), C=SessionClosed(412),
    // close=412
    let (ea, eb, ec, eclose) = run_scenario(Scenario::Reject412).await;
    assert!(
        matches!(ea, AppendSessionError::SeqNumMismatch(_)),
        "{ea:?}"
    );
    assert!(
        matches!(eb, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::SeqNumMismatch(_)))),
        "Row 1 B: {eb:?}"
    );
    assert!(
        matches!(ec, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::SeqNumMismatch(_)))),
        "Row 1 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::SeqNumMismatch(_)),
        "{eclose:?}"
    );

    // Row 2: Server fails A with storage (indefinite) -> A=storage, B=storage,
    // C=SessionClosed(storage), close=storage
    let (ea, eb, ec, eclose) = run_scenario(Scenario::FailStorage).await;
    assert!(
        matches!(ea, AppendSessionError::Server(ref s) if s.code.as_deref() == Some("storage")),
        "{ea:?}"
    );
    assert!(
        matches!(eb, AppendSessionError::Server(ref s) if s.code.as_deref() == Some("storage")),
        "{eb:?}"
    );
    assert!(
        matches!(ec, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::Server(s)) if s.code.as_deref() == Some("storage"))),
        "Row 2 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::Server(ref s) if s.code.as_deref() == Some("storage")),
        "{eclose:?}"
    );

    // Row 3: Connection lost -> A=ConnectionLost, B=ConnectionLost,
    // C=SessionClosed(ConnectionLost), close=ConnectionLost
    let (ea, eb, ec, eclose) = run_scenario(Scenario::ConnectionLost).await;
    assert!(
        matches!(ea, AppendSessionError::ConnectionLost(_)),
        "{ea:?}"
    );
    assert!(
        matches!(eb, AppendSessionError::ConnectionLost(_)),
        "{eb:?}"
    );
    assert!(
        matches!(ec, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::ConnectionLost(_)))),
        "Row 3 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::ConnectionLost(_)),
        "{eclose:?}"
    );

    // Row 4: Connection lost and retried; A and B resent; server rejects A with 412 ->
    //   A = Indefinite(412)
    //   B = Indefinite(SessionClosed(Indefinite(412)))
    //   C = SessionClosed(Indefinite(412))
    //   close() = Indefinite(412)
    let (ea, eb, ec, eclose) = run_scenario(Scenario::RetryThen412).await;
    assert!(ea.server_error().is_none(), "E5a: {ea:?}");
    assert!(!ea.has_no_side_effects(), "E5: {ea:?}");
    assert!(
        matches!(
            ea,
            AppendSessionError::IndefiniteAppend(ref w)
                if matches!(w.final_attempt_error(), AppendSessionError::SeqNumMismatch(_))
                    && w.source().and_then(|s| s.downcast_ref::<AppendSessionError>()).is_some()
        ),
        "Row 4 A: {ea:?}"
    );
    assert!(
        matches!(
            eb,
            AppendSessionError::IndefiniteAppend(ref w)
                if matches!(
                    w.final_attempt_error(),
                    AppendSessionError::SessionClosed(c)
                        if matches!(
                            c.failure(),
                            Some(AppendSessionError::IndefiniteAppend(inner))
                                if matches!(inner.final_attempt_error(), AppendSessionError::SeqNumMismatch(_))
                        )
                )
        ),
        "Row 4 B: {eb:?}"
    );
    assert!(
        matches!(
            ec,
            AppendSessionError::SessionClosed(ref c)
                if matches!(
                    c.failure(),
                    Some(AppendSessionError::IndefiniteAppend(inner))
                        if matches!(inner.final_attempt_error(), AppendSessionError::SeqNumMismatch(_))
                )
        ),
        "Row 4 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::IndefiniteAppend(ref w) if matches!(w.final_attempt_error(), AppendSessionError::SeqNumMismatch(_))),
        "Row 4 close: {eclose:?}"
    );
    // E5c: root_cause() unwraps 1-, 2-, and 3-layer wrappers uniformly while E5a keeps
    // outer server_error() hidden.
    for (label, err) in [
        ("Row 4 A", &ea),
        ("Row 4 B", &eb),
        ("Row 4 C", &ec),
        ("Row 4 close", &eclose),
    ] {
        assert!(err.server_error().is_none(), "E5a {label}: {err:?}");
        assert!(
            matches!(err.root_cause(), AppendSessionError::SeqNumMismatch(_)),
            "E5c {label}: {err:?}"
        );
        let s2_err: s2_sdk::S2Error = err.clone().into();
        assert!(s2_err.server_error().is_none(), "E5a S2Error {label}");
        assert!(
            matches!(s2_err.root_cause(), s2_sdk::S2Error::SeqNumMismatch(_)),
            "E5c S2Error {label}"
        );
    }

    // Row 5: Client closed while A and B await acks -> A=Aborted, B=Aborted,
    // C=SessionClosed(Aborted), close=Aborted
    let (ea, eb, ec, eclose) = run_scenario(Scenario::ClientClose).await;
    assert!(matches!(ea, AppendSessionError::Aborted(_)), "{ea:?}");
    assert!(matches!(eb, AppendSessionError::Aborted(_)), "{eb:?}");
    assert!(
        matches!(ec, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))),
        "Row 5 C: {ec:?}"
    );
    assert!(
        matches!(ec.root_cause(), AppendSessionError::Aborted(_)),
        "E5c Row 5 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::Aborted(_)),
        "{eclose:?}"
    );

    // T10 + A6d: Ack received before terminal error takes effect first, and Producer preserves
    // exact AppendSession outcomes without overriding them.
    let t10_server = MockH2Server::start(|_conn_id, req, respond| async move {
        let Some(mut s2s) = S2sResponder::open(respond) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        // Send ack for batch 0 AND 412 rejection for batch 1 in one coalesced write.
        let mut combined = BytesMut::new();
        combined.extend_from_slice(&encode_s2s_regular_frame(&proto_append_ack(0, 1), false));
        combined.extend_from_slice(&encode_s2s_terminal_frame(
            412,
            br#"{"seq_num_mismatch":1}"#,
        ));
        s2s.send_raw(combined.freeze(), true);
    })
    .await;

    let producer = t10_server
        .stream(no_retry_config())
        .producer(
            ProducerConfig::new()
                .with_max_batch_records(1)
                .with_linger(Duration::from_secs(60)),
        )
        .unwrap();
    let r0 = producer
        .submit(AppendRecord::new("r0").unwrap())
        .await
        .unwrap();
    let r1 = producer
        .submit(AppendRecord::new("r1").unwrap())
        .await
        .unwrap();
    assert_eq!(r0.await.unwrap().seq_num, 0);
    assert!(matches!(
        r1.await.unwrap_err(),
        AppendSessionError::SeqNumMismatch(_)
    ));
    assert!(matches!(
        producer.close().await.unwrap_err(),
        AppendSessionError::SeqNumMismatch(_)
    ));
}

// spec: r1 A7, A4c
#[tokio::test]
async fn spec_a7_producer_flush_isolation_and_close_interaction() {
    let batch0_received = Arc::new(tokio::sync::Notify::new());
    let allow_batch0_ack = Arc::new(tokio::sync::Notify::new());
    let batch0_records = Arc::new(AtomicUsize::new(0));
    let server = MockH2Server::start({
        let batch0_received = batch0_received.clone();
        let allow_batch0_ack = allow_batch0_ack.clone();
        let batch0_records = batch0_records.clone();
        move |_conn_id, req, respond| {
            let batch0_received = batch0_received.clone();
            let allow_batch0_ack = allow_batch0_ack.clone();
            let batch0_records = batch0_records.clone();
            async move {
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                // Batch 0 succeeds after gate; Batch 1 fails with 412.
                if let Some(decoded) = read_append_input(&mut body, &mut buf).await {
                    batch0_records.store(decoded.records.len(), Ordering::SeqCst);
                    batch0_received.notify_one();
                    allow_batch0_ack.notified().await;
                    s2s.send_ack(0, decoded.records.len() as u64, false, false);
                }
                if read_one_s2s_frame(&mut body, &mut buf, true)
                    .await
                    .is_some()
                {
                    s2s.send_terminal(412, br#"{"seq_num_mismatch":1}"#);
                }
            }
        }
    })
    .await;

    let stream = server.stream(no_retry_config());

    // 1. Empty flush succeeds immediately without opening a request, and leaves producer reusable;
    //    then with max_batch_records = 10 and long linger, flush() cuts the partial batch
    //    containing t0 so a record accepted after flush() begins is NOT co-batched with t0, and a
    //    failure on that later record + close() does NOT fail flush0!
    let producer = Arc::new(
        stream
            .producer(
                ProducerConfig::new()
                    .with_max_batch_records(10)
                    .with_linger(Duration::from_secs(3600)),
            )
            .unwrap(),
    );
    producer.flush().await.expect("empty flush succeeds");
    assert_eq!(server.request_count(), 0);

    let t0 = producer
        .submit(AppendRecord::new("ok").unwrap())
        .await
        .unwrap();
    let flush0 = tokio::spawn({
        let producer = producer.clone();
        async move { producer.flush().await }
    });
    // Wait until Batch 0 (cut by flush0) reaches the server; then submit t1 and close().
    tokio::time::timeout(Duration::from_secs(2), batch0_received.notified())
        .await
        .expect("A7: flush() must cut and send t0 without waiting for linger");
    assert_eq!(
        batch0_records.load(Ordering::SeqCst),
        1,
        "A7: Batch 0 must contain only t0"
    );
    let t1 = producer
        .submit(AppendRecord::new("fail").unwrap())
        .await
        .unwrap();
    let close_task = tokio::spawn({
        let producer = producer.clone();
        async move { producer.close().await }
    });
    allow_batch0_ack.notify_one();

    // flush0 ONLY covered t0 (which succeeded) -> flush0 MUST return Ok(())!
    flush0
        .await
        .unwrap()
        .expect("A7: later failure and close() must not fail earlier flush()");
    assert_eq!(t0.await.unwrap().seq_num, 0);
    assert!(matches!(
        t1.await.unwrap_err(),
        AppendSessionError::SeqNumMismatch(_)
    ));
    assert!(matches!(
        close_task.await.unwrap().unwrap_err(),
        AppendSessionError::SeqNumMismatch(_)
    ));

    // A later flush() after t1 failed returns the session failure (NEVER SessionClosedError).
    let flush_after_err = producer.flush().await.unwrap_err();
    assert!(
        matches!(flush_after_err, AppendSessionError::SeqNumMismatch(_)),
        "A4c/A7: flush must never return SessionClosedError, got {flush_after_err:?}"
    );

    // 2. flush() after a clean close returns Ok(()) (NEVER SessionClosedError).
    let clean_prod = stream.producer(ProducerConfig::new()).unwrap();
    clean_prod.close().await.unwrap();
    clean_prod
        .flush()
        .await
        .expect("A4c/A7: flush after clean close must return Ok(())");
}

// spec: r1 A8a, A8c, T8
#[tokio::test]
async fn spec_a8_t8_close_idempotent_cancel_wait_and_drop_aborts() {
    let ack_gate = Arc::new(tokio::sync::Notify::new());
    let frame_seen = Arc::new(tokio::sync::Notify::new());
    let server = gated_ack_s2s_server(ack_gate.clone(), Some(frame_seen.clone())).await;
    let stream = server.stream(no_retry_config());

    // 1. Dropping a close(&self) future cancels only the wait (T8); repeated/concurrent close()
    //    calls all return the exact same result (A8a).
    let session = Arc::new(stream.append_session(AppendSessionConfig::new()).unwrap());
    let ticket = session.submit(sample_append_input()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), frame_seen.notified())
        .await
        .expect("first batch must reach server");

    // Start close() and cancel that wait by dropping the future.
    {
        let mut close_fut = Box::pin(session.close());
        assert!(futures_util::poll!(close_fut.as_mut()).is_pending());
        drop(close_fut);
    }

    // Session is now closing (new submit fails immediately with SessionClosed), NOT aborted!
    let closed_err = session.submit(sample_append_input()).await.err().unwrap();
    assert!(matches!(closed_err, AppendSessionError::SessionClosed(_)));

    // Two concurrent close() calls both wait and return Ok(()).
    let c1 = tokio::spawn({
        let session = session.clone();
        async move { session.close().await }
    });
    let c2 = tokio::spawn({
        let session = session.clone();
        async move { session.close().await }
    });
    ack_gate.notify_one();
    assert_eq!(ticket.await.unwrap().end.seq_num, 1);
    c1.await.unwrap().unwrap();
    c2.await.unwrap().unwrap();
    // Subsequent close() also returns the same Ok(()).
    session.close().await.unwrap();

    // 2. Dropping AppendSession without calling close() aborts unacked sent batches with
    //    AbortedError (A8c).
    let drop_sess = stream.append_session(AppendSessionConfig::new()).unwrap();
    let drop_ticket = drop_sess.submit(sample_append_input()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), frame_seen.notified())
        .await
        .expect("batch must be sent on the wire before dropping session");
    drop(drop_sess);
    let err = drop_ticket.await.unwrap_err();
    assert!(matches!(err, AppendSessionError::Aborted(_)), "{err:?}");
    assert!(!err.has_no_side_effects());

    // 3. Dropping Producer with buffered (unsent) records fails all claimable tickets without
    //    flushing them (A8c).
    let drop_prod = stream
        .producer(ProducerConfig::new().with_linger(Duration::from_secs(60)))
        .unwrap();
    let prod_t1 = drop_prod
        .submit(AppendRecord::new("buf-1").unwrap())
        .await
        .unwrap();
    let prod_t2 = drop_prod
        .submit(AppendRecord::new("buf-2").unwrap())
        .await
        .unwrap();
    drop(drop_prod);
    for t in [prod_t1, prod_t2] {
        let err = t.await.unwrap_err();
        assert!(
            matches!(
                err,
                AppendSessionError::SessionClosed(ref c)
                    if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))
            ),
            "A8c: dropped producer must fail unsent tickets with SessionClosed(Some(Aborted)), got {err:?}"
        );
    }
}

// spec: r1 T6a
#[tokio::test]
async fn spec_t6a_append_reconnect_advice_cooldown() {
    // T6a: Reconnect advice triggers handover to a new connection, then a second reconnect
    // advice within 60 s is ignored (stays on the same connection!).
    let seen_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let req_idx = Arc::new(AtomicUsize::new(0));
    let advice_server = MockH2Server::start({
        let seen_conns = seen_conns.clone();
        let req_idx = req_idx.clone();
        move |conn_id, req, respond| {
            let seen_conns = seen_conns.clone();
            let req_idx = req_idx.clone();
            async move {
                let n = req_idx.fetch_add(1, Ordering::SeqCst);
                seen_conns.lock().unwrap().push(conn_id);
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                if n == 0 {
                    // Ack batch 0 with reconnect-advised bit -> client drains and closes body.
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    s2s.send_ack(0, 1, true, false);
                    let _ = drain_body(&mut body).await;
                    s2s.send_eof();
                } else {
                    // Request 2: ack batch 1 WITH reconnect-advised bit (must be ignored within
                    // 60 s cooldown!), then ack batch 2 on the SAME request!
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    s2s.send_ack(1, 2, true, false);
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    s2s.send_ack(2, 3, false, false);
                    let _ = drain_body(&mut body).await;
                    s2s.send_eof();
                }
            }
        }
    })
    .await;

    let session = advice_server
        .stream(no_retry_config())
        .append_session(AppendSessionConfig::new())
        .unwrap();
    for expected_end in 1u64..=3 {
        assert_eq!(
            submit_and_ack(&session, sample_append_input())
                .await
                .end
                .seq_num,
            expected_end
        );
    }
    session.close().await.unwrap();
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

// spec: r1 T7c
#[tokio::test]
async fn spec_t7c_oldest_batch_ack_timeout() {
    // T7c: Only the oldest unacked batch is timed! With request_timeout = 10s (virtual time):
    //   - Batch 0 and Batch 1 are pipelined together at t = 0.
    //   - Advance 6s (< 10s) -> ack Batch 0.
    //   - Advance 6s (12s > 10s since t = 0, but only 6s since Batch 1 became oldest!) -> ack Batch
    //     1 -> BOTH MUST SUCCEED!
    //   - Batch 2 is never acked -> advance 11s -> fails with TimeoutError!
    let both_received = Arc::new(tokio::sync::Notify::new());
    let send_ack0 = Arc::new(tokio::sync::Notify::new());
    let send_ack1 = Arc::new(tokio::sync::Notify::new());
    let b2_received = Arc::new(tokio::sync::Notify::new());
    let timeout_server = MockH2Server::start({
        let both_received = both_received.clone();
        let send_ack0 = send_ack0.clone();
        let send_ack1 = send_ack1.clone();
        let b2_received = b2_received.clone();
        move |_conn_id, req, respond| {
            let both_received = both_received.clone();
            let send_ack0 = send_ack0.clone();
            let send_ack1 = send_ack1.clone();
            let b2_received = b2_received.clone();
            async move {
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                both_received.notify_one();
                send_ack0.notified().await;
                s2s.send_ack(0, 1, false, false);
                send_ack1.notified().await;
                s2s.send_ack(1, 2, false, false);
                // Never ack Batch 2.
                let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                b2_received.notify_one();
                std::future::pending::<()>().await;
            }
        }
    })
    .await;

    let session = timeout_server
        .stream_with(|cfg| {
            cfg.with_request_timeout(Duration::from_secs(10))
                .with_retry(no_retry_config())
        })
        .append_session(AppendSessionConfig::new())
        .unwrap();

    let t0 = session.submit(sample_append_input()).await.unwrap();
    let t1 = session.submit(sample_append_input()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), both_received.notified())
        .await
        .expect("both batches received");

    advance_virtual_time(Duration::from_secs(6)).await;
    send_ack0.notify_one();
    assert_eq!(t0.await.unwrap().end.seq_num, 1);

    advance_virtual_time(Duration::from_secs(6)).await;
    send_ack1.notify_one();
    assert_eq!(
        t1.await
            .expect("T7c: Batch 1 timer must start when it becomes oldest, not when pipelined")
            .end
            .seq_num,
        2
    );

    let t2 = session.submit(sample_append_input()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), b2_received.notified())
        .await
        .expect("Batch 2 received");
    advance_virtual_time(Duration::from_secs(11)).await;
    let err = t2.await.unwrap_err();
    assert!(matches!(err, AppendSessionError::Timeout(_)), "{err:?}");
    assert!(err.is_retryable());
    assert!(!err.has_no_side_effects());
}

// spec: r1 T7c
#[tokio::test]
async fn spec_t7c_stalled_append_write_times_out_and_slow_progressing_upload_succeeds() {
    // 1. Peer accepts 200 OK headers and stops granting HTTP/2 send capacity mid-batch (while
    //    keeping the connection and stream open). Attempt 1 must time out, retire the wedged
    //    connection, and retry cleanly on a fresh connection.
    let seen_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let attempt_ctr = Arc::new(AtomicUsize::new(0));
    let stall_server = MockH2Server::start({
        let seen_conns = seen_conns.clone();
        let attempt_ctr = attempt_ctr.clone();
        move |conn_id, req, respond| {
            let seen_conns = seen_conns.clone();
            let attempt_ctr = attempt_ctr.clone();
            async move {
                seen_conns.lock().unwrap().push(conn_id);
                let attempt = attempt_ctr.fetch_add(1, Ordering::SeqCst);
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                let mut body = req.into_body();
                if attempt == 0 {
                    // Hold `body` and `s2s` open without calling release_capacity so h2's
                    // 64 KiB initial stream window stalls the 256 KiB upload indefinitely.
                    let _keep_alive = (body, s2s);
                    std::future::pending::<()>().await;
                } else {
                    let mut buf = BytesMut::new();
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    s2s.send_ack(0, 1, false, true);
                }
            }
        }
    })
    .await;

    let session = stall_server
        .stream_with(|cfg| {
            cfg.with_request_timeout(Duration::from_millis(150))
                .with_retry(
                    RetryConfig::new()
                        .with_max_attempts(2)
                        .with_min_base_delay(Duration::from_millis(10))
                        .with_max_base_delay(Duration::from_millis(10))
                        .with_append_retry_policy(AppendRetryPolicy::All),
                )
        })
        .append_session(AppendSessionConfig::new())
        .unwrap();
    let ticket = session
        .submit(sized_append_input(256 * 1024))
        .await
        .unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(3), ticket)
        .await
        .expect("stalled append write must time out and recover")
        .expect("retry on fresh connection must succeed");
    assert_eq!(ack.end.seq_num, 1);
    session.close().await.unwrap();
    let conns = seen_conns.lock().unwrap().clone();
    assert_eq!(conns.len(), 2, "{conns:?}");
    assert_ne!(
        conns[0], conns[1],
        "stalled write timeout must retire the wedged HTTP/2 connection"
    );

    // 2. With max_attempts = 1, a stalled write must fail the ticket and close() with TimeoutError
    //    instead of hanging forever.
    let permanent_stall = MockH2Server::start(|_conn_id, req, respond| async move {
        let Some(s2s) = S2sResponder::open(respond) else {
            return;
        };
        let _keep_alive = (req.into_body(), s2s);
        std::future::pending::<()>().await;
    })
    .await;
    let session = permanent_stall
        .stream_with(|cfg| {
            cfg.with_request_timeout(Duration::from_millis(120))
                .with_retry(no_retry_config())
        })
        .append_session(AppendSessionConfig::new())
        .unwrap();
    let ticket = session
        .submit(sized_append_input(256 * 1024))
        .await
        .unwrap();
    let err = tokio::time::timeout(Duration::from_secs(3), ticket)
        .await
        .expect("stalled write must not hang ticket")
        .unwrap_err();
    assert!(
        matches!(&err, AppendSessionError::Timeout(t) if t.message.contains("append write timed out")),
        "{err:?}"
    );
    let close_err = tokio::time::timeout(Duration::from_secs(1), session.close())
        .await
        .expect("stalled write must not hang close()")
        .unwrap_err();
    assert!(
        matches!(&close_err, AppendSessionError::Timeout(t) if t.message.contains("append write timed out")),
        "{close_err:?}"
    );

    // 3. Slow upload that keeps making forward chunk progress over > 2x request_timeout must NOT
    //    falsely time out, and the T7c ack timer must still start only after the last byte.
    let slow_server = MockH2Server::start(|_conn_id, req, respond| async move {
        let Some(mut s2s) = S2sResponder::open(respond) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let mut released_pending = 0usize;
        let mut decoder = s2_api::v1::stream::s2s::FrameDecoder;
        loop {
            if let Ok(Some(_)) = tokio_util::codec::Decoder::decode(&mut decoder, &mut buf) {
                break;
            }
            let Some(Ok(chunk)) = body.data().await else {
                return;
            };
            buf.extend_from_slice(&chunk);
            released_pending += chunk.len();
            // Drip WINDOW_UPDATEs in >=32 KiB steps every 40 ms so the 512 KiB upload takes
            // ~600 ms (> 2x the 250 ms request_timeout) while continuously advancing.
            if released_pending >= 32 * 1024 {
                tokio::time::sleep(Duration::from_millis(40)).await;
                let _ = body.flow_control().release_capacity(released_pending);
                released_pending = 0;
            }
        }
        // After draining the final 64 KiB (~80 ms after client's last byte), wait another 40 ms
        // (~120 ms < 250 ms ack timeout, while total elapsed since submit is > 600 ms).
        tokio::time::sleep(Duration::from_millis(40)).await;
        s2s.send_ack(0, 1, false, true);
    })
    .await;
    let session = slow_server
        .stream_with(|cfg| {
            cfg.with_request_timeout(Duration::from_millis(250))
                .with_retry(no_retry_config())
        })
        .append_session(AppendSessionConfig::new())
        .unwrap();
    let ticket = session
        .submit(sized_append_input(512 * 1024))
        .await
        .unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(3), ticket)
        .await
        .expect("slow progressing upload must complete")
        .expect("slow progressing upload must not falsely time out");
    assert_eq!(ack.end.seq_num, 1);
    session.close().await.unwrap();
}

// spec: r1 T6b
#[tokio::test]
async fn spec_t6b_append_session_server_draining_resend_and_exhaustion() {
    // 1. After progress (Batch 0 acked), terminal 503 server_draining causes AppendSession to
    //    reconnect on a fresh connection and resend ALL unacked batches (Batch 1 and Batch 2)
    //    without spending retry budget (verified with max_attempts = 1!).
    let seen_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let attempt2_bodies = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let attempt_ctr = Arc::new(AtomicUsize::new(0));
    let resend_server = MockH2Server::start({
        let seen_conns = seen_conns.clone();
        let attempt2_bodies = attempt2_bodies.clone();
        let attempt_ctr = attempt_ctr.clone();
        move |conn_id, req, respond| {
            let seen_conns = seen_conns.clone();
            let attempt2_bodies = attempt2_bodies.clone();
            let attempt_ctr = attempt_ctr.clone();
            async move {
                let n = attempt_ctr.fetch_add(1, Ordering::SeqCst);
                seen_conns.lock().unwrap().push(conn_id);
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                if n == 0 {
                    // Read Batch 0, Batch 1, Batch 2; ack Batch 0 (making progress), then fail
                    // with terminal 503 server_draining!
                    for _ in 0..3 {
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    }
                    s2s.send_ack(0, 1, false, false);
                    s2s.send_terminal(503, br#"{"code":"server_draining","message":"draining"}"#);
                } else {
                    let mut seq = 1u64;
                    while let Some(decoded) = read_append_input(&mut body, &mut buf).await {
                        attempt2_bodies
                            .lock()
                            .unwrap()
                            .push(decoded.records[0].body.to_vec());
                        s2s.send_ack(seq, seq + 1, false, false);
                        seq += 1;
                    }
                    s2s.send_eof();
                }
            }
        }
    })
    .await;

    let session = resend_server
        .stream(no_retry_config()) // max_attempts = 1!
        .append_session(AppendSessionConfig::new())
        .unwrap();
    let t0 = session
        .submit(AppendRecord::new("batch-0").unwrap())
        .await
        .unwrap();
    let t1 = session
        .submit(AppendRecord::new("batch-1").unwrap())
        .await
        .unwrap();
    let t2 = session
        .submit(AppendRecord::new("batch-2").unwrap())
        .await
        .unwrap();
    session.close().await.unwrap();
    assert_eq!(t0.await.unwrap().start.seq_num, 0);
    assert_eq!(t1.await.unwrap().start.seq_num, 1);
    assert_eq!(t2.await.unwrap().start.seq_num, 2);
    assert_eq!(
        *attempt2_bodies.lock().unwrap(),
        vec![b"batch-1".to_vec(), b"batch-2".to_vec()],
        "T6b: must resend every unacked batch in order"
    );
    let conns = seen_conns.lock().unwrap().clone();
    assert_eq!(conns.len(), 2);
    assert_ne!(
        conns[0], conns[1],
        "T6b: server_draining must retire the old connection"
    );

    // 2. Sustained server_draining with NO progress exhausts max_attempts and resolves both
    //    AppendSession::close() and all unacked tickets promptly (T6).
    let draining_server = MockH2Server::start(|_conn_id, req, respond| async move {
        let Some(mut s2s) = S2sResponder::open(respond) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        s2s.send_terminal(
            503,
            br#"{"code":"server_draining","message":"still draining"}"#,
        );
    })
    .await;

    let session = draining_server
        .stream(fast_retry_config(2))
        .append_session(AppendSessionConfig::new())
        .unwrap();
    let t0 = session
        .submit(AppendRecord::new("stuck-0").unwrap())
        .await
        .unwrap();
    let t1 = session
        .submit(AppendRecord::new("stuck-1").unwrap())
        .await
        .unwrap();
    let close_err = tokio::time::timeout(Duration::from_secs(3), session.close())
        .await
        .expect("T6: sustained server_draining must not hang close()")
        .expect_err("must fail after exhausting max_attempts");
    assert!(
        matches!(close_err, AppendSessionError::Server(ref s) if s.code.as_deref() == Some("server_draining")),
        "expected Server(server_draining), got {close_err:?}"
    );
    assert_eq!(draining_server.request_count(), 2);
    assert!(t0.await.is_err());
    assert!(t1.await.is_err());
}

// Regression: hyper dropping request body when server sends Ok(ack 0) + terminal 412 must drain
// ack 0 and deliver SeqNumMismatch (not ConnectionLost) to batch 1 (T10, A6a).
#[tokio::test]
async fn regression_append_session_drains_buffered_ack_and_terminal_412_after_body_drop() {
    let server = MockH2Server::start(|_conn_id, req, respond| async move {
        let Some(mut s2s) = S2sResponder::open(respond) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        // Drop request body stream right before sending ack 0 + terminal 412 so the client's
        // input_tx.reserve() fails while responses are still in flight.
        drop(body);
        s2s.send_ack(0, 1, false, false);
        s2s.send_terminal(412, br#"{"seq_num_mismatch":1}"#);
    })
    .await;

    let session = server
        .stream(no_retry_config())
        .append_session(AppendSessionConfig::new())
        .unwrap();

    let t0 = session.submit(sample_append_input()).await.unwrap();
    let t1 = session.submit(sample_append_input()).await.unwrap();
    // Submit a 3rd batch so `input_tx.reserve()` is actively raced against the server body drop.
    let t2 = session.submit(sample_append_input()).await.unwrap();

    assert_eq!(t0.await.expect("batch 0 must succeed").end.seq_num, 1);
    let err1 = t1.await.expect_err("batch 1 must receive SeqNumMismatch");
    assert!(
        matches!(err1, AppendSessionError::SeqNumMismatch(ref e) if e.assignable_seq_num == 1),
        "expected SeqNumMismatch(1), got {err1:?}"
    );
    let err2 = t2.await.expect_err("batch 2 must receive SessionClosed");
    assert!(
        matches!(
            err2,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::SeqNumMismatch(_)))
        ),
        "expected SessionClosed(SeqNumMismatch), got {err2:?}"
    );
    let close_err = session.close().await.unwrap_err();
    assert!(
        matches!(close_err, AppendSessionError::SeqNumMismatch(_)),
        "{close_err:?}"
    );
}

// spec: r1 A1
#[tokio::test]
async fn spec_a1_malformed_ack_returns_protocol_error() {
    // 1. Unary append: reversed range, count mismatch, and matching count.
    let unary_server = MockH2Server::from_responses([
        // end.seq_num < start.seq_num
        CannedResponse::new(200, proto_append_ack(5, 3))
            .with_header("content-type", "application/protobuf"),
        // end.seq_num - start.seq_num != batch record count (submitted 2, acked 1)
        CannedResponse::new(200, proto_append_ack(10, 11))
            .with_header("content-type", "application/protobuf"),
        // matching count (submitted 2, acked 2) succeeds
        CannedResponse::new(200, proto_append_ack(10, 12))
            .with_header("content-type", "application/protobuf"),
    ])
    .await;

    let stream = unary_server.stream(no_retry_config());
    let two_records = || {
        AppendInput::new(
            AppendRecordBatch::try_from_iter([
                AppendRecord::new("a").unwrap(),
                AppendRecord::new("b").unwrap(),
            ])
            .unwrap(),
        )
    };

    let err_reversed = stream.append(two_records()).await.unwrap_err();
    assert!(
        matches!(err_reversed, AppendError::Protocol(_)),
        "expected ProtocolError when end.seq_num < start.seq_num, got {err_reversed:?}"
    );
    assert!(!err_reversed.is_retryable());
    assert!(!err_reversed.has_no_side_effects());

    let err_mismatch = stream.append(two_records()).await.unwrap_err();
    assert!(
        matches!(err_mismatch, AppendError::Protocol(_)),
        "expected ProtocolError when ack count mismatches batch size, got {err_mismatch:?}"
    );

    let ok_ack = stream.append(two_records()).await.unwrap();
    assert_eq!(ok_ack.start.seq_num, 10);
    assert_eq!(ok_ack.end.seq_num, 12);

    // 2. AppendSession: invalid ack record count delivers ProtocolError to ticket & close().
    let session_server = MockH2Server::start(|_conn_id, req, respond| async move {
        let Some(mut s2s) = S2sResponder::open(respond) else {
            return;
        };
        let mut body = req.into_body();
        let mut buf = BytesMut::new();
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        // Batch had 1 record, but server erroneously acks 2 records [0, 2).
        s2s.send_ack(0, 2, false, true);
    })
    .await;

    let session = session_server
        .stream(no_retry_config())
        .append_session(AppendSessionConfig::new())
        .unwrap();
    let ticket = session.submit(sample_append_input()).await.unwrap();
    let err = ticket.await.expect_err("bad ack must yield ProtocolError");
    assert!(
        matches!(err, AppendSessionError::Protocol(_)),
        "expected ProtocolError, got {err:?}"
    );
    let close_err = session.close().await.unwrap_err();
    assert!(
        matches!(close_err, AppendSessionError::Protocol(_)),
        "{close_err:?}"
    );
}

// spec: r1 E7, A8c
#[tokio::test]
async fn session_abort_try_ack_fused_and_validation_context() {
    use futures_core::FusedFuture as _;

    // 1. E7: session validation errors include op/basin/stream context.
    let stall_server = MockH2Server::start(|_conn_id, req, respond| async move {
        let Some(s2s) = S2sResponder::open(respond) else {
            return;
        };
        let _keep = (req, s2s);
        std::future::pending::<()>().await;
    })
    .await;
    let stream = stall_server.stream(no_retry_config());

    let session = stream.append_session(AppendSessionConfig::new()).unwrap();
    let err = session.reserve(1).await.unwrap_err();
    assert!(matches!(err, AppendSessionError::Validation(_)));
    let msg = err.to_string();
    assert!(
        msg.contains("append_session") && msg.contains("test-basin") && msg.contains("test-stream"),
        "expected E7 context on reserve ValidationError, got: {msg}"
    );

    let permit = session.reserve(8).await.unwrap();
    assert_eq!(permit.reserved_bytes(), 8);
    let err = permit
        .submit(AppendRecord::new("payload longer than 0 bytes").unwrap())
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("append_session") && msg.contains("test-basin") && msg.contains("test-stream"),
        "expected E7 context on permit.submit ValidationError, got: {msg}"
    );

    // Explicit abort() settles pending tickets and close() promptly even while handle stays alive.
    let mut ticket = session.submit(sample_append_input()).await.unwrap();
    assert!(!ticket.is_terminated());
    assert!(ticket.try_ack().is_none());
    session.abort();
    let close_err = tokio::time::timeout(Duration::from_secs(1), session.close())
        .await
        .expect("abort must settle close promptly")
        .unwrap_err();
    assert!(matches!(close_err, AppendSessionError::Aborted(_)));
    let ticket_err = ticket
        .try_ack()
        .expect("ticket settled after close")
        .unwrap_err();
    assert!(ticket.is_terminated());
    assert!(ticket.try_ack().is_none());
    assert!(matches!(
        ticket_err,
        AppendSessionError::Aborted(_) | AppendSessionError::SessionClosed(_)
    ));
    // Awaiting after `try_ack()` returned `Some` returns the cached outcome without panicking.
    let awaited_err = ticket.await.unwrap_err();
    assert!(matches!(
        awaited_err,
        AppendSessionError::Aborted(_) | AppendSessionError::SessionClosed(_)
    ));

    // Same for Producer: E7 validation context + explicit abort() + try_ack() / FusedFuture.
    let producer = stream
        .producer(
            ProducerConfig::new()
                .with_max_batch_bytes(16)
                .with_linger(Duration::from_secs(60)),
        )
        .unwrap();
    let err = producer
        .submit(AppendRecord::new("this record exceeds 16 bytes").unwrap())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("producer") && msg.contains("test-basin") && msg.contains("test-stream"),
        "expected E7 context on producer.submit ValidationError, got: {msg}"
    );

    let mut rec_ticket = producer
        .submit(AppendRecord::new("hi").unwrap())
        .await
        .unwrap();
    assert!(!rec_ticket.is_terminated());
    assert!(rec_ticket.try_ack().is_none());
    producer.abort();
    let close_err = tokio::time::timeout(Duration::from_secs(1), producer.close())
        .await
        .expect("producer abort must settle close promptly")
        .unwrap_err();
    assert!(matches!(close_err, AppendSessionError::Aborted(_)));
    let rec_err = rec_ticket
        .try_ack()
        .expect("record ticket settled")
        .unwrap_err();
    assert!(rec_ticket.is_terminated());
    assert!(rec_ticket.try_ack().is_none());
    assert!(matches!(
        rec_err,
        AppendSessionError::Aborted(_) | AppendSessionError::SessionClosed(_)
    ));
    let awaited_rec_err = rec_ticket.await.unwrap_err();
    assert!(matches!(
        awaited_rec_err,
        AppendSessionError::Aborted(_) | AppendSessionError::SessionClosed(_)
    ));
}

// spec: r1 A4c, A6a, A8c, E6
#[tokio::test]
async fn spec_a8c_explicit_abort_append_session_and_producer() {
    // 1. AppendSession::abort() when idle closes cleanly without sending any request, and
    //    subsequent submit()/reserve() fail with SessionClosedError { failure: None }.
    let idle_server = auto_ack_s2s_server().await;
    let idle_stream = idle_server.stream(no_retry_config());
    let idle_session = idle_stream
        .append_session(AppendSessionConfig::new())
        .unwrap();
    idle_session.abort();
    idle_session
        .close()
        .await
        .expect("A8c: aborting an idle AppendSession must close cleanly");
    assert_eq!(idle_server.request_count(), 0);
    let err = idle_session
        .submit(sample_append_input())
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppendSessionError::SessionClosed(ref c) if c.failure().is_none()),
        "A4c/E6: {err:?}"
    );
    let err = idle_session.reserve(16).await.err().unwrap();
    assert!(
        matches!(err, AppendSessionError::SessionClosed(ref c) if c.failure().is_none()),
        "A4c/E6: {err:?}"
    );

    // 2. AppendSession::abort() when active with sent batches (A, B) + unsent batch (C blocked by
    //    65 KiB HTTP/2 initial stream window) + waiting reserve():
    //    - A & B -> AbortedError ("append session aborted", indefinite, non-retryable)
    //    - C -> SessionClosedError { failure: Some(Aborted) } (definite)
    //    - waiting reserve() and subsequent submit() -> SessionClosedError { failure: Some(Aborted)
    //      }
    //    - close() -> AbortedError, repeated abort() is a no-op
    let ab_sent = Arc::new(tokio::sync::Notify::new());
    let active_server = MockH2Server::start({
        let ab_sent = ab_sent.clone();
        move |_conn_id, req, respond| {
            let ab_sent = ab_sent.clone();
            async move {
                let Some(s2s) = S2sResponder::open(respond) else {
                    return;
                };
                let mut body = req.into_body();
                let _ = read_exact_h2_bytes(&mut body, 50 * 1024).await;
                ab_sent.notify_one();
                let _keep = (body, s2s);
                std::future::pending::<()>().await;
            }
        }
    })
    .await;
    let session = active_server
        .stream(no_retry_config())
        .append_session(AppendSessionConfig::new().with_max_unacked_batches(3))
        .unwrap();
    let ta = session.submit(sized_append_input(40 * 1024)).await.unwrap();
    let tb = session.submit(sized_append_input(40 * 1024)).await.unwrap();
    let tc = session.submit(sized_append_input(1024)).await.unwrap();
    ab_sent.notified().await;

    let mut waiting_reserve = Box::pin(session.reserve(16));
    assert!(futures_util::poll!(waiting_reserve.as_mut()).is_pending());

    session.abort();

    let reserve_err = tokio::time::timeout(Duration::from_secs(1), waiting_reserve)
        .await
        .expect("A4c/A8c: waiting reserve must wake immediately on abort")
        .err()
        .unwrap();
    assert!(
        matches!(
            reserve_err,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))
        ),
        "waiting reserve: {reserve_err:?}"
    );
    assert!(reserve_err.has_no_side_effects());

    let ea = ta.await.unwrap_err();
    let eb = tb.await.unwrap_err();
    let ec = tc.await.unwrap_err();
    let eclose = session.close().await.unwrap_err();
    assert!(matches!(ea, AppendSessionError::Aborted(_)), "A: {ea:?}");
    assert!(matches!(eb, AppendSessionError::Aborted(_)), "B: {eb:?}");
    assert!(!ea.is_retryable() && !ea.has_no_side_effects());
    assert!(
        ea.to_string().contains("append session aborted") && !ea.to_string().contains("dropped"),
        "expected explicit abort message, got: {ea}"
    );
    assert!(
        matches!(
            ec,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))
        ),
        "C (unsent): {ec:?}"
    );
    assert!(ec.has_no_side_effects());
    assert!(
        matches!(eclose, AppendSessionError::Aborted(_)),
        "close: {eclose:?}"
    );
    let post_submit = session.submit(sample_append_input()).await.unwrap_err();
    assert!(
        matches!(
            post_submit,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))
        ),
        "post-abort submit: {post_submit:?}"
    );
    session.abort();
    assert!(matches!(
        session.close().await.unwrap_err(),
        AppendSessionError::Aborted(_)
    ));

    // 3. AppendSession::abort() after a clean close() is a no-op.
    let closed_session = idle_stream
        .append_session(AppendSessionConfig::new())
        .unwrap();
    let ack = submit_and_ack(&closed_session, sample_append_input()).await;
    assert_eq!(ack.end.seq_num, 1);
    closed_session.close().await.unwrap();
    closed_session.abort();
    closed_session
        .close()
        .await
        .expect("abort() after clean close() must be a no-op");

    // 4. Producer::abort() when idle closes cleanly without sending any request.
    let prod_idle_server = auto_ack_s2s_server().await;
    let prod_idle_stream = prod_idle_server.stream(no_retry_config());
    let idle_prod = prod_idle_stream.producer(ProducerConfig::new()).unwrap();
    idle_prod.abort();
    idle_prod
        .close()
        .await
        .expect("A8c: aborting an idle Producer must close cleanly");
    assert_eq!(prod_idle_server.request_count(), 0);
    let err = idle_prod
        .submit(AppendRecord::new("after-idle-abort").unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppendSessionError::SessionClosed(ref c) if c.failure().is_none()),
        "A4c/E6: {err:?}"
    );

    // 5. Producer::abort() with only a lingering partial batch (owned session still idle): close()
    //    -> AbortedError ("producer aborted"), lingering ticket & subsequent submit() ->
    //    SessionClosedError { failure: Some(Aborted) }.
    let partial_prod = prod_idle_stream
        .producer(ProducerConfig::new().with_linger(Duration::from_secs(60)))
        .unwrap();
    let lingering = partial_prod
        .submit(AppendRecord::new("lingering").unwrap())
        .await
        .unwrap();
    partial_prod.abort();
    let close_err = partial_prod.close().await.unwrap_err();
    assert!(matches!(close_err, AppendSessionError::Aborted(_)));
    assert!(
        close_err.to_string().contains("producer aborted")
            && !close_err.to_string().contains("dropped"),
        "expected explicit producer abort message, got: {close_err}"
    );
    let linger_err = lingering.await.unwrap_err();
    assert!(
        matches!(
            linger_err,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))
        ),
        "lingering ticket: {linger_err:?}"
    );
    let post_err = partial_prod
        .submit(AppendRecord::new("after").unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(
            post_err,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))
        ),
        "post-abort producer submit: {post_err:?}"
    );
    assert_eq!(prod_idle_server.request_count(), 0);

    // 6. Producer::abort() with an in-flight batch (received on server, ack held) + a lingering
    //    partial batch + a waiting reserve():
    //    - in-flight record -> AbortedError
    //    - lingering record -> SessionClosedError { failure: Some(Aborted) }
    //    - waiting reserve() & subsequent submit() -> SessionClosedError { failure: Some(Aborted) }
    //    - close() -> AbortedError
    let batch1_seen = Arc::new(tokio::sync::Notify::new());
    let prod_gate = Arc::new(tokio::sync::Notify::new());
    let prod_server = gated_ack_s2s_server(prod_gate, Some(batch1_seen.clone())).await;
    let prod = Arc::new(
        prod_server
            .stream(no_retry_config())
            .producer(
                ProducerConfig::new()
                    .with_max_unacked_bytes(1024 * 1024)
                    .with_max_batch_bytes(1024 * 1024)
                    .with_linger(Duration::from_secs(60)),
            )
            .unwrap(),
    );
    let t_inflight = prod
        .submit(AppendRecord::new(vec![b'a'; 400 * 1024]).unwrap())
        .await
        .unwrap();
    let flush_task = tokio::spawn({
        let prod = prod.clone();
        async move { prod.flush().await }
    });
    batch1_seen.notified().await;

    let t_partial = prod
        .submit(AppendRecord::new(vec![b'b'; 400 * 1024]).unwrap())
        .await
        .unwrap();
    let mut prod_waiting_reserve = Box::pin(prod.reserve(400 * 1024));
    assert!(futures_util::poll!(prod_waiting_reserve.as_mut()).is_pending());

    prod.abort();

    let wait_err = tokio::time::timeout(Duration::from_secs(1), prod_waiting_reserve)
        .await
        .expect("A4c/A8c: waiting producer reserve must wake immediately on abort")
        .err()
        .unwrap();
    assert!(
        matches!(
            wait_err,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))
        ),
        "waiting producer reserve: {wait_err:?}"
    );

    let inflight_err = t_inflight.await.unwrap_err();
    let partial_err = t_partial.await.unwrap_err();
    let flush_err = flush_task.await.unwrap().unwrap_err();
    let close_err = prod.close().await.unwrap_err();
    assert!(
        matches!(inflight_err, AppendSessionError::Aborted(_)),
        "in-flight record: {inflight_err:?}"
    );
    assert!(
        inflight_err.to_string().contains("producer aborted")
            && !inflight_err.to_string().contains("dropped"),
        "expected explicit producer abort message, got: {inflight_err}"
    );
    assert!(
        matches!(
            partial_err,
            AppendSessionError::SessionClosed(ref c)
                if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))
        ),
        "lingering partial record: {partial_err:?}"
    );
    assert!(
        matches!(flush_err, AppendSessionError::Aborted(_)),
        "flush: {flush_err:?}"
    );
    assert!(
        matches!(close_err, AppendSessionError::Aborted(_)),
        "close: {close_err:?}"
    );

    // 7. Producer::abort() after clean close() is a no-op.
    let closed_prod = prod_idle_stream.producer(ProducerConfig::new()).unwrap();
    let t_ok = closed_prod
        .submit(AppendRecord::new("ok").unwrap())
        .await
        .unwrap();
    closed_prod.close().await.unwrap();
    assert_eq!(t_ok.await.unwrap().seq_num, 0);
    closed_prod.abort();
    closed_prod
        .close()
        .await
        .expect("Producer::abort() after clean close() must be a no-op");
}

// spec: r1 A10, A10a, A10b, A10c
#[tokio::test]
async fn producer_and_append_session_progress_accessors() {
    use std::sync::atomic::AtomicBool;

    use s2_api::v1::stream::{proto::AppendInput as ProtoAppendInput, s2s::SessionMessage};

    // 1. Producer: submit -> flush -> single ack -> terminal failure -> abort.
    let fail_next = Arc::new(AtomicBool::new(false));
    let hold_acks = Arc::new(AtomicBool::new(false));
    let hold_gate = Arc::new(tokio::sync::Notify::new());
    let seen_frame = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let fail_next = fail_next.clone();
        let hold_acks = hold_acks.clone();
        let hold_gate = hold_gate.clone();
        let seen_frame = seen_frame.clone();
        move |_conn_id, req, respond| {
            let fail_next = fail_next.clone();
            let hold_acks = hold_acks.clone();
            let hold_gate = hold_gate.clone();
            let seen_frame = seen_frame.clone();
            async move {
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                let mut next_seq = 0u64;
                while let Some(msg) = read_one_s2s_frame(&mut body, &mut buf, true).await {
                    let count = match msg {
                        SessionMessage::Regular(r) => r
                            .try_into_proto::<ProtoAppendInput>()
                            .expect("valid append input")
                            .records
                            .len() as u64,
                        SessionMessage::Terminal(_) => break,
                    };
                    seen_frame.notify_waiters();
                    if hold_acks.load(Ordering::SeqCst) {
                        hold_gate.notified().await;
                    }
                    if fail_next.load(Ordering::SeqCst) {
                        s2s.send_terminal(
                            412,
                            r#"{"code":"fencing_token_mismatch","expected_fencing_token":"other"}"#
                                .as_bytes(),
                        );
                        return;
                    }
                    let start = next_seq;
                    next_seq += count;
                    s2s.send_ack(start, next_seq, false, false);
                }
            }
        }
    })
    .await;

    let stream = server.stream(no_retry_config());
    let prod = stream
        .producer(ProducerConfig::new().with_linger(Duration::from_secs(10)))
        .unwrap();
    assert_eq!(prod.unacked_bytes(), 0);
    assert_eq!(prod.unacked_records(), 0);
    assert_eq!(prod.acked_records(), 0);

    let r1 = AppendRecord::new("alpha").unwrap();
    let r2 = AppendRecord::new("beta-2").unwrap();
    let expected_bytes = r1.metered_bytes() + r2.metered_bytes();

    let t1 = prod.submit(r1).await.unwrap();
    let t2 = prod.submit(r2).await.unwrap();
    assert_eq!(prod.unacked_bytes(), expected_bytes);
    assert_eq!(prod.unacked_records(), 2);
    assert_eq!(prod.acked_records(), 0);

    prod.flush().await.unwrap();
    assert_eq!(prod.unacked_bytes(), 0);
    assert_eq!(prod.unacked_records(), 0);
    assert_eq!(prod.acked_records(), 2);
    assert_eq!(t1.await.unwrap().seq_num, 0);
    assert_eq!(t2.await.unwrap().seq_num, 1);

    // Single record acked via concurrent flush/ticket completes promptly without waiting out the
    // 10s linger and updates counters before ticket resolves.
    let r3 = AppendRecord::new("gamma").unwrap();
    let t3 = prod.submit(r3).await.unwrap();
    assert_eq!(prod.unacked_records(), 1);
    let (flush_res, ticket_res) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(prod.flush(), t3)
    })
    .await
    .expect("concurrent flush() must complete well below 10s linger");
    flush_res.unwrap();
    let ack3 = ticket_res.unwrap();
    assert_eq!(ack3.seq_num, 2);
    assert_eq!(prod.unacked_bytes(), 0);
    assert_eq!(prod.unacked_records(), 0);
    assert_eq!(prod.acked_records(), 3);

    // Terminal failure settles unacked_bytes and unacked_records back to 0 without advancing
    // acked_records.
    fail_next.store(true, Ordering::SeqCst);
    let t_fail1 = prod
        .submit(AppendRecord::new("fail-1").unwrap())
        .await
        .unwrap();
    let t_fail2 = prod
        .submit(AppendRecord::new("fail-2").unwrap())
        .await
        .unwrap();
    assert_eq!(prod.unacked_records(), 2);
    assert!(prod.flush().await.is_err());
    assert!(t_fail1.await.is_err());
    assert!(t_fail2.await.is_err());
    assert!(prod.close().await.is_err());
    assert_eq!(prod.unacked_bytes(), 0);
    assert_eq!(prod.unacked_records(), 0);
    assert_eq!(prod.acked_records(), 3);

    // Abort on Producer with both in-flight and lingering records drops counters to 0.
    fail_next.store(false, Ordering::SeqCst);
    hold_acks.store(true, Ordering::SeqCst);
    let prod2 = stream
        .producer(ProducerConfig::new().with_linger(Duration::from_secs(10)))
        .unwrap();
    let ta1 = prod2
        .submit(AppendRecord::new("inflight").unwrap())
        .await
        .unwrap();
    let _flush_task = tokio::spawn({
        // Flush first record so it is in flight on the session.
        let seen = seen_frame.clone();
        async move { seen.notified().await }
    });
    let flush_wait = prod2.flush();
    tokio::pin!(flush_wait);
    let mut flushed_sent = false;
    tokio::select! {
        _ = &mut flush_wait => { flushed_sent = true; }
        _ = seen_frame.notified() => {}
    }
    assert!(!flushed_sent);
    let ta2 = prod2
        .submit(AppendRecord::new("lingering").unwrap())
        .await
        .unwrap();
    assert_eq!(prod2.unacked_records(), 2);
    assert!(prod2.unacked_bytes() > 0);
    prod2.abort();
    assert!(prod2.close().await.is_err());
    assert!(ta1.await.is_err());
    assert!(ta2.await.is_err());
    assert_eq!(prod2.unacked_bytes(), 0);
    assert_eq!(prod2.unacked_records(), 0);
    assert_eq!(prod2.acked_records(), 0);
    hold_gate.notify_waiters();

    // 2. AppendSession: submit -> ack -> terminal failure -> abort.
    hold_acks.store(true, Ordering::SeqCst);
    let sess = stream.append_session(AppendSessionConfig::new()).unwrap();
    assert_eq!(sess.unacked_bytes(), 0);
    assert_eq!(sess.unacked_batches(), 0);

    let b1 = AppendInput::new(
        AppendRecordBatch::try_from_iter([AppendRecord::new("batch-1").unwrap()]).unwrap(),
    );
    let b2 = AppendInput::new(
        AppendRecordBatch::try_from_iter([AppendRecord::new("batch-2-longer").unwrap()]).unwrap(),
    );
    let b1_bytes = b1.metered_bytes();
    let b2_bytes = b2.metered_bytes();

    let st1 = sess.submit(b1).await.unwrap();
    let st2 = sess.submit(b2).await.unwrap();
    assert_eq!(sess.unacked_batches(), 2);
    assert_eq!(sess.unacked_bytes(), b1_bytes + b2_bytes);

    // Release ack for batch 1 only, then batch 2.
    hold_acks.store(false, Ordering::SeqCst);
    hold_gate.notify_waiters();
    let _ = st1.await.unwrap();
    let _ = st2.await.unwrap();
    assert_eq!(sess.unacked_batches(), 0);
    assert_eq!(sess.unacked_bytes(), 0);

    // Terminal failure on AppendSession settles counters to 0.
    fail_next.store(true, Ordering::SeqCst);
    let sf1 = sess
        .submit(AppendRecord::new("sess-fail-1").unwrap())
        .await
        .unwrap();
    let sf2 = sess
        .submit(AppendRecord::new("sess-fail-2").unwrap())
        .await
        .unwrap();
    assert!(sess.close().await.is_err());
    assert!(sf1.await.is_err());
    assert!(sf2.await.is_err());
    assert_eq!(sess.unacked_batches(), 0);
    assert_eq!(sess.unacked_bytes(), 0);

    // Abort on AppendSession settles counters to 0.
    fail_next.store(false, Ordering::SeqCst);
    hold_acks.store(true, Ordering::SeqCst);
    let sess2 = stream.append_session(AppendSessionConfig::new()).unwrap();
    let sa1 = sess2
        .submit(AppendRecord::new("sess-abort-1").unwrap())
        .await
        .unwrap();
    let sa2 = sess2
        .submit(AppendRecord::new("sess-abort-2").unwrap())
        .await
        .unwrap();
    assert_eq!(sess2.unacked_batches(), 2);
    assert!(sess2.unacked_bytes() > 0);
    sess2.abort();
    assert!(sess2.close().await.is_err());
    assert!(sa1.await.is_err());
    assert!(sa2.await.is_err());
    assert_eq!(sess2.unacked_batches(), 0);
    assert_eq!(sess2.unacked_bytes(), 0);
    hold_gate.notify_waiters();
}

// spec: r1 A1, A6, A8b, A9
#[tokio::test]
async fn regression_unsent_batch_cannot_be_acked_and_producer_wakes_on_session_failure() {
    // 1. A1/A6: While batch 1 is flow-control blocked so batch 2 stays buffered in the local body
    //    channel (`batches_started == 1`), an unsolicited 2nd ack MUST fail with ProtocolError
    //    rather than settling unsent batch 2 as durable.
    let extra_ack_server = MockH2Server::start(|_conn_id, _req, respond| async move {
        // Deliberately never read `req` so H2 stream flow control stalls batch 1 after the initial
        // 64 KiB window and keeps batch 2 unstarted in the local body channel.
        if let Some(mut s2s) = S2sResponder::open(respond) {
            // Wait briefly for batch 1 to start sending and batch 2 to enter the local channel.
            tokio::time::sleep(Duration::from_millis(50)).await;
            s2s.send_ack(0, 1, false, false);
            s2s.send_ack(1, 2, false, false);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })
    .await;

    let sess = extra_ack_server
        .stream(no_retry_config())
        .append_session(AppendSessionConfig::new())
        .unwrap();
    let big_payload = vec![b'a'; 256 * 1024];
    let t1 = sess
        .submit(AppendRecord::new(big_payload.clone()).unwrap())
        .await
        .unwrap();
    let t2 = sess
        .submit(AppendRecord::new(big_payload).unwrap())
        .await
        .unwrap();
    // Batch 1 started sending, so its ack settles cleanly; batch 2 was never started, so the extra
    // ack must trigger ProtocolError rather than reporting durable success for batch 2.
    assert_eq!(t1.await.unwrap().start.seq_num, 0);
    let err2 = tokio::time::timeout(Duration::from_secs(2), t2)
        .await
        .expect("extra ack must fail promptly")
        .expect_err("unsent batch 2 must NOT be settled as durable");
    assert!(
        matches!(
            err2,
            AppendSessionError::Protocol(_) | AppendSessionError::SessionClosed(_)
        ),
        "expected ProtocolError or SessionClosedError wrapping ProtocolError for unsent batch 2, got {err2:?}"
    );
    let close_err = sess.close().await.unwrap_err();
    assert!(
        matches!(close_err, AppendSessionError::Protocol(_)),
        "expected session failure to be ProtocolError, got {close_err:?}"
    );

    // 2. A8b/A9: Producer with an idle open session and a lingering record settles immediately (not
    //    waiting out the 10s linger) when the owned session receives a permanent error.
    let fail_gate = Arc::new(tokio::sync::Notify::new());
    let perm_err_server = MockH2Server::start({
        let fail_gate = fail_gate.clone();
        move |_conn_id, req, respond| {
            let fail_gate = fail_gate.clone();
            async move {
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                let Some(mut s2s) = S2sResponder::open(respond) else {
                    return;
                };
                if read_one_s2s_frame(&mut body, &mut buf, true)
                    .await
                    .is_some()
                {
                    s2s.send_ack(0, 1, false, false);
                }
                // Wait until the producer holds a lingering record, then emit permanent 403.
                fail_gate.notified().await;
                s2s.send_terminal(403, br#"{"code":"permission_denied","message":"revoked"}"#);
            }
        }
    })
    .await;

    let prod = perm_err_server
        .stream(no_retry_config())
        .producer(ProducerConfig::new().with_linger(Duration::from_secs(10)))
        .unwrap();
    let p1 = prod
        .submit(AppendRecord::new("first").unwrap())
        .await
        .unwrap();
    prod.flush().await.unwrap();
    assert_eq!(p1.await.unwrap().seq_num, 0);

    // Submit a second record that stays lingering in `partial_batch` while `pending_batch_acks` is
    // empty, then fail the open append session with permanent 403.
    let p2 = prod
        .submit(AppendRecord::new("lingering").unwrap())
        .await
        .unwrap();
    assert_eq!(prod.unacked_records(), 1);
    fail_gate.notify_one();

    let p2_err = tokio::time::timeout(Duration::from_secs(2), p2)
        .await
        .expect("producer must wake immediately on owned session failure without waiting out 10s linger")
        .unwrap_err();
    assert!(
        matches!(p2_err, AppendSessionError::SessionClosed(_)),
        "lingering record must fail with SessionClosedError, got {p2_err:?}"
    );
    let prod_close_err = prod.close().await.unwrap_err();
    assert!(
        matches!(prod_close_err, AppendSessionError::Server(ref e) if e.status == 403),
        "producer close must surface 403, got {prod_close_err:?}"
    );
    assert_eq!(prod.unacked_records(), 0);
    assert_eq!(prod.unacked_bytes(), 0);
}
