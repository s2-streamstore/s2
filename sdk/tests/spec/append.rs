use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use http::Response;
use prost::Message as _;
use s2_api::v1::{self as api, stream::s2s::SessionMessage};
use s2_sdk::{
    S2,
    append_session::AppendSessionConfig,
    error::{AppendError, AppendSessionError},
    producer::ProducerConfig,
    types::{
        AccountEndpoint, AppendInput, AppendRecord, AppendRecordBatch, AppendRetryPolicy,
        BasinEndpoint, BasinName, MeteredBytes, RetryConfig, S2Config, S2Endpoints, StreamName,
    },
};

use crate::support::*;

// spec: r1 A2, A2a, A2b, A2c, A2d, A5
#[tokio::test]
async fn spec_a2_validation_before_capacity_and_split_reserve_submit() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // Server holds the first batch unacked until released so capacity is full.
    let release = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let release = release.clone();
        move |_conn_id, req, mut respond| {
            let release = release.clone();
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
                let mut buf = BytesMut::new();
                let mut seq = 0u64;
                while read_one_s2s_frame(&mut body, &mut buf, true)
                    .await
                    .is_some()
                {
                    release.notified().await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(seq, seq + 1), false),
                        false,
                    );
                    seq += 1;
                }
                let _ = send.send_data(Bytes::new(), true);
            }
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);

    // 1. AppendSession: reserve() validates before waiting for capacity; permit.submit() rejects
    //    batches larger than reserved_bytes, releases reservation, and leaves session open.
    let session = stream
        .append_session(
            AppendSessionConfig::new()
                .with_max_unacked_batches(1)
                .unwrap(),
        )
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
                .unwrap()
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
}

// spec: r1 A3, A3a, A3b, T9
#[tokio::test]
async fn spec_a3_t9_lazy_open_and_idle_disconnect_uses_no_budget() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let seen_attempts = Arc::new(Mutex::new(Vec::<String>::new()));
    let trigger_idle_reset = Arc::new(tokio::sync::Notify::new());
    let idle_reset_sent = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let seen_attempts = seen_attempts.clone();
        let trigger_idle_reset = trigger_idle_reset.clone();
        let idle_reset_sent = idle_reset_sent.clone();
        move |_conn_id, req, mut respond| {
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
                match idx {
                    1 => {
                        // Ack batch 0, then immediately close cleanly while idle (T9).
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
                            true,
                        );
                    }
                    2 => {
                        // Ack batch 1, wait until caller observes idle state, then reset stream.
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(1, 2), false),
                            false,
                        );
                        trigger_idle_reset.notified().await;
                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                        idle_reset_sent.notify_one();
                    }
                    _ => {
                        // Ack batch 2 and wait for close.
                        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
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

    // max_attempts = 1: ANY budget consumption would immediately fail the session!
    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);

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

    let ack0 = session
        .submit(sample_append_input())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(ack0.end.seq_num, 1);
    // Allow the session task to process the clean EOF while idle; must NOT open request #2 yet.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        server.request_count(),
        1,
        "A3: idle clean end must not eagerly open a new request"
    );

    let ack1 = session
        .submit(sample_append_input())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(ack1.end.seq_num, 2);
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

    let ack2 = session
        .submit(sample_append_input())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(ack2.end.seq_num, 3);
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
    let (basin_name, stream_name) = test_basin_and_stream();

    let ack_gate = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let ack_gate = ack_gate.clone();
        move |_conn_id, req, mut respond| {
            let ack_gate = ack_gate.clone();
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
                let mut buf = BytesMut::new();
                let mut seq = 0u64;
                while read_one_s2s_frame(&mut body, &mut buf, true)
                    .await
                    .is_some()
                {
                    ack_gate.notified().await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(seq, seq + 1), false),
                        false,
                    );
                    seq += 1;
                }
                let _ = send.send_data(Bytes::new(), true);
            }
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);

    // 1. FIFO capacity: max_unacked_bytes = 1 MiB. Batch 1 takes 700 KiB -> 324 KiB remaining.
    //    Waiter A requests 500 KiB (must wait). Waiter B requests 200 KiB (fits in 324 KiB, but
    //    MUST queue behind Waiter A!).
    let session = Arc::new(
        stream
            .append_session(
                AppendSessionConfig::new()
                    .with_max_unacked_bytes(1024 * 1024)
                    .unwrap(),
            )
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
    let fail_server = MockH2Server::start(|_conn_id, req, mut respond| async move {
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
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        let _ = send.send_data(
            encode_s2s_terminal_frame(412, br#"{"seq_num_mismatch":99}"#),
            true,
        );
    })
    .await;
    let (fail_basin, fail_stream) = test_basin_and_stream();
    let producer = fail_server
        .client(no_retry_config())
        .basin(fail_basin)
        .stream(fail_stream)
        .producer(ProducerConfig::new().with_max_batch_records(1).unwrap())
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
    let (basin_name, stream_name) = test_basin_and_stream();

    // Producer match_seq_num overflow rejects submit() with ValidationError without accepting
    // and leaves the producer open to flush/close earlier accepted records (A5). Per A5, end =
    // match_seq_num + record_count <= u64::MAX:
    //   - match_seq_num = u64::MAX rejects even the first record;
    //   - match_seq_num = u64::MAX - 1 accepts 1 record (end = u64::MAX) and rejects the 2nd.
    let wire_match_seq = Arc::new(std::sync::Mutex::new(None::<u64>));
    let wire_match_seq_srv = wire_match_seq.clone();
    let server = MockH2Server::start(move |_conn_id, req, mut respond| {
        let wire_match_seq_srv = wire_match_seq_srv.clone();
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
            let mut buf = BytesMut::new();
            if let Some(SessionMessage::Regular(regular)) =
                read_one_s2s_frame(&mut body, &mut buf, true).await
            {
                let payload = regular.decompressed().unwrap();
                let decoded = api::stream::proto::AppendInput::decode(payload).unwrap();
                *wire_match_seq_srv.lock().unwrap() = decoded.match_seq_num;
                let _ = send.send_data(
                    encode_s2s_regular_frame(&proto_append_ack(u64::MAX - 1, u64::MAX), false),
                    false,
                );
            }
            while let Some(Ok(_)) = body.data().await {}
            let _ = send.send_data(Bytes::new(), true);
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);

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
    let (basin_name, stream_name) = test_basin_and_stream();

    // 1. Lost-wakeup / multi-task reserve() race: Task X acquires a 600 KiB permit first (nothing
    //    in batcher yet), then Task Y blocks in reserve(600 KiB) on a 1 MiB capacity budget while
    //    linger is 1 hour. When Task X submits its record into the partial batch, no other batch is
    //    in flight and Task Y is already waiting, so A5a MUST flush the partial batch immediately
    //    instead of deadlocking!
    let race_server = MockH2Server::start(|_conn_id, req, mut respond| async move {
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
        let mut seq = 0u64;
        while read_one_s2s_frame(&mut body, &mut buf, true)
            .await
            .is_some()
        {
            let _ = send.send_data(
                encode_s2s_regular_frame(&proto_append_ack(seq, seq + 1), false),
                false,
            );
            seq += 1;
        }
        let _ = send.send_data(Bytes::new(), true);
    })
    .await;

    let prod_race = race_server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .producer(
            ProducerConfig::new()
                .with_max_unacked_bytes(1024 * 1024)
                .unwrap()
                .with_max_batch_bytes(1024 * 1024)
                .unwrap()
                .with_linger(Duration::MAX),
        )
        .unwrap();

    let rec_600k = AppendRecord::new(vec![b'x'; 600 * 1024]).unwrap();
    let size_600k = rec_600k.metered_bytes() as u32;
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
        move |_conn_id, req, mut respond| {
            let batch_received = batch_received.clone();
            let batch1_seen = batch1_seen.clone();
            let allow_batch1_ack = allow_batch1_ack.clone();
            let batch2_seen = batch2_seen.clone();
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
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(seq, seq + 1), false),
                        false,
                    );
                    seq += 1;
                }
                let _ = send.send_data(Bytes::new(), true);
            }
        }
    })
    .await;

    let prod_steady = Arc::new(
        steady_server
            .client(no_retry_config())
            .basin(basin_name)
            .stream(stream_name)
            .producer(
                ProducerConfig::new()
                    .with_max_unacked_bytes(1024 * 1024)
                    .unwrap()
                    .with_max_batch_bytes(1024 * 1024)
                    .unwrap()
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

// spec: r1 A6, A6a, A6b, A6c, A6d, A8, A8b, A9, T10
#[tokio::test]
async fn spec_a6_a9_outcome_table_all_five_scenarios_and_producer_passthrough() {
    let (basin_name, stream_name) = test_basin_and_stream();

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
        basin_name: BasinName,
        stream_name: StreamName,
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
    let (ea, eb, ec, eclose) =
        run_scenario(basin_name.clone(), stream_name.clone(), Scenario::Reject412).await;
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
    let (ea, eb, ec, eclose) = run_scenario(
        basin_name.clone(),
        stream_name.clone(),
        Scenario::FailStorage,
    )
    .await;
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
    let (ea, eb, ec, eclose) = run_scenario(
        basin_name.clone(),
        stream_name.clone(),
        Scenario::ConnectionLost,
    )
    .await;
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
    let (ea, eb, ec, eclose) = run_scenario(
        basin_name.clone(),
        stream_name.clone(),
        Scenario::RetryThen412,
    )
    .await;
    assert!(
        matches!(ea, AppendSessionError::IndefiniteAppend(ref w) if matches!(w.final_attempt_error(), AppendSessionError::SeqNumMismatch(_))),
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

    // Row 5: Client closed while A and B await acks -> A=Aborted, B=Aborted,
    // C=SessionClosed(Aborted), close=Aborted
    let (ea, eb, ec, eclose) = run_scenario(
        basin_name.clone(),
        stream_name.clone(),
        Scenario::ClientClose,
    )
    .await;
    assert!(matches!(ea, AppendSessionError::Aborted(_)), "{ea:?}");
    assert!(matches!(eb, AppendSessionError::Aborted(_)), "{eb:?}");
    assert!(
        matches!(ec, AppendSessionError::SessionClosed(ref c) if matches!(c.failure(), Some(AppendSessionError::Aborted(_)))),
        "Row 5 C: {ec:?}"
    );
    assert!(
        matches!(eclose, AppendSessionError::Aborted(_)),
        "{eclose:?}"
    );

    // T10 + A6d: Ack received before terminal error takes effect first, and Producer preserves
    // exact AppendSession outcomes without overriding them.
    let t10_server = MockH2Server::start(|_conn_id, req, mut respond| async move {
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
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        // Send ack for batch 0 AND 412 rejection for batch 1 in one coalesced write.
        let mut combined = BytesMut::new();
        combined.extend_from_slice(&encode_s2s_regular_frame(&proto_append_ack(0, 1), false));
        combined.extend_from_slice(&encode_s2s_terminal_frame(
            412,
            br#"{"seq_num_mismatch":1}"#,
        ));
        let _ = send.send_data(combined.freeze(), true);
    })
    .await;

    let producer = t10_server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
        .producer(
            ProducerConfig::new()
                .with_max_batch_records(1)
                .unwrap()
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
    let (basin_name, stream_name) = test_basin_and_stream();

    let batch0_received = Arc::new(tokio::sync::Notify::new());
    let allow_batch0_ack = Arc::new(tokio::sync::Notify::new());
    let batch0_records = Arc::new(AtomicUsize::new(0));
    let server = MockH2Server::start({
        let batch0_received = batch0_received.clone();
        let allow_batch0_ack = allow_batch0_ack.clone();
        let batch0_records = batch0_records.clone();
        move |_conn_id, req, mut respond| {
            let batch0_received = batch0_received.clone();
            let allow_batch0_ack = allow_batch0_ack.clone();
            let batch0_records = batch0_records.clone();
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
                let mut buf = BytesMut::new();
                // Batch 0 succeeds after gate; Batch 1 fails with 412.
                if let Some(SessionMessage::Regular(regular)) =
                    read_one_s2s_frame(&mut body, &mut buf, true).await
                {
                    let decoded =
                        api::stream::proto::AppendInput::decode(regular.decompressed().unwrap())
                            .unwrap();
                    batch0_records.store(decoded.records.len(), Ordering::SeqCst);
                    batch0_received.notify_one();
                    allow_batch0_ack.notified().await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(
                            &proto_append_ack(0, decoded.records.len() as u64),
                            false,
                        ),
                        false,
                    );
                }
                if read_one_s2s_frame(&mut body, &mut buf, true)
                    .await
                    .is_some()
                {
                    let _ = send.send_data(
                        encode_s2s_terminal_frame(412, br#"{"seq_num_mismatch":1}"#),
                        true,
                    );
                }
            }
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone());

    // 1. With max_batch_records = 10 and long linger, flush() cuts the partial batch containing t0
    //    so a record accepted after flush() begins is NOT co-batched with t0, and a failure on that
    //    later record + close() does NOT fail flush0!
    let producer = Arc::new(
        stream
            .producer(
                ProducerConfig::new()
                    .with_max_batch_records(10)
                    .unwrap()
                    .with_linger(Duration::from_secs(3600)),
            )
            .unwrap(),
    );

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
    let (basin_name, stream_name) = test_basin_and_stream();

    let ack_gate = Arc::new(tokio::sync::Notify::new());
    let frame_seen = Arc::new(tokio::sync::Notify::new());
    let server = MockH2Server::start({
        let ack_gate = ack_gate.clone();
        let frame_seen = frame_seen.clone();
        move |_conn_id, req, mut respond| {
            let ack_gate = ack_gate.clone();
            let frame_seen = frame_seen.clone();
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
                let mut buf = BytesMut::new();
                if read_one_s2s_frame(&mut body, &mut buf, true)
                    .await
                    .is_some()
                {
                    frame_seen.notify_one();
                    ack_gate.notified().await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
                        false,
                    );
                }
                while let Some(Ok(_)) = body.data().await {}
                let _ = send.send_data(Bytes::new(), true);
            }
        }
    })
    .await;

    let stream = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name);

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
}

// spec: r1 T6a
#[tokio::test]
async fn spec_t6a_append_reconnect_advice_cooldown() {
    let (basin_name, stream_name) = test_basin_and_stream();

    // T6a: Reconnect advice triggers handover to a new connection, then a second reconnect
    // advice within 60 s is ignored (stays on the same connection!).
    let seen_conns = Arc::new(Mutex::new(Vec::<usize>::new()));
    let req_idx = Arc::new(AtomicUsize::new(0));
    let advice_server = MockH2Server::start({
        let seen_conns = seen_conns.clone();
        let req_idx = req_idx.clone();
        move |conn_id, req, mut respond| {
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
                let mut body = req.into_body();
                let mut buf = BytesMut::new();
                if n == 0 {
                    // Ack batch 0 with reconnect-advised bit -> client drains and closes body.
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(0, 1), true),
                        false,
                    );
                    while let Some(Ok(_)) = body.data().await {}
                    let _ = send.send_data(Bytes::new(), true);
                } else {
                    // Request 2: ack batch 1 WITH reconnect-advised bit (must be ignored within
                    // 60 s cooldown!), then ack batch 2 on the SAME request!
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(1, 2), true),
                        false,
                    );
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(2, 3), false),
                        false,
                    );
                    while let Some(Ok(_)) = body.data().await {}
                    let _ = send.send_data(Bytes::new(), true);
                }
            }
        }
    })
    .await;

    let session = advice_server
        .client(no_retry_config())
        .basin(basin_name.clone())
        .stream(stream_name.clone())
        .append_session(AppendSessionConfig::new())
        .unwrap();
    assert_eq!(
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
            .end
            .seq_num,
        1
    );
    assert_eq!(
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
            .end
            .seq_num,
        2
    );
    assert_eq!(
        session
            .submit(sample_append_input())
            .await
            .unwrap()
            .await
            .unwrap()
            .end
            .seq_num,
        3
    );
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
    let (basin_name, stream_name) = test_basin_and_stream();

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
        move |_conn_id, req, mut respond| {
            let both_received = both_received.clone();
            let send_ack0 = send_ack0.clone();
            let send_ack1 = send_ack1.clone();
            let b2_received = b2_received.clone();
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
                let mut buf = BytesMut::new();
                let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                both_received.notify_one();
                send_ack0.notified().await;
                let _ = send.send_data(
                    encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
                    false,
                );
                send_ack1.notified().await;
                let _ = send.send_data(
                    encode_s2s_regular_frame(&proto_append_ack(1, 2), false),
                    false,
                );
                // Never ack Batch 2.
                let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                b2_received.notify_one();
                std::future::pending::<()>().await;
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
    let s2 = S2::new(
        S2Config::new("test-token")
            .with_endpoints(endpoints)
            .with_request_timeout(Duration::from_secs(10))
            .unwrap()
            .with_retry(no_retry_config()),
    )
    .unwrap();
    let session = s2
        .basin(basin_name)
        .stream(stream_name)
        .append_session(AppendSessionConfig::new())
        .unwrap();

    let t0 = session.submit(sample_append_input()).await.unwrap();
    let t1 = session.submit(sample_append_input()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), both_received.notified())
        .await
        .expect("both batches received");

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::time::resume();
    send_ack0.notify_one();
    assert_eq!(t0.await.unwrap().end.seq_num, 1);

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::time::resume();
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
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::resume();
    let err = t2.await.unwrap_err();
    assert!(matches!(err, AppendSessionError::Timeout(_)), "{err:?}");
    assert!(err.is_retryable());
    assert!(!err.has_no_side_effects());
}

// spec: r1 T6b
#[tokio::test]
async fn spec_t6b_append_session_server_draining_resend_and_exhaustion() {
    let (basin_name, stream_name) = test_basin_and_stream();

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
        move |conn_id, req, mut respond| {
            let seen_conns = seen_conns.clone();
            let attempt2_bodies = attempt2_bodies.clone();
            let attempt_ctr = attempt_ctr.clone();
            async move {
                let n = attempt_ctr.fetch_add(1, Ordering::SeqCst);
                seen_conns.lock().unwrap().push(conn_id);
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
                if n == 0 {
                    // Read Batch 0, Batch 1, Batch 2; ack Batch 0 (making progress), then fail
                    // with terminal 503 server_draining!
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
                    let _ = send.send_data(
                        encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
                        false,
                    );
                    let _ = send.send_data(
                        encode_s2s_terminal_frame(
                            503,
                            br#"{"code":"server_draining","message":"draining"}"#,
                        ),
                        true,
                    );
                } else {
                    let mut seq = 1u64;
                    while let Some(SessionMessage::Regular(regular)) =
                        read_one_s2s_frame(&mut body, &mut buf, true).await
                    {
                        let decoded = api::stream::proto::AppendInput::decode(
                            regular.decompressed().unwrap(),
                        )
                        .unwrap();
                        attempt2_bodies
                            .lock()
                            .unwrap()
                            .push(decoded.records[0].body.to_vec());
                        let _ = send.send_data(
                            encode_s2s_regular_frame(&proto_append_ack(seq, seq + 1), false),
                            false,
                        );
                        seq += 1;
                    }
                    let _ = send.send_data(Bytes::new(), true);
                }
            }
        }
    })
    .await;

    let session = resend_server
        .client(no_retry_config()) // max_attempts = 1!
        .basin(basin_name.clone())
        .stream(stream_name.clone())
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
    let draining_server = MockH2Server::start(|_conn_id, req, mut respond| async move {
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
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        let _ = send.send_data(
            encode_s2s_terminal_frame(
                503,
                br#"{"code":"server_draining","message":"still draining"}"#,
            ),
            true,
        );
    })
    .await;

    let retry_2 = RetryConfig::new()
        .with_max_attempts(2)
        .unwrap()
        .with_min_base_delay(Duration::ZERO)
        .with_max_base_delay(Duration::ZERO);
    let session = draining_server
        .client(retry_2)
        .basin(basin_name)
        .stream(stream_name)
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
    let (basin_name, stream_name) = test_basin_and_stream();
    let server = MockH2Server::start(|_conn_id, req, mut respond| async move {
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
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        // Drop request body stream right before sending ack 0 + terminal 412 so the client's
        // input_tx.reserve() fails while responses are still in flight.
        drop(body);
        let _ = send.send_data(
            encode_s2s_regular_frame(&proto_append_ack(0, 1), false),
            false,
        );
        let _ = send.send_data(
            encode_s2s_terminal_frame(412, br#"{"seq_num_mismatch":1}"#),
            true,
        );
    })
    .await;

    let session = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
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

// Regression: invalid ack record count delivers ProtocolError to the batch ticket (not Aborted).
#[tokio::test]
async fn regression_append_session_invalid_ack_delivers_protocol_error_to_ticket() {
    let (basin_name, stream_name) = test_basin_and_stream();
    let server = MockH2Server::start(|_conn_id, req, mut respond| async move {
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
        let _ = read_one_s2s_frame(&mut body, &mut buf, true).await;
        // Batch had 1 record, but server erroneously acks 2 records [0, 2).
        let _ = send.send_data(
            encode_s2s_regular_frame(&proto_append_ack(0, 2), false),
            true,
        );
    })
    .await;

    let session = server
        .client(no_retry_config())
        .basin(basin_name)
        .stream(stream_name)
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

// spec: r1 A1
#[tokio::test]
async fn spec_a1_unary_append_rejects_malformed_ack_range() {
    let (basin_name, stream_name) = test_basin_and_stream();

    let server = MockH2Server::from_responses([
        // 1. end.seq_num < start.seq_num
        CannedResponse::new(200, proto_append_ack(5, 3))
            .with_header("content-type", "application/protobuf"),
        // 2. end.seq_num - start.seq_num != batch record count (submitted 2, acked 1)
        CannedResponse::new(200, proto_append_ack(10, 11))
            .with_header("content-type", "application/protobuf"),
        // 3. matching count (submitted 2, acked 2) succeeds
        CannedResponse::new(200, proto_append_ack(10, 12))
            .with_header("content-type", "application/protobuf"),
    ])
    .await;

    let stream = server
        .client(RetryConfig::new().with_max_attempts(1).unwrap())
        .basin(basin_name)
        .stream(stream_name);

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
}
