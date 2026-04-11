use std::{task::Poll, time::Duration};

use bytes::Bytes;
use futures::StreamExt;
use rstest::rstest;
use s2_common::{
    encryption::EncryptionSpec,
    read_extent::{ReadLimit, ReadUntil},
    record::MeteredSize,
    types::{
        config::{OptionalStreamConfig, OptionalTimestampingConfig, TimestampingMode},
        stream::{AppendInput, ReadEnd, ReadFrom, ReadStart, StoredReadSessionOutput},
    },
};
use s2_lite::backend::FOLLOWER_MAX_LAG;

use super::common::*;

const VIRTUAL_TIME_STEP: Duration = Duration::from_millis(50);

async fn run_follow_mode_receives_new_data_case(test_suffix: &str, encryption: &EncryptionSpec) {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream(test_suffix, "stream", OptionalStreamConfig::default()).await;

    append_payloads_with_encryption(
        &backend,
        &basin_name,
        &stream_name,
        &[b"initial"],
        encryption,
    )
    .await;

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let wait_duration = Duration::from_millis(200);
    let first_follow_delay = Duration::from_millis(100);
    let second_follow_delay = Duration::from_millis(50);
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(wait_duration),
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    let backend_clone = backend.clone();
    let basin_clone = basin_name.clone();
    let stream_clone = stream_name.clone();
    let encryption_clone = encryption.clone();

    let append_handle = tokio::spawn(async move {
        tokio::time::sleep(first_follow_delay).await;
        append_payloads_with_encryption(
            &backend_clone,
            &basin_clone,
            &stream_clone,
            &[b"follow-1"],
            &encryption_clone,
        )
        .await;
        tokio::time::sleep(second_follow_delay).await;
        append_payloads_with_encryption(
            &backend_clone,
            &basin_clone,
            &stream_clone,
            &[b"follow-2"],
            &encryption_clone,
        )
        .await;
    });

    let probe_step = Duration::from_millis(1);
    let deadline = tokio::time::Instant::now()
        + wait_duration
        + first_follow_delay
        + second_follow_delay
        + Duration::from_secs(1);
    let mut outputs = Vec::new();
    let mut final_delivery_at = None;
    let closed_at = loop {
        match poll_session_with_deadline(&mut session, deadline, Some(probe_step)).await {
            SessionPoll::Output(output) => {
                if matches!(output, StoredReadSessionOutput::Batch(_)) {
                    final_delivery_at = Some(tokio::time::Instant::now());
                }
                outputs.push(output);
            }
            SessionPoll::Closed => break tokio::time::Instant::now(),
            SessionPoll::TimedOut => panic!("Timed out waiting for read session to close"),
        }
    };

    append_handle.await.unwrap();

    let all_records = outputs
        .into_iter()
        .filter_map(|output| match output {
            StoredReadSessionOutput::Batch(batch) => Some(batch),
            StoredReadSessionOutput::Heartbeat(_) => None,
        })
        .flat_map(|batch| {
            decrypt_batch_for_stream(batch, &basin_name, &stream_name, encryption)
                .records
                .into_iter()
        })
        .collect::<Vec<_>>();
    let bodies = envelope_bodies(&all_records);
    assert_eq!(
        bodies,
        vec![
            b"initial".to_vec(),
            b"follow-1".to_vec(),
            b"follow-2".to_vec()
        ]
    );
    let final_delivery_at =
        final_delivery_at.expect("read session should deliver the initial and follow batches");
    assert!(closed_at >= final_delivery_at + wait_duration);
    assert!(closed_at <= final_delivery_at + wait_duration + probe_step);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_broadcast_lag_resets_wait_after_db_catchup() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-broadcast-lag",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let message_count = FOLLOWER_MAX_LAG + 25;
    let wait_duration = Duration::from_millis(200);
    let pre_lag_delay = Duration::from_millis(100);
    let probe_step = Duration::from_millis(1);

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(wait_duration),
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    expect_heartbeat_advanced(&mut session, Duration::from_secs(1), VIRTUAL_TIME_STEP).await;
    advance_time(pre_lag_delay).await;

    let mut expected = Vec::with_capacity(message_count);
    for i in 0..message_count {
        let payload = format!("msg-{}", i);
        expected.push(payload.as_bytes().to_vec());
        append_payloads(&backend, &basin_name, &stream_name, &[payload.as_bytes()]).await;
    }

    let follow = session
        .as_mut()
        .next()
        .await
        .expect("session should deliver the lagged catchup batch")
        .expect("session should not error");
    let reset_at = tokio::time::Instant::now();
    let StoredReadSessionOutput::Batch(batch) = follow else {
        panic!("expected catchup batch after lagged follow");
    };
    let batch = decrypt_plain_batch(batch);
    assert_eq!(envelope_bodies(&batch.records), expected);

    let outputs = collect_outputs_until_closed_advanced(
        &mut session,
        wait_duration + Duration::from_secs(1),
        probe_step,
    )
    .await;

    assert!(outputs.closed_at >= reset_at + wait_duration);
    assert!(outputs.closed_at <= reset_at + wait_duration + probe_step);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_broadcast_lag_respects_count_limit() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-broadcast-lag-count-limit",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let message_count = FOLLOWER_MAX_LAG + 25;
    let count_limit = 3;

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Count(count_limit),
        until: ReadUntil::Unbounded,
        wait: Some(Duration::from_secs(3)),
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    expect_heartbeat_advanced(&mut session, Duration::from_secs(1), VIRTUAL_TIME_STEP).await;
    advance_time(Duration::from_millis(100)).await;

    let mut expected = Vec::with_capacity(message_count);
    for i in 0..message_count {
        let payload = format!("msg-{}", i);
        expected.push(payload.as_bytes().to_vec());
        append_payloads(&backend, &basin_name, &stream_name, &[payload.as_bytes()]).await;
    }

    let records = collect_records_until_closed_advanced(
        &mut session,
        Duration::from_secs(2),
        VIRTUAL_TIME_STEP,
    )
    .await;
    assert_eq!(
        envelope_bodies(&records),
        expected.into_iter().take(count_limit).collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_broadcast_lag_respects_bytes_limit() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-broadcast-lag-bytes-limit",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"item-00"]).await;

    let stored_batch = first_stored_batch(&backend, &basin_name, &stream_name).await;
    let per_record_bytes = stored_batch.records[0].metered_size();
    let message_count = FOLLOWER_MAX_LAG + 25;
    let bytes_limit = per_record_bytes * 3;

    let session = backend
        .read(
            basin_name.clone(),
            stream_name.clone(),
            ReadStart {
                from: ReadFrom::TailOffset(0),
                clamp: false,
            },
            ReadEnd {
                limit: ReadLimit::Bytes(bytes_limit),
                until: ReadUntil::Unbounded,
                wait: Some(Duration::from_secs(3)),
            },
        )
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    expect_heartbeat_advanced(&mut session, Duration::from_secs(1), VIRTUAL_TIME_STEP).await;
    advance_time(Duration::from_millis(100)).await;

    let expected: Vec<_> = (1..=message_count)
        .map(|i| format!("item-{i:02}").into_bytes())
        .collect();
    for body in &expected {
        append_payloads(&backend, &basin_name, &stream_name, &[body.as_slice()]).await;
    }

    let records = collect_records_until_closed_advanced(
        &mut session,
        Duration::from_secs(2),
        VIRTUAL_TIME_STEP,
    )
    .await;

    assert_eq!(
        envelope_bodies(&records),
        expected.into_iter().take(3).collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_broadcast_lag_respects_timestamp_until() {
    let stream_config = OptionalStreamConfig {
        timestamping: OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            ..Default::default()
        },
        ..Default::default()
    };
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("follow-broadcast-lag-until", "stream", stream_config).await;

    let message_count = FOLLOWER_MAX_LAG + 25;
    let cutoff = 4_000;

    let session = backend
        .read(
            basin_name.clone(),
            stream_name.clone(),
            ReadStart {
                from: ReadFrom::SeqNum(0),
                clamp: false,
            },
            ReadEnd {
                limit: ReadLimit::Unbounded,
                until: ReadUntil::Timestamp(cutoff),
                wait: Some(Duration::from_secs(3)),
            },
        )
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    expect_heartbeat_advanced(&mut session, Duration::from_secs(1), VIRTUAL_TIME_STEP).await;
    advance_time(Duration::from_millis(100)).await;

    let expected: Vec<_> = (1..=message_count)
        .map(|i| (format!("ts-{i:03}").into_bytes(), i as u64 * 1_000))
        .collect();
    for (body, timestamp) in &expected {
        append_timestamped_payloads(
            &backend,
            &basin_name,
            &stream_name,
            vec![(Bytes::from(body.clone()), *timestamp)],
        )
        .await;
    }

    let catchup = session
        .as_mut()
        .next()
        .await
        .expect("session should deliver the lagged catchup batch")
        .expect("session should not error");
    let StoredReadSessionOutput::Batch(batch) = catchup else {
        panic!("expected lagged catchup batch");
    };
    let batch = decrypt_plain_batch(batch);
    assert_eq!(
        envelope_bodies(&batch.records),
        expected
            .iter()
            .take_while(|(_, timestamp)| *timestamp < cutoff)
            .map(|(body, _)| body.clone())
            .collect::<Vec<_>>()
    );

    tokio::task::yield_now().await;
    match futures::poll!(session.as_mut().next()) {
        Poll::Ready(None) => {}
        Poll::Ready(Some(Ok(output))) => {
            panic!("unexpected output after timestamp cutoff catchup: {output:?}");
        }
        Poll::Ready(Some(Err(e))) => panic!("Read error: {e:?}"),
        Poll::Pending => {
            panic!(
                "session should close immediately once lagged catchup crosses the timestamp cutoff"
            );
        }
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_broadcast_lag_resumes_live_follow_after_catchup() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-broadcast-lag-live",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let message_count = FOLLOWER_MAX_LAG + 25;
    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::from_millis(300)),
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    expect_heartbeat_advanced(&mut session, Duration::from_secs(1), VIRTUAL_TIME_STEP).await;
    advance_time(Duration::from_millis(100)).await;

    let mut expected_catchup = Vec::with_capacity(message_count);
    for i in 0..message_count {
        let payload = format!("lag-{}", i);
        expected_catchup.push(payload.as_bytes().to_vec());
        append_payloads(&backend, &basin_name, &stream_name, &[payload.as_bytes()]).await;
    }

    let catchup = session
        .as_mut()
        .next()
        .await
        .expect("session should deliver the lagged catchup batch")
        .expect("session should not error");
    let StoredReadSessionOutput::Batch(batch) = catchup else {
        panic!("expected catchup batch after lagged follow");
    };
    let batch = decrypt_plain_batch(batch);
    assert_eq!(envelope_bodies(&batch.records), expected_catchup);

    let backend_clone = backend.clone();
    let basin_clone = basin_name.clone();
    let stream_clone = stream_name.clone();
    let append_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        append_payloads(
            &backend_clone,
            &basin_clone,
            &stream_clone,
            &[b"live-after-lag"],
        )
        .await;
    });

    let live_records =
        collect_records_until_advanced(&mut session, Duration::from_secs(1), 1, VIRTUAL_TIME_STEP)
            .await;

    append_handle.await.unwrap();

    assert_eq!(
        envelope_bodies(&live_records),
        vec![b"live-after-lag".to_vec()]
    );
}

#[rstest]
#[case::plaintext("follow-new-data", EncryptionSpec::Plain)]
#[case::encrypted("follow-enc", aegis256_encryption())]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_receives_new_data(
    #[case] test_suffix: &str,
    #[case] encryption: EncryptionSpec,
) {
    run_follow_mode_receives_new_data_case(test_suffix, &encryption).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_transition_from_catchup_to_follow() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "catchup-to-follow",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(
        &backend,
        &basin_name,
        &stream_name,
        &[b"record-0", b"record-1", b"record-2"],
    )
    .await;

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::from_secs(3)),
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    let backend_clone = backend.clone();
    let basin_clone = basin_name.clone();
    let stream_clone = stream_name.clone();

    let append_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        append_payloads(&backend_clone, &basin_clone, &stream_clone, &[b"live-1"]).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        append_payloads(&backend_clone, &basin_clone, &stream_clone, &[b"live-2"]).await;
    });

    let all_records =
        collect_records_until_advanced(&mut session, Duration::from_secs(4), 5, VIRTUAL_TIME_STEP)
            .await;

    append_handle.await.unwrap();

    let bodies = envelope_bodies(&all_records);
    assert_eq!(
        bodies,
        vec![
            b"record-0".to_vec(),
            b"record-1".to_vec(),
            b"record-2".to_vec(),
            b"live-1".to_vec(),
            b"live-2".to_vec(),
        ]
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_with_count_limit() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-count-limit",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"initial"]).await;

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Count(3),
        until: ReadUntil::Unbounded,
        wait: Some(Duration::from_secs(3)),
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    let backend_clone = backend.clone();
    let basin_clone = basin_name.clone();
    let stream_clone = stream_name.clone();

    let append_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        append_payloads(
            &backend_clone,
            &basin_clone,
            &stream_clone,
            &[b"follow-1", b"follow-2", b"follow-3"],
        )
        .await;
    });

    let all_records = collect_records_until_closed_advanced(
        &mut session,
        Duration::from_secs(4),
        VIRTUAL_TIME_STEP,
    )
    .await;

    append_handle.await.unwrap();

    let bodies = envelope_bodies(&all_records);
    assert_eq!(
        bodies,
        vec![
            b"initial".to_vec(),
            b"follow-1".to_vec(),
            b"follow-2".to_vec()
        ]
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_with_exact_count_limit() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-exact-count-limit",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Count(2),
        until: ReadUntil::Unbounded,
        wait: Some(Duration::from_secs(2)),
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    let backend_clone = backend.clone();
    let basin_clone = basin_name.clone();
    let stream_clone = stream_name.clone();

    let append_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        append_payloads(
            &backend_clone,
            &basin_clone,
            &stream_clone,
            &[b"follow-1", b"follow-2"],
        )
        .await;
    });

    let all_records = collect_records_until_closed_advanced(
        &mut session,
        Duration::from_secs(3),
        VIRTUAL_TIME_STEP,
    )
    .await;

    append_handle.await.unwrap();

    let bodies = envelope_bodies(&all_records);
    assert_eq!(bodies, vec![b"follow-1".to_vec(), b"follow-2".to_vec()]);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_collect_records_until_advanced_stops_at_target_count_with_multi_record_batch() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-target-count",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"seed"]).await;

    let session = backend
        .read(
            basin_name.clone(),
            stream_name.clone(),
            ReadStart {
                from: ReadFrom::TailOffset(0),
                clamp: false,
            },
            ReadEnd {
                limit: ReadLimit::Unbounded,
                until: ReadUntil::Unbounded,
                wait: Some(Duration::from_secs(2)),
            },
        )
        .await
        .expect("Failed to create follow read session");
    let mut session = Box::pin(session);

    expect_heartbeat_advanced(&mut session, Duration::from_secs(1), VIRTUAL_TIME_STEP).await;

    let backend_clone = backend.clone();
    let basin_clone = basin_name.clone();
    let stream_clone = stream_name.clone();
    let append_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        append_payloads(
            &backend_clone,
            &basin_clone,
            &stream_clone,
            &[b"follow-1", b"follow-2", b"follow-3"],
        )
        .await;
    });

    let records =
        collect_records_until_advanced(&mut session, Duration::from_secs(1), 2, VIRTUAL_TIME_STEP)
            .await;

    append_handle.await.unwrap();

    assert_eq!(
        envelope_bodies(&records),
        vec![b"follow-1".to_vec(), b"follow-2".to_vec()]
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_with_bytes_limit_truncates_live_batch() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-bytes-limit",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"item-00"]).await;

    let stored_batch = first_stored_batch(&backend, &basin_name, &stream_name).await;
    let per_record_bytes = stored_batch.records[0].metered_size();

    let session = backend
        .read(
            basin_name.clone(),
            stream_name.clone(),
            ReadStart {
                from: ReadFrom::TailOffset(0),
                clamp: false,
            },
            ReadEnd {
                limit: ReadLimit::Bytes(per_record_bytes * 2),
                until: ReadUntil::Unbounded,
                wait: Some(Duration::from_secs(2)),
            },
        )
        .await
        .expect("Failed to create follow read session");
    let mut session = Box::pin(session);

    expect_heartbeat_advanced(&mut session, Duration::from_secs(1), VIRTUAL_TIME_STEP).await;

    let backend_clone = backend.clone();
    let basin_clone = basin_name.clone();
    let stream_clone = stream_name.clone();
    let append_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let input = AppendInput {
            records: create_test_record_batch(vec![
                Bytes::from_static(b"item-01"),
                Bytes::from_static(b"item-02"),
                Bytes::from_static(b"item-03"),
            ]),
            match_seq_num: None,
            fencing_token: None,
        };
        backend_clone
            .append(basin_clone, stream_clone, input)
            .await
            .expect("live append should succeed");
    });

    let records = collect_records_until_closed_advanced(
        &mut session,
        Duration::from_secs(3),
        VIRTUAL_TIME_STEP,
    )
    .await;

    append_handle.await.unwrap();

    assert_eq!(
        envelope_bodies(&records),
        vec![b"item-01".to_vec(), b"item-02".to_vec()]
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_with_bytes_limit_smaller_than_first_live_record_closes_without_batch() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-bytes-too-small",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"item-00"]).await;

    let stored_batch = first_stored_batch(&backend, &basin_name, &stream_name).await;
    let per_record_bytes = stored_batch.records[0].metered_size();

    let session = backend
        .read(
            basin_name.clone(),
            stream_name.clone(),
            ReadStart {
                from: ReadFrom::TailOffset(0),
                clamp: false,
            },
            ReadEnd {
                limit: ReadLimit::Bytes(per_record_bytes - 1),
                until: ReadUntil::Unbounded,
                wait: Some(Duration::from_secs(2)),
            },
        )
        .await
        .expect("Failed to create follow read session");
    let mut session = Box::pin(session);

    expect_heartbeat_advanced(&mut session, Duration::from_secs(1), VIRTUAL_TIME_STEP).await;

    let backend_clone = backend.clone();
    let basin_clone = basin_name.clone();
    let stream_clone = stream_name.clone();
    let append_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        append_payloads(&backend_clone, &basin_clone, &stream_clone, &[b"item-01"]).await;
    });

    let outputs = collect_outputs_until_closed_advanced(
        &mut session,
        Duration::from_secs(1),
        VIRTUAL_TIME_STEP,
    )
    .await;

    append_handle.await.unwrap();

    assert!(
        outputs
            .outputs
            .iter()
            .all(|output| matches!(output, StoredReadSessionOutput::Heartbeat(_))),
        "live oversize record should close the session without yielding a batch"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_with_timestamp_until() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-timestamp-until",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_timestamped_payloads(
        &backend,
        &basin_name,
        &stream_name,
        vec![(Bytes::from_static(b"initial"), 1000)],
    )
    .await;

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Timestamp(2500),
        wait: Some(Duration::from_secs(2)),
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    let backend_clone = backend.clone();
    let basin_clone = basin_name.clone();
    let stream_clone = stream_name.clone();

    let append_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        append_timestamped_payloads(
            &backend_clone,
            &basin_clone,
            &stream_clone,
            vec![(Bytes::from_static(b"before-cutoff"), 2000)],
        )
        .await;

        tokio::time::sleep(Duration::from_millis(200)).await;
        append_timestamped_payloads(
            &backend_clone,
            &basin_clone,
            &stream_clone,
            vec![(Bytes::from_static(b"after-cutoff"), 3000)],
        )
        .await;
    });

    let all_records = collect_records_until_closed_advanced(
        &mut session,
        Duration::from_secs(3),
        VIRTUAL_TIME_STEP,
    )
    .await;

    append_handle.await.unwrap();

    let bodies = envelope_bodies(&all_records);
    assert_eq!(bodies, vec![b"initial".to_vec(), b"before-cutoff".to_vec()]);
}
