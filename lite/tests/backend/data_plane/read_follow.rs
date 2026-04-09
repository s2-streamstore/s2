use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use rstest::rstest;
use s2_common::{
    encryption::EncryptionConfig,
    read_extent::{ReadLimit, ReadUntil},
    types::{
        config::OptionalStreamConfig,
        stream::{AppendInput, ReadEnd, ReadFrom, ReadStart, StoredReadSessionOutput},
    },
};
use s2_lite::backend::FOLLOWER_MAX_LAG;

use super::common::*;

async fn run_follow_mode_receives_new_data_case(test_suffix: &str, encryption: &EncryptionConfig) {
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
    let encryption_clone = encryption.clone();

    let append_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        append_payloads_with_encryption(
            &backend_clone,
            &basin_clone,
            &stream_clone,
            &[b"follow-1"],
            &encryption_clone,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        append_payloads_with_encryption(
            &backend_clone,
            &basin_clone,
            &stream_clone,
            &[b"follow-2"],
            &encryption_clone,
        )
        .await;
    });

    let mut all_records = Vec::new();
    while all_records.len() < 3 {
        let output = {
            let mut pinned_session = session.as_mut();
            let next = pinned_session.next();
            tokio::pin!(next);
            let mut advanced = Duration::ZERO;

            loop {
                tokio::select! {
                    output = &mut next => break output,
                    () = tokio::time::advance(Duration::from_millis(100)) => {
                        advanced += Duration::from_millis(100);
                        assert!(
                            advanced <= Duration::from_secs(4),
                            "timed out waiting for follow-mode output"
                        );
                        tokio::task::yield_now().await;
                    }
                }
            }
        };

        match output {
            Some(Ok(StoredReadSessionOutput::Batch(batch))) => {
                let batch = decrypt_batch_for_stream(batch, &basin_name, &stream_name, encryption);
                all_records.extend(batch.records.iter().cloned());
            }
            Some(Ok(StoredReadSessionOutput::Heartbeat(_))) => {}
            Some(Err(e)) => panic!("Read error: {:?}", e),
            None => break,
        }
    }

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

#[tokio::test]
async fn test_follow_mode_wait_duration() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-wait-duration",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"initial"]).await;

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let wait_duration = Duration::from_millis(500);
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(wait_duration),
    };

    let start_time = tokio::time::Instant::now();
    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    let mut batch_count = 0;

    while let Some(result) = session.as_mut().next().await {
        match result {
            Ok(StoredReadSessionOutput::Batch(_)) => batch_count += 1,
            Ok(StoredReadSessionOutput::Heartbeat(_)) => {}
            Err(e) => panic!("Read error: {:?}", e),
        }
    }

    let elapsed = start_time.elapsed();
    assert_eq!(batch_count, 1);
    assert!(elapsed >= wait_duration, "Session ended too quickly");
    assert!(
        elapsed < wait_duration + Duration::from_secs(1),
        "Session took too long to end"
    );
}

#[tokio::test]
async fn test_follow_mode_heartbeats() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-heartbeat",
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
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::from_secs(1)),
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    let mut heartbeat_count = 0;
    let mut batch_count = 0;
    let timeout = Duration::from_secs(2);
    let start_time = tokio::time::Instant::now();

    while start_time.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(500), session.as_mut().next()).await {
            Ok(Some(Ok(StoredReadSessionOutput::Batch(_)))) => {
                batch_count += 1;
            }
            Ok(Some(Ok(StoredReadSessionOutput::Heartbeat(_)))) => {
                heartbeat_count += 1;
            }
            Ok(Some(Err(e))) => panic!("Read error: {:?}", e),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    assert_eq!(batch_count, 1);
    assert!(heartbeat_count > 0);
}

#[rstest]
#[case::plaintext("follow-new-data", EncryptionConfig::Plain)]
#[case::encrypted("follow-enc", aegis256_encryption())]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_follow_mode_receives_new_data(
    #[case] test_suffix: &str,
    #[case] encryption: EncryptionConfig,
) {
    run_follow_mode_receives_new_data_case(test_suffix, &encryption).await;
}

#[tokio::test]
async fn test_follow_mode_with_multiple_appends() {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("follow-multiple", "stream", OptionalStreamConfig::default())
            .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"initial"]).await;

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
        for i in 0..5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let payload = format!("follow-{}", i);
            append_payloads(
                &backend_clone,
                &basin_clone,
                &stream_clone,
                &[payload.as_bytes()],
            )
            .await;
        }
    });

    let mut all_records = Vec::new();
    let timeout = Duration::from_secs(4);
    let start_time = tokio::time::Instant::now();

    while start_time.elapsed() < timeout && all_records.len() < 6 {
        match tokio::time::timeout(Duration::from_millis(500), session.as_mut().next()).await {
            Ok(Some(Ok(StoredReadSessionOutput::Batch(batch)))) => {
                let batch = decrypt_plain_batch(batch);
                all_records.extend(batch.records.iter().cloned());
            }
            Ok(Some(Ok(StoredReadSessionOutput::Heartbeat(_)))) => continue,
            Ok(Some(Err(e))) => panic!("Read error: {:?}", e),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    append_handle.await.unwrap();

    let bodies = envelope_bodies(&all_records);
    assert_eq!(
        bodies,
        vec![
            b"initial".to_vec(),
            b"follow-0".to_vec(),
            b"follow-1".to_vec(),
            b"follow-2".to_vec(),
            b"follow-3".to_vec(),
            b"follow-4".to_vec(),
        ]
    );
}

#[tokio::test]
async fn test_follow_mode_broadcast_lag_falls_back_to_db_catchup() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-broadcast-lag",
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
        limit: ReadLimit::Count(message_count),
        until: ReadUntil::Unbounded,
        wait: Some(Duration::from_secs(3)),
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);

    let first_output = tokio::time::timeout(Duration::from_secs(1), session.as_mut().next())
        .await
        .expect("Timed out waiting for initial heartbeat")
        .expect("Read session ended unexpectedly")
        .expect("Read session error");
    assert!(matches!(
        first_output,
        StoredReadSessionOutput::Heartbeat(_)
    ));

    let mut expected = Vec::with_capacity(message_count);
    for i in 0..message_count {
        let payload = format!("msg-{}", i);
        expected.push(payload.as_bytes().to_vec());
        append_payloads(&backend, &basin_name, &stream_name, &[payload.as_bytes()]).await;
    }

    let records = tokio::time::timeout(Duration::from_secs(5), collect_records(&mut session))
        .await
        .expect("Timed out waiting for records");
    let bodies = envelope_bodies(&records);

    assert_eq!(bodies, expected);
}

#[tokio::test]
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

    let mut all_records = Vec::new();
    let timeout = Duration::from_secs(4);
    let start_time = tokio::time::Instant::now();

    while start_time.elapsed() < timeout && all_records.len() < 5 {
        match tokio::time::timeout(Duration::from_millis(500), session.as_mut().next()).await {
            Ok(Some(Ok(StoredReadSessionOutput::Batch(batch)))) => {
                let batch = decrypt_plain_batch(batch);
                all_records.extend(batch.records.iter().cloned());
            }
            Ok(Some(Ok(StoredReadSessionOutput::Heartbeat(_)))) => continue,
            Ok(Some(Err(e))) => panic!("Read error: {:?}", e),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

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

#[tokio::test]
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

    let mut all_records = Vec::new();
    let timeout = Duration::from_secs(4);
    let start_time = tokio::time::Instant::now();

    while start_time.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(500), session.as_mut().next()).await {
            Ok(Some(Ok(StoredReadSessionOutput::Batch(batch)))) => {
                let batch = decrypt_plain_batch(batch);
                all_records.extend(batch.records.iter().cloned());
            }
            Ok(Some(Ok(StoredReadSessionOutput::Heartbeat(_)))) => continue,
            Ok(Some(Err(e))) => panic!("Read error: {:?}", e),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    append_handle.await.unwrap();

    assert_eq!(all_records.len(), 3);
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

#[tokio::test]
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

    let mut all_records = Vec::new();
    let timeout = Duration::from_secs(3);
    let start_time = tokio::time::Instant::now();

    while start_time.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(500), session.as_mut().next()).await {
            Ok(Some(Ok(StoredReadSessionOutput::Batch(batch)))) => {
                let batch = decrypt_plain_batch(batch);
                all_records.extend(batch.records.iter().cloned());
            }
            Ok(Some(Ok(StoredReadSessionOutput::Heartbeat(_)))) => continue,
            Ok(Some(Err(e))) => panic!("Read error: {:?}", e),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    append_handle.await.unwrap();

    assert_eq!(all_records.len(), 2);
    let bodies = envelope_bodies(&all_records);
    assert_eq!(bodies, vec![b"follow-1".to_vec(), b"follow-2".to_vec()]);
}

#[tokio::test]
async fn test_follow_mode_with_timestamp_until() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "follow-timestamp-until",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let initial_records = vec![(Bytes::from_static(b"initial"), 1000)];
    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(initial_records),
        match_seq_num: None,
        fencing_token: None,
    };
    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append initial record");

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
        let timestamped_records = vec![(Bytes::from_static(b"before-cutoff"), 2000)];
        let input = AppendInput {
            records: create_test_record_batch_with_timestamps(timestamped_records),
            match_seq_num: None,
            fencing_token: None,
        };
        backend_clone
            .append(basin_clone.clone(), stream_clone.clone(), input)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;
        let timestamped_records = vec![(Bytes::from_static(b"after-cutoff"), 3000)];
        let input = AppendInput {
            records: create_test_record_batch_with_timestamps(timestamped_records),
            match_seq_num: None,
            fencing_token: None,
        };
        backend_clone
            .append(basin_clone, stream_clone, input)
            .await
            .unwrap();
    });

    let mut all_records = Vec::new();
    let timeout = Duration::from_secs(3);
    let start_time = tokio::time::Instant::now();

    while start_time.elapsed() < timeout && all_records.len() < 3 {
        match tokio::time::timeout(Duration::from_millis(500), session.as_mut().next()).await {
            Ok(Some(Ok(StoredReadSessionOutput::Batch(batch)))) => {
                let batch = decrypt_plain_batch(batch);
                all_records.extend(batch.records.iter().cloned());
            }
            Ok(Some(Ok(StoredReadSessionOutput::Heartbeat(_)))) => continue,
            Ok(Some(Err(e))) => panic!("Read error: {:?}", e),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    append_handle.await.unwrap();

    assert_eq!(all_records.len(), 2);
    let bodies = envelope_bodies(&all_records);
    assert_eq!(bodies, vec![b"initial".to_vec(), b"before-cutoff".to_vec()]);
}
