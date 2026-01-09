use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use s2_common::{
    read_extent::{ReadLimit, ReadUntil},
    record::{MeteredSize, StreamPosition},
    types::{
        config::{OptionalStreamConfig, OptionalTimestampingConfig, TimestampingMode},
        stream::{AppendInput, ReadEnd, ReadFrom, ReadSessionOutput, ReadStart},
    },
};
use s2_lite::backend::error::{CheckTailError, ReadError, UnwrittenError};

use super::common::*;

#[tokio::test]
async fn test_check_tail_scenarios() {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("check-tail", "stream", OptionalStreamConfig::default()).await;

    let empty_tail = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail on empty stream");
    assert_eq!(empty_tail, StreamPosition::MIN);

    let ack = append_payloads(&backend, &basin_name, &stream_name, &[b"test data"]).await;

    let tail_after_append = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail after append");
    assert_eq!(tail_after_append, ack.end);

    let missing_backend = create_backend().await;
    let missing_result = missing_backend
        .check_tail(
            test_basin_name("check-tail-missing"),
            test_stream_name("missing"),
        )
        .await;

    assert!(matches!(
        missing_result,
        Err(CheckTailError::BasinNotFound(_))
    ));
}

#[tokio::test]
async fn test_read_from_beginning() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-from-beginning",
        "read",
        OptionalStreamConfig::default(),
    )
    .await;

    append_repeat(&backend, &basin_name, &stream_name, b"test data", 5).await;

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::ZERO),
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert_eq!(records.len(), 5);
}

#[tokio::test]
async fn test_read_with_limit() {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("read-with-limit", "limit", OptionalStreamConfig::default())
            .await;

    append_repeat(&backend, &basin_name, &stream_name, b"test data", 10).await;

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Count(5),
        until: ReadUntil::Unbounded,
        wait: None,
    };

    let session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert!(records.len() <= 5);
}

#[tokio::test]
async fn test_read_unwritten_clamp_behavior() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-unwritten-clamp",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"record"]).await;

    // Without clamp: returns Unwritten error
    let start = ReadStart {
        from: ReadFrom::SeqNum(100),
        clamp: false,
    };
    let result = backend
        .read(
            basin_name.clone(),
            stream_name.clone(),
            start,
            ReadEnd::default(),
        )
        .await;
    assert!(matches!(result, Err(ReadError::Unwritten(_))));

    // With clamp: succeeds with empty result
    let start = ReadStart {
        from: ReadFrom::SeqNum(100),
        clamp: true,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::ZERO),
    };
    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("should succeed with clamp");
    let records = collect_records(&mut Box::pin(session)).await;
    assert!(records.is_empty());
}

#[tokio::test]
async fn test_read_at_tail_without_follow_returns_unwritten() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-at-tail-no-follow",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(vec![
            (Bytes::from_static(b"record 1"), 1000),
            (Bytes::from_static(b"record 2"), 2000),
        ]),
        match_seq_num: None,
        fencing_token: None,
    };
    let ack = backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("append");

    let starts = [
        ReadFrom::TailOffset(0),
        ReadFrom::SeqNum(ack.end.seq_num),
        ReadFrom::Timestamp(ack.end.timestamp + 1),
    ];
    let ends = [
        ReadEnd {
            limit: ReadLimit::Count(10),
            until: ReadUntil::Unbounded,
            wait: None,
        },
        ReadEnd {
            limit: ReadLimit::Count(10),
            until: ReadUntil::Unbounded,
            wait: Some(Duration::ZERO),
        },
        ReadEnd {
            limit: ReadLimit::Unbounded,
            until: ReadUntil::Timestamp(u64::MAX),
            wait: None,
        },
    ];

    for from in starts {
        for end in ends {
            for clamp in [false, true] {
                let start = ReadStart { from, clamp };
                let result = backend
                    .read(basin_name.clone(), stream_name.clone(), start, end)
                    .await;
                match result {
                    Err(ReadError::Unwritten(UnwrittenError(tail))) => {
                        assert_eq!(tail, ack.end);
                    }
                    Ok(_) => panic!(
                        "Expected Unwritten error for {from:?} / clamp={clamp} / {end:?}, got Ok"
                    ),
                    Err(e) => panic!(
                        "Expected Unwritten error for {from:?} / clamp={clamp} / {end:?}, got: {e:?}"
                    ),
                }
            }
        }
    }
}

#[tokio::test]
async fn test_read_from_tail_offset() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-tail-offset",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    for payload in ["record 1", "record 2", "record 3", "record 4", "record 5"] {
        append_payloads(&backend, &basin_name, &stream_name, &[payload.as_bytes()]).await;
    }

    let start = ReadStart {
        from: ReadFrom::TailOffset(2),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::ZERO),
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;
    let bodies = envelope_bodies(&records);

    assert_eq!(bodies, vec![b"record 4".to_vec(), b"record 5".to_vec()]);
}

#[tokio::test]
async fn test_read_timestamp_range() {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("read-timestamp", "range", OptionalStreamConfig::default()).await;

    let timestamped_records = vec![
        (Bytes::from_static(b"ts-100"), 100),
        (Bytes::from_static(b"ts-200"), 200),
        (Bytes::from_static(b"ts-300"), 300),
    ];

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(timestamped_records),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append records with timestamps");

    let start = ReadStart {
        from: ReadFrom::Timestamp(150),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Timestamp(300),
        wait: Some(Duration::ZERO),
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");

    let mut session = Box::pin(session);
    let records = loop {
        let output = tokio::time::timeout(Duration::from_secs(1), session.as_mut().next())
            .await
            .expect("Timed out waiting for read output");
        match output {
            Some(Ok(ReadSessionOutput::Batch(batch))) => {
                break batch.records.iter().cloned().collect::<Vec<_>>();
            }
            Some(Ok(ReadSessionOutput::Heartbeat(_))) => continue,
            Some(Err(e)) => panic!("Read error: {:?}", e),
            None => panic!("Read session ended without delivering expected batch"),
        }
    };
    drop(session);

    let bodies = envelope_bodies(&records);

    assert_eq!(bodies, vec![b"ts-200".to_vec()]);
    assert!(records.iter().all(|record| record.position.timestamp < 300));
}

#[tokio::test]
async fn test_read_from_timestamp_includes_duplicate_timestamps() {
    let stream_config = OptionalStreamConfig {
        timestamping: OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            ..Default::default()
        },
        ..Default::default()
    };

    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("read-dupe-timestamp", "stream", stream_config).await;

    let timestamp = 1000;
    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(vec![
            (Bytes::from_static(b"dup-1"), timestamp),
            (Bytes::from_static(b"dup-2"), timestamp),
            (Bytes::from_static(b"dup-3"), timestamp),
        ]),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append duplicate timestamp records");

    let start = ReadStart {
        from: ReadFrom::Timestamp(timestamp),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::ZERO),
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    let bodies = envelope_bodies(&records);
    assert_eq!(
        bodies,
        vec![b"dup-1".to_vec(), b"dup-2".to_vec(), b"dup-3".to_vec()]
    );
}

#[tokio::test]
async fn test_read_from_tail_times_out_without_new_data() {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("read-tail-wait", "idle", OptionalStreamConfig::default()).await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"seed data"]).await;

    let start = ReadStart {
        from: ReadFrom::TailOffset(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::from_millis(100)),
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    tokio::pin!(session);

    let first_output = tokio::time::timeout(Duration::from_secs(1), session.next())
        .await
        .expect("Timed out waiting for initial heartbeat")
        .expect("Read session ended unexpectedly");

    match first_output {
        Ok(ReadSessionOutput::Heartbeat(_)) => {}
        other => panic!("Unexpected first output: {:?}", other),
    }

    let second_output = tokio::time::timeout(Duration::from_secs(1), session.next())
        .await
        .expect("Timed out waiting for read session to finish");

    assert!(
        second_output.is_none(),
        "Read session produced unexpected additional output"
    );
}

#[tokio::test]
async fn test_read_with_bytes_limit() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-bytes-limit",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let large_body = vec![b'X'; 5000];
    for _i in 0..10 {
        append_payloads(&backend, &basin_name, &stream_name, &[&large_body]).await;
    }

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Bytes(15000),
        until: ReadUntil::Unbounded,
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert!(records.len() >= 2);
    assert!(records.len() <= 4);

    let total_bytes: usize = records.iter().map(|r| r.record.metered_size()).sum();
    assert!(total_bytes <= 20000);
}

#[tokio::test]
async fn test_read_with_count_or_bytes_limit_count_wins() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-count-or-bytes-count",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let small_body = vec![b'Y'; 100];
    for _i in 0..20 {
        append_payloads(&backend, &basin_name, &stream_name, &[&small_body]).await;
    }

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::from_count_and_bytes(Some(5), Some(1_000_000)),
        until: ReadUntil::Unbounded,
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert_eq!(records.len(), 5);
}

#[tokio::test]
async fn test_read_with_count_or_bytes_limit_bytes_wins() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-count-or-bytes-bytes",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let large_body = vec![b'Z'; 10000];
    for _i in 0..20 {
        append_payloads(&backend, &basin_name, &stream_name, &[&large_body]).await;
    }

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::from_count_and_bytes(Some(100), Some(35000)),
        until: ReadUntil::Unbounded,
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert!(records.len() >= 2);
    assert!(records.len() <= 5);
    assert!(records.len() < 100);

    let total_bytes: usize = records.iter().map(|r| r.record.metered_size()).sum();
    assert!(total_bytes <= 50000);
}

#[tokio::test]
async fn test_read_until_timestamp_basic() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-until-timestamp",
        "basic",
        OptionalStreamConfig::default(),
    )
    .await;

    let timestamped_records = vec![
        (Bytes::from_static(b"ts-1000"), 1000),
        (Bytes::from_static(b"ts-2000"), 2000),
        (Bytes::from_static(b"ts-3000"), 3000),
        (Bytes::from_static(b"ts-4000"), 4000),
        (Bytes::from_static(b"ts-5000"), 5000),
    ];

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(timestamped_records),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append timestamped records");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Timestamp(3500),
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    let bodies = envelope_bodies(&records);
    assert_eq!(
        bodies,
        vec![
            b"ts-1000".to_vec(),
            b"ts-2000".to_vec(),
            b"ts-3000".to_vec()
        ]
    );
    assert!(
        records
            .iter()
            .all(|record| record.position.timestamp < 3500)
    );
}

#[tokio::test]
async fn test_read_until_timestamp_exact_boundary() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-until-boundary",
        "exact",
        OptionalStreamConfig::default(),
    )
    .await;

    let timestamped_records = vec![
        (Bytes::from_static(b"ts-1000"), 1000),
        (Bytes::from_static(b"ts-2000"), 2000),
        (Bytes::from_static(b"ts-3000"), 3000),
        (Bytes::from_static(b"ts-4000"), 4000),
    ];

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(timestamped_records),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append timestamped records");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Timestamp(3000),
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    let bodies = envelope_bodies(&records);
    assert_eq!(bodies, vec![b"ts-1000".to_vec(), b"ts-2000".to_vec()]);
    assert!(
        records
            .iter()
            .all(|record| record.position.timestamp < 3000)
    );
}

#[tokio::test]
async fn test_read_until_timestamp_before_all_records() {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("read-until-before", "all", OptionalStreamConfig::default())
            .await;

    let timestamped_records = vec![
        (Bytes::from_static(b"ts-1000"), 1000),
        (Bytes::from_static(b"ts-2000"), 2000),
        (Bytes::from_static(b"ts-3000"), 3000),
    ];

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(timestamped_records),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append timestamped records");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Timestamp(500),
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert_eq!(records.len(), 0);
}

#[tokio::test]
async fn test_read_until_timestamp_after_all_records() {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("read-until-after", "all", OptionalStreamConfig::default()).await;

    let timestamped_records = vec![
        (Bytes::from_static(b"ts-1000"), 1000),
        (Bytes::from_static(b"ts-2000"), 2000),
        (Bytes::from_static(b"ts-3000"), 3000),
    ];

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(timestamped_records),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append timestamped records");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Timestamp(5000),
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    let bodies = envelope_bodies(&records);
    assert_eq!(
        bodies,
        vec![
            b"ts-1000".to_vec(),
            b"ts-2000".to_vec(),
            b"ts-3000".to_vec()
        ]
    );
}

#[tokio::test]
async fn test_read_until_with_count_limit_count_wins() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-until-count",
        "count-wins",
        OptionalStreamConfig::default(),
    )
    .await;

    let timestamped_records = vec![
        (Bytes::from_static(b"ts-1000"), 1000),
        (Bytes::from_static(b"ts-2000"), 2000),
        (Bytes::from_static(b"ts-3000"), 3000),
        (Bytes::from_static(b"ts-4000"), 4000),
        (Bytes::from_static(b"ts-5000"), 5000),
    ];

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(timestamped_records),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append timestamped records");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Count(2),
        until: ReadUntil::Timestamp(5000),
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert_eq!(records.len(), 2);
    let bodies = envelope_bodies(&records);
    assert_eq!(bodies, vec![b"ts-1000".to_vec(), b"ts-2000".to_vec()]);
}

#[tokio::test]
async fn test_read_until_with_count_limit_timestamp_wins() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-until-count",
        "timestamp-wins",
        OptionalStreamConfig::default(),
    )
    .await;

    let timestamped_records = vec![
        (Bytes::from_static(b"ts-1000"), 1000),
        (Bytes::from_static(b"ts-2000"), 2000),
        (Bytes::from_static(b"ts-3000"), 3000),
        (Bytes::from_static(b"ts-4000"), 4000),
        (Bytes::from_static(b"ts-5000"), 5000),
    ];

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(timestamped_records),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append timestamped records");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Count(10),
        until: ReadUntil::Timestamp(3500),
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert_eq!(records.len(), 3);
    let bodies = envelope_bodies(&records);
    assert_eq!(
        bodies,
        vec![
            b"ts-1000".to_vec(),
            b"ts-2000".to_vec(),
            b"ts-3000".to_vec()
        ]
    );
}

#[tokio::test]
async fn test_read_until_with_bytes_limit_bytes_wins() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-until-bytes",
        "bytes-wins",
        OptionalStreamConfig::default(),
    )
    .await;

    let large_body = vec![b'X'; 5000];
    let timestamped_records = vec![
        (Bytes::from(large_body.clone()), 1000),
        (Bytes::from(large_body.clone()), 2000),
        (Bytes::from(large_body.clone()), 3000),
        (Bytes::from(large_body.clone()), 4000),
        (Bytes::from(large_body), 5000),
    ];

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(timestamped_records),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append timestamped records");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Bytes(12000),
        until: ReadUntil::Timestamp(5000),
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert!(records.len() >= 2);
    assert!(records.len() <= 3);

    let total_bytes: usize = records.iter().map(|r| r.record.metered_size()).sum();
    assert!(total_bytes <= 15000);
}

#[tokio::test]
async fn test_read_until_with_bytes_limit_timestamp_wins() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-until-bytes",
        "timestamp-wins",
        OptionalStreamConfig::default(),
    )
    .await;

    let small_body = vec![b'Y'; 100];
    let timestamped_records = vec![
        (Bytes::from(small_body.clone()), 1000),
        (Bytes::from(small_body.clone()), 2000),
        (Bytes::from(small_body.clone()), 3000),
        (Bytes::from(small_body.clone()), 4000),
        (Bytes::from(small_body), 5000),
    ];

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(timestamped_records),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append timestamped records");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Bytes(100000),
        until: ReadUntil::Timestamp(3500),
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|record| record.position.timestamp < 3500)
    );
}

#[tokio::test]
async fn test_read_timestamp_range_with_from_and_until() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-timestamp-range",
        "from-until",
        OptionalStreamConfig::default(),
    )
    .await;

    let timestamped_records = vec![
        (Bytes::from_static(b"ts-500"), 500),
        (Bytes::from_static(b"ts-1500"), 1500),
        (Bytes::from_static(b"ts-2500"), 2500),
        (Bytes::from_static(b"ts-3500"), 3500),
        (Bytes::from_static(b"ts-4500"), 4500),
        (Bytes::from_static(b"ts-5500"), 5500),
    ];

    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(timestamped_records),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append timestamped records");

    let start = ReadStart {
        from: ReadFrom::Timestamp(2000),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Timestamp(4500),
        wait: None,
    };

    let session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;

    assert_eq!(records.len(), 2);
    let bodies = envelope_bodies(&records);
    assert_eq!(bodies, vec![b"ts-2500".to_vec(), b"ts-3500".to_vec()]);
    assert!(
        records
            .iter()
            .all(|record| record.position.timestamp >= 2000 && record.position.timestamp < 4500)
    );
}
