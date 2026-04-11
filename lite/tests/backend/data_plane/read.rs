use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use rstest::rstest;
use s2_common::{
    encryption::{EncryptionMode, EncryptionSpec},
    read_extent::{ReadLimit, ReadUntil},
    record::{MeteredSize, RecordDecryptionError, StreamPosition},
    types::{
        basin::BasinName,
        config::{OptionalStreamConfig, OptionalTimestampingConfig, TimestampingMode},
        stream::{ReadEnd, ReadFrom, ReadStart, StoredReadSessionOutput, StreamName},
    },
};
use s2_lite::backend::{
    Backend,
    error::{CheckTailError, ReadError, UnwrittenError},
};

use super::common::*;

#[derive(Clone, Copy, Debug)]
enum TailStartCase {
    TailOffset,
    SeqNumAtEnd,
    TimestampAfterEnd,
}

#[derive(Clone, Copy, Debug)]
enum TailEndCase {
    CountNoWait,
    CountZeroWait,
    TimestampMax,
}

fn tail_read_from(case: TailStartCase, tail: &StreamPosition) -> ReadFrom {
    match case {
        TailStartCase::TailOffset => ReadFrom::TailOffset(0),
        TailStartCase::SeqNumAtEnd => ReadFrom::SeqNum(tail.seq_num),
        TailStartCase::TimestampAfterEnd => ReadFrom::Timestamp(tail.timestamp + 1),
    }
}

fn tail_read_end(case: TailEndCase) -> ReadEnd {
    match case {
        TailEndCase::CountNoWait => ReadEnd {
            limit: ReadLimit::Count(10),
            until: ReadUntil::Unbounded,
            wait: None,
        },
        TailEndCase::CountZeroWait => ReadEnd {
            limit: ReadLimit::Count(10),
            until: ReadUntil::Unbounded,
            wait: Some(Duration::ZERO),
        },
        TailEndCase::TimestampMax => ReadEnd {
            limit: ReadLimit::Unbounded,
            until: ReadUntil::Timestamp(u64::MAX),
            wait: None,
        },
    }
}

fn body_vecs(bodies: &[&[u8]]) -> Vec<Vec<u8>> {
    bodies.iter().map(|body| body.to_vec()).collect()
}

fn timestamped_payloads(records: &[(&[u8], u64)]) -> Vec<(Bytes, u64)> {
    records
        .iter()
        .map(|(body, timestamp)| (Bytes::copy_from_slice(body), *timestamp))
        .collect()
}

fn client_timestamp_stream_config() -> OptionalStreamConfig {
    OptionalStreamConfig {
        timestamping: OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn seed_timestamped_stream(
    basin_suffix: &str,
    stream_suffix: &str,
    stream_config: OptionalStreamConfig,
    records: &[(&[u8], u64)],
) -> (Backend, BasinName, StreamName) {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream(basin_suffix, stream_suffix, stream_config).await;
    append_timestamped_payloads(
        &backend,
        &basin_name,
        &stream_name,
        timestamped_payloads(records),
    )
    .await;
    (backend, basin_name, stream_name)
}

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

    let (start, end) = read_all_bounds();
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;

    assert_eq!(envelope_bodies(&records), vec![b"test data".to_vec(); 5]);
}

#[tokio::test]
async fn test_read_encrypted_roundtrip() {
    let encryption = aegis256_encryption();
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("read-enc", "stream", OptionalStreamConfig::default()).await;

    append_payloads_with_encryption(
        &backend,
        &basin_name,
        &stream_name,
        &[b"secret-1", b"secret-2"],
        &encryption,
    )
    .await;

    let (start, end) = read_all_bounds();
    let records =
        read_records_with_encryption(&backend, &basin_name, &stream_name, start, end, &encryption)
            .await;
    assert_eq!(
        envelope_bodies(&records),
        vec![b"secret-1".to_vec(), b"secret-2".to_vec()]
    );
}

#[tokio::test]
async fn test_read_encrypted_batch_rejects_plaintext_decryption() {
    let encryption = aegis256_encryption();
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-enc-plain-mismatch",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads_with_encryption(
        &backend,
        &basin_name,
        &stream_name,
        &[b"secret-1", b"secret-2"],
        &encryption,
    )
    .await;

    let batch = first_stored_batch(&backend, &basin_name, &stream_name).await;
    assert!(matches!(
        batch.decrypt(&EncryptionSpec::Plain, &[]),
        Err(RecordDecryptionError::ModeMismatch {
            expected: EncryptionMode::Plain,
            actual,
        }) if actual == EncryptionMode::Aegis256
    ));
}

#[tokio::test]
async fn test_read_with_limit() {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("read-with-limit", "limit", OptionalStreamConfig::default())
            .await;

    let expected_bodies: Vec<_> = (0..10)
        .map(|i| format!("record-{i}").into_bytes())
        .collect();
    for body in &expected_bodies {
        append_payloads(&backend, &basin_name, &stream_name, &[body.as_slice()]).await;
    }

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Count(5),
        until: ReadUntil::Unbounded,
        wait: None,
    };

    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;

    assert_eq!(
        envelope_bodies(&records),
        expected_bodies.into_iter().take(5).collect::<Vec<_>>()
    );
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
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    assert!(records.is_empty());
}

#[rstest]
#[case::tail_offset_no_wait(TailStartCase::TailOffset, TailEndCase::CountNoWait, false)]
#[case::tail_seq_num_zero_wait(TailStartCase::SeqNumAtEnd, TailEndCase::CountZeroWait, false)]
#[case::tail_timestamp_max(TailStartCase::TimestampAfterEnd, TailEndCase::TimestampMax, false)]
#[case::timestamp_after_end_with_clamp(
    TailStartCase::TimestampAfterEnd,
    TailEndCase::CountNoWait,
    true
)]
#[tokio::test]
async fn test_read_at_tail_without_follow_returns_unwritten(
    #[case] start_case: TailStartCase,
    #[case] end_case: TailEndCase,
    #[case] clamp: bool,
) {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-at-tail-no-follow",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let ack = append_timestamped_payloads(
        &backend,
        &basin_name,
        &stream_name,
        vec![
            (Bytes::from_static(b"record 1"), 1000),
            (Bytes::from_static(b"record 2"), 2000),
        ],
    )
    .await;

    let start = ReadStart {
        from: tail_read_from(start_case, &ack.end),
        clamp,
    };
    let end = tail_read_end(end_case);
    let result = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await;

    match result {
        Err(ReadError::Unwritten(UnwrittenError(tail))) => {
            assert_eq!(tail, ack.end);
        }
        Ok(_) => panic!(
            "Expected Unwritten error for {start_case:?} / clamp={clamp} / {end_case:?}, got Ok"
        ),
        Err(e) => panic!(
            "Expected Unwritten error for {start_case:?} / clamp={clamp} / {end_case:?}, got: {e:?}"
        ),
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

    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    let bodies = envelope_bodies(&records);

    assert_eq!(bodies, vec![b"record 4".to_vec(), b"record 5".to_vec()]);
}

#[tokio::test]
async fn test_read_from_timestamp_includes_duplicate_timestamps() {
    let timestamp = 1000;
    let (backend, basin_name, stream_name) = seed_timestamped_stream(
        "read-dupe-timestamp",
        "stream",
        client_timestamp_stream_config(),
        &[
            (b"dup-1", timestamp),
            (b"dup-2", timestamp),
            (b"dup-3", timestamp),
        ],
    )
    .await;

    let start = ReadStart {
        from: ReadFrom::Timestamp(timestamp),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::ZERO),
    };

    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;

    assert_eq!(
        envelope_bodies(&records),
        body_vecs(&[b"dup-1", b"dup-2", b"dup-3"])
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
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

    let mut session = open_read_session(&backend, &basin_name, &stream_name, start, end).await;
    let probe_step = Duration::from_millis(1);

    let started = tokio::time::Instant::now();
    let outputs =
        collect_outputs_until_closed_advanced(&mut session, Duration::from_secs(1), probe_step)
            .await;

    assert!(!outputs.outputs.is_empty());
    assert!(
        outputs
            .outputs
            .iter()
            .all(|output| matches!(output, StoredReadSessionOutput::Heartbeat(_)))
    );
    let wait = Duration::from_millis(100);
    assert!(outputs.closed_at >= started + wait);
    assert!(outputs.closed_at <= started + wait + probe_step);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_read_from_tail_wait_is_reset_by_new_data() {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("read-tail-reset", "stream", OptionalStreamConfig::default())
            .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"seed data"]).await;

    let wait = Duration::from_millis(100);
    let follow_delay = Duration::from_millis(40);
    let probe_step = Duration::from_millis(1);
    let start = ReadStart {
        from: ReadFrom::TailOffset(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(wait),
    };

    let mut session = open_read_session(&backend, &basin_name, &stream_name, start, end).await;

    let first = session
        .as_mut()
        .next()
        .await
        .expect("session should enter follow mode")
        .expect("session should not error");
    assert!(matches!(first, StoredReadSessionOutput::Heartbeat(_)));

    advance_time(follow_delay).await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"follow data"]).await;

    let follow = session
        .as_mut()
        .next()
        .await
        .expect("session should yield the live tail batch")
        .expect("session should not error");
    let reset_at = tokio::time::Instant::now();
    let StoredReadSessionOutput::Batch(batch) = follow else {
        panic!("expected a batch after appending past tail");
    };
    let batch = decrypt_plain_batch(batch);
    assert_eq!(
        envelope_bodies(&batch.records),
        vec![b"follow data".to_vec()]
    );

    let outputs = collect_outputs_until_closed_advanced(
        &mut session,
        wait + Duration::from_secs(1),
        probe_step,
    )
    .await;

    assert!(outputs.closed_at >= reset_at + wait);
    assert!(outputs.closed_at <= reset_at + wait + probe_step);
}

#[tokio::test]
async fn test_read_with_bytes_limit_exact_fit() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-bytes-limit",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(
        &backend,
        &basin_name,
        &stream_name,
        &[b"record-1", b"record-2", b"record-3"],
    )
    .await;

    let stored_batch = first_stored_batch(&backend, &basin_name, &stream_name).await;
    let exact_limit =
        stored_batch.records[0].metered_size() + stored_batch.records[1].metered_size();

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Bytes(exact_limit),
        until: ReadUntil::Unbounded,
        wait: None,
    };

    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    assert_eq!(
        envelope_bodies(&records),
        vec![b"record-1".to_vec(), b"record-2".to_vec()]
    );
}

#[tokio::test]
async fn test_read_with_bytes_limit_smaller_than_first_record_returns_empty() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-bytes-too-small",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"oversized"]).await;

    let stored_batch = first_stored_batch(&backend, &basin_name, &stream_name).await;
    let first_size = stored_batch.records[0].metered_size();
    assert!(first_size > 0);

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Bytes(first_size - 1),
        until: ReadUntil::Unbounded,
        wait: None,
    };

    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    assert!(records.is_empty());
}

#[tokio::test]
async fn test_read_with_count_or_bytes_limit_count_wins() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-count-or-bytes-count",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let expected_bodies: Vec<_> = (0..20).map(|i| format!("count-{i}").into_bytes()).collect();
    for body in &expected_bodies {
        append_payloads(&backend, &basin_name, &stream_name, &[body.as_slice()]).await;
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

    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;

    assert_eq!(
        envelope_bodies(&records),
        expected_bodies.into_iter().take(5).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_read_with_count_or_bytes_limit_bytes_wins() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-count-or-bytes-bytes",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(
        &backend,
        &basin_name,
        &stream_name,
        &[b"slot-0", b"slot-1", b"slot-2", b"slot-3", b"slot-4"],
    )
    .await;

    let stored_batch = first_stored_batch(&backend, &basin_name, &stream_name).await;
    let per_record_bytes = stored_batch.records[0].metered_size();

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::from_count_and_bytes(Some(100), Some(per_record_bytes * 3)),
        until: ReadUntil::Unbounded,
        wait: None,
    };

    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    assert_eq!(
        envelope_bodies(&records),
        vec![b"slot-0".to_vec(), b"slot-1".to_vec(), b"slot-2".to_vec()]
    );
}

#[rstest]
#[case::before("read-until-before", 500, vec![])]
#[case::exact_duplicate_boundary(
    "read-until-exact-duplicate-boundary",
    2000,
    vec![b"ts-1000".to_vec()]
)]
#[case::after(
    "read-until-after",
    5000,
    vec![
        b"ts-1000".to_vec(),
        b"ts-2000-a".to_vec(),
        b"ts-2000-b".to_vec(),
        b"ts-3000".to_vec(),
    ]
)]
#[tokio::test]
async fn test_read_until_timestamp_boundaries(
    #[case] suffix: &str,
    #[case] cutoff: u64,
    #[case] expected: Vec<Vec<u8>>,
) {
    let boundary_records = [
        (b"ts-1000".as_ref(), 1000),
        (b"ts-2000-a".as_ref(), 2000),
        (b"ts-2000-b".as_ref(), 2000),
        (b"ts-3000".as_ref(), 3000),
    ];

    let (backend, basin_name, stream_name) = seed_timestamped_stream(
        suffix,
        "boundary",
        client_timestamp_stream_config(),
        &boundary_records,
    )
    .await;

    let records = read_records(
        &backend,
        &basin_name,
        &stream_name,
        ReadStart {
            from: ReadFrom::SeqNum(0),
            clamp: false,
        },
        ReadEnd {
            limit: ReadLimit::Unbounded,
            until: ReadUntil::Timestamp(cutoff),
            wait: None,
        },
    )
    .await;

    assert_eq!(envelope_bodies(&records), expected, "case {suffix}");
    assert!(
        records
            .iter()
            .all(|record| record.position().timestamp < cutoff),
        "case {suffix}"
    );
}

#[tokio::test]
async fn test_read_until_with_additional_limits() {
    let timestamped_records = [
        (b"ts-1000".as_ref(), 1000),
        (b"ts-2000".as_ref(), 2000),
        (b"ts-3000".as_ref(), 3000),
        (b"ts-4000".as_ref(), 4000),
        (b"ts-5000".as_ref(), 5000),
    ];
    let (backend, basin_name, stream_name) = seed_timestamped_stream(
        "read-until-limits",
        "stream",
        client_timestamp_stream_config(),
        &timestamped_records,
    )
    .await;

    let stored_batch = first_stored_batch(&backend, &basin_name, &stream_name).await;
    let per_record_bytes = stored_batch.records[0].metered_size();
    let cases = vec![
        (
            "count wins",
            ReadLimit::Count(2),
            5_000,
            body_vecs(&[b"ts-1000", b"ts-2000"]),
        ),
        (
            "timestamp beats count",
            ReadLimit::Count(10),
            3_500,
            body_vecs(&[b"ts-1000", b"ts-2000", b"ts-3000"]),
        ),
        (
            "bytes win",
            ReadLimit::Bytes(per_record_bytes * 2),
            5_000,
            body_vecs(&[b"ts-1000", b"ts-2000"]),
        ),
        (
            "timestamp beats bytes",
            ReadLimit::Bytes(per_record_bytes * 100),
            3_500,
            body_vecs(&[b"ts-1000", b"ts-2000", b"ts-3000"]),
        ),
    ];

    for (label, limit, cutoff, expected) in cases {
        let records = read_records(
            &backend,
            &basin_name,
            &stream_name,
            ReadStart {
                from: ReadFrom::SeqNum(0),
                clamp: false,
            },
            ReadEnd {
                limit,
                until: ReadUntil::Timestamp(cutoff),
                wait: None,
            },
        )
        .await;

        assert_eq!(envelope_bodies(&records), expected, "{label}");
    }
}

#[tokio::test]
async fn test_read_timestamp_range_with_from_and_until() {
    let timestamped_records = [
        (b"ts-500".as_ref(), 500),
        (b"ts-2000-a".as_ref(), 2000),
        (b"ts-2000-b".as_ref(), 2000),
        (b"ts-2500".as_ref(), 2500),
        (b"ts-3500".as_ref(), 3500),
        (b"ts-4500".as_ref(), 4500),
        (b"ts-5500".as_ref(), 5500),
    ];
    let (backend, basin_name, stream_name) = seed_timestamped_stream(
        "read-timestamp-range",
        "from-until",
        client_timestamp_stream_config(),
        &timestamped_records,
    )
    .await;

    let records = read_records(
        &backend,
        &basin_name,
        &stream_name,
        ReadStart {
            from: ReadFrom::Timestamp(2000),
            clamp: false,
        },
        ReadEnd {
            limit: ReadLimit::Unbounded,
            until: ReadUntil::Timestamp(4500),
            wait: None,
        },
    )
    .await;

    assert_eq!(
        envelope_bodies(&records),
        body_vecs(&[b"ts-2000-a", b"ts-2000-b", b"ts-2500", b"ts-3500"])
    );
    assert!(records.iter().all(|record| {
        let position = record.position();
        position.timestamp >= 2000 && position.timestamp < 4500
    }));
}
