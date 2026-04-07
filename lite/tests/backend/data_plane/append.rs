use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use s2_common::{
    encryption::EncryptionConfig,
    read_extent::{ReadLimit, ReadUntil},
    record::FencingToken,
    types::{
        config::{BasinConfig, OptionalStreamConfig, OptionalTimestampingConfig, TimestampingMode},
        stream::{
            AppendInput, AppendRecord, AppendRecordBatch, ListStreamsRequest, ReadEnd, ReadFrom,
            ReadStart,
        },
    },
};
use s2_lite::backend::error::{AppendConditionFailedError, AppendError};

use super::common::*;

async fn assert_append_session_roundtrip(test_suffix: &str, encryption: &EncryptionConfig) {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream(test_suffix, "stream", OptionalStreamConfig::default()).await;

    let expected_bodies = vec![
        b"batch 1".to_vec(),
        b"batch 2".to_vec(),
        b"batch 3".to_vec(),
    ];
    let inputs = futures::stream::iter(
        expected_bodies
            .iter()
            .map(|body| AppendInput {
                records: create_test_record_batch(vec![Bytes::copy_from_slice(body)]),
                match_seq_num: None,
                fencing_token: None,
            })
            .collect::<Vec<_>>(),
    )
    .map(|input| encrypt_input_for_stream(input, &basin_name, &stream_name, encryption));

    let session = backend
        .clone()
        .append_session(basin_name.clone(), stream_name.clone(), inputs)
        .await
        .expect("Failed to create append session");
    tokio::pin!(session);

    let mut acks = Vec::new();
    while let Some(result) = session.next().await {
        acks.push(result.expect("Append should succeed"));
    }

    assert_eq!(acks.len(), expected_bodies.len());
    for (index, ack) in acks.iter().enumerate() {
        let index = index as u64;
        assert_eq!(ack.start.seq_num, index);
        assert_eq!(ack.end.seq_num, index + 1);
    }

    let tail = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, expected_bodies.len() as u64);

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::ZERO),
    };
    let read_session = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut read_session = Box::pin(read_session);
    let records =
        collect_records_with_encryption(&mut read_session, &basin_name, &stream_name, encryption)
            .await;
    assert_eq!(envelope_bodies(&records), expected_bodies);
}

#[tokio::test]
async fn test_append_multiple_records() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-multiple",
        "multiple",
        OptionalStreamConfig::default(),
    )
    .await;

    let ack = append_payloads(
        &backend,
        &basin_name,
        &stream_name,
        &[b"record 1", b"record 2", b"record 3"],
    )
    .await;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 3);
}

#[tokio::test]
async fn test_append_empty_batch() {
    let empty_batch: Result<AppendRecordBatch, _> = Vec::<AppendRecord>::new().try_into();

    assert!(
        empty_batch.is_err(),
        "Empty batches should be rejected by AppendRecordBatch"
    );
}

#[tokio::test]
async fn test_append_fencing_token_conditions() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-fencing",
        "mismatch",
        OptionalStreamConfig::default(),
    )
    .await;

    let matching_token = FencingToken::default();

    let matching_input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"matched token")]),
        match_seq_num: None,
        fencing_token: Some(matching_token.clone()),
    };

    let ack = backend
        .append(basin_name.clone(), stream_name.clone(), matching_input)
        .await
        .expect("Expected append to succeed with matching fencing token");

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let new_token: FencingToken = "updated-token".parse().unwrap();
    let command_batch: AppendRecordBatch = vec![create_fencing_command_record(new_token.clone())]
        .try_into()
        .unwrap();

    let command_input = AppendInput {
        records: command_batch,
        match_seq_num: Some(ack.end.seq_num),
        fencing_token: Some(matching_token.clone()),
    };

    let command_ack = backend
        .append(basin_name.clone(), stream_name.clone(), command_input)
        .await
        .expect("Expected fencing command to succeed");

    assert_eq!(command_ack.start.seq_num, ack.end.seq_num);
    assert_eq!(command_ack.end.seq_num, ack.end.seq_num + 1);

    let mismatched_input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"mismatched token")]),
        match_seq_num: Some(command_ack.end.seq_num),
        fencing_token: Some(matching_token.clone()),
    };

    let result = backend
        .append(basin_name.clone(), stream_name.clone(), mismatched_input)
        .await;

    let Err(AppendError::ConditionFailed(AppendConditionFailedError::FencingTokenMismatch {
        expected,
        actual,
        ..
    })) = result
    else {
        panic!("Expected fencing token mismatch");
    };
    assert_eq!(expected, matching_token);
    assert_eq!(actual, new_token);

    let refreshed_input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"updated token accepted")]),
        match_seq_num: Some(command_ack.end.seq_num),
        fencing_token: Some(new_token.clone()),
    };

    let refreshed_ack = backend
        .append(basin_name, stream_name, refreshed_input)
        .await
        .expect("Expected append to succeed with updated fencing token");

    assert_eq!(refreshed_ack.start.seq_num, command_ack.end.seq_num);
    assert_eq!(refreshed_ack.end.seq_num, command_ack.end.seq_num + 1);
}

#[tokio::test]
async fn test_encrypted_fencing_command_controls_stream_state() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-fencing-encrypted",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let encryption = aegis256_encryption();
    let matching_token = FencingToken::default();
    let new_token: FencingToken = "updated-token".parse().unwrap();

    let command_batch: AppendRecordBatch = vec![create_fencing_command_record(new_token.clone())]
        .try_into()
        .unwrap();
    let command_input = AppendInput {
        records: command_batch,
        match_seq_num: None,
        fencing_token: Some(matching_token.clone()),
    };
    let command_input =
        encrypt_input_for_stream(command_input, &basin_name, &stream_name, &encryption);

    let command_ack = backend
        .append(basin_name.clone(), stream_name.clone(), command_input)
        .await
        .expect("encrypted fencing command should succeed");

    let mismatched_input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"mismatched token")]),
        match_seq_num: Some(command_ack.end.seq_num),
        fencing_token: Some(matching_token.clone()),
    };
    let mismatched_input =
        encrypt_input_for_stream(mismatched_input, &basin_name, &stream_name, &encryption);

    let result = backend
        .append(basin_name.clone(), stream_name.clone(), mismatched_input)
        .await;

    let Err(AppendError::ConditionFailed(AppendConditionFailedError::FencingTokenMismatch {
        expected,
        actual,
        ..
    })) = result
    else {
        panic!("expected encrypted fencing token mismatch");
    };
    assert_eq!(expected, matching_token);
    assert_eq!(actual, new_token);

    let refreshed_input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"updated token accepted")]),
        match_seq_num: Some(command_ack.end.seq_num),
        fencing_token: Some(new_token.clone()),
    };
    let refreshed_input =
        encrypt_input_for_stream(refreshed_input, &basin_name, &stream_name, &encryption);

    let refreshed_ack = backend
        .append(basin_name, stream_name, refreshed_input)
        .await
        .expect("encrypted append should succeed with updated token");

    assert_eq!(refreshed_ack.start.seq_num, command_ack.end.seq_num);
    assert_eq!(refreshed_ack.end.seq_num, command_ack.end.seq_num + 1);
}

#[tokio::test]
async fn test_append_requires_timestamp() {
    let stream_config = OptionalStreamConfig {
        timestamping: OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            ..Default::default()
        },
        ..Default::default()
    };

    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("append-timestamp", "require", stream_config).await;

    let missing_timestamp = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"missing timestamp")]),
        match_seq_num: None,
        fencing_token: None,
    };

    let result = backend
        .append(basin_name.clone(), stream_name.clone(), missing_timestamp)
        .await;

    assert!(matches!(result, Err(AppendError::TimestampMissing(_))));

    let with_timestamp = AppendInput {
        records: create_test_record_batch_with_timestamps(vec![(
            Bytes::from_static(b"with timestamp"),
            123,
        )]),
        match_seq_num: None,
        fencing_token: None,
    };

    let ack = backend
        .append(basin_name, stream_name, with_timestamp)
        .await
        .expect("Expected append to succeed when timestamp is provided");

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);
}

#[tokio::test]
async fn test_append_with_seq_num_match() {
    let (backend, basin_name, stream_name) =
        setup_backend_with_stream("seq-num-match", "match", OptionalStreamConfig::default()).await;

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"first record")]),
        match_seq_num: Some(0),
        fencing_token: None,
    };

    let ack = backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append with matching seq_num");

    assert_eq!(ack.start.seq_num, 0);

    let input2 = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"second record")]),
        match_seq_num: Some(1),
        fencing_token: None,
    };

    let ack2 = backend
        .append(basin_name.clone(), stream_name.clone(), input2)
        .await
        .expect("Failed to append with matching seq_num");

    assert_eq!(ack2.start.seq_num, 1);
}

#[tokio::test]
async fn test_append_with_seq_num_mismatch() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "seq-num-mismatch",
        "mismatch",
        OptionalStreamConfig::default(),
    )
    .await;

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"first record")]),
        match_seq_num: Some(0),
        fencing_token: None,
    };

    backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append first record");

    let input2 = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"second record")]),
        match_seq_num: Some(0),
        fencing_token: None,
    };

    let result = backend
        .append(basin_name.clone(), stream_name.clone(), input2)
        .await;

    assert!(matches!(
        result,
        Err(AppendError::ConditionFailed(
            AppendConditionFailedError::SeqNumMismatch { .. }
        ))
    ));
}

#[tokio::test]
async fn test_append_session_basic() {
    let encryption = EncryptionConfig::Plain;
    assert_append_session_roundtrip("append-session-basic", &encryption).await;
}

#[tokio::test]
async fn test_append_session_basic_with_encryption() {
    let encryption = aegis256_encryption();
    assert_append_session_roundtrip("appsess-enc", &encryption).await;
}

#[tokio::test]
async fn test_append_session_auto_create_stream() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_append: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "append-session-auto-create", basin_config).await;
    let stream_name = test_stream_name("auto");

    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert_eq!(stream_list.values.len(), 0);

    let inputs = futures::stream::iter(vec![AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"auto created")]),
        match_seq_num: None,
        fencing_token: None,
    }]);

    let session = backend
        .clone()
        .append_session(basin_name.clone(), stream_name.clone(), inputs)
        .await
        .expect("Failed to create append session");
    tokio::pin!(session);

    let ack = session
        .next()
        .await
        .expect("Should have ack")
        .expect("Append should succeed");
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);
    assert!(session.next().await.is_none());

    let stream_list = backend
        .list_streams(basin_name, ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert_eq!(stream_list.values.len(), 1);
    assert_eq!(stream_list.values[0].name, stream_name);
}

#[tokio::test]
async fn test_append_session_empty() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-session-empty",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let inputs = futures::stream::iter(Vec::<AppendInput>::new());

    let session = backend
        .clone()
        .append_session(basin_name.clone(), stream_name.clone(), inputs)
        .await
        .expect("Failed to create append session");
    tokio::pin!(session);

    let ack = session.next().await;
    assert!(ack.is_none());

    let tail = backend
        .check_tail(basin_name, stream_name)
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 0);
}

#[tokio::test]
async fn test_append_session_multiple_records_per_batch() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-session-multi",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let inputs = futures::stream::iter(vec![
        AppendInput {
            records: create_test_record_batch(vec![
                Bytes::from_static(b"record 1"),
                Bytes::from_static(b"record 2"),
            ]),
            match_seq_num: None,
            fencing_token: None,
        },
        AppendInput {
            records: create_test_record_batch(vec![
                Bytes::from_static(b"record 3"),
                Bytes::from_static(b"record 4"),
                Bytes::from_static(b"record 5"),
            ]),
            match_seq_num: None,
            fencing_token: None,
        },
    ]);

    let session = backend
        .clone()
        .append_session(basin_name.clone(), stream_name.clone(), inputs)
        .await
        .expect("Failed to create append session");
    tokio::pin!(session);

    let ack1 = session
        .next()
        .await
        .expect("Should have first ack")
        .expect("First append should succeed");
    assert_eq!(ack1.start.seq_num, 0);
    assert_eq!(ack1.end.seq_num, 2);

    let ack2 = session
        .next()
        .await
        .expect("Should have second ack")
        .expect("Second append should succeed");
    assert_eq!(ack2.start.seq_num, 2);
    assert_eq!(ack2.end.seq_num, 5);

    let tail = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 5);

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::ZERO),
    };

    let read_session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut read_session = Box::pin(read_session);
    let records = collect_records(&mut read_session).await;

    assert_eq!(records.len(), 5);
}

#[tokio::test]
async fn test_append_session_with_seq_num_conditions() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-session-seqnum",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let inputs = futures::stream::iter(vec![
        AppendInput {
            records: create_test_record_batch(vec![Bytes::from_static(b"batch 1")]),
            match_seq_num: Some(0),
            fencing_token: None,
        },
        AppendInput {
            records: create_test_record_batch(vec![Bytes::from_static(b"batch 2")]),
            match_seq_num: Some(1),
            fencing_token: None,
        },
    ]);

    let session = backend
        .append_session(basin_name.clone(), stream_name.clone(), inputs)
        .await
        .expect("Failed to create append session");
    tokio::pin!(session);

    let ack1 = session
        .next()
        .await
        .expect("Should have first ack")
        .expect("First append should succeed");
    assert_eq!(ack1.start.seq_num, 0);

    let ack2 = session
        .next()
        .await
        .expect("Should have second ack")
        .expect("Second append should succeed");
    assert_eq!(ack2.start.seq_num, 1);
}

#[tokio::test]
async fn test_append_session_seq_num_mismatch() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-session-mismatch",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"existing data"]).await;

    let inputs = futures::stream::iter(vec![AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"batch 1")]),
        match_seq_num: Some(0),
        fencing_token: None,
    }]);

    let session = backend
        .append_session(basin_name, stream_name, inputs)
        .await
        .expect("Failed to create append session");
    tokio::pin!(session);

    let result = session.next().await.expect("Should have result");
    assert!(matches!(result, Err(AppendError::ConditionFailed(_))));
}

#[tokio::test]
async fn test_append_session_with_fencing_token() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-session-fence",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let token = FencingToken::default();

    let inputs = futures::stream::iter(vec![
        AppendInput {
            records: create_test_record_batch(vec![Bytes::from_static(b"batch 1")]),
            match_seq_num: None,
            fencing_token: Some(token.clone()),
        },
        AppendInput {
            records: create_test_record_batch(vec![Bytes::from_static(b"batch 2")]),
            match_seq_num: None,
            fencing_token: Some(token.clone()),
        },
    ]);

    let session = backend
        .append_session(basin_name, stream_name, inputs)
        .await
        .expect("Failed to create append session");
    tokio::pin!(session);

    let ack1 = session
        .next()
        .await
        .expect("Should have first ack")
        .expect("First append should succeed");
    assert_eq!(ack1.start.seq_num, 0);

    let ack2 = session
        .next()
        .await
        .expect("Should have second ack")
        .expect("Second append should succeed");
    assert_eq!(ack2.start.seq_num, 1);
}

#[tokio::test]
async fn test_append_session_large_batches() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-session-large",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let large_record = vec![0u8; 100_000];
    let batch_count = 50;

    let inputs = futures::stream::iter((0..batch_count).map(|_| AppendInput {
        records: create_test_record_batch(vec![Bytes::from(large_record.clone())]),
        match_seq_num: None,
        fencing_token: None,
    }));

    let session = backend
        .clone()
        .append_session(basin_name.clone(), stream_name.clone(), inputs)
        .await
        .expect("Failed to create append session");
    tokio::pin!(session);

    let mut ack_count = 0;
    while let Some(result) = session.next().await {
        result.expect("Append should succeed");
        ack_count += 1;
    }

    assert_eq!(ack_count, batch_count);

    let tail = backend
        .check_tail(basin_name, stream_name)
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, batch_count);
}

#[tokio::test]
async fn test_append_session_pipeline_preserves_ack_tail_and_read_order() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-session-pipeline-order",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let expected_bodies: Vec<_> = (0..32)
        .map(|i| format!("msg-{i:02}").into_bytes())
        .collect();
    let inputs: Vec<_> = expected_bodies
        .iter()
        .map(|body| AppendInput {
            records: create_test_record_batch(vec![Bytes::copy_from_slice(body)]),
            match_seq_num: None,
            fencing_token: None,
        })
        .collect();
    let inputs = futures::stream::iter(inputs);

    let session = backend
        .clone()
        .append_session(basin_name.clone(), stream_name.clone(), inputs)
        .await
        .expect("Failed to create append session");
    tokio::pin!(session);

    let mut acks = Vec::new();
    while let Some(result) = session.next().await {
        acks.push(result.expect("append should succeed"));
    }

    assert_eq!(acks.len(), expected_bodies.len());
    for (i, ack) in acks.iter().enumerate() {
        assert_eq!(ack.start.seq_num, i as u64);
        assert_eq!(ack.end.seq_num, i as u64 + 1);
        assert!(
            ack.tail.seq_num >= ack.end.seq_num,
            "tail must include acknowledged append"
        );
        if let Some(prev) = i.checked_sub(1).and_then(|idx| acks.get(idx)) {
            assert!(
                ack.tail.seq_num >= prev.tail.seq_num,
                "tail seq must be monotonic"
            );
        }
    }

    let tail = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, expected_bodies.len() as u64);

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: Some(Duration::ZERO),
    };
    let read_session = backend
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut read_session = Box::pin(read_session);
    let records = collect_records(&mut read_session).await;
    assert_eq!(records.len(), expected_bodies.len());
    assert_eq!(envelope_bodies(&records), expected_bodies);
}
