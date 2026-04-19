use bytes::Bytes;
use futures::StreamExt;
use rstest::rstest;
use s2_common::{
    encryption::EncryptionSpec,
    record::FencingToken,
    types::{
        basin::BasinName,
        config::{OptionalStreamConfig, OptionalTimestampingConfig, TimestampingMode},
        stream::{AppendInput, AppendRecordBatch, StreamName},
    },
};
use s2_lite::backend::{
    Backend,
    error::{AppendConditionFailedError, AppendError},
};

use super::common::*;

async fn assert_append_session_roundtrip(test_suffix: &str, encryption: &EncryptionSpec) {
    let (backend, basin_name, stream_name) =
        setup_backend_for_encryption_spec(test_suffix, "stream", encryption).await;

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
    );

    let session = append_session(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        Some(encryption),
        inputs,
    )
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

    let tail = check_tail(&backend, basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, expected_bodies.len() as u64);

    let (start, end) = read_all_bounds();
    let records =
        read_records_with_encryption(&backend, &basin_name, &stream_name, start, end, encryption)
            .await;
    assert_eq!(envelope_bodies(&records), expected_bodies);
}

async fn append_with_optional_encryption(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    input: AppendInput,
    encryption: Option<&EncryptionSpec>,
) -> Result<s2_common::types::stream::AppendAck, AppendError> {
    append(backend, basin.clone(), stream.clone(), input, encryption).await
}

#[derive(Clone, Copy)]
enum FencingBootstrap {
    SeedWithData,
    CommandFirst,
}

async fn issue_fencing_command(
    backend: &Backend,
    basin_name: &BasinName,
    stream_name: &StreamName,
    matching_token: &FencingToken,
    new_token: &FencingToken,
    encryption: Option<&EncryptionSpec>,
    bootstrap: FencingBootstrap,
) -> s2_common::types::stream::AppendAck {
    let command_match_seq_num = match bootstrap {
        FencingBootstrap::SeedWithData => {
            let matching_input = AppendInput {
                records: create_test_record_batch(vec![Bytes::from_static(b"matched token")]),
                match_seq_num: None,
                fencing_token: Some(matching_token.clone()),
            };

            let ack = append_with_optional_encryption(
                backend,
                basin_name,
                stream_name,
                matching_input,
                encryption,
            )
            .await
            .expect("append should succeed with matching fencing token");

            assert_eq!(ack.start.seq_num, 0);
            assert_eq!(ack.end.seq_num, 1);
            Some(ack.end.seq_num)
        }
        FencingBootstrap::CommandFirst => None,
    };

    let command_batch: AppendRecordBatch = vec![create_fencing_command_record(new_token.clone())]
        .try_into()
        .unwrap();
    let command_input = AppendInput {
        records: command_batch,
        match_seq_num: command_match_seq_num,
        fencing_token: Some(matching_token.clone()),
    };

    let command_ack = append_with_optional_encryption(
        backend,
        basin_name,
        stream_name,
        command_input,
        encryption,
    )
    .await
    .expect("fencing command should succeed");

    let expected_start = command_match_seq_num.unwrap_or(0);
    assert_eq!(command_ack.start.seq_num, expected_start);
    assert_eq!(command_ack.end.seq_num, expected_start + 1);
    command_ack
}

async fn assert_fencing_command_controls_stream_state(
    test_suffix: &str,
    encryption: Option<EncryptionSpec>,
    bootstrap: FencingBootstrap,
) {
    let (backend, basin_name, stream_name) = match encryption.as_ref() {
        Some(encryption) => {
            setup_backend_for_encryption_spec(test_suffix, "stream", encryption).await
        }
        None => {
            setup_backend_with_stream(test_suffix, "stream", OptionalStreamConfig::default()).await
        }
    };

    let encryption = encryption.as_ref();
    let matching_token = FencingToken::default();
    let new_token: FencingToken = "updated-token".parse().unwrap();

    let command_ack = issue_fencing_command(
        &backend,
        &basin_name,
        &stream_name,
        &matching_token,
        &new_token,
        encryption,
        bootstrap,
    )
    .await;

    let mismatched_input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"mismatched token")]),
        match_seq_num: Some(command_ack.end.seq_num),
        fencing_token: Some(matching_token.clone()),
    };

    let result = append_with_optional_encryption(
        &backend,
        &basin_name,
        &stream_name,
        mismatched_input,
        encryption,
    )
    .await;

    let Err(AppendError::ConditionFailed(AppendConditionFailedError::FencingTokenMismatch {
        expected,
        actual,
        ..
    })) = result
    else {
        panic!("expected fencing token mismatch");
    };
    assert_eq!(expected, matching_token);
    assert_eq!(actual, new_token);

    let refreshed_input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"updated token accepted")]),
        match_seq_num: Some(command_ack.end.seq_num),
        fencing_token: Some(new_token.clone()),
    };

    let refreshed_ack = append_with_optional_encryption(
        &backend,
        &basin_name,
        &stream_name,
        refreshed_input,
        encryption,
    )
    .await
    .expect("append should succeed with refreshed fencing token");

    assert_eq!(refreshed_ack.start.seq_num, command_ack.end.seq_num);
    assert_eq!(refreshed_ack.end.seq_num, command_ack.end.seq_num + 1);
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

#[rstest]
#[case::plaintext_seeded("append-fencing", None, FencingBootstrap::SeedWithData)]
#[case::encrypted_seeded(
    "append-fencing-encrypted",
    Some(aegis256_encryption_spec()),
    FencingBootstrap::SeedWithData
)]
#[case::encrypted_command_first(
    "fence-enc-first",
    Some(aegis256_encryption_spec()),
    FencingBootstrap::CommandFirst
)]
#[tokio::test]
async fn test_fencing_command_controls_stream_state(
    #[case] test_suffix: &str,
    #[case] encryption: Option<EncryptionSpec>,
    #[case] bootstrap: FencingBootstrap,
) {
    assert_fencing_command_controls_stream_state(test_suffix, encryption, bootstrap).await;
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

    let result = append(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        missing_timestamp,
        None,
    )
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

    let ack = append(&backend, basin_name, stream_name, with_timestamp, None)
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

    let ack = append(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        input,
        None,
    )
    .await
    .expect("Failed to append with matching seq_num");

    assert_eq!(ack.start.seq_num, 0);

    let input2 = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"second record")]),
        match_seq_num: Some(1),
        fencing_token: None,
    };

    let ack2 = append(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        input2,
        None,
    )
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

    append(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        input,
        None,
    )
    .await
    .expect("Failed to append first record");

    let input2 = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"second record")]),
        match_seq_num: Some(0),
        fencing_token: None,
    };

    let result = append(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        input2,
        None,
    )
    .await;

    assert!(matches!(
        result,
        Err(AppendError::ConditionFailed(
            AppendConditionFailedError::SeqNumMismatch { .. }
        ))
    ));
}

#[rstest]
#[case::plaintext("append-session-basic", EncryptionSpec::Plain)]
#[case::encrypted("appsess-enc", aegis256_encryption_spec())]
#[tokio::test]
async fn test_append_session_roundtrip(
    #[case] test_suffix: &str,
    #[case] encryption: EncryptionSpec,
) {
    assert_append_session_roundtrip(test_suffix, &encryption).await;
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

    let session = append_session(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        None,
        inputs,
    )
    .await
    .expect("Failed to create append session");
    tokio::pin!(session);

    let ack = session.next().await;
    assert!(ack.is_none());

    let tail = check_tail(&backend, basin_name, stream_name)
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

    let session = append_session(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        None,
        inputs,
    )
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

    let tail = check_tail(&backend, basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 5);

    let (start, end) = read_all_bounds();
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;

    assert_eq!(
        envelope_bodies(&records),
        vec![
            b"record 1".to_vec(),
            b"record 2".to_vec(),
            b"record 3".to_vec(),
            b"record 4".to_vec(),
            b"record 5".to_vec(),
        ]
    );
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

    let session = append_session(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        None,
        inputs,
    )
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

    let session = append_session(&backend, basin_name, stream_name, None, inputs)
        .await
        .expect("Failed to create append session");
    tokio::pin!(session);

    let result = session.next().await.expect("Should have result");
    assert!(matches!(result, Err(AppendError::ConditionFailed(_))));
}

#[tokio::test]
async fn test_append_session_stops_after_condition_failure() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "append-session-stop-after-error",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let inputs = futures::stream::iter(vec![
        AppendInput {
            records: create_test_record_batch(vec![Bytes::from_static(b"first")]),
            match_seq_num: Some(0),
            fencing_token: None,
        },
        AppendInput {
            records: create_test_record_batch(vec![Bytes::from_static(b"bad")]),
            match_seq_num: Some(0),
            fencing_token: None,
        },
        AppendInput {
            records: create_test_record_batch(vec![Bytes::from_static(b"after-error")]),
            match_seq_num: Some(1),
            fencing_token: None,
        },
    ]);

    let session = append_session(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        None,
        inputs,
    )
    .await
    .expect("Failed to create append session");
    tokio::pin!(session);

    let ack = session
        .next()
        .await
        .expect("Should have first ack")
        .expect("First append should succeed");
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let result = session
        .next()
        .await
        .expect("Should have a condition failure");
    assert!(matches!(
        result,
        Err(AppendError::ConditionFailed(
            AppendConditionFailedError::SeqNumMismatch { .. }
        ))
    ));
    assert!(session.next().await.is_none());

    let tail = check_tail(&backend, basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 1);

    let (start, end) = read_all_bounds();
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    assert_eq!(envelope_bodies(&records), vec![b"first".to_vec()]);
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

    let session = append_session(&backend, basin_name, stream_name, None, inputs)
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

    let inputs = futures::stream::iter((0..batch_count).map({
        let large_record = large_record.clone();
        move |_| AppendInput {
            records: create_test_record_batch(vec![Bytes::from(large_record.clone())]),
            match_seq_num: None,
            fencing_token: None,
        }
    }));

    let session = append_session(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        None,
        inputs,
    )
    .await
    .expect("Failed to create append session");
    tokio::pin!(session);

    let mut ack_count = 0;
    while let Some(result) = session.next().await {
        result.expect("Append should succeed");
        ack_count += 1;
    }

    assert_eq!(ack_count, batch_count);

    let tail = check_tail(&backend, basin_name, stream_name)
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

    let session = append_session(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        None,
        inputs,
    )
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

    let tail = check_tail(&backend, basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, expected_bodies.len() as u64);

    let (start, end) = read_all_bounds();
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    assert_eq!(envelope_bodies(&records), expected_bodies);
}
