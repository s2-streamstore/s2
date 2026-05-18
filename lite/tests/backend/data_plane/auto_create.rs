use std::time::Duration;

use bytes::Bytes;
use s2_common::{
    encryption::EncryptionAlgorithm,
    read_extent::{ReadLimit, ReadUntil},
    record::StreamPosition,
    types::{
        config::BasinConfig,
        stream::{AppendInput, ListStreamsRequest, ReadEnd, ReadFrom, ReadStart},
    },
};
use s2_lite::backend::error::{AppendError, CheckTailError, ReadError};

use super::common::*;

const MAX_AUTO_CREATE_ATTEMPTS: usize = 50;

async fn assert_stream_count(
    backend: &s2_lite::backend::Backend,
    basin_name: &s2_common::types::basin::BasinName,
    expected: usize,
) {
    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert_eq!(stream_list.values.len(), expected);
}

async fn assert_stream_cipher(
    backend: &s2_lite::backend::Backend,
    basin_name: &s2_common::types::basin::BasinName,
    stream_name: &s2_common::types::stream::StreamName,
    expected: Option<EncryptionAlgorithm>,
) {
    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert_eq!(stream_list.values.len(), 1);
    assert_eq!(stream_list.values[0].name.as_ref(), stream_name.as_ref());
    assert_eq!(stream_list.values[0].cipher, expected);
}

#[tokio::test]
async fn test_backend_append_auto_creates_stream() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_append: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "backend-auto-create-append", basin_config).await;
    let stream_name = test_stream_name("missing");

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"should fail")]),
        match_seq_num: None,
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
    .expect("Failed to append to auto-created stream");

    assert_eq!(ack.end.seq_num, 1);
    assert_stream_count(&backend, &basin_name, 1).await;
    let tail = check_tail(&backend, basin_name, stream_name)
        .await
        .expect("Failed to check tail on auto-created stream");
    assert_eq!(tail.seq_num, 1);
}

#[tokio::test]
async fn test_backend_append_auto_creates_stream_with_basin_cipher() {
    let backend = create_backend().await;
    let mut basin_config = basin_config_with_stream_cipher(EncryptionAlgorithm::Aegis256);
    basin_config.create_stream_on_append = true;
    let basin_name = create_test_basin(
        &backend,
        "backend-auto-create-append-encrypted",
        basin_config,
    )
    .await;
    let stream_name = test_stream_name("missing");
    let encryption = aegis256_encryption_spec();

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"secret")]),
        match_seq_num: None,
        fencing_token: None,
    };

    let ack = append(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        input,
        Some(&encryption),
    )
    .await
    .expect("Failed to append to auto-created encrypted stream");

    assert_eq!(ack.end.seq_num, 1);
    assert_stream_count(&backend, &basin_name, 1).await;
    assert_stream_cipher(
        &backend,
        &basin_name,
        &stream_name,
        Some(EncryptionAlgorithm::Aegis256),
    )
    .await;

    let (start, end) = read_all_bounds();
    let records =
        read_records_with_encryption(&backend, &basin_name, &stream_name, start, end, &encryption)
            .await;
    assert_eq!(envelope_bodies(&records), vec![b"secret".to_vec()]);
}

#[tokio::test]
async fn test_backend_append_without_auto_create_returns_not_found() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "backend-no-auto-create-append",
        BasinConfig::default(),
    )
    .await;
    let stream_name = test_stream_name("missing");

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"should fail")]),
        match_seq_num: None,
        fencing_token: None,
    };

    let result = append(&backend, basin_name.clone(), stream_name, input, None).await;

    assert!(matches!(result, Err(AppendError::StreamNotFound(_))));
    assert_stream_count(&backend, &basin_name, 0).await;
}

#[tokio::test]
async fn test_backend_read_auto_creates_stream() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_read: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "backend-auto-create-read", basin_config).await;
    let stream_name = test_stream_name("missing");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let _session = open_read_session(
        &backend,
        &basin_name,
        &stream_name,
        start,
        ReadEnd::default(),
    )
    .await;
    assert_stream_count(&backend, &basin_name, 1).await;
    let tail = check_tail(&backend, basin_name, stream_name)
        .await
        .expect("Failed to check tail on auto-created read stream");
    assert_eq!(tail.seq_num, 0);
}

#[tokio::test]
async fn test_backend_read_without_auto_create_returns_not_found() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "backend-no-auto-create-read",
        BasinConfig::default(),
    )
    .await;
    let stream_name = test_stream_name("missing");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let result = try_open_read_session(
        &backend,
        &basin_name,
        &stream_name,
        start,
        ReadEnd::default(),
    )
    .await;

    assert!(matches!(result, Err(ReadError::StreamNotFound(_))));
    assert_stream_count(&backend, &basin_name, 0).await;
}

#[tokio::test]
async fn test_backend_check_tail_auto_creates_stream() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_read: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "backend-auto-create-tail", basin_config).await;
    let stream_name = test_stream_name("missing");

    let tail = check_tail(&backend, basin_name.clone(), stream_name)
        .await
        .expect("Failed to check tail on auto-created stream");

    assert_eq!(tail.seq_num, 0);
    assert_stream_count(&backend, &basin_name, 1).await;
}

#[tokio::test]
async fn test_backend_check_tail_auto_creates_stream_with_basin_cipher() {
    let backend = create_backend().await;
    let mut basin_config = basin_config_with_stream_cipher(EncryptionAlgorithm::Aegis256);
    basin_config.create_stream_on_read = true;
    let basin_name =
        create_test_basin(&backend, "backend-auto-create-tail-encrypted", basin_config).await;
    let stream_name = test_stream_name("missing");

    let tail = check_tail(&backend, basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail on auto-created encrypted stream");

    assert_eq!(tail, StreamPosition::MIN);
    assert_stream_count(&backend, &basin_name, 1).await;
    assert_stream_cipher(
        &backend,
        &basin_name,
        &stream_name,
        Some(EncryptionAlgorithm::Aegis256),
    )
    .await;
}

#[tokio::test]
async fn test_backend_check_tail_without_auto_create_returns_not_found() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "backend-no-auto-create-tail",
        BasinConfig::default(),
    )
    .await;
    let stream_name = test_stream_name("missing");

    let result = check_tail(&backend, basin_name.clone(), stream_name).await;

    assert!(matches!(result, Err(CheckTailError::StreamNotFound(_))));
    assert_stream_count(&backend, &basin_name, 0).await;
}

#[tokio::test]
async fn test_backend_append_auto_create_is_race_safe() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "backend-auto-create-append-race",
        BasinConfig {
            create_stream_on_append: true,
            ..Default::default()
        },
    )
    .await;
    let stream_name = test_stream_name("missing");
    let expected_bodies: Vec<_> = (0..10).map(|i| format!("racer-{i}").into_bytes()).collect();
    let mut handles = Vec::new();

    for body in &expected_bodies {
        let backend = backend.clone();
        let basin_name = basin_name.clone();
        let stream_name = stream_name.clone();
        let body = body.clone();
        handles.push(tokio::spawn(async move {
            let input = AppendInput {
                records: create_test_record_batch(vec![Bytes::from(body)]),
                match_seq_num: None,
                fencing_token: None,
            };
            for _ in 0..MAX_AUTO_CREATE_ATTEMPTS {
                match append(
                    &backend,
                    basin_name.clone(),
                    stream_name.clone(),
                    input.clone(),
                    None,
                )
                .await
                {
                    Ok(ack) => return Ok(ack),
                    Err(AppendError::TransactionConflict(_))
                    | Err(AppendError::StreamNotFound(_)) => {
                        tokio::task::yield_now().await;
                    }
                    Err(err) => return Err(err),
                }
            }
            append(&backend, basin_name, stream_name, input, None).await
        }));
    }

    for handle in handles {
        handle
            .await
            .unwrap()
            .expect("auto-create append racer should succeed");
    }

    let tail = check_tail(&backend, basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 10);
    assert_stream_count(&backend, &basin_name, 1).await;

    let (start, end) = read_all_bounds();
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    let mut actual_bodies = envelope_bodies(&records);
    let mut expected_bodies = expected_bodies;
    actual_bodies.sort();
    expected_bodies.sort();
    assert_eq!(actual_bodies, expected_bodies);
}

#[tokio::test]
async fn test_backend_read_auto_create_is_race_safe() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "backend-auto-create-read-race",
        BasinConfig {
            create_stream_on_read: true,
            ..Default::default()
        },
    )
    .await;
    let stream_name = test_stream_name("missing");
    let mut handles = Vec::new();

    for _ in 0..10 {
        let backend = backend.clone();
        let basin_name = basin_name.clone();
        let stream_name = stream_name.clone();
        handles.push(tokio::spawn(async move {
            let start = ReadStart {
                from: ReadFrom::SeqNum(0),
                clamp: false,
            };
            let end = ReadEnd {
                limit: ReadLimit::Unbounded,
                until: ReadUntil::Unbounded,
                wait: Some(Duration::ZERO),
            };
            for _ in 0..MAX_AUTO_CREATE_ATTEMPTS {
                match try_open_read_session(&backend, &basin_name, &stream_name, start, end).await {
                    Ok(session) => {
                        drop(session);
                        return Ok::<(), ReadError>(());
                    }
                    Err(ReadError::TransactionConflict(_)) | Err(ReadError::StreamNotFound(_)) => {
                        tokio::task::yield_now().await;
                    }
                    Err(err) => return Err(err),
                }
            }
            match try_open_read_session(&backend, &basin_name, &stream_name, start, end).await {
                Ok(session) => {
                    drop(session);
                    Ok::<(), ReadError>(())
                }
                Err(err) => Err(err),
            }
        }));
    }

    for handle in handles {
        handle
            .await
            .unwrap()
            .expect("auto-create read racer should succeed");
    }

    let tail = check_tail(&backend, basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail after auto-create reads");
    assert_eq!(tail, StreamPosition::MIN);
    assert_stream_count(&backend, &basin_name, 1).await;

    let (start, end) = read_all_bounds();
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    assert!(records.is_empty());
}
