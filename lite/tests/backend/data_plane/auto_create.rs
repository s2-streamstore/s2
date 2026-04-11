use std::time::Duration;

use bytes::Bytes;
use s2_common::{
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

#[tokio::test]
async fn test_auto_create_stream_on_append() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_append: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "auto-create-append", basin_config).await;
    let stream_name = test_stream_name("auto");

    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert!(stream_list.values.is_empty());

    let ack = append_payloads(&backend, &basin_name, &stream_name, &[b"auto created"]).await;
    assert_eq!(ack.start.seq_num, 0);

    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    let stream_names: Vec<_> = stream_list
        .values
        .iter()
        .map(|info| info.name.as_ref())
        .collect();
    assert_eq!(stream_names, vec![stream_name.as_ref()]);

    let config = backend
        .get_stream_config(basin_name, stream_name)
        .await
        .expect("Failed to get stream config");
    assert!(config.storage_class.is_some());
}

#[tokio::test]
async fn test_auto_create_stream_on_read() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_read: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "auto-create-read", basin_config).await;
    let stream_name = test_stream_name("auto");

    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert!(stream_list.values.is_empty());

    let (start, end) = read_all_bounds();
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    assert!(records.is_empty());

    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    let stream_names: Vec<_> = stream_list
        .values
        .iter()
        .map(|info| info.name.as_ref())
        .collect();
    assert_eq!(stream_names, vec![stream_name.as_ref()]);
}

#[tokio::test]
async fn test_auto_create_disabled_append_fails() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_append: false,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "no-auto-create-append", basin_config).await;
    let stream_name = test_stream_name("missing");

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"should fail")]),
        match_seq_num: None,
        fencing_token: None,
    };

    let result = backend.append(basin_name, stream_name, input).await;

    assert!(matches!(result, Err(AppendError::StreamNotFound(_))));
}

#[tokio::test]
async fn test_auto_create_disabled_read_fails() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_read: false,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "no-auto-create-read", basin_config).await;
    let stream_name = test_stream_name("missing");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd::default();

    let result = backend.read(basin_name, stream_name, start, end).await;

    assert!(matches!(result, Err(ReadError::StreamNotFound(_))));
}

#[tokio::test]
async fn test_auto_create_disabled_check_tail_fails() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_read: false,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "no-auto-create-tail", basin_config).await;
    let stream_name = test_stream_name("missing");

    let result = backend.check_tail(basin_name, stream_name).await;

    assert!(matches!(result, Err(CheckTailError::StreamNotFound(_))));
}

#[tokio::test]
async fn test_auto_create_check_tail() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_read: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "auto-create-tail", basin_config).await;
    let stream_name = test_stream_name("auto");

    let tail = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("check_tail should auto-create stream");
    assert_eq!(tail, StreamPosition::MIN);

    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    let stream_names: Vec<_> = stream_list
        .values
        .iter()
        .map(|info| info.name.as_ref())
        .collect();
    assert_eq!(stream_names, vec![stream_name.as_ref()]);
}

#[tokio::test]
async fn test_auto_create_race_condition_append() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_append: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "auto-race-append", basin_config).await;
    let stream_name = test_stream_name("racing");

    let expected_bodies: Vec<_> = (0..10).map(|i| format!("racer-{i}").into_bytes()).collect();
    let mut handles = vec![];
    for body in &expected_bodies {
        let backend = backend.clone();
        let basin_name = basin_name.clone();
        let stream_name = stream_name.clone();
        let body = body.clone();
        let handle = tokio::spawn(async move {
            let input = AppendInput {
                records: create_test_record_batch(vec![Bytes::from(body)]),
                match_seq_num: None,
                fencing_token: None,
            };
            for _ in 0..MAX_AUTO_CREATE_ATTEMPTS {
                match backend
                    .append(basin_name.clone(), stream_name.clone(), input.clone())
                    .await
                {
                    Ok(ack) => return Ok(ack),
                    Err(AppendError::TransactionConflict(_))
                    | Err(AppendError::StreamNotFound(_)) => {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            backend.append(basin_name, stream_name, input).await
        });
        handles.push(handle);
    }

    for handle in handles {
        handle
            .await
            .unwrap()
            .expect("Auto-create append racer should succeed");
    }

    let tail = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 10);

    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    let stream_names: Vec<_> = stream_list
        .values
        .iter()
        .map(|info| info.name.as_ref())
        .collect();
    assert_eq!(stream_names, vec![stream_name.as_ref()]);

    let (start, end) = read_all_bounds();
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    let mut actual_bodies = envelope_bodies(&records);
    let mut expected_bodies = expected_bodies;
    actual_bodies.sort();
    expected_bodies.sort();
    assert_eq!(actual_bodies, expected_bodies);
}

#[tokio::test]
async fn test_auto_create_race_condition_read() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_read: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "auto-race-read", basin_config).await;
    let stream_name = test_stream_name("racing");

    let mut handles = vec![];
    for _ in 0..10 {
        let backend = backend.clone();
        let basin_name = basin_name.clone();
        let stream_name = stream_name.clone();
        let handle = tokio::spawn(async move {
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
                match backend
                    .read(basin_name.clone(), stream_name.clone(), start, end)
                    .await
                {
                    Ok(session) => {
                        drop(session);
                        return Ok::<(), ReadError>(());
                    }
                    Err(ReadError::TransactionConflict(_)) | Err(ReadError::StreamNotFound(_)) => {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            match backend.read(basin_name, stream_name, start, end).await {
                Ok(session) => {
                    drop(session);
                    Ok::<(), ReadError>(())
                }
                Err(e) => Err(e),
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle
            .await
            .unwrap()
            .expect("Auto-create read racer should succeed");
    }

    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    let stream_names: Vec<_> = stream_list
        .values
        .iter()
        .map(|info| info.name.as_ref())
        .collect();
    assert_eq!(stream_names, vec![stream_name.as_ref()]);

    let tail = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail after auto-create reads");
    assert_eq!(tail, StreamPosition::MIN);

    let (start, end) = read_all_bounds();
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    assert!(records.is_empty());
}
