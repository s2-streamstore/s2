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
use s2_lite::backend::error::{AppendError, ReadError};

use super::common::*;

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
    assert_eq!(stream_list.values.len(), 0);

    let ack = append_payloads(&backend, &basin_name, &stream_name, &[b"auto created"]).await;
    assert_eq!(ack.start.seq_num, 0);

    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert_eq!(stream_list.values.len(), 1);
    assert_eq!(stream_list.values[0].name, stream_name);

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
    assert_eq!(stream_list.values.len(), 0);

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
    assert_eq!(records.len(), 0);

    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert_eq!(stream_list.values.len(), 1);
    assert_eq!(stream_list.values[0].name, stream_name);
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
        .list_streams(basin_name, ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert_eq!(stream_list.values.len(), 1);
    assert_eq!(stream_list.values[0].name, stream_name);
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

    let mut handles = vec![];
    for i in 0..10 {
        let backend = backend.clone();
        let basin_name = basin_name.clone();
        let stream_name = stream_name.clone();
        let handle = tokio::spawn(async move {
            let input = AppendInput {
                records: create_test_record_batch(vec![Bytes::from(format!("racer-{}", i))]),
                match_seq_num: None,
                fencing_token: None,
            };
            for _ in 0..5 {
                match backend
                    .append(basin_name.clone(), stream_name.clone(), input.clone())
                    .await
                {
                    Ok(ack) => return Ok(ack),
                    Err(AppendError::TransactionConflict(_))
                    | Err(AppendError::StreamNotFound(_)) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            backend.append(basin_name, stream_name, input).await
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    let mut errors = vec![];
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => success_count += 1,
            Err(e) => errors.push(format!("{:?}", e)),
        }
    }

    if success_count != 10 {
        eprintln!("Success count: {}, errors: {:?}", success_count, errors);
    }
    assert_eq!(success_count, 10);

    let tail = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 10);

    let stream_list = backend
        .list_streams(basin_name, ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert_eq!(stream_list.values.len(), 1);
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
            for _ in 0..5 {
                match backend
                    .read(basin_name.clone(), stream_name.clone(), start, end)
                    .await
                {
                    Ok(session) => {
                        drop(session);
                        return Ok::<(), ReadError>(());
                    }
                    Err(ReadError::TransactionConflict(_)) | Err(ReadError::StreamNotFound(_)) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
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

    let mut success_count = 0;
    let mut errors = vec![];
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => success_count += 1,
            Err(e) => errors.push(format!("{:?}", e)),
        }
    }

    if success_count != 10 {
        eprintln!("Success count: {}, errors: {:?}", success_count, errors);
    }
    assert_eq!(success_count, 10);

    let stream_list = backend
        .list_streams(basin_name, ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert_eq!(stream_list.values.len(), 1);
}
