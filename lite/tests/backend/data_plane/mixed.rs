use std::time::Duration;

use bytes::Bytes;
use s2_common::{
    read_extent::{ReadLimit, ReadUntil},
    types::{
        config::{OptionalStreamConfig, RetentionPolicy, StorageClass, StreamReconfiguration},
        stream::{AppendInput, ReadEnd, ReadFrom, ReadStart},
    },
};
use s2_lite::backend::error::{AppendError, CheckTailError, ReadError};

use super::common::*;

#[tokio::test]
async fn test_operations_on_nonexistent_basin() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("nonexistent");
    let stream_name = test_stream_name("nonexistent");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd {
        limit: ReadLimit::Unbounded,
        until: ReadUntil::Unbounded,
        wait: None,
    };

    let read_result = backend
        .read(basin_name.clone(), stream_name.clone(), start, end)
        .await;
    assert!(matches!(read_result, Err(ReadError::BasinNotFound(_))));

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"test data")]),
        match_seq_num: None,
        fencing_token: None,
    };
    let append_result = backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await;
    assert!(matches!(append_result, Err(AppendError::BasinNotFound(_))));

    let check_tail_result = backend.check_tail(basin_name, stream_name).await;
    assert!(matches!(
        check_tail_result,
        Err(CheckTailError::BasinNotFound(_))
    ));
}

#[tokio::test]
async fn test_concurrent_appends_to_same_stream() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "concurrent-append",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let mut handles = vec![];
    for i in 0..20 {
        let backend = backend.clone();
        let basin_name = basin_name.clone();
        let stream_name = stream_name.clone();
        let handle = tokio::spawn(async move {
            let input = AppendInput {
                records: create_test_record_batch(vec![Bytes::from(format!("concurrent-{i}"))]),
                match_seq_num: None,
                fencing_token: None,
            };
            backend.append(basin_name, stream_name, input).await
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(success_count, 20);

    let tail = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 20);

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
        .read(basin_name, stream_name, start, end)
        .await
        .expect("Failed to create read session");
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;
    assert_eq!(records.len(), 20);
}

#[tokio::test]
async fn test_read_while_appending() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "read-while-append",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"initial"]).await;

    let backend_clone = backend.clone();
    let basin_clone = basin_name.clone();
    let stream_clone = stream_name.clone();

    let append_handle = tokio::spawn(async move {
        for i in 0..10 {
            append_payloads(
                &backend_clone,
                &basin_clone,
                &stream_clone,
                &[format!("append-{i}").as_bytes()],
            )
            .await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

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
    assert!(!records.is_empty());
    assert!(records.len() <= 5);

    append_handle.await.unwrap();

    let tail = backend
        .check_tail(basin_name, stream_name)
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 11);
}

#[tokio::test]
async fn test_concurrent_reconfigure_during_append() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "concurrent-reconfig",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    let backend_append = backend.clone();
    let basin_append = basin_name.clone();
    let stream_append = stream_name.clone();

    let append_handle = tokio::spawn(async move {
        for i in 0..10 {
            append_payloads(
                &backend_append,
                &basin_append,
                &stream_append,
                &[format!("data-{i}").as_bytes()],
            )
            .await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let reconfig = StreamReconfiguration {
        storage_class: s2_common::maybe::Maybe::from(Some(StorageClass::Express)),
        retention_policy: s2_common::maybe::Maybe::from(Some(RetentionPolicy::Infinite())),
        timestamping: s2_common::maybe::Maybe::default(),
        delete_on_empty: s2_common::maybe::Maybe::default(),
    };

    let updated_config = backend
        .reconfigure_stream(basin_name.clone(), stream_name.clone(), reconfig)
        .await
        .expect("Failed to reconfigure stream during appends");
    assert_eq!(updated_config.storage_class, Some(StorageClass::Express));

    append_handle.await.unwrap();

    let tail = backend
        .check_tail(basin_name, stream_name)
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 10);
}

#[tokio::test]
async fn test_concurrent_reads_same_stream() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "concurrent-reads",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    for i in 0..20 {
        append_payloads(
            &backend,
            &basin_name,
            &stream_name,
            &[format!("record-{i}").as_bytes()],
        )
        .await;
    }

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
            let session = backend.read(basin_name, stream_name, start, end).await?;
            let mut session = Box::pin(session);
            let records = collect_records(&mut session).await;
            Ok::<usize, ReadError>(records.len())
        });
        handles.push(handle);
    }

    for handle in handles {
        let count = handle.await.unwrap().expect("Read should succeed");
        assert_eq!(count, 20);
    }
}
