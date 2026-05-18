use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use s2_common::{
    read_extent::{ReadLimit, ReadUntil},
    types::{
        config::{OptionalStreamConfig, RetentionPolicy, StorageClass, StreamReconfiguration},
        stream::{AppendInput, ReadEnd, ReadFrom, ReadStart},
    },
};
use s2_lite::backend::error::{AppendError, CheckTailError, ReadError};
use tokio::sync::Notify;

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

    let read_result = try_open_read_session(&backend, &basin_name, &stream_name, start, end).await;
    assert!(matches!(read_result, Err(ReadError::BasinNotFound(_))));

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"test data")]),
        match_seq_num: None,
        fencing_token: None,
    };
    let append_result = append(
        &backend,
        basin_name.clone(),
        stream_name.clone(),
        input,
        None,
    )
    .await;
    assert!(matches!(append_result, Err(AppendError::BasinNotFound(_))));

    let check_tail_result = check_tail(&backend, basin_name, stream_name).await;
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

    let expected_bodies: Vec<_> = (0..20)
        .map(|i| format!("concurrent-{i}").into_bytes())
        .collect();
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
            append(&backend, basin_name, stream_name, input, None).await
        });
        handles.push(handle);
    }

    for handle in handles {
        handle
            .await
            .unwrap()
            .expect("Concurrent append should succeed");
    }

    let tail = check_tail(&backend, basin_name.clone(), stream_name.clone())
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

    let session = open_read_session(&backend, &basin_name, &stream_name, start, end).await;
    let mut session = Box::pin(session);
    let records = collect_records(&mut session).await;
    let mut actual_bodies = envelope_bodies(&records);
    let mut expected_bodies = expected_bodies;
    actual_bodies.sort();
    expected_bodies.sort();
    assert_eq!(actual_bodies, expected_bodies);
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
    let ready = Arc::new(Notify::new());

    let ready_clone = ready.clone();
    let append_handle = tokio::spawn(async move {
        for i in 0..10 {
            append_payloads(
                &backend_append,
                &basin_append,
                &stream_append,
                &[format!("data-{}", i).as_bytes()],
            )
            .await;
            if i == 0 {
                ready_clone.notify_one();
            }
            tokio::task::yield_now().await;
        }
    });

    ready.notified().await;

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

    let tail = check_tail(&backend, basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");
    assert_eq!(tail.seq_num, 10);

    let (start, end) = read_all_bounds();
    let records = read_records(&backend, &basin_name, &stream_name, start, end).await;
    assert_eq!(
        envelope_bodies(&records),
        (0..10)
            .map(|i| format!("data-{i}").into_bytes())
            .collect::<Vec<_>>()
    );
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
            &[format!("record-{}", i).as_bytes()],
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
            let session =
                try_open_read_session(&backend, &basin_name, &stream_name, start, end).await?;
            let mut session = Box::pin(session);
            let records = collect_records(&mut session).await;
            Ok::<Vec<Vec<u8>>, ReadError>(envelope_bodies(&records))
        });
        handles.push(handle);
    }

    let expected_bodies: Vec<_> = (0..20)
        .map(|i| format!("record-{i}").into_bytes())
        .collect();
    for handle in handles {
        let bodies = handle.await.unwrap().expect("Read should succeed");
        assert_eq!(bodies, expected_bodies);
    }
}
