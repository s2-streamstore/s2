use std::time::Duration;

use bytes::Bytes;
use s2_common::{
    maybe::Maybe,
    types::{
        config::{
            BasinConfig, OptionalStreamConfig, OptionalTimestampingConfig, RetentionPolicy,
            StorageClass, StreamReconfiguration, TimestampingMode, TimestampingReconfiguration,
        },
        resources::{CreateMode, ListItemsRequestParts, RequestToken},
        stream::{
            AppendInput, ListStreamsRequest, ReadEnd, ReadFrom, ReadStart, StreamNamePrefix,
            StreamNameStartAfter,
        },
    },
};
use s2_lite::backend::error::{
    AppendError, CheckTailError, CreateStreamError, DeleteStreamError, GetStreamConfigError,
    ReadError, ReconfigureStreamError, StreamDeletionPendingError,
};

use super::common::*;

#[tokio::test]
async fn test_create_stream_honors_basin_defaults() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("stream-defaults");

    let basin_config = BasinConfig {
        default_stream_config: OptionalStreamConfig {
            storage_class: Some(StorageClass::Standard),
            retention_policy: Some(RetentionPolicy::Infinite()),
            timestamping: OptionalTimestampingConfig {
                mode: Some(TimestampingMode::ClientRequire),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    backend
        .create_basin(
            basin_name.clone(),
            basin_config,
            CreateMode::CreateOnly(None),
        )
        .await
        .expect("Failed to create basin");

    let stream_name = test_stream_name("stream-defaults");

    backend
        .create_stream(
            basin_name.clone(),
            stream_name.clone(),
            OptionalStreamConfig::default(),
            CreateMode::CreateOnly(None),
        )
        .await
        .expect("Failed to create stream");

    let config = backend
        .get_stream_config(basin_name, stream_name)
        .await
        .expect("Failed to fetch stream config");
    assert_eq!(config.storage_class, Some(StorageClass::Standard));
    assert_eq!(config.retention_policy, Some(RetentionPolicy::Infinite()));
    assert_eq!(
        config.timestamping.mode,
        Some(TimestampingMode::ClientRequire)
    );
}

#[tokio::test]
async fn test_get_nonexistent_stream_config() {
    let backend = create_backend().await;
    let basin_name =
        create_test_basin(&backend, "basin-for-missing-stream", BasinConfig::default()).await;
    let stream_name = test_stream_name("nonexistent-stream");

    let result = backend.get_stream_config(basin_name, stream_name).await;

    assert!(matches!(
        result,
        Err(GetStreamConfigError::StreamNotFound(_))
    ));
}

#[tokio::test]
async fn test_create_stream_idempotency_and_request_token() {
    let backend = create_backend().await;
    let basin_name =
        create_test_basin(&backend, "stream-idempotency", BasinConfig::default()).await;
    let stream_name = test_stream_name("stream-idempotency");

    let config = OptionalStreamConfig {
        storage_class: Some(StorageClass::Express),
        ..Default::default()
    };

    let token1: RequestToken = "stream-token-1".parse().unwrap();

    backend
        .create_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            CreateMode::CreateOnly(Some(token1.clone())),
        )
        .await
        .expect("Failed to create stream");

    let stored_config = backend
        .get_stream_config(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to fetch stored stream config");
    assert_eq!(stored_config.storage_class, Some(StorageClass::Express));

    backend
        .create_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            CreateMode::CreateOnly(Some(token1.clone())),
        )
        .await
        .expect("Idempotent create should succeed with same request token");

    let different_token_result = backend
        .create_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            CreateMode::CreateOnly(Some("stream-token-2".parse().unwrap())),
        )
        .await;
    assert!(matches!(
        different_token_result,
        Err(CreateStreamError::StreamAlreadyExists(_))
    ));

    let mut different_config = config.clone();
    different_config.timestamping.mode = Some(TimestampingMode::Arrival);
    let different_config_result = backend
        .create_stream(
            basin_name.clone(),
            stream_name.clone(),
            different_config,
            CreateMode::CreateOnly(Some(token1)),
        )
        .await;
    assert!(matches!(
        different_config_result,
        Err(CreateStreamError::StreamAlreadyExists(_))
    ));
}

#[tokio::test]
async fn test_reconfigure_stream_updates_selected_fields() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("stream-reconfigure");

    let mut basin_config = BasinConfig::default();
    basin_config.default_stream_config.storage_class = Some(StorageClass::Standard);

    backend
        .create_basin(
            basin_name.clone(),
            basin_config,
            CreateMode::CreateOnly(None),
        )
        .await
        .expect("Failed to create basin");

    let stream_name = test_stream_name("stream-reconfigure");
    let initial_config = OptionalStreamConfig {
        retention_policy: Some(RetentionPolicy::Age(Duration::from_secs(60))),
        timestamping: OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            ..Default::default()
        },
        ..Default::default()
    };

    backend
        .create_stream(
            basin_name.clone(),
            stream_name.clone(),
            initial_config,
            CreateMode::CreateOnly(None),
        )
        .await
        .expect("Failed to create stream");

    let ts_reconfig = TimestampingReconfiguration {
        mode: Maybe::from(Some(TimestampingMode::Arrival)),
        uncapped: Maybe::from(Some(true)),
    };
    let mut stream_reconfig = StreamReconfiguration {
        storage_class: Maybe::from(Some(StorageClass::Express)),
        retention_policy: Maybe::from(Some(RetentionPolicy::Infinite())),
        ..Default::default()
    };
    stream_reconfig.timestamping = Maybe::from(Some(ts_reconfig));

    let updated = backend
        .reconfigure_stream(basin_name.clone(), stream_name.clone(), stream_reconfig)
        .await
        .expect("Failed to reconfigure stream");

    assert_eq!(updated.storage_class, Some(StorageClass::Express));
    assert_eq!(updated.retention_policy, Some(RetentionPolicy::Infinite()));
    assert_eq!(updated.timestamping.mode, Some(TimestampingMode::Arrival));
    assert_eq!(updated.timestamping.uncapped, Some(true));

    let fetched = backend
        .get_stream_config(basin_name, stream_name)
        .await
        .expect("Failed to fetch stream config after reconfigure");
    assert_eq!(fetched.storage_class, Some(StorageClass::Express));
    assert_eq!(fetched.retention_policy, Some(RetentionPolicy::Infinite()));
    assert_eq!(fetched.timestamping.mode, Some(TimestampingMode::Arrival));
    assert_eq!(fetched.timestamping.uncapped, Some(true));
}

#[tokio::test]
async fn test_reconfigure_stream_updates_active_streamer() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "stream-reconfigure-active",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"seed"]).await;

    let ts_reconfig = TimestampingReconfiguration {
        mode: Maybe::from(Some(TimestampingMode::ClientRequire)),
        uncapped: Maybe::default(),
    };
    let reconfig = StreamReconfiguration {
        timestamping: Maybe::from(Some(ts_reconfig)),
        ..Default::default()
    };

    backend
        .reconfigure_stream(basin_name.clone(), stream_name.clone(), reconfig)
        .await
        .expect("Failed to reconfigure stream");

    backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"missing timestamp")]),
        match_seq_num: None,
        fencing_token: None,
    };
    let result = backend.append(basin_name, stream_name, input).await;
    assert!(matches!(result, Err(AppendError::TimestampMissing(_))));
}

#[tokio::test]
async fn test_create_stream_create_or_reconfigure_updates_active_streamer() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "stream-create-or-reconfigure-active",
        "stream",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"seed"]).await;

    let config = OptionalStreamConfig {
        timestamping: OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            ..Default::default()
        },
        ..Default::default()
    };

    backend
        .create_stream(
            basin_name.clone(),
            stream_name.clone(),
            config,
            CreateMode::CreateOrReconfigure,
        )
        .await
        .expect("CreateOrReconfigure should succeed for an existing stream");

    backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"missing timestamp")]),
        match_seq_num: None,
        fencing_token: None,
    };
    let result = backend.append(basin_name, stream_name, input).await;
    assert!(matches!(result, Err(AppendError::TimestampMissing(_))));
}

#[tokio::test]
async fn test_create_stream_fails_when_basin_deleting() {
    let backend = create_backend().await;
    let basin_name =
        create_test_basin(&backend, "stream-basin-deleting", BasinConfig::default()).await;

    backend
        .delete_basin(basin_name.clone())
        .await
        .expect("Failed to delete basin");

    let stream_name = test_stream_name("blocked");
    let result = backend
        .create_stream(
            basin_name,
            stream_name,
            OptionalStreamConfig::default(),
            CreateMode::CreateOnly(None),
        )
        .await;

    assert!(matches!(
        result,
        Err(CreateStreamError::BasinDeletionPending(_))
    ));
}

#[tokio::test]
async fn test_delete_stream_marks_deleted_and_blocks_recreation() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(&backend, "stream-delete", BasinConfig::default()).await;
    let stream_name = create_test_stream(
        &backend,
        &basin_name,
        "stream-delete",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads(&backend, &basin_name, &stream_name, &[b"seed data"]).await;

    backend
        .delete_stream(basin_name.clone(), stream_name.clone())
        .await
        .unwrap();

    let page = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    let info = page
        .values
        .iter()
        .find(|info| info.name == stream_name)
        .expect("Deleted stream should appear in listing");
    assert!(info.deleted_at.is_some());

    let recreate_result = backend
        .create_stream(
            basin_name.clone(),
            stream_name.clone(),
            OptionalStreamConfig::default(),
            CreateMode::CreateOnly(None),
        )
        .await;
    assert!(matches!(
        recreate_result,
        Err(CreateStreamError::StreamDeletionPending(
            StreamDeletionPendingError { basin, stream }
        )) if basin == basin_name && stream == stream_name
    ));

    let reconfigure_result = backend
        .reconfigure_stream(
            basin_name.clone(),
            stream_name.clone(),
            StreamReconfiguration::default(),
        )
        .await;
    assert!(matches!(
        reconfigure_result,
        Err(ReconfigureStreamError::StreamDeletionPending(_))
    ));

    backend
        .delete_stream(basin_name.clone(), stream_name.clone())
        .await
        .expect("Second delete should be idempotent");
}

#[tokio::test]
async fn test_delete_stream_blocks_data_operations() {
    let backend = create_backend().await;

    let basin_name =
        create_test_basin(&backend, "stream-delete-blocks", BasinConfig::default()).await;
    let stream_name = create_test_stream(
        &backend,
        &basin_name,
        "stream-delete-blocks",
        OptionalStreamConfig::default(),
    )
    .await;

    backend
        .delete_stream(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to delete stream");

    let tail = backend
        .check_tail(basin_name.clone(), stream_name.clone())
        .await;
    assert!(matches!(
        tail,
        Err(CheckTailError::StreamDeletionPending(_))
    ),);

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"should fail")]),
        match_seq_num: None,
        fencing_token: None,
    };
    let append_result = backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await;
    assert!(matches!(
        append_result,
        Err(AppendError::StreamDeletionPending(_))
    ));

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd::default();
    let read_result = backend.read(basin_name, stream_name, start, end).await;
    assert!(matches!(
        read_result,
        Err(ReadError::StreamDeletionPending(_))
    ));
}

#[tokio::test]
async fn test_get_stream_config_for_deleting_stream_returns_pending() {
    let backend = create_backend().await;
    let basin_name =
        create_test_basin(&backend, "stream-delete-config", BasinConfig::default()).await;
    let stream_name = create_test_stream(
        &backend,
        &basin_name,
        "stream-delete-config",
        OptionalStreamConfig::default(),
    )
    .await;

    backend
        .delete_stream(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to delete stream");

    let result = backend.get_stream_config(basin_name, stream_name).await;
    assert!(matches!(
        result,
        Err(GetStreamConfigError::StreamDeletionPending(_))
    ));
}

#[tokio::test]
async fn test_delete_stream_nonexistent_returns_not_found() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "stream-delete-nonexistent",
        BasinConfig::default(),
    )
    .await;
    let stream_name = test_stream_name("missing");

    let result = backend.delete_stream(basin_name, stream_name).await;
    assert!(matches!(result, Err(DeleteStreamError::StreamNotFound(_))));
}

#[tokio::test]
async fn test_list_streams_empty() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(&backend, "empty-streams", BasinConfig::default()).await;

    let page = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");

    assert!(page.values.is_empty());
    assert!(!page.has_more);
}

#[tokio::test]
async fn test_list_streams_multiple() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(&backend, "list-streams", BasinConfig::default()).await;

    for i in 0..5 {
        create_test_stream(
            &backend,
            &basin_name,
            &format!("list-{}", i),
            OptionalStreamConfig::default(),
        )
        .await;
    }

    let page = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");

    assert_eq!(page.values.len(), 5);
    assert!(!page.has_more);
}

#[tokio::test]
async fn test_list_streams_pagination() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(&backend, "stream-pagination", BasinConfig::default()).await;

    for i in 0..12 {
        create_test_stream(
            &backend,
            &basin_name,
            &format!("stream-{:02}", i),
            OptionalStreamConfig::default(),
        )
        .await;
    }

    let page1 = backend
        .list_streams(
            basin_name.clone(),
            ListItemsRequestParts {
                prefix: StreamNamePrefix::default(),
                start_after: StreamNameStartAfter::default(),
                limit: 5.into(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list streams page 1");

    assert_eq!(page1.values.len(), 5);
    assert!(page1.has_more);

    let page2 = backend
        .list_streams(
            basin_name.clone(),
            ListItemsRequestParts {
                prefix: StreamNamePrefix::default(),
                start_after: page1.values.last().unwrap().name.clone().into(),
                limit: 5.into(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list streams page 2");

    assert_eq!(page2.values.len(), 5);
    assert!(page2.has_more);

    let page3 = backend
        .list_streams(
            basin_name.clone(),
            ListItemsRequestParts {
                prefix: StreamNamePrefix::default(),
                start_after: page2.values.last().unwrap().name.clone().into(),
                limit: 5.into(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list streams page 3");

    assert_eq!(page3.values.len(), 2);
    assert!(!page3.has_more);
}

#[tokio::test]
async fn test_list_streams_prefix_filter() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(&backend, "stream-prefix", BasinConfig::default()).await;

    create_test_stream(
        &backend,
        &basin_name,
        "metrics-cpu",
        OptionalStreamConfig::default(),
    )
    .await;
    create_test_stream(
        &backend,
        &basin_name,
        "metrics-memory",
        OptionalStreamConfig::default(),
    )
    .await;
    create_test_stream(
        &backend,
        &basin_name,
        "logs-app",
        OptionalStreamConfig::default(),
    )
    .await;
    create_test_stream(
        &backend,
        &basin_name,
        "traces-span",
        OptionalStreamConfig::default(),
    )
    .await;

    let metrics_streams = backend
        .list_streams(
            basin_name.clone(),
            ListItemsRequestParts {
                prefix: "test-stream-metrics-".parse().unwrap(),
                start_after: StreamNameStartAfter::default(),
                limit: Default::default(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list streams with prefix");

    assert_eq!(metrics_streams.values.len(), 2);
    assert!(
        metrics_streams
            .values
            .iter()
            .all(|s| s.name.as_ref().starts_with("test-stream-metrics-"))
    );
}
