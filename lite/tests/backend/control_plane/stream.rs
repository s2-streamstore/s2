use std::time::Duration;

use bytes::Bytes;
use s2_common::{
    config::{
        BasinConfig, BasinReconfiguration, DeleteOnEmptyReconfiguration,
        OptionalDeleteOnEmptyConfig, OptionalStreamConfig, OptionalTimestampingConfig,
        RetentionPolicy, StorageClass, StreamReconfiguration, TimestampingMode,
        TimestampingReconfiguration,
    },
    encryption::EncryptionAlgorithm,
    maybe::Maybe,
    resources::{ProvisionMode, ProvisionResult, RequestToken},
    stream::{
        AppendInput, ListStreamsRequest, ReadEnd, ReadFrom, ReadStart, StreamNamePrefix,
        StreamNameStartAfter,
    },
};
use s2_lite::backend::error::{
    AppendError, CheckTailError, DeleteStreamError, GetStreamConfigError, ProvisionStreamError,
    ReadError, ReconfigureStreamError,
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
        .provision_basin(
            basin_name.clone(),
            basin_config,
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await
        .expect("Failed to create basin");

    let stream_name = test_stream_name("stream-defaults");

    backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            OptionalStreamConfig::default(),
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await
        .expect("Failed to create stream");

    let config = backend
        .get_stream_config(basin_name, stream_name)
        .await
        .expect("Failed to fetch stream config");
    assert_eq!(config.storage_class, StorageClass::Standard);
    assert_eq!(config.retention_policy, RetentionPolicy::Infinite());
    assert_eq!(config.timestamping.mode, TimestampingMode::ClientRequire);
}

#[tokio::test]
async fn test_create_stream_defaults_to_no_encryption_algorithm() {
    let backend = create_backend().await;
    let basin_name =
        create_test_basin(&backend, "stream-default-enc", BasinConfig::default()).await;
    let stream_name = create_test_stream(
        &backend,
        &basin_name,
        "stream-default-enc",
        OptionalStreamConfig::default(),
    )
    .await;

    let page = backend
        .list_streams(basin_name, ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    let info = page
        .values
        .iter()
        .find(|info| info.name == stream_name)
        .expect("stream info should be present");
    assert_eq!(info.cipher, None);
}

#[tokio::test]
async fn test_create_stream_uses_basin_cipher() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "stream-cipher",
        BasinConfig {
            stream_cipher: Some(EncryptionAlgorithm::Aegis256),
            ..Default::default()
        },
    )
    .await;
    let stream_name = create_test_stream(
        &backend,
        &basin_name,
        "stream-cipher",
        OptionalStreamConfig::default(),
    )
    .await;

    let page = backend
        .list_streams(basin_name, ListStreamsRequest::default())
        .await;
    let page = page.expect("Failed to list streams");
    let info = page
        .values
        .iter()
        .find(|info| info.name == stream_name)
        .expect("stream info should be present");
    assert_eq!(info.cipher, Some(EncryptionAlgorithm::Aegis256));
}

#[tokio::test]
async fn test_existing_stream_keeps_cipher_after_basin_reconfigure() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "stream-basin-cipher-reconfigure",
        BasinConfig {
            stream_cipher: Some(EncryptionAlgorithm::Aegis256),
            ..Default::default()
        },
    )
    .await;
    let stream_name = create_test_stream(
        &backend,
        &basin_name,
        "stream-basin-cipher-reconfigure",
        OptionalStreamConfig::default(),
    )
    .await;

    backend
        .reconfigure_basin(
            basin_name.clone(),
            BasinReconfiguration {
                stream_cipher: Maybe::Specified(Some(EncryptionAlgorithm::Aes256Gcm)),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to reconfigure basin");

    let next_stream = create_test_stream(
        &backend,
        &basin_name,
        "stream-basin-cipher-reconfigure-next",
        OptionalStreamConfig::default(),
    )
    .await;

    let page = backend
        .list_streams(basin_name, ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    let original = page
        .values
        .iter()
        .find(|info| info.name == stream_name)
        .expect("original stream info should be present");
    let next = page
        .values
        .iter()
        .find(|info| info.name == next_stream)
        .expect("new stream info should be present");
    assert_eq!(original.cipher, Some(EncryptionAlgorithm::Aegis256));
    assert_eq!(next.cipher, Some(EncryptionAlgorithm::Aes256Gcm));
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
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            ProvisionMode::CreateOnly {
                request_token: Some(token1.clone()),
            },
        )
        .await
        .expect("Failed to create stream");

    let stored_config = backend
        .get_stream_config(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to fetch stored stream config");
    assert_eq!(stored_config.storage_class, StorageClass::Express);

    let idempotent = backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            ProvisionMode::CreateOnly {
                request_token: Some(token1.clone()),
            },
        )
        .await
        .expect("Idempotent create should succeed with same request token");
    assert!(matches!(
        idempotent,
        ProvisionResult::Noop(ref info) if info.deleted_at.is_none()
            && info.created_at <= time::OffsetDateTime::now_utc()
    ));

    let different_token_result = backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            ProvisionMode::CreateOnly {
                request_token: Some("stream-token-2".parse().unwrap()),
            },
        )
        .await;
    assert!(matches!(
        different_token_result,
        Err(ProvisionStreamError::StreamAlreadyExists(_))
    ));

    let mut different_config = config.clone();
    different_config.timestamping.mode = Some(TimestampingMode::Arrival);
    let different_config_result = backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            different_config,
            ProvisionMode::CreateOnly {
                request_token: Some(token1),
            },
        )
        .await;
    assert!(matches!(
        different_config_result,
        Err(ProvisionStreamError::StreamAlreadyExists(_))
    ));
}

#[tokio::test]
async fn test_provision_stream_ensure_preserves_idempotency_key() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "stream-idempotency-key-preserve",
        BasinConfig::default(),
    )
    .await;
    let stream_name = test_stream_name("stream-idempotency-key-preserve");

    let config = OptionalStreamConfig {
        storage_class: Some(StorageClass::Standard),
        ..Default::default()
    };
    let token: RequestToken = "stream-token-preserve".parse().unwrap();

    backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            ProvisionMode::CreateOnly {
                request_token: Some(token.clone()),
            },
        )
        .await
        .expect("Failed to create stream");

    backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            ProvisionMode::CreateOnly {
                request_token: Some(token.clone()),
            },
        )
        .await
        .expect("Idempotency should work before Ensure");

    backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            OptionalStreamConfig {
                timestamping: OptionalTimestampingConfig {
                    mode: Some(TimestampingMode::Arrival),
                    ..Default::default()
                },
                ..Default::default()
            },
            ProvisionMode::Ensure,
        )
        .await
        .expect("Ensure should succeed");

    let stored_config = backend
        .get_stream_config(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to fetch stream config");
    assert_eq!(stored_config.storage_class, StorageClass::Express);
    assert_eq!(stored_config.timestamping.mode, TimestampingMode::Arrival);

    backend
        .provision_stream(
            basin_name,
            stream_name,
            config,
            ProvisionMode::CreateOnly {
                request_token: Some(token),
            },
        )
        .await
        .expect("Idempotency should still work after Ensure");
}

#[tokio::test]
async fn test_provision_stream_ensure_noops_when_effective_config_matches() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "stream-ensure-effective-noop",
        BasinConfig {
            default_stream_config: OptionalStreamConfig {
                storage_class: Some(StorageClass::Express),
                retention_policy: Some(RetentionPolicy::Age(Duration::from_secs(
                    10 * 24 * 60 * 60,
                ))),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let stream_name = test_stream_name("stream-ensure-effective-noop");
    let config = OptionalStreamConfig {
        storage_class: Some(StorageClass::Standard),
        retention_policy: Some(RetentionPolicy::Infinite()),
        ..Default::default()
    };

    backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await
        .expect("Failed to create stream");

    let ensured = backend
        .provision_stream(basin_name, stream_name, config, ProvisionMode::Ensure)
        .await
        .expect("Ensure should succeed");

    assert!(matches!(ensured, ProvisionResult::Noop(_)));
}

#[tokio::test]
async fn test_provision_stream_preserves_explicit_zero_delete_on_empty() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "stream-zero-doe",
        BasinConfig {
            default_stream_config: OptionalStreamConfig {
                delete_on_empty: OptionalDeleteOnEmptyConfig {
                    min_age: Some(Duration::from_secs(60)),
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let stream_name = test_stream_name("stream-zero-doe");
    let config = OptionalStreamConfig {
        delete_on_empty: OptionalDeleteOnEmptyConfig {
            min_age: Some(Duration::ZERO),
        },
        ..Default::default()
    };

    backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await
        .expect("Failed to create stream");

    let stored_config = backend
        .get_stream_config(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to fetch stream config");
    assert_eq!(stored_config.delete_on_empty.min_age, Duration::ZERO);

    let ensured = backend
        .provision_stream(basin_name, stream_name, config, ProvisionMode::Ensure)
        .await
        .expect("Ensure should succeed");

    assert!(matches!(ensured, ProvisionResult::Noop(_)));
}

#[tokio::test]
async fn test_provision_stream_idempotency_ignores_changed_basin_defaults() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "stream-idempotency-defaults",
        BasinConfig::default(),
    )
    .await;
    let stream_name = test_stream_name("stream-idempotency-defaults");
    let config = OptionalStreamConfig::default();
    let token: RequestToken = "stream-token-defaults".parse().unwrap();

    backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            config.clone(),
            ProvisionMode::CreateOnly {
                request_token: Some(token.clone()),
            },
        )
        .await
        .expect("Failed to create stream");

    backend
        .reconfigure_basin(
            basin_name.clone(),
            BasinReconfiguration {
                default_stream_config: Maybe::from(Some(StreamReconfiguration {
                    storage_class: Maybe::from(Some(StorageClass::Standard)),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to reconfigure basin defaults");

    backend
        .provision_stream(
            basin_name,
            stream_name,
            config,
            ProvisionMode::CreateOnly {
                request_token: Some(token),
            },
        )
        .await
        .expect("Idempotency key should be based on the raw create config");
}

#[tokio::test]
async fn test_reconfigure_stream_updates_selected_fields() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("stream-reconfigure");

    let mut basin_config = BasinConfig::default();
    basin_config.default_stream_config.storage_class = Some(StorageClass::Standard);

    backend
        .provision_basin(
            basin_name.clone(),
            basin_config,
            ProvisionMode::CreateOnly {
                request_token: None,
            },
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
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            initial_config,
            ProvisionMode::CreateOnly {
                request_token: None,
            },
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

    assert_eq!(updated.storage_class, StorageClass::Express);
    assert_eq!(updated.retention_policy, RetentionPolicy::Infinite());
    assert_eq!(updated.timestamping.mode, TimestampingMode::Arrival);
    assert!(updated.timestamping.uncapped);

    let fetched = backend
        .get_stream_config(basin_name, stream_name)
        .await
        .expect("Failed to fetch stream config after reconfigure");
    assert_eq!(fetched.storage_class, StorageClass::Express);
    assert_eq!(fetched.retention_policy, RetentionPolicy::Infinite());
    assert_eq!(fetched.timestamping.mode, TimestampingMode::Arrival);
    assert!(fetched.timestamping.uncapped);
}

#[tokio::test]
async fn test_reconfigure_stream_clears_fields_to_basin_defaults() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("stream-reconfigure-clear-defaults");

    let basin_config = BasinConfig {
        default_stream_config: OptionalStreamConfig {
            storage_class: Some(StorageClass::Standard),
            retention_policy: Some(RetentionPolicy::Infinite()),
            timestamping: OptionalTimestampingConfig {
                mode: Some(TimestampingMode::Arrival),
                uncapped: Some(true),
            },
            delete_on_empty: OptionalDeleteOnEmptyConfig {
                min_age: Some(Duration::from_secs(300)),
            },
        },
        ..Default::default()
    };

    backend
        .provision_basin(
            basin_name.clone(),
            basin_config,
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await
        .expect("Failed to create basin");

    let stream_name = test_stream_name("stream-reconfigure-clear-defaults");
    let stream_config = OptionalStreamConfig {
        storage_class: Some(StorageClass::Express),
        retention_policy: Some(RetentionPolicy::Age(Duration::from_secs(60))),
        timestamping: OptionalTimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            uncapped: Some(false),
        },
        delete_on_empty: OptionalDeleteOnEmptyConfig {
            min_age: Some(Duration::ZERO),
        },
    };

    backend
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            stream_config,
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await
        .expect("Failed to create stream");

    let reconfig = StreamReconfiguration {
        storage_class: Maybe::from(None),
        retention_policy: Maybe::from(None),
        timestamping: Maybe::from(Some(TimestampingReconfiguration {
            mode: Maybe::from(None),
            uncapped: Maybe::from(None),
        })),
        delete_on_empty: Maybe::from(Some(DeleteOnEmptyReconfiguration {
            min_age: Maybe::from(None),
        })),
    };

    let updated = backend
        .reconfigure_stream(basin_name.clone(), stream_name.clone(), reconfig)
        .await
        .expect("Failed to reconfigure stream");

    assert_eq!(updated.storage_class, StorageClass::Standard);
    assert_eq!(updated.retention_policy, RetentionPolicy::Infinite());
    assert_eq!(updated.timestamping.mode, TimestampingMode::Arrival);
    assert!(updated.timestamping.uncapped);
    assert_eq!(updated.delete_on_empty.min_age, Duration::from_secs(300));

    let fetched = backend
        .get_stream_config(basin_name, stream_name)
        .await
        .expect("Failed to fetch stream config after reconfigure");

    assert_eq!(fetched, updated);
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

    check_tail(&backend, basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"missing timestamp")]),
        match_seq_num: None,
        fencing_token: None,
    };
    let result = append(&backend, basin_name, stream_name, input, None).await;
    assert!(matches!(result, Err(AppendError::TimestampMissing(_))));
}

#[tokio::test]
async fn test_provision_stream_ensure_updates_active_streamer() {
    let (backend, basin_name, stream_name) = setup_backend_with_stream(
        "stream-ensure-active",
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
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            config,
            ProvisionMode::Ensure,
        )
        .await
        .expect("Ensure should succeed for an existing stream");

    check_tail(&backend, basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to check tail");

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"missing timestamp")]),
        match_seq_num: None,
        fencing_token: None,
    };
    let result = append(&backend, basin_name, stream_name, input, None).await;
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
        .provision_stream(
            basin_name,
            stream_name,
            OptionalStreamConfig::default(),
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(ProvisionStreamError::BasinDeletionPending(_))
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
        .provision_stream(
            basin_name.clone(),
            stream_name.clone(),
            OptionalStreamConfig::default(),
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await;
    assert!(matches!(
        recreate_result,
        Err(ProvisionStreamError::StreamDeletionPending(_))
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
async fn test_delete_stream_allows_plaintext_command_records_on_encrypted_only_stream() {
    let backend = create_backend().await;
    let basin_name = create_test_basin(
        &backend,
        "stream-delete-encrypted-only",
        basin_config_with_stream_cipher(EncryptionAlgorithm::Aegis256),
    )
    .await;
    let stream_name = create_test_stream(
        &backend,
        &basin_name,
        "stream-delete-encrypted-only",
        OptionalStreamConfig::default(),
    )
    .await;

    append_payloads_with_encryption(
        &backend,
        &basin_name,
        &stream_name,
        &[b"secret"],
        &aegis256_encryption_spec(),
    )
    .await;

    backend
        .delete_stream(basin_name.clone(), stream_name.clone())
        .await
        .expect("Failed to delete encrypted-only stream");

    let page = backend
        .list_streams(basin_name, ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    let info = page
        .values
        .iter()
        .find(|info| info.name == stream_name)
        .expect("Deleted stream should appear in listing");
    assert!(info.deleted_at.is_some());
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

    let tail = check_tail(&backend, basin_name.clone(), stream_name.clone()).await;
    assert!(matches!(
        tail,
        Err(CheckTailError::StreamDeletionPending(_))
    ),);

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"should fail")]),
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
    assert!(matches!(
        append_result,
        Err(AppendError::StreamDeletionPending(_))
    ));

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let end = ReadEnd::default();
    let read_result = try_open_read_session(&backend, &basin_name, &stream_name, start, end).await;
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

    let names: Vec<_> = page.values.iter().map(|info| info.name.as_ref()).collect();
    assert_eq!(
        names,
        vec![
            "test-stream-list-0",
            "test-stream-list-1",
            "test-stream-list-2",
            "test-stream-list-3",
            "test-stream-list-4",
        ]
    );
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
            ListStreamsRequest {
                prefix: StreamNamePrefix::default(),
                start_after: StreamNameStartAfter::default(),
                limit: 5.into(),
            },
        )
        .await
        .expect("Failed to list streams page 1");

    assert!(page1.has_more);
    let page1_names: Vec<_> = page1.values.iter().map(|info| info.name.as_ref()).collect();
    assert_eq!(
        page1_names,
        vec![
            "test-stream-stream-00",
            "test-stream-stream-01",
            "test-stream-stream-02",
            "test-stream-stream-03",
            "test-stream-stream-04",
        ]
    );

    let page2 = backend
        .list_streams(
            basin_name.clone(),
            ListStreamsRequest {
                prefix: StreamNamePrefix::default(),
                start_after: page1.values.last().unwrap().name.clone().into(),
                limit: 5.into(),
            },
        )
        .await
        .expect("Failed to list streams page 2");

    assert!(page2.has_more);
    let page2_names: Vec<_> = page2.values.iter().map(|info| info.name.as_ref()).collect();
    assert_eq!(
        page2_names,
        vec![
            "test-stream-stream-05",
            "test-stream-stream-06",
            "test-stream-stream-07",
            "test-stream-stream-08",
            "test-stream-stream-09",
        ]
    );

    let page3 = backend
        .list_streams(
            basin_name.clone(),
            ListStreamsRequest {
                prefix: StreamNamePrefix::default(),
                start_after: page2.values.last().unwrap().name.clone().into(),
                limit: 5.into(),
            },
        )
        .await
        .expect("Failed to list streams page 3");

    assert!(!page3.has_more);
    let page3_names: Vec<_> = page3.values.iter().map(|info| info.name.as_ref()).collect();
    assert_eq!(
        page3_names,
        vec!["test-stream-stream-10", "test-stream-stream-11"]
    );
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
            ListStreamsRequest {
                prefix: "test-stream-metrics-".parse().unwrap(),
                start_after: StreamNameStartAfter::default(),
                limit: Default::default(),
            },
        )
        .await
        .expect("Failed to list streams with prefix");

    let metric_names: Vec<_> = metrics_streams
        .values
        .iter()
        .map(|info| info.name.as_ref())
        .collect();
    assert_eq!(
        metric_names,
        vec!["test-stream-metrics-cpu", "test-stream-metrics-memory"]
    );
}
