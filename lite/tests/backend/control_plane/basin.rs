use s2_common::{
    maybe::Maybe,
    types::{
        basin::{BasinNamePrefix, BasinNameStartAfter, BasinState, ListBasinsRequest},
        config::{
            BasinConfig, BasinReconfiguration, RetentionPolicy, StorageClass,
            StreamReconfiguration, TimestampingMode, TimestampingReconfiguration,
        },
        resources::{CreateMode, ListItemsRequestParts, RequestToken},
    },
};
use s2_lite::backend::error::{
    CreateBasinError, DeleteBasinError, GetBasinConfigError, ReconfigureBasinError,
};

use super::common::*;

#[tokio::test]
async fn test_create_basin_idempotency_respects_request_token() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("basin-idempotency");
    let config = BasinConfig {
        create_stream_on_append: true,
        ..Default::default()
    };

    let token1: RequestToken = "token-1".parse().unwrap();

    backend
        .create_basin(
            basin_name.clone(),
            config.clone(),
            CreateMode::CreateOnly(Some(token1.clone())),
        )
        .await
        .expect("Failed to create basin");

    backend
        .create_basin(
            basin_name.clone(),
            config.clone(),
            CreateMode::CreateOnly(Some(token1.clone())),
        )
        .await
        .expect("Idempotent create should succeed with same request token");

    let different_token: RequestToken = "token-2".parse().unwrap();
    let different_token_result = backend
        .create_basin(
            basin_name.clone(),
            config.clone(),
            CreateMode::CreateOnly(Some(different_token)),
        )
        .await;
    assert!(matches!(
        different_token_result,
        Err(CreateBasinError::BasinAlreadyExists(_))
    ));

    let mut different_config = config.clone();
    different_config.create_stream_on_append = false;
    let different_config_result = backend
        .create_basin(
            basin_name,
            different_config,
            CreateMode::CreateOnly(Some(token1)),
        )
        .await;
    assert!(matches!(
        different_config_result,
        Err(CreateBasinError::BasinAlreadyExists(_))
    ));
}

#[tokio::test]
async fn test_create_basin_create_or_reconfigure_updates_config() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("basin-recreate");
    let initial_config = BasinConfig {
        create_stream_on_append: false,
        create_stream_on_read: false,
        ..Default::default()
    };

    backend
        .create_basin(
            basin_name.clone(),
            initial_config.clone(),
            CreateMode::CreateOnly(None),
        )
        .await
        .expect("Failed to create basin");

    let mut updated_config = initial_config.clone();
    updated_config.create_stream_on_append = true;
    updated_config.create_stream_on_read = true;
    updated_config.default_stream_config.storage_class = Some(StorageClass::Standard);

    backend
        .create_basin(
            basin_name.clone(),
            updated_config.clone(),
            CreateMode::CreateOrReconfigure,
        )
        .await
        .expect("CreateOrReconfigure should update basin config");

    let stored_config = backend
        .get_basin_config(basin_name.clone())
        .await
        .expect("Failed to fetch basin config");
    assert!(stored_config.create_stream_on_append);
    assert!(stored_config.create_stream_on_read);
    assert_eq!(
        stored_config.default_stream_config.storage_class,
        Some(StorageClass::Standard)
    );

    backend
        .create_basin(
            basin_name.clone(),
            updated_config,
            CreateMode::CreateOnly(None),
        )
        .await
        .expect_err("CreateOnly without request token should not be idempotent");
}

#[tokio::test]
async fn test_reconfigure_basin_updates_nested_defaults() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("basin-reconfigure");
    let mut initial_config = BasinConfig::default();
    initial_config.default_stream_config.storage_class = Some(StorageClass::Standard);

    backend
        .create_basin(
            basin_name.clone(),
            initial_config.clone(),
            CreateMode::CreateOnly(None),
        )
        .await
        .expect("Failed to create basin");

    let timestamping_reconfig = TimestampingReconfiguration {
        mode: Maybe::from(Some(TimestampingMode::Arrival)),
        ..Default::default()
    };
    let mut stream_reconfig = StreamReconfiguration {
        storage_class: Maybe::from(Some(StorageClass::Express)),
        retention_policy: Maybe::from(Some(RetentionPolicy::Infinite())),
        ..Default::default()
    };
    stream_reconfig.timestamping = Maybe::from(Some(timestamping_reconfig));

    let reconfig = BasinReconfiguration {
        default_stream_config: Maybe::from(Some(stream_reconfig)),
        create_stream_on_append: Maybe::from(true),
        create_stream_on_read: Maybe::from(true),
    };

    let updated = backend
        .reconfigure_basin(basin_name.clone(), reconfig)
        .await
        .expect("Failed to reconfigure basin");

    assert!(updated.create_stream_on_append);
    assert!(updated.create_stream_on_read);
    assert_eq!(
        updated.default_stream_config.storage_class,
        Some(StorageClass::Express)
    );
    assert_eq!(
        updated.default_stream_config.retention_policy,
        Some(RetentionPolicy::Infinite())
    );
    assert_eq!(
        updated.default_stream_config.timestamping.mode,
        Some(TimestampingMode::Arrival)
    );

    let fetched = backend
        .get_basin_config(basin_name)
        .await
        .expect("Failed to fetch basin config after reconfigure");
    assert_eq!(
        fetched.default_stream_config.storage_class,
        Some(StorageClass::Express)
    );
    assert_eq!(
        fetched.default_stream_config.retention_policy,
        Some(RetentionPolicy::Infinite())
    );
    assert_eq!(
        fetched.default_stream_config.timestamping.mode,
        Some(TimestampingMode::Arrival)
    );
    assert!(fetched.create_stream_on_append);
    assert!(fetched.create_stream_on_read);
}

#[tokio::test]
async fn test_delete_basin_marks_deleting_and_blocks_create() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("basin-delete");

    backend
        .create_basin(
            basin_name.clone(),
            BasinConfig::default(),
            CreateMode::CreateOnly(None),
        )
        .await
        .expect("Failed to create basin");

    backend
        .delete_basin(basin_name.clone())
        .await
        .expect("Failed to delete basin");

    let page = backend
        .list_basins(ListBasinsRequest::default())
        .await
        .expect("Failed to list basins");
    let info = page
        .values
        .iter()
        .find(|info| info.name == basin_name)
        .expect("Deleted basin should appear in listing");
    assert!(matches!(info.state, BasinState::Deleting));

    let reconfigure_result = backend
        .reconfigure_basin(basin_name.clone(), BasinReconfiguration::default())
        .await;
    assert!(matches!(
        reconfigure_result,
        Err(ReconfigureBasinError::BasinDeletionPending(_))
    ));

    let recreate_result = backend
        .create_basin(
            basin_name.clone(),
            BasinConfig::default(),
            CreateMode::CreateOnly(None),
        )
        .await;
    assert!(matches!(
        recreate_result,
        Err(CreateBasinError::BasinDeletionPending(_))
    ));

    backend
        .delete_basin(basin_name)
        .await
        .expect("Second delete should be idempotent");
}

#[tokio::test]
async fn test_get_nonexistent_basin_config() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("nonexistent-basin");

    let result = backend.get_basin_config(basin_name).await;

    assert!(matches!(result, Err(GetBasinConfigError::BasinNotFound(_))));
}

#[tokio::test]
async fn test_delete_nonexistent_basin_returns_not_found() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("delete-missing-basin");

    let result = backend.delete_basin(basin_name).await;

    assert!(matches!(result, Err(DeleteBasinError::BasinNotFound(_))));
}

#[tokio::test]
async fn test_list_basins_empty() {
    let backend = create_backend().await;

    let page = backend
        .list_basins(ListBasinsRequest::default())
        .await
        .expect("Failed to list basins");

    assert!(page.values.is_empty());
    assert!(!page.has_more);
}

#[tokio::test]
async fn test_list_basins_multiple() {
    let backend = create_backend().await;

    for i in 0..5 {
        create_test_basin(&backend, &format!("list-{}", i), BasinConfig::default()).await;
    }

    let page = backend
        .list_basins(ListBasinsRequest::default())
        .await
        .expect("Failed to list basins");

    assert_eq!(page.values.len(), 5);
    assert!(!page.has_more);
}

#[tokio::test]
async fn test_list_basins_pagination() {
    let backend = create_backend().await;

    for i in 0..15 {
        create_test_basin(
            &backend,
            &format!("paginated-{:02}", i),
            BasinConfig::default(),
        )
        .await;
    }

    let page1 = backend
        .list_basins(
            ListItemsRequestParts {
                prefix: BasinNamePrefix::default(),
                start_after: BasinNameStartAfter::default(),
                limit: 5.into(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list basins page 1");

    assert_eq!(page1.values.len(), 5);
    assert!(page1.has_more);
    assert_eq!(page1.values[0].name.as_ref(), "test-basin-paginated-00");
    assert_eq!(page1.values[4].name.as_ref(), "test-basin-paginated-04");

    let page2 = backend
        .list_basins(
            ListItemsRequestParts {
                prefix: BasinNamePrefix::default(),
                start_after: page1.values.last().unwrap().name.clone().into(),
                limit: 5.into(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list basins page 2");

    assert_eq!(page2.values.len(), 5);
    assert!(page2.has_more);
    assert_eq!(page2.values[0].name.as_ref(), "test-basin-paginated-05");
    assert_eq!(page2.values[4].name.as_ref(), "test-basin-paginated-09");

    let page3 = backend
        .list_basins(
            ListItemsRequestParts {
                prefix: BasinNamePrefix::default(),
                start_after: page2.values.last().unwrap().name.clone().into(),
                limit: 5.into(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list basins page 3");

    assert_eq!(page3.values.len(), 5);
    assert!(!page3.has_more);
    assert_eq!(page3.values[0].name.as_ref(), "test-basin-paginated-10");
    assert_eq!(page3.values[4].name.as_ref(), "test-basin-paginated-14");
}

#[tokio::test]
async fn test_list_basins_prefix_filter() {
    let backend = create_backend().await;

    create_test_basin(&backend, "prod-app-1", BasinConfig::default()).await;
    create_test_basin(&backend, "prod-app-2", BasinConfig::default()).await;
    create_test_basin(&backend, "dev-app-1", BasinConfig::default()).await;
    create_test_basin(&backend, "staging-app-1", BasinConfig::default()).await;

    let prod_basins = backend
        .list_basins(
            ListItemsRequestParts {
                prefix: "test-basin-prod-".parse().unwrap(),
                start_after: BasinNameStartAfter::default(),
                limit: Default::default(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list basins with prefix");

    assert_eq!(prod_basins.values.len(), 2);
    assert!(
        prod_basins
            .values
            .iter()
            .all(|b| b.name.as_ref().starts_with("test-basin-prod-"))
    );
}

#[tokio::test]
async fn test_list_basins_prefix_with_pagination() {
    let backend = create_backend().await;

    for i in 0..10 {
        create_test_basin(
            &backend,
            &format!("prefixed-{:02}", i),
            BasinConfig::default(),
        )
        .await;
    }
    create_test_basin(&backend, "other-basin", BasinConfig::default()).await;

    let page1 = backend
        .list_basins(
            ListItemsRequestParts {
                prefix: "test-basin-prefixed-".parse().unwrap(),
                start_after: BasinNameStartAfter::default(),
                limit: 4.into(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list basins");

    assert_eq!(page1.values.len(), 4);
    assert!(page1.has_more);
    assert!(
        page1
            .values
            .iter()
            .all(|b| b.name.as_ref().starts_with("test-basin-prefixed-"))
    );

    let page2 = backend
        .list_basins(
            ListItemsRequestParts {
                prefix: "test-basin-prefixed-".parse().unwrap(),
                start_after: page1.values.last().unwrap().name.clone().into(),
                limit: 4.into(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list basins");

    assert_eq!(page2.values.len(), 4);
    assert!(page2.has_more);

    let page3 = backend
        .list_basins(
            ListItemsRequestParts {
                prefix: "test-basin-prefixed-".parse().unwrap(),
                start_after: page2.values.last().unwrap().name.clone().into(),
                limit: 4.into(),
            }
            .try_into()
            .unwrap(),
        )
        .await
        .expect("Failed to list basins");

    assert_eq!(page3.values.len(), 2);
    assert!(!page3.has_more);
}
