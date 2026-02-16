mod common;

use std::time::Duration;

use assert_matches::assert_matches;
use common::{S2Basin, SharedS2Basin, unique_stream_name, uuid};
use futures::StreamExt;
use s2_sdk::types::*;
use test_context::test_context;

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_list_and_delete_stream(basin: &S2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();

    let stream_info = basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    assert_eq!(stream_info.name, stream_name);

    let page = basin.list_streams(ListStreamsInput::new()).await?;

    assert_eq!(page.values, vec![stream_info]);
    assert!(!page.has_more);

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    let page = basin.list_streams(ListStreamsInput::new()).await?;

    assert_matches!(
        page.values.as_slice(),
        [] | [StreamInfo {
            deleted_at: Some(_),
            ..
        }]
    );

    Ok(())
}

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn stream_config_roundtrip(basin: &S2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    let config = StreamConfig::new()
        .with_storage_class(StorageClass::Standard)
        .with_retention_policy(RetentionPolicy::Age(3600))
        .with_timestamping(TimestampingConfig::new().with_mode(TimestampingMode::ClientRequire));

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config.clone()))
        .await?;

    let retrieved_config = basin.get_stream_config(stream_name.clone()).await?;

    assert_matches!(
        retrieved_config,
        StreamConfig {
            storage_class: Some(StorageClass::Standard),
            retention_policy: Some(RetentionPolicy::Age(3600)),
            timestamping: Some(TimestampingConfig {
                mode: Some(TimestampingMode::ClientRequire),
                ..
            }),
            ..
        }
    );

    Ok(())
}

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream(basin: &S2Basin) -> Result<(), S2Error> {
    let stream_name: StreamName = unique_stream_name();

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let new_config = StreamReconfiguration::new().with_delete_on_empty(
        DeleteOnEmptyReconfiguration::new().with_min_age(Duration::from_hours(12)),
    );

    let updated_config = basin
        .reconfigure_stream(ReconfigureStreamInput::new(stream_name.clone(), new_config))
        .await?;

    assert_matches!(
        updated_config.delete_on_empty,
        Some(DeleteOnEmptyConfig {
            min_age_secs: 43200,
            ..
        })
    );

    Ok(())
}

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_streams_with_limit(basin: &S2Basin) -> Result<(), S2Error> {
    let stream_name_1 = unique_stream_name();
    let stream_name_2 = unique_stream_name();
    let stream_name_3 = unique_stream_name();

    let stream_info_1 = basin
        .create_stream(CreateStreamInput::new(stream_name_1.clone()))
        .await?;

    let _stream_info_2 = basin
        .create_stream(CreateStreamInput::new(stream_name_2.clone()))
        .await?;
    let _stream_info_3 = basin
        .create_stream(CreateStreamInput::new(stream_name_3.clone()))
        .await?;

    let page = basin
        .list_streams(ListStreamsInput::new().with_limit(1))
        .await?;

    assert_eq!(page.values, vec![stream_info_1]);
    assert!(page.has_more);

    Ok(())
}

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_streams_with_prefix(basin: &S2Basin) -> Result<(), S2Error> {
    let stream_name_1: StreamName = "users/eu/0001".parse().expect("valid stream name");
    let stream_name_2: StreamName = "users/ca/0001".parse().expect("valid stream name");
    let stream_name_3: StreamName = "users/ca/0002".parse().expect("valid stream name");

    let _stream_info_1 = basin
        .create_stream(CreateStreamInput::new(stream_name_1.clone()))
        .await?;
    let stream_info_2 = basin
        .create_stream(CreateStreamInput::new(stream_name_2.clone()))
        .await?;
    let stream_info_3 = basin
        .create_stream(CreateStreamInput::new(stream_name_3.clone()))
        .await?;

    let page = basin
        .list_streams(
            ListStreamsInput::new().with_prefix("users/ca/".parse().expect("valid prefix")),
        )
        .await?;

    assert_eq!(page.values, vec![stream_info_2, stream_info_3]);
    assert!(!page.has_more);

    Ok(())
}

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_streams_with_start_after(basin: &S2Basin) -> Result<(), S2Error> {
    let stream_name_1 = unique_stream_name();
    let stream_name_2 = unique_stream_name();

    let _stream_info_1 = basin
        .create_stream(CreateStreamInput::new(stream_name_1.clone()))
        .await?;
    let stream_info_2 = basin
        .create_stream(CreateStreamInput::new(stream_name_2.clone()))
        .await?;

    let page = basin
        .list_streams(
            ListStreamsInput::new()
                .with_start_after(stream_name_1.parse().expect("valid start after")),
        )
        .await?;

    assert_eq!(page.values, vec![stream_info_2]);
    assert!(!page.has_more);

    Ok(())
}

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_streams_with_start_after_returns_empty_page(basin: &S2Basin) -> Result<(), S2Error> {
    let stream_name_1 = unique_stream_name();
    let stream_name_2 = unique_stream_name();

    basin
        .create_stream(CreateStreamInput::new(stream_name_1.clone()))
        .await?;
    basin
        .create_stream(CreateStreamInput::new(stream_name_2.clone()))
        .await?;

    let page = basin
        .list_streams(
            ListStreamsInput::new()
                .with_start_after(stream_name_2.parse().expect("valid start after")),
        )
        .await?;

    assert_eq!(page.values.len(), 0);
    assert!(!page.has_more);

    Ok(())
}

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_streams_with_start_after_less_than_prefix_errors(
    basin: &S2Basin,
) -> Result<(), S2Error> {
    let prefix = uuid();
    let stream_name_1: StreamName = format!("{}-a-a", prefix)
        .parse()
        .expect("valid stream name");
    let stream_name_2: StreamName = format!("{}-a-b", prefix)
        .parse()
        .expect("valid stream name");
    let stream_name_3: StreamName = format!("{}-b-a", prefix)
        .parse()
        .expect("valid stream name");

    basin
        .create_stream(CreateStreamInput::new(stream_name_1.clone()))
        .await?;
    basin
        .create_stream(CreateStreamInput::new(stream_name_2.clone()))
        .await?;
    basin
        .create_stream(CreateStreamInput::new(stream_name_3.clone()))
        .await?;

    let result = basin
        .list_streams(
            ListStreamsInput::new()
                .with_prefix(format!("{}-b", prefix).parse().expect("valid prefix"))
                .with_start_after(format!("{}-a", prefix).parse().expect("valid start after")),
        )
        .await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, message, .. })) => {
            assert_eq!(code, "invalid");
            assert_eq!(message, "`start_after` must be greater than or equal to the `prefix`");
        }
    );

    Ok(())
}

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn delete_nonexistent_stream_errors(basin: &S2Basin) -> Result<(), S2Error> {
    let result = basin
        .delete_stream(DeleteStreamInput::new(unique_stream_name()))
        .await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse {code, message: _, ..})) => {
            assert_eq!(code, "stream_not_found")
        }
    );

    Ok(())
}

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn delete_nonexistent_stream_with_ignore(basin: &S2Basin) -> Result<(), S2Error> {
    let result = basin
        .delete_stream(DeleteStreamInput::new(unique_stream_name()).with_ignore_not_found(true))
        .await;

    assert_matches!(result, Ok(()));

    Ok(())
}

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn get_stream_config(basin: &S2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();

    let config = StreamConfig::new().with_storage_class(StorageClass::Express);

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config))
        .await?;

    let retrieved_config = basin.get_stream_config(stream_name.clone()).await?;

    assert_matches!(retrieved_config.storage_class, Some(StorageClass::Express));

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_streams_with_limit_zero(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let prefix = format!("limit0-{}", uuid());
    let stream_name: StreamName = format!("{}-0001", prefix)
        .parse()
        .expect("valid stream name");

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let page = basin
        .list_streams(
            ListStreamsInput::new()
                .with_prefix(prefix.parse().expect("valid prefix"))
                .with_limit(0),
        )
        .await?;

    assert!(page.values.iter().any(|info| info.name == stream_name));
    assert!(page.values.len() <= 1000);

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_streams_with_limit_over_max(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let prefix = format!("limitmax-{}", uuid());
    let stream_name: StreamName = format!("{}-0001", prefix)
        .parse()
        .expect("valid stream name");

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let page = basin
        .list_streams(
            ListStreamsInput::new()
                .with_prefix(prefix.parse().expect("valid prefix"))
                .with_limit(1500),
        )
        .await?;

    assert!(page.values.iter().any(|info| info.name == stream_name));
    assert!(page.values.len() <= 1000);

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_streams_with_pagination(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let prefix = format!("page-{}", uuid());
    let stream_names: Vec<StreamName> = (0..3)
        .map(|idx| {
            format!("{}-{:04}", prefix, idx)
                .parse()
                .expect("valid stream name")
        })
        .collect();

    for name in &stream_names {
        basin
            .create_stream(CreateStreamInput::new(name.clone()))
            .await?;
    }

    let page_1 = basin
        .list_streams(
            ListStreamsInput::new()
                .with_prefix(prefix.parse().expect("valid prefix"))
                .with_limit(2),
        )
        .await?;

    assert!(!page_1.values.is_empty());

    let last_name = page_1
        .values
        .last()
        .expect("page should have value")
        .name
        .clone();

    let page_2 = basin
        .list_streams(
            ListStreamsInput::new()
                .with_prefix(prefix.parse().expect("valid prefix"))
                .with_start_after(last_name.clone().into())
                .with_limit(2),
        )
        .await?;

    assert!(
        page_2
            .values
            .iter()
            .all(|info| info.name.as_ref() > last_name.as_ref())
    );

    let mut listed: Vec<String> = page_1
        .values
        .into_iter()
        .chain(page_2.values.into_iter())
        .map(|info| info.name.to_string())
        .collect();
    listed.sort();
    let mut expected: Vec<String> = stream_names.iter().map(|name| name.to_string()).collect();
    expected.sort();
    assert_eq!(listed, expected);

    for name in stream_names {
        let _ = basin.delete_stream(DeleteStreamInput::new(name)).await;
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_streams_returns_lexicographic_order(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let prefix = format!("order-{}", uuid());
    let stream_names: Vec<StreamName> = (1..=3)
        .map(|idx| {
            format!("{}-{:04}", prefix, idx)
                .parse()
                .expect("valid stream name")
        })
        .collect();

    for name in &stream_names {
        basin
            .create_stream(CreateStreamInput::new(name.clone()))
            .await?;
    }

    let page = basin
        .list_streams(ListStreamsInput::new().with_prefix(prefix.parse().expect("valid prefix")))
        .await?;

    let listed: Vec<StreamName> = page.values.into_iter().map(|info| info.name).collect();
    assert_eq!(listed, stream_names);

    for name in stream_names {
        let _ = basin.delete_stream(DeleteStreamInput::new(name)).await;
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_all_streams_iterates_with_prefix(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let prefix = format!("iter-{}", uuid());
    let stream_names: Vec<StreamName> = (1..=3)
        .map(|idx| {
            format!("{}-{:04}", prefix, idx)
                .parse()
                .expect("valid stream name")
        })
        .collect();

    for name in &stream_names {
        basin
            .create_stream(CreateStreamInput::new(name.clone()))
            .await?;
    }

    let mut listed = Vec::new();
    let mut stream = basin.list_all_streams(
        ListAllStreamsInput::new().with_prefix(prefix.parse().expect("valid prefix")),
    );
    while let Some(info) = stream.next().await {
        listed.push(info?.name);
    }

    assert_eq!(listed, stream_names);

    for name in stream_names {
        let _ = basin.delete_stream(DeleteStreamInput::new(name)).await;
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_all_streams_include_deleted(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let prefix = format!("iter-del-{}", uuid());
    let stream_name: StreamName = format!("{}-0001", prefix)
        .parse()
        .expect("valid stream name");

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;
    basin
        .delete_stream(DeleteStreamInput::new(stream_name.clone()))
        .await?;

    let mut stream = basin.list_all_streams(
        ListAllStreamsInput::new()
            .with_prefix(prefix.parse().expect("valid prefix"))
            .with_include_deleted(true),
    );

    let mut found = None;
    while let Some(info) = stream.next().await {
        let info = info?;
        if info.name == stream_name {
            found = Some(info);
            break;
        }
    }

    if let Some(info) = found {
        assert!(info.deleted_at.is_some());
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_stream_with_full_config(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    let config = StreamConfig::new()
        .with_storage_class(StorageClass::Standard)
        .with_retention_policy(RetentionPolicy::Age(86400))
        .with_timestamping(
            TimestampingConfig::new()
                .with_mode(TimestampingMode::ClientRequire)
                .with_uncapped(true),
        )
        .with_delete_on_empty(DeleteOnEmptyConfig::new().with_min_age(Duration::from_secs(3600)));

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config))
        .await?;

    let retrieved = basin.get_stream_config(stream_name.clone()).await?;

    assert_matches!(
        retrieved,
        StreamConfig {
            storage_class: Some(StorageClass::Standard),
            retention_policy: Some(RetentionPolicy::Age(86400)),
            timestamping: Some(TimestampingConfig {
                mode: Some(TimestampingMode::ClientRequire),
                uncapped: true,
                ..
            }),
            delete_on_empty: Some(DeleteOnEmptyConfig {
                min_age_secs: 3600,
                ..
            }),
            ..
        }
    );

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_stream_storage_class_express(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    let config = StreamConfig::new().with_storage_class(StorageClass::Express);

    let result = basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config))
        .await;

    let info = match result {
        Ok(info) => info,
        Err(err) if is_free_tier_limitation(&err) => return Ok(()),
        Err(err) => return Err(err),
    };

    assert_eq!(info.name, stream_name);

    let retrieved = basin.get_stream_config(stream_name.clone()).await?;
    assert_matches!(retrieved.storage_class, Some(StorageClass::Express) | None);

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_stream_retention_policy_infinite(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    let config = StreamConfig::new().with_retention_policy(RetentionPolicy::Infinite);

    let result = basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config))
        .await;

    let info = match result {
        Ok(info) => info,
        Err(err) if is_free_tier_limitation(&err) => return Ok(()),
        Err(err) => return Err(err),
    };

    assert_eq!(info.name, stream_name);

    let retrieved = basin.get_stream_config(stream_name.clone()).await?;
    assert_matches!(retrieved.retention_policy, Some(RetentionPolicy::Infinite));

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_stream_timestamping_modes(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let modes = [
        TimestampingMode::ClientPrefer,
        TimestampingMode::ClientRequire,
        TimestampingMode::Arrival,
    ];

    for mode in modes {
        let stream_name = unique_stream_name();
        let config =
            StreamConfig::new().with_timestamping(TimestampingConfig::new().with_mode(mode));

        basin
            .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config))
            .await?;

        let retrieved = basin.get_stream_config(stream_name.clone()).await?;
        match mode {
            TimestampingMode::ClientPrefer => {
                if let Some(timestamping) = retrieved.timestamping {
                    assert_matches!(
                        timestamping.mode,
                        Some(TimestampingMode::ClientPrefer) | None
                    );
                }
            }
            _ => {
                assert_matches!(
                    retrieved.timestamping,
                    Some(TimestampingConfig {
                        mode: Some(m),
                        ..
                    }) if m == mode
                );
            }
        }

        basin
            .delete_stream(DeleteStreamInput::new(stream_name))
            .await?;
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_stream_timestamping_uncapped(basin: &SharedS2Basin) -> Result<(), S2Error> {
    for uncapped in [true, false] {
        let stream_name = unique_stream_name();
        let config = StreamConfig::new()
            .with_timestamping(TimestampingConfig::new().with_uncapped(uncapped));

        basin
            .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config))
            .await?;

        let retrieved = basin.get_stream_config(stream_name.clone()).await?;
        match retrieved.timestamping {
            Some(timestamping) => assert_eq!(timestamping.uncapped, uncapped),
            None => assert!(!uncapped),
        }

        basin
            .delete_stream(DeleteStreamInput::new(stream_name))
            .await?;
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_stream_delete_on_empty_min_age(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    let config = StreamConfig::new()
        .with_delete_on_empty(DeleteOnEmptyConfig::new().with_min_age(Duration::from_secs(3600)));

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config))
        .await?;

    let retrieved = basin.get_stream_config(stream_name.clone()).await?;
    assert_matches!(
        retrieved.delete_on_empty,
        Some(DeleteOnEmptyConfig {
            min_age_secs: 3600,
            ..
        })
    );

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_stream_invalid_retention_age_zero(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    let config = StreamConfig::new().with_retention_policy(RetentionPolicy::Age(0));

    let result = basin
        .create_stream(CreateStreamInput::new(stream_name).with_config(config))
        .await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "invalid");
        }
    );

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn get_stream_config_nonexistent_errors(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let result = basin.get_stream_config(unique_stream_name()).await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "stream_not_found");
        }
    );

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_storage_class_standard(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let config = basin
        .reconfigure_stream(ReconfigureStreamInput::new(
            stream_name.clone(),
            StreamReconfiguration::new().with_storage_class(StorageClass::Standard),
        ))
        .await?;

    assert_matches!(config.storage_class, Some(StorageClass::Standard));

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_storage_class_express(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let result = basin
        .reconfigure_stream(ReconfigureStreamInput::new(
            stream_name.clone(),
            StreamReconfiguration::new().with_storage_class(StorageClass::Express),
        ))
        .await;

    let config = match result {
        Ok(config) => config,
        Err(err) if is_free_tier_limitation(&err) => {
            let _ = basin
                .delete_stream(DeleteStreamInput::new(stream_name))
                .await;
            return Ok(());
        }
        Err(err) => return Err(err),
    };

    assert_matches!(config.storage_class, Some(StorageClass::Express) | None);

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_retention_policy_age(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let config = basin
        .reconfigure_stream(ReconfigureStreamInput::new(
            stream_name.clone(),
            StreamReconfiguration::new().with_retention_policy(RetentionPolicy::Age(3600)),
        ))
        .await?;

    assert_matches!(config.retention_policy, Some(RetentionPolicy::Age(3600)));

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_retention_policy_infinite(
    basin: &SharedS2Basin,
) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let result = basin
        .reconfigure_stream(ReconfigureStreamInput::new(
            stream_name.clone(),
            StreamReconfiguration::new().with_retention_policy(RetentionPolicy::Infinite),
        ))
        .await;

    let config = match result {
        Ok(config) => config,
        Err(err) if is_free_tier_limitation(&err) => {
            let _ = basin
                .delete_stream(DeleteStreamInput::new(stream_name))
                .await;
            return Ok(());
        }
        Err(err) => return Err(err),
    };

    assert_matches!(config.retention_policy, Some(RetentionPolicy::Infinite));

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_timestamping_modes(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let modes = [
        TimestampingMode::ClientPrefer,
        TimestampingMode::ClientRequire,
        TimestampingMode::Arrival,
    ];

    for mode in modes {
        let stream_name = unique_stream_name();
        basin
            .create_stream(CreateStreamInput::new(stream_name.clone()))
            .await?;

        let config = basin
            .reconfigure_stream(ReconfigureStreamInput::new(
                stream_name.clone(),
                StreamReconfiguration::new()
                    .with_timestamping(TimestampingReconfiguration::new().with_mode(mode)),
            ))
            .await?;

        match mode {
            TimestampingMode::ClientPrefer => {
                if let Some(timestamping) = config.timestamping {
                    assert_matches!(
                        timestamping.mode,
                        Some(TimestampingMode::ClientPrefer) | None
                    );
                }
            }
            _ => {
                assert_matches!(
                    config.timestamping,
                    Some(TimestampingConfig {
                        mode: Some(m),
                        ..
                    }) if m == mode
                );
            }
        }

        basin
            .delete_stream(DeleteStreamInput::new(stream_name))
            .await?;
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_timestamping_uncapped(basin: &SharedS2Basin) -> Result<(), S2Error> {
    for uncapped in [true, false] {
        let stream_name = unique_stream_name();
        basin
            .create_stream(CreateStreamInput::new(stream_name.clone()))
            .await?;

        let config = basin
            .reconfigure_stream(ReconfigureStreamInput::new(
                stream_name.clone(),
                StreamReconfiguration::new()
                    .with_timestamping(TimestampingReconfiguration::new().with_uncapped(uncapped)),
            ))
            .await?;

        match config.timestamping {
            Some(timestamping) => assert_eq!(timestamping.uncapped, uncapped),
            None => assert!(!uncapped),
        }

        basin
            .delete_stream(DeleteStreamInput::new(stream_name))
            .await?;
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_delete_on_empty(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let config = basin
        .reconfigure_stream(ReconfigureStreamInput::new(
            stream_name.clone(),
            StreamReconfiguration::new().with_delete_on_empty(
                DeleteOnEmptyReconfiguration::new().with_min_age(Duration::from_secs(3600)),
            ),
        ))
        .await?;

    assert_matches!(
        config.delete_on_empty,
        Some(DeleteOnEmptyConfig {
            min_age_secs: 3600,
            ..
        })
    );

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_disable_delete_on_empty(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(
            StreamConfig::new().with_delete_on_empty(
                DeleteOnEmptyConfig::new().with_min_age(Duration::from_secs(3600)),
            ),
        ))
        .await?;

    let config = basin
        .reconfigure_stream(ReconfigureStreamInput::new(
            stream_name.clone(),
            StreamReconfiguration::new().with_delete_on_empty(
                DeleteOnEmptyReconfiguration::new().with_min_age(Duration::from_secs(0)),
            ),
        ))
        .await?;

    assert!(
        config.delete_on_empty.is_none()
            || config.delete_on_empty == Some(DeleteOnEmptyConfig::new())
    );

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_empty_config_no_change(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(
            CreateStreamInput::new(stream_name.clone()).with_config(
                StreamConfig::new()
                    .with_storage_class(StorageClass::Standard)
                    .with_retention_policy(RetentionPolicy::Age(3600)),
            ),
        )
        .await?;

    let _ = basin
        .reconfigure_stream(ReconfigureStreamInput::new(
            stream_name.clone(),
            StreamReconfiguration::new(),
        ))
        .await?;

    let retrieved = basin.get_stream_config(stream_name.clone()).await?;
    assert_matches!(retrieved.storage_class, Some(StorageClass::Standard));
    assert_matches!(retrieved.retention_policy, Some(RetentionPolicy::Age(3600)));

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_partial_update(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(
            CreateStreamInput::new(stream_name.clone()).with_config(
                StreamConfig::new()
                    .with_retention_policy(RetentionPolicy::Age(3600))
                    .with_timestamping(
                        TimestampingConfig::new().with_mode(TimestampingMode::ClientPrefer),
                    ),
            ),
        )
        .await?;

    let _ = basin
        .reconfigure_stream(ReconfigureStreamInput::new(
            stream_name.clone(),
            StreamReconfiguration::new().with_timestamping(
                TimestampingReconfiguration::new().with_mode(TimestampingMode::Arrival),
            ),
        ))
        .await?;

    let retrieved = basin.get_stream_config(stream_name.clone()).await?;
    assert_matches!(retrieved.retention_policy, Some(RetentionPolicy::Age(3600)));
    assert_matches!(
        retrieved.timestamping,
        Some(TimestampingConfig {
            mode: Some(TimestampingMode::Arrival),
            ..
        })
    );

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_invalid_retention_age_zero(
    basin: &SharedS2Basin,
) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let result = basin
        .reconfigure_stream(ReconfigureStreamInput::new(
            stream_name.clone(),
            StreamReconfiguration::new().with_retention_policy(RetentionPolicy::Age(0)),
        ))
        .await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "invalid");
        }
    );

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_nonexistent_errors(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let result = basin
        .reconfigure_stream(ReconfigureStreamInput::new(
            unique_stream_name(),
            StreamReconfiguration::new().with_storage_class(StorageClass::Standard),
        ))
        .await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "stream_not_found");
        }
    );

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_stream_duplicate_name_errors(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let result = basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "resource_already_exists");
        }
    );

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn delete_stream_already_deleting_is_idempotent(
    basin: &SharedS2Basin,
) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    basin
        .delete_stream(DeleteStreamInput::new(stream_name.clone()))
        .await?;

    let result = basin
        .delete_stream(DeleteStreamInput::new(stream_name.clone()))
        .await;

    match result {
        Ok(()) => {}
        Err(S2Error::Server(ErrorResponse { code, .. })) if code == "stream_not_found" => {}
        Err(err) => return Err(err),
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn get_stream_config_for_deleting_stream_errors(
    basin: &SharedS2Basin,
) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    basin
        .delete_stream(DeleteStreamInput::new(stream_name.clone()))
        .await?;

    let result = basin.get_stream_config(stream_name.clone()).await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert!(code == "stream_deletion_pending" || code == "stream_not_found");
        }
    );

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn deleted_stream_has_deleted_at_when_listed(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    basin
        .delete_stream(DeleteStreamInput::new(stream_name.clone()))
        .await?;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let page = basin
            .list_streams(ListStreamsInput::new().with_prefix(stream_name.clone().into()))
            .await?;

        let mut found = false;
        for info in page.values {
            if info.name == stream_name {
                found = true;
                if info.deleted_at.is_some() {
                    return Ok(());
                }
            }
        }

        if !found {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    panic!("deleted stream still listed without deleted_at after timeout");
}

fn is_free_tier_limitation(err: &S2Error) -> bool {
    match err {
        S2Error::Server(ErrorResponse { code, message, .. }) if code == "invalid" => {
            message.to_lowercase().contains("free tier")
        }
        _ => false,
    }
}
