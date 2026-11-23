mod common;

use std::time::Duration;

use assert_matches::assert_matches;
use common::{S2Basin, SharedS2Basin, unique_stream_name, uuid};
use s2_sdk::{
    error::{RequestError, ServerError},
    types::*,
};
use test_context::test_context;

#[test_context(S2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_list_and_delete_stream(basin: &S2Basin) -> Result<(), RequestError> {
    let stream_name = unique_stream_name();

    let stream_info = basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    assert_eq!(stream_info.name, stream_name);

    let page = basin.list_streams(ListStreamsInput::new()).await?;

    assert_eq!(page.values, vec![stream_info]);
    assert!(!page.has_more);

    basin.delete_stream(stream_name.clone()).await?;

    let page = basin.list_streams(ListStreamsInput::new()).await?;

    match page.values.as_slice() {
        [] => {}
        [
            StreamInfo {
                name,
                deleted_at: Some(_),
                ..
            },
        ] => {
            assert_eq!(name, &stream_name);
        }
        values => panic!("unexpected stream listing after delete: {values:?}"),
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn ensure_stream_lifecycle(basin: &SharedS2Basin) -> Result<(), RequestError> {
    let stream_name = unique_stream_name();
    let delete_on_empty = DeleteOnEmptyConfig::new().with_min_age(Duration::from_hours(24))?;
    let initial = StreamConfig::new()
        .with_delete_on_empty(delete_on_empty)
        .with_timestamping(TimestampingConfig::new().with_mode(TimestampingMode::ClientRequire));

    let created = basin
        .ensure_stream(EnsureStreamInput::new(stream_name.clone()).with_config(initial))
        .await?;
    assert_matches!(created, EnsureOutput::Created(info) => {
        assert_eq!(info.name, stream_name);
    });

    let config = basin.get_stream_config(stream_name.clone()).await?;
    assert_eq!(config.delete_on_empty, Some(delete_on_empty));
    assert_matches!(
        config.timestamping,
        Some(TimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            ..
        })
    );

    let noop = basin
        .ensure_stream(EnsureStreamInput::new(stream_name.clone()).with_config(config.clone()))
        .await?;
    assert_matches!(noop, EnsureOutput::Noop(_));
    assert_eq!(basin.get_stream_config(stream_name.clone()).await?, config);

    let updated =
        basin
            .ensure_stream(EnsureStreamInput::new(stream_name.clone()).with_config(
                StreamConfig::new().with_timestamping(
                    TimestampingConfig::new().with_mode(TimestampingMode::Arrival),
                ),
            ))
            .await?;
    assert_matches!(updated, EnsureOutput::Updated(_));
    let updated_config = basin.get_stream_config(stream_name.clone()).await?;
    assert_matches!(
        updated_config.timestamping,
        Some(TimestampingConfig {
            mode: Some(TimestampingMode::Arrival),
            ..
        })
    );

    basin.delete_stream(stream_name).await?;
    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn list_streams_pagination_and_filters(
    basin: &SharedS2Basin,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = format!("list-{}", uuid());
    let ca_names: Vec<StreamName> = (1..=3)
        .map(|i| {
            format!("{root}/ca/{i:04}")
                .parse()
                .expect("valid stream name")
        })
        .collect();
    let eu_name: StreamName = format!("{root}/eu/0001")
        .parse()
        .expect("valid stream name");

    let mut ca_infos = Vec::with_capacity(ca_names.len());
    for name in &ca_names {
        ca_infos.push(
            basin
                .create_stream(CreateStreamInput::new(name.clone()))
                .await?,
        );
    }
    basin
        .create_stream(CreateStreamInput::new(eu_name.clone()))
        .await?;

    let ca_prefix: StreamNamePrefix = format!("{root}/ca/").parse().expect("valid prefix");

    // Prefix filter returns matching streams in lexicographic order.
    let by_prefix = basin
        .list_streams(ListStreamsInput::new().with_prefix(ca_prefix.clone()))
        .await?;
    assert_eq!(by_prefix.values, ca_infos);
    assert!(!by_prefix.has_more);

    // Pagination with limit + start_after, plus empty page past the last item.
    let page_1 = basin
        .list_streams(
            ListStreamsInput::new()
                .with_prefix(ca_prefix.clone())
                .with_limit(2),
        )
        .await?;
    assert_eq!(page_1.values, ca_infos[..2]);
    assert!(page_1.has_more);

    let page_2 = basin
        .list_streams(
            ListStreamsInput::new()
                .with_prefix(ca_prefix.clone())
                .with_start_after(ca_names[1].clone().into())
                .with_limit(2),
        )
        .await?;
    assert_eq!(page_2.values, ca_infos[2..]);
    assert!(!page_2.has_more);

    let empty = basin
        .list_streams(
            ListStreamsInput::new()
                .with_prefix(ca_prefix.clone())
                .with_start_after(ca_names[2].clone().into()),
        )
        .await?;
    assert!(empty.values.is_empty());
    assert!(!empty.has_more);

    // Server clamps limit=0 and limit>1000 to valid bounds.
    for limit in [0usize, 1500] {
        let page = basin
            .list_streams(
                ListStreamsInput::new()
                    .with_prefix(ca_prefix.clone())
                    .with_limit(limit),
            )
            .await?;
        assert_eq!(page.values, ca_infos);
        assert!(page.values.len() <= 1000);
    }

    // list_all_streams paginates across matching prefix.
    let mut listed = Vec::new();
    let mut stream = basin.list_all_streams(ListAllStreamsInput::new().with_prefix(ca_prefix));
    while let Some(info) = stream.next().await {
        listed.push(info?.name);
    }
    assert_eq!(listed, ca_names);

    for name in ca_names.into_iter().chain([eu_name]) {
        let _ = basin.delete_stream(name).await;
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn create_stream_configs(basin: &SharedS2Basin) -> Result<(), RequestError> {
    // Full config: standard + age retention + ClientRequire + uncapped=true + delete_on_empty.
    let s1 = unique_stream_name();
    let full = StreamConfig::new()
        .with_storage_class("standard")
        .with_retention_policy(RetentionPolicy::Age(86400))
        .with_timestamping(
            TimestampingConfig::new()
                .with_mode(TimestampingMode::ClientRequire)
                .with_uncapped(true),
        )
        .with_delete_on_empty(DeleteOnEmptyConfig::new().with_min_age(Duration::from_secs(3600))?);
    basin
        .create_stream(CreateStreamInput::new(s1.clone()).with_config(full))
        .await?;
    let retrieved = basin.get_stream_config(s1.clone()).await?;
    assert_matches!(
        retrieved,
        StreamConfig {
            storage_class: Some(ref storage_class),
            retention_policy: Some(RetentionPolicy::Age(86400)),
            timestamping: Some(TimestampingConfig {
                mode: Some(TimestampingMode::ClientRequire),
                uncapped: Some(true),
                ..
            }),
            delete_on_empty: Some(ref delete_on_empty),
            ..
        } if storage_class == "standard" && delete_on_empty.min_age() == Duration::from_secs(3600)
    );
    basin.delete_stream(s1).await?;

    // Arrival + uncapped=false and ClientPrefer.
    let s2 = unique_stream_name();
    basin
        .create_stream(
            CreateStreamInput::new(s2.clone()).with_config(
                StreamConfig::new().with_timestamping(
                    TimestampingConfig::new()
                        .with_mode(TimestampingMode::Arrival)
                        .with_uncapped(false),
                ),
            ),
        )
        .await?;
    let retrieved = basin.get_stream_config(s2.clone()).await?;
    assert_matches!(
        retrieved.timestamping,
        Some(TimestampingConfig {
            mode: Some(TimestampingMode::Arrival),
            uncapped: Some(false),
            ..
        })
    );
    basin.delete_stream(s2).await?;

    let s3 = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(s3.clone()).with_config(
            StreamConfig::new().with_timestamping(
                TimestampingConfig::new().with_mode(TimestampingMode::ClientPrefer),
            ),
        ))
        .await?;
    let retrieved = basin.get_stream_config(s3.clone()).await?;
    if let Some(ts) = retrieved.timestamping {
        assert_matches!(ts.mode, Some(TimestampingMode::ClientPrefer) | None);
    }
    basin.delete_stream(s3).await?;

    // Tier-gated options: express storage class and infinite retention.
    let s4 = unique_stream_name();
    match basin
        .create_stream(
            CreateStreamInput::new(s4.clone())
                .with_config(StreamConfig::new().with_storage_class("express")),
        )
        .await
    {
        Ok(info) => {
            assert_eq!(info.name, s4);
            let retrieved = basin.get_stream_config(s4.clone()).await?;
            assert_matches!(retrieved.storage_class.as_deref(), Some("express") | None);
            basin.delete_stream(s4).await?;
        }
        Err(err) if is_free_tier_limitation(&err) => {}
        Err(err) => return Err(err),
    }

    let s5 = unique_stream_name();
    match basin
        .create_stream(
            CreateStreamInput::new(s5.clone())
                .with_config(StreamConfig::new().with_retention_policy(RetentionPolicy::Infinite)),
        )
        .await
    {
        Ok(info) => {
            assert_eq!(info.name, s5);
            let retrieved = basin.get_stream_config(s5.clone()).await?;
            assert_matches!(retrieved.retention_policy, Some(RetentionPolicy::Infinite));
            basin.delete_stream(s5).await?;
        }
        Err(err) if is_free_tier_limitation(&err) => {}
        Err(err) => return Err(err),
    }

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn reconfigure_stream_configs(basin: &SharedS2Basin) -> Result<(), RequestError> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    // Set storage class, age retention, timestamping, and delete_on_empty.
    let config = basin
        .reconfigure_stream(
            stream_name.clone(),
            StreamReconfiguration::new()
                .with_storage_class("standard")
                .with_retention_policy(RetentionPolicy::Age(3600))
                .with_timestamping(
                    TimestampingReconfiguration::new()
                        .with_mode(TimestampingMode::ClientPrefer)
                        .with_uncapped(true),
                )
                .with_delete_on_empty(
                    DeleteOnEmptyReconfiguration::new().with_min_age(Duration::from_secs(3600))?,
                ),
        )
        .await?;
    assert_matches!(config.storage_class.as_deref(), Some("standard"));
    assert_matches!(config.retention_policy, Some(RetentionPolicy::Age(3600)));
    assert_eq!(
        config.delete_on_empty.map(|d| d.min_age()),
        Some(Duration::from_secs(3600))
    );
    let ts = config.timestamping.expect("timestamping should be present");
    assert_matches!(ts.mode, Some(TimestampingMode::ClientPrefer) | None);
    assert_eq!(ts.uncapped, Some(true));

    // Empty reconfiguration leaves existing config untouched.
    let _ = basin
        .reconfigure_stream(stream_name.clone(), StreamReconfiguration::new())
        .await?;
    let retrieved = basin.get_stream_config(stream_name.clone()).await?;
    assert_matches!(retrieved.storage_class.as_deref(), Some("standard"));
    assert_matches!(retrieved.retention_policy, Some(RetentionPolicy::Age(3600)));

    // Partial update modifies only timestamping while preserving retention_policy.
    let partial = basin
        .reconfigure_stream(
            stream_name.clone(),
            StreamReconfiguration::new().with_timestamping(
                TimestampingReconfiguration::new()
                    .with_mode(TimestampingMode::Arrival)
                    .with_uncapped(false),
            ),
        )
        .await?;
    assert_matches!(partial.retention_policy, Some(RetentionPolicy::Age(3600)));
    assert_matches!(
        partial.timestamping,
        Some(TimestampingConfig {
            mode: Some(TimestampingMode::Arrival),
            uncapped: Some(false),
            ..
        })
    );

    // Switch mode to ClientRequire and disable delete_on_empty with min_age = 0.
    let updated = basin
        .reconfigure_stream(
            stream_name.clone(),
            StreamReconfiguration::new()
                .with_timestamping(
                    TimestampingReconfiguration::new().with_mode(TimestampingMode::ClientRequire),
                )
                .with_delete_on_empty(
                    DeleteOnEmptyReconfiguration::new().with_min_age(Duration::ZERO)?,
                ),
        )
        .await?;
    assert_matches!(
        updated.timestamping,
        Some(TimestampingConfig {
            mode: Some(TimestampingMode::ClientRequire),
            ..
        })
    );
    assert!(
        updated.delete_on_empty.is_none()
            || updated.delete_on_empty == Some(DeleteOnEmptyConfig::new())
    );

    // Tier-gated reconfigurations: express and infinite retention.
    match basin
        .reconfigure_stream(
            stream_name.clone(),
            StreamReconfiguration::new().with_storage_class("express"),
        )
        .await
    {
        Ok(cfg) => assert_matches!(cfg.storage_class.as_deref(), Some("express") | None),
        Err(err) if is_free_tier_limitation(&err) => {}
        Err(err) => return Err(err),
    }

    match basin
        .reconfigure_stream(
            stream_name.clone(),
            StreamReconfiguration::new().with_retention_policy(RetentionPolicy::Infinite),
        )
        .await
    {
        Ok(cfg) => assert_matches!(cfg.retention_policy, Some(RetentionPolicy::Infinite)),
        Err(err) if is_free_tier_limitation(&err) => {}
        Err(err) => return Err(err),
    }

    basin.delete_stream(stream_name).await?;
    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn stream_management_errors_and_delete_idempotency(
    basin: &SharedS2Basin,
) -> Result<(), RequestError> {
    let stream_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    // Duplicate create fails with resource_already_exists.
    let dup = basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await;
    assert_matches!(
        dup,
        Err(RequestError::Server(ServerError { code, .. })) => {
            assert_eq!(code.as_deref(), Some("resource_already_exists"));
        }
    );

    // Invalid retention age 0 rejected on create and reconfigure.
    let bad_create = basin
        .create_stream(
            CreateStreamInput::new(unique_stream_name())
                .with_config(StreamConfig::new().with_retention_policy(RetentionPolicy::Age(0))),
        )
        .await;
    assert_matches!(
        bad_create,
        Err(RequestError::Server(ServerError { code, .. })) => {
            assert_eq!(code.as_deref(), Some("invalid"));
        }
    );

    let bad_reconf = basin
        .reconfigure_stream(
            stream_name.clone(),
            StreamReconfiguration::new().with_retention_policy(RetentionPolicy::Age(0)),
        )
        .await;
    assert_matches!(
        bad_reconf,
        Err(RequestError::Server(ServerError { code, .. })) => {
            assert_eq!(code.as_deref(), Some("invalid"));
        }
    );

    // Nonexistent stream errors on get_stream_config and reconfigure_stream; delete is idempotent.
    let missing = unique_stream_name();
    assert_matches!(
        basin.get_stream_config(missing.clone()).await,
        Err(RequestError::Server(ServerError { code, .. })) => {
            assert_eq!(code.as_deref(), Some("stream_not_found"));
        }
    );
    assert_matches!(
        basin
            .reconfigure_stream(
                missing.clone(),
                StreamReconfiguration::new().with_storage_class("standard"),
            )
            .await,
        Err(RequestError::Server(ServerError { code, .. })) => {
            assert_eq!(code.as_deref(), Some("stream_not_found"));
        }
    );
    basin.delete_stream(missing).await?;

    // Deleting an existing stream is idempotent, and get_stream_config errors once deleting.
    basin.delete_stream(stream_name.clone()).await?;
    basin.delete_stream(stream_name.clone()).await?;
    assert_matches!(
        basin.get_stream_config(stream_name).await,
        Err(RequestError::Server(ServerError { code, .. })) => {
            assert!(matches!(
                code.as_deref(),
                Some("stream_deletion_pending" | "stream_not_found")
            ));
        }
    );

    Ok(())
}

fn is_free_tier_limitation(err: &RequestError) -> bool {
    match err {
        RequestError::Server(ServerError { code, message, .. })
            if code.as_deref() == Some("invalid") =>
        {
            message.to_lowercase().contains("free tier")
        }
        _ => false,
    }
}
