mod common;

use std::time::Duration;

use assert_matches::assert_matches;
use common::{s2, unique_basin_name, uuid};
use s2_sdk::{
    error::{RequestError, ServerError},
    types::*,
};

#[tokio::test]
async fn create_list_and_delete_basin() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = s2();
    let basin_name = unique_basin_name();

    let basin_info = s2
        .create_basin(CreateBasinInput::new(basin_name.clone()))
        .await?;

    assert_eq!(basin_info.name, basin_name);
    assert!(basin_info.created_at <= Timestamp::now());
    assert!(basin_info.deleted_at.is_none());

    let page = s2
        .list_basins(ListBasinsInput::new().with_prefix(basin_name.clone().into()))
        .await?;

    assert_matches!(
        page.values.as_slice(),
        [BasinInfo {
            name,
            location,
            deleted_at: None,
            ..
        }] if name == &basin_info.name && location == &basin_info.location
    );
    assert!(!page.has_more);

    s2.delete_basin(basin_name.clone()).await?;

    let page = s2
        .list_basins(ListBasinsInput::new().with_prefix(basin_name.clone().into()))
        .await?;

    match page.values.as_slice() {
        [] => {}
        [
            BasinInfo {
                name,
                location,
                deleted_at: Some(_),
                ..
            },
        ] => {
            assert_eq!(name, &basin_info.name);
            assert_eq!(location, &basin_info.location);
        }
        values => panic!("unexpected basin listing after delete: {values:?}"),
    }

    // Deleting a nonexistent basin is idempotent (M4).
    s2.delete_basin(unique_basin_name()).await?;

    Ok(())
}

#[tokio::test]
async fn basin_config_and_reconfigure() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = s2();
    let basin_name = unique_basin_name();
    let config = BasinConfig::new()
        .with_default_stream_config(
            StreamConfig::new()
                .with_storage_class("express")
                .with_delete_on_empty(DeleteOnEmptyConfig::new().with_min_age_secs(60)),
        )
        .with_create_stream_on_append(true)
        .with_create_stream_on_read(true);

    s2.create_basin(CreateBasinInput::new(basin_name.clone()).with_config(config))
        .await?;

    let retrieved = s2.get_basin_config(basin_name.clone()).await?;
    let default_cfg = retrieved
        .default_stream_config()
        .expect("default_stream_config should be present");
    assert_eq!(default_cfg.storage_class(), Some("express"));
    assert_eq!(
        default_cfg.delete_on_empty().map(|d| d.min_age_secs()),
        Some(60)
    );
    assert!(retrieved.create_stream_on_append());
    assert!(retrieved.create_stream_on_read());

    let updated = s2
        .reconfigure_basin(
            basin_name.clone(),
            BasinReconfiguration::new()
                .with_default_stream_config(
                    StreamReconfiguration::new().with_storage_class("standard"),
                )
                .with_create_stream_on_append(false),
        )
        .await?;
    assert_eq!(
        updated
            .default_stream_config()
            .and_then(|c| c.storage_class()),
        Some("standard")
    );
    assert!(!updated.create_stream_on_append());

    s2.delete_basin(basin_name).await?;

    Ok(())
}

#[tokio::test]
async fn ensure_basin_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = s2();
    let basin_name = unique_basin_name();

    let created = s2
        .ensure_basin(
            EnsureBasinInput::new(basin_name.clone())
                .with_config(BasinConfig::new().with_create_stream_on_read(true)),
        )
        .await?;
    assert_matches!(created, EnsureOutput::Created(info) => {
        assert_eq!(info.name, basin_name);
    });

    let config = s2.get_basin_config(basin_name.clone()).await?;
    assert!(config.create_stream_on_read());

    let noop = s2
        .ensure_basin(EnsureBasinInput::new(basin_name.clone()).with_config(config.clone()))
        .await?;
    assert_matches!(noop, EnsureOutput::Noop(_));
    assert_eq!(s2.get_basin_config(basin_name.clone()).await?, config);

    let updated = s2
        .ensure_basin(
            EnsureBasinInput::new(basin_name.clone())
                .with_config(BasinConfig::new().with_create_stream_on_read(false)),
        )
        .await?;
    assert_matches!(updated, EnsureOutput::Updated(_));
    assert!(
        !s2.get_basin_config(basin_name.clone())
            .await?
            .create_stream_on_read()
    );

    s2.delete_basin(basin_name).await?;

    Ok(())
}

#[tokio::test]
async fn list_basins_filters() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = s2();
    let prefix_1: BasinNamePrefix = uuid().parse().expect("valid basin name prefix");
    let prefix_2: BasinNamePrefix = uuid().parse().expect("valid basin name prefix");
    let basin_1a: BasinName = format!("{prefix_1}-a").parse().expect("valid basin name");
    let basin_1b: BasinName = format!("{prefix_1}-b").parse().expect("valid basin name");
    let basin_2a: BasinName = format!("{prefix_2}-a").parse().expect("valid basin name");

    for name in [&basin_1a, &basin_1b, &basin_2a] {
        s2.create_basin(CreateBasinInput::new(name.clone())).await?;
    }

    let by_prefix = s2
        .list_basins(ListBasinsInput::new().with_prefix(prefix_1.clone()))
        .await?;
    assert_eq!(by_prefix.values.len(), 2);
    assert_eq!(by_prefix.values[0].name, basin_1a);
    assert_eq!(by_prefix.values[1].name, basin_1b);

    let limited = s2
        .list_basins(
            ListBasinsInput::new()
                .with_prefix(prefix_1.clone())
                .with_limit(1),
        )
        .await?;
    assert_eq!(limited.values.len(), 1);
    assert_eq!(limited.values[0].name, basin_1a);
    assert!(limited.has_more);

    let after = s2
        .list_basins(
            ListBasinsInput::new()
                .with_prefix(prefix_1)
                .with_start_after(basin_1a.as_ref().parse().expect("valid start after")),
        )
        .await?;
    assert_eq!(after.values.len(), 1);
    assert_eq!(after.values[0].name, basin_1b);

    for name in [basin_1a, basin_1b, basin_2a] {
        s2.delete_basin(name).await?;
    }

    Ok(())
}

#[tokio::test]
async fn issue_list_and_revoke_access_token() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = s2();
    let token_id: AccessTokenId = uuid().parse().expect("valid token id");
    let expires_at = Timestamp::now() + Duration::from_secs(3600);

    let token = s2
        .issue_access_token(
            IssueAccessTokenInput::new(
                token_id.clone(),
                AccessTokenScope::from_op_group_perms(OperationGroupPermissions::read_write_all())
                    .with_streams(StreamMatcher::Prefix(
                        "namespace".parse().expect("valid prefix"),
                    )),
            )
            .with_expires_at(expires_at)
            .with_auto_prefix_streams(true),
        )
        .await?;
    assert!(!token.is_empty());

    let page = s2
        .list_access_tokens(ListAccessTokensInput::new().with_prefix(token_id.clone().into()))
        .await?;
    let issued = page
        .values
        .iter()
        .find(|t| t.id == token_id)
        .expect("token should be present");
    assert_eq!(issued.expires_at, Some(expires_at));
    assert!(issued.auto_prefix_streams);

    s2.revoke_access_token(token_id.clone()).await?;

    let page = s2
        .list_access_tokens(ListAccessTokensInput::new().with_prefix(token_id.clone().into()))
        .await?;
    assert!(!page.values.iter().any(|t| t.id == token_id));

    Ok(())
}

#[tokio::test]
async fn list_access_tokens_with_prefix_and_limit() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = s2();
    let prefix = uuid();
    let token_id_1: AccessTokenId = format!("{prefix}-a").parse().expect("valid token id");
    let token_id_2: AccessTokenId = format!("{prefix}-b").parse().expect("valid token id");
    let token_id_3: AccessTokenId = format!("{}-c", uuid()).parse().expect("valid token id");

    let scope = AccessTokenScope::from_op_group_perms(OperationGroupPermissions::read_write_all());
    for id in [&token_id_1, &token_id_2, &token_id_3] {
        s2.issue_access_token(IssueAccessTokenInput::new(id.clone(), scope.clone()))
            .await?;
    }

    let prefix_parsed: AccessTokenIdPrefix = prefix.parse().expect("valid prefix");
    let by_prefix = s2
        .list_access_tokens(ListAccessTokensInput::new().with_prefix(prefix_parsed.clone()))
        .await?;
    assert_eq!(by_prefix.values.len(), 2);
    assert!(by_prefix.values.iter().any(|t| t.id == token_id_1));
    assert!(by_prefix.values.iter().any(|t| t.id == token_id_2));

    let limited = s2
        .list_access_tokens(
            ListAccessTokensInput::new()
                .with_prefix(prefix_parsed)
                .with_limit(1),
        )
        .await?;
    assert_eq!(limited.values.len(), 1);

    for id in [token_id_1, token_id_2, token_id_3] {
        s2.revoke_access_token(id).await?;
    }

    Ok(())
}

#[tokio::test]
async fn issue_access_token_validation_errors() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = s2();
    let token_id: AccessTokenId = uuid().parse().expect("valid token id");

    let err = s2
        .issue_access_token(
            IssueAccessTokenInput::new(
                token_id.clone(),
                AccessTokenScope::from_op_group_perms(OperationGroupPermissions::read_write_all()),
            )
            .with_auto_prefix_streams(true),
        )
        .await;
    assert_matches!(err, Err(RequestError::Server(ServerError { code, message, .. })) => {
        assert_eq!(code.as_deref(), Some("invalid"));
        assert_eq!(message, "Auto prefixing is only allowed for streams with prefix matching");
    });

    for scope in [
        AccessTokenScope::from_op_group_perms(OperationGroupPermissions::new()),
        AccessTokenScope::from_ops(vec![]),
    ] {
        let err = s2
            .issue_access_token(IssueAccessTokenInput::new(token_id.clone(), scope))
            .await;
        assert_matches!(err, Err(RequestError::Server(ServerError { code, message, .. })) => {
            assert_eq!(code.as_deref(), Some("invalid"));
            assert_eq!(message, "Access token permissions cannot be empty");
        });
    }

    Ok(())
}
