mod common;

use std::time::Duration;

use assert_matches::assert_matches;
use common::{s2, unique_basin_name, uuid};
use s2_sdk::types::*;

#[tokio::test]
async fn create_list_and_delete_basin() -> Result<(), S2Error> {
    let s2 = s2();
    let basin_name = unique_basin_name();

    let basin_info = s2
        .create_basin(CreateBasinInput::new(basin_name.clone()))
        .await?;

    assert_eq!(basin_info.name, basin_name);

    let page = s2
        .list_basins(ListBasinsInput::new().with_prefix(basin_name.clone().into()))
        .await?;

    assert_eq!(page.values, vec![basin_info]);
    assert!(!page.has_more);

    s2.delete_basin(DeleteBasinInput::new(basin_name.clone()))
        .await?;

    let page = s2
        .list_basins(ListBasinsInput::new().with_prefix(basin_name.into()))
        .await?;

    assert_matches!(
        page.values.as_slice(),
        [] | [BasinInfo {
            state: BasinState::Deleting,
            ..
        }]
    );

    Ok(())
}

#[tokio::test]
async fn basin_config_roundtrip() -> Result<(), S2Error> {
    let s2 = s2();
    let basin_name = unique_basin_name();
    let config = BasinConfig::new()
        .with_default_stream_config(
            StreamConfig::new()
                .with_storage_class(StorageClass::Express)
                .with_delete_on_empty(
                    DeleteOnEmptyConfig::new().with_min_age(Duration::from_secs(60)),
                ),
        )
        .with_create_stream_on_read(true);

    s2.create_basin(CreateBasinInput::new(basin_name.clone()).with_config(config.clone()))
        .await?;

    let retrieved_config = s2.get_basin_config(basin_name.clone()).await?;
    assert_matches!(
        retrieved_config,
        BasinConfig {
            default_stream_config: Some(StreamConfig {
                storage_class: Some(StorageClass::Express),
                delete_on_empty: Some(DeleteOnEmptyConfig {
                    min_age_secs: 60,
                    ..
                }),
                ..
            }),
            create_stream_on_read: true,
            ..
        }
    );

    s2.delete_basin(DeleteBasinInput::new(basin_name)).await?;

    Ok(())
}

#[tokio::test]
async fn reconfigure_basin() -> Result<(), S2Error> {
    let s2 = s2();
    let basin_name = unique_basin_name();

    s2.create_basin(
        CreateBasinInput::new(basin_name.clone())
            .with_config(BasinConfig::new().with_create_stream_on_append(true)),
    )
    .await?;

    let new_config = BasinReconfiguration::new()
        .with_default_stream_config(
            StreamReconfiguration::new().with_storage_class(StorageClass::Standard),
        )
        .with_create_stream_on_append(false);

    let updated_config = s2
        .reconfigure_basin(ReconfigureBasinInput::new(basin_name.clone(), new_config))
        .await?;

    assert_matches!(
        updated_config,
        BasinConfig {
            default_stream_config: Some(StreamConfig {
                storage_class: Some(StorageClass::Standard),
                ..
            }),
            create_stream_on_append: false,
            ..
        }
    );

    s2.delete_basin(DeleteBasinInput::new(basin_name)).await?;

    Ok(())
}

#[tokio::test]
async fn list_basins_with_limit() -> Result<(), S2Error> {
    let s2 = s2();
    let basin_name_1 = unique_basin_name();
    let basin_name_2 = unique_basin_name();

    s2.create_basin(CreateBasinInput::new(basin_name_1.clone()))
        .await?;
    s2.create_basin(CreateBasinInput::new(basin_name_2.clone()))
        .await?;

    let page = s2.list_basins(ListBasinsInput::new().with_limit(1)).await?;

    assert_eq!(page.values.len(), 1);
    assert!(page.has_more);

    s2.delete_basin(DeleteBasinInput::new(basin_name_1)).await?;
    s2.delete_basin(DeleteBasinInput::new(basin_name_2)).await?;

    Ok(())
}

#[tokio::test]
async fn list_basins_with_prefix() -> Result<(), S2Error> {
    let s2 = s2();

    let prefix_1: BasinNamePrefix = uuid().parse().expect("valid basin name prefix");
    let prefix_2: BasinNamePrefix = uuid().parse().expect("valid basin name prefix");
    let basin_name_1: BasinName = format!("{}-a", prefix_1).parse().expect("valid basin name");
    let basin_name_2: BasinName = format!("{}-b", prefix_2).parse().expect("valid basin name");

    s2.create_basin(CreateBasinInput::new(basin_name_1.clone()))
        .await?;
    s2.create_basin(CreateBasinInput::new(basin_name_2.clone()))
        .await?;

    let page = s2
        .list_basins(ListBasinsInput::new().with_prefix(prefix_1))
        .await?;

    assert_eq!(page.values.len(), 1);
    assert_matches!(page.values.first(), Some(b) => {
        assert_eq!(b.name, basin_name_1)
    });

    s2.delete_basin(DeleteBasinInput::new(basin_name_1)).await?;
    s2.delete_basin(DeleteBasinInput::new(basin_name_2)).await?;

    Ok(())
}

#[tokio::test]
async fn list_basins_with_prefix_and_start_after() -> Result<(), S2Error> {
    let s2 = s2();

    let prefix: BasinNamePrefix = uuid().parse().expect("valid prefix");
    let basin_name_1: BasinName = format!("{}-a", prefix).parse().expect("valid basin name");
    let basin_name_2: BasinName = format!("{}-b", prefix).parse().expect("valid basin name");

    s2.create_basin(CreateBasinInput::new(basin_name_1.clone()))
        .await?;
    s2.create_basin(CreateBasinInput::new(basin_name_2.clone()))
        .await?;

    let page = s2
        .list_basins(
            ListBasinsInput::new()
                .with_prefix(prefix)
                .with_start_after(basin_name_1.as_ref().parse().expect("valid start after")),
        )
        .await?;

    assert_eq!(page.values.len(), 1);
    assert_eq!(page.values[0].name, basin_name_2);

    s2.delete_basin(DeleteBasinInput::new(basin_name_1)).await?;
    s2.delete_basin(DeleteBasinInput::new(basin_name_2)).await?;

    Ok(())
}

#[tokio::test]
async fn delete_nonexistent_basin_errors() -> Result<(), S2Error> {
    let s2 = s2();
    let result = s2
        .delete_basin(DeleteBasinInput::new(unique_basin_name()))
        .await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, message: _, .. })) => {
            assert_eq!(code, "basin_not_found")
        }
    );

    Ok(())
}

#[tokio::test]
async fn delete_nonexistent_basin_with_ignore() -> Result<(), S2Error> {
    let s2 = s2();
    let result = s2
        .delete_basin(DeleteBasinInput::new(unique_basin_name()).with_ignore_not_found(true))
        .await;

    assert_matches!(result, Ok(()));

    Ok(())
}

#[tokio::test]
async fn get_basin_config() -> Result<(), S2Error> {
    let s2 = s2();
    let basin_name = unique_basin_name();

    let config = BasinConfig::new()
        .with_default_stream_config(StreamConfig::new().with_storage_class(StorageClass::Express));

    s2.create_basin(CreateBasinInput::new(basin_name.clone()).with_config(config))
        .await?;

    let retrieved_config = s2.get_basin_config(basin_name.clone()).await?;

    assert_matches!(
        retrieved_config.default_stream_config,
        Some(StreamConfig {
            storage_class: Some(StorageClass::Express),
            ..
        })
    );

    s2.delete_basin(DeleteBasinInput::new(basin_name)).await?;

    Ok(())
}

#[tokio::test]
async fn issue_list_and_revoke_access_token() -> Result<(), S2Error> {
    let s2 = s2();
    let token_id: AccessTokenId = uuid().parse().expect("valid token id");

    let _token = s2
        .issue_access_token(IssueAccessTokenInput::new(
            token_id.clone(),
            AccessTokenScopeInput::from_op_group_perms(OperationGroupPermissions::read_write_all()),
        ))
        .await?;

    let page = s2
        .list_access_tokens(ListAccessTokensInput::new().with_prefix(token_id.clone().into()))
        .await?;

    assert!(page.values.iter().any(|t| t.id == token_id));

    s2.revoke_access_token(token_id.clone()).await?;

    let page = s2.list_access_tokens(ListAccessTokensInput::new()).await?;

    assert!(!page.values.iter().any(|t| t.id == token_id));

    Ok(())
}

#[tokio::test]
async fn issue_access_token_with_expiration_and_auto_prefix_streams() -> Result<(), S2Error> {
    let s2 = s2();
    let token_id: AccessTokenId = uuid().parse().expect("valid token id");

    let expires_at: S2DateTime =
        (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).try_into()?;

    let token = s2
        .issue_access_token(
            IssueAccessTokenInput::new(
                token_id.clone(),
                AccessTokenScopeInput::from_op_group_perms(
                    OperationGroupPermissions::read_write_all(),
                )
                .with_streams(StreamMatcher::Prefix(
                    "namespace".parse().expect("valid prefix"),
                )),
            )
            .with_expires_at(expires_at)
            .with_auto_prefix_streams(true),
        )
        .await?;

    assert!(!token.is_empty());

    let page = s2.list_access_tokens(ListAccessTokensInput::new()).await?;

    let issued_token = page
        .values
        .iter()
        .find(|t| t.id == token_id)
        .expect("token should be present");
    assert_eq!(issued_token.expires_at, expires_at);
    assert!(issued_token.auto_prefix_streams);

    s2.revoke_access_token(token_id).await?;

    Ok(())
}

#[tokio::test]
async fn issue_access_token_with_auto_prefix_streams_but_without_prefix_errors()
-> Result<(), S2Error> {
    let s2 = s2();
    let token_id: AccessTokenId = uuid().parse().expect("valid token id");

    let result = s2
        .issue_access_token(
            IssueAccessTokenInput::new(
                token_id.clone(),
                AccessTokenScopeInput::from_op_group_perms(
                    OperationGroupPermissions::read_write_all(),
                ),
            )
            .with_auto_prefix_streams(true),
        )
        .await;

    assert_matches!(result, Err(S2Error::Server(ErrorResponse { code, message, .. })) => {
        assert_eq!(code, "invalid");
        assert_eq!(message, "Auto prefixing is only allowed for streams with prefix matching");
    });
    Ok(())
}

#[tokio::test]
async fn issue_access_token_with_no_permitted_ops_errors() -> Result<(), S2Error> {
    let s2 = s2();
    let token_id: AccessTokenId = uuid().parse().expect("valid token id");

    let result_matches = |result: Result<String, S2Error>| {
        assert_matches!(result, Err(S2Error::Server(ErrorResponse { code, message, .. })) => {
            assert_eq!(code, "invalid");
            assert_eq!(message, "Access token permissions cannot be empty");
        });
    };

    let result = s2
        .issue_access_token(IssueAccessTokenInput::new(
            token_id.clone(),
            AccessTokenScopeInput::from_op_group_perms(OperationGroupPermissions::new()),
        ))
        .await;

    result_matches(result);

    let result = s2
        .issue_access_token(IssueAccessTokenInput::new(
            token_id.clone(),
            AccessTokenScopeInput::from_ops(vec![]),
        ))
        .await;

    result_matches(result);

    Ok(())
}

#[tokio::test]
async fn list_access_tokens_with_limit() -> Result<(), S2Error> {
    let s2 = s2();

    let page = s2
        .list_access_tokens(ListAccessTokensInput::new().with_limit(1))
        .await?;

    assert_eq!(page.values.len(), 1);

    Ok(())
}

#[tokio::test]
async fn list_access_tokens_with_prefix() -> Result<(), S2Error> {
    let s2 = s2();
    let prefix = format!("{}", uuid::Uuid::new_v4().simple());
    let token_id_1: AccessTokenId = format!("{}-a", prefix).parse().expect("valid token id");
    let token_id_2: AccessTokenId = format!("{}-b", prefix).parse().expect("valid token id");
    let token_id_3: AccessTokenId = format!("{}-c", uuid::Uuid::new_v4().simple())
        .parse()
        .expect("valid token id");

    let scope =
        AccessTokenScopeInput::from_op_group_perms(OperationGroupPermissions::read_write_all());

    s2.issue_access_token(IssueAccessTokenInput::new(
        token_id_1.clone(),
        scope.clone(),
    ))
    .await?;
    s2.issue_access_token(IssueAccessTokenInput::new(
        token_id_2.clone(),
        scope.clone(),
    ))
    .await?;
    s2.issue_access_token(IssueAccessTokenInput::new(token_id_3.clone(), scope))
        .await?;

    let page = s2
        .list_access_tokens(
            ListAccessTokensInput::new().with_prefix(prefix.parse().expect("valid prefix")),
        )
        .await?;

    assert_eq!(page.values.len(), 2);
    assert!(page.values.iter().any(|t| t.id == token_id_1));
    assert!(page.values.iter().any(|t| t.id == token_id_2));

    s2.revoke_access_token(token_id_1).await?;
    s2.revoke_access_token(token_id_2).await?;
    s2.revoke_access_token(token_id_3).await?;

    Ok(())
}
