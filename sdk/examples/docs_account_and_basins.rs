//! Documentation examples for Account and Basins page.
//!
//! Run with: cargo run --example docs_account_and_basins

use futures::StreamExt;
use s2_sdk::{
    S2,
    types::{
        AccessTokenScopeInput, BasinMatcher, BasinName, CreateBasinInput, CreateStreamInput,
        DeleteBasinInput, DeleteStreamInput, IssueAccessTokenInput, ListAllStreamsInput,
        ListBasinsInput, ListStreamsInput, OperationGroupPermissions, ReadWritePermissions,
        S2Config, StreamMatcher,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("S2_ACCESS_TOKEN")?;
    let basin_name: BasinName = std::env::var("S2_BASIN")?.parse()?;

    let client = S2::new(S2Config::new(token))?;

    // ANCHOR: basin-operations
    // List basins
    let basins = client.list_basins(ListBasinsInput::new()).await?;

    // Create a basin
    client
        .create_basin(CreateBasinInput::new("my-events".parse()?))
        .await?;

    // Get configuration
    let config = client.get_basin_config("my-events".parse()?).await?;

    // Delete
    client
        .delete_basin(DeleteBasinInput::new("my-events".parse()?))
        .await?;
    // ANCHOR_END: basin-operations
    println!("Basins: {:?}, config: {:?}", basins, config);

    let basin = client.basin(basin_name);

    // ANCHOR: stream-operations
    // List streams
    let streams = basin
        .list_streams(ListStreamsInput::new().with_prefix("user-".parse()?))
        .await?;

    // Create a stream
    basin
        .create_stream(CreateStreamInput::new("user-actions".parse()?))
        .await?;

    // Get configuration
    let config = basin.get_stream_config("user-actions".parse()?).await?;

    // Delete
    basin
        .delete_stream(DeleteStreamInput::new("user-actions".parse()?))
        .await?;
    // ANCHOR_END: stream-operations
    println!("Streams: {:?}, config: {:?}", streams, config);

    // ANCHOR: access-token-basic
    // List tokens (returns metadata, not the secret)
    let tokens = client.list_access_tokens(Default::default()).await?;

    // Issue a token scoped to streams under "users/1234/"
    let result = client
        .issue_access_token(
            IssueAccessTokenInput::new(
                "user-1234-rw-token".parse()?,
                AccessTokenScopeInput::from_op_group_perms(
                    OperationGroupPermissions::new()
                        .with_stream(ReadWritePermissions::read_write()),
                )
                .with_basins(BasinMatcher::Prefix("".parse()?)) // all basins
                .with_streams(StreamMatcher::Prefix("users/1234/".parse()?)),
            )
            .with_expires_at("2027-01-01T00:00:00Z".parse()?),
        )
        .await?;

    // Revoke a token
    client
        .revoke_access_token("user-1234-rw-token".parse()?)
        .await?;
    // ANCHOR_END: access-token-basic
    println!("Tokens: {:?}, issued: {:?}", tokens, result);

    // ANCHOR: access-token-restricted
    client
        .issue_access_token(IssueAccessTokenInput::new(
            "restricted-token".parse()?,
            AccessTokenScopeInput::from_op_group_perms(
                OperationGroupPermissions::new().with_stream(ReadWritePermissions::read_only()),
            )
            .with_basins(BasinMatcher::Exact("production".parse()?))
            .with_streams(StreamMatcher::Prefix("logs/".parse()?)),
        ))
        .await?;
    // ANCHOR_END: access-token-restricted

    // Pagination example - not executed by default
    if false {
        // ANCHOR: pagination
        // Iterate through all streams with automatic pagination
        let mut stream = basin.list_all_streams(ListAllStreamsInput::new());
        while let Some(info) = stream.next().await {
            let info = info?;
            println!("{}", info.name);
        }
        // ANCHOR_END: pagination
    }

    Ok(())
}
