use s2_sdk::{
    S2,
    types::{
        AccessTokenScopeInput, BasinMatcher, BasinName, IssueAccessTokenInput, Operation,
        OperationGroupPermissions, ReadWritePermissions, S2Config, StreamMatcher,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let access_token =
        std::env::var("S2_ACCESS_TOKEN").map_err(|_| "S2_ACCESS_TOKEN env var not set")?;
    let basin_name: BasinName = std::env::var("S2_BASIN")
        .map_err(|_| "S2_BASIN env var not set")?
        .parse()?;

    let config = S2Config::new(access_token);
    let s2 = S2::new(config)?;

    let input = IssueAccessTokenInput::new(
        "ro-token".parse()?,
        AccessTokenScopeInput::from_op_group_perms(
            OperationGroupPermissions::new().with_account(ReadWritePermissions::read_only()),
        )
        .with_ops([Operation::CreateStream])
        .with_streams(StreamMatcher::Prefix("audit".parse()?))
        .with_basins(BasinMatcher::Exact(basin_name)),
    );
    let issued_token = s2.issue_access_token(input).await?;
    println!("Issued access token: {issued_token}");

    Ok(())
}
