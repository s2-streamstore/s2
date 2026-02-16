use s2_sdk::{
    S2,
    types::{BasinConfig, BasinName, CreateBasinInput, RetentionPolicy, S2Config, StreamConfig},
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

    let input = CreateBasinInput::new(basin_name.clone()).with_config(
        BasinConfig::new().with_default_stream_config(
            StreamConfig::new().with_retention_policy(RetentionPolicy::Age(10 * 24 * 60 * 60)),
        ),
    );
    let basin_info = s2.create_basin(input).await?;
    println!("{basin_info:#?}");

    let basin_config = s2.get_basin_config(basin_name).await?;
    println!("{basin_config:#?}");

    Ok(())
}
