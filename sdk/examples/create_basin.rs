use std::time::Duration;

use s2_sdk::{
    S2,
    types::{BasinConfig, BasinName, CreateBasinInput, RetentionPolicy, StreamConfig},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basin_name: BasinName = std::env::var("S2_BASIN")
        .map_err(|_| "S2_BASIN env var not set")?
        .parse()?;

    let s2 = S2::from_env()?;

    let input = CreateBasinInput::new(basin_name.clone()).with_config(
        BasinConfig::new().with_default_stream_config(
            StreamConfig::new()
                .with_retention_policy(RetentionPolicy::age(Duration::from_secs(10 * 24 * 3600))?),
        ),
    );
    let basin_info = s2.create_basin(input).await?;
    println!("{basin_info:#?}");

    let basin_config = s2.get_basin_config(basin_name).await?;
    println!("{basin_config:#?}");

    Ok(())
}
