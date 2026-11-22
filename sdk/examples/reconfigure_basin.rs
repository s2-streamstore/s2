use s2_sdk::{
    S2,
    types::{
        BasinName, BasinReconfiguration, S2Config, StreamReconfiguration,
        TimestampingReconfiguration,
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

    let reconfig = BasinReconfiguration::new()
        .with_default_stream_config(
            StreamReconfiguration::new()
                .with_storage_class("standard")
                .with_timestamping(TimestampingReconfiguration::new().with_uncapped(true)),
        )
        .with_create_stream_on_read(true);
    let config = s2.reconfigure_basin(basin_name, reconfig).await?;
    println!("{config:#?}");

    Ok(())
}
