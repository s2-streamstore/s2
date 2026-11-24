use s2_sdk::{
    S2,
    types::{BasinName, BasinReconfiguration, StreamReconfiguration, TimestampingReconfiguration},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basin_name: BasinName = std::env::var("S2_BASIN")
        .map_err(|_| "S2_BASIN env var not set")?
        .parse()?;

    let s2 = S2::from_env()?;

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
