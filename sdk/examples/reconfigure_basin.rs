use s2_sdk::{
    S2,
    types::{
        BasinName, BasinReconfiguration, ReconfigureBasinInput, S2Config, StorageClass,
        StreamReconfiguration, TimestampingReconfiguration,
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

    let input = ReconfigureBasinInput::new(
        basin_name,
        BasinReconfiguration::new()
            .with_default_stream_config(
                StreamReconfiguration::new()
                    .with_storage_class(StorageClass::Standard)
                    .with_timestamping(TimestampingReconfiguration::new().with_uncapped(true)),
            )
            .with_create_stream_on_read(true),
    );
    let config = s2.reconfigure_basin(input).await?;
    println!("{config:#?}");

    Ok(())
}
