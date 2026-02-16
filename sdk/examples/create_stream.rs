use s2_sdk::{
    S2,
    types::{
        BasinName, CreateStreamInput, S2Config, StreamConfig, StreamName, TimestampingConfig,
        TimestampingMode,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let access_token =
        std::env::var("S2_ACCESS_TOKEN").map_err(|_| "S2_ACCESS_TOKEN env var not set")?;
    let basin_name: BasinName = std::env::var("S2_BASIN")
        .map_err(|_| "S2_BASIN env var not set")?
        .parse()?;
    let stream_name: StreamName = std::env::var("S2_STREAM")
        .map_err(|_| "S2_STREAM env var not set")?
        .parse()?;

    let s2 = S2::new(S2Config::new(access_token))?;
    let basin = s2.basin(basin_name);

    let input = CreateStreamInput::new(stream_name.clone()).with_config(
        StreamConfig::new().with_timestamping(
            TimestampingConfig::new().with_mode(TimestampingMode::ClientRequire),
        ),
    );
    let stream_info = basin.create_stream(input).await?;
    println!("{stream_info:#?}");

    let stream_config = basin.get_stream_config(stream_name).await?;
    println!("{stream_config:#?}");

    Ok(())
}
