use s2_sdk::{
    S2,
    types::{
        BasinName, ReadFrom, ReadInput, ReadLimits, ReadStart, ReadStop, S2Config, StreamName,
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
    let stream = s2.basin(basin_name).stream(stream_name);

    let input = ReadInput::new()
        .with_start(ReadStart::new().with_from(ReadFrom::TailOffset(1)))
        .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(1)));
    let batch = stream.read(input).await?;
    println!("{batch:#?}");

    Ok(())
}
