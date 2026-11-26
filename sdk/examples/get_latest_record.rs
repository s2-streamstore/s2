use s2_sdk::{
    S2,
    types::{BasinName, ReadInput, ReadStart, StreamName},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basin_name: BasinName = std::env::var("S2_BASIN")
        .map_err(|_| "S2_BASIN env var not set")?
        .parse()?;
    let stream_name: StreamName = std::env::var("S2_STREAM")
        .map_err(|_| "S2_STREAM env var not set")?
        .parse()?;

    let s2 = S2::from_env()?;
    let stream = s2.basin(basin_name).stream(stream_name);

    let input = ReadInput::new(ReadStart::TailOffset(1)).with_count(1);
    let batch = stream.read(input).await?;
    println!("{batch:#?}");

    Ok(())
}
