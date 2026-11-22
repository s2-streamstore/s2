use futures_util::StreamExt;
use s2_sdk::{
    S2,
    types::{BasinName, ReadInput, ReadSessionConfig, S2Config, StreamName},
};
use tokio::select;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let access_token = std::env::var("S2_ACCESS_TOKEN")?;
    let basin_name: BasinName = std::env::var("S2_BASIN")?.parse()?;
    let stream_name: StreamName = std::env::var("S2_STREAM")?.parse()?;

    let s2 = S2::new(S2Config::new(access_token))?;
    let stream = s2.basin(basin_name).stream(stream_name);

    let input = ReadInput::new();
    let mut records = stream.read_session(input, ReadSessionConfig::default())?;
    loop {
        select! {
            record = records.next() => {
                let Some(record) = record else { break };
                let record = record?;
                println!("{record:?}");
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    Ok(())
}
