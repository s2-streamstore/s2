use s2_sdk::{
    S2,
    read_session::ReadSessionConfig,
    types::{BasinName, ReadInput, StreamName},
};
use tokio::select;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basin_name: BasinName = std::env::var("S2_BASIN")?.parse()?;
    let stream_name: StreamName = std::env::var("S2_STREAM")?.parse()?;

    let s2 = S2::from_env()?;
    let stream = s2.basin(basin_name).stream(stream_name);

    let input = ReadInput::new();
    let mut records = stream.read_session(input, ReadSessionConfig::new())?;
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
