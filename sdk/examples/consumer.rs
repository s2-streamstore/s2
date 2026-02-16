use futures::StreamExt;
use s2_sdk::{
    S2,
    types::{BasinName, ReadInput, S2Config, StreamName},
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
    let mut batches = stream.read_session(input).await?;
    loop {
        select! {
            batch = batches.next() => {
                let Some(batch) = batch else { break };
                let batch = batch?;
                println!("{batch:?}");
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    Ok(())
}
