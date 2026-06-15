use s2_sdk::types::{BasinName, EnsureBasinInput, EnsureStreamInput, StreamName};
use s2_testcontainers::S2Lite;

#[tokio::main(flavor = "current_thread")]
async fn main() -> s2_testcontainers::Result<()> {
    let s2 = S2Lite::start().await?;

    let client = s2.client()?;
    let basin_name: BasinName = "test-basin".parse()?;
    client
        .ensure_basin(EnsureBasinInput::new(basin_name.clone()))
        .await?;

    let basin = client.basin(basin_name.clone());
    let stream_name: StreamName = "test-stream".parse()?;
    basin
        .ensure_stream(EnsureStreamInput::new(stream_name.clone()))
        .await?;

    println!(
        "s2-lite is running at {} with basin {basin_name} and stream {stream_name}",
        s2.endpoint()
    );

    Ok(())
}
