use s2_testcontainers::S2Lite;

#[tokio::main(flavor = "current_thread")]
async fn main() -> s2_testcontainers::Result<()> {
    let s2 = S2Lite::start().await?;

    let _client = s2.client()?;
    let basin = s2.ensure_basin("test-basin").await?;
    let stream = s2.ensure_stream(&basin, "test-stream").await?;

    println!(
        "s2-lite is running at {} with basin {basin} and stream {stream}",
        s2.endpoint()
    );

    Ok(())
}
