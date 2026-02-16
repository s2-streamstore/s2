use s2_sdk::{
    S2,
    types::{AppendInput, AppendRecordBatch, BasinName, CommandRecord, S2Config, StreamName},
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

    let tail = stream.check_tail().await?;
    if tail.seq_num == 0 {
        println!("Empty stream");
        return Ok(());
    }

    let input = AppendInput::new(AppendRecordBatch::try_from_iter([CommandRecord::trim(
        tail.seq_num - 1,
    )
    .into()])?);
    stream.append(input).await?;
    println!("Trim requested");

    Ok(())
}
