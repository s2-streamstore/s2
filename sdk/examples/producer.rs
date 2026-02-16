use s2_sdk::{
    S2,
    producer::ProducerConfig,
    types::{AppendRecord, BasinName, S2Config, StreamName},
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

    let producer = stream.producer(ProducerConfig::new());

    let ticket1 = producer.submit(AppendRecord::new("lorem")?).await?;
    let ticket2 = producer.submit(AppendRecord::new("ipsum")?).await?;

    let ack1 = ticket1.await?;
    let ack2 = ticket2.await?;
    println!("Record 1 seq_num: {}", ack1.seq_num);
    println!("Record 2 seq_num: {}", ack2.seq_num);

    producer.close().await?;

    Ok(())
}
