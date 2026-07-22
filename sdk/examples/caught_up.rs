use futures_util::StreamExt;
use s2_sdk::{
    S2,
    types::{
        AppendInput, AppendRecord, AppendRecordBatch, BasinName, CreateBasinInput,
        CreateStreamInput, DeleteBasinInput, DeleteStreamInput, ReadBatch, ReadFrom, ReadInput,
        ReadStart, S2Config, S2Endpoints, StreamName,
    },
};

fn print_batch(label: &str, batch: &ReadBatch) {
    let seq_nums = batch
        .records
        .iter()
        .map(|record| record.seq_num)
        .collect::<Vec<_>>();
    println!("{label}: {seq_nums:?}");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let access_token =
        std::env::var("S2_ACCESS_TOKEN").map_err(|_| "S2_ACCESS_TOKEN env var not set")?;
    let mut config = S2Config::new(access_token);
    if std::env::var_os("S2_ACCOUNT_ENDPOINT").is_some()
        || std::env::var_os("S2_BASIN_ENDPOINT").is_some()
    {
        config = config.with_endpoints(S2Endpoints::from_env()?);
    }

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let basin_name: BasinName = format!("caught-up-{suffix}").parse()?;
    let stream_name: StreamName = "example".parse()?;
    let s2 = S2::new(config)?;
    let basin = s2.basin(basin_name.clone());

    s2.create_basin(CreateBasinInput::new(basin_name.clone()))
        .await?;
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;
    let stream = basin.stream(stream_name.clone());

    stream
        .append(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("first")?,
            AppendRecord::new("second")?,
        ])?))
        .await?;

    let mut session = stream
        .read_session(
            ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::TailOffset(2))),
        )
        .await?;
    let mut caught_up = session.caught_up();

    loop {
        tokio::select! {
            tail = &mut caught_up => {
                println!("Caught up through sequence number {}", tail?.seq_num);
                break;
            }
            Some(batch) = session.next() => {
                print_batch("Read before catching up", &batch?);
            }
        }
    }

    let ack = stream
        .append(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("third")?,
        ])?))
        .await?;
    println!(
        "Appended another record at sequence number {}",
        ack.start.seq_num
    );

    while let Some(batch) = session.next().await {
        let batch = batch?;
        print_batch("Read after catching up", &batch);
        if batch
            .records
            .iter()
            .any(|record| record.seq_num == ack.start.seq_num)
        {
            break;
        }
    }
    println!("Session is caught up again: {}", session.is_caught_up());

    drop(session);
    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;
    s2.delete_basin(DeleteBasinInput::new(basin_name)).await?;

    Ok(())
}
