use s2_sdk::{
    S2,
    read_session::ReadSessionConfig,
    types::{
        AppendRecord, AppendRecordBatch, BasinName, CreateBasinInput, CreateStreamInput, ReadFrom,
        ReadInput, StreamName,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = S2::from_env()?;

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let basin_name: BasinName = format!("caught-up-{suffix}").parse()?;
    let stream_name: StreamName = "example".parse()?;
    let basin = s2.basin(basin_name.clone());

    s2.create_basin(CreateBasinInput::new(basin_name.clone()))
        .await?;
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;
    let stream = basin.stream(stream_name.clone());

    stream
        .append(AppendRecordBatch::try_from_iter([
            AppendRecord::new("first")?,
            AppendRecord::new("second")?,
        ])?)
        .await?;

    let mut session = stream.read_session(
        ReadInput::new().with_start(ReadFrom::TailOffset(2)),
        ReadSessionConfig::new(),
    )?;
    let mut caught_up = session.caught_up();

    loop {
        tokio::select! {
            tail = &mut caught_up => {
                println!("Caught up through sequence number {}", tail?.seq_num);
                break;
            }
            Some(record) = session.next() => {
                let record = record?;
                println!("Read before catching up: {}", record.seq_num);
            }
        }
    }

    let ack = stream.append(AppendRecord::new("third")?).await?;
    println!(
        "Appended another record at sequence number {}",
        ack.start.seq_num
    );

    while let Some(record) = session.next().await {
        let record = record?;
        println!("Read after catching up: {}", record.seq_num);
        if record.seq_num == ack.start.seq_num {
            break;
        }
    }
    println!("Session is caught up again: {}", session.is_caught_up());

    drop(session);
    basin.delete_stream(stream_name).await?;
    s2.delete_basin(basin_name).await?;

    Ok(())
}
