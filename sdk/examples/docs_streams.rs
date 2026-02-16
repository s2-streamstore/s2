//! Documentation examples for Streams page.
//!
//! Run with: cargo run --example docs_streams

use std::time::Duration;

use futures::StreamExt;
use s2_sdk::{
    S2,
    append_session::AppendSessionConfig,
    batching::BatchingConfig,
    producer::ProducerConfig,
    types::{
        AppendInput, AppendRecord, AppendRecordBatch, BasinName, ReadFrom, ReadInput, ReadLimits,
        ReadStart, ReadStop, S2Config, StreamName,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("S2_ACCESS_TOKEN")?;
    let basin_name: BasinName = std::env::var("S2_BASIN")?.parse()?;

    let client = S2::new(S2Config::new(token))?;
    let basin = client.basin(basin_name);

    // Create a temporary stream for examples
    let stream_name: StreamName = format!(
        "docs-streams-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
    )
    .parse()?;
    basin
        .create_stream(s2_sdk::types::CreateStreamInput::new(stream_name.clone()))
        .await?;

    // ANCHOR: simple-append
    let stream = basin.stream(stream_name.clone());

    let records = AppendRecordBatch::try_from_iter([
        AppendRecord::new("first event")?,
        AppendRecord::new("second event")?,
    ])?;

    let ack = stream.append(AppendInput::new(records)).await?;

    // ack tells us where the records landed
    println!(
        "Wrote records {} through {}",
        ack.start.seq_num,
        ack.end.seq_num - 1
    );
    // ANCHOR_END: simple-append

    // ANCHOR: simple-read
    let batch = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(100))),
        )
        .await?;

    for record in batch.records {
        println!("[{}] {:?}", record.seq_num, record.body);
    }
    // ANCHOR_END: simple-read

    // ANCHOR: append-session
    let session = stream.append_session(AppendSessionConfig::new());

    // Submit a batch - this enqueues it and returns a ticket
    let records = AppendRecordBatch::try_from_iter([
        AppendRecord::new("event-1")?,
        AppendRecord::new("event-2")?,
    ])?;
    let ticket = session.submit(AppendInput::new(records)).await?;

    // Wait for durability
    let ack = ticket.await?;
    println!("Durable at seqNum {}", ack.start.seq_num);

    session.close().await?;
    // ANCHOR_END: append-session

    // ANCHOR: producer
    let producer = stream.producer(
        ProducerConfig::new()
            .with_batching(BatchingConfig::new().with_linger(Duration::from_millis(5))),
    );

    // Submit individual records
    let ticket = producer.submit(AppendRecord::new("my event")?).await?;

    // Get the exact sequence number
    let ack = ticket.await?;
    println!("Record durable at seqNum {}", ack.seq_num);

    producer.close().await?;
    // ANCHOR_END: producer

    // ANCHOR: check-tail
    let tail = stream.check_tail().await?;
    println!("Stream has {} records", tail.seq_num);
    // ANCHOR_END: check-tail

    // Cleanup
    basin
        .delete_stream(s2_sdk::types::DeleteStreamInput::new(stream_name))
        .await?;

    println!("Streams examples completed");

    // The following read session examples are for documentation snippets only.
    // They are not executed because they would block waiting for new records.
    if std::env::var("RUN_READ_SESSIONS").is_err() {
        return Ok(());
    }

    // ANCHOR: read-session
    let mut session = stream
        .read_session(ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0))))
        .await?;

    while let Some(batch) = session.next().await {
        let batch = batch?;
        for record in batch.records {
            println!("[{}] {:?}", record.seq_num, record.body);
        }
    }
    // ANCHOR_END: read-session

    // ANCHOR: read-session-tail-offset
    // Start reading from 10 records before the current tail
    let mut session = stream
        .read_session(
            ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::TailOffset(10))),
        )
        .await?;

    while let Some(batch) = session.next().await {
        let batch = batch?;
        for record in batch.records {
            println!("[{}] {:?}", record.seq_num, record.body);
        }
    }
    // ANCHOR_END: read-session-tail-offset

    // ANCHOR: read-session-timestamp
    // Start reading from a specific timestamp
    let one_hour_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64
        - 3600 * 1000;
    let mut session = stream
        .read_session(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::Timestamp(one_hour_ago))),
        )
        .await?;

    while let Some(batch) = session.next().await {
        let batch = batch?;
        for record in batch.records {
            println!("[{}] {:?}", record.seq_num, record.body);
        }
    }
    // ANCHOR_END: read-session-timestamp

    // ANCHOR: read-session-until
    // Read records until a specific timestamp
    let one_hour_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64
        - 3600 * 1000;
    let mut session = stream
        .read_session(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_until(..one_hour_ago)),
        )
        .await?;

    while let Some(batch) = session.next().await {
        let batch = batch?;
        for record in batch.records {
            println!("[{}] {:?}", record.seq_num, record.body);
        }
    }
    // ANCHOR_END: read-session-until

    // ANCHOR: read-session-wait
    // Read all available records, and once reaching the current tail, wait an additional 30 seconds
    // for new ones
    let mut session = stream
        .read_session(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_wait(30)),
        )
        .await?;

    while let Some(batch) = session.next().await {
        let batch = batch?;
        for record in batch.records {
            println!("[{}] {:?}", record.seq_num, record.body);
        }
    }
    // ANCHOR_END: read-session-wait

    Ok(())
}
