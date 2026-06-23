//! Documentation examples for Encryption page.
//!
//! Run with: cargo run --example docs_encryption

use s2_sdk::{
    S2,
    types::{
        AppendInput, AppendRecord, AppendRecordBatch, BasinConfig, BasinName, BasinReconfiguration,
        CreateBasinInput, CreateStreamInput, DeleteStreamInput, EncryptionAlgorithm, ReadFrom,
        ReadInput, ReadLimits, ReadStart, ReadStop, ReconfigureBasinInput, S2Config, StreamName,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let access_token = std::env::var("S2_ACCESS_TOKEN")?;
    let basin_name: BasinName = std::env::var("S2_BASIN")?.parse()?;
    let stream_name: StreamName = format!(
        "docs-encryption-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
    )
    .parse()?;

    let client = S2::new(S2Config::new(access_token))?;

    // ANCHOR: basin-cipher
    client
        .create_basin(
            CreateBasinInput::new(basin_name.clone())
                .with_config(BasinConfig::new().with_stream_cipher(EncryptionAlgorithm::Aegis256)),
        )
        .await?;

    client
        .reconfigure_basin(ReconfigureBasinInput::new(
            basin_name.clone(),
            BasinReconfiguration::new().with_stream_cipher(EncryptionAlgorithm::Aes256Gcm),
        ))
        .await?;
    // ANCHOR_END: basin-cipher

    let basin = client.basin(basin_name.clone());
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    // ANCHOR: append-read
    let stream = basin
        .stream(stream_name.clone())
        .with_encryption_key(std::env::var("S2_ENCRYPTION_KEY")?.parse()?);

    stream
        .append(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("top secret")?,
        ])?))
        .await?;

    let batch = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(10))),
        )
        .await?;
    // ANCHOR_END: append-read

    println!("Read {} encrypted record(s)", batch.records.len());

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}
