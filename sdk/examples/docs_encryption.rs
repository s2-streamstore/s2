//! Documentation examples for Encryption page.
//!
//! Run with: cargo run --example docs_encryption

use s2_sdk::{
    S2,
    types::{
        AppendRecord, BasinConfig, BasinName, BasinReconfiguration, CreateBasinInput,
        CreateStreamInput, EncryptionAlgorithm, ReadFrom, ReadInput, StreamName, Timestamp,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basin_name: BasinName = std::env::var("S2_BASIN")?.parse()?;
    let stream_name: StreamName =
        format!("docs-encryption-{}", Timestamp::now().as_millisecond()).parse()?;

    let client = S2::from_env()?;

    // ANCHOR: basin-cipher
    client
        .create_basin(
            CreateBasinInput::new(basin_name.clone())
                .with_config(BasinConfig::new().with_stream_cipher(EncryptionAlgorithm::Aegis256)),
        )
        .await?;

    client
        .reconfigure_basin(
            basin_name.clone(),
            BasinReconfiguration::new().with_stream_cipher(EncryptionAlgorithm::Aes256Gcm),
        )
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

    stream.append(AppendRecord::new("top secret")?).await?;

    let batch = stream
        .read(
            ReadInput::new()
                .with_from(ReadFrom::SeqNum(0))
                .with_count(10),
        )
        .await?;
    // ANCHOR_END: append-read

    println!("Read {} encrypted record(s)", batch.records.len());

    basin.delete_stream(stream_name).await?;

    Ok(())
}
