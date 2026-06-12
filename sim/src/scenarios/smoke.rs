//! Minimal end-to-end check: create a basin and stream, append a couple of
//! records, read them back.

use s2_sdk::types::{AppendInput, AppendRecord, AppendRecordBatch, ReadInput};
use tracing::info;

pub async fn workload() -> turmoil::Result {
    let stream = super::provision_stream().await.map_err(|e| e.to_string())?;
    info!(basin = super::BASIN, stream = super::STREAM, "provisioned");

    let batch = AppendRecordBatch::try_from_iter([
        AppendRecord::new("hello")?,
        AppendRecord::new("turmoil")?,
    ])?;
    let ack = stream.append(AppendInput::new(batch)).await?;
    info!(?ack, "appended records");

    let batch = stream.read(ReadInput::new()).await?;
    info!(?batch, "read records");

    Ok(())
}
