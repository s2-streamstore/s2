use std::{pin::Pin, sync::Arc, time::Duration};

use bytes::Bytes;
use bytesize::ByteSize;
use futures::StreamExt;
use s2_common::{
    record::{CommandRecord, FencingToken, Metered, Record, SequencedRecord, Timestamp},
    types::{
        basin::BasinName,
        config::{BasinConfig, OptionalStreamConfig},
        resources::CreateMode,
        stream::{
            AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts, ReadSessionOutput,
            StreamName,
        },
    },
};
use s2_lite::backend::{Backend, error::ReadError};
use slatedb::{Db, config::Settings, object_store::memory::InMemory};
use uuid::Uuid;

pub async fn create_in_memory_db() -> Db {
    let object_store = Arc::new(InMemory::new());
    let db_path = format!("/tmp/test_{}", Uuid::new_v4());

    Db::builder(db_path, object_store)
        .with_settings(Settings {
            flush_interval: Some(Duration::from_millis(5)),
            ..Default::default()
        })
        .build()
        .await
        .expect("Failed to create in-memory database")
}

pub async fn create_backend() -> Backend {
    let db = create_in_memory_db().await;
    Backend::new(db, ByteSize::mib(10))
}

pub fn test_basin_name(suffix: &str) -> BasinName {
    format!("test-basin-{}", suffix).parse().unwrap()
}

pub fn test_stream_name(suffix: &str) -> StreamName {
    format!("test-stream-{}", suffix).parse().unwrap()
}

pub fn create_test_record(body: Bytes) -> AppendRecord {
    create_test_record_with_optional_timestamp(body, None)
}

pub fn create_test_record_with_optional_timestamp(
    body: Bytes,
    timestamp: Option<Timestamp>,
) -> AppendRecord {
    let envelope = s2_common::record::EnvelopeRecord::try_from_parts(vec![], body).unwrap();
    let record: Metered<Record> = Record::Envelope(envelope).into();
    let parts = AppendRecordParts { timestamp, record };
    parts.try_into().unwrap()
}

pub fn create_test_record_with_timestamp(body: Bytes, timestamp: Timestamp) -> AppendRecord {
    create_test_record_with_optional_timestamp(body, Some(timestamp))
}

pub fn create_fencing_command_record(token: FencingToken) -> AppendRecord {
    let record: Metered<Record> = Record::Command(CommandRecord::Fence(token)).into();
    let parts = AppendRecordParts {
        timestamp: None,
        record,
    };
    parts.try_into().unwrap()
}

pub fn create_test_record_batch(bodies: Vec<Bytes>) -> AppendRecordBatch {
    let records: Vec<AppendRecord> = bodies.into_iter().map(create_test_record).collect();
    records.try_into().unwrap()
}

pub fn create_test_record_batch_with_timestamps(
    items: Vec<(Bytes, Timestamp)>,
) -> AppendRecordBatch {
    let records: Vec<AppendRecord> = items
        .into_iter()
        .map(|(body, timestamp)| create_test_record_with_timestamp(body, timestamp))
        .collect();
    records.try_into().unwrap()
}

pub async fn create_test_basin(backend: &Backend, suffix: &str, config: BasinConfig) -> BasinName {
    let basin_name = test_basin_name(suffix);
    backend
        .create_basin(basin_name.clone(), config, CreateMode::CreateOnly(None))
        .await
        .expect("Failed to create basin");
    basin_name
}

pub async fn create_test_stream(
    backend: &Backend,
    basin: &BasinName,
    suffix: &str,
    config: OptionalStreamConfig,
) -> StreamName {
    let stream_name = test_stream_name(suffix);
    backend
        .create_stream(
            basin.clone(),
            stream_name.clone(),
            config,
            CreateMode::CreateOnly(None),
        )
        .await
        .expect("Failed to create stream");
    stream_name
}

pub async fn setup_backend_with_stream(
    basin_suffix: &str,
    stream_suffix: &str,
    stream_config: OptionalStreamConfig,
) -> (Backend, BasinName, StreamName) {
    let backend = create_backend().await;
    let basin_name = create_test_basin(&backend, basin_suffix, BasinConfig::default()).await;
    let stream_name = create_test_stream(&backend, &basin_name, stream_suffix, stream_config).await;
    (backend, basin_name, stream_name)
}

pub async fn append_payloads(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    payloads: &[&[u8]],
) -> s2_common::types::stream::AppendAck {
    let bodies = payloads
        .iter()
        .map(|bytes| Bytes::copy_from_slice(bytes))
        .collect::<Vec<_>>();
    let input = AppendInput {
        records: create_test_record_batch(bodies),
        match_seq_num: None,
        fencing_token: None,
    };
    backend
        .append(basin.clone(), stream.clone(), input)
        .await
        .expect("Failed to append payloads")
}

pub async fn append_repeat(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    payload: &[u8],
    count: usize,
) {
    for _ in 0..count {
        append_payloads(backend, basin, stream, &[payload]).await;
    }
}

pub async fn collect_records<S>(session: &mut Pin<Box<S>>) -> Vec<SequencedRecord>
where
    S: futures::Stream<Item = Result<ReadSessionOutput, ReadError>>,
{
    let mut records = Vec::new();
    while let Some(output) = session.as_mut().next().await {
        match output {
            Ok(ReadSessionOutput::Batch(batch)) => {
                records.extend(batch.records.iter().cloned());
            }
            Ok(ReadSessionOutput::Heartbeat(_)) => {}
            Err(e) => panic!("Read error: {:?}", e),
        }
    }
    records
}

pub fn envelope_bodies(records: &[SequencedRecord]) -> Vec<Vec<u8>> {
    records
        .iter()
        .map(|record| match &record.record {
            Record::Envelope(envelope) => envelope.body().to_vec(),
            other => panic!("Unexpected record type: {:?}", other),
        })
        .collect()
}
