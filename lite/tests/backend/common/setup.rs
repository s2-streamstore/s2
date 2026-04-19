use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use bytesize::ByteSize;
use s2_common::{
    encryption::{EncryptionAlgorithm, EncryptionKey, EncryptionSpec},
    record::{CommandRecord, FencingToken, Metered, Record, Timestamp},
    types::{
        basin::BasinName,
        config::{BasinConfig, OptionalStreamConfig},
        resources::CreateMode,
        stream::{AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts, StreamName},
    },
};
use s2_lite::backend::Backend;
use slatedb::{Db, config::Settings, object_store::memory::InMemory};
use uuid::Uuid;

const TEST_AEGIS256_KEY: [u8; 32] = [0x42; 32];
const TEST_AES256_GCM_KEY: [u8; 32] = [0x24; 32];

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

pub fn basin_config_with_stream_cipher(stream_cipher: EncryptionAlgorithm) -> BasinConfig {
    BasinConfig {
        default_stream_config: OptionalStreamConfig::default(),
        stream_cipher: Some(stream_cipher),
        ..Default::default()
    }
}

pub fn aegis256_encryption_spec() -> EncryptionSpec {
    EncryptionSpec::aegis256(TEST_AEGIS256_KEY)
}

pub fn aegis256_encryption_key() -> EncryptionKey {
    EncryptionKey::new(TEST_AEGIS256_KEY)
}

pub fn aes256_gcm_encryption_key() -> EncryptionKey {
    EncryptionKey::new(TEST_AES256_GCM_KEY)
}

pub fn encryption_key_for_spec(encryption: &EncryptionSpec) -> Option<EncryptionKey> {
    match encryption {
        EncryptionSpec::Plain => None,
        // Test helpers use fixed key material for encrypted cases.
        EncryptionSpec::Aegis256(_) => Some(aegis256_encryption_key()),
        EncryptionSpec::Aes256Gcm(_) => Some(aes256_gcm_encryption_key()),
    }
}

pub async fn setup_backend_for_encryption_spec(
    basin_suffix: &str,
    stream_suffix: &str,
    encryption: &EncryptionSpec,
) -> (Backend, BasinName, StreamName) {
    match encryption {
        EncryptionSpec::Plain => {
            setup_backend_with_stream(basin_suffix, stream_suffix, OptionalStreamConfig::default())
                .await
        }
        EncryptionSpec::Aegis256(_) => {
            setup_backend_with_basin_and_stream(
                basin_suffix,
                stream_suffix,
                basin_config_with_stream_cipher(EncryptionAlgorithm::Aegis256),
                OptionalStreamConfig::default(),
            )
            .await
        }
        EncryptionSpec::Aes256Gcm(_) => {
            setup_backend_with_basin_and_stream(
                basin_suffix,
                stream_suffix,
                basin_config_with_stream_cipher(EncryptionAlgorithm::Aes256Gcm),
                OptionalStreamConfig::default(),
            )
            .await
        }
    }
}

pub fn create_test_record(body: Bytes) -> AppendRecord {
    create_test_record_with_optional_timestamp(body, None)
}

pub fn create_test_record_with_optional_timestamp(
    body: Bytes,
    timestamp: Option<Timestamp>,
) -> AppendRecord {
    let envelope = s2_common::record::EnvelopeRecord::try_from_parts(vec![], body).unwrap();
    let record = Metered::from(Record::Envelope(envelope));
    let parts = AppendRecordParts { timestamp, record };
    parts.try_into().unwrap()
}

pub fn create_test_record_with_timestamp(body: Bytes, timestamp: Timestamp) -> AppendRecord {
    create_test_record_with_optional_timestamp(body, Some(timestamp))
}

pub fn create_fencing_command_record(token: FencingToken) -> AppendRecord {
    let record = Metered::from(Record::Command(CommandRecord::Fence(token)));
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
    setup_backend_with_basin_and_stream(
        basin_suffix,
        stream_suffix,
        BasinConfig::default(),
        stream_config,
    )
    .await
}

pub async fn setup_backend_with_basin_and_stream(
    basin_suffix: &str,
    stream_suffix: &str,
    basin_config: BasinConfig,
    stream_config: OptionalStreamConfig,
) -> (Backend, BasinName, StreamName) {
    let backend = create_backend().await;
    let basin_name = create_test_basin(&backend, basin_suffix, basin_config).await;
    let stream_name = create_test_stream(&backend, &basin_name, stream_suffix, stream_config).await;
    (backend, basin_name, stream_name)
}

pub async fn append_payloads(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    payloads: &[&[u8]],
) -> s2_common::types::stream::AppendAck {
    let encryption = EncryptionSpec::Plain;
    append_payloads_with_encryption(backend, basin, stream, payloads, &encryption).await
}

pub async fn append_payloads_with_encryption(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    payloads: &[&[u8]],
    encryption: &EncryptionSpec,
) -> s2_common::types::stream::AppendAck {
    let bodies = payloads
        .iter()
        .map(|bytes| Bytes::copy_from_slice(bytes))
        .collect();
    let input = AppendInput {
        records: create_test_record_batch(bodies),
        match_seq_num: None,
        fencing_token: None,
    };
    backend
        .open_for_append(basin, stream, encryption_key_for_spec(encryption))
        .await
        .expect("Failed to open append handle")
        .append(input)
        .await
        .expect("Failed to append payloads")
}

pub async fn append_timestamped_payloads(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    payloads: Vec<(Bytes, Timestamp)>,
) -> s2_common::types::stream::AppendAck {
    let input = AppendInput {
        records: create_test_record_batch_with_timestamps(payloads),
        match_seq_num: None,
        fencing_token: None,
    };
    backend
        .open_for_append(basin, stream, None)
        .await
        .expect("Failed to open append handle")
        .append(input)
        .await
        .expect("Failed to append timestamped payloads")
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
