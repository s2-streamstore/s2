pub mod basin_deletion_pending;
pub mod basin_meta;
pub mod stream_doe_deadline;
pub mod stream_fencing_token;
pub mod stream_id_mapping;
pub mod stream_meta;
pub mod stream_record_data;
pub mod stream_record_timestamp;
pub mod stream_tail_position;
pub mod stream_trim_point;
pub mod timestamp;

use std::{ops::Range, str::FromStr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use s2_common::{basin::BasinName, caps::MIN_BASIN_NAME_LEN};
use thiserror::Error;

use crate::stream_id::StreamId;

#[derive(Debug, Clone, Error)]
pub enum DeserializationError {
    #[error("invalid ordinal: {0}")]
    InvalidOrdinal(u8),
    #[error("invalid size: expected {expected} bytes, got {actual}")]
    InvalidSize { expected: usize, actual: usize },
    #[error("invalid value '{name}': {error}")]
    InvalidValue { name: &'static str, error: String },
    #[error("missing field separator")]
    MissingFieldSeparator,
    #[error("json deserialization error: {0}")]
    JsonDeserialization(String),
}

// IDs persisted so must be kept stable.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyType {
    BasinMeta = 1,
    BasinDeletionPending = 8,
    StreamMeta = 2,
    StreamIdMapping = 9,
    StreamTailPosition = 3,
    StreamFencingToken = 4,
    StreamTrimPoint = 5,
    StreamRecordData = 6,
    StreamRecordTimestamp = 7,
    StreamDeleteOnEmptyDeadline = 10,
}

/// Shared serializer for keys of the form `[KeyType][StreamId]`.
pub fn ser_stream_id_key(key_type: KeyType, stream_id: StreamId) -> Bytes {
    let key_len = 1 + StreamId::LEN;
    let mut buf = BytesMut::with_capacity(key_len);
    buf.put_u8(key_type as u8);
    buf.put_slice(stream_id.as_bytes());
    debug_assert_eq!(buf.len(), key_len, "serialized length mismatch");
    buf.freeze()
}

/// Shared deserializer for keys of the form `[KeyType][StreamId]`.
pub fn deser_stream_id_key(
    key_type: KeyType,
    mut bytes: Bytes,
) -> Result<StreamId, DeserializationError> {
    let key_len = 1 + StreamId::LEN;
    check_exact_size(&bytes, key_len)?;
    let ordinal = bytes.get_u8();
    if ordinal != (key_type as u8) {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let mut stream_id_bytes = [0u8; StreamId::LEN];
    bytes.copy_to_slice(&mut stream_id_bytes);
    Ok(stream_id_bytes.into())
}

/// Shared serializer for keys of the form `[KeyType][BasinName]`.
pub fn ser_basin_name_key(key_type: KeyType, basin: &BasinName) -> Bytes {
    let basin_bytes = basin.as_bytes();
    let capacity = 1 + basin_bytes.len();
    let mut buf = BytesMut::with_capacity(capacity);
    buf.put_u8(key_type as u8);
    buf.put_slice(basin_bytes);
    debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
    buf.freeze()
}

/// Shared deserializer for keys of the form `[KeyType][BasinName]`.
pub fn deser_basin_name_key(
    key_type: KeyType,
    mut bytes: Bytes,
) -> Result<BasinName, DeserializationError> {
    check_min_size(&bytes, 1 + MIN_BASIN_NAME_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != (key_type as u8) {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let basin_str = std::str::from_utf8(&bytes).map_err(|e| invalid_value_err("basin", e))?;
    BasinName::from_str(basin_str).map_err(|e| invalid_value_err("basin", e))
}

fn check_exact_size(bytes: &Bytes, expected: usize) -> Result<(), DeserializationError> {
    if bytes.remaining() != expected {
        return Err(DeserializationError::InvalidSize {
            expected,
            actual: bytes.remaining(),
        });
    }
    Ok(())
}

fn check_min_size(bytes: &Bytes, min: usize) -> Result<(), DeserializationError> {
    if bytes.remaining() < min {
        return Err(DeserializationError::InvalidSize {
            expected: min,
            actual: bytes.remaining(),
        });
    }
    Ok(())
}

pub fn key_type_range(key_type: KeyType) -> Range<Bytes> {
    let ordinal = key_type as u8;
    let start = Bytes::from(vec![ordinal]);
    let end = Bytes::from(vec![
        ordinal.checked_add(1).expect("key type ordinal overflow"),
    ]);
    start..end
}

fn increment_bytes(mut buf: BytesMut) -> Option<Bytes> {
    for i in (0..buf.len()).rev() {
        if buf[i] < 0xFF {
            buf[i] += 1;
            buf.truncate(i + 1);
            return Some(buf.freeze());
        }
    }
    None
}

fn invalid_value_err<E: std::fmt::Display>(name: &'static str, e: E) -> DeserializationError {
    DeserializationError::InvalidValue {
        name,
        error: e.to_string(),
    }
}

fn ser_json_value<T, S>(value: &T, type_name: &str) -> Bytes
where
    T: Clone + Into<S>,
    S: serde::Serialize,
{
    let serde_value: S = value.clone().into();
    serde_json::to_vec(&serde_value)
        .unwrap_or_else(|_| panic!("failed to serialize {}", type_name))
        .into()
}

fn deser_json_value<T, S>(bytes: Bytes, name: &'static str) -> Result<T, DeserializationError>
where
    S: serde::de::DeserializeOwned,
    T: TryFrom<S>,
    T::Error: std::fmt::Display,
{
    let serde_value: S = serde_json::from_slice(&bytes)
        .map_err(|e| DeserializationError::JsonDeserialization(e.to_string()))?;
    T::try_from(serde_value).map_err(|e| invalid_value_err(name, e))
}

#[cfg(test)]
mod proptest_strategies {
    use std::str::FromStr;

    use proptest::prelude::*;
    use s2_common::{basin::BasinName, stream::StreamName};

    pub(super) fn basin_name_strategy() -> impl Strategy<Value = BasinName> {
        "[a-z][a-z0-9-]{6,46}[a-z0-9]".prop_map(|s| BasinName::from_str(&s).unwrap())
    }

    pub(super) fn stream_name_strategy() -> impl Strategy<Value = StreamName> {
        "[a-zA-Z0-9_-]{1,100}".prop_map(|s| StreamName::from_str(&s).unwrap())
    }
}
