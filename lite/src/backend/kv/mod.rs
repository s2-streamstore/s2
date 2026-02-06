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

use std::ops::Range;

use bytes::{Buf, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::{
    record::StreamPosition,
    types::{basin::BasinName, stream::StreamName},
};
use thiserror::Error;

use crate::backend::stream_id::StreamId;

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
    #[error("json serialization error: {0}")]
    JsonSerialization(String),
    #[error("json deserialization error: {0}")]
    JsonDeserialization(String),
}

// IDs persisted so must be kept stable.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ordinalize)]
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

#[derive(Debug, Clone)]
pub enum Key {
    /// (BM) per-basin, updatable
    /// Key: BasinName
    /// Value: BasinMeta
    BasinMeta(BasinName),
    /// (BDP) per-basin, deletable, only present while basin deletion pending
    /// Key: BasinName
    /// Value: StreamNameStartAfter (cursor for resumable deletion)
    BasinDeletionPending(BasinName),
    /// (SM) per-stream, updatable
    /// Key: BasinName \0 StreamName
    /// Value: StreamMeta
    StreamMeta(BasinName, StreamName),
    /// (SIM) per-stream, immutable
    /// Key: StreamID
    /// Value: BasinName \0 StreamName
    StreamIdMapping(StreamId),
    /// (SP) per-stream, updatable
    /// Key: StreamID
    /// Value: SeqNum Timestamp WriteTimestampSecs
    StreamTailPosition(StreamId),
    /// (SFT) per-stream, updatable, optional, default empty
    /// Key: StreamID
    /// Value: FencingToken
    StreamFencingToken(StreamId),
    /// (STP) per-stream, updatable, optional; missing implies 0; only present while trim pending
    /// Key: StreamID
    /// Value: NonZeroSeqNum
    StreamTrimPoint(StreamId),
    /// (SRD) per-record, immutable
    /// Key: StreamID StreamPosition
    /// Value: EnvelopedRecord
    StreamRecordData(StreamId, StreamPosition),
    /// (SRT) per-record, immutable
    /// Key: StreamID Timestamp SeqNum
    /// Value: empty
    StreamRecordTimestamp(StreamId, StreamPosition),
    /// (SDOED) per-deadline-per-stream, deletable, present while pending
    /// Key: TimestampSecs StreamID
    /// Value: MinAge seconds (u64)
    StreamDeleteOnEmptyDeadline(timestamp::TimestampSecs, StreamId),
}

impl From<Key> for Bytes {
    fn from(value: Key) -> Self {
        match value {
            Key::BasinMeta(basin) => basin_meta::ser_key(&basin),
            Key::BasinDeletionPending(basin) => basin_deletion_pending::ser_key(&basin),
            Key::StreamMeta(basin, stream) => stream_meta::ser_key(&basin, &stream),
            Key::StreamIdMapping(stream_id) => stream_id_mapping::ser_key(stream_id),
            Key::StreamTailPosition(stream_id) => stream_tail_position::ser_key(stream_id),
            Key::StreamFencingToken(stream_id) => stream_fencing_token::ser_key(stream_id),
            Key::StreamTrimPoint(stream_id) => stream_trim_point::ser_key(stream_id),
            Key::StreamRecordData(stream_id, pos) => stream_record_data::ser_key(stream_id, pos),
            Key::StreamRecordTimestamp(stream_id, pos) => {
                stream_record_timestamp::ser_key(stream_id, pos)
            }
            Key::StreamDeleteOnEmptyDeadline(deadline, stream_id) => {
                stream_doe_deadline::ser_key(deadline, stream_id)
            }
        }
    }
}

impl TryFrom<Bytes> for Key {
    type Error = DeserializationError;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        check_min_size(&bytes, 1)?;
        let ordinal = KeyType::from_ordinal(bytes[0])
            .ok_or_else(|| DeserializationError::InvalidOrdinal(bytes[0]))?;
        match ordinal {
            KeyType::BasinMeta => basin_meta::deser_key(bytes).map(Key::BasinMeta),
            KeyType::BasinDeletionPending => {
                basin_deletion_pending::deser_key(bytes).map(Key::BasinDeletionPending)
            }
            KeyType::StreamMeta => {
                stream_meta::deser_key(bytes).map(|(basin, stream)| Key::StreamMeta(basin, stream))
            }
            KeyType::StreamIdMapping => {
                stream_id_mapping::deser_key(bytes).map(Key::StreamIdMapping)
            }
            KeyType::StreamTailPosition => {
                stream_tail_position::deser_key(bytes).map(Key::StreamTailPosition)
            }
            KeyType::StreamFencingToken => {
                stream_fencing_token::deser_key(bytes).map(Key::StreamFencingToken)
            }
            KeyType::StreamTrimPoint => {
                stream_trim_point::deser_key(bytes).map(Key::StreamTrimPoint)
            }
            KeyType::StreamRecordData => stream_record_data::deser_key(bytes)
                .map(|(stream_id, pos)| Key::StreamRecordData(stream_id, pos)),
            KeyType::StreamRecordTimestamp => stream_record_timestamp::deser_key(bytes)
                .map(|(stream_id, pos)| Key::StreamRecordTimestamp(stream_id, pos)),
            KeyType::StreamDeleteOnEmptyDeadline => stream_doe_deadline::deser_key(bytes)
                .map(|(deadline, stream_id)| Key::StreamDeleteOnEmptyDeadline(deadline, stream_id)),
        }
    }
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
    let ordinal = key_type.ordinal();
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
    use s2_common::types::{basin::BasinName, stream::StreamName};

    pub(super) fn basin_name_strategy() -> impl Strategy<Value = BasinName> {
        "[a-z][a-z0-9-]{6,46}[a-z0-9]".prop_map(|s| BasinName::from_str(&s).unwrap())
    }

    pub(super) fn stream_name_strategy() -> impl Strategy<Value = StreamName> {
        "[a-zA-Z0-9_-]{1,100}".prop_map(|s| StreamName::from_str(&s).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, Bytes, BytesMut};
    use enum_ordinalize::Ordinalize;

    use super::{DeserializationError, Key, KeyType};

    #[test]
    fn error_on_invalid_ordinal() {
        let bytes = Bytes::from(vec![255u8]);
        let result = Key::try_from(bytes);
        assert!(matches!(
            result,
            Err(DeserializationError::InvalidOrdinal(255))
        ));
    }

    #[test]
    fn error_on_insufficient_data() {
        let bytes = Bytes::from(vec![KeyType::StreamTailPosition.ordinal(), 1, 2, 3]);
        let result = Key::try_from(bytes);
        assert!(matches!(
            result,
            Err(DeserializationError::InvalidSize { .. })
        ));
    }

    #[test]
    fn error_on_missing_separator() {
        let mut buf = BytesMut::new();
        buf.put_u8(KeyType::StreamMeta.ordinal());
        buf.put_slice(b"basin-without-separator");
        let bytes = buf.freeze();

        let result = Key::try_from(bytes);
        assert!(matches!(
            result,
            Err(DeserializationError::MissingFieldSeparator)
        ));
    }
}
