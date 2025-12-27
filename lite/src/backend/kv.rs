use std::{ops::Range, str::FromStr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use s2_common::{
    caps::{MIN_BASIN_NAME_LEN, MIN_STREAM_NAME_LEN},
    record::{Encodable, FencingToken, MeteredRecord, SeqNum, StreamPosition, Timestamp},
    types::{
        basin::{BasinName, BasinNamePrefix, BasinNameStartAfter},
        config::{BasinConfig, OptionalStreamConfig},
        stream::{StreamName, StreamNamePrefix, StreamNameStartAfter},
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::backend::stream_id::StreamId;

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

#[derive(Debug, Clone, Error)]
pub enum DeserializationError {
    #[error("Invalid ordinal: {0}")]
    InvalidOrdinal(u8),
    #[error("Invalid size: expected {expected} bytes, got {actual}")]
    InvalidSize { expected: usize, actual: usize },
    #[error("Invalid value '{name}': {error}")]
    InvalidValue { name: &'static str, error: String },
    #[error("Missing field separator")]
    MissingFieldSeparator,
    #[error("JSON serialization error: {0}")]
    JsonSerialization(String),
    #[error("JSON deserialization error: {0}")]
    JsonDeserialization(String),
}

#[derive(Debug, Clone)]
pub struct BasinMeta {
    pub config: BasinConfig,
    pub created_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BasinMetaSerde {
    config: Option<s2_api::v1::config::BasinConfig>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    deleted_at: Option<OffsetDateTime>,
}

impl From<BasinMeta> for BasinMetaSerde {
    fn from(meta: BasinMeta) -> Self {
        Self {
            config: Some(meta.config.into()),
            created_at: meta.created_at,
            deleted_at: meta.deleted_at,
        }
    }
}

impl TryFrom<BasinMetaSerde> for BasinMeta {
    type Error = s2_common::types::ValidationError;

    fn try_from(serde: BasinMetaSerde) -> Result<Self, Self::Error> {
        let config = match serde.config {
            Some(api_config) => api_config.try_into()?,
            None => BasinConfig::default(),
        };

        Ok(Self {
            config,
            created_at: serde.created_at,
            deleted_at: serde.deleted_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct StreamMeta {
    pub config: OptionalStreamConfig,
    pub created_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamMetaSerde {
    config: Option<s2_api::v1::config::StreamConfig>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    deleted_at: Option<OffsetDateTime>,
}

impl From<StreamMeta> for StreamMetaSerde {
    fn from(meta: StreamMeta) -> Self {
        Self {
            config: s2_api::v1::config::StreamConfig::to_opt(meta.config),
            created_at: meta.created_at,
            deleted_at: meta.deleted_at,
        }
    }
}

impl TryFrom<StreamMetaSerde> for StreamMeta {
    type Error = s2_common::types::ValidationError;

    fn try_from(serde: StreamMetaSerde) -> Result<Self, Self::Error> {
        let config = match serde.config {
            Some(api_config) => api_config.try_into()?,
            None => OptionalStreamConfig::default(),
        };

        Ok(Self {
            config,
            created_at: serde.created_at,
            deleted_at: serde.deleted_at,
        })
    }
}

#[derive(Debug, Clone)]
pub enum DbKey {
    /// (BM) per-basin, updatable
    /// Key: BasinName
    /// Value: BasinMeta
    BasinMeta(BasinName),
    /// (SM) per-stream, updatable
    /// Key: BasinName \0 StreamName
    /// Value: StreamMeta
    StreamMeta(BasinName, StreamName),
    /// (SP) per-stream, updatable
    /// Key: StreamID
    /// Value: SeqNum Timestamp
    StreamTailPosition(StreamId),
    /// (SFT) per-stream, updatable, optional, default empty
    /// Key: StreamID
    /// Value: FencingToken
    StreamFencingToken(StreamId),
    /// (STP) per-stream, updatable, optional, default 0, only present while trim pending
    /// Key: StreamID
    /// Value: SeqNum
    StreamTrimPoint(StreamId),
    /// (SRD) per-record, imutable
    /// Key: StreamID StreamPosition
    /// Value: EnvelopedRecord
    StreamRecordData(StreamId, StreamPosition),
    /// (SRT) per-record, imutable
    /// Key: StreamID Timestamp
    /// Value: SeqNum
    StreamRecordTimestamp(StreamId, Timestamp),
}

pub mod basin_meta {
    use super::*;

    pub fn ser_key_prefix(prefix: &BasinNamePrefix) -> Bytes {
        ser_key_internal(prefix.as_bytes()).freeze()
    }

    pub fn ser_key_prefix_end(prefix: &BasinNamePrefix) -> Bytes {
        increment_bytes(ser_key_internal(prefix.as_bytes())).expect("non-empty")
    }

    pub fn ser_key_start_after(start_after: &BasinNameStartAfter) -> Bytes {
        let start_after_bytes = start_after.as_bytes();
        let mut bytes = Vec::with_capacity(start_after_bytes.len() + 1);
        bytes.extend_from_slice(start_after_bytes);
        bytes.push(0x00);
        ser_key_internal(&bytes).freeze()
    }

    pub fn ser_key_range(
        prefix: &BasinNamePrefix,
        start_after: &BasinNameStartAfter,
    ) -> Range<Bytes> {
        let start = if !start_after.is_empty() {
            ser_key_start_after(start_after)
        } else {
            ser_key_prefix(prefix)
        };
        let end = ser_key_prefix_end(prefix);
        start..end
    }

    pub fn ser_key(basin: &BasinName) -> Bytes {
        ser_key_internal(basin.as_bytes()).freeze()
    }

    fn ser_key_internal(basin: &[u8]) -> BytesMut {
        let capacity = 1 + basin.len();
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u8(ordinals::BASIN_META);
        buf.put_slice(basin);
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf
    }

    pub fn deser_key(mut bytes: Bytes) -> Result<BasinName, DeserializationError> {
        check_min_size(&bytes, 1 + MIN_BASIN_NAME_LEN)?;
        let ordinal = bytes.get_u8();
        if ordinal != ordinals::BASIN_META {
            return Err(DeserializationError::InvalidOrdinal(ordinal));
        }
        let basin_str = std::str::from_utf8(&bytes).map_err(|e| invalid_value_err("basin", e))?;
        BasinName::from_str(basin_str).map_err(|e| invalid_value_err("basin", e))
    }

    pub fn ser_value(basin_meta: &BasinMeta) -> Bytes {
        ser_json_value::<BasinMeta, BasinMetaSerde>(basin_meta, "BasinMeta")
    }

    pub fn deser_value(bytes: Bytes) -> Result<BasinMeta, DeserializationError> {
        deser_json_value::<BasinMeta, BasinMetaSerde>(bytes, "basin_meta")
    }
}

pub mod stream_meta {

    use super::*;

    pub fn ser_key_prefix(basin: &BasinName, prefix: &StreamNamePrefix) -> Bytes {
        ser_key_internal(basin.as_bytes(), prefix.as_bytes()).freeze()
    }

    pub fn ser_key_prefix_end(basin: &BasinName, prefix: &StreamNamePrefix) -> Bytes {
        increment_bytes(ser_key_internal(basin.as_bytes(), prefix.as_bytes())).expect("non-empty")
    }

    pub fn ser_key_start_after(basin: &BasinName, start_after: &StreamNameStartAfter) -> Bytes {
        let start_after_bytes = start_after.as_bytes();
        let mut bytes = Vec::with_capacity(start_after_bytes.len() + 1);
        bytes.extend_from_slice(start_after_bytes);
        bytes.push(0x00);
        ser_key_internal(basin.as_bytes(), &bytes).freeze()
    }

    pub fn ser_key_range(
        basin: &BasinName,
        prefix: &StreamNamePrefix,
        start_after: &StreamNameStartAfter,
    ) -> Range<Bytes> {
        let start = if !start_after.is_empty() {
            ser_key_start_after(basin, start_after)
        } else {
            ser_key_prefix(basin, prefix)
        };
        let end = ser_key_prefix_end(basin, prefix);
        start..end
    }

    pub fn ser_key(basin: &BasinName, stream: &StreamName) -> Bytes {
        ser_key_internal(basin.as_bytes(), stream.as_bytes()).freeze()
    }

    fn ser_key_internal(basin_bytes: &[u8], stream_bytes: &[u8]) -> BytesMut {
        let capacity = 1 + basin_bytes.len() + 1 + stream_bytes.len();
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u8(ordinals::STREAM_META);
        buf.put_slice(basin_bytes);
        buf.put_u8(0x00);
        buf.put_slice(stream_bytes);
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf
    }

    pub fn deser_key(mut bytes: Bytes) -> Result<(BasinName, StreamName), DeserializationError> {
        check_min_size(&bytes, 1 + MIN_BASIN_NAME_LEN + 1 + MIN_STREAM_NAME_LEN)?;
        let ordinal = bytes.get_u8();
        if ordinal != ordinals::STREAM_META {
            return Err(DeserializationError::InvalidOrdinal(ordinal));
        }
        let sep_pos = bytes
            .iter()
            .position(|&b| b == 0x00)
            .ok_or(DeserializationError::MissingFieldSeparator)?;

        let basin_str =
            std::str::from_utf8(&bytes[..sep_pos]).map_err(|e| invalid_value_err("basin", e))?;
        let stream_str = std::str::from_utf8(&bytes[sep_pos + 1..])
            .map_err(|e| invalid_value_err("stream", e))?;

        let basin = BasinName::from_str(basin_str).map_err(|e| invalid_value_err("basin", e))?;
        let stream =
            StreamName::from_str(stream_str).map_err(|e| invalid_value_err("stream", e))?;

        Ok((basin, stream))
    }

    pub fn ser_value(stream_meta: &StreamMeta) -> Bytes {
        ser_json_value::<StreamMeta, StreamMetaSerde>(stream_meta, "StreamMeta")
    }

    pub fn deser_value(bytes: Bytes) -> Result<StreamMeta, DeserializationError> {
        deser_json_value::<StreamMeta, StreamMetaSerde>(bytes, "stream_meta")
    }
}

pub mod stream_tail_position {
    use super::*;

    pub fn ser_key(stream_id: StreamId) -> Bytes {
        let capacity = 1 + 32;
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u8(ordinals::STREAM_TAIL_POSITION);
        buf.put_slice(stream_id.as_ref());
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf.freeze()
    }

    pub fn deser_key(mut bytes: Bytes) -> Result<StreamId, DeserializationError> {
        check_exact_size(&bytes, 33)?;
        let ordinal = bytes.get_u8();
        if ordinal != ordinals::STREAM_TAIL_POSITION {
            return Err(DeserializationError::InvalidOrdinal(ordinal));
        }
        let mut stream_id_bytes = [0u8; 32];
        bytes.copy_to_slice(&mut stream_id_bytes);
        Ok(stream_id_bytes.into())
    }

    pub fn ser_value(pos: StreamPosition) -> Bytes {
        let capacity = 8 + 8;
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u64(pos.seq_num);
        buf.put_u64(pos.timestamp);
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf.freeze()
    }

    pub fn deser_value(mut bytes: Bytes) -> Result<StreamPosition, DeserializationError> {
        check_exact_size(&bytes, 16)?;
        let seq_num = bytes.get_u64();
        let timestamp = bytes.get_u64();
        Ok(StreamPosition { seq_num, timestamp })
    }
}

pub mod stream_fencing_token {
    use super::*;

    pub fn ser_key(stream_id: StreamId) -> Bytes {
        let capacity = 1 + 32;
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u8(ordinals::STREAM_FENCING_TOKEN);
        buf.put_slice(stream_id.as_ref());
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf.freeze()
    }

    pub fn deser_key(mut bytes: Bytes) -> Result<StreamId, DeserializationError> {
        check_exact_size(&bytes, 33)?;
        let ordinal = bytes.get_u8();
        if ordinal != ordinals::STREAM_FENCING_TOKEN {
            return Err(DeserializationError::InvalidOrdinal(ordinal));
        }
        let mut stream_id_bytes = [0u8; 32];
        bytes.copy_to_slice(&mut stream_id_bytes);
        Ok(stream_id_bytes.into())
    }

    pub fn ser_value(token: &FencingToken) -> Bytes {
        let token_bytes = token.as_bytes();
        let capacity = token_bytes.len();
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_slice(token_bytes);
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf.freeze()
    }

    pub fn deser_value(bytes: Bytes) -> Result<FencingToken, DeserializationError> {
        let token_str =
            std::str::from_utf8(&bytes).map_err(|e| invalid_value_err("fencing_token", e))?;
        FencingToken::from_str(token_str).map_err(|e| invalid_value_err("fencing_token", e))
    }
}

pub mod stream_trim_point {
    use super::*;

    pub fn ser_key(stream_id: StreamId) -> Bytes {
        let capacity = 1 + 32;
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u8(ordinals::STREAM_TRIM_POINT);
        buf.put_slice(stream_id.as_ref());
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf.freeze()
    }

    pub fn deser_key(mut bytes: Bytes) -> Result<StreamId, DeserializationError> {
        check_exact_size(&bytes, 33)?;
        let ordinal = bytes.get_u8();
        if ordinal != ordinals::STREAM_TRIM_POINT {
            return Err(DeserializationError::InvalidOrdinal(ordinal));
        }
        let mut stream_id_bytes = [0u8; 32];
        bytes.copy_to_slice(&mut stream_id_bytes);
        Ok(stream_id_bytes.into())
    }

    pub fn ser_value(seq_num: SeqNum) -> Bytes {
        let capacity = 8;
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u64(seq_num);
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf.freeze()
    }

    pub fn deser_value(mut bytes: Bytes) -> Result<SeqNum, DeserializationError> {
        check_exact_size(&bytes, 8)?;
        Ok(bytes.get_u64())
    }
}

pub mod stream_record_data {
    use super::*;

    pub fn ser_key(stream_id: StreamId, pos: StreamPosition) -> Bytes {
        let capacity = 1 + 32 + 8 + 8;
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u8(ordinals::STREAM_RECORD_DATA);
        buf.put_slice(stream_id.as_ref());
        buf.put_u64(pos.seq_num);
        buf.put_u64(pos.timestamp);
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf.freeze()
    }

    pub fn deser_key(mut bytes: Bytes) -> Result<(StreamId, StreamPosition), DeserializationError> {
        check_exact_size(&bytes, 49)?;
        let ordinal = bytes.get_u8();
        if ordinal != ordinals::STREAM_RECORD_DATA {
            return Err(DeserializationError::InvalidOrdinal(ordinal));
        }
        let mut stream_id_bytes = [0u8; 32];
        bytes.copy_to_slice(&mut stream_id_bytes);
        let seq_num = bytes.get_u64();
        let timestamp = bytes.get_u64();
        Ok((
            stream_id_bytes.into(),
            StreamPosition { seq_num, timestamp },
        ))
    }

    pub fn ser_value(record: &MeteredRecord) -> Bytes {
        record.to_bytes()
    }

    pub fn deser_value(bytes: Bytes) -> Result<MeteredRecord, DeserializationError> {
        MeteredRecord::try_from(bytes).map_err(|e| invalid_value_err("record", e))
    }
}

pub mod stream_record_timestamp {
    use super::*;

    pub fn ser_key(stream_id: StreamId, timestamp: Timestamp) -> Bytes {
        let capacity = 1 + 32 + 8;
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u8(ordinals::STREAM_RECORD_TIMESTAMP);
        buf.put_slice(stream_id.as_ref());
        buf.put_u64(timestamp);
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf.freeze()
    }

    pub fn deser_key(mut bytes: Bytes) -> Result<(StreamId, Timestamp), DeserializationError> {
        check_exact_size(&bytes, 41)?;
        let ordinal = bytes.get_u8();
        if ordinal != ordinals::STREAM_RECORD_TIMESTAMP {
            return Err(DeserializationError::InvalidOrdinal(ordinal));
        }
        let mut stream_id_bytes = [0u8; 32];
        bytes.copy_to_slice(&mut stream_id_bytes);
        let timestamp = bytes.get_u64();
        Ok((stream_id_bytes.into(), timestamp))
    }

    pub fn ser_value(seq_num: SeqNum) -> Bytes {
        let capacity = 8;
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u64(seq_num);
        debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
        buf.freeze()
    }

    pub fn deser_value(mut bytes: Bytes) -> Result<SeqNum, DeserializationError> {
        check_exact_size(&bytes, 8)?;
        Ok(bytes.get_u64())
    }
}

pub mod ordinals {
    pub const BASIN_META: u8 = 1;
    pub(super) const STREAM_META: u8 = 2;
    pub(super) const STREAM_TAIL_POSITION: u8 = 3;
    pub(super) const STREAM_FENCING_TOKEN: u8 = 4;
    pub(super) const STREAM_TRIM_POINT: u8 = 5;
    pub(super) const STREAM_RECORD_DATA: u8 = 6;
    pub(super) const STREAM_RECORD_TIMESTAMP: u8 = 7;
}

impl From<DbKey> for Bytes {
    fn from(value: DbKey) -> Self {
        match value {
            DbKey::BasinMeta(basin) => basin_meta::ser_key(&basin),
            DbKey::StreamMeta(basin, stream) => stream_meta::ser_key(&basin, &stream),
            DbKey::StreamTailPosition(stream_id) => stream_tail_position::ser_key(stream_id),
            DbKey::StreamFencingToken(stream_id) => stream_fencing_token::ser_key(stream_id),
            DbKey::StreamTrimPoint(stream_id) => stream_trim_point::ser_key(stream_id),
            DbKey::StreamRecordData(stream_id, pos) => stream_record_data::ser_key(stream_id, pos),
            DbKey::StreamRecordTimestamp(stream_id, timestamp) => {
                stream_record_timestamp::ser_key(stream_id, timestamp)
            }
        }
    }
}

impl TryFrom<Bytes> for DbKey {
    type Error = DeserializationError;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        check_min_size(&bytes, 1)?;
        match bytes[0] {
            ordinals::BASIN_META => basin_meta::deser_key(bytes).map(DbKey::BasinMeta),
            ordinals::STREAM_META => stream_meta::deser_key(bytes)
                .map(|(basin, stream)| DbKey::StreamMeta(basin, stream)),
            ordinals::STREAM_TAIL_POSITION => {
                stream_tail_position::deser_key(bytes).map(DbKey::StreamTailPosition)
            }
            ordinals::STREAM_FENCING_TOKEN => {
                stream_fencing_token::deser_key(bytes).map(DbKey::StreamFencingToken)
            }
            ordinals::STREAM_TRIM_POINT => {
                stream_trim_point::deser_key(bytes).map(DbKey::StreamTrimPoint)
            }
            ordinals::STREAM_RECORD_DATA => stream_record_data::deser_key(bytes)
                .map(|(stream_id, pos)| DbKey::StreamRecordData(stream_id, pos)),
            ordinals::STREAM_RECORD_TIMESTAMP => stream_record_timestamp::deser_key(bytes)
                .map(|(stream_id, timestamp)| DbKey::StreamRecordTimestamp(stream_id, timestamp)),
            ordinal => Err(DeserializationError::InvalidOrdinal(ordinal)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_basin_meta() {
        let basin = BasinName::from_str("test-basin").unwrap();
        let key = DbKey::BasinMeta(basin.clone());
        let bytes: Bytes = key.clone().into();
        let decoded = DbKey::try_from(bytes).unwrap();

        match decoded {
            DbKey::BasinMeta(decoded_basin) => {
                assert_eq!(basin.as_ref(), decoded_basin.as_ref());
            }
            _ => panic!("Expected BasinMeta variant"),
        }
    }

    #[test]
    fn round_trip_stream_meta() {
        let basin = BasinName::from_str("test-basin").unwrap();
        let stream = StreamName::from_str("test-stream").unwrap();
        let key = DbKey::StreamMeta(basin.clone(), stream.clone());
        let bytes: Bytes = key.clone().into();
        let decoded = DbKey::try_from(bytes).unwrap();

        match decoded {
            DbKey::StreamMeta(decoded_basin, decoded_stream) => {
                assert_eq!(basin.as_ref(), decoded_basin.as_ref());
                assert_eq!(stream.as_ref(), decoded_stream.as_ref());
            }
            _ => panic!("Expected StreamMeta variant"),
        }
    }

    #[test]
    fn round_trip_stream_tail_position() {
        let basin = BasinName::from_str("test-basin").unwrap();
        let stream = StreamName::from_str("test-stream").unwrap();
        let stream_id = StreamId::new(&basin, &stream);
        let key = DbKey::StreamTailPosition(stream_id);
        let bytes: Bytes = key.into();
        let decoded = DbKey::try_from(bytes).unwrap();

        match decoded {
            DbKey::StreamTailPosition(decoded_stream_id) => {
                assert_eq!(stream_id, decoded_stream_id);
            }
            _ => panic!("Expected StreamTailPosition variant"),
        }
    }

    #[test]
    fn round_trip_stream_record_data() {
        let basin = BasinName::from_str("test-basin").unwrap();
        let stream = StreamName::from_str("test-stream").unwrap();
        let stream_id = StreamId::new(&basin, &stream);
        let pos = StreamPosition {
            seq_num: 12345,
            timestamp: 1234567890,
        };
        let key = DbKey::StreamRecordData(stream_id, pos);
        let bytes: Bytes = key.into();
        let decoded = DbKey::try_from(bytes).unwrap();

        match decoded {
            DbKey::StreamRecordData(decoded_stream_id, decoded_pos) => {
                assert_eq!(stream_id, decoded_stream_id);
                assert_eq!(pos, decoded_pos);
            }
            _ => panic!("Expected StreamRecordData variant"),
        }
    }

    #[test]
    fn round_trip_stream_record_timestamp() {
        let basin = BasinName::from_str("test-basin").unwrap();
        let stream = StreamName::from_str("test-stream").unwrap();
        let stream_id = StreamId::new(&basin, &stream);
        let timestamp = 1234567890u64;
        let key = DbKey::StreamRecordTimestamp(stream_id, timestamp);
        let bytes: Bytes = key.into();
        let decoded = DbKey::try_from(bytes).unwrap();

        match decoded {
            DbKey::StreamRecordTimestamp(decoded_stream_id, decoded_timestamp) => {
                assert_eq!(stream_id, decoded_stream_id);
                assert_eq!(timestamp, decoded_timestamp);
            }
            _ => panic!("Expected StreamRecordTimestamp variant"),
        }
    }

    #[test]
    fn ordinals_are_unique() {
        use std::collections::HashSet;

        use super::ordinals::*;

        let ordinals = [
            BASIN_META,
            STREAM_META,
            STREAM_TAIL_POSITION,
            STREAM_FENCING_TOKEN,
            STREAM_TRIM_POINT,
            STREAM_RECORD_DATA,
            STREAM_RECORD_TIMESTAMP,
        ];

        let unique: HashSet<_> = ordinals.iter().collect();
        assert_eq!(
            ordinals.len(),
            unique.len(),
            "Found duplicate ordinals: {:?}",
            ordinals
        );
    }

    #[test]
    fn basin_meta_ser_key_prefix() {
        use s2_common::types::basin::BasinNamePrefix;

        let prefix = BasinNamePrefix::from_str("test-prefix").unwrap();
        let key = basin_meta::ser_key_prefix(&prefix);

        assert_eq!(key[0], ordinals::BASIN_META);
        assert_eq!(&key[1..], b"test-prefix");
    }

    #[test]
    fn basin_meta_ser_key_prefix_empty() {
        use s2_common::types::basin::BasinNamePrefix;

        let prefix = BasinNamePrefix::default();
        let key = basin_meta::ser_key_prefix(&prefix);

        assert_eq!(key.len(), 1);
        assert_eq!(key[0], ordinals::BASIN_META);
    }

    #[test]
    fn basin_meta_ser_key_prefix_end_empty() {
        use s2_common::types::basin::BasinNamePrefix;

        let prefix = BasinNamePrefix::default();
        let end_key = basin_meta::ser_key_prefix_end(&prefix);

        assert_eq!(end_key.len(), 1);
        assert_eq!(end_key[0], ordinals::BASIN_META + 1);
    }

    #[test]
    fn basin_meta_ser_key_prefix_end_normal() {
        use s2_common::types::basin::BasinNamePrefix;

        let prefix = BasinNamePrefix::from_str("test-abc").unwrap();
        let end_key = basin_meta::ser_key_prefix_end(&prefix);

        assert_eq!(end_key[0], ordinals::BASIN_META);
        assert_eq!(&end_key[1..], b"test-abd");
    }

    #[test]
    fn basin_meta_ser_key_prefix_end_increments_last_byte() {
        use s2_common::types::basin::BasinNamePrefix;

        let prefix = BasinNamePrefix::from_str("test-a").unwrap();
        let end_key = basin_meta::ser_key_prefix_end(&prefix);

        assert_eq!(end_key[0], ordinals::BASIN_META);
        assert_eq!(&end_key[1..], b"test-b");
    }

    #[test]
    fn basin_meta_ser_key_prefix_end_range_semantics() {
        use s2_common::types::basin::BasinNamePrefix;

        let prefix = BasinNamePrefix::from_str("prod-").unwrap();
        let start_key = basin_meta::ser_key_prefix(&prefix);
        let end_key = basin_meta::ser_key_prefix_end(&prefix);

        let prod_a = BasinName::from_str("prod-aaa").unwrap();
        let prod_z = BasinName::from_str("prod-zzz").unwrap();
        let staging = BasinName::from_str("stag-ing").unwrap();

        let key_prod_a = basin_meta::ser_key(&prod_a);
        let key_prod_z = basin_meta::ser_key(&prod_z);
        let key_staging = basin_meta::ser_key(&staging);

        assert!(key_prod_a >= start_key);
        assert!(key_prod_a < end_key);
        assert!(key_prod_z >= start_key);
        assert!(key_prod_z < end_key);
        assert!(key_staging >= end_key);
    }

    #[test]
    fn basin_meta_ser_key_start_after() {
        use s2_common::types::basin::BasinNameStartAfter;

        let start_after = BasinNameStartAfter::from_str("my-basin").unwrap();
        let key = basin_meta::ser_key_start_after(&start_after);

        assert_eq!(key[0], ordinals::BASIN_META);
        assert_eq!(&key[1..key.len() - 1], b"my-basin");
        assert_eq!(
            key[key.len() - 1],
            0x00,
            "should end with null byte for exclusion"
        );
    }

    #[test]
    fn basin_meta_ser_key_start_after_pagination() {
        let basin1 = BasinName::from_str("test-aaa").unwrap();
        let basin2 = BasinName::from_str("test-bbb").unwrap();
        let basin3 = BasinName::from_str("test-ccc").unwrap();

        let key1 = basin_meta::ser_key(&basin1);
        let key2 = basin_meta::ser_key(&basin2);
        let key3 = basin_meta::ser_key(&basin3);

        let start_after = BasinNameStartAfter::from(basin1.clone());
        let start_after_key = basin_meta::ser_key_start_after(&start_after);

        assert!(
            start_after_key > key1,
            "start_after key should be after basin1"
        );
        assert!(
            start_after_key < key2,
            "start_after key should be before basin2"
        );
        assert!(start_after_key < key3);
    }

    #[test]
    fn basin_meta_prefix_scan_range() {
        use s2_common::types::basin::BasinNamePrefix;

        let prefix = BasinNamePrefix::from_str("prod-").unwrap();
        let start_key = basin_meta::ser_key_prefix(&prefix);
        let end_key = basin_meta::ser_key_prefix_end(&prefix);

        let basin_in_range = BasinName::from_str("prod-service1").unwrap();
        let basin_out_range = BasinName::from_str("staging-service1").unwrap();

        let key_in = basin_meta::ser_key(&basin_in_range);
        let key_out = basin_meta::ser_key(&basin_out_range);

        assert!(key_in >= start_key && key_in < end_key);
        assert!(key_out < start_key || key_out >= end_key);
    }

    #[test]
    fn basin_meta_ser_key_range_no_start_after() {
        use s2_common::types::basin::{BasinNamePrefix, BasinNameStartAfter};

        let prefix = BasinNamePrefix::from_str("prod-").unwrap();
        let start_after = BasinNameStartAfter::default();

        let range = basin_meta::ser_key_range(&prefix, &start_after);

        assert_eq!(range.start, basin_meta::ser_key_prefix(&prefix));
        assert_eq!(range.end, basin_meta::ser_key_prefix_end(&prefix));
    }

    #[test]
    fn basin_meta_ser_key_range_with_start_after() {
        use s2_common::types::basin::{BasinNamePrefix, BasinNameStartAfter};

        let prefix = BasinNamePrefix::from_str("prod-").unwrap();
        let start_after = BasinNameStartAfter::from_str("prod-api").unwrap();

        let range = basin_meta::ser_key_range(&prefix, &start_after);

        assert_eq!(range.start, basin_meta::ser_key_start_after(&start_after));
        assert_eq!(range.end, basin_meta::ser_key_prefix_end(&prefix));
    }

    #[test]
    fn basin_meta_ser_key_range_pagination_scenario() {
        use s2_common::types::basin::{BasinNamePrefix, BasinNameStartAfter};

        let prefix = BasinNamePrefix::from_str("test-").unwrap();
        let basin1 = BasinName::from_str("test-aaa").unwrap();
        let basin2 = BasinName::from_str("test-bbb").unwrap();
        let basin3 = BasinName::from_str("test-ccc").unwrap();

        let page1_range = basin_meta::ser_key_range(&prefix, &BasinNameStartAfter::default());
        let key1 = basin_meta::ser_key(&basin1);
        let key2 = basin_meta::ser_key(&basin2);
        let key3 = basin_meta::ser_key(&basin3);

        assert!(key1 >= page1_range.start && key1 < page1_range.end);
        assert!(key2 >= page1_range.start && key2 < page1_range.end);
        assert!(key3 >= page1_range.start && key3 < page1_range.end);

        let start_after = BasinNameStartAfter::from(basin1.clone());
        let page2_range = basin_meta::ser_key_range(&prefix, &start_after);

        assert!(
            key1 < page2_range.start,
            "basin1 should be excluded from page2"
        );
        assert!(
            key2 >= page2_range.start && key2 < page2_range.end,
            "basin2 should be in page2"
        );
        assert!(
            key3 >= page2_range.start && key3 < page2_range.end,
            "basin3 should be in page2"
        );
    }

    #[test]
    fn value_roundtrip_stream_tail_position() {
        let pos = StreamPosition {
            seq_num: 42,
            timestamp: 1234567890,
        };

        let bytes = stream_tail_position::ser_value(pos);
        let decoded_pos = stream_tail_position::deser_value(bytes).unwrap();

        assert_eq!(pos, decoded_pos);
    }

    #[test]
    fn value_roundtrip_basin_meta() {
        let config = BasinConfig {
            create_stream_on_append: true,
            ..Default::default()
        };
        let created_at = OffsetDateTime::from_unix_timestamp(1234567890)
            .unwrap()
            .replace_nanosecond(123456789)
            .unwrap();
        let deleted_at = Some(
            OffsetDateTime::from_unix_timestamp(1234567890)
                .unwrap()
                .replace_nanosecond(123456789)
                .unwrap(),
        );
        let basin_meta = BasinMeta {
            config: config.clone(),
            created_at,
            deleted_at,
        };

        let bytes = basin_meta::ser_value(&basin_meta);
        let decoded = basin_meta::deser_value(bytes).unwrap();

        assert_eq!(
            basin_meta.config.create_stream_on_append,
            decoded.config.create_stream_on_append
        );
        assert_eq!(
            basin_meta.config.create_stream_on_read,
            decoded.config.create_stream_on_read
        );
        assert_eq!(basin_meta.created_at, decoded.created_at);
        assert_eq!(basin_meta.deleted_at, decoded.deleted_at);
    }

    #[test]
    fn value_roundtrip_stream_meta() {
        use s2_common::types::config::{OptionalStreamConfig, StorageClass};

        let config = OptionalStreamConfig {
            storage_class: Some(StorageClass::Express),
            ..Default::default()
        };
        let created_at = OffsetDateTime::from_unix_timestamp(1234567890)
            .unwrap()
            .replace_nanosecond(123456789)
            .unwrap();
        let deleted_at = Some(
            OffsetDateTime::from_unix_timestamp(1234567890)
                .unwrap()
                .replace_nanosecond(123456789)
                .unwrap(),
        );
        let stream_meta = StreamMeta {
            config: config.clone(),
            created_at,
            deleted_at,
        };

        let bytes = stream_meta::ser_value(&stream_meta);
        let decoded = stream_meta::deser_value(bytes).unwrap();

        assert_eq!(
            stream_meta.config.storage_class,
            decoded.config.storage_class
        );
        assert_eq!(stream_meta.created_at, decoded.created_at);
        assert_eq!(stream_meta.deleted_at, decoded.deleted_at);
    }

    #[test]
    fn value_roundtrip_stream_fencing_token() {
        let token = FencingToken::from_str("my-fencing-token-123").unwrap();

        let bytes = stream_fencing_token::ser_value(&token);
        let decoded_token = stream_fencing_token::deser_value(bytes).unwrap();

        assert_eq!(token.as_ref(), decoded_token.as_ref());
    }

    #[test]
    fn value_roundtrip_stream_trim_point() {
        let seq_num = 99999u64;

        let bytes = stream_trim_point::ser_value(seq_num);
        let decoded_seq_num = stream_trim_point::deser_value(bytes).unwrap();

        assert_eq!(seq_num, decoded_seq_num);
    }

    #[test]
    fn value_roundtrip_stream_record_data() {
        use s2_common::record::{Header, MeteredSize, Record};

        let headers = vec![Header {
            name: Bytes::from_static(b"content-type"),
            value: Bytes::from_static(b"application/json"),
        }];
        let body = Bytes::from_static(b"{\"test\": \"data\"}");
        let record = Record::try_from_parts(headers, body).unwrap();
        let metered_record: MeteredRecord = record.into();

        let bytes = stream_record_data::ser_value(&metered_record);
        let decoded_record = stream_record_data::deser_value(bytes).unwrap();

        assert_eq!(metered_record.metered_size(), decoded_record.metered_size());
    }

    #[test]
    fn value_roundtrip_stream_record_timestamp() {
        let seq_num = 777u64;

        let bytes = stream_record_timestamp::ser_value(seq_num);
        let decoded_seq_num = stream_record_timestamp::deser_value(bytes).unwrap();

        assert_eq!(seq_num, decoded_seq_num);
    }

    #[test]
    fn error_on_invalid_ordinal() {
        let bytes = Bytes::from(vec![255u8]);
        let result = DbKey::try_from(bytes);
        assert!(matches!(
            result,
            Err(DeserializationError::InvalidOrdinal(255))
        ));
    }

    #[test]
    fn error_on_insufficient_data() {
        use ordinals::*;
        let bytes = Bytes::from(vec![STREAM_TAIL_POSITION, 1, 2, 3]);
        let result = DbKey::try_from(bytes);
        assert!(matches!(
            result,
            Err(DeserializationError::InvalidSize { .. })
        ));
    }

    #[test]
    fn error_on_missing_separator() {
        use ordinals::*;
        let mut buf = BytesMut::new();
        buf.put_u8(STREAM_META);
        buf.put_slice(b"basin-without-separator");
        let bytes = buf.freeze();

        let result = DbKey::try_from(bytes);
        assert!(matches!(
            result,
            Err(DeserializationError::MissingFieldSeparator)
        ));
    }

    mod proptests {
        use proptest::prelude::*;
        use s2_common::types::{
            basin::{BasinNamePrefix, BasinNameStartAfter},
            stream::{StreamNamePrefix, StreamNameStartAfter},
        };

        use super::*;

        fn basin_name_strategy() -> impl Strategy<Value = BasinName> {
            "[a-z][a-z0-9-]{6,46}[a-z0-9]".prop_map(|s| BasinName::from_str(&s).unwrap())
        }

        fn basin_name_prefix_strategy() -> impl Strategy<Value = BasinNamePrefix> {
            prop_oneof![
                Just(BasinNamePrefix::default()),
                "[a-z][a-z0-9-]{0,46}".prop_map(|s| BasinNamePrefix::from_str(&s).unwrap()),
            ]
        }

        fn stream_name_strategy() -> impl Strategy<Value = StreamName> {
            "[a-zA-Z0-9_-]{1,100}".prop_map(|s| StreamName::from_str(&s).unwrap())
        }

        fn stream_name_prefix_strategy() -> impl Strategy<Value = StreamNamePrefix> {
            prop_oneof![
                Just(StreamNamePrefix::default()),
                "[a-zA-Z0-9_-]{0,100}".prop_map(|s| StreamNamePrefix::from_str(&s).unwrap()),
            ]
        }

        fn stream_id_strategy() -> impl Strategy<Value = StreamId> {
            (basin_name_strategy(), stream_name_strategy())
                .prop_map(|(basin, stream)| StreamId::new(&basin, &stream))
        }

        fn db_key_strategy() -> impl Strategy<Value = DbKey> {
            prop_oneof![
                basin_name_strategy().prop_map(DbKey::BasinMeta),
                (basin_name_strategy(), stream_name_strategy())
                    .prop_map(|(b, s)| DbKey::StreamMeta(b, s)),
                stream_id_strategy().prop_map(DbKey::StreamTailPosition),
                stream_id_strategy().prop_map(DbKey::StreamFencingToken),
                stream_id_strategy().prop_map(DbKey::StreamTrimPoint),
                (stream_id_strategy(), any::<SeqNum>(), any::<Timestamp>()).prop_map(
                    |(id, seq_num, timestamp)| {
                        DbKey::StreamRecordData(id, StreamPosition { seq_num, timestamp })
                    }
                ),
                (stream_id_strategy(), any::<Timestamp>())
                    .prop_map(|(id, ts)| DbKey::StreamRecordTimestamp(id, ts)),
            ]
        }

        proptest! {
            #[test]
            fn roundtrip_key_serialization(key in db_key_strategy()) {
                let bytes: Bytes = key.clone().into();
                let decoded = DbKey::try_from(bytes).unwrap();

                match (&key, &decoded) {
                    (DbKey::BasinMeta(b1), DbKey::BasinMeta(b2)) => {
                        assert_eq!(b1.as_ref(), b2.as_ref());
                    }
                    (DbKey::StreamMeta(b1, s1), DbKey::StreamMeta(b2, s2)) => {
                        assert_eq!(b1.as_ref(), b2.as_ref());
                        assert_eq!(s1.as_ref(), s2.as_ref());
                    }
                    (DbKey::StreamTailPosition(id1), DbKey::StreamTailPosition(id2)) => {
                        assert_eq!(id1, id2);
                    }
                    (DbKey::StreamFencingToken(id1), DbKey::StreamFencingToken(id2)) => {
                        assert_eq!(id1, id2);
                    }
                    (DbKey::StreamTrimPoint(id1), DbKey::StreamTrimPoint(id2)) => {
                        assert_eq!(id1, id2);
                    }
                    (DbKey::StreamRecordData(id1, pos1), DbKey::StreamRecordData(id2, pos2)) => {
                        assert_eq!(id1, id2);
                        assert_eq!(pos1, pos2);
                    }
                    (DbKey::StreamRecordTimestamp(id1, ts1), DbKey::StreamRecordTimestamp(id2, ts2)) => {
                        assert_eq!(id1, id2);
                        assert_eq!(ts1, ts2);
                    }
                    _ => panic!("Variant mismatch: expected {:?}, got {:?}", key, decoded),
                }
            }

            #[test]
            fn roundtrip_stream_tail_position_value(seq_num in any::<SeqNum>(), timestamp in any::<Timestamp>()) {
                let pos = StreamPosition { seq_num, timestamp };
                let bytes = stream_tail_position::ser_value(pos);
                let decoded_pos = stream_tail_position::deser_value(bytes).unwrap();
                prop_assert_eq!(pos, decoded_pos);
            }

            #[test]
            fn roundtrip_stream_fencing_token_value(token_str in "[a-zA-Z0-9_-]{0,36}") {
                let token = FencingToken::from_str(&token_str).unwrap();
                let bytes = stream_fencing_token::ser_value(&token);
                let decoded = stream_fencing_token::deser_value(bytes).unwrap();
                prop_assert_eq!(token.as_ref(), decoded.as_ref());
            }

            #[test]
            fn roundtrip_stream_trim_point_value(seq_num in any::<SeqNum>()) {
                let bytes = stream_trim_point::ser_value(seq_num);
                let decoded = stream_trim_point::deser_value(bytes).unwrap();
                prop_assert_eq!(seq_num, decoded);
            }

            #[test]
            fn roundtrip_stream_record_timestamp_value(seq_num in any::<SeqNum>()) {
                let bytes = stream_record_timestamp::ser_value(seq_num);
                let decoded = stream_record_timestamp::deser_value(bytes).unwrap();
                prop_assert_eq!(seq_num, decoded);
            }

            #[test]
            fn roundtrip_stream_record_data_value(
                header_name in prop::collection::vec(any::<u8>(), 1..20),
                header_value in prop::collection::vec(any::<u8>(), 0..50),
                body in prop::collection::vec(any::<u8>(), 0..200),
            ) {
                use s2_common::record::{Header, MeteredSize, Record};

                let headers = vec![Header {
                    name: Bytes::from(header_name),
                    value: Bytes::from(header_value),
                }];
                let body = Bytes::from(body);
                let record = Record::try_from_parts(headers, body).unwrap();
                let metered_record: MeteredRecord = record.into();
                let original_size = metered_record.metered_size();

                let bytes = stream_record_data::ser_value(&metered_record);
                let decoded = stream_record_data::deser_value(bytes).unwrap();

                prop_assert_eq!(original_size, decoded.metered_size());
            }

            #[test]
            fn basin_meta_range_contains_prefixed_keys(
                prefix in basin_name_prefix_strategy(),
                basin in basin_name_strategy(),
            ) {
                let prefix_str = prefix.as_ref();
                let basin_str = basin.as_ref();

                if !prefix_str.is_empty() && !basin_str.starts_with(prefix_str) {
                    return Ok(());
                }

                let range = basin_meta::ser_key_range(&prefix, &BasinNameStartAfter::default());
                let key = basin_meta::ser_key(&basin);

                if basin_str.starts_with(prefix_str) || prefix_str.is_empty() {
                    prop_assert!(key >= range.start, "key {:?} should be >= range.start {:?}", key, range.start);
                    prop_assert!(key < range.end, "key {:?} should be < range.end {:?}", key, range.end);
                } else {
                    prop_assert!(key < range.start || key >= range.end);
                }
            }

            #[test]
            fn basin_meta_keys_preserve_ordering(
                basin1 in basin_name_strategy(),
                basin2 in basin_name_strategy(),
            ) {
                let key1 = basin_meta::ser_key(&basin1);
                let key2 = basin_meta::ser_key(&basin2);

                let basin_cmp = basin1.as_ref().cmp(basin2.as_ref());
                let key_cmp = key1.cmp(&key2);

                prop_assert_eq!(basin_cmp, key_cmp, "ordering should be preserved");
            }

            #[test]
            fn basin_meta_prefix_end_is_exclusive_upper_bound(
                prefix in basin_name_prefix_strategy(),
                basin in basin_name_strategy(),
            ) {
                let end_key = basin_meta::ser_key_prefix_end(&prefix);

                if prefix.is_empty() || basin.as_ref().starts_with(prefix.as_ref()) {
                    let key = basin_meta::ser_key(&basin);
                    prop_assert!(key < end_key, "prefixed key should be < end_key");
                }
            }

            #[test]
            fn basin_meta_start_after_excludes_cursor(
                prefix in basin_name_prefix_strategy(),
                basin1 in basin_name_strategy(),
                basin2 in basin_name_strategy(),
            ) {
                if basin1.as_ref() >= basin2.as_ref() {
                    return Ok(());
                }

                let start_after = BasinNameStartAfter::from(basin1.clone());
                let range = basin_meta::ser_key_range(&prefix, &start_after);

                let key1 = basin_meta::ser_key(&basin1);
                let key2 = basin_meta::ser_key(&basin2);

                prop_assert!(key1 < range.start, "cursor basin should be excluded (before range.start)");
                prop_assert!(key2 >= range.start, "later basin should be included (at or after range.start)");
            }

            #[test]
            fn stream_meta_range_contains_prefixed_keys(
                basin in basin_name_strategy(),
                prefix in stream_name_prefix_strategy(),
                stream in stream_name_strategy(),
            ) {
                let prefix_str = prefix.as_ref();
                let stream_str = stream.as_ref();

                if !prefix_str.is_empty() && !stream_str.starts_with(prefix_str) {
                    return Ok(());
                }

                let range = stream_meta::ser_key_range(&basin, &prefix, &StreamNameStartAfter::default());
                let key = stream_meta::ser_key(&basin, &stream);

                if stream_str.starts_with(prefix_str) || prefix_str.is_empty() {
                    prop_assert!(key >= range.start, "key {:?} should be >= range.start {:?}", key, range.start);
                    prop_assert!(key < range.end, "key {:?} should be < range.end {:?}", key, range.end);
                } else {
                    prop_assert!(key < range.start || key >= range.end);
                }
            }

            #[test]
            fn stream_meta_keys_preserve_ordering(
                basin in basin_name_strategy(),
                stream1 in stream_name_strategy(),
                stream2 in stream_name_strategy(),
            ) {
                let key1 = stream_meta::ser_key(&basin, &stream1);
                let key2 = stream_meta::ser_key(&basin, &stream2);

                let stream_cmp = stream1.as_ref().cmp(stream2.as_ref());
                let key_cmp = key1.cmp(&key2);

                prop_assert_eq!(stream_cmp, key_cmp, "ordering should be preserved");
            }

            #[test]
            fn stream_meta_prefix_end_is_exclusive_upper_bound(
                basin in basin_name_strategy(),
                prefix in stream_name_prefix_strategy(),
                stream in stream_name_strategy(),
            ) {
                let end_key = stream_meta::ser_key_prefix_end(&basin, &prefix);

                if prefix.is_empty() || stream.as_ref().starts_with(prefix.as_ref()) {
                    let key = stream_meta::ser_key(&basin, &stream);
                    prop_assert!(key < end_key, "prefixed key should be < end_key");
                }
            }

            #[test]
            fn stream_meta_start_after_excludes_cursor(
                basin in basin_name_strategy(),
                prefix in stream_name_prefix_strategy(),
                stream1 in stream_name_strategy(),
                stream2 in stream_name_strategy(),
            ) {
                if stream1.as_ref() >= stream2.as_ref() {
                    return Ok(());
                }

                let start_after = StreamNameStartAfter::from(stream1.clone());
                let range = stream_meta::ser_key_range(&basin, &prefix, &start_after);

                let key1 = stream_meta::ser_key(&basin, &stream1);
                let key2 = stream_meta::ser_key(&basin, &stream2);

                prop_assert!(key1 < range.start, "cursor stream should be excluded (before range.start)");
                prop_assert!(key2 >= range.start, "later stream should be included (at or after range.start)");
            }
        }
    }
}
