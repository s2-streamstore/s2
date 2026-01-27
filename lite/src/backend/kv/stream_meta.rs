use std::{ops::Range, str::FromStr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::{
    bash::Bash,
    caps::{MIN_BASIN_NAME_LEN, MIN_STREAM_NAME_LEN},
    types::{
        basin::BasinName,
        config::OptionalStreamConfig,
        stream::{StreamName, StreamNamePrefix, StreamNameStartAfter},
    },
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{
    DeserializationError, KeyType, check_min_size, deser_json_value, increment_bytes,
    invalid_value_err, ser_json_value,
};

const FIELD_SEPARATOR: u8 = b'\0';

#[derive(Debug, Clone)]
pub struct StreamMeta {
    pub config: OptionalStreamConfig,
    pub created_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub creation_idempotency_key: Option<Bash>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamMetaSerde {
    config: Option<s2_api::v1::config::StreamConfig>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    deleted_at: Option<OffsetDateTime>,
    creation_idempotency_key: Option<Bash>,
}

impl From<StreamMeta> for StreamMetaSerde {
    fn from(meta: StreamMeta) -> Self {
        Self {
            config: s2_api::v1::config::StreamConfig::to_opt(meta.config),
            created_at: meta.created_at,
            deleted_at: meta.deleted_at,
            creation_idempotency_key: meta.creation_idempotency_key,
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
            creation_idempotency_key: serde.creation_idempotency_key,
        })
    }
}

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
    bytes.push(FIELD_SEPARATOR);
    ser_key_internal(basin.as_bytes(), &bytes).freeze()
}

pub fn ser_key_range(
    basin: &BasinName,
    prefix: &StreamNamePrefix,
    start_after: &StreamNameStartAfter,
) -> Range<Bytes> {
    let prefix_start = ser_key_prefix(basin, prefix);
    let start = if start_after.is_empty() {
        prefix_start
    } else {
        let start_after_key = ser_key_start_after(basin, start_after);
        std::cmp::max(prefix_start, start_after_key)
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
    buf.put_u8(KeyType::StreamMeta.ordinal());
    buf.put_slice(basin_bytes);
    buf.put_u8(FIELD_SEPARATOR);
    buf.put_slice(stream_bytes);
    debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
    buf
}

pub fn deser_key(mut bytes: Bytes) -> Result<(BasinName, StreamName), DeserializationError> {
    check_min_size(&bytes, 1 + MIN_BASIN_NAME_LEN + 1 + MIN_STREAM_NAME_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::StreamMeta.ordinal() {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let sep_pos = bytes
        .iter()
        .position(|&b| b == FIELD_SEPARATOR)
        .ok_or(DeserializationError::MissingFieldSeparator)?;

    let basin_str =
        std::str::from_utf8(&bytes[..sep_pos]).map_err(|e| invalid_value_err("basin", e))?;
    let stream_str =
        std::str::from_utf8(&bytes[sep_pos + 1..]).map_err(|e| invalid_value_err("stream", e))?;

    let basin = BasinName::from_str(basin_str).map_err(|e| invalid_value_err("basin", e))?;
    let stream = StreamName::from_str(stream_str).map_err(|e| invalid_value_err("stream", e))?;

    Ok((basin, stream))
}

pub fn ser_value(stream_meta: &StreamMeta) -> Bytes {
    ser_json_value::<StreamMeta, StreamMetaSerde>(stream_meta, "StreamMeta")
}

pub fn deser_value(bytes: Bytes) -> Result<StreamMeta, DeserializationError> {
    deser_json_value::<StreamMeta, StreamMetaSerde>(bytes, "stream_meta")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bytes::Bytes;
    use proptest::prelude::*;
    use s2_common::{
        bash::Bash,
        types::{
            basin::BasinName,
            config::{OptionalStreamConfig, StorageClass},
            stream::{StreamName, StreamNamePrefix, StreamNameStartAfter},
        },
    };
    use time::OffsetDateTime;

    use crate::backend::kv::proptest_strategies::{basin_name_strategy, stream_name_strategy};

    #[test]
    fn value_roundtrip_stream_meta() {
        let config = OptionalStreamConfig {
            storage_class: Some(StorageClass::Express),
            ..Default::default()
        };
        let created_at = OffsetDateTime::from_unix_timestamp(1_234_567_890)
            .unwrap()
            .replace_nanosecond(123_456_789)
            .unwrap();
        let deleted_at = Some(
            OffsetDateTime::from_unix_timestamp(1_234_567_890)
                .unwrap()
                .replace_nanosecond(123_456_789)
                .unwrap(),
        );
        let stream_meta = super::StreamMeta {
            config,
            created_at,
            deleted_at,
            creation_idempotency_key: Some(Bash::new(&[
                b"test-basin",
                b"test-stream",
                b"request-token-456",
            ])),
        };

        let bytes = super::ser_value(&stream_meta);
        let decoded = super::deser_value(bytes).unwrap();

        assert_eq!(
            stream_meta.config.storage_class,
            decoded.config.storage_class
        );
        assert_eq!(stream_meta.created_at, decoded.created_at);
        assert_eq!(stream_meta.deleted_at, decoded.deleted_at);
    }

    #[test]
    fn stream_meta_deser_defaults_config_missing() {
        let serde_value = super::StreamMetaSerde {
            config: None,
            created_at: OffsetDateTime::from_unix_timestamp(2_345_678).unwrap(),
            deleted_at: None,
            creation_idempotency_key: Some(Bash::new(&[b"my-basin", b"my-stream", b"req-abc"])),
        };
        let bytes = Bytes::from(serde_json::to_vec(&serde_value).unwrap());
        let decoded = super::deser_value(bytes).unwrap();
        let default_config = OptionalStreamConfig::default();

        assert_eq!(decoded.config.storage_class, default_config.storage_class);
        assert_eq!(
            decoded.config.retention_policy,
            default_config.retention_policy
        );
        assert_eq!(
            decoded.config.timestamping.mode,
            default_config.timestamping.mode
        );
        assert_eq!(
            decoded.config.timestamping.uncapped,
            default_config.timestamping.uncapped
        );
        assert_eq!(
            decoded.config.delete_on_empty.min_age,
            default_config.delete_on_empty.min_age
        );
        assert_eq!(decoded.created_at, serde_value.created_at);
        assert_eq!(decoded.deleted_at, serde_value.deleted_at);
    }

    fn stream_name_prefix_strategy() -> impl Strategy<Value = StreamNamePrefix> {
        prop_oneof![
            Just(StreamNamePrefix::default()),
            "[a-zA-Z0-9_-]{0,100}".prop_map(|s| StreamNamePrefix::from_str(&s).unwrap()),
        ]
    }

    #[test]
    fn stream_meta_range_start_after_before_prefix() {
        let basin = BasinName::from_str("my-basin").unwrap();
        let prefix = StreamNamePrefix::from_str("staging-").unwrap();
        let start_after = StreamNameStartAfter::from_str("prod-api").unwrap();

        let range = super::ser_key_range(&basin, &prefix, &start_after);

        assert!(
            range.start < range.end,
            "range should be valid when start_after is before prefix range"
        );

        let staging_stream = StreamName::from_str("staging-api").unwrap();
        let staging_key = super::ser_key(&basin, &staging_stream);
        assert!(
            staging_key >= range.start && staging_key < range.end,
            "streams matching prefix should be in range"
        );

        let prod_stream = StreamName::from_str("prod-service").unwrap();
        let prod_key = super::ser_key(&basin, &prod_stream);
        assert!(
            prod_key < range.start,
            "streams before prefix should NOT be in range"
        );
    }

    proptest! {
        #[test]
        fn roundtrip_stream_meta_key(
            basin in basin_name_strategy(),
            stream in stream_name_strategy(),
        ) {
            let bytes = super::ser_key(&basin, &stream);
            let (decoded_basin, decoded_stream) = super::deser_key(bytes).unwrap();
            prop_assert_eq!(basin.as_ref(), decoded_basin.as_ref());
            prop_assert_eq!(stream.as_ref(), decoded_stream.as_ref());
        }

        #[test]
        fn stream_meta_range_contains_prefixed_keys(
            basin in basin_name_strategy(),
            prefix in stream_name_prefix_strategy(),
            stream in stream_name_strategy(),
        ) {
            let prefix_str = prefix.as_ref();
            let stream_str = stream.as_ref();
            let matches_prefix = prefix_str.is_empty() || stream_str.starts_with(prefix_str);

            let range = super::ser_key_range(&basin, &prefix, &StreamNameStartAfter::default());
            let key = super::ser_key(&basin, &stream);

            if matches_prefix {
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
            let key1 = super::ser_key(&basin, &stream1);
            let key2 = super::ser_key(&basin, &stream2);

            let stream_cmp = stream1.as_ref().cmp(stream2.as_ref());
            let key_cmp = key1.cmp(&key2);

            prop_assert_eq!(stream_cmp, key_cmp, "ordering should be preserved");
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
            let range = super::ser_key_range(&basin, &prefix, &start_after);

            let key1 = super::ser_key(&basin, &stream1);
            let key2 = super::ser_key(&basin, &stream2);

            let prefix_str = prefix.as_ref();
            let stream1_matches = prefix_str.is_empty() || stream1.as_ref().starts_with(prefix_str);
            let stream2_matches = prefix_str.is_empty() || stream2.as_ref().starts_with(prefix_str);

            prop_assert!(key1 < range.start, "cursor stream should be excluded (before range.start)");
            if stream2_matches && (stream1_matches || stream2.as_ref() > prefix_str) {
                prop_assert!(key2 >= range.start, "later stream matching prefix should be included (at or after range.start)");
            }
        }
    }
}
