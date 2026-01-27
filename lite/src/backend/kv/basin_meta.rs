use std::{ops::Range, str::FromStr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::{
    bash::Bash,
    caps::MIN_BASIN_NAME_LEN,
    types::{
        basin::{BasinName, BasinNamePrefix, BasinNameStartAfter},
        config::BasinConfig,
    },
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{
    DeserializationError, KeyType, check_min_size, deser_json_value, increment_bytes,
    invalid_value_err, ser_json_value,
};

#[derive(Debug, Clone)]
pub struct BasinMeta {
    pub config: BasinConfig,
    pub created_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub creation_idempotency_key: Option<Bash>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BasinMetaSerde {
    config: Option<s2_api::v1::config::BasinConfig>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    deleted_at: Option<OffsetDateTime>,
    creation_idempotency_key: Option<Bash>,
}

impl From<BasinMeta> for BasinMetaSerde {
    fn from(meta: BasinMeta) -> Self {
        Self {
            config: Some(meta.config.into()),
            created_at: meta.created_at,
            deleted_at: meta.deleted_at,
            creation_idempotency_key: meta.creation_idempotency_key,
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
            creation_idempotency_key: serde.creation_idempotency_key,
        })
    }
}

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
    bytes.push(b'\0');
    ser_key_internal(&bytes).freeze()
}

pub fn ser_key_range(prefix: &BasinNamePrefix, start_after: &BasinNameStartAfter) -> Range<Bytes> {
    let prefix_start = ser_key_prefix(prefix);
    let start = if start_after.is_empty() {
        prefix_start
    } else {
        let start_after_key = ser_key_start_after(start_after);
        std::cmp::max(prefix_start, start_after_key)
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
    buf.put_u8(KeyType::BasinMeta.ordinal());
    buf.put_slice(basin);
    debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
    buf
}

pub fn deser_key(mut bytes: Bytes) -> Result<BasinName, DeserializationError> {
    check_min_size(&bytes, 1 + MIN_BASIN_NAME_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::BasinMeta.ordinal() {
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bytes::Bytes;
    use enum_ordinalize::Ordinalize;
    use proptest::prelude::*;
    use s2_common::{
        bash::Bash,
        types::{
            basin::{BasinName, BasinNamePrefix, BasinNameStartAfter},
            config::BasinConfig,
        },
    };
    use time::OffsetDateTime;

    use crate::backend::kv::{
        DeserializationError, KeyType, proptest_strategies::basin_name_strategy,
    };

    fn basin(name: &str) -> BasinName {
        BasinName::from_str(name).unwrap()
    }

    fn basin_prefix(prefix: &str) -> BasinNamePrefix {
        BasinNamePrefix::from_str(prefix).unwrap()
    }

    fn basin_start_after(name: &str) -> BasinNameStartAfter {
        BasinNameStartAfter::from_str(name).unwrap()
    }

    #[test]
    fn basin_meta_ser_key_prefix() {
        let prefix = basin_prefix("test-prefix");
        let key = super::ser_key_prefix(&prefix);

        assert_eq!(key[0], KeyType::BasinMeta.ordinal());
        assert_eq!(&key[1..], b"test-prefix");
    }

    #[test]
    fn basin_meta_ser_key_prefix_empty() {
        let prefix = BasinNamePrefix::default();
        let key = super::ser_key_prefix(&prefix);

        assert_eq!(key.len(), 1);
        assert_eq!(key[0], KeyType::BasinMeta.ordinal());
    }

    #[test]
    fn basin_meta_ser_key_prefix_end_empty() {
        let prefix = BasinNamePrefix::default();
        let end_key = super::ser_key_prefix_end(&prefix);

        assert_eq!(end_key.len(), 1);
        assert_eq!(end_key[0], KeyType::BasinMeta.ordinal() + 1);
    }

    #[test]
    fn basin_meta_ser_key_prefix_end_advances() {
        for (input, expected_suffix) in [("test-a", &b"test-b"[..]), ("test-abc", &b"test-abd"[..])]
        {
            let end_key = super::ser_key_prefix_end(&basin_prefix(input));
            assert_eq!(end_key[0], KeyType::BasinMeta.ordinal());
            assert_eq!(&end_key[1..], expected_suffix);
        }
    }

    #[test]
    fn basin_meta_ser_key_start_after() {
        let key = super::ser_key_start_after(&basin_start_after("my-basin"));

        assert_eq!(key[0], KeyType::BasinMeta.ordinal());
        assert_eq!(&key[1..key.len() - 1], b"my-basin");
        assert_eq!(
            key[key.len() - 1],
            b'\0',
            "should end with null byte for exclusion"
        );
    }

    #[test]
    fn basin_meta_key_range_handles_pagination() {
        let prefix = basin_prefix("test-");
        let basin1 = basin("test-aaa");
        let basin2 = basin("test-bbb");
        let basin3 = basin("test-ccc");
        let outside = basin("staging-service1");

        let page1 = super::ser_key_range(&prefix, &BasinNameStartAfter::default());
        assert_eq!(page1.start, super::ser_key_prefix(&prefix));
        assert_eq!(page1.end, super::ser_key_prefix_end(&prefix));

        let key1 = super::ser_key(&basin1);
        let key2 = super::ser_key(&basin2);
        let key3 = super::ser_key(&basin3);
        let key_outside = super::ser_key(&outside);

        assert!(key1 >= page1.start && key1 < page1.end);
        assert!(key2 >= page1.start && key2 < page1.end);
        assert!(key3 >= page1.start && key3 < page1.end);
        assert!(key_outside < page1.start || key_outside >= page1.end);

        let start_after = BasinNameStartAfter::from(basin1);
        let cursor_key = super::ser_key_start_after(&start_after);
        assert!(cursor_key > key1);
        assert!(cursor_key < key2);

        let page2 = super::ser_key_range(&prefix, &start_after);
        assert_eq!(page2.start, super::ser_key_start_after(&start_after));
        assert_eq!(page2.end, super::ser_key_prefix_end(&prefix));

        assert!(key1 < page2.start);
        assert!(key2 >= page2.start && key2 < page2.end);
        assert!(key3 >= page2.start && key3 < page2.end);
    }

    #[test]
    fn value_roundtrip_basin_meta() {
        let config = BasinConfig {
            create_stream_on_append: true,
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
        let basin_meta = super::BasinMeta {
            config,
            created_at,
            deleted_at,
            creation_idempotency_key: Some(Bash::new(&[b"test-basin", b"request-token-123"])),
        };

        let bytes = super::ser_value(&basin_meta);
        let decoded = super::deser_value(bytes).unwrap();

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
    fn basin_meta_deser_defaults_config_missing() {
        let serde_value = super::BasinMetaSerde {
            config: None,
            created_at: OffsetDateTime::from_unix_timestamp(1_234_567).unwrap(),
            deleted_at: None,
            creation_idempotency_key: Some(Bash::new(&[b"my-basin", b"req-789"])),
        };
        let bytes = Bytes::from(serde_json::to_vec(&serde_value).unwrap());
        let decoded = super::deser_value(bytes).unwrap();
        let default_config = BasinConfig::default();

        assert_eq!(
            decoded.config.create_stream_on_append,
            default_config.create_stream_on_append
        );
        assert_eq!(
            decoded.config.create_stream_on_read,
            default_config.create_stream_on_read
        );
        assert_eq!(
            decoded.config.default_stream_config.storage_class,
            default_config.default_stream_config.storage_class
        );
        assert_eq!(
            decoded.config.default_stream_config.retention_policy,
            default_config.default_stream_config.retention_policy
        );
        assert_eq!(
            decoded.config.default_stream_config.timestamping.mode,
            default_config.default_stream_config.timestamping.mode
        );
        assert_eq!(
            decoded.config.default_stream_config.timestamping.uncapped,
            default_config.default_stream_config.timestamping.uncapped
        );
        assert_eq!(
            decoded.config.default_stream_config.delete_on_empty.min_age,
            default_config.default_stream_config.delete_on_empty.min_age
        );
        assert_eq!(decoded.created_at, serde_value.created_at);
        assert_eq!(decoded.deleted_at, serde_value.deleted_at);
    }

    #[test]
    fn basin_meta_deser_invalid_json() {
        let err = super::deser_value(Bytes::from_static(b"{")).unwrap_err();
        assert!(matches!(err, DeserializationError::JsonDeserialization(_)));
    }

    fn basin_name_prefix_strategy() -> impl Strategy<Value = BasinNamePrefix> {
        prop_oneof![
            Just(BasinNamePrefix::default()),
            "[a-z][a-z0-9-]{0,46}".prop_map(|s| BasinNamePrefix::from_str(&s).unwrap()),
        ]
    }

    #[test]
    fn basin_meta_range_start_after_before_prefix() {
        let prefix = BasinNamePrefix::from_str("staging-").unwrap();
        let start_after = BasinNameStartAfter::from_str("prod-api").unwrap();

        let range = super::ser_key_range(&prefix, &start_after);

        assert!(
            range.start < range.end,
            "range should be valid when start_after is before prefix range"
        );

        let staging_basin = BasinName::from_str("staging-api").unwrap();
        let staging_key = super::ser_key(&staging_basin);
        assert!(
            staging_key >= range.start && staging_key < range.end,
            "basins matching prefix should be in range"
        );

        let prod_basin = BasinName::from_str("prod-service").unwrap();
        let prod_key = super::ser_key(&prod_basin);
        assert!(
            prod_key < range.start,
            "basins before prefix should NOT be in range"
        );
    }

    proptest! {
        #[test]
        fn roundtrip_basin_meta_key(basin in basin_name_strategy()) {
            let bytes = super::ser_key(&basin);
            let decoded = super::deser_key(bytes).unwrap();
            prop_assert_eq!(basin.as_ref(), decoded.as_ref());
        }

        #[test]
        fn basin_meta_range_contains_prefixed_keys(
            prefix in basin_name_prefix_strategy(),
            basin in basin_name_strategy(),
        ) {
            let prefix_str = prefix.as_ref();
            let basin_str = basin.as_ref();
            let matches_prefix = prefix_str.is_empty() || basin_str.starts_with(prefix_str);

            let range = super::ser_key_range(&prefix, &BasinNameStartAfter::default());
            let key = super::ser_key(&basin);

            if matches_prefix {
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
            let key1 = super::ser_key(&basin1);
            let key2 = super::ser_key(&basin2);

            let basin_cmp = basin1.as_ref().cmp(basin2.as_ref());
            let key_cmp = key1.cmp(&key2);

            prop_assert_eq!(basin_cmp, key_cmp, "ordering should be preserved");
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
            let range = super::ser_key_range(&prefix, &start_after);

            let key1 = super::ser_key(&basin1);
            let key2 = super::ser_key(&basin2);

            let prefix_str = prefix.as_ref();
            let basin1_matches = prefix_str.is_empty() || basin1.as_ref().starts_with(prefix_str);
            let basin2_matches = prefix_str.is_empty() || basin2.as_ref().starts_with(prefix_str);

            prop_assert!(key1 < range.start, "cursor basin should be excluded (before range.start)");
            if basin2_matches && (basin1_matches || basin2.as_ref() > prefix_str) {
                prop_assert!(key2 >= range.start, "later basin matching prefix should be included (at or after range.start)");
            }
        }
    }
}
