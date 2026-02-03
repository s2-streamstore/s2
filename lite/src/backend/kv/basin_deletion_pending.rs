use std::str::FromStr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::{
    caps::MIN_BASIN_NAME_LEN,
    types::{basin::BasinName, stream::StreamNameStartAfter},
};

use super::{DeserializationError, KeyType, check_min_size, invalid_value_err};

pub fn ser_key(basin: &BasinName) -> Bytes {
    let basin_bytes = basin.as_bytes();
    let capacity = 1 + basin_bytes.len();
    let mut buf = BytesMut::with_capacity(capacity);
    buf.put_u8(KeyType::BasinDeletionPending.ordinal());
    buf.put_slice(basin_bytes);
    debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_key(mut bytes: Bytes) -> Result<BasinName, DeserializationError> {
    check_min_size(&bytes, 1 + MIN_BASIN_NAME_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::BasinDeletionPending.ordinal() {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let basin_str = std::str::from_utf8(&bytes).map_err(|e| invalid_value_err("basin", e))?;
    BasinName::from_str(basin_str).map_err(|e| invalid_value_err("basin", e))
}

pub fn ser_value(cursor: &StreamNameStartAfter) -> Bytes {
    let cursor_bytes = cursor.as_bytes();
    let capacity = cursor_bytes.len();
    let mut buf = BytesMut::with_capacity(capacity);
    buf.put_slice(cursor_bytes);
    debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_value(bytes: Bytes) -> Result<StreamNameStartAfter, DeserializationError> {
    let cursor_str = std::str::from_utf8(&bytes).map_err(|e| invalid_value_err("cursor", e))?;
    StreamNameStartAfter::from_str(cursor_str).map_err(|e| invalid_value_err("cursor", e))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use s2_common::types::stream::StreamNameStartAfter;

    use crate::backend::kv::proptest_strategies::{basin_name_strategy, stream_name_strategy};

    proptest! {
        #[test]
        fn roundtrip_basin_deletion_pending_key(basin in basin_name_strategy()) {
            let bytes = super::ser_key(&basin);
            let decoded = super::deser_key(bytes).unwrap();
            prop_assert_eq!(basin.as_ref(), decoded.as_ref());
        }

        #[test]
        fn roundtrip_basin_deletion_pending_value(stream in stream_name_strategy(),) {
            let cursor = StreamNameStartAfter::from(stream.clone());
            let bytes = super::ser_value(&cursor);
            let decoded = super::deser_value(bytes).unwrap();
            prop_assert_eq!(cursor.as_ref(), decoded.as_ref());
        }
    }
}
