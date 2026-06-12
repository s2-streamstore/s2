use std::str::FromStr;

use bytes::{BufMut, Bytes, BytesMut};
use s2_common::{basin::BasinName, stream::StreamNameStartAfter};

use super::{DeserializationError, KeyType, invalid_value_err};

pub fn ser_key(basin: &BasinName) -> Bytes {
    super::ser_basin_name_key(KeyType::BasinDeletionPending, basin)
}

pub fn deser_key(bytes: Bytes) -> Result<BasinName, DeserializationError> {
    super::deser_basin_name_key(KeyType::BasinDeletionPending, bytes)
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
    use s2_common::stream::StreamNameStartAfter;

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
