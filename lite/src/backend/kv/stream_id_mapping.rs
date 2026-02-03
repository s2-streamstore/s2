use std::str::FromStr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::{
    caps::{MIN_BASIN_NAME_LEN, MIN_STREAM_NAME_LEN},
    types::{basin::BasinName, stream::StreamName},
};

use super::{DeserializationError, KeyType, check_exact_size, check_min_size, invalid_value_err};
use crate::backend::stream_id::StreamId;

const KEY_LEN: usize = 1 + StreamId::LEN;
const FIELD_SEPARATOR: u8 = b'\0';

pub fn ser_key(stream_id: StreamId) -> Bytes {
    let mut buf = BytesMut::with_capacity(KEY_LEN);
    buf.put_u8(KeyType::StreamIdMapping.ordinal());
    buf.put_slice(stream_id.as_bytes());
    debug_assert_eq!(buf.len(), KEY_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_key(mut bytes: Bytes) -> Result<StreamId, DeserializationError> {
    check_exact_size(&bytes, KEY_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::StreamIdMapping.ordinal() {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let mut stream_id_bytes = [0u8; StreamId::LEN];
    bytes.copy_to_slice(&mut stream_id_bytes);
    Ok(stream_id_bytes.into())
}

pub fn ser_value(basin: &BasinName, stream: &StreamName) -> Bytes {
    let basin_bytes = basin.as_bytes();
    let stream_bytes = stream.as_bytes();
    let capacity = basin_bytes.len() + 1 + stream_bytes.len();
    let mut buf = BytesMut::with_capacity(capacity);
    buf.put_slice(basin_bytes);
    buf.put_u8(FIELD_SEPARATOR);
    buf.put_slice(stream_bytes);
    debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_value(bytes: Bytes) -> Result<(BasinName, StreamName), DeserializationError> {
    check_min_size(&bytes, MIN_BASIN_NAME_LEN + 1 + MIN_STREAM_NAME_LEN)?;
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use proptest::prelude::*;
    use s2_common::types::{basin::BasinName, stream::StreamName};

    use crate::backend::stream_id::StreamId;

    #[test]
    fn roundtrip_stream_id_mapping_value() {
        let basin = BasinName::from_str("test-basin").unwrap();
        let stream = StreamName::from_str("test-stream").unwrap();
        let bytes = super::ser_value(&basin, &stream);
        let (decoded_basin, decoded_stream) = super::deser_value(bytes).unwrap();
        assert_eq!(basin, decoded_basin);
        assert_eq!(stream, decoded_stream);
    }

    proptest! {
        #[test]
        fn roundtrip_stream_id_mapping_key(stream_id_bytes in any::<[u8; StreamId::LEN]>()) {
            let stream_id = StreamId::from(stream_id_bytes);
            let bytes = super::ser_key(stream_id);
            let decoded = super::deser_key(bytes).unwrap();
            prop_assert_eq!(stream_id, decoded);
        }
    }
}
