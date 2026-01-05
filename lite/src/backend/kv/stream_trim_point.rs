use std::ops::RangeTo;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::record::SeqNum;

use super::{DeserializationError, KeyType, check_exact_size};
use crate::backend::stream_id::StreamId;

const KEY_LEN: usize = 1 + StreamId::LEN;
const VALUE_LEN: usize = 8;

pub fn ser_key(stream_id: StreamId) -> Bytes {
    let mut buf = BytesMut::with_capacity(KEY_LEN);
    buf.put_u8(KeyType::StreamTrimPoint.ordinal());
    buf.put_slice(stream_id.as_bytes());
    debug_assert_eq!(buf.len(), KEY_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_key(mut bytes: Bytes) -> Result<StreamId, DeserializationError> {
    check_exact_size(&bytes, KEY_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::StreamTrimPoint.ordinal() {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let mut stream_id_bytes = [0u8; StreamId::LEN];
    bytes.copy_to_slice(&mut stream_id_bytes);
    Ok(stream_id_bytes.into())
}

pub fn ser_value(trim_point: RangeTo<SeqNum>) -> Bytes {
    let mut buf = BytesMut::with_capacity(VALUE_LEN);
    buf.put_u64(trim_point.end);
    debug_assert_eq!(buf.len(), VALUE_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_value(mut bytes: Bytes) -> Result<RangeTo<SeqNum>, DeserializationError> {
    check_exact_size(&bytes, VALUE_LEN)?;
    Ok(..bytes.get_u64())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use s2_common::record::SeqNum;

    use crate::backend::stream_id::StreamId;

    proptest! {
        #[test]
        fn roundtrip_stream_trim_point_key(stream_id_bytes in any::<[u8; StreamId::LEN]>()) {
            let stream_id = StreamId::from(stream_id_bytes);
            let bytes = super::ser_key(stream_id);
            let decoded = super::deser_key(bytes).unwrap();
            prop_assert_eq!(stream_id, decoded);
        }

        #[test]
        fn roundtrip_stream_trim_point_value(seq_num in any::<SeqNum>()) {
            let bytes = super::ser_value(..seq_num);
            let decoded = super::deser_value(bytes).unwrap();
            prop_assert_eq!(..seq_num, decoded);
        }
    }
}
