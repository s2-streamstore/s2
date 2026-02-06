use std::ops::RangeTo;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::record::NonZeroSeqNum;

use super::{DeserializationError, KeyType, check_exact_size, invalid_value_err};
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

pub fn ser_value(trim_point: RangeTo<NonZeroSeqNum>) -> Bytes {
    let mut buf = BytesMut::with_capacity(VALUE_LEN);
    buf.put_u64(trim_point.end.get());
    debug_assert_eq!(buf.len(), VALUE_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_value(mut bytes: Bytes) -> Result<RangeTo<NonZeroSeqNum>, DeserializationError> {
    check_exact_size(&bytes, VALUE_LEN)?;
    let seq_num = NonZeroSeqNum::new(bytes.get_u64())
        .ok_or_else(|| invalid_value_err("trim_point", "must be non-zero"))?;
    Ok(..seq_num)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use s2_common::record::NonZeroSeqNum;

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
        fn roundtrip_stream_trim_point_value(seq_num in any::<NonZeroSeqNum>()) {
            let bytes = super::ser_value(..seq_num);
            let decoded = super::deser_value(bytes).unwrap();
            prop_assert_eq!(..seq_num, decoded);
        }
    }
}
