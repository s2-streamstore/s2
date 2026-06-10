use std::ops::RangeTo;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use s2_common::record::NonZeroSeqNum;

use super::{DeserializationError, KeyType, check_exact_size, invalid_value_err};
use crate::stream_id::StreamId;

const VALUE_LEN: usize = 8;

pub fn ser_key(stream_id: StreamId) -> Bytes {
    super::ser_stream_id_key(KeyType::StreamTrimPoint, stream_id)
}

pub fn deser_key(bytes: Bytes) -> Result<StreamId, DeserializationError> {
    super::deser_stream_id_key(KeyType::StreamTrimPoint, bytes)
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

    use crate::stream_id::StreamId;

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
