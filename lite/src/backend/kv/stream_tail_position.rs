use bytes::{Buf, BufMut, Bytes, BytesMut};
use s2_common::record::StreamPosition;

use super::{DeserializationError, KeyType};
use crate::stream_id::StreamId;

const VALUE_LEN: usize = 8 + 8;
const LEGACY_VALUE_LEN: usize = 8 + 8 + 4;

pub fn ser_key(stream_id: StreamId) -> Bytes {
    super::ser_stream_id_key(KeyType::StreamTailPosition, stream_id)
}

pub fn deser_key(bytes: Bytes) -> Result<StreamId, DeserializationError> {
    super::deser_stream_id_key(KeyType::StreamTailPosition, bytes)
}

pub fn ser_value(tail: StreamPosition) -> Bytes {
    let mut buf = BytesMut::with_capacity(VALUE_LEN);
    buf.put_u64(tail.seq_num);
    buf.put_u64(tail.timestamp);
    debug_assert_eq!(buf.len(), VALUE_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_value(mut bytes: Bytes) -> Result<StreamPosition, DeserializationError> {
    match bytes.remaining() {
        VALUE_LEN | LEGACY_VALUE_LEN => {}
        actual => {
            return Err(DeserializationError::InvalidSize {
                expected: VALUE_LEN,
                actual,
            });
        }
    }
    let seq_num = bytes.get_u64();
    let timestamp = bytes.get_u64();
    Ok(StreamPosition { seq_num, timestamp })
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use proptest::prelude::*;
    use s2_common::record::{SeqNum, Timestamp};

    use crate::{backend::kv::DeserializationError, stream_id::StreamId};

    #[test]
    fn stream_tail_position_value_rejects_unsupported_size() {
        let err = super::deser_value(Bytes::from_static(&[0u8; 15])).unwrap_err();
        assert!(matches!(
            err,
            DeserializationError::InvalidSize {
                expected: super::VALUE_LEN,
                ..
            }
        ));
    }

    proptest! {
        #[test]
        fn roundtrip_stream_tail_position_key(stream_id_bytes in any::<[u8; StreamId::LEN]>()) {
            let stream_id = StreamId::from(stream_id_bytes);
            let bytes = super::ser_key(stream_id);
            let decoded = super::deser_key(bytes).unwrap();
            prop_assert_eq!(stream_id, decoded);
        }

        #[test]
        fn roundtrip_stream_tail_position_value(
            seq_num in any::<SeqNum>(),
            timestamp in any::<Timestamp>(),
        ) {
            let tail = s2_common::record::StreamPosition { seq_num, timestamp };
            let bytes = super::ser_value(tail);
            let decoded = super::deser_value(bytes).unwrap();
            prop_assert_eq!(tail, decoded);
        }
    }
}
