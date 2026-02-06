use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::record::StreamPosition;

use super::{DeserializationError, KeyType, check_exact_size, timestamp::TimestampSecs};
use crate::backend::stream_id::StreamId;

const KEY_LEN: usize = 1 + StreamId::LEN;
const VALUE_LEN: usize = 8 + 8 + 4;

pub fn ser_key(stream_id: StreamId) -> Bytes {
    let mut buf = BytesMut::with_capacity(KEY_LEN);
    buf.put_u8(KeyType::StreamTailPosition.ordinal());
    buf.put_slice(stream_id.as_bytes());
    debug_assert_eq!(buf.len(), KEY_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_key(mut bytes: Bytes) -> Result<StreamId, DeserializationError> {
    check_exact_size(&bytes, KEY_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::StreamTailPosition.ordinal() {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let mut stream_id_bytes = [0u8; StreamId::LEN];
    bytes.copy_to_slice(&mut stream_id_bytes);
    Ok(stream_id_bytes.into())
}

pub fn ser_value(pos: StreamPosition, write_timestamp_secs: TimestampSecs) -> Bytes {
    let mut buf = BytesMut::with_capacity(VALUE_LEN);
    buf.put_u64(pos.seq_num);
    buf.put_u64(pos.timestamp);
    buf.put_u32(write_timestamp_secs.as_u32());
    debug_assert_eq!(buf.len(), VALUE_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_value(
    mut bytes: Bytes,
) -> Result<(StreamPosition, TimestampSecs), DeserializationError> {
    check_exact_size(&bytes, VALUE_LEN)?;
    let seq_num = bytes.get_u64();
    let timestamp = bytes.get_u64();
    let write_timestamp_secs = TimestampSecs::from_secs(bytes.get_u32());
    Ok((StreamPosition { seq_num, timestamp }, write_timestamp_secs))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use proptest::prelude::*;
    use s2_common::record::{SeqNum, Timestamp};

    use crate::backend::{
        kv::{DeserializationError, timestamp::TimestampSecs},
        stream_id::StreamId,
    };

    #[test]
    fn stream_tail_position_value_requires_exact_size() {
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
            write_ts_secs in any::<u32>(),
        ) {
            let pos = s2_common::record::StreamPosition { seq_num, timestamp };
            let write_timestamp_secs = TimestampSecs::from_secs(write_ts_secs);
            let bytes = super::ser_value(pos, write_timestamp_secs);
            let decoded = super::deser_value(bytes).unwrap();
            prop_assert_eq!(pos, decoded.0);
            prop_assert_eq!(write_timestamp_secs, decoded.1);
        }
    }
}
