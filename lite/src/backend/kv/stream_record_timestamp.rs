use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::record::StreamPosition;

use super::{DeserializationError, KeyType, check_exact_size};
use crate::backend::stream_id::StreamId;

const KEY_LEN: usize = 1 + StreamId::LEN + 8 + 8;

pub fn ser_key(stream_id: StreamId, pos: StreamPosition) -> Bytes {
    let mut buf = BytesMut::with_capacity(KEY_LEN);
    buf.put_u8(KeyType::StreamRecordTimestamp.ordinal());
    buf.put_slice(stream_id.as_bytes());
    buf.put_u64(pos.timestamp);
    buf.put_u64(pos.seq_num);
    debug_assert_eq!(buf.len(), KEY_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_key(mut bytes: Bytes) -> Result<(StreamId, StreamPosition), DeserializationError> {
    check_exact_size(&bytes, KEY_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::StreamRecordTimestamp.ordinal() {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let mut stream_id_bytes = [0u8; StreamId::LEN];
    bytes.copy_to_slice(&mut stream_id_bytes);
    let timestamp = bytes.get_u64();
    let seq_num = bytes.get_u64();
    Ok((
        stream_id_bytes.into(),
        StreamPosition { seq_num, timestamp },
    ))
}

pub fn ser_value() -> Bytes {
    Bytes::new()
}

pub fn deser_value(bytes: Bytes) -> Result<(), DeserializationError> {
    check_exact_size(&bytes, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use s2_common::record::{SeqNum, StreamPosition, Timestamp};

    use crate::backend::stream_id::StreamId;

    #[test]
    fn roundtrip_stream_record_timestamp_value() {
        let bytes = super::ser_value();
        super::deser_value(bytes).unwrap();
    }

    proptest! {
        #[test]
        fn roundtrip_stream_record_timestamp_key(
            stream_id_bytes in any::<[u8; StreamId::LEN]>(),
            timestamp in any::<Timestamp>(),
            seq_num in any::<SeqNum>(),
        ) {
            let stream_id = StreamId::from(stream_id_bytes);
            let key_bytes = super::ser_key(stream_id, StreamPosition { seq_num, timestamp });
            let (decoded_stream_id, decoded_pos) =
                super::deser_key(key_bytes).unwrap();
            prop_assert_eq!(stream_id, decoded_stream_id);
            prop_assert_eq!(timestamp, decoded_pos.timestamp);
            prop_assert_eq!(seq_num, decoded_pos.seq_num);
        }
    }
}
