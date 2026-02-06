use std::{ops::Range, time::Duration};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;

use super::{DeserializationError, KeyType, check_exact_size, timestamp::TimestampSecs};
use crate::backend::stream_id::StreamId;

const KEY_LEN: usize = 1 + 4 + StreamId::LEN;
const VALUE_LEN: usize = 8;

pub fn ser_key(deadline: TimestampSecs, stream_id: StreamId) -> Bytes {
    let mut buf = BytesMut::with_capacity(KEY_LEN);
    buf.put_u8(KeyType::StreamDeleteOnEmptyDeadline.ordinal());
    buf.put_u32(deadline.as_u32());
    buf.put_slice(stream_id.as_bytes());
    debug_assert_eq!(buf.len(), KEY_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn expired_key_range(deadline: TimestampSecs) -> Range<Bytes> {
    let start = Bytes::from(vec![KeyType::StreamDeleteOnEmptyDeadline.ordinal()]);
    let end = ser_key_range_end(deadline);
    start..end
}

fn ser_key_range_end(deadline: TimestampSecs) -> Bytes {
    let max_stream_id = StreamId::from([u8::MAX; StreamId::LEN]);
    let end_key = ser_key(deadline, max_stream_id);
    super::increment_bytes(BytesMut::from(end_key.as_ref())).expect("non-empty")
}

pub fn deser_key(mut bytes: Bytes) -> Result<(TimestampSecs, StreamId), DeserializationError> {
    check_exact_size(&bytes, KEY_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::StreamDeleteOnEmptyDeadline.ordinal() {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let deadline_secs = bytes.get_u32();
    let mut stream_id_bytes = [0u8; StreamId::LEN];
    bytes.copy_to_slice(&mut stream_id_bytes);
    Ok((
        TimestampSecs::from_secs(deadline_secs),
        stream_id_bytes.into(),
    ))
}

pub fn ser_value(min_age: Duration) -> Bytes {
    let mut buf = BytesMut::with_capacity(VALUE_LEN);
    buf.put_u64(min_age.as_secs());
    debug_assert_eq!(buf.len(), VALUE_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_value(mut bytes: Bytes) -> Result<Duration, DeserializationError> {
    check_exact_size(&bytes, VALUE_LEN)?;
    Ok(Duration::from_secs(bytes.get_u64()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use proptest::prelude::*;

    use crate::backend::{
        kv::{stream_doe_deadline, timestamp::TimestampSecs},
        stream_id::StreamId,
    };

    proptest! {
        #[test]
        fn roundtrip_stream_doe_deadline_key(
            deadline_secs in any::<u32>(),
            stream_id_bytes in any::<[u8; StreamId::LEN]>(),
        ) {
            let deadline = TimestampSecs::from_secs(deadline_secs);
            let stream_id = StreamId::from(stream_id_bytes);
            let bytes = stream_doe_deadline::ser_key(deadline, stream_id);
            let (decoded_deadline, decoded_stream_id) = stream_doe_deadline::deser_key(bytes).unwrap();
            prop_assert_eq!(deadline, decoded_deadline);
            prop_assert_eq!(stream_id, decoded_stream_id);
        }
    }

    #[test]
    fn roundtrip_stream_doe_deadline_value() {
        let min_age = Duration::from_secs(123);
        let bytes = stream_doe_deadline::ser_value(min_age);
        let decoded = stream_doe_deadline::deser_value(bytes).unwrap();
        assert_eq!(min_age, decoded);
    }
}
