use std::{ops::Range, time::Duration};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;

use super::{DeserializationError, KeyType, check_exact_size, timestamp::TimestampSecs};
use crate::backend::stream_id::StreamId;

const KEY_LEN: usize = 1 + 4 + StreamId::LEN;
const VALUE_LEN_V1: usize = 8;
const VALUE_LEN_V2: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDoeDeadlineValue {
    pub min_age: Duration,
    pub doe_config_epoch: u64,
}

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

pub fn ser_value(value: StreamDoeDeadlineValue) -> Bytes {
    let mut buf = BytesMut::with_capacity(VALUE_LEN_V2);
    buf.put_u64(value.min_age.as_secs());
    buf.put_u64(value.doe_config_epoch);
    debug_assert_eq!(buf.len(), VALUE_LEN_V2, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_value(mut bytes: Bytes) -> Result<StreamDoeDeadlineValue, DeserializationError> {
    let len = bytes.remaining();
    match len {
        VALUE_LEN_V1 => Ok(StreamDoeDeadlineValue {
            min_age: Duration::from_secs(bytes.get_u64()),
            doe_config_epoch: 0,
        }),
        VALUE_LEN_V2 => Ok(StreamDoeDeadlineValue {
            min_age: Duration::from_secs(bytes.get_u64()),
            doe_config_epoch: bytes.get_u64(),
        }),
        _ => {
            check_exact_size(&bytes, VALUE_LEN_V2)?;
            unreachable!("size already checked")
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
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
        let value = stream_doe_deadline::StreamDoeDeadlineValue {
            min_age: std::time::Duration::from_secs(123),
            doe_config_epoch: 42,
        };
        let bytes = stream_doe_deadline::ser_value(value);
        let decoded = stream_doe_deadline::deser_value(bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn deser_legacy_stream_doe_deadline_value_defaults_epoch() {
        let mut buf = BytesMut::with_capacity(8);
        buf.put_u64(321);
        let decoded = stream_doe_deadline::deser_value(buf.freeze()).unwrap();
        assert_eq!(decoded.min_age, std::time::Duration::from_secs(321));
        assert_eq!(decoded.doe_config_epoch, 0);
    }
}
