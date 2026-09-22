use std::{ops::Range, time::Duration};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{DeserializationError, KeyType, check_exact_size, timestamp::TimestampSecs};
use crate::stream_id::StreamId;

const LEGACY_KEY_LEN: usize = 1 + 4 + StreamId::LEN;
const KEY_LEN: usize = LEGACY_KEY_LEN + 16;
const VALUE_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::backend) struct Entry {
    pub deadline: TimestampSecs,
    pub min_age: Duration,
}

/// Give each scheduling operation its own key so cleanup cannot delete a later
/// schedule for the same stream and deadline, including after recreation.
pub fn new_key(deadline: TimestampSecs, stream_id: StreamId) -> Bytes {
    ser_key(deadline, stream_id, Some(rand::random()))
}

/// Serialize an existing key. Use `new_key` when scheduling a deadline.
pub fn ser_key(deadline: TimestampSecs, stream_id: StreamId, schedule_id: Option<u128>) -> Bytes {
    let key_len = if schedule_id.is_some() {
        KEY_LEN
    } else {
        LEGACY_KEY_LEN
    };
    let mut buf = BytesMut::with_capacity(key_len);
    buf.put_u8(KeyType::StreamDeleteOnEmptyDeadline as u8);
    buf.put_u32(deadline.as_u32());
    buf.put_slice(stream_id.as_bytes());
    if let Some(schedule_id) = schedule_id {
        buf.put_u128(schedule_id);
    }
    debug_assert_eq!(buf.len(), key_len, "serialized length mismatch");
    buf.freeze()
}

pub fn expired_key_range(deadline: TimestampSecs) -> Range<Bytes> {
    let start = Bytes::from(vec![KeyType::StreamDeleteOnEmptyDeadline as u8]);
    let end = ser_key_range_end(deadline);
    start..end
}

fn ser_key_range_end(deadline: TimestampSecs) -> Bytes {
    let mut prefix = BytesMut::with_capacity(1 + 4);
    prefix.put_u8(KeyType::StreamDeleteOnEmptyDeadline as u8);
    prefix.put_u32(deadline.as_u32());
    super::increment_bytes(prefix).expect("non-empty")
}

pub fn deser_key(
    mut bytes: Bytes,
) -> Result<(TimestampSecs, StreamId, Option<u128>), DeserializationError> {
    if bytes.len() != LEGACY_KEY_LEN {
        check_exact_size(&bytes, KEY_LEN)?;
    }
    let ordinal = bytes.get_u8();
    if ordinal != (KeyType::StreamDeleteOnEmptyDeadline as u8) {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let deadline_secs = bytes.get_u32();
    let mut stream_id_bytes = [0u8; StreamId::LEN];
    bytes.copy_to_slice(&mut stream_id_bytes);
    let schedule_id = bytes.has_remaining().then(|| bytes.get_u128());
    Ok((
        TimestampSecs::from_secs(deadline_secs),
        stream_id_bytes.into(),
        schedule_id,
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

    use crate::{
        backend::kv::{stream_doe_deadline, timestamp::TimestampSecs},
        stream_id::StreamId,
    };

    proptest! {
        #[test]
        fn roundtrip_stream_doe_deadline_key(
            deadline_secs in any::<u32>(),
            stream_id_bytes in any::<[u8; StreamId::LEN]>(),
            schedule_id in proptest::option::of(any::<u128>()),
        ) {
            let deadline = TimestampSecs::from_secs(deadline_secs);
            let stream_id = StreamId::from(stream_id_bytes);
            let bytes = stream_doe_deadline::ser_key(deadline, stream_id, schedule_id);
            let (decoded_deadline, decoded_stream_id, decoded_schedule_id) = stream_doe_deadline::deser_key(bytes.clone()).unwrap();
            prop_assert_eq!(deadline, decoded_deadline);
            prop_assert_eq!(stream_id, decoded_stream_id);
            prop_assert_eq!(schedule_id, decoded_schedule_id);
            let decoded = super::super::Key::try_from(bytes.clone()).unwrap();
            prop_assert_eq!(bytes, bytes::Bytes::from(decoded));
        }
    }

    #[test]
    fn expired_range_includes_all_schedules_at_deadline() {
        for deadline_secs in [0, 100, u32::MAX] {
            let deadline = TimestampSecs::from_secs(deadline_secs);
            let range = stream_doe_deadline::expired_key_range(deadline);
            for stream_id_bytes in [[0; StreamId::LEN], [u8::MAX; StreamId::LEN]] {
                let stream_id = StreamId::from(stream_id_bytes);
                for schedule_id in [None, Some(0), Some(u128::MAX)] {
                    let key = stream_doe_deadline::ser_key(deadline, stream_id, schedule_id);
                    assert!(range.contains(&key));
                    if let Some(next_secs) = deadline_secs.checked_add(1) {
                        let next_key = stream_doe_deadline::ser_key(
                            TimestampSecs::from_secs(next_secs),
                            stream_id,
                            schedule_id,
                        );
                        assert!(!range.contains(&next_key));
                    }
                }
            }
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
