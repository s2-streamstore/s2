use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{DeserializationError, KeyType, check_exact_size};
use crate::{backend::timestamp::TimestampSecs, stream_id::StreamId};

const LEGACY_KEY_LEN: usize = 1 + 4 + StreamId::LEN;
const KEY_LEN: usize = LEGACY_KEY_LEN + 16;
/// Legacy keys are retained only for decoding and migration. New schedules use
/// `stream_doe_state` and `stream_doe_check`.
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::{
        backend::{kv::stream_doe_deadline, timestamp::TimestampSecs},
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
}
