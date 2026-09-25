use std::ops::Range;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{DeserializationError, KeyType, check_exact_size, stream_doe_state::Check};
use crate::{backend::timestamp::TimestampSecs, stream_id::StreamId};

const KEY_LEN: usize = 1 + 4 + StreamId::LEN + 16;

pub fn ser_key(stream_id: StreamId, check: Check) -> Bytes {
    let mut buf = BytesMut::with_capacity(KEY_LEN);
    buf.put_u8(KeyType::StreamDeleteOnEmptyCheck as u8);
    buf.put_u32(check.at.as_u32());
    buf.put_slice(stream_id.as_bytes());
    buf.put_u128(check.id);
    buf.freeze()
}

pub fn deser_key(mut bytes: Bytes) -> Result<(StreamId, Check), DeserializationError> {
    check_exact_size(&bytes, KEY_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::StreamDeleteOnEmptyCheck as u8 {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let at = TimestampSecs::from_secs(bytes.get_u32());
    let mut stream_id = [0; StreamId::LEN];
    bytes.copy_to_slice(&mut stream_id);
    let id = bytes.get_u128();
    Ok((stream_id.into(), Check { at, id }))
}

pub fn due_key_range(now: TimestampSecs) -> Range<Bytes> {
    let start = Bytes::from_static(&[KeyType::StreamDeleteOnEmptyCheck as u8]);
    let mut end = BytesMut::with_capacity(5);
    end.put_u8(KeyType::StreamDeleteOnEmptyCheck as u8);
    end.put_u32(now.as_u32());
    start..super::increment_bytes(end).expect("non-empty")
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn roundtrip_check(at in any::<u32>(), id in any::<u128>(), stream in any::<[u8; StreamId::LEN]>()) {
            let check = Check { at: TimestampSecs::from_secs(at), id };
            let stream_id = StreamId::from(stream);
            let key = ser_key(stream_id, check);
            prop_assert_eq!(deser_key(key.clone()).unwrap(), (stream_id, check));
        }
    }

    #[test]
    fn due_range_includes_every_ticket_at_boundary() {
        for seconds in [0, 100, u32::MAX] {
            let at = TimestampSecs::from_secs(seconds);
            let range = due_key_range(at);
            for stream_id in [[0; StreamId::LEN], [u8::MAX; StreamId::LEN]].map(StreamId::from) {
                for id in [0, u128::MAX] {
                    assert!(range.contains(&ser_key(stream_id, Check { at, id })));
                    if let Some(next) = seconds.checked_add(1) {
                        assert!(!range.contains(&ser_key(
                            stream_id,
                            Check {
                                at: TimestampSecs::from_secs(next),
                                id
                            }
                        )));
                    }
                }
            }
        }
    }
}
