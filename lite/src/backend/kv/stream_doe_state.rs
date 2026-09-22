use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{DeserializationError, KeyType, check_exact_size, timestamp::TimestampSecs};
use crate::stream_id::StreamId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Check {
    pub at: TimestampSecs,
    pub id: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Scheduled(Check),
    /// An observed record has no expiration. Only a trim can remove it.
    Parked,
}

pub fn ser_key(stream_id: StreamId) -> Bytes {
    super::ser_stream_id_key(KeyType::StreamDeleteOnEmptyState, stream_id)
}

pub fn deser_key(bytes: Bytes) -> Result<StreamId, DeserializationError> {
    super::deser_stream_id_key(KeyType::StreamDeleteOnEmptyState, bytes)
}

pub fn ser_value(state: State) -> Bytes {
    let mut buf = BytesMut::with_capacity(21);
    match state {
        State::Parked => buf.put_u8(0),
        State::Scheduled(Check { at, id }) => {
            buf.put_u8(1);
            buf.put_u32(at.as_u32());
            buf.put_u128(id);
        }
    }
    buf.freeze()
}

pub fn deser_value(mut bytes: Bytes) -> Result<State, DeserializationError> {
    super::check_min_size(&bytes, 1)?;
    match bytes.get_u8() {
        0 => {
            check_exact_size(&bytes, 0)?;
            Ok(State::Parked)
        }
        1 => {
            check_exact_size(&bytes, 20)?;
            Ok(State::Scheduled(Check {
                at: TimestampSecs::from_secs(bytes.get_u32()),
                id: bytes.get_u128(),
            }))
        }
        ordinal => Err(DeserializationError::InvalidOrdinal(ordinal)),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn roundtrip_state(at in any::<u32>(), id in any::<u128>(), stream in any::<[u8; StreamId::LEN]>()) {
            for state in [State::Parked, State::Scheduled(Check { at: TimestampSecs::from_secs(at), id })] {
                prop_assert_eq!(deser_value(ser_value(state)).unwrap(), state);
            }
            let key = ser_key(stream.into());
            prop_assert_eq!(deser_key(key.clone()).unwrap(), StreamId::from(stream));
            prop_assert_eq!(Bytes::from(super::super::Key::try_from(key.clone()).unwrap()), key);
        }
    }

    #[test]
    fn reject_truncated_or_unknown_state() {
        for bytes in [&[][..], &[0, 1], &[1], &[2]] {
            assert!(deser_value(Bytes::copy_from_slice(bytes)).is_err());
        }
    }
}
