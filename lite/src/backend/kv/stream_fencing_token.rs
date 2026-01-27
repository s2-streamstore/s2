use std::str::FromStr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::record::FencingToken;

use super::{DeserializationError, KeyType, check_exact_size, invalid_value_err};
use crate::backend::stream_id::StreamId;

const KEY_LEN: usize = 1 + StreamId::LEN;

pub fn ser_key(stream_id: StreamId) -> Bytes {
    let mut buf = BytesMut::with_capacity(KEY_LEN);
    buf.put_u8(KeyType::StreamFencingToken.ordinal());
    buf.put_slice(stream_id.as_bytes());
    debug_assert_eq!(buf.len(), KEY_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_key(mut bytes: Bytes) -> Result<StreamId, DeserializationError> {
    check_exact_size(&bytes, KEY_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::StreamFencingToken.ordinal() {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let mut stream_id_bytes = [0_u8; StreamId::LEN];
    bytes.copy_to_slice(&mut stream_id_bytes);
    Ok(stream_id_bytes.into())
}

pub fn ser_value(token: &FencingToken) -> Bytes {
    let token_bytes = token.as_bytes();
    let capacity = token_bytes.len();
    let mut buf = BytesMut::with_capacity(capacity);
    buf.put_slice(token_bytes);
    debug_assert_eq!(buf.len(), capacity, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_value(bytes: Bytes) -> Result<FencingToken, DeserializationError> {
    let token_str =
        std::str::from_utf8(&bytes).map_err(|e| invalid_value_err("fencing_token", e))?;
    FencingToken::from_str(token_str).map_err(|e| invalid_value_err("fencing_token", e))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bytes::Bytes;
    use proptest::prelude::*;
    use s2_common::record::FencingToken;

    use crate::backend::{kv::DeserializationError, stream_id::StreamId};

    #[test]
    fn stream_fencing_token_rejects_invalid_utf8() {
        let err = super::deser_value(Bytes::from_static(&[0xFF])).unwrap_err();
        assert!(matches!(
            err,
            DeserializationError::InvalidValue {
                name: "fencing_token",
                ..
            }
        ));
    }

    proptest! {
        #[test]
        fn roundtrip_stream_fencing_token_key(stream_id_bytes in any::<[u8; StreamId::LEN]>()) {
            let stream_id = StreamId::from(stream_id_bytes);
            let bytes = super::ser_key(stream_id);
            let decoded = super::deser_key(bytes).unwrap();
            prop_assert_eq!(stream_id, decoded);
        }

        #[test]
        fn roundtrip_stream_fencing_token_value(token_str in "[a-zA-Z0-9_-]{0,36}") {
            let token = FencingToken::from_str(&token_str).unwrap();
            let bytes = super::ser_value(&token);
            let decoded = super::deser_value(bytes).unwrap();
            prop_assert_eq!(token.as_ref(), decoded.as_ref());
        }
    }
}
