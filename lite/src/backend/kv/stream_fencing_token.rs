use std::str::FromStr;

use bytes::{BufMut, Bytes, BytesMut};
use s2_common::record::FencingToken;

use super::{DeserializationError, KeyType, invalid_value_err};
use crate::stream_id::StreamId;

pub fn ser_key(stream_id: StreamId) -> Bytes {
    super::ser_stream_id_key(KeyType::StreamFencingToken, stream_id)
}

#[allow(dead_code)]
pub fn deser_key(bytes: Bytes) -> Result<StreamId, DeserializationError> {
    super::deser_stream_id_key(KeyType::StreamFencingToken, bytes)
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

    use crate::{backend::kv::DeserializationError, stream_id::StreamId};

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
