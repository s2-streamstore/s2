use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use s2_common::record::{Encodable, Metered, Record, StreamPosition};

use super::{DeserializationError, KeyType, check_exact_size, invalid_value_err};
use crate::backend::stream_id::StreamId;

const KEY_LEN: usize = 1 + StreamId::LEN + 8 + 8;

pub fn ser_key(stream_id: StreamId, pos: StreamPosition) -> Bytes {
    let mut buf = BytesMut::with_capacity(KEY_LEN);
    buf.put_u8(KeyType::StreamRecordData.ordinal());
    buf.put_slice(stream_id.as_bytes());
    buf.put_u64(pos.seq_num);
    buf.put_u64(pos.timestamp);
    debug_assert_eq!(buf.len(), KEY_LEN, "serialized length mismatch");
    buf.freeze()
}

pub fn deser_key(mut bytes: Bytes) -> Result<(StreamId, StreamPosition), DeserializationError> {
    check_exact_size(&bytes, KEY_LEN)?;
    let ordinal = bytes.get_u8();
    if ordinal != KeyType::StreamRecordData.ordinal() {
        return Err(DeserializationError::InvalidOrdinal(ordinal));
    }
    let mut stream_id_bytes = [0_u8; StreamId::LEN];
    bytes.copy_to_slice(&mut stream_id_bytes);
    let seq_num = bytes.get_u64();
    let timestamp = bytes.get_u64();
    Ok((
        stream_id_bytes.into(),
        StreamPosition { seq_num, timestamp },
    ))
}

pub fn ser_value(record: Metered<&Record>) -> Bytes {
    record.to_bytes()
}

pub fn deser_value(bytes: Bytes) -> Result<Metered<Record>, DeserializationError> {
    Metered::try_from(bytes).map_err(|e| invalid_value_err("record", e))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use proptest::prelude::*;
    use s2_common::record::{SeqNum, StreamPosition, Timestamp};

    use crate::backend::{kv::DeserializationError, stream_id::StreamId};

    #[test]
    fn stream_record_data_rejects_invalid_payload() {
        let err = super::deser_value(Bytes::from_static(&[0x00])).unwrap_err();
        assert!(matches!(
            err,
            DeserializationError::InvalidValue { name: "record", .. }
        ));
    }

    proptest! {
        #[test]
        fn roundtrip_stream_record_data_key(
            stream_id_bytes in any::<[u8; StreamId::LEN]>(),
            seq_num in any::<SeqNum>(),
            timestamp in any::<Timestamp>(),
        ) {
            let stream_id = StreamId::from(stream_id_bytes);
            let pos = StreamPosition { seq_num, timestamp };
            let key_bytes = super::ser_key(stream_id, pos);
            let (decoded_stream_id, decoded_pos) = super::deser_key(key_bytes).unwrap();
            prop_assert_eq!(stream_id, decoded_stream_id);
            prop_assert_eq!(pos, decoded_pos);
        }

        #[test]
        fn roundtrip_stream_record_data_value(
            header_name in prop::collection::vec(any::<u8>(), 1..20),
            header_value in prop::collection::vec(any::<u8>(), 0..50),
            body in prop::collection::vec(any::<u8>(), 0..200),
        ) {
            use s2_common::record::{Header, MeteredSize, Record};

            let header_name = Bytes::from(header_name);
            let header_value = Bytes::from(header_value);
            let headers = vec![Header {
                name: header_name,
                value: header_value,
            }];
            let body = Bytes::from(body);
            let expected_headers = headers.clone();
            let expected_body = body.clone();
            let record = Record::try_from_parts(headers, body).unwrap();
            let metered_record: s2_common::record::Metered<Record> = record.into();
            let original_size = metered_record.metered_size();

            let bytes = super::ser_value(metered_record.as_ref());
            let decoded = super::deser_value(bytes).unwrap();

            prop_assert_eq!(original_size, decoded.metered_size());
            let (decoded_headers, decoded_body) = decoded.into_inner().into_parts();
            prop_assert_eq!(decoded_headers, expected_headers);
            prop_assert_eq!(decoded_body, expected_body);
        }
    }
}
