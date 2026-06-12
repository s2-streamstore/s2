use std::num::NonZeroU8;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use s2_common::record::{
    CommandOp, CommandPayloadError, CommandRecord, EnvelopeRecord, Header, HeaderValidationError,
    RecordPartsError,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoredRecordDecodeError {
    #[error("truncated: {0}")]
    Truncated(&'static str),
    #[error("invalid value [{0}]: {1}")]
    InvalidValue(&'static str, &'static str),
}

pub(crate) trait WireEncode {
    fn to_bytes(&self) -> Bytes {
        let expected_size = self.encoded_size();
        let mut buf = BytesMut::with_capacity(expected_size);
        self.encode_into(&mut buf);
        assert_eq!(buf.len(), expected_size, "no reallocation");
        buf.freeze()
    }

    fn encoded_size(&self) -> usize;

    fn encode_into(&self, buf: &mut impl BufMut);
}

const COMMAND_ORDINAL_FENCE: u8 = 0;
const COMMAND_ORDINAL_TRIM: u8 = 1;

fn command_op_ordinal(op: CommandOp) -> u8 {
    match op {
        CommandOp::Fence => COMMAND_ORDINAL_FENCE,
        CommandOp::Trim => COMMAND_ORDINAL_TRIM,
    }
}

fn command_op_from_ordinal(ordinal: u8) -> Option<CommandOp> {
    match ordinal {
        COMMAND_ORDINAL_FENCE => Some(CommandOp::Fence),
        COMMAND_ORDINAL_TRIM => Some(CommandOp::Trim),
        _ => None,
    }
}

impl From<CommandPayloadError> for StoredRecordDecodeError {
    fn from(e: CommandPayloadError) -> Self {
        match e {
            CommandPayloadError::InvalidUtf8(_) => StoredRecordDecodeError::InvalidValue(
                "CommandPayload",
                "fencing token not valid utf8",
            ),
            CommandPayloadError::FencingTokenTooLong(_) => {
                StoredRecordDecodeError::InvalidValue("CommandPayload", "fencing token too long")
            }
            CommandPayloadError::TrimPointSize(_) => {
                StoredRecordDecodeError::InvalidValue("CommandPayload", "trim point size")
            }
        }
    }
}

impl WireEncode for CommandRecord {
    fn encoded_size(&self) -> usize {
        1 + match self {
            CommandRecord::Fence(token) => token.len(),
            CommandRecord::Trim(trim_point) => size_of_val(trim_point),
        }
    }

    fn encode_into(&self, buf: &mut impl BufMut) {
        buf.put_u8(command_op_ordinal(self.op()));
        match self {
            CommandRecord::Fence(token) => {
                buf.put_slice(token.as_bytes());
            }
            CommandRecord::Trim(trim_point) => {
                buf.put_u64(*trim_point);
            }
        }
    }
}

pub(super) fn decode_command_record(
    record: &[u8],
) -> Result<CommandRecord, StoredRecordDecodeError> {
    if record.is_empty() {
        return Err(StoredRecordDecodeError::Truncated("CommandOrdinal"));
    }
    let op = command_op_from_ordinal(record[0]).ok_or(StoredRecordDecodeError::InvalidValue(
        "CommandOrdinal",
        "unknown",
    ))?;
    CommandRecord::try_from_parts(op, &record[1..]).map_err(Into::into)
}

const EMPTY_HEADER_FLAG: HeaderFlag = HeaderFlag {
    num_headers_length_bytes: 0,
    name_length_bytes: NonZeroU8::new(1).unwrap(),
    value_length_bytes: NonZeroU8::new(1).unwrap(),
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct HeaderFlag {
    num_headers_length_bytes: u8,
    name_length_bytes: NonZeroU8,
    value_length_bytes: NonZeroU8,
}

impl From<HeaderFlag> for u8 {
    fn from(value: HeaderFlag) -> Self {
        (value.num_headers_length_bytes << 4)
            | ((value.name_length_bytes.get() - 1) << 2)
            | (value.value_length_bytes.get() - 1)
    }
}

impl TryFrom<u8> for HeaderFlag {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (value & (0b11u8 << 6)) != 0u8 {
            return Err("reserved bit set");
        }
        Ok(Self {
            num_headers_length_bytes: (0b110000 & value) >> 4,
            name_length_bytes: NonZeroU8::new(((0b1100 & value) >> 2) + 1).unwrap(),
            value_length_bytes: NonZeroU8::new((0b11 & value) + 1).unwrap(),
        })
    }
}

const EMPTY_HEADERS_ENCODING_INFO: EncodingInfo = EncodingInfo {
    headers_total_bytes: 0,
    flag: EMPTY_HEADER_FLAG,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct EncodingInfo {
    headers_total_bytes: usize,
    flag: HeaderFlag,
}

impl EncodingInfo {
    fn for_record(record: &EnvelopeRecord) -> Self {
        Self::from_header_summary(
            record.headers().len(),
            record.headers_total_bytes(),
            record.header_name_length_width_bytes(),
            record.header_value_length_width_bytes(),
        )
        .expect("envelope record headers should be validated")
    }

    fn from_header_summary(
        header_count: usize,
        headers_total_bytes: usize,
        name_length_width_bytes: usize,
        value_length_width_bytes: usize,
    ) -> Result<Self, HeaderValidationError> {
        fn size_bytes_header_count(count: u64) -> Result<u8, HeaderValidationError> {
            let size = 8 - count.leading_zeros() / 8;
            if size <= 3 {
                Ok(size as u8)
            } else {
                Err(HeaderValidationError::TooMany)
            }
        }

        fn header_part_width(width: usize) -> Result<NonZeroU8, HeaderValidationError> {
            let width = u8::try_from(width).map_err(|_| HeaderValidationError::TooLong)?;
            if (1..=4).contains(&width) {
                Ok(NonZeroU8::new(width).expect("header part width should be non-zero"))
            } else {
                Err(HeaderValidationError::TooLong)
            }
        }

        if header_count == 0 {
            return Ok(EMPTY_HEADERS_ENCODING_INFO);
        }

        let num_headers_length_bytes = size_bytes_header_count(header_count as u64)?;
        let name_length_bytes = header_part_width(name_length_width_bytes)?;
        let value_length_bytes = header_part_width(value_length_width_bytes)?;

        Ok(Self {
            headers_total_bytes,
            flag: HeaderFlag {
                num_headers_length_bytes,
                name_length_bytes,
                value_length_bytes,
            },
        })
    }
}

impl WireEncode for EnvelopeRecord {
    fn encoded_size(&self) -> usize {
        let encoding_info = EncodingInfo::for_record(self);
        1 + encoding_info.flag.num_headers_length_bytes as usize
            + self.headers().len()
                * (encoding_info.flag.name_length_bytes.get() as usize
                    + encoding_info.flag.value_length_bytes.get() as usize)
            + encoding_info.headers_total_bytes
            + self.body().len()
    }

    fn encode_into(&self, buf: &mut impl BufMut) {
        let encoding_info = EncodingInfo::for_record(self);
        buf.put_u8(encoding_info.flag.into());
        buf.put_uint(
            self.headers().len() as u64,
            encoding_info.flag.num_headers_length_bytes as usize,
        );
        for Header { name, value } in self.headers() {
            buf.put_uint(
                name.len() as u64,
                encoding_info.flag.name_length_bytes.get() as usize,
            );
            buf.put_slice(name);
            buf.put_uint(
                value.len() as u64,
                encoding_info.flag.value_length_bytes.get() as usize,
            );
            buf.put_slice(value);
        }
        buf.put_slice(self.body());
    }
}

pub(super) fn decode_envelope_record(
    mut buf: Bytes,
) -> Result<EnvelopeRecord, StoredRecordDecodeError> {
    if buf.is_empty() {
        return Err(StoredRecordDecodeError::InvalidValue(
            "HeaderFlag",
            "missing",
        ));
    }

    let flag: HeaderFlag = buf
        .get_u8()
        .try_into()
        .map_err(|info| StoredRecordDecodeError::InvalidValue("HeaderFlag", info))?;
    if flag.num_headers_length_bytes == 0 {
        return EnvelopeRecord::try_from_parts(vec![], buf).map_err(record_parts_decode_error);
    }

    let num_headers = buf
        .try_get_uint(flag.num_headers_length_bytes as usize)
        .map_err(|_| StoredRecordDecodeError::Truncated("NumHeaders"))?;
    let num_headers = usize::try_from(num_headers)
        .map_err(|_| StoredRecordDecodeError::InvalidValue("NumHeaders", "too many"))?;

    let mut headers: Vec<Header> = Vec::with_capacity(num_headers);
    for _ in 0..num_headers {
        let name_len = buf
            .try_get_uint(flag.name_length_bytes.get() as usize)
            .map_err(|_| StoredRecordDecodeError::Truncated("HeaderNameLen"))?
            as usize;
        if name_len == 0 {
            return Err(StoredRecordDecodeError::InvalidValue("HeaderName", "empty"));
        }
        if buf.remaining() < name_len {
            return Err(StoredRecordDecodeError::Truncated("HeaderName"));
        }
        let name = buf.split_to(name_len);

        let value_len = buf
            .try_get_uint(flag.value_length_bytes.get() as usize)
            .map_err(|_| StoredRecordDecodeError::Truncated("HeaderValueLen"))?
            as usize;
        if buf.remaining() < value_len {
            return Err(StoredRecordDecodeError::Truncated("HeaderValue"));
        }
        let value = buf.split_to(value_len);

        headers.push(Header { name, value })
    }

    EnvelopeRecord::try_from_parts(headers, buf).map_err(record_parts_decode_error)
}

fn record_parts_decode_error(error: RecordPartsError) -> StoredRecordDecodeError {
    match error {
        RecordPartsError::Header(HeaderValidationError::NameEmpty) => {
            StoredRecordDecodeError::InvalidValue("HeaderName", "empty")
        }
        RecordPartsError::Header(HeaderValidationError::TooMany) => {
            StoredRecordDecodeError::InvalidValue("NumHeaders", "too many")
        }
        RecordPartsError::Header(HeaderValidationError::TooLong) => {
            StoredRecordDecodeError::InvalidValue("Header", "too long")
        }
        RecordPartsError::UnknownCommand | RecordPartsError::CommandPayload(_, _) => {
            StoredRecordDecodeError::InvalidValue("EnvelopeRecord", "unexpected command record")
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, Bytes, BytesMut};
    use rstest::rstest;
    use s2_common::record::{FencingToken, FencingTokenTooLongError, SeqNum};

    use super::*;

    fn roundtrip_command(cmd: CommandRecord, expected_len: usize) {
        assert_eq!(cmd.encoded_size(), expected_len);
        let encoded = cmd.to_bytes();
        assert_eq!(encoded.len(), expected_len);
        assert_eq!(decode_command_record(encoded.as_ref()), Ok(cmd));
    }

    #[rstest]
    #[case::empty("")]
    #[case::arbit("arbitrary")]
    #[case::full("0123456789012345")]
    fn command_fence_roundtrip(#[case] token: &str) {
        let cmd = CommandRecord::Fence(token.parse::<FencingToken>().unwrap());
        roundtrip_command(cmd, 1 + token.len());
    }

    #[rstest]
    #[case::zero(0)]
    #[case::large(SeqNum::MAX)]
    fn command_trim_roundtrip(#[case] trim_point: SeqNum) {
        roundtrip_command(CommandRecord::Trim(trim_point), 1 + size_of::<SeqNum>());
    }

    #[test]
    fn decode_invalid_command() {
        let try_convert = |raw: &[u8]| decode_command_record(raw);
        assert_eq!(
            try_convert(&[]),
            Err(StoredRecordDecodeError::Truncated("CommandOrdinal"))
        );
        assert_eq!(
            try_convert(&[0xff]),
            Err(StoredRecordDecodeError::InvalidValue(
                "CommandOrdinal",
                "unknown"
            ))
        );
        assert_eq!(
            try_convert(&[command_op_ordinal(CommandOp::Fence), 0xff, 0xff]),
            Err(StoredRecordDecodeError::InvalidValue(
                "CommandPayload",
                "fencing token not valid utf8"
            ))
        );
        assert_eq!(
            try_convert(&[
                command_op_ordinal(CommandOp::Fence),
                b'0',
                b'1',
                b'2',
                b'3',
                b'4',
                b'5',
                b'6',
                b'7',
                b'8',
                b'9',
                b'0',
                b'1',
                b'2',
                b'3',
                b'4',
                b'5',
                b'6',
                b'7',
                b'8',
                b'9',
                b'0',
                b'1',
                b'2',
                b'3',
                b'4',
                b'5',
                b'6',
                b'7',
                b'8',
                b'9',
                b'0',
                b'1',
                b'2',
                b'3',
                b'4',
                b'5',
                b'6',
                b'7',
                b'8',
                b'9',
            ]),
            Err(CommandPayloadError::FencingTokenTooLong(FencingTokenTooLongError(40)).into())
        );
        assert_eq!(
            try_convert(&[command_op_ordinal(CommandOp::Trim), 0xff]),
            Err(CommandPayloadError::TrimPointSize(1).into())
        );
    }

    fn roundtrip_envelope_parts(headers: Vec<Header>, body: Bytes) {
        let encoded: Bytes = EnvelopeRecord::try_from_parts(headers.clone(), body.clone())
            .unwrap()
            .to_bytes();
        let decoded = decode_envelope_record(encoded).unwrap();
        assert_eq!(decoded.headers(), headers);
        assert_eq!(decoded.body(), &body);
    }

    #[test]
    fn envelope_framed_with_headers() {
        roundtrip_envelope_parts(
            vec![
                Header {
                    name: Bytes::from("key_1"),
                    value: Bytes::from("val_1"),
                },
                Header {
                    name: Bytes::from("key_2"),
                    value: Bytes::from("val_2"),
                },
                Header {
                    name: Bytes::from("key_3"),
                    value: Bytes::from("val_3"),
                },
                Header {
                    name: Bytes::from("key_4"),
                    value: Bytes::from("val_4"),
                },
            ],
            Bytes::from("hello"),
        );
    }

    #[test]
    fn envelope_framed_no_headers() {
        roundtrip_envelope_parts(vec![], Bytes::from("hello"));
    }

    #[test]
    fn envelope_decode_rejects_empty_header_name() {
        let mut encoded = BytesMut::new();
        encoded.put_u8(
            HeaderFlag {
                num_headers_length_bytes: 1,
                name_length_bytes: NonZeroU8::new(1).unwrap(),
                value_length_bytes: NonZeroU8::new(1).unwrap(),
            }
            .into(),
        );
        encoded.put_u8(1);
        encoded.put_u8(0);
        encoded.put_u8(5);
        encoded.put_slice(b"value");
        encoded.put_slice(b"body");

        assert_eq!(
            decode_envelope_record(encoded.freeze()),
            Err(StoredRecordDecodeError::InvalidValue("HeaderName", "empty"))
        );
    }

    #[test]
    fn envelope_framed_duplicate_keys() {
        roundtrip_envelope_parts(
            vec![
                Header {
                    name: Bytes::from("b"),
                    value: Bytes::from("val_1"),
                },
                Header {
                    name: Bytes::from("b"),
                    value: Bytes::from("val_2"),
                },
                Header {
                    name: Bytes::from("a"),
                    value: Bytes::from("val_3"),
                },
            ],
            Bytes::from("hello"),
        );
    }

    #[test]
    fn flag_ex1() {
        assert_eq!(
            Ok(HeaderFlag {
                num_headers_length_bytes: 2,
                name_length_bytes: NonZeroU8::new(1).unwrap(),
                value_length_bytes: NonZeroU8::new(1).unwrap(),
            }),
            0b00100000.try_into()
        );

        let u8_repr: u8 = HeaderFlag {
            num_headers_length_bytes: 2,
            name_length_bytes: NonZeroU8::new(1).unwrap(),
            value_length_bytes: NonZeroU8::new(1).unwrap(),
        }
        .into();
        assert_eq!(u8_repr, 0b00100000);
    }

    #[test]
    fn flag_ex2() {
        assert_eq!(
            Ok(HeaderFlag {
                num_headers_length_bytes: 1,
                name_length_bytes: NonZeroU8::new(1).unwrap(),
                value_length_bytes: NonZeroU8::new(1).unwrap(),
            }),
            0b00010000.try_into()
        );

        let u8_repr: u8 = HeaderFlag {
            num_headers_length_bytes: 1,
            name_length_bytes: NonZeroU8::new(1).unwrap(),
            value_length_bytes: NonZeroU8::new(1).unwrap(),
        }
        .into();
        assert_eq!(u8_repr, 0b00010000);
    }

    #[test]
    fn empty_envelope_size() {
        assert_eq!(
            1,
            EnvelopeRecord::try_from_parts(vec![], Bytes::new())
                .unwrap()
                .to_bytes()
                .len()
        );
    }

    #[test]
    fn truncated_envelope_returns_error() {
        let record = EnvelopeRecord::try_from_parts(
            vec![Header {
                name: Bytes::from("key"),
                value: Bytes::from("value"),
            }],
            Bytes::new(),
        )
        .unwrap();
        let encoded = record.to_bytes();

        for len in 1..encoded.len() {
            let truncated = encoded.slice(..len);
            assert!(
                matches!(
                    decode_envelope_record(truncated),
                    Err(StoredRecordDecodeError::Truncated(_))
                ),
                "expected Truncated error for len {len}"
            );
        }
    }
}
