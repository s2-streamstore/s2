mod batcher;
mod command;
mod envelope;
mod fencing;
mod metering;

pub use batcher::{RecordBatch, RecordBatcher};
use bytes::{Buf, BufMut, Bytes, BytesMut};
pub use command::CommandRecord;
use command::{CommandOp, CommandPayloadError};
use enum_ordinalize::Ordinalize;
pub use envelope::EnvelopeRecord;
use envelope::HeaderValidationError;
pub use fencing::{FencingToken, FencingTokenTooLongError, MAX_FENCING_TOKEN_LENGTH};
pub use metering::{Metered, MeteredSize};

use crate::deep_size::DeepSize;

pub type SeqNum = u64;
pub type NonZeroSeqNum = std::num::NonZeroU64;
pub type Timestamp = u64;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct StreamPosition {
    pub seq_num: SeqNum,
    pub timestamp: Timestamp,
}

impl StreamPosition {
    pub const MIN: StreamPosition = StreamPosition {
        seq_num: SeqNum::MIN,
        timestamp: Timestamp::MIN,
    };
}

impl std::fmt::Display for StreamPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} @ {}", self.seq_num, self.timestamp)
    }
}

impl DeepSize for StreamPosition {
    fn deep_size(&self) -> usize {
        self.seq_num.deep_size() + self.timestamp.deep_size()
    }
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum InternalRecordError {
    #[error("Truncated: {0}")]
    Truncated(&'static str),
    #[error("Invalid value [{0}]: {1}")]
    InvalidValue(&'static str, &'static str),
}

/// `impl Display` can be safely returned to the client without leaking internal details.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum PublicRecordError {
    #[error("Unknown command")]
    UnknownCommand,
    #[error("Invalid `{0}` command: {1}")]
    CommandPayload(CommandOp, CommandPayloadError),
    #[error("Invalid header: {0}")]
    Header(#[from] HeaderValidationError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: Bytes,
    pub value: Bytes,
}

impl DeepSize for Header {
    fn deep_size(&self) -> usize {
        self.name.len() + self.value.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Ordinalize)]
#[repr(u8)]
pub enum RecordType {
    Command = 1,
    Envelope = 2,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct MagicByte {
    pub record_type: RecordType,
    pub metered_size_varlen: u8,
}

/// Read bytes to u32 in big-endian order.
fn read_vint_u32_be(bytes: &[u8]) -> u32 {
    if bytes.len() > size_of::<u32>() || bytes.is_empty() {
        panic!("invalid variable int bytes = {} len", bytes.len())
    }
    let mut acc: u32 = 0;
    for &byte in bytes {
        acc = (acc << 8) | byte as u32;
    }
    acc
}

pub fn try_metered_size(record_bytes: &[u8]) -> Result<u32, &'static str> {
    let magic_byte_u8 = *record_bytes.first().ok_or("byte range is empty")?;
    let magic_byte = MagicByte::try_from(magic_byte_u8)?;
    Ok(read_vint_u32_be(
        record_bytes
            .get(1..1 + magic_byte.metered_size_varlen as usize)
            .ok_or("byte range doesn't include bytes for metered size")?,
    ))
}

impl MeteredSize for Record {
    fn metered_size(&self) -> usize {
        8 + (match self {
            Record::Command(command) => 2 + command.op().to_id().len() + command.payload().len(),
            Record::Envelope(envelope) => {
                (2 * envelope.headers().len())
                    + envelope.headers().deep_size()
                    + envelope.body().len()
            }
        })
    }
}

impl TryFrom<u8> for MagicByte {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let record_type =
            RecordType::from_ordinal(value & 0b111).ok_or("invalid record type ordinal")?;
        Ok(Self {
            record_type,
            metered_size_varlen: match (value >> 3) & 0b11 {
                0 => 1u8,
                1 => 2u8,
                2 => 3u8,
                _ => Err("invalid metered_size_varlen")?,
            },
        })
    }
}

impl From<MagicByte> for u8 {
    fn from(value: MagicByte) -> Self {
        ((value.metered_size_varlen - 1) << 3) | value.record_type as u8
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Record {
    Command(CommandRecord),
    Envelope(EnvelopeRecord),
}

impl DeepSize for Record {
    fn deep_size(&self) -> usize {
        match self {
            Self::Command(c) => c.deep_size(),
            Self::Envelope(e) => e.deep_size(),
        }
    }
}

impl Record {
    pub fn try_from_parts(headers: Vec<Header>, body: Bytes) -> Result<Self, PublicRecordError> {
        if headers.len() == 1 {
            let header = &headers[0];
            if header.name.is_empty() {
                let op = CommandOp::from_id(header.value.as_ref())
                    .ok_or(PublicRecordError::UnknownCommand)?;
                let command_record = CommandRecord::try_from_parts(op, body.as_ref())
                    .map_err(|e| PublicRecordError::CommandPayload(op, e))?;
                return Ok(Self::Command(command_record));
            }
        }
        let envelope = EnvelopeRecord::try_from_parts(headers, body)?;
        Ok(Self::Envelope(envelope))
    }

    pub fn sequenced(self, position: StreamPosition) -> SequencedRecord {
        SequencedRecord {
            position,
            record: self,
        }
    }

    pub fn into_parts(self) -> (Vec<Header>, Bytes) {
        match self {
            Record::Envelope(e) => e.into_parts(),
            Record::Command(c) => {
                let op = c.op();
                let header = Header {
                    name: Bytes::new(),
                    value: Bytes::from_static(op.to_id()),
                };
                (vec![header], c.payload())
            }
        }
    }
}

pub fn decode_if_command_record(
    record: &[u8],
) -> Result<Option<CommandRecord>, InternalRecordError> {
    if record.is_empty() {
        return Err(InternalRecordError::Truncated("MagicByte"));
    }
    let magic_byte = MagicByte::try_from(record[0])
        .map_err(|msg| InternalRecordError::InvalidValue("MagicByte", msg))?;
    match magic_byte.record_type {
        RecordType::Command => {
            let offset = 1 + magic_byte.metered_size_varlen as usize;
            if record.len() < offset {
                return Err(InternalRecordError::Truncated("MeteredSize"));
            }
            Ok(Some(CommandRecord::try_from(&record[offset..])?))
        }
        RecordType::Envelope => Ok(None),
    }
}

pub trait Encodable {
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

impl Encodable for MeteredRecord {
    fn encoded_size(&self) -> usize {
        1 + self.magic_byte().metered_size_varlen as usize
            + match &**self {
                Record::Command(r) => r.encoded_size(),
                Record::Envelope(r) => r.encoded_size(),
            }
    }

    fn encode_into(&self, buf: &mut impl BufMut) {
        let magic_byte = self.magic_byte();
        buf.put_u8(magic_byte.into());
        buf.put_uint(
            self.metered_size() as u64,
            magic_byte.metered_size_varlen as usize,
        );
        match &**self {
            Record::Command(r) => r.encode_into(buf),
            Record::Envelope(r) => r.encode_into(buf),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencedRecord {
    pub position: StreamPosition,
    pub record: Record,
}

impl MeteredSize for SequencedRecord {
    fn metered_size(&self) -> usize {
        self.record.metered_size()
    }
}

impl DeepSize for SequencedRecord {
    fn deep_size(&self) -> usize {
        self.position.deep_size() + self.record.deep_size()
    }
}

pub type MeteredRecord = Metered<Record>;

impl MeteredRecord {
    pub fn sequenced(self, position: StreamPosition) -> MeteredSequencedRecord {
        MeteredSequencedRecord {
            size: self.metered_size(),
            inner: self.inner.sequenced(position),
        }
    }

    fn magic_byte(&self) -> MagicByte {
        let metered_size = self.metered_size();
        let metered_size_varlen = 8 - (metered_size.leading_zeros() / 8) as u8;
        if metered_size_varlen > 3 {
            panic!("illegal metered size varlen {metered_size} for record")
        }
        let record_type = match self.inner {
            Record::Command(_) => RecordType::Command,
            Record::Envelope(_) => RecordType::Envelope,
        };
        MagicByte {
            record_type,
            metered_size_varlen,
        }
    }
}

impl TryFrom<Bytes> for MeteredRecord {
    type Error = InternalRecordError;

    fn try_from(mut buf: Bytes) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(InternalRecordError::Truncated("MagicByte"));
        }
        let magic_byte = MagicByte::try_from(buf.get_u8())
            .map_err(|msg| InternalRecordError::InvalidValue("MagicByte", msg))?;

        let metered_size = buf.get_uint(magic_byte.metered_size_varlen as usize) as usize;

        Ok(Self {
            size: metered_size,
            inner: match magic_byte.record_type {
                RecordType::Command => Record::Command(CommandRecord::try_from(buf.as_ref())?),
                RecordType::Envelope => Record::Envelope(EnvelopeRecord::try_from(buf)?),
            },
        })
    }
}

pub type MeteredSequencedRecord = Metered<SequencedRecord>;

pub type MeteredSequencedRecords = Metered<Vec<SequencedRecord>>;

impl MeteredSequencedRecord {
    pub fn into_parts(self) -> (StreamPosition, MeteredRecord) {
        (
            self.position,
            MeteredRecord {
                size: self.size,
                inner: self.inner.record,
            },
        )
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    fn bytes_strategy(allow_empty: bool) -> impl Strategy<Value = Bytes> {
        prop_oneof![
            prop::collection::vec(any::<u8>(), (if allow_empty { 0 } else { 1 })..10)
                .prop_map(Bytes::from),
            prop::collection::vec(any::<u8>(), 100..1000).prop_map(Bytes::from),
        ]
    }

    fn header_strategy() -> impl Strategy<Value = Header> {
        (bytes_strategy(false), bytes_strategy(true))
            .prop_map(|(name, value)| Header { name, value })
    }

    fn headers_strategy() -> impl Strategy<Value = Vec<Header>> {
        prop_oneof![
            prop::collection::vec(header_strategy(), 0..10),
            prop::collection::vec(header_strategy(), 200..300),
        ]
    }

    proptest!(
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn roundtrip_envelope(
            seq_num in any::<SeqNum>(),
            timestamp in any::<Timestamp>(),
            headers in headers_strategy(),
            body in bytes_strategy(true),
        ) {
            let record = Record::try_from_parts(headers, body).unwrap();
            let metered_record: MeteredRecord = record.clone().into();
            let as_bytes = metered_record.clone().to_bytes();
            let decoded_record = MeteredRecord::try_from(as_bytes).unwrap();
            prop_assert_eq!(&decoded_record, &metered_record);
            let sequenced = decoded_record.sequenced(StreamPosition { seq_num, timestamp });
            assert_eq!(sequenced.position, StreamPosition {seq_num, timestamp});
            assert_eq!(sequenced.record, record);
        }
    );

    proptest!(
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn roundtrip_metered(
            headers in headers_strategy(),
            body in bytes_strategy(true),
        ) {
            let record = Record::try_from_parts(headers.clone(), body.clone()).unwrap();
            let data_as_bytes = MeteredRecord::from(record.clone()).to_bytes();
            assert_eq!(record.metered_size(), try_metered_size(data_as_bytes.as_ref()).unwrap() as usize);
        }
    );

    #[test]
    fn empty_header_name_solo() {
        let headers = vec![Header {
            name: Bytes::new(),
            value: Bytes::from("hi"),
        }];
        let body = Bytes::from("hello");
        assert_eq!(
            Record::try_from_parts(headers, body),
            Err(PublicRecordError::UnknownCommand)
        );
    }

    #[test]
    fn empty_header_name_among_others() {
        let headers = vec![
            Header {
                name: Bytes::from("boku"),
                value: Bytes::from("hi"),
            },
            Header {
                name: Bytes::new(),
                value: Bytes::from("hi"),
            },
        ];
        let body = Bytes::from("hello");
        assert_eq!(
            Record::try_from_parts(headers, body),
            Err(PublicRecordError::Header(HeaderValidationError::NameEmpty))
        );
    }

    #[rstest]
    #[case::fence_empty(b"fence", b"")]
    #[case::fence_uuid(b"fence", b"my-special-uuid")]
    #[should_panic(expected = "FencingTokenTooLongError(49)")]
    #[case::fence_too_long(b"fence", b"toolongtoolongtoolongtoolongtoolongtoolongtoolong")]
    #[case::trim_0(b"trim", b"\x00\x00\x00\x00\x00\x00\x00\x00")]
    #[should_panic(expected = "TrimPointSize(0)")]
    #[case::trim_empty(b"trim", b"")]
    #[should_panic(expected = "TrimPointSize(9)")]
    #[case::trim_overflow(b"trim", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00")]
    fn command_records(#[case] op: &'static [u8], #[case] payload: &'static [u8]) {
        let headers = vec![Header {
            name: Bytes::new(),
            value: Bytes::from_static(op),
        }];
        let body = Bytes::from_static(payload);
        let record = Record::try_from_parts(headers.clone(), body.clone()).unwrap();
        let record_metered = record.metered_size();
        match &record {
            Record::Command(cmd) => {
                assert_eq!(cmd.op().to_id(), op);
                assert_eq!(cmd.payload().as_ref(), payload);
            }
            Record::Envelope(e) => panic!("Command expected, got Envelope: {e:?}"),
        }
        let sequenced_record = record.sequenced(StreamPosition {
            seq_num: 42,
            timestamp: 100_000,
        });
        let sequenced_metered = sequenced_record.metered_size();
        assert_eq!(record_metered, sequenced_metered);
        assert_eq!(
            sequenced_record.position,
            StreamPosition {
                seq_num: 42,
                timestamp: 100_000,
            }
        );
        assert_eq!(
            sequenced_record.record,
            Record::try_from_parts(headers, body).unwrap()
        );
    }

    #[rstest]
    #[case(0b0000_0010, MagicByte { record_type: RecordType::Envelope, metered_size_varlen: 1})]
    #[case(0b0001_0010, MagicByte { record_type: RecordType::Envelope, metered_size_varlen: 3})]
    #[case(0b0000_1001, MagicByte { record_type: RecordType::Command, metered_size_varlen: 2})]
    #[should_panic(expected = "invalid record type ordinal")]
    #[case(0b0000_1101, MagicByte { record_type: RecordType::Command, metered_size_varlen: 2})]
    fn magic_byte_parsing(#[case] as_u8: u8, #[case] magic_byte: MagicByte) {
        assert_eq!(MagicByte::try_from(as_u8).unwrap(), magic_byte);
        assert_eq!(u8::from(magic_byte), as_u8);
    }

    #[test]
    fn test_read_varint() {
        let data = [0u8, 0, 0, 1, 0, 0, 0];

        assert_eq!(read_vint_u32_be(&data[..4]), 1u32);
        assert_eq!(read_vint_u32_be(&data[2..5]), 2u32.pow(8));
        assert_eq!(read_vint_u32_be(&data[2..6]), 2u32.pow(16));
        assert_eq!(read_vint_u32_be(&data[3..]), 2u32.pow(24));
    }
}
