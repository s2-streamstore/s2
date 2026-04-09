mod batcher;
mod command;
mod encryption;
mod envelope;
mod fencing;
mod iterator;
mod metering;

pub use batcher::{RecordBatch, RecordBatcher};
use bytes::{Buf, BufMut, Bytes, BytesMut};
pub use command::CommandRecord;
use command::{CommandOp, CommandPayloadError};
pub use encryption::{
    EncryptedRecord, RecordDecryptionError, decrypt_stored_record, encrypt_record,
};
use enum_ordinalize::Ordinalize;
pub use envelope::EnvelopeRecord;
use envelope::HeaderValidationError;
pub use fencing::{FencingToken, FencingTokenTooLongError, MAX_FENCING_TOKEN_LENGTH};
pub use iterator::StoredRecordIterator;
pub use metering::{Metered, MeteredExt, MeteredSize};

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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordDecodeError {
    #[error("truncated: {0}")]
    Truncated(&'static str),
    #[error("invalid value [{0}]: {1}")]
    InvalidValue(&'static str, &'static str),
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum RecordPartsError {
    #[error("unknown command")]
    UnknownCommand,
    #[error("invalid `{0}` command: {1}")]
    CommandPayload(CommandOp, CommandPayloadError),
    #[error("invalid header: {0}")]
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
    EncryptedEnvelope = 3,
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
        match self {
            Self::Command(command) => command.metered_size(),
            Self::Envelope(envelope) => envelope.metered_size(),
        }
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
    pub fn try_from_parts(headers: Vec<Header>, body: Bytes) -> Result<Self, RecordPartsError> {
        if headers.len() == 1 {
            let header = &headers[0];
            if header.name.is_empty() {
                let op = CommandOp::from_id(header.value.as_ref())
                    .ok_or(RecordPartsError::UnknownCommand)?;
                let command_record = CommandRecord::try_from_parts(op, body.as_ref())
                    .map_err(|e| RecordPartsError::CommandPayload(op, e))?;
                return Ok(Self::Command(command_record));
            }
        }
        let envelope = EnvelopeRecord::try_from_parts(headers, body)?;
        Ok(Self::Envelope(envelope))
    }

    pub fn sequenced(self, position: StreamPosition) -> SequencedRecord {
        Sequenced::new(position, self)
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StoredRecord {
    Plaintext(Record),
    Encrypted {
        metered_size: usize,
        record: EncryptedRecord,
    },
}

impl StoredRecord {
    pub(crate) fn encrypted(record: EncryptedRecord, metered_size: usize) -> Self {
        Self::Encrypted {
            metered_size,
            record,
        }
    }

    fn record_type(&self) -> RecordType {
        match self {
            Self::Plaintext(Record::Command(_)) => RecordType::Command,
            Self::Plaintext(Record::Envelope(_)) => RecordType::Envelope,
            Self::Encrypted { .. } => RecordType::EncryptedEnvelope,
        }
    }

    fn encoded_body_size(&self) -> usize {
        match self {
            Self::Plaintext(Record::Command(record)) => record.encoded_size(),
            Self::Plaintext(Record::Envelope(record)) => record.encoded_size(),
            Self::Encrypted { record, .. } => record.encoded_size(),
        }
    }

    fn encode_body_into(&self, buf: &mut impl BufMut) {
        match self {
            Self::Plaintext(Record::Command(record)) => record.encode_into(buf),
            Self::Plaintext(Record::Envelope(record)) => record.encode_into(buf),
            Self::Encrypted { record, .. } => record.encode_into(buf),
        }
    }

    pub fn encryption_mode(&self) -> crate::encryption::EncryptionMode {
        match self {
            Self::Plaintext(_) => crate::encryption::EncryptionMode::Plain,
            Self::Encrypted { record, .. } => record.algorithm().into(),
        }
    }
}

impl DeepSize for StoredRecord {
    fn deep_size(&self) -> usize {
        match self {
            Self::Plaintext(record) => record.deep_size(),
            Self::Encrypted {
                metered_size,
                record,
            } => metered_size.deep_size() + record.deep_size(),
        }
    }
}

impl MeteredSize for StoredRecord {
    fn metered_size(&self) -> usize {
        match self {
            Self::Plaintext(record) => record.metered_size(),
            Self::Encrypted { metered_size, .. } => *metered_size,
        }
    }
}

impl From<Record> for StoredRecord {
    fn from(value: Record) -> Self {
        Self::Plaintext(value)
    }
}

impl From<Record> for Metered<StoredRecord> {
    fn from(value: Record) -> Self {
        Self::from(StoredRecord::from(value))
    }
}

pub fn decode_if_command_record(record: &[u8]) -> Result<Option<CommandRecord>, RecordDecodeError> {
    if record.is_empty() {
        return Err(RecordDecodeError::Truncated("MagicByte"));
    }
    let magic_byte = MagicByte::try_from(record[0])
        .map_err(|msg| RecordDecodeError::InvalidValue("MagicByte", msg))?;
    match magic_byte.record_type {
        RecordType::Command => {
            let offset = 1 + magic_byte.metered_size_varlen as usize;
            if record.len() < offset {
                return Err(RecordDecodeError::Truncated("MeteredSize"));
            }
            Ok(Some(CommandRecord::try_from(&record[offset..])?))
        }
        RecordType::Envelope | RecordType::EncryptedEnvelope => Ok(None),
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

impl Encodable for Metered<&StoredRecord> {
    fn encoded_size(&self) -> usize {
        1 + self.magic_byte().metered_size_varlen as usize + self.encoded_body_size()
    }

    fn encode_into(&self, buf: &mut impl BufMut) {
        let magic_byte = self.magic_byte();
        buf.put_u8(magic_byte.into());
        buf.put_uint(
            self.metered_size() as u64,
            magic_byte.metered_size_varlen as usize,
        );
        self.encode_body_into(buf);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sequenced<T> {
    position: StreamPosition,
    inner: T,
}

impl<T> Sequenced<T> {
    pub const fn new(position: StreamPosition, inner: T) -> Self {
        Self { position, inner }
    }

    pub const fn position(&self) -> &StreamPosition {
        &self.position
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn as_ref(&self) -> Sequenced<&T> {
        Sequenced::new(self.position, &self.inner)
    }

    pub fn parts(&self) -> (StreamPosition, &T) {
        (self.position, &self.inner)
    }

    pub fn into_parts(self) -> (StreamPosition, T) {
        (self.position, self.inner)
    }
}

pub type StoredSequencedBytes = Sequenced<Bytes>;
pub type SequencedRecord = Sequenced<Record>;
pub type StoredSequencedRecord = Sequenced<StoredRecord>;

impl<T> MeteredSize for Sequenced<T>
where
    T: MeteredSize,
{
    fn metered_size(&self) -> usize {
        self.inner.metered_size()
    }
}

impl<T> DeepSize for Sequenced<T>
where
    T: DeepSize,
{
    fn deep_size(&self) -> usize {
        self.position.deep_size() + self.inner.deep_size()
    }
}

impl<T> Metered<T>
where
    T: MeteredSize,
{
    pub fn sequenced(self, position: StreamPosition) -> Metered<Sequenced<T>> {
        Metered::with_size(
            self.metered_size(),
            Sequenced::new(position, self.into_inner()),
        )
    }
}

impl Metered<&StoredRecord> {
    fn magic_byte(&self) -> MagicByte {
        let metered_size = self.metered_size();
        let metered_size_varlen = 8 - (metered_size.leading_zeros() / 8) as u8;
        if metered_size_varlen > 3 {
            panic!("illegal metered size varlen {metered_size} for record")
        }
        MagicByte {
            record_type: self.record_type(),
            metered_size_varlen,
        }
    }
}

impl TryFrom<Bytes> for Metered<StoredRecord> {
    type Error = RecordDecodeError;

    fn try_from(mut buf: Bytes) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(RecordDecodeError::Truncated("MagicByte"));
        }
        let magic_byte = MagicByte::try_from(buf.get_u8())
            .map_err(|msg| RecordDecodeError::InvalidValue("MagicByte", msg))?;

        let metered_size =
            buf.try_get_uint(magic_byte.metered_size_varlen as usize)
                .map_err(|_| RecordDecodeError::Truncated("MeteredSize"))? as usize;

        Ok(Self::with_size(
            metered_size,
            match magic_byte.record_type {
                RecordType::Command => {
                    StoredRecord::Plaintext(Record::Command(CommandRecord::try_from(buf.as_ref())?))
                }
                RecordType::Envelope => {
                    StoredRecord::Plaintext(Record::Envelope(EnvelopeRecord::try_from(buf)?))
                }
                RecordType::EncryptedEnvelope => {
                    StoredRecord::encrypted(EncryptedRecord::try_from(buf)?, metered_size)
                }
            },
        ))
    }
}

impl TryFrom<Bytes> for Metered<Record> {
    type Error = RecordDecodeError;

    fn try_from(buf: Bytes) -> Result<Self, Self::Error> {
        let stored: Metered<StoredRecord> = buf.try_into()?;
        let size = stored.metered_size();
        match stored.into_inner() {
            StoredRecord::Plaintext(record) => Ok(record),
            StoredRecord::Encrypted { .. } => Err(RecordDecodeError::InvalidValue(
                "RecordType",
                "encrypted envelope requires decryption",
            )),
        }
        .map(|record| Metered::with_size(size, record))
    }
}

impl<T> Metered<Sequenced<T>> {
    pub fn parts(&self) -> (StreamPosition, Metered<&T>) {
        let size = self.metered_size();
        let (position, inner) = self.as_ref().into_inner().parts();
        (position, Metered::with_size(size, inner))
    }

    pub fn into_parts(self) -> (StreamPosition, Metered<T>) {
        let size = self.metered_size();
        let (position, inner) = self.into_inner().into_parts();
        (position, Metered::with_size(size, inner))
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    struct LegacyPlaintextFrame<'a> {
        record: &'a Record,
    }

    impl LegacyPlaintextFrame<'_> {
        fn magic_byte(&self) -> MagicByte {
            let metered_size = self.record.metered_size();
            let metered_size_varlen = 8 - (metered_size.leading_zeros() / 8) as u8;
            assert!(metered_size_varlen <= 3);

            MagicByte {
                record_type: match self.record {
                    Record::Command(_) => RecordType::Command,
                    Record::Envelope(_) => RecordType::Envelope,
                },
                metered_size_varlen,
            }
        }
    }

    impl Encodable for LegacyPlaintextFrame<'_> {
        fn encoded_size(&self) -> usize {
            let body_size = match self.record {
                Record::Command(record) => record.encoded_size(),
                Record::Envelope(record) => record.encoded_size(),
            };
            1 + self.magic_byte().metered_size_varlen as usize + body_size
        }

        fn encode_into(&self, buf: &mut impl BufMut) {
            let magic_byte = self.magic_byte();
            buf.put_u8(magic_byte.into());
            buf.put_uint(
                self.record.metered_size() as u64,
                magic_byte.metered_size_varlen as usize,
            );
            match self.record {
                Record::Command(record) => record.encode_into(buf),
                Record::Envelope(record) => record.encode_into(buf),
            }
        }
    }

    fn legacy_plaintext_bytes(record: &Record) -> Bytes {
        LegacyPlaintextFrame { record }.to_bytes()
    }

    fn semantic_metered_size(record: &Record) -> usize {
        let (headers, body) = record.clone().into_parts();
        8 + (2 * headers.len())
            + headers
                .iter()
                .map(|header| header.name.len() + header.value.len())
                .sum::<usize>()
            + body.len()
    }

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

    fn command_strategy() -> impl Strategy<Value = CommandRecord> {
        prop_oneof![
            proptest::string::string_regex(&format!("[ -~]{{0,{MAX_FENCING_TOKEN_LENGTH}}}"))
                .unwrap()
                .prop_map(|token| CommandRecord::Fence(token.parse().unwrap())),
            any::<SeqNum>().prop_map(CommandRecord::Trim),
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
            let metered_record: Metered<Record> = record.clone().into();
            let encoded_record = Metered::from(StoredRecord::from(record.clone()))
                .as_ref()
                .to_bytes();
            let legacy_record = legacy_plaintext_bytes(&record);
            prop_assert_eq!(encoded_record.as_ref(), legacy_record.as_ref());
            let decoded_record = Metered::try_from(encoded_record).unwrap();
            prop_assert_eq!(&decoded_record, &metered_record);
            let sequenced = decoded_record.sequenced(StreamPosition { seq_num, timestamp });
            let (position, sequenced_record) = sequenced.into_parts();
            assert_eq!(position, StreamPosition { seq_num, timestamp });
            assert_eq!(sequenced_record.into_inner(), record);
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
            let encoded_record = Metered::from(StoredRecord::from(record.clone()))
                .as_ref()
                .to_bytes();
            assert_eq!(record.metered_size(), semantic_metered_size(&record));
            assert_eq!(record.metered_size(), try_metered_size(encoded_record.as_ref()).unwrap() as usize);
        }
    );

    proptest!(
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn roundtrip_command_metered(command in command_strategy()) {
            let record = Record::Command(command);
            let encoded_record = Metered::from(StoredRecord::from(record.clone()))
                .as_ref()
                .to_bytes();
            let expected_metered = semantic_metered_size(&record);
            let wire_metered = try_metered_size(encoded_record.as_ref()).unwrap() as usize;
            let decoded_record: Metered<Record> = Metered::try_from(encoded_record).unwrap();

            assert_eq!(record.metered_size(), expected_metered);
            assert_eq!(record.metered_size(), wire_metered);
            prop_assert_eq!(decoded_record, Metered::<Record>::from(record));
        }
    );

    #[test]
    fn roundtrip_encrypted_stored_record() {
        let mut encoded = BytesMut::with_capacity(1 + 12 + 10 + 16);
        encoded.put_u8(0x02);
        encoded.put_slice(b"0123456789ab");
        encoded.put_slice(b"ciphertext");
        encoded.put_slice(b"0123456789abcdef");
        let record =
            StoredRecord::encrypted(EncryptedRecord::try_from(encoded.freeze()).unwrap(), 123);
        let metered_record: Metered<StoredRecord> = record.clone().into();
        let encoded_record = metered_record.as_ref().to_bytes();
        let decoded_record = Metered::try_from(encoded_record).unwrap();
        assert_eq!(decoded_record, metered_record);
    }

    #[test]
    fn empty_header_name_solo() {
        let headers = vec![Header {
            name: Bytes::new(),
            value: Bytes::from("hi"),
        }];
        let body = Bytes::from("hello");
        assert_eq!(
            Record::try_from_parts(headers, body),
            Err(RecordPartsError::UnknownCommand)
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
            Err(RecordPartsError::Header(HeaderValidationError::NameEmpty))
        );
    }

    fn command_parts(op: &'static [u8], payload: &'static [u8]) -> (Vec<Header>, Bytes) {
        let headers = vec![Header {
            name: Bytes::new(),
            value: Bytes::from_static(op),
        }];
        let body = Bytes::from_static(payload);
        (headers, body)
    }

    fn assert_valid_command_record(op: &'static [u8], payload: &'static [u8]) {
        let (headers, body) = command_parts(op, payload);
        let record = Record::try_from_parts(headers.clone(), body.clone()).unwrap();
        let record_metered = record.metered_size();
        match &record {
            Record::Command(cmd) => {
                assert_eq!(cmd.op().to_id(), op);
                assert_eq!(cmd.payload().as_ref(), payload);
            }
            other => panic!("Command expected, got {other:?}"),
        }
        let encoded_record = Metered::from(StoredRecord::from(record.clone()))
            .as_ref()
            .to_bytes();
        assert_eq!(record_metered, semantic_metered_size(&record));
        assert_eq!(
            record_metered,
            try_metered_size(encoded_record.as_ref()).unwrap() as usize
        );
        assert_eq!(
            encoded_record.as_ref(),
            legacy_plaintext_bytes(&record).as_ref()
        );
        let sequenced_record = record.clone().sequenced(StreamPosition {
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
            sequenced_record.inner,
            Record::try_from_parts(headers, body).unwrap()
        );
    }

    #[rstest]
    #[case::fence_empty(b"fence", b"")]
    #[case::fence_uuid(b"fence", b"my-special-uuid")]
    #[case::trim_0(b"trim", b"\x00\x00\x00\x00\x00\x00\x00\x00")]
    fn valid_command_records(#[case] op: &'static [u8], #[case] payload: &'static [u8]) {
        assert_valid_command_record(op, payload);
    }

    #[rstest]
    #[case::fence_too_long(
        b"fence",
        b"toolongtoolongtoolongtoolongtoolongtoolongtoolong",
        RecordPartsError::CommandPayload(
            CommandOp::Fence,
            CommandPayloadError::FencingTokenTooLong(FencingTokenTooLongError(49)),
        )
    )]
    #[case::trim_empty(
        b"trim",
        b"",
        RecordPartsError::CommandPayload(CommandOp::Trim, CommandPayloadError::TrimPointSize(0),)
    )]
    #[case::trim_overflow(
        b"trim",
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        RecordPartsError::CommandPayload(CommandOp::Trim, CommandPayloadError::TrimPointSize(9),)
    )]
    fn invalid_command_records(
        #[case] op: &'static [u8],
        #[case] payload: &'static [u8],
        #[case] expected: RecordPartsError,
    ) {
        let (headers, body) = command_parts(op, payload);
        assert_eq!(Record::try_from_parts(headers, body), Err(expected));
    }

    #[rstest]
    #[case(0b0000_0010, MagicByte { record_type: RecordType::Envelope, metered_size_varlen: 1})]
    #[case(0b0001_0010, MagicByte { record_type: RecordType::Envelope, metered_size_varlen: 3})]
    #[case(0b0000_0011, MagicByte { record_type: RecordType::EncryptedEnvelope, metered_size_varlen: 1})]
    #[case(0b0000_1001, MagicByte { record_type: RecordType::Command, metered_size_varlen: 2})]
    fn valid_magic_byte_parsing(#[case] as_u8: u8, #[case] magic_byte: MagicByte) {
        assert_eq!(MagicByte::try_from(as_u8).unwrap(), magic_byte);
        assert_eq!(u8::from(magic_byte), as_u8);
    }

    #[rstest]
    #[case(0b0000_1101, "invalid record type ordinal")]
    #[case(0b0001_1001, "invalid metered_size_varlen")]
    fn invalid_magic_byte_parsing(#[case] as_u8: u8, #[case] expected: &'static str) {
        assert_eq!(MagicByte::try_from(as_u8), Err(expected));
    }

    #[test]
    fn metered_record_truncated_after_magic_byte_returns_error() {
        // Magic byte: Envelope (0b0000_0010), metered_size_varlen = 1 → expects 1 more byte.
        let truncated = Bytes::from_static(&[0b0000_0010]);
        let result: Result<Metered<Record>, _> = truncated.try_into();
        assert_eq!(result, Err(RecordDecodeError::Truncated("MeteredSize")));
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
