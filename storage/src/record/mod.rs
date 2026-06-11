mod batcher;
mod encryption;
mod iterator;

pub use batcher::{RecordBatch, RecordBatcher};
use bytes::{Buf, BufMut, Bytes, BytesMut};
pub use encryption::{
    EncryptedRecord, RecordDecryptionError, decrypt_stored_record, encrypt_record,
};
pub use iterator::StoredRecordIterator;
pub use s2_common::record::{
    CommandRecord, Encodable, EnvelopeRecord, FencingToken, FencingTokenTooLongError, Header,
    MAX_FENCING_TOKEN_LENGTH, Metered, MeteredExt, MeteredSize, NonZeroSeqNum, Record,
    RecordDecodeError, RecordPartsError, SeqNum, Sequenced, SequencedRecord, StreamPosition,
    Timestamp,
};
use s2_common::{deep_size::DeepSize, encryption::EncryptionAlgorithm};

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum RecordType {
    Command = 1,
    Envelope = 2,
    EncryptedEnvelope = 3,
}

impl TryFrom<u8> for RecordType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Command),
            2 => Ok(Self::Envelope),
            3 => Ok(Self::EncryptedEnvelope),
            _ => Err("invalid record type ordinal"),
        }
    }
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

impl TryFrom<u8> for MagicByte {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let record_type = RecordType::try_from(value & 0b111)?;
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

    pub fn encryption_algorithm(&self) -> Option<EncryptionAlgorithm> {
        match self {
            Self::Plaintext(_) => None,
            Self::Encrypted { record, .. } => Some(record.algorithm()),
        }
    }

    pub fn max_assignable_seq_num(&self) -> SeqNum {
        match self {
            Self::Plaintext(_) => SeqNum::MAX,
            Self::Encrypted { record, .. } => record.max_assignable_seq_num(),
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

pub trait StoredEncodable {
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

impl StoredEncodable for Metered<&StoredRecord> {
    fn encoded_size(&self) -> usize {
        1 + magic_byte(self).metered_size_varlen as usize + self.encoded_body_size()
    }

    fn encode_into(&self, buf: &mut impl BufMut) {
        let magic_byte = magic_byte(self);
        buf.put_u8(magic_byte.into());
        buf.put_uint(
            self.metered_size() as u64,
            magic_byte.metered_size_varlen as usize,
        );
        self.encode_body_into(buf);
    }
}

fn magic_byte(record: &Metered<&StoredRecord>) -> MagicByte {
    let metered_size = record.metered_size();
    let metered_size_varlen = 8 - (metered_size.leading_zeros() / 8) as u8;
    if metered_size_varlen > 3 {
        panic!("illegal metered size varlen {metered_size} for record")
    }
    MagicByte {
        record_type: record.record_type(),
        metered_size_varlen,
    }
}

pub type StoredSequencedBytes = Sequenced<Bytes>;
pub type StoredSequencedRecord = Sequenced<StoredRecord>;

pub fn decode_stored_record(mut buf: Bytes) -> Result<Metered<StoredRecord>, RecordDecodeError> {
    if buf.is_empty() {
        return Err(RecordDecodeError::Truncated("MagicByte"));
    }
    let magic_byte = MagicByte::try_from(buf.get_u8())
        .map_err(|msg| RecordDecodeError::InvalidValue("MagicByte", msg))?;

    let metered_size = buf
        .try_get_uint(magic_byte.metered_size_varlen as usize)
        .map_err(|_| RecordDecodeError::Truncated("MeteredSize"))? as usize;

    Ok(Metered::with_size(
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

pub fn decode_record(buf: Bytes) -> Result<Metered<Record>, RecordDecodeError> {
    let stored = decode_stored_record(buf)?;
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
            let encoded_record = StoredRecord::from(record.clone())
                .metered()
                .as_ref()
                .to_bytes();
            let legacy_record = legacy_plaintext_bytes(&record);
            prop_assert_eq!(encoded_record.as_ref(), legacy_record.as_ref());
            let decoded_record = decode_record(encoded_record).unwrap();
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
            let encoded_record = StoredRecord::from(record.clone())
                .metered()
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
            let encoded_record = StoredRecord::from(record.clone())
                .metered()
                .as_ref()
                .to_bytes();
            let expected_metered = semantic_metered_size(&record);
            let wire_metered = try_metered_size(encoded_record.as_ref()).unwrap() as usize;
            let decoded_record = decode_record(encoded_record).unwrap();

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
        let metered_record = record.clone().metered();
        let encoded_record = metered_record.as_ref().to_bytes();
        let decoded_record = decode_stored_record(encoded_record).unwrap();
        assert_eq!(decoded_record, metered_record);
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
        // Magic byte: Envelope (0b0000_0010), metered_size_varlen = 1 -> expects 1 more byte.
        let truncated = Bytes::from_static(&[0b0000_0010]);
        let result = decode_record(truncated);
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
