use std::{marker::PhantomData, ops::Deref, str::FromStr, time::Duration};

use compact_str::{CompactString, ToCompactString};
use time::OffsetDateTime;

use super::{
    ValidationError,
    strings::{NameProps, PrefixProps, StartAfterProps, StrProps},
};
use crate::{
    caps,
    encryption::EncryptionSpec,
    read_extent::{ReadLimit, ReadUntil},
    record::{
        FencingToken, Metered, MeteredExt, MeteredSize, Record, RecordDecryptionError, SeqNum,
        Sequenced, StoredRecord, StreamPosition, Timestamp, decrypt_stored_record, encrypt_record,
    },
    types::resources::ListItemsRequest,
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct StreamNameStr<T: StrProps>(CompactString, PhantomData<T>);

impl<T: StrProps> StreamNameStr<T> {
    fn validate_str(name: &str) -> Result<(), ValidationError> {
        if !T::IS_PREFIX && name.is_empty() {
            return Err(format!("stream {} must not be empty", T::FIELD_NAME).into());
        }

        if !T::IS_PREFIX && (name == "." || name == "..") {
            return Err(format!("stream {} must not be \".\" or \"..\"", T::FIELD_NAME).into());
        }

        if name.len() > caps::MAX_STREAM_NAME_LEN {
            return Err(format!(
                "stream {} must not exceed {} bytes in length",
                T::FIELD_NAME,
                caps::MAX_STREAM_NAME_LEN
            )
            .into());
        }

        Ok(())
    }
}

#[cfg(feature = "utoipa")]
impl<T> utoipa::PartialSchema for StreamNameStr<T>
where
    T: StrProps,
{
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .min_length((!T::IS_PREFIX).then_some(caps::MIN_STREAM_NAME_LEN))
            .max_length(Some(caps::MAX_STREAM_NAME_LEN))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl<T> utoipa::ToSchema for StreamNameStr<T> where T: StrProps {}

impl<T: StrProps> serde::Serialize for StreamNameStr<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, T: StrProps> serde::Deserialize<'de> for StreamNameStr<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

impl<T: StrProps> AsRef<str> for StreamNameStr<T> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<T: StrProps> Deref for StreamNameStr<T> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: StrProps> TryFrom<CompactString> for StreamNameStr<T> {
    type Error = ValidationError;

    fn try_from(name: CompactString) -> Result<Self, Self::Error> {
        Self::validate_str(&name)?;
        Ok(Self(name, PhantomData))
    }
}

impl<T: StrProps> FromStr for StreamNameStr<T> {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::validate_str(s)?;
        Ok(Self(s.to_compact_string(), PhantomData))
    }
}

impl<T: StrProps> std::fmt::Debug for StreamNameStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> std::fmt::Display for StreamNameStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> From<StreamNameStr<T>> for CompactString {
    fn from(value: StreamNameStr<T>) -> Self {
        value.0
    }
}

pub type StreamName = StreamNameStr<NameProps>;

pub type StreamNamePrefix = StreamNameStr<PrefixProps>;

impl Default for StreamNamePrefix {
    fn default() -> Self {
        StreamNameStr(CompactString::default(), PhantomData)
    }
}

impl From<StreamName> for StreamNamePrefix {
    fn from(value: StreamName) -> Self {
        Self(value.0, PhantomData)
    }
}

pub type StreamNameStartAfter = StreamNameStr<StartAfterProps>;

impl Default for StreamNameStartAfter {
    fn default() -> Self {
        StreamNameStr(CompactString::default(), PhantomData)
    }
}

impl From<StreamName> for StreamNameStartAfter {
    fn from(value: StreamName) -> Self {
        Self(value.0, PhantomData)
    }
}

#[derive(Debug, Clone)]
pub struct StreamInfo {
    pub name: StreamName,
    pub created_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct AppendRecord<T = Record>(AppendRecordParts<T>);

impl<T> AppendRecord<T> {
    pub fn parts(&self) -> &AppendRecordParts<T> {
        let Self(parts) = self;
        parts
    }

    pub fn into_parts(self) -> AppendRecordParts<T> {
        let Self(parts) = self;
        parts
    }
}

impl<T> MeteredSize for AppendRecord<T> {
    fn metered_size(&self) -> usize {
        self.0.record.metered_size()
    }
}

#[derive(Debug, Clone)]
pub struct AppendRecordParts<T = Record> {
    pub timestamp: Option<Timestamp>,
    pub record: Metered<T>,
}

impl<T> MeteredSize for AppendRecordParts<T> {
    fn metered_size(&self) -> usize {
        self.record.metered_size()
    }
}

impl<T> From<AppendRecord<T>> for AppendRecordParts<T> {
    fn from(record: AppendRecord<T>) -> Self {
        record.into_parts()
    }
}

impl<T> TryFrom<AppendRecordParts<T>> for AppendRecord<T> {
    type Error = &'static str;

    fn try_from(parts: AppendRecordParts<T>) -> Result<Self, Self::Error> {
        if parts.metered_size() > caps::RECORD_BATCH_MAX.bytes {
            Err("record must have metered size less than 1 MiB")
        } else {
            Ok(Self(parts))
        }
    }
}

#[derive(Clone)]
pub struct AppendRecordBatch<T = Record>(Metered<Vec<AppendRecord<T>>>);

impl<T> std::fmt::Debug for AppendRecordBatch<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppendRecordBatch")
            .field("num_records", &self.0.len())
            .field("metered_size", &self.0.metered_size())
            .finish()
    }
}

impl<T> MeteredSize for AppendRecordBatch<T> {
    fn metered_size(&self) -> usize {
        self.0.metered_size()
    }
}

impl<T> std::ops::Deref for AppendRecordBatch<T> {
    type Target = [AppendRecord<T>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> TryFrom<Metered<Vec<AppendRecord<T>>>> for AppendRecordBatch<T> {
    type Error = &'static str;

    fn try_from(records: Metered<Vec<AppendRecord<T>>>) -> Result<Self, Self::Error> {
        if records.is_empty() {
            return Err("record batch must not be empty");
        }

        if records.len() > caps::RECORD_BATCH_MAX.count {
            return Err("record batch must not exceed 1000 records");
        }

        if records.metered_size() > caps::RECORD_BATCH_MAX.bytes {
            return Err("record batch must not exceed a metered size of 1 MiB");
        }

        Ok(Self(records))
    }
}

impl<T> TryFrom<Vec<AppendRecord<T>>> for AppendRecordBatch<T> {
    type Error = &'static str;

    fn try_from(records: Vec<AppendRecord<T>>) -> Result<Self, Self::Error> {
        let records = Metered::from(records);
        Self::try_from(records)
    }
}

impl<T> IntoIterator for AppendRecordBatch<T> {
    type Item = AppendRecord<T>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

pub type StoredAppendRecord = AppendRecord<StoredRecord>;
pub type StoredAppendRecordParts = AppendRecordParts<StoredRecord>;
pub type StoredAppendRecordBatch = AppendRecordBatch<StoredRecord>;

impl From<AppendRecordParts<Record>> for AppendRecordParts<StoredRecord> {
    fn from(
        AppendRecordParts { timestamp, record }: AppendRecordParts<Record>,
    ) -> AppendRecordParts<StoredRecord> {
        AppendRecordParts {
            timestamp,
            record: StoredRecord::from(record.into_inner()).into(),
        }
    }
}

impl From<AppendRecord<Record>> for AppendRecord<StoredRecord> {
    fn from(record: AppendRecord<Record>) -> Self {
        Self(record.into_parts().into())
    }
}

impl From<AppendRecordBatch<Record>> for AppendRecordBatch<StoredRecord> {
    fn from(records: AppendRecordBatch<Record>) -> Self {
        AppendRecordBatch(
            records
                .into_iter()
                .map(|r| AppendRecord::<StoredRecord>::from(r).metered())
                .collect(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct AppendInput<T = Record> {
    pub records: AppendRecordBatch<T>,
    pub match_seq_num: Option<SeqNum>,
    pub fencing_token: Option<FencingToken>,
}

impl AppendInput<Record> {
    pub fn encrypt(self, encryption: &EncryptionSpec, aad: &[u8]) -> AppendInput<StoredRecord> {
        let AppendInput {
            records,
            match_seq_num,
            fencing_token,
        } = self;
        let records = AppendRecordBatch(
            records
                .into_iter()
                .map(|record| {
                    let AppendRecordParts { timestamp, record } = record.into_parts();
                    let record = encrypt_record(record, encryption, aad);
                    AppendRecord(AppendRecordParts { timestamp, record }).metered()
                })
                .collect(),
        );

        AppendInput {
            records,
            match_seq_num,
            fencing_token,
        }
    }
}

pub type StoredAppendInput = AppendInput<StoredRecord>;

impl From<AppendInput<Record>> for AppendInput<StoredRecord> {
    fn from(value: AppendInput<Record>) -> Self {
        let AppendInput {
            records,
            match_seq_num,
            fencing_token,
        } = value;
        let records = records.into();
        AppendInput {
            records,
            match_seq_num,
            fencing_token,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppendAck {
    pub start: StreamPosition,
    pub end: StreamPosition,
    pub tail: StreamPosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadPosition {
    SeqNum(SeqNum),
    Timestamp(Timestamp),
}

#[derive(Debug, Clone, Copy)]
pub enum ReadFrom {
    SeqNum(SeqNum),
    Timestamp(Timestamp),
    TailOffset(u64),
}

impl Default for ReadFrom {
    fn default() -> Self {
        Self::SeqNum(0)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ReadStart {
    pub from: ReadFrom,
    pub clamp: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ReadEnd {
    pub limit: ReadLimit,
    pub until: ReadUntil,
    pub wait: Option<Duration>,
}

impl ReadEnd {
    pub fn may_follow(&self) -> bool {
        (self.limit.is_unbounded() && self.until.is_unbounded())
            || self.wait.is_some_and(|d| d > Duration::ZERO)
    }
}

#[derive(Clone)]
pub struct ReadBatch<T = Record> {
    pub records: Metered<Vec<Sequenced<T>>>,
    pub tail: Option<StreamPosition>,
}

impl<T> Default for ReadBatch<T>
where
    T: MeteredSize,
{
    fn default() -> Self {
        Self {
            records: Metered::default(),
            tail: None,
        }
    }
}

impl<T> std::fmt::Debug for ReadBatch<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadBatch")
            .field("num_records", &self.records.len())
            .field("metered_size", &self.records.metered_size())
            .field("tail", &self.tail)
            .finish()
    }
}

impl ReadBatch<StoredRecord> {
    pub fn decrypt(
        self,
        encryption: &EncryptionSpec,
        aad: &[u8],
    ) -> Result<ReadBatch, RecordDecryptionError> {
        let records: Result<Metered<Vec<Sequenced<Record>>>, RecordDecryptionError> = self
            .records
            .into_inner()
            .into_iter()
            .map(|record| {
                let (position, record) = record.into_parts();
                decrypt_stored_record(record, encryption, aad)
                    .map(|record| record.sequenced(position))
            })
            .collect();

        Ok(ReadBatch {
            records: records?,
            tail: self.tail,
        })
    }
}

pub type StoredReadBatch = ReadBatch<StoredRecord>;

#[derive(Debug, Clone)]
pub enum ReadSessionOutput<T = Record> {
    Heartbeat(StreamPosition),
    Batch(ReadBatch<T>),
}

impl ReadSessionOutput<StoredRecord> {
    pub fn decrypt(
        self,
        encryption: &EncryptionSpec,
        aad: &[u8],
    ) -> Result<ReadSessionOutput, RecordDecryptionError> {
        match self {
            Self::Heartbeat(tail) => Ok(ReadSessionOutput::Heartbeat(tail)),
            Self::Batch(batch) => batch.decrypt(encryption, aad).map(ReadSessionOutput::Batch),
        }
    }
}

pub type StoredReadSessionOutput = ReadSessionOutput<StoredRecord>;

pub type ListStreamsRequest = ListItemsRequest<StreamNamePrefix, StreamNameStartAfter>;

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use rstest::rstest;

    use super::{
        super::strings::{NameProps, PrefixProps, StartAfterProps},
        *,
    };
    use crate::record::{EnvelopeRecord, MeteredExt, Record, StoredRecord, StreamPosition};

    #[rstest]
    #[case::normal("my-stream".to_owned())]
    #[case::max_len("a".repeat(crate::caps::MAX_STREAM_NAME_LEN))]
    fn validate_name_ok(#[case] name: String) {
        assert_eq!(StreamNameStr::<NameProps>::validate_str(&name), Ok(()));
    }

    #[rstest]
    #[case::empty("".to_owned())]
    #[case::dot(".".to_owned())]
    #[case::dot_dot("..".to_owned())]
    #[case::too_long("a".repeat(crate::caps::MAX_STREAM_NAME_LEN + 1))]
    fn validate_name_err(#[case] name: String) {
        StreamNameStr::<NameProps>::validate_str(&name).expect_err("expected validation error");
    }

    #[rstest]
    #[case::empty("".to_owned())]
    #[case::dot(".".to_owned())]
    #[case::dot_dot("..".to_owned())]
    #[case::max_len("a".repeat(crate::caps::MAX_STREAM_NAME_LEN))]
    fn validate_prefix_ok(#[case] prefix: String) {
        assert_eq!(StreamNameStr::<PrefixProps>::validate_str(&prefix), Ok(()));
    }

    #[rstest]
    #[case::too_long("a".repeat(crate::caps::MAX_STREAM_NAME_LEN + 1))]
    fn validate_prefix_err(#[case] prefix: String) {
        StreamNameStr::<PrefixProps>::validate_str(&prefix).expect_err("expected validation error");
    }

    #[rstest]
    #[case::empty("".to_owned())]
    #[case::dot(".".to_owned())]
    #[case::dot_dot("..".to_owned())]
    #[case::max_len("a".repeat(crate::caps::MAX_STREAM_NAME_LEN))]
    fn validate_start_after_ok(#[case] start_after: String) {
        assert_eq!(
            StreamNameStr::<StartAfterProps>::validate_str(&start_after),
            Ok(())
        );
    }

    #[rstest]
    #[case::too_long("a".repeat(crate::caps::MAX_STREAM_NAME_LEN + 1))]
    fn validate_start_after_err(#[case] start_after: String) {
        StreamNameStr::<StartAfterProps>::validate_str(&start_after)
            .expect_err("expected validation error");
    }

    const TEST_AAD: &[u8] = b"test-stream-aad";

    fn sample_append_input() -> AppendInput {
        let record = Record::Envelope(
            EnvelopeRecord::try_from_parts(vec![], Bytes::from_static(b"hello")).unwrap(),
        );
        AppendInput {
            records: vec![
                AppendRecord::try_from(AppendRecordParts {
                    timestamp: Some(42),
                    record: record.metered(),
                })
                .unwrap(),
            ]
            .try_into()
            .unwrap(),
            match_seq_num: Some(7),
            fencing_token: Some("fence".parse().unwrap()),
        }
    }

    #[rstest]
    #[case::encrypt(true)]
    #[case::into(false)]
    fn append_input_to_stored_preserves_metadata(#[case] encrypt: bool) {
        let encryption = EncryptionSpec::aegis256([0x42; 32]);
        let mapped = if encrypt {
            sample_append_input().encrypt(&encryption, TEST_AAD)
        } else {
            sample_append_input().into()
        };

        assert_eq!(mapped.match_seq_num, Some(7));
        assert_eq!(
            mapped.fencing_token.as_ref().map(|token| token.as_ref()),
            Some("fence")
        );

        let append_record: AppendRecordParts<StoredRecord> = mapped
            .records
            .into_iter()
            .next()
            .expect("sample append input should contain a single record")
            .into_parts();
        assert_eq!(append_record.timestamp, Some(42));

        let stored_record = append_record.record.into_inner();
        assert_eq!(
            matches!(&stored_record, StoredRecord::Encrypted { .. }),
            encrypt
        );

        let decrypted = decrypt_stored_record(stored_record, &encryption, TEST_AAD).unwrap();
        let Record::Envelope(record) = decrypted.into_inner() else {
            panic!("expected envelope record");
        };
        assert_eq!(record.body().as_ref(), b"hello");
    }

    #[test]
    fn stored_read_batch_decrypt_preserves_positions_and_tail() {
        let batch = ReadBatch {
            records: Metered::from(vec![
                StoredRecord::Plaintext(Record::Envelope(
                    EnvelopeRecord::try_from_parts(vec![], Bytes::from_static(b"one")).unwrap(),
                ))
                .metered()
                .sequenced(StreamPosition {
                    seq_num: 1,
                    timestamp: 10,
                })
                .into_inner(),
                StoredRecord::Plaintext(Record::Envelope(
                    EnvelopeRecord::try_from_parts(vec![], Bytes::from_static(b"two")).unwrap(),
                ))
                .metered()
                .sequenced(StreamPosition {
                    seq_num: 2,
                    timestamp: 20,
                })
                .into_inner(),
            ]),
            tail: Some(StreamPosition {
                seq_num: 3,
                timestamp: 30,
            }),
        };

        let mapped = batch
            .decrypt(&crate::encryption::EncryptionSpec::Plain, &[])
            .unwrap();
        let records = mapped.records.into_inner();

        assert_eq!(
            mapped.tail,
            Some(StreamPosition {
                seq_num: 3,
                timestamp: 30
            })
        );
        assert_eq!(
            records[0].position(),
            &StreamPosition {
                seq_num: 1,
                timestamp: 10
            }
        );
        assert_eq!(
            records[1].position(),
            &StreamPosition {
                seq_num: 2,
                timestamp: 20
            }
        );
        assert!(matches!(records[0].inner(), Record::Envelope(_)));
        assert!(matches!(records[1].inner(), Record::Envelope(_)));
    }
}
