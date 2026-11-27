use std::{marker::PhantomData, time::Duration};

use compact_str::CompactString;

use super::{
    ValidationError,
    strings::{NameProps, PrefixProps, StartAfterProps, StrProps, impl_validated_str},
};
use crate::{
    caps,
    encryption::EncryptionAlgorithm,
    read_extent::{ReadLimit, ReadUntil},
    record::{
        FencingToken, Metered, MeteredSize, Record, SeqNum, Sequenced, StreamPosition, Timestamp,
    },
    resources::ListItemsRequest,
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct StreamNameStr<T: StrProps>(CompactString, PhantomData<T>);

impl<T: StrProps> StreamNameStr<T> {
    fn validate_str(name: &str) -> Result<(), ValidationError> {
        if !T::IS_PREFIX && name.len() < caps::MIN_STREAM_NAME_LEN {
            return Err(format!(
                "stream {} should be at least {} bytes in length",
                T::FIELD_NAME,
                caps::MIN_STREAM_NAME_LEN
            )
            .into());
        }

        if !T::IS_PREFIX && (name == "." || name == "..") {
            return Err(format!("stream {} must not be \".\" or \"..\"", T::FIELD_NAME).into());
        }

        if name.contains('\0') {
            return Err(format!("stream {} must not contain NUL bytes", T::FIELD_NAME).into());
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

impl_validated_str!(StreamNameStr<T: StrProps>);

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
    pub created_at: jiff::Timestamp,
    pub deleted_at: Option<jiff::Timestamp>,
    pub cipher: Option<EncryptionAlgorithm>,
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

#[derive(Debug, Clone)]
pub struct AppendInput<T = Record> {
    pub records: AppendRecordBatch<T>,
    pub match_seq_num: Option<SeqNum>,
    pub fencing_token: Option<FencingToken>,
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
    /// Returns `true` if a read may wait at the tail for new records:
    /// when `wait` is explicitly positive, or when `wait` is omitted with no `count`, `bytes`, or
    /// `until` bound.
    pub fn may_follow(&self) -> bool {
        match self.wait {
            Some(wait) => !wait.is_zero(),
            None => self.limit.is_unbounded() && self.until.is_unbounded(),
        }
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

#[derive(Debug, Clone)]
pub enum ReadSessionOutput<T = Record> {
    Heartbeat(StreamPosition),
    Batch(ReadBatch<T>),
}

pub type ListStreamsRequest = ListItemsRequest<StreamNamePrefix, StreamNameStartAfter>;

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::{
        super::strings::{NameProps, PrefixProps, StartAfterProps},
        *,
    };

    #[rstest]
    #[case::normal("my-stream".to_owned())]
    #[case::control_chars("a\tb\nc\rd\x01e".to_owned())]
    #[case::unicode("stream/名前 😀?#%20".to_owned())]
    #[case::min_len("a".repeat(crate::caps::MIN_STREAM_NAME_LEN))]
    #[case::max_len("a".repeat(crate::caps::MAX_STREAM_NAME_LEN))]
    fn validate_name_ok(#[case] name: String) {
        assert_eq!(StreamNameStr::<NameProps>::validate_str(&name), Ok(()));
    }

    #[rstest]
    #[case::empty("".to_owned())]
    #[case::too_short("a".repeat(crate::caps::MIN_STREAM_NAME_LEN - 1))]
    #[case::dot(".".to_owned())]
    #[case::dot_dot("..".to_owned())]
    #[case::too_long("a".repeat(crate::caps::MAX_STREAM_NAME_LEN + 1))]
    #[case::nul("a\0b".to_owned())]
    #[case::leading_nul("\0a".to_owned())]
    #[case::trailing_nul("a\0".to_owned())]
    #[case::only_nul("\0".to_owned())]
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
    #[case::nul("a\0b".to_owned())]
    #[case::only_nul("\0".to_owned())]
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
    #[case::nul("a\0b".to_owned())]
    #[case::only_nul("\0".to_owned())]
    fn validate_start_after_err(#[case] start_after: String) {
        StreamNameStr::<StartAfterProps>::validate_str(&start_after)
            .expect_err("expected validation error");
    }

    #[test]
    fn append_record_batch_rejects_empty_batches() {
        let empty_batch: Result<AppendRecordBatch, _> = Vec::<AppendRecord>::new().try_into();

        assert_eq!(empty_batch.unwrap_err(), "record batch must not be empty");
    }

    #[test]
    fn string_conversions_and_serde_roundtrip() {
        let from_str = StreamName::try_from("my-stream").unwrap();
        let from_string = StreamName::try_from("my-stream".to_owned()).unwrap();
        assert_eq!(from_str, from_string);
        assert_eq!(String::from(from_string), "my-stream");

        let json = serde_json::to_string(&from_str).unwrap();
        assert_eq!(json, r#""my-stream""#);
        let decoded: StreamName = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, from_str);
        assert!(serde_json::from_str::<StreamName>(r#""""#).is_err());
    }

    #[rstest]
    #[case::unbounded_omitted_wait(ReadLimit::Unbounded, ReadUntil::Unbounded, None, true)]
    #[case::unbounded_zero_wait(
        ReadLimit::Unbounded,
        ReadUntil::Unbounded,
        Some(Duration::ZERO),
        false
    )]
    #[case::unbounded_nonzero_wait(
        ReadLimit::Unbounded,
        ReadUntil::Unbounded,
        Some(Duration::from_secs(1)),
        true
    )]
    #[case::count_omitted_wait(ReadLimit::Count(10), ReadUntil::Unbounded, None, false)]
    #[case::count_zero_wait(
        ReadLimit::Count(10),
        ReadUntil::Unbounded,
        Some(Duration::ZERO),
        false
    )]
    #[case::count_nonzero_wait(
        ReadLimit::Count(10),
        ReadUntil::Unbounded,
        Some(Duration::from_secs(1)),
        true
    )]
    #[case::bytes_omitted_wait(ReadLimit::Bytes(1024), ReadUntil::Unbounded, None, false)]
    #[case::until_omitted_wait(ReadLimit::Unbounded, ReadUntil::Timestamp(1000), None, false)]
    #[case::until_nonzero_wait(
        ReadLimit::Unbounded,
        ReadUntil::Timestamp(1000),
        Some(Duration::from_secs(1)),
        true
    )]
    fn read_end_may_follow(
        #[case] limit: ReadLimit,
        #[case] until: ReadUntil,
        #[case] wait: Option<Duration>,
        #[case] expected: bool,
    ) {
        let end = ReadEnd { limit, until, wait };
        assert_eq!(end.may_follow(), expected);
    }
}
