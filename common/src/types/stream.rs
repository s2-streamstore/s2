use std::{marker::PhantomData, ops::Deref, str::FromStr, time::Duration};

use compact_str::{CompactString, ToCompactString};
use time::OffsetDateTime;

use super::{
    ValidationError,
    strings::{NameProps, PrefixProps, StartAfterProps, StrProps},
};
use crate::{
    caps,
    read_extent::{ReadLimit, ReadUntil},
    record::{
        FencingToken, Metered, MeteredRecord, MeteredSequencedRecords, MeteredSize, SeqNum,
        StreamPosition, Timestamp,
    },
    types::resources::ListItemsRequest,
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct StreamNameStr<T: StrProps>(CompactString, PhantomData<T>);

#[cfg(feature = "utoipa")]
impl<T> utoipa::PartialSchema for StreamNameStr<T>
where
    T: StrProps,
{
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .min_length((!T::IS_PREFIX).then_some(1))
            .max_length(Some(Self::MAX_LENGTH))
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

impl<T: StrProps> StreamNameStr<T> {
    const MAX_LENGTH: usize = caps::MAX_STREAM_NAME_LEN;
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
        if !T::IS_PREFIX && name.is_empty() {
            return Err(format!("Stream {} must not be empty", T::FIELD_NAME).into());
        }

        if name.len() > Self::MAX_LENGTH {
            return Err(format!(
                "Stream {} must not exceed {} characters in length",
                T::FIELD_NAME,
                Self::MAX_LENGTH
            )
            .into());
        }

        Ok(Self(name, PhantomData))
    }
}

impl<T: StrProps> FromStr for StreamNameStr<T> {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_compact_string().try_into()
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
pub struct AppendRecord(AppendRecordParts);

impl Deref for AppendRecord {
    type Target = AppendRecordParts;

    fn deref(&self) -> &Self::Target {
        let Self(parts) = self;
        parts
    }
}

impl MeteredSize for AppendRecord {
    fn metered_size(&self) -> usize {
        self.0.record.metered_size()
    }
}

#[derive(Debug, Clone)]
pub struct AppendRecordParts {
    pub timestamp: Option<Timestamp>,
    pub record: MeteredRecord,
}

impl MeteredSize for AppendRecordParts {
    fn metered_size(&self) -> usize {
        self.record.metered_size()
    }
}

impl From<AppendRecord> for AppendRecordParts {
    fn from(AppendRecord(parts): AppendRecord) -> Self {
        parts
    }
}

impl TryFrom<AppendRecordParts> for AppendRecord {
    type Error = &'static str;

    fn try_from(parts: AppendRecordParts) -> Result<Self, Self::Error> {
        if parts.metered_size() > caps::RECORD_BATCH_MAX.bytes {
            Err("Record must have metered size less than 1 MiB")
        } else {
            Ok(Self(parts))
        }
    }
}

#[derive(Clone)]
pub struct AppendRecordBatch(Metered<Vec<AppendRecord>>);

impl std::fmt::Debug for AppendRecordBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppendRecordBatch")
            .field("num_records", &self.0.len())
            .field("metered_size", &self.0.metered_size())
            .finish()
    }
}

impl MeteredSize for AppendRecordBatch {
    fn metered_size(&self) -> usize {
        self.0.metered_size()
    }
}

impl std::ops::Deref for AppendRecordBatch {
    type Target = [AppendRecord];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Metered<Vec<AppendRecord>>> for AppendRecordBatch {
    type Error = &'static str;

    fn try_from(records: Metered<Vec<AppendRecord>>) -> Result<Self, Self::Error> {
        if records.is_empty() {
            return Err("Record batch must not be empty");
        }

        if records.len() > caps::RECORD_BATCH_MAX.count {
            return Err("Record batch must not exceed 1000 records");
        }

        if records.metered_size() > caps::RECORD_BATCH_MAX.bytes {
            return Err("Record batch must not exceed a metered size of 1 MiB");
        }

        Ok(Self(records))
    }
}

impl TryFrom<Vec<AppendRecord>> for AppendRecordBatch {
    type Error = &'static str;

    fn try_from(records: Vec<AppendRecord>) -> Result<Self, Self::Error> {
        let records = Metered::from(records);
        Self::try_from(records)
    }
}

impl IntoIterator for AppendRecordBatch {
    type Item = AppendRecord;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Debug, Clone)]
pub struct AppendInput {
    pub records: AppendRecordBatch,
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
    pub fn may_follow(&self) -> bool {
        (self.limit.is_unbounded() && self.until.is_unbounded())
            || self.wait.is_some_and(|d| d > Duration::ZERO)
    }
}

#[derive(Default, Clone)]
pub struct ReadBatch {
    pub records: MeteredSequencedRecords,
    pub tail: Option<StreamPosition>,
}

impl std::fmt::Debug for ReadBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadBatch")
            .field("num_records", &self.records.len())
            .field("metered_size", &self.records.metered_size())
            .field("tail", &self.tail)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub enum ReadSessionOutput {
    Heartbeat(StreamPosition),
    Batch(ReadBatch),
}

pub type ListStreamsRequest = ListItemsRequest<StreamNamePrefix, StreamNameStartAfter>;
