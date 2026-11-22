use std::{fmt, ops::Deref, str::FromStr, time::Duration};

use bytes::Bytes;
use rand::RngExt;
use s2_api::v1 as api;
use s2_common::{
    ValidationError,
    caps::RECORD_BATCH_MAX,
    record::{MAX_FENCING_TOKEN_LENGTH, Metered, MeteredSize},
};

use super::{StreamConfig, whole_seconds};
use crate::error::{ErrorContext, ProtocolError};

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Token for fencing appends to a stream.
///
/// **Note:** It must not exceed 36 bytes in length.
///
/// See [`CommandRecord::fence`] and [`AppendInput::fencing_token`].
pub struct FencingToken(String);

impl FencingToken {
    pub(crate) fn from_server(value: String) -> Self {
        Self(value)
    }

    fn validate_len(len: usize) -> Result<(), ValidationError> {
        if len > MAX_FENCING_TOKEN_LENGTH {
            return Err(ValidationError(format!(
                "fencing token exceeds {MAX_FENCING_TOKEN_LENGTH} bytes in length",
            )));
        }
        Ok(())
    }

    /// Generate a random alphanumeric fencing token of `n` bytes.
    pub fn generate(n: usize) -> Result<Self, ValidationError> {
        Self::validate_len(n)?;
        Ok(Self(
            rand::rng()
                .sample_iter(&rand::distr::Alphanumeric)
                .take(n)
                .map(char::from)
                .collect(),
        ))
    }
}

impl FromStr for FencingToken {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::validate_len(s.len())?;
        Ok(FencingToken(s.to_string()))
    }
}

impl TryFrom<&str> for FencingToken {
    type Error = ValidationError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for FencingToken {
    type Error = ValidationError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::validate_len(s.len())?;
        Ok(Self(s))
    }
}

impl From<FencingToken> for String {
    fn from(value: FencingToken) -> Self {
        value.0
    }
}

impl AsRef<str> for FencingToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FencingToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for FencingToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// A position in a stream.
pub struct StreamPosition {
    /// Sequence number assigned by the service.
    pub seq_num: u64,
    /// Timestamp. When assigned by the service, represents milliseconds since Unix epoch.
    /// User-specified timestamps are passed through as-is.
    pub timestamp: u64,
}

impl StreamPosition {
    /// Construct a stream position.
    ///
    /// This is intended for building fixtures in downstream tests.
    pub fn new(seq_num: u64, timestamp: u64) -> Self {
        Self { seq_num, timestamp }
    }
}

impl fmt::Display for StreamPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seq_num={}, timestamp={}", self.seq_num, self.timestamp)
    }
}

impl From<api::stream::proto::StreamPosition> for StreamPosition {
    fn from(value: api::stream::proto::StreamPosition) -> Self {
        Self {
            seq_num: value.seq_num,
            timestamp: value.timestamp,
        }
    }
}

impl From<api::stream::StreamPosition> for StreamPosition {
    fn from(value: api::stream::StreamPosition) -> Self {
        Self {
            seq_num: value.seq_num,
            timestamp: value.timestamp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// A name-value pair.
pub struct Header {
    /// Name.
    pub name: Bytes,
    /// Value.
    pub value: Bytes,
}

impl Header {
    /// Create a new [`Header`] with the given name and value.
    pub fn new(name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl From<Header> for api::stream::proto::Header {
    fn from(value: Header) -> Self {
        Self {
            name: value.name,
            value: value.value,
        }
    }
}

impl From<api::stream::proto::Header> for Header {
    fn from(value: api::stream::proto::Header) -> Self {
        Self {
            name: value.name,
            value: value.value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A record to append.
pub struct AppendRecord {
    body: Bytes,
    headers: Vec<Header>,
    timestamp: Option<u64>,
}

impl AppendRecord {
    fn validate(self) -> Result<Self, ValidationError> {
        if self.metered_bytes() > RECORD_BATCH_MAX.bytes {
            Err(ValidationError(format!(
                "metered_bytes: {} exceeds {}",
                self.metered_bytes(),
                RECORD_BATCH_MAX.bytes
            )))
        } else {
            Ok(self)
        }
    }

    /// Create a new [`AppendRecord`] with the given record body.
    pub fn new(body: impl Into<Bytes>) -> Result<Self, ValidationError> {
        let record = Self {
            body: body.into(),
            headers: Vec::default(),
            timestamp: None,
        };
        record.validate()
    }

    /// Set the headers for this record.
    pub fn with_headers(
        self,
        headers: impl IntoIterator<Item = Header>,
    ) -> Result<Self, ValidationError> {
        let record = Self {
            headers: headers.into_iter().collect(),
            ..self
        };
        record.validate()
    }

    /// Set the timestamp for this record.
    ///
    /// Precise semantics depend on [`StreamConfig::timestamping`].
    pub fn with_timestamp(self, timestamp: u64) -> Self {
        Self {
            timestamp: Some(timestamp),
            ..self
        }
    }

    /// Get the body of this record.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Get the headers of this record.
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Get the timestamp of this record.
    pub fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }
}

impl From<AppendRecord> for api::stream::proto::AppendRecord {
    fn from(value: AppendRecord) -> Self {
        Self {
            timestamp: value.timestamp,
            headers: value.headers.into_iter().map(Into::into).collect(),
            body: value.body,
        }
    }
}

/// Metered byte size calculation.
///
/// Formula for a record:
/// ```text
/// 8 + 2 * len(headers) + sum(len(h.name) + len(h.value) for h in headers) + len(body)
/// ```
pub trait MeteredBytes {
    /// Returns the metered byte size.
    fn metered_bytes(&self) -> usize;
}

macro_rules! metered_bytes_impl {
    ($ty:ty) => {
        impl MeteredBytes for $ty {
            fn metered_bytes(&self) -> usize {
                let mut total = 8usize.saturating_add(self.headers.len().saturating_mul(2));
                for h in &self.headers {
                    total = total
                        .saturating_add(h.name.len())
                        .saturating_add(h.value.len());
                }
                total.saturating_add(self.body.len())
            }
        }
    };
}

metered_bytes_impl!(AppendRecord);

impl MeteredSize for AppendRecord {
    fn metered_size(&self) -> usize {
        self.metered_bytes()
    }
}

#[derive(Debug, Clone)]
/// A batch of records to append atomically.
///
/// **Note:** It must contain at least `1` record and no more than `1000`.
/// The total size of the batch must not exceed `1MiB` in metered bytes.
///
/// See [`Batcher`](crate::batching::Batcher) for convenient and automatic batching of records
/// that takes care of the abovementioned constraints.
pub struct AppendRecordBatch(Metered<Vec<AppendRecord>>);

impl PartialEq for AppendRecordBatch {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for AppendRecordBatch {}

impl From<AppendRecord> for AppendRecordBatch {
    fn from(record: AppendRecord) -> Self {
        let mut batch = Metered::with_capacity(1);
        batch.push(Metered::from(record));
        Self(batch)
    }
}

impl From<CommandRecord> for AppendRecordBatch {
    fn from(record: CommandRecord) -> Self {
        Self::from(AppendRecord::from(record))
    }
}

impl AppendRecordBatch {
    pub(crate) fn from_metered(records: Metered<Vec<AppendRecord>>) -> Self {
        debug_assert!(!records.is_empty());
        debug_assert!(records.len() <= RECORD_BATCH_MAX.count);
        debug_assert!(records.metered_size() <= RECORD_BATCH_MAX.bytes);
        Self(records)
    }

    /// Try to create an [`AppendRecordBatch`] from an iterator of records.
    pub fn try_from_iter<I, R>(iter: I) -> Result<Self, ValidationError>
    where
        I: IntoIterator<Item = R>,
        R: Into<AppendRecord>,
    {
        let iter = iter.into_iter();
        let cap = iter.size_hint().0.min(RECORD_BATCH_MAX.count);
        let mut records = Metered::with_capacity(cap);

        for record in iter {
            records.push(Metered::from(record.into()));

            if records.metered_size() > RECORD_BATCH_MAX.bytes {
                return Err(ValidationError(format!(
                    "batch size in metered bytes ({}) exceeds {}",
                    records.metered_size(),
                    RECORD_BATCH_MAX.bytes
                )));
            }

            if records.len() > RECORD_BATCH_MAX.count {
                return Err(ValidationError(format!(
                    "number of records in the batch exceeds {}",
                    RECORD_BATCH_MAX.count
                )));
            }
        }

        if records.is_empty() {
            return Err(ValidationError("batch is empty".into()));
        }

        Ok(Self::from_metered(records))
    }
}

impl Deref for AppendRecordBatch {
    type Target = [AppendRecord];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl MeteredBytes for AppendRecordBatch {
    fn metered_bytes(&self) -> usize {
        self.0.metered_size()
    }
}

impl IntoIterator for AppendRecordBatch {
    type Item = AppendRecord;
    type IntoIter = std::vec::IntoIter<AppendRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a AppendRecordBatch {
    type Item = &'a AppendRecord;
    type IntoIter = std::slice::Iter<'a, AppendRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Command to signal an operation.
pub enum Command {
    /// Fence operation.
    Fence {
        /// Fencing token.
        fencing_token: FencingToken,
    },
    /// Trim operation.
    Trim {
        /// Trim point.
        trim_point: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Command record for signaling operations to the service.
///
/// See [here](https://s2.dev/docs/rest/records/overview#command-records) for more information.
pub struct CommandRecord {
    /// Command to signal an operation.
    pub command: Command,
    /// Timestamp for this record.
    pub timestamp: Option<u64>,
}

impl CommandRecord {
    const FENCE: &[u8] = b"fence";
    const TRIM: &[u8] = b"trim";

    /// Create a fence command record with the given fencing token.
    ///
    /// Fencing is strongly consistent, and subsequent appends that specify a
    /// fencing token will fail if it does not match.
    pub fn fence(fencing_token: FencingToken) -> Self {
        Self {
            command: Command::Fence { fencing_token },
            timestamp: None,
        }
    }

    /// Create a trim command record with the given trim point.
    ///
    /// Trim point is the desired earliest sequence number for the stream.
    ///
    /// Trimming is eventually consistent, and trimmed records may be visible
    /// for a brief period.
    pub fn trim(trim_point: u64) -> Self {
        Self {
            command: Command::Trim { trim_point },
            timestamp: None,
        }
    }

    /// Set the timestamp for this record.
    pub fn with_timestamp(self, timestamp: u64) -> Self {
        Self {
            timestamp: Some(timestamp),
            ..self
        }
    }
}

impl From<CommandRecord> for AppendRecord {
    fn from(value: CommandRecord) -> Self {
        let (header_value, body) = match value.command {
            Command::Fence { fencing_token } => (
                CommandRecord::FENCE,
                Bytes::copy_from_slice(fencing_token.as_bytes()),
            ),
            Command::Trim { trim_point } => (
                CommandRecord::TRIM,
                Bytes::copy_from_slice(&trim_point.to_be_bytes()),
            ),
        };
        Self {
            body,
            headers: vec![Header::new("", header_value)],
            timestamp: value.timestamp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Input for [`append`](crate::S2Stream::append),
/// [`append_with_stream_config`](crate::S2Stream::append_with_stream_config), and
/// [`AppendSession::submit`](crate::append_session::AppendSession::submit).
pub struct AppendInput {
    /// Batch of records to append atomically.
    pub records: AppendRecordBatch,
    /// Expected sequence number for the first record in the batch.
    ///
    /// If unspecified, no matching is performed. If specified and mismatched, the append fails.
    pub match_seq_num: Option<u64>,
    /// Fencing token to match against the stream's current fencing token.
    ///
    /// If unspecified, no matching is performed. If specified and mismatched,
    /// the append fails. A stream defaults to `""` as its fencing token.
    pub fencing_token: Option<FencingToken>,
}

impl AppendInput {
    /// Create a new [`AppendInput`] with the given batch of records.
    pub fn new(records: AppendRecordBatch) -> Self {
        Self {
            records,
            match_seq_num: None,
            fencing_token: None,
        }
    }

    /// Set the expected sequence number for the first record in the batch.
    pub fn with_match_seq_num(self, match_seq_num: u64) -> Self {
        Self {
            match_seq_num: Some(match_seq_num),
            ..self
        }
    }

    /// Set the fencing token to match against the stream's current fencing token.
    pub fn with_fencing_token(self, fencing_token: FencingToken) -> Self {
        Self {
            fencing_token: Some(fencing_token),
            ..self
        }
    }
}

impl From<AppendRecordBatch> for AppendInput {
    fn from(records: AppendRecordBatch) -> Self {
        Self::new(records)
    }
}

impl From<AppendRecord> for AppendInput {
    fn from(record: AppendRecord) -> Self {
        Self::new(AppendRecordBatch::from(record))
    }
}

impl From<CommandRecord> for AppendInput {
    fn from(record: CommandRecord) -> Self {
        Self::new(AppendRecordBatch::from(record))
    }
}

impl From<AppendInput> for api::stream::proto::AppendInput {
    fn from(value: AppendInput) -> Self {
        Self {
            records: value.records.into_iter().map(Into::into).collect(),
            match_seq_num: value.match_seq_num,
            fencing_token: value.fencing_token.map(|t| t.0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Acknowledgement for an [`AppendInput`].
pub struct AppendAck {
    /// Sequence number and timestamp of the first record that was appended.
    pub start: StreamPosition,
    /// Sequence number of the last record that was appended + 1, and timestamp of the last record
    /// that was appended.
    ///
    /// The difference between `end.seq_num` and `start.seq_num` will be the number of records
    /// appended.
    pub end: StreamPosition,
    /// Sequence number that will be assigned to the next record on the stream, and timestamp of
    /// the last record on the stream.
    ///
    /// This can be greater than the `end` position in case of concurrent appends.
    pub tail: StreamPosition,
}

impl AppendAck {
    /// Construct an append acknowledgement.
    ///
    /// This is intended for building fixtures in downstream tests.
    pub fn new(start: StreamPosition, end: StreamPosition, tail: StreamPosition) -> Self {
        Self { start, end, tail }
    }

    pub(crate) fn try_from_proto(
        value: api::stream::proto::AppendAck,
        expected_records: u64,
        context: ErrorContext,
    ) -> Result<Self, ProtocolError> {
        let start: StreamPosition = value
            .start
            .ok_or_else(|| {
                ProtocolError::new("append ack missing start position", context.clone())
            })?
            .into();
        let end: StreamPosition = value
            .end
            .ok_or_else(|| ProtocolError::new("append ack missing end position", context.clone()))?
            .into();
        let tail: StreamPosition = value
            .tail
            .ok_or_else(|| ProtocolError::new("append ack missing tail position", context.clone()))?
            .into();
        let ack = Self { start, end, tail };
        ack.validate_record_count(expected_records, &context)?;
        Ok(ack)
    }

    pub(crate) fn validate_record_count(
        &self,
        expected_records: u64,
        context: &ErrorContext,
    ) -> Result<(), ProtocolError> {
        let Some(num_acked_records) = self.end.seq_num.checked_sub(self.start.seq_num) else {
            return Err(ProtocolError::new(
                "ack end seq_num should be greater than or equal to start seq_num",
                context.clone(),
            ));
        };
        if num_acked_records != expected_records {
            return Err(ProtocolError::new(
                format!(
                    "acked record count {num_acked_records} does not match submitted batch size {expected_records}"
                ),
                context.clone(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Starting position for reading from a stream.
pub enum ReadFrom {
    /// Read from this sequence number.
    SeqNum(u64),
    /// Read from this timestamp.
    Timestamp(u64),
    /// Read from N records before the tail.
    TailOffset(u64),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Input for [`read`](crate::S2Stream::read), [`read_session`](crate::S2Stream::read_session),
/// and [`read_batch_session`](crate::S2Stream::read_batch_session) operations.
pub struct ReadInput {
    from: Option<ReadFrom>,
    clamp: bool,
    count: Option<u64>,
    bytes: Option<u64>,
    until: Option<u64>,
    wait_secs: Option<u32>,
    stream_config: Option<StreamConfig>,
}

impl ReadInput {
    /// Create a new [`ReadInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the starting position, if specified (otherwise begins at the tail).
    pub fn from(&self) -> Option<ReadFrom> {
        self.from
    }

    /// Return whether to start from the tail if the requested starting position is beyond it.
    pub fn clamp(&self) -> bool {
        self.clamp
    }

    /// Return the limit on number of records, if set.
    pub fn count(&self) -> Option<u64> {
        self.count
    }

    /// Return the limit on total metered bytes of records, if set.
    pub fn bytes(&self) -> Option<u64> {
        self.bytes
    }

    /// Return the exclusive stop timestamp, if set.
    pub fn until(&self) -> Option<u64> {
        self.until
    }

    /// Return the duration to wait for new records before stopping, if set.
    pub fn wait(&self) -> Option<Duration> {
        self.wait_secs.map(|s| Duration::from_secs(u64::from(s)))
    }

    /// Return the stream configuration to apply if the stream is created on read, if set.
    pub fn stream_config(&self) -> Option<&StreamConfig> {
        self.stream_config.as_ref()
    }

    /// Set the starting position.
    ///
    /// Defaults to `None` (no start parameter is sent, causing the API to begin at the tail).
    pub fn with_from(self, from: ReadFrom) -> Self {
        Self {
            from: Some(from),
            ..self
        }
    }

    /// Set whether to start from tail if the requested starting position is beyond it.
    ///
    /// Defaults to `false` (errors if position is beyond tail).
    pub fn with_clamp(self, clamp: bool) -> Self {
        Self { clamp, ..self }
    }

    /// Set the limit on number of records.
    ///
    /// Defaults to `1000` for non-streaming [`read`](crate::S2Stream::read).
    pub fn with_count(self, count: u64) -> Self {
        Self {
            count: Some(count),
            ..self
        }
    }

    /// Set the limit on total metered bytes of records.
    ///
    /// Defaults to `1MiB` for non-streaming [`read`](crate::S2Stream::read).
    pub fn with_bytes(self, bytes: u64) -> Self {
        Self {
            bytes: Some(bytes),
            ..self
        }
    }

    /// Set the timestamp at which to stop (exclusive).
    ///
    /// Defaults to `None`.
    pub fn with_until(self, until: u64) -> Self {
        Self {
            until: Some(until),
            ..self
        }
    }

    /// Set the duration to wait for new records before stopping.
    ///
    /// Will be clamped to `60` seconds for [`read`](crate::S2Stream::read).
    ///
    /// Defaults to:
    /// - `0` (no wait) for [`read`](crate::S2Stream::read).
    /// - `0` (no wait) for [`read_session`](crate::S2Stream::read_session) if `count`, `bytes`, or
    ///   `until` is specified.
    /// - Infinite wait for [`read_session`](crate::S2Stream::read_session) if none of `count`,
    ///   `bytes`, or `until` is specified.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `wait` has sub-second precision or exceeds `u32::MAX`
    /// seconds.
    pub fn with_wait(self, wait: Duration) -> Result<Self, ValidationError> {
        let secs = whole_seconds(wait, "read.wait")?;
        let secs = u32::try_from(secs).map_err(|_| {
            ValidationError(format!("read.wait ({secs}s) exceeds maximum {}s", u32::MAX))
        })?;
        Ok(Self {
            wait_secs: Some(secs),
            ..self
        })
    }

    /// Set the stream configuration to apply if the stream is created on read.
    ///
    /// Unset fields inherit the basin's default stream configuration. Ignored if the stream
    /// already exists.
    pub fn with_stream_config(self, stream_config: StreamConfig) -> Self {
        Self {
            stream_config: Some(stream_config),
            ..self
        }
    }

    pub(crate) fn into_api_parts(
        self,
    ) -> (
        api::stream::ReadStart,
        api::stream::ReadEnd,
        Option<StreamConfig>,
    ) {
        let (seq_num, timestamp, tail_offset) = match self.from {
            Some(ReadFrom::SeqNum(n)) => (Some(n), None, None),
            Some(ReadFrom::Timestamp(t)) => (None, Some(t), None),
            Some(ReadFrom::TailOffset(o)) => (None, None, Some(o)),
            None => (None, None, None),
        };
        let start = api::stream::ReadStart {
            seq_num,
            timestamp,
            tail_offset,
            clamp: self.clamp.then_some(true),
        };
        let end = api::stream::ReadEnd {
            count: self.count,
            bytes: self.bytes,
            until: self.until,
            wait: self.wait_secs,
        };
        (start, end, self.stream_config)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Record that is durably sequenced on a stream.
pub struct SequencedRecord {
    /// Sequence number assigned to this record.
    pub seq_num: u64,
    /// Body of this record.
    pub body: Bytes,
    /// Headers for this record.
    pub headers: Vec<Header>,
    /// Timestamp for this record.
    pub timestamp: u64,
}

impl SequencedRecord {
    /// Construct a sequenced record.
    ///
    /// This is intended for building fixtures in downstream tests.
    pub fn new(seq_num: u64, body: impl Into<Bytes>, headers: Vec<Header>, timestamp: u64) -> Self {
        Self {
            seq_num,
            body: body.into(),
            headers,
            timestamp,
        }
    }

    /// Whether this is a command record.
    pub fn is_command_record(&self) -> bool {
        self.headers.len() == 1 && *self.headers[0].name == *b""
    }
}

impl From<api::stream::proto::SequencedRecord> for SequencedRecord {
    fn from(value: api::stream::proto::SequencedRecord) -> Self {
        Self {
            seq_num: value.seq_num,
            body: value.body,
            headers: value.headers.into_iter().map(Into::into).collect(),
            timestamp: value.timestamp,
        }
    }
}

metered_bytes_impl!(SequencedRecord);

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Batch of records returned by [`read`](crate::S2Stream::read) or streamed by
/// [`read_batch_session`](crate::S2Stream::read_batch_session).
pub struct ReadBatch {
    /// Records that are durably sequenced on the stream.
    ///
    /// It can be empty only for a [`read`](crate::S2Stream::read) operation when the
    /// stop condition was already met.
    pub records: Vec<SequencedRecord>,
    /// Sequence number that will be assigned to the next record on the stream, and timestamp of
    /// the last record.
    ///
    /// It will only be present when reading recent records.
    pub tail: Option<StreamPosition>,
}

impl ReadBatch {
    /// Construct a read batch.
    ///
    /// This is intended for building fixtures in downstream tests.
    pub fn new(records: Vec<SequencedRecord>, tail: Option<StreamPosition>) -> Self {
        Self { records, tail }
    }
}

impl From<api::stream::proto::ReadBatch> for ReadBatch {
    fn from(batch: api::stream::proto::ReadBatch) -> Self {
        Self {
            records: batch.records.into_iter().map(Into::into).collect(),
            tail: batch.tail.map(Into::into),
        }
    }
}
