use std::{
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
    str::FromStr,
};

use bytes::Bytes;
use rand::RngExt;
use s2_api::v1 as api;
use s2_common::record::MAX_FENCING_TOKEN_LENGTH;

use super::{RECORD_BATCH_MAX, StreamConfig};
use crate::error::{ProtocolError, ValidationError};

/// Token for fencing appends to a stream.
///
/// **Note:** It must not exceed 36 bytes in length.
///
/// See [`CommandRecord::fence`] and [`AppendInput::fencing_token`].
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FencingToken(String);

impl FencingToken {
    pub(crate) fn from_server(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        Self::validate_len(self.0.len())
    }

    pub(crate) fn validate_len(len: usize) -> Result<(), ValidationError> {
        if len > MAX_FENCING_TOKEN_LENGTH {
            return Err(ValidationError(format!(
                "fencing token exceeds {MAX_FENCING_TOKEN_LENGTH} bytes in length",
            )));
        }
        Ok(())
    }

    /// Generate a random alphanumeric fencing token of `n` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `n` exceeds `36`.
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

/// A position in a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    #[must_use]
    pub fn new(seq_num: u64, timestamp: u64) -> Self {
        Self { seq_num, timestamp }
    }

    pub(crate) fn from_proto(value: api::stream::proto::StreamPosition) -> Self {
        Self {
            seq_num: value.seq_num,
            timestamp: value.timestamp,
        }
    }

    pub(crate) fn from_api(value: api::stream::StreamPosition) -> Self {
        Self {
            seq_num: value.seq_num,
            timestamp: value.timestamp,
        }
    }
}

impl fmt::Display for StreamPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seq_num={}, timestamp={}", self.seq_num, self.timestamp)
    }
}

/// A name-value pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[must_use]
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

    #[cfg(test)]
    pub(crate) fn into_proto(self) -> api::stream::proto::Header {
        api::stream::proto::Header {
            name: self.name,
            value: self.value,
        }
    }

    pub(crate) fn from_proto(value: api::stream::proto::Header) -> Self {
        Self {
            name: value.name,
            value: value.value,
        }
    }
}

/// Metered byte size calculation.
///
/// Formula for a record:
/// ```text
/// 8 + 2 * len(headers) + sum(len(h.name) + len(h.value) for h in headers) + len(body)
/// ```
///
/// Every record, batch, and input type also exposes an inherent `metered_bytes(&self) -> usize`
/// method so callers do not need to import this trait for concrete types.
pub trait MeteredBytes {
    /// Returns the metered byte size.
    #[must_use]
    fn metered_bytes(&self) -> usize;
}

fn record_metered_bytes(headers: &[Header], body: &[u8]) -> usize {
    let mut total = 8usize.saturating_add(headers.len().saturating_mul(2));
    for h in headers {
        total = total
            .saturating_add(h.name.len())
            .saturating_add(h.value.len());
    }
    total.saturating_add(body.len())
}

/// A record to append.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
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
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if the record's metered size exceeds `1 MiB`.
    pub fn new(body: impl Into<Bytes>) -> Result<Self, ValidationError> {
        let record = Self {
            body: body.into(),
            headers: Vec::default(),
            timestamp: None,
        };
        record.validate()
    }

    /// Return the body of this record.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Return the headers of this record.
    #[must_use]
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Return the timestamp of this record, if set.
    #[must_use]
    pub fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }

    /// Return the metered byte size of this record.
    #[must_use]
    pub fn metered_bytes(&self) -> usize {
        record_metered_bytes(&self.headers, &self.body)
    }

    /// Set the headers for this record.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if the resulting record's metered size exceeds `1 MiB`.
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

    pub(crate) fn validate_for_write(&self) -> Result<(), ValidationError> {
        if self.headers.len() == 1
            && self.headers[0].name.is_empty()
            && self.headers[0].value.as_ref() == CommandRecord::FENCE
        {
            FencingToken::validate_len(self.body.len())?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn into_proto(self) -> api::stream::proto::AppendRecord {
        api::stream::proto::AppendRecord {
            timestamp: self.timestamp,
            headers: self.headers.into_iter().map(Header::into_proto).collect(),
            body: self.body,
        }
    }
}

impl MeteredBytes for AppendRecord {
    fn metered_bytes(&self) -> usize {
        Self::metered_bytes(self)
    }
}

/// A batch of records to append atomically.
///
/// Must contain at least `1` record and no more than `1000`, with a total metered size not
/// exceeding `1 MiB`.
///
/// See [`Batcher`](crate::batching::Batcher) for automatic batching of records that handles these
/// constraints.
#[derive(Clone)]
#[must_use]
pub struct AppendRecordBatch {
    records: Vec<AppendRecord>,
    metered_bytes: usize,
}

impl fmt::Debug for AppendRecordBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AppendRecordBatch")
            .field(&self.records)
            .finish()
    }
}

impl PartialEq for AppendRecordBatch {
    fn eq(&self, other: &Self) -> bool {
        self.records == other.records
    }
}

impl Eq for AppendRecordBatch {}

impl Hash for AppendRecordBatch {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.records.hash(state);
    }
}

impl From<AppendRecord> for AppendRecordBatch {
    fn from(record: AppendRecord) -> Self {
        let metered_bytes = record.metered_bytes();
        Self {
            records: vec![record],
            metered_bytes,
        }
    }
}

impl From<CommandRecord> for AppendRecordBatch {
    fn from(record: CommandRecord) -> Self {
        Self::from(AppendRecord::from(record))
    }
}

impl AppendRecordBatch {
    pub(crate) fn from_parts(records: Vec<AppendRecord>, metered_bytes: usize) -> Self {
        debug_assert!(!records.is_empty());
        debug_assert!(records.len() <= RECORD_BATCH_MAX.count);
        debug_assert!(metered_bytes <= RECORD_BATCH_MAX.bytes);
        Self {
            records,
            metered_bytes,
        }
    }

    /// Try to create an [`AppendRecordBatch`] from an iterator of records.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if the iterator is empty, contains more than `1000` records,
    /// or exceeds `1 MiB` in total metered bytes.
    pub fn try_from_iter<I, R>(iter: I) -> Result<Self, ValidationError>
    where
        I: IntoIterator<Item = R>,
        R: Into<AppendRecord>,
    {
        let iter = iter.into_iter();
        let cap = iter.size_hint().0.min(RECORD_BATCH_MAX.count);
        let mut records = Vec::with_capacity(cap);
        let mut metered_bytes = 0usize;

        for record in iter {
            let record = record.into();
            metered_bytes = metered_bytes.saturating_add(record.metered_bytes());
            records.push(record);

            if metered_bytes > RECORD_BATCH_MAX.bytes {
                return Err(ValidationError(format!(
                    "batch size in metered bytes ({metered_bytes}) exceeds {}",
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

        Ok(Self::from_parts(records, metered_bytes))
    }

    /// Return the total metered byte size of this batch.
    #[must_use]
    pub fn metered_bytes(&self) -> usize {
        self.metered_bytes
    }
}

impl Deref for AppendRecordBatch {
    type Target = [AppendRecord];

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

impl MeteredBytes for AppendRecordBatch {
    fn metered_bytes(&self) -> usize {
        Self::metered_bytes(self)
    }
}

impl IntoIterator for AppendRecordBatch {
    type Item = AppendRecord;
    type IntoIter = std::vec::IntoIter<AppendRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.records.into_iter()
    }
}

impl<'a> IntoIterator for &'a AppendRecordBatch {
    type Item = &'a AppendRecord;
    type IntoIter = std::slice::Iter<'a, AppendRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.records.iter()
    }
}

/// Command to signal an operation on a stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
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

/// Command record for signaling operations to the service.
///
/// See [here](https://s2.dev/docs/rest/records/overview#command-records) for more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct CommandRecord {
    command: Command,
    timestamp: Option<u64>,
}

impl CommandRecord {
    const FENCE: &[u8] = b"fence";
    const TRIM: &[u8] = b"trim";

    /// Create a command record from a [`Command`].
    pub fn new(command: Command) -> Self {
        Self {
            command,
            timestamp: None,
        }
    }

    /// Create a fence command record with the given fencing token.
    ///
    /// Fencing is strongly consistent, and subsequent appends that specify a
    /// fencing token will fail if it does not match.
    pub fn fence(fencing_token: FencingToken) -> Self {
        Self::new(Command::Fence { fencing_token })
    }

    /// Create a trim command record with the given trim point.
    ///
    /// Trim point is the desired earliest sequence number for the stream.
    ///
    /// Trimming is eventually consistent, and trimmed records may be visible
    /// for a brief period.
    pub fn trim(trim_point: u64) -> Self {
        Self::new(Command::Trim { trim_point })
    }

    /// Return the command carried by this record.
    #[must_use]
    pub fn command(&self) -> &Command {
        &self.command
    }

    /// Return the timestamp of this record, if set.
    #[must_use]
    pub fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }

    /// Return the metered byte size of this command record.
    #[must_use]
    pub fn metered_bytes(&self) -> usize {
        // 8 (record overhead) + 2 * 1 (one header) + 0 (empty header name) + header value + body
        match &self.command {
            Command::Fence { fencing_token } => 10 + Self::FENCE.len() + fencing_token.len(),
            Command::Trim { .. } => 10 + Self::TRIM.len() + 8,
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

impl From<Command> for CommandRecord {
    fn from(command: Command) -> Self {
        Self::new(command)
    }
}

impl MeteredBytes for CommandRecord {
    fn metered_bytes(&self) -> usize {
        Self::metered_bytes(self)
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

/// Input for [`append`](crate::S2Stream::append),
/// [`append_with_stream_config`](crate::S2Stream::append_with_stream_config), and
/// [`AppendSession::submit`](crate::append_session::AppendSession::submit).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct AppendInput {
    records: AppendRecordBatch,
    match_seq_num: Option<u64>,
    fencing_token: Option<FencingToken>,
}

impl AppendInput {
    /// Create a new [`AppendInput`] with the given batch or record.
    ///
    /// Accepts an [`AppendRecordBatch`], [`AppendRecord`], or [`CommandRecord`].
    pub fn new(records: impl Into<AppendRecordBatch>) -> Self {
        Self {
            records: records.into(),
            match_seq_num: None,
            fencing_token: None,
        }
    }

    /// Return the batch of records to append atomically.
    #[must_use]
    pub fn records(&self) -> &AppendRecordBatch {
        &self.records
    }

    /// Return the expected sequence number for the first record in the batch, if set.
    #[must_use]
    pub fn match_seq_num(&self) -> Option<u64> {
        self.match_seq_num
    }

    /// Return the fencing token to match against the stream's current fencing token, if set.
    #[must_use]
    pub fn fencing_token(&self) -> Option<&FencingToken> {
        self.fencing_token.as_ref()
    }

    /// Return the total metered byte size of the records in this input.
    #[must_use]
    pub fn metered_bytes(&self) -> usize {
        self.records.metered_bytes()
    }

    pub(crate) fn validate_for_write(&self) -> Result<(), ValidationError> {
        if let Some(token) = &self.fencing_token {
            token.validate()?;
        }
        for record in &self.records.records {
            record.validate_for_write()?;
        }
        Ok(())
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

    pub(crate) fn encode_proto_to(&self, buf: &mut impl bytes::BufMut) {
        encode_append_input_parts(
            &self.records.records,
            self.match_seq_num,
            self.fencing_token.as_deref(),
            buf,
        );
    }

    pub(crate) fn proto_encoded_len(&self) -> usize {
        append_input_parts_encoded_len(
            &self.records.records,
            self.match_seq_num,
            self.fencing_token.as_deref(),
        )
    }

    #[cfg(test)]
    pub(crate) fn into_proto(self) -> api::stream::proto::AppendInput {
        api::stream::proto::AppendInput {
            records: self
                .records
                .into_iter()
                .map(AppendRecord::into_proto)
                .collect(),
            match_seq_num: self.match_seq_num,
            fencing_token: self.fencing_token.map(|t| t.0),
        }
    }
}

fn header_proto_encoded_len(header: &Header) -> usize {
    let mut len = 0;
    if !header.name.is_empty() {
        len += prost::encoding::bytes::encoded_len(1, &header.name);
    }
    if !header.value.is_empty() {
        len += prost::encoding::bytes::encoded_len(2, &header.value);
    }
    len
}

fn encode_header_proto(header: &Header, buf: &mut impl bytes::BufMut) {
    if !header.name.is_empty() {
        prost::encoding::bytes::encode(1, &header.name, buf);
    }
    if !header.value.is_empty() {
        prost::encoding::bytes::encode(2, &header.value, buf);
    }
}

fn append_record_proto_encoded_len(record: &AppendRecord) -> usize {
    let mut len = 0;
    if let Some(timestamp) = record.timestamp {
        len += prost::encoding::uint64::encoded_len(1, &timestamp);
    }
    for header in &record.headers {
        let hlen = header_proto_encoded_len(header);
        len +=
            prost::encoding::key_len(2) + prost::encoding::encoded_len_varint(hlen as u64) + hlen;
    }
    if !record.body.is_empty() {
        len += prost::encoding::bytes::encoded_len(3, &record.body);
    }
    len
}

fn encode_append_record_proto(record: &AppendRecord, buf: &mut impl bytes::BufMut) {
    if let Some(timestamp) = record.timestamp {
        prost::encoding::uint64::encode(1, &timestamp, buf);
    }
    for header in &record.headers {
        let hlen = header_proto_encoded_len(header);
        prost::encoding::encode_key(2, prost::encoding::WireType::LengthDelimited, buf);
        prost::encoding::encode_varint(hlen as u64, buf);
        encode_header_proto(header, buf);
    }
    if !record.body.is_empty() {
        prost::encoding::bytes::encode(3, &record.body, buf);
    }
}

fn append_input_parts_encoded_len(
    records: &[AppendRecord],
    match_seq_num: Option<u64>,
    fencing_token: Option<&str>,
) -> usize {
    let mut len = 0;
    for record in records {
        let rlen = append_record_proto_encoded_len(record);
        len +=
            prost::encoding::key_len(1) + prost::encoding::encoded_len_varint(rlen as u64) + rlen;
    }
    if let Some(seq) = match_seq_num {
        len += prost::encoding::uint64::encoded_len(2, &seq);
    }
    if let Some(token) = fencing_token {
        len += prost::encoding::key_len(3)
            + prost::encoding::encoded_len_varint(token.len() as u64)
            + token.len();
    }
    len
}

fn encode_append_input_parts(
    records: &[AppendRecord],
    match_seq_num: Option<u64>,
    fencing_token: Option<&str>,
    buf: &mut impl bytes::BufMut,
) {
    for record in records {
        let rlen = append_record_proto_encoded_len(record);
        prost::encoding::encode_key(1, prost::encoding::WireType::LengthDelimited, buf);
        prost::encoding::encode_varint(rlen as u64, buf);
        encode_append_record_proto(record, buf);
    }
    if let Some(seq) = match_seq_num {
        prost::encoding::uint64::encode(2, &seq, buf);
    }
    if let Some(token) = fencing_token {
        prost::encoding::encode_key(3, prost::encoding::WireType::LengthDelimited, buf);
        prost::encoding::encode_varint(token.len() as u64, buf);
        buf.put_slice(token.as_bytes());
    }
}

impl MeteredBytes for AppendInput {
    fn metered_bytes(&self) -> usize {
        Self::metered_bytes(self)
    }
}

impl From<AppendRecordBatch> for AppendInput {
    fn from(records: AppendRecordBatch) -> Self {
        Self::new(records)
    }
}

impl From<AppendRecord> for AppendInput {
    fn from(record: AppendRecord) -> Self {
        Self::new(record)
    }
}

impl From<CommandRecord> for AppendInput {
    fn from(record: CommandRecord) -> Self {
        Self::new(record)
    }
}

/// Acknowledgement for an [`AppendInput`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    #[must_use]
    pub fn new(start: StreamPosition, end: StreamPosition, tail: StreamPosition) -> Self {
        Self { start, end, tail }
    }

    pub(crate) fn try_from_proto(
        value: api::stream::proto::AppendAck,
        expected_records: u64,
    ) -> Result<Self, ProtocolError> {
        let start = StreamPosition::from_proto(
            value
                .start
                .ok_or_else(|| ProtocolError::new("append ack missing start position"))?,
        );
        let end = StreamPosition::from_proto(
            value
                .end
                .ok_or_else(|| ProtocolError::new("append ack missing end position"))?,
        );
        let tail = StreamPosition::from_proto(
            value
                .tail
                .ok_or_else(|| ProtocolError::new("append ack missing tail position"))?,
        );
        let ack = Self { start, end, tail };
        ack.validate_record_count(expected_records)?;
        Ok(ack)
    }

    pub(crate) fn validate_record_count(&self, expected_records: u64) -> Result<(), ProtocolError> {
        let Some(num_acked_records) = self.end.seq_num.checked_sub(self.start.seq_num) else {
            return Err(ProtocolError::new(
                "ack end seq_num should be greater than or equal to start seq_num",
            ));
        };
        if num_acked_records != expected_records {
            return Err(ProtocolError::new(format!(
                "acked record count {num_acked_records} does not match submitted batch size {expected_records}"
            )));
        }
        Ok(())
    }
}

/// Starting position for reading from a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadStart {
    /// Read from this sequence number.
    SeqNum(u64),
    /// Read from this timestamp.
    Timestamp(u64),
    /// Read from N records before the tail.
    TailOffset(u64),
}

/// Input for [`read`](crate::S2Stream::read), [`read_session`](crate::S2Stream::read_session),
/// and [`read_batch_session`](crate::S2Stream::read_batch_session) operations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct ReadInput {
    start: Option<ReadStart>,
    clamp: bool,
    count: Option<u64>,
    bytes: Option<u64>,
    until: Option<u64>,
    wait_secs: Option<u32>,
    stream_config: Option<StreamConfig>,
}

impl From<ReadStart> for ReadInput {
    fn from(start: ReadStart) -> Self {
        Self::new().with_start(start)
    }
}

impl ReadInput {
    /// Create a new [`ReadInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the starting position, if specified (otherwise begins at the tail).
    #[must_use]
    pub fn start(&self) -> Option<ReadStart> {
        self.start
    }

    /// Return whether to start from the tail if the requested starting position is beyond it.
    #[must_use]
    pub fn clamp(&self) -> bool {
        self.clamp
    }

    /// Return the limit on number of records, if set.
    #[must_use]
    pub fn count(&self) -> Option<u64> {
        self.count
    }

    /// Return the limit on total metered bytes of records, if set.
    #[must_use]
    pub fn bytes(&self) -> Option<u64> {
        self.bytes
    }

    /// Return the exclusive stop timestamp, if set.
    #[must_use]
    pub fn until(&self) -> Option<u64> {
        self.until
    }

    /// Return the number of seconds to wait for new records before stopping, if set.
    #[must_use]
    pub fn wait_secs(&self) -> Option<u32> {
        self.wait_secs
    }

    /// Return the stream configuration to apply if the stream is created on read, if set.
    #[must_use]
    pub fn stream_config(&self) -> Option<&StreamConfig> {
        self.stream_config.as_ref()
    }

    /// Set the starting position.
    ///
    /// Defaults to `None` (no start parameter is sent, causing the API to begin at the tail).
    pub fn with_start(self, start: ReadStart) -> Self {
        Self {
            start: Some(start),
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
    /// Defaults to `1 MiB` for non-streaming [`read`](crate::S2Stream::read).
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

    /// Set the number of seconds to wait for new records before stopping.
    ///
    /// Will be clamped to `60` seconds for [`read`](crate::S2Stream::read).
    ///
    /// Defaults to:
    /// - `0` (no wait) for [`read`](crate::S2Stream::read).
    /// - `0` (no wait) for [`read_session`](crate::S2Stream::read_session) and
    ///   [`read_batch_session`](crate::S2Stream::read_batch_session) if `count`, `bytes`, or
    ///   `until` is specified.
    /// - Infinite wait for [`read_session`](crate::S2Stream::read_session) and
    ///   [`read_batch_session`](crate::S2Stream::read_batch_session) if none of `count`, `bytes`,
    ///   or `until` is specified.
    pub fn with_wait_secs(self, wait_secs: u32) -> Self {
        Self {
            wait_secs: Some(wait_secs),
            ..self
        }
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
        let (seq_num, timestamp, tail_offset) = match self.start {
            Some(ReadStart::SeqNum(n)) => (Some(n), None, None),
            Some(ReadStart::Timestamp(t)) => (None, Some(t), None),
            Some(ReadStart::TailOffset(o)) => (None, None, Some(o)),
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

/// Record that is durably sequenced on a stream.
///
/// Note: `body` and header `Bytes` slices may share the backing allocation of the network chunk
/// or batch frame they were decoded from. Copy into an independent allocation (for example via
/// `.to_vec()` or `Bytes::copy_from_slice`) if retaining small records long-term independently of
/// their batch (`Bytes::clone` still shares the underlying buffer).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    #[must_use]
    pub fn new(seq_num: u64, body: impl Into<Bytes>, headers: Vec<Header>, timestamp: u64) -> Self {
        Self {
            seq_num,
            body: body.into(),
            headers,
            timestamp,
        }
    }

    /// Whether this is a command record (exactly one header with an empty name).
    #[must_use]
    pub fn is_command_record(&self) -> bool {
        self.headers.len() == 1 && self.headers[0].name.is_empty()
    }

    /// Decode this record as a recognized [`Command`] (`fence` or `trim`), if applicable.
    ///
    /// Returns `None` for regular records, unrecognized future command types, or malformed
    /// command payloads. Use [`is_command_record`](Self::is_command_record) to distinguish any
    /// command record (including unrecognized future commands) from regular data records.
    #[must_use]
    pub fn command(&self) -> Option<Command> {
        if !self.is_command_record() {
            return None;
        }
        match self.headers[0].value.as_ref() {
            CommandRecord::FENCE => {
                let token = std::str::from_utf8(&self.body).ok()?;
                Some(Command::Fence {
                    fencing_token: FencingToken::from_server(token.to_owned()),
                })
            }
            CommandRecord::TRIM => {
                let bytes: [u8; 8] = self.body.as_ref().try_into().ok()?;
                Some(Command::Trim {
                    trim_point: u64::from_be_bytes(bytes),
                })
            }
            _ => None,
        }
    }

    /// Return the metered byte size of this record.
    #[must_use]
    pub fn metered_bytes(&self) -> usize {
        record_metered_bytes(&self.headers, &self.body)
    }

    pub(crate) fn from_proto(value: api::stream::proto::SequencedRecord) -> Self {
        Self {
            seq_num: value.seq_num,
            body: value.body,
            headers: value.headers.into_iter().map(Header::from_proto).collect(),
            timestamp: value.timestamp,
        }
    }
}

impl MeteredBytes for SequencedRecord {
    fn metered_bytes(&self) -> usize {
        Self::metered_bytes(self)
    }
}

/// Batch of records returned by [`read`](crate::S2Stream::read) or streamed by
/// [`read_batch_session`](crate::S2Stream::read_batch_session).
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    #[must_use]
    pub fn new(records: Vec<SequencedRecord>, tail: Option<StreamPosition>) -> Self {
        Self { records, tail }
    }

    /// Return the sum of metered byte sizes across all records in this batch.
    #[must_use]
    pub fn metered_bytes(&self) -> usize {
        self.records
            .iter()
            .fold(0usize, |acc, r| acc.saturating_add(r.metered_bytes()))
    }

    pub(crate) fn from_proto(batch: api::stream::proto::ReadBatch) -> Self {
        Self {
            records: batch
                .records
                .into_iter()
                .map(SequencedRecord::from_proto)
                .collect(),
            tail: batch.tail.map(StreamPosition::from_proto),
        }
    }
}

impl MeteredBytes for ReadBatch {
    fn metered_bytes(&self) -> usize {
        Self::metered_bytes(self)
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    #[test]
    fn direct_append_input_proto_encode_matches_prost_byte_for_byte() {
        let cases = vec![
            AppendInput::new(AppendRecord::new("").unwrap()),
            AppendInput::new(
                AppendRecord::new("hello")
                    .unwrap()
                    .with_timestamp(0)
                    .with_headers([
                        Header::new("", ""),
                        Header::new("k", ""),
                        Header::new("", "v"),
                        Header::new("name", "value"),
                    ])
                    .unwrap(),
            )
            .with_match_seq_num(0)
            .with_fencing_token(FencingToken::try_from("").unwrap()),
            AppendInput::new(
                AppendRecordBatch::try_from_iter([
                    AppendRecord::new(vec![0xAB; 4096])
                        .unwrap()
                        .with_timestamp(u64::MAX)
                        .with_headers([Header::new("h1", "v1"), Header::new("h2", "v2")])
                        .unwrap(),
                    AppendRecord::from(CommandRecord::fence(
                        FencingToken::try_from("tok-123").unwrap(),
                    )),
                    AppendRecord::from(CommandRecord::trim(42)).with_timestamp(123456),
                    AppendRecord::new(Bytes::new()).unwrap(),
                    AppendRecord::new(vec![0x5Au8; 200])
                        .unwrap()
                        .with_headers(vec![Header::new(vec![b'k'; 160], vec![b'v'; 200])])
                        .unwrap(),
                ])
                .unwrap(),
            )
            .with_match_seq_num(u64::MAX - 4)
            .with_fencing_token(FencingToken::try_from("fence-token").unwrap()),
        ];

        for input in cases {
            let expected_proto = input.clone().into_proto();
            let expected_bytes = expected_proto.encode_to_vec();

            let encoded_len = input.proto_encoded_len();
            assert_eq!(encoded_len, expected_bytes.len());

            let mut actual_bytes = Vec::with_capacity(encoded_len);
            input.encode_proto_to(&mut actual_bytes);
            assert_eq!(actual_bytes, expected_bytes);

            let decoded =
                api::stream::proto::AppendInput::decode(Bytes::from(actual_bytes)).unwrap();
            assert_eq!(decoded, expected_proto);
        }

        // Deterministic randomized property check across 200 varied AppendInput shapes.
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for _ in 0..200 {
            let num_records = (next_u64() % 8) as usize + 1;
            let mut records = Vec::with_capacity(num_records);
            for _ in 0..num_records {
                let body_len = match next_u64() % 6 {
                    0 => 0,
                    1 => 1,
                    2 => 127,
                    3 => 128,
                    _ => (next_u64() % 512) as usize,
                };
                let body: Vec<u8> = (0..body_len).map(|_| (next_u64() & 0xFF) as u8).collect();
                let mut rec = AppendRecord::new(body).unwrap();
                match next_u64() % 4 {
                    0 => {}
                    1 => rec = rec.with_timestamp(0),
                    2 => rec = rec.with_timestamp(u64::MAX),
                    _ => rec = rec.with_timestamp(next_u64()),
                }
                let num_headers = (next_u64() % 5) as usize;
                let mut headers = Vec::with_capacity(num_headers);
                for _ in 0..num_headers {
                    let nlen = (next_u64() % 16) as usize;
                    let vlen = (next_u64() % 24) as usize;
                    let name: Vec<u8> = (0..nlen).map(|_| (next_u64() & 0xFF) as u8).collect();
                    let value: Vec<u8> = (0..vlen).map(|_| (next_u64() & 0xFF) as u8).collect();
                    if num_headers > 1 && name.is_empty() {
                        headers.push(Header::new(b"k".as_slice(), value));
                    } else {
                        headers.push(Header::new(name, value));
                    }
                }
                if !headers.is_empty() {
                    rec = rec.with_headers(headers).unwrap();
                }
                records.push(rec);
            }
            let mut input = AppendInput::new(AppendRecordBatch::try_from_iter(records).unwrap());
            match next_u64() % 3 {
                0 => {}
                1 => input = input.with_match_seq_num(0),
                _ => input = input.with_match_seq_num(next_u64()),
            }
            match next_u64() % 3 {
                0 => {}
                1 => input = input.with_fencing_token(FencingToken::try_from("").unwrap()),
                _ => {
                    let flen = (next_u64() % 20) as usize + 1;
                    let tok: String = (0..flen)
                        .map(|_| (b'a' + (next_u64() % 26) as u8) as char)
                        .collect();
                    input = input.with_fencing_token(FencingToken::try_from(tok).unwrap());
                }
            }

            let expected_proto = input.clone().into_proto();
            let expected_bytes = expected_proto.encode_to_vec();
            let encoded_len = input.proto_encoded_len();
            assert_eq!(encoded_len, expected_bytes.len());

            let mut actual_bytes = Vec::with_capacity(encoded_len);
            input.encode_proto_to(&mut actual_bytes);
            assert_eq!(actual_bytes, expected_bytes);
        }
    }
}
