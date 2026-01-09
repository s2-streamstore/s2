#[cfg(feature = "axum")]
pub mod extract;

pub mod proto;
pub mod s2s;
pub mod sse;

use std::time::Duration;

use futures::stream::BoxStream;
use itertools::Itertools as _;
use s2_common::{
    record,
    types::{
        self,
        stream::{StreamName, StreamNamePrefix, StreamNameStartAfter},
    },
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::config::StreamConfig;
use crate::{data::Format, mime::JsonOrProto};

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct StreamInfo {
    /// Stream name.
    pub name: StreamName,
    /// Creation time in RFC 3339 format.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Deletion time in RFC 3339 format, if the stream is being deleted.
    #[serde(with = "time::serde::rfc3339::option")]
    pub deleted_at: Option<OffsetDateTime>,
}

impl From<types::stream::StreamInfo> for StreamInfo {
    fn from(value: types::stream::StreamInfo) -> Self {
        Self {
            name: value.name,
            created_at: value.created_at,
            deleted_at: value.deleted_at,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct ListStreamsRequest {
    /// Filter to streams whose name begins with this prefix.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub prefix: Option<StreamNamePrefix>,
    /// Filter to streams whose name begins with this prefix.
    /// It must be greater than or equal to the `prefix` if specified.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub start_after: Option<StreamNameStartAfter>,
    /// Number of results, up to a maximum of 1000.
    #[cfg_attr(feature = "utoipa", param(value_type = usize, maximum = 1000, default = 1000, required = false))]
    pub limit: Option<usize>,
}

super::impl_list_request_conversions!(
    ListStreamsRequest,
    types::stream::StreamNamePrefix,
    types::stream::StreamNameStartAfter
);

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ListStreamsResponse {
    /// Matching streams.
    #[cfg_attr(feature = "utoipa", schema(max_items = 1000))]
    pub streams: Vec<StreamInfo>,
    /// Indicates that there are more results that match the criteria.
    pub has_more: bool,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateStreamRequest {
    /// Stream name that is unique to the basin.
    /// It can be between 1 and 512 bytes in length.
    pub stream: StreamName,
    /// Stream configuration.
    pub config: Option<StreamConfig>,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
/// Position of a record in a stream.
pub struct StreamPosition {
    /// Sequence number assigned by the service.
    pub seq_num: record::SeqNum,
    /// Timestamp, which may be client-specified or assigned by the service.
    /// If it is assigned by the service, it will represent milliseconds since Unix epoch.
    pub timestamp: record::Timestamp,
}

impl From<record::StreamPosition> for StreamPosition {
    fn from(pos: record::StreamPosition) -> Self {
        Self {
            seq_num: pos.seq_num,
            timestamp: pos.timestamp,
        }
    }
}

impl From<StreamPosition> for record::StreamPosition {
    fn from(pos: StreamPosition) -> Self {
        Self {
            seq_num: pos.seq_num,
            timestamp: pos.timestamp,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TailResponse {
    /// Sequence number that will be assigned to the next record on the stream, and timestamp of the last record.
    pub tail: StreamPosition,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct ReadStart {
    /// Start from a sequence number.
    #[cfg_attr(feature = "utoipa", param(value_type = record::SeqNum, required = false))]
    pub seq_num: Option<record::SeqNum>,
    /// Start from a timestamp.
    #[cfg_attr(feature = "utoipa", param(value_type = record::Timestamp, required = false))]
    pub timestamp: Option<record::Timestamp>,
    /// Start from number of records before the next sequence number.
    #[cfg_attr(feature = "utoipa", param(value_type = u64, required = false))]
    pub tail_offset: Option<u64>,
    /// Start reading from the tail if the requested position is beyond it.
    /// Otherwise, a `416 Range Not Satisfiable` response is returned.
    #[cfg_attr(feature = "utoipa", param(value_type = bool, required = false))]
    pub clamp: Option<bool>,
}

impl TryFrom<ReadStart> for types::stream::ReadStart {
    type Error = types::ValidationError;

    fn try_from(value: ReadStart) -> Result<Self, Self::Error> {
        let from = match (value.seq_num, value.timestamp, value.tail_offset) {
            (Some(seq_num), None, None) => types::stream::ReadFrom::SeqNum(seq_num),
            (None, Some(timestamp), None) => types::stream::ReadFrom::Timestamp(timestamp),
            (None, None, Some(tail_offset)) => types::stream::ReadFrom::TailOffset(tail_offset),
            (None, None, None) => types::stream::ReadFrom::TailOffset(0),
            _ => {
                return Err(types::ValidationError(
                    "only one of seq_num, timestamp, or tail_offset can be provided".to_owned(),
                ));
            }
        };
        let clamp = value.clamp.unwrap_or(false);
        Ok(Self { from, clamp })
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct ReadEnd {
    /// Record count limit.
    /// Non-streaming reads are capped by the default limit of 1000 records.
    #[cfg_attr(feature = "utoipa", param(value_type = u64, required = false))]
    pub count: Option<usize>,
    /// Metered bytes limit.
    /// Non-streaming reads are capped by the default limit of 1 MiB.
    #[cfg_attr(feature = "utoipa", param(value_type = usize, required = false))]
    pub bytes: Option<usize>,
    /// Exclusive timestamp to read until.
    #[cfg_attr(feature = "utoipa", param(value_type = record::Timestamp, required = false))]
    pub until: Option<record::Timestamp>,
    /// Duration in seconds to wait for new records.
    /// The default duration is 0 if there is a bound on `count`, `bytes`, or `until`, and otherwise infinite.
    /// Non-streaming reads are always bounded on `count` and `bytes`, so you can achieve long poll semantics by specifying a non-zero duration up to 60 seconds.
    /// In the context of an SSE or S2S streaming read, the duration will bound how much time can elapse between records throughout the lifetime of the session.
    #[cfg_attr(feature = "utoipa", param(value_type = u32, required = false))]
    pub wait: Option<u32>,
}

impl From<ReadEnd> for types::stream::ReadEnd {
    fn from(value: ReadEnd) -> Self {
        Self {
            limit: s2_common::read_extent::ReadLimit::from_count_and_bytes(
                value.count,
                value.bytes,
            ),
            until: value.until.into(),
            wait: value.wait.map(|w| Duration::from_secs(w as u64)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReadRequest {
    /// Unary
    Unary {
        format: Format,
        response_mime: JsonOrProto,
    },
    /// Server-Sent Events streaming response
    EventStream {
        format: Format,
        last_event_id: Option<sse::LastEventId>,
    },
    /// S2S streaming response
    S2s {
        response_compression: s2s::CompressionAlgorithm,
    },
}

pub enum AppendRequest {
    /// Unary
    Unary {
        input: types::stream::AppendInput,
        response_mime: JsonOrProto,
    },
    /// S2S bi-directional streaming
    S2s {
        inputs: BoxStream<'static, Result<types::stream::AppendInput, AppendInputStreamError>>,
        response_compression: s2s::CompressionAlgorithm,
    },
}

impl std::fmt::Debug for AppendRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppendRequest::Unary {
                input,
                response_mime: response,
            } => f
                .debug_struct("AppendRequest::Unary")
                .field("input", input)
                .field("response", response)
                .finish(),
            AppendRequest::S2s { .. } => f.debug_struct("AppendRequest::S2s").finish(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppendInputStreamError {
    #[error("Failed to decode S2S frame: {0}")]
    FrameDecode(#[from] std::io::Error),
    #[error(transparent)]
    Validation(#[from] types::ValidationError),
}

/// Headers add structured information to a record as name-value pairs.
///
/// The name cannot be empty, with the exception of an S2 command record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Header(pub String, pub String);

#[rustfmt::skip]
/// Record that is durably sequenced on a stream.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct SequencedRecord {
    /// Sequence number assigned by the service.
    pub seq_num: record::SeqNum,
    /// Timestamp for this record.
    pub timestamp: record::Timestamp,
    /// Series of name-value pairs for this record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "utoipa", schema(required = false))]
    pub headers: Vec<Header>,
    /// Body of the record.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "utoipa", schema(required = false))]
    pub body: String,
}

impl SequencedRecord {
    pub fn encode(
        format: Format,
        record::SequencedRecord {
            position: record::StreamPosition { seq_num, timestamp },
            record,
        }: record::SequencedRecord,
    ) -> Self {
        let (headers, body) = record.into_parts();
        Self {
            seq_num,
            timestamp,
            headers: headers
                .into_iter()
                .map(|h| Header(format.encode(&h.name), format.encode(&h.value)))
                .collect(),
            body: format.encode(&body),
        }
    }
}

#[rustfmt::skip]
/// Record to be appended to a stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AppendRecord {
    /// Timestamp for this record.
    /// The service will always ensure monotonicity by adjusting it up if necessary to the maximum observed timestamp.
    /// Refer to stream timestamping configuration for the finer semantics around whether a client-specified timestamp is required, and whether it will be capped at the arrival time.
    pub timestamp: Option<record::Timestamp>,
    /// Series of name-value pairs for this record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "utoipa", schema(required = false))]
    pub headers: Vec<Header>,
    /// Body of the record.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "utoipa", schema(required = false))]
    pub body: String,
}

impl AppendRecord {
    pub fn decode(
        self,
        format: Format,
    ) -> Result<types::stream::AppendRecord, types::ValidationError> {
        let headers = self
            .headers
            .into_iter()
            .map(|Header(name, value)| {
                Ok::<record::Header, types::ValidationError>(record::Header {
                    name: format.decode(name)?,
                    value: format.decode(value)?,
                })
            })
            .try_collect()?;

        let body = format.decode(self.body)?;

        let record = record::Record::try_from_parts(headers, body)
            .map_err(|e| e.to_string())?
            .into();

        let parts = types::stream::AppendRecordParts {
            timestamp: self.timestamp,
            record,
        };

        types::stream::AppendRecord::try_from(parts)
            .map_err(|e| types::ValidationError(e.to_string()))
    }
}

#[rustfmt::skip]
/// Payload of an `append` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AppendInput {
    /// Batch of records to append atomically, which must contain at least one record, and no more than 1000.
    /// The total size of a batch of records may not exceed 1 MiB of metered bytes.
    pub records: Vec<AppendRecord>,
    /// Enforce that the sequence number assigned to the first record matches.
    pub match_seq_num: Option<record::SeqNum>,
    /// Enforce a fencing token, which starts out as an empty string that can be overridden by a `fence` command record.
    pub fencing_token: Option<record::FencingToken>,
}

impl AppendInput {
    pub fn decode(
        self,
        format: Format,
    ) -> Result<types::stream::AppendInput, types::ValidationError> {
        let records: Vec<types::stream::AppendRecord> = self
            .records
            .into_iter()
            .map(|record| record.decode(format))
            .try_collect()?;

        Ok(types::stream::AppendInput {
            records: types::stream::AppendRecordBatch::try_from(records)?,
            match_seq_num: self.match_seq_num,
            fencing_token: self.fencing_token,
        })
    }
}

#[rustfmt::skip]
/// Success response to an `append` request.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AppendAck {
    /// Sequence number and timestamp of the first record that was appended.
    pub start: StreamPosition,
    /// Sequence number of the last record that was appended `+ 1`, and timestamp of the last record that was appended.
    /// The difference between `end.seq_num` and `start.seq_num` will be the number of records appended.
    pub end: StreamPosition,
    /// Sequence number that will be assigned to the next record on the stream, and timestamp of the last record on the stream.
    /// This can be greater than the `end` position in case of concurrent appends.
    pub tail: StreamPosition,
}

impl From<types::stream::AppendAck> for AppendAck {
    fn from(ack: types::stream::AppendAck) -> Self {
        Self {
            start: ack.start.into(),
            end: ack.end.into(),
            tail: ack.tail.into(),
        }
    }
}

#[rustfmt::skip]
/// Aborted due to a failed condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AppendConditionFailed {
    /// Fencing token did not match.
    /// The expected fencing token is returned.
    #[cfg_attr(feature = "utoipa", schema(title = "fencing token"))]
    FencingTokenMismatch(record::FencingToken),
    /// Sequence number did not match the tail of the stream.
    /// The expected next sequence number is returned.
    #[cfg_attr(feature = "utoipa", schema(title = "seq num"))]
    SeqNumMismatch(record::SeqNum),
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ReadBatch {
    /// Records that are durably sequenced on the stream, retrieved based on the requested criteria.
    /// This can only be empty in response to a unary read (i.e. not SSE), if the request cannot be satisfied without violating an explicit bound (`count`, `bytes`, or `until`).
    pub records: Vec<SequencedRecord>,
    /// Sequence number that will be assigned to the next record on the stream, and timestamp of the last record.
    /// This will only be present when reading recent records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tail: Option<StreamPosition>,
}

impl ReadBatch {
    pub fn encode(format: Format, batch: types::stream::ReadBatch) -> Self {
        Self {
            records: batch
                .records
                .into_iter()
                .map(|record| SequencedRecord::encode(format, record))
                .collect(),
            tail: batch.tail.map(Into::into),
        }
    }
}
