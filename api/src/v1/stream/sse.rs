use std::{str::FromStr, time::Duration};

#[cfg(feature = "axum")]
use base64ct::{Base64, Encoding as _};
use s2_common::{http::ParseableHeader, types};
use serde::Serialize;
#[cfg(feature = "axum")]
use serde::ser::{SerializeSeq, SerializeStruct, SerializeTuple};

use super::ReadBatch;
#[cfg(feature = "axum")]
use crate::data::Format;

static LAST_EVENT_ID_HEADER: http::HeaderName = http::HeaderName::from_static("last-event-id");

#[derive(Debug, Clone, Copy)]
pub struct LastEventId {
    pub seq_num: u64,
    pub count: usize,
    pub bytes: usize,
}

impl ParseableHeader for LastEventId {
    fn name() -> &'static http::HeaderName {
        &LAST_EVENT_ID_HEADER
    }
}

impl Serialize for LastEventId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl std::fmt::Display for LastEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            seq_num,
            count,
            bytes,
        } = self;
        write!(f, "{seq_num},{count},{bytes}")
    }
}

impl FromStr for LastEventId {
    type Err = types::ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.splitn(3, ",");

        fn get_next<T>(
            iter: &mut std::str::SplitN<&str>,
            field: &str,
        ) -> Result<T, types::ValidationError>
        where
            T: FromStr,
            <T as FromStr>::Err: std::fmt::Display,
        {
            let item = iter
                .next()
                .ok_or_else(|| format!("missing {field} in Last-Event-Id"))?;
            item.parse()
                .map_err(|e| format!("invalid {field} in Last-Event-ID: {e}").into())
        }

        let seq_num = get_next(&mut iter, "seq_num")?;
        let count = get_next(&mut iter, "count")?;
        let bytes = get_next(&mut iter, "bytes")?;

        Ok(Self {
            seq_num,
            count,
            bytes,
        })
    }
}

macro_rules! event {
    ($name:ident, $val:expr) => {
        #[derive(Serialize)]
        #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $name,
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                $val
            }
        }
    };
}

event!(Batch, "batch");
event!(Error, "error");
event!(Ping, "ping");

#[derive(Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(untagged)]
pub enum ReadEvent {
    #[cfg_attr(feature = "utoipa", schema(title = "batch"))]
    Batch {
        #[cfg_attr(feature = "utoipa", schema(inline))]
        event: Batch,
        data: ReadBatch,
        #[cfg_attr(feature = "utoipa", schema(value_type = String, pattern = "^[0-9]+,[0-9]+,[0-9]+$"))]
        id: LastEventId,
    },
    #[cfg_attr(feature = "utoipa", schema(title = "error"))]
    Error {
        #[cfg_attr(feature = "utoipa", schema(inline))]
        event: Error,
        data: String,
    },
    #[cfg_attr(feature = "utoipa", schema(title = "ping"))]
    Ping {
        #[cfg_attr(feature = "utoipa", schema(inline))]
        event: Ping,
        data: PingEventData,
    },
    #[cfg_attr(feature = "utoipa", schema(title = "done"))]
    #[serde(skip)]
    Done {
        #[cfg_attr(feature = "utoipa", schema(value_type = String, pattern = r"^\[DONE\]$"))]
        data: DoneEventData,
    },
}

fn elapsed_since_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("healthy clock")
}

impl ReadEvent {
    pub fn batch(data: ReadBatch, id: LastEventId) -> Self {
        Self::Batch {
            event: Batch::Batch,
            data,
            id,
        }
    }

    pub fn error(data: String) -> Self {
        Self::Error {
            event: Error::Error,
            data,
        }
    }

    pub fn ping() -> Self {
        Self::Ping {
            event: Ping::Ping,
            data: PingEventData {
                timestamp: elapsed_since_epoch().as_millis() as u64,
            },
        }
    }

    pub fn done() -> Self {
        Self::Done {
            data: DoneEventData,
        }
    }
}

#[cfg(feature = "axum")]
pub fn batch_event(
    format: Format,
    batch: &types::stream::ReadBatch,
    id: LastEventId,
) -> Result<axum::response::sse::Event, axum::Error> {
    axum::response::sse::Event::default()
        .event(Batch::Batch)
        .id(id.to_string())
        .json_data(SerializedReadBatch { format, batch })
}

#[cfg(feature = "axum")]
struct SerializedReadBatch<'a> {
    format: Format,
    batch: &'a types::stream::ReadBatch,
}

#[cfg(feature = "axum")]
impl Serialize for SerializedReadBatch<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state =
            serializer.serialize_struct("ReadBatch", 1 + usize::from(self.batch.tail.is_some()))?;
        state.serialize_field(
            "records",
            &SerializedRecords {
                format: self.format,
                records: self.batch.records.as_slice(),
            },
        )?;
        if let Some(tail) = self.batch.tail {
            state.serialize_field("tail", &SerializedStreamPosition(tail))?;
        }
        state.end()
    }
}

#[cfg(feature = "axum")]
struct SerializedRecords<'a> {
    format: Format,
    records: &'a [s2_common::record::SequencedRecord],
}

#[cfg(feature = "axum")]
impl Serialize for SerializedRecords<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.records.len()))?;
        for record in self.records {
            seq.serialize_element(&SerializedRecord {
                format: self.format,
                record,
            })?;
        }
        seq.end()
    }
}

#[cfg(feature = "axum")]
struct SerializedRecord<'a> {
    format: Format,
    record: &'a s2_common::record::SequencedRecord,
}

#[cfg(feature = "axum")]
impl Serialize for SerializedRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SequencedRecord", 4)?;
        state.serialize_field("seq_num", &self.record.position.seq_num)?;
        state.serialize_field("timestamp", &self.record.position.timestamp)?;
        match &self.record.record {
            s2_common::record::Record::Command(command) => {
                state.serialize_field(
                    "headers",
                    &SerializedCommandHeaders {
                        format: self.format,
                        command,
                    },
                )?;
                match command {
                    s2_common::record::CommandRecord::Fence(token) => {
                        if !token.is_empty() {
                            state.serialize_field(
                                "body",
                                &FormattedBytes {
                                    format: self.format,
                                    bytes: token.as_bytes(),
                                },
                            )?;
                        }
                    }
                    s2_common::record::CommandRecord::Trim(trim_point) => {
                        let bytes = trim_point.to_be_bytes();
                        state.serialize_field(
                            "body",
                            &FormattedBytes {
                                format: self.format,
                                bytes: &bytes,
                            },
                        )?;
                    }
                }
            }
            s2_common::record::Record::Envelope(envelope) => {
                if !envelope.headers().is_empty() {
                    state.serialize_field(
                        "headers",
                        &SerializedHeaders {
                            format: self.format,
                            headers: envelope.headers(),
                        },
                    )?;
                }
                if !envelope.body().is_empty() {
                    state.serialize_field(
                        "body",
                        &FormattedBytes {
                            format: self.format,
                            bytes: envelope.body().as_ref(),
                        },
                    )?;
                }
            }
        }
        state.end()
    }
}

#[cfg(feature = "axum")]
struct SerializedHeaders<'a> {
    format: Format,
    headers: &'a [s2_common::record::Header],
}

#[cfg(feature = "axum")]
impl Serialize for SerializedHeaders<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.headers.len()))?;
        for header in self.headers {
            seq.serialize_element(&SerializedHeader {
                format: self.format,
                header,
            })?;
        }
        seq.end()
    }
}

#[cfg(feature = "axum")]
struct SerializedHeader<'a> {
    format: Format,
    header: &'a s2_common::record::Header,
}

#[cfg(feature = "axum")]
impl Serialize for SerializedHeader<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&FormattedBytes {
            format: self.format,
            bytes: self.header.name.as_ref(),
        })?;
        tuple.serialize_element(&FormattedBytes {
            format: self.format,
            bytes: self.header.value.as_ref(),
        })?;
        tuple.end()
    }
}

#[cfg(feature = "axum")]
struct SerializedCommandHeaders<'a> {
    format: Format,
    command: &'a s2_common::record::CommandRecord,
}

#[cfg(feature = "axum")]
impl Serialize for SerializedCommandHeaders<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(1))?;
        seq.serialize_element(&SerializedCommandHeader {
            format: self.format,
            command: self.command,
        })?;
        seq.end()
    }
}

#[cfg(feature = "axum")]
struct SerializedCommandHeader<'a> {
    format: Format,
    command: &'a s2_common::record::CommandRecord,
}

#[cfg(feature = "axum")]
impl Serialize for SerializedCommandHeader<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&FormattedBytes {
            format: self.format,
            bytes: b"",
        })?;
        tuple.serialize_element(&FormattedBytes {
            format: self.format,
            bytes: self.command.op().to_id(),
        })?;
        tuple.end()
    }
}

#[cfg(feature = "axum")]
struct SerializedStreamPosition(s2_common::record::StreamPosition);

#[cfg(feature = "axum")]
impl Serialize for SerializedStreamPosition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("StreamPosition", 2)?;
        state.serialize_field("seq_num", &self.0.seq_num)?;
        state.serialize_field("timestamp", &self.0.timestamp)?;
        state.end()
    }
}

#[cfg(feature = "axum")]
struct FormattedBytes<'a> {
    format: Format,
    bytes: &'a [u8],
}

#[cfg(feature = "axum")]
impl Serialize for FormattedBytes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.format {
            Format::Raw => serializer.collect_str(&LossyUtf8(self.bytes)),
            Format::Base64 => serializer.collect_str(&Base64Display(self.bytes)),
        }
    }
}

#[cfg(feature = "axum")]
struct LossyUtf8<'a>(&'a [u8]);

#[cfg(feature = "axum")]
impl std::fmt::Display for LossyUtf8<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;

        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_char(char::REPLACEMENT_CHARACTER)?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "axum")]
struct Base64Display<'a>(&'a [u8]);

#[cfg(feature = "axum")]
impl std::fmt::Display for Base64Display<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const INPUT_CHUNK: usize = 3 * 256;
        const OUTPUT_CHUNK: usize = 4 * 256;

        let mut output = [0u8; OUTPUT_CHUNK];
        let mut chunks = self.0.chunks_exact(INPUT_CHUNK);
        for chunk in &mut chunks {
            let encoded = Base64::encode(chunk, &mut output).map_err(|_| std::fmt::Error)?;
            f.write_str(encoded)?;
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let encoded_len = Base64::encoded_len(remainder);
            let encoded = Base64::encode(remainder, &mut output[..encoded_len])
                .map_err(|_| std::fmt::Error)?;
            f.write_str(encoded)?;
        }

        Ok(())
    }
}

#[cfg(feature = "axum")]
impl TryFrom<ReadEvent> for axum::response::sse::Event {
    type Error = axum::Error;

    fn try_from(event: ReadEvent) -> Result<Self, Self::Error> {
        match event {
            ReadEvent::Batch { event, data, id } => Self::default()
                .event(event)
                .id(id.to_string())
                .json_data(data),
            ReadEvent::Error { event, data } => Ok(Self::default().event(event).data(data)),
            ReadEvent::Ping { event, data } => Self::default().event(event).json_data(data),
            ReadEvent::Done { data } => Ok(Self::default().data(data)),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename = "[DONE]")]
pub struct DoneEventData;

impl AsRef<str> for DoneEventData {
    fn as_ref(&self) -> &str {
        "[DONE]"
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PingEventData {
    pub timestamp: u64,
}

#[cfg(all(test, feature = "axum"))]
mod tests {
    use bytes::Bytes;
    use s2_common::record;

    use super::*;

    fn fixture_batch() -> types::stream::ReadBatch {
        let envelope = record::Record::try_from_parts(
            vec![record::Header {
                name: Bytes::from_static(b"kind"),
                value: Bytes::from(vec![b'a', 0xff, b'z']),
            }],
            Bytes::from(vec![0xf0, 0x28, 0x8c, 0xbc]),
        )
        .expect("valid envelope");

        let empty_fence = record::Record::Command(record::CommandRecord::Fence(
            "".parse().expect("valid token"),
        ));

        let trim = record::Record::Command(record::CommandRecord::Trim(42));

        types::stream::ReadBatch {
            records: vec![
                record::Metered::from(envelope).sequenced(record::StreamPosition {
                    seq_num: 7,
                    timestamp: 11,
                }),
                record::Metered::from(empty_fence).sequenced(record::StreamPosition {
                    seq_num: 8,
                    timestamp: 12,
                }),
                record::Metered::from(trim).sequenced(record::StreamPosition {
                    seq_num: 9,
                    timestamp: 13,
                }),
            ]
            .into_iter()
            .collect(),
            tail: Some(record::StreamPosition {
                seq_num: 10,
                timestamp: 14,
            }),
        }
    }

    #[test]
    fn serialized_batch_matches_existing_json_shape() {
        let batch = fixture_batch();

        for format in [Format::Raw, Format::Base64] {
            let expected =
                serde_json::to_string(&ReadBatch::encode(format, batch.clone())).expect("json");
            let actual = serde_json::to_string(&SerializedReadBatch {
                format,
                batch: &batch,
            })
            .expect("json");
            assert_eq!(actual, expected);
        }
    }
}
