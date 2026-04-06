use base64ct::{Base64, Encoding as _};
use s2_common::{record, types};
use serde::{
    Serialize,
    ser::{SerializeSeq, SerializeStruct, SerializeTuple},
};

use crate::data::Format;

pub fn serialize_read_batch(
    format: Format,
    batch: &types::stream::ReadBatch,
) -> impl Serialize + '_ {
    ReadBatchJson { format, batch }
}

struct ReadBatchJson<'a> {
    format: Format,
    batch: &'a types::stream::ReadBatch,
}

impl Serialize for ReadBatchJson<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state =
            serializer.serialize_struct("ReadBatch", 1 + usize::from(self.batch.tail.is_some()))?;
        state.serialize_field(
            "records",
            &RecordsJson {
                format: self.format,
                records: self.batch.records.as_slice(),
            },
        )?;
        if let Some(tail) = self.batch.tail {
            state.serialize_field("tail", &StreamPositionJson(tail))?;
        }
        state.end()
    }
}

struct RecordsJson<'a> {
    format: Format,
    records: &'a [record::SequencedRecord],
}

impl Serialize for RecordsJson<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.records.len()))?;
        for record in self.records {
            seq.serialize_element(&RecordJson {
                format: self.format,
                record,
            })?;
        }
        seq.end()
    }
}

struct RecordJson<'a> {
    format: Format,
    record: &'a record::SequencedRecord,
}

impl Serialize for RecordJson<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Some records omit `headers` and/or `body`, but `serde_json` does not rely on an exact
        // field count here, so keep the fixed upper bound and avoid extra bookkeeping.
        let mut state = serializer.serialize_struct("SequencedRecord", 4)?;
        let position = self.record.position();
        state.serialize_field("seq_num", &position.seq_num)?;
        state.serialize_field("timestamp", &position.timestamp)?;
        match self.record.inner() {
            record::Record::Command(command) => {
                state.serialize_field(
                    "headers",
                    &CommandHeadersJson {
                        format: self.format,
                        command,
                    },
                )?;
                match command {
                    record::CommandRecord::Fence(token) => {
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
                    record::CommandRecord::Trim(trim_point) => {
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
            record::Record::Envelope(envelope) => {
                if !envelope.headers().is_empty() {
                    state.serialize_field(
                        "headers",
                        &HeadersJson {
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

struct HeadersJson<'a> {
    format: Format,
    headers: &'a [record::Header],
}

impl Serialize for HeadersJson<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.headers.len()))?;
        for header in self.headers {
            seq.serialize_element(&HeaderJson {
                format: self.format,
                header,
            })?;
        }
        seq.end()
    }
}

struct HeaderJson<'a> {
    format: Format,
    header: &'a record::Header,
}

impl Serialize for HeaderJson<'_> {
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

struct CommandHeadersJson<'a> {
    format: Format,
    command: &'a record::CommandRecord,
}

impl Serialize for CommandHeadersJson<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(1))?;
        seq.serialize_element(&CommandHeaderJson {
            format: self.format,
            command: self.command,
        })?;
        seq.end()
    }
}

struct CommandHeaderJson<'a> {
    format: Format,
    command: &'a record::CommandRecord,
}

impl Serialize for CommandHeaderJson<'_> {
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

struct StreamPositionJson(record::StreamPosition);

impl Serialize for StreamPositionJson {
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

struct FormattedBytes<'a> {
    format: Format,
    bytes: &'a [u8],
}

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

struct LossyUtf8<'a>(&'a [u8]);

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

struct Base64Display<'a>(&'a [u8]);

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

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use s2_common::record::MeteredExt;

    use super::*;
    use crate::v1::stream::ReadBatch;

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

        let non_empty_fence = record::Record::Command(record::CommandRecord::Fence(
            "token-1".parse().expect("valid token"),
        ));

        let trim = record::Record::Command(record::CommandRecord::Trim(42));

        types::stream::ReadBatch {
            records: vec![
                envelope.metered().sequenced(record::StreamPosition {
                    seq_num: 7,
                    timestamp: 11,
                }),
                empty_fence.metered().sequenced(record::StreamPosition {
                    seq_num: 8,
                    timestamp: 12,
                }),
                non_empty_fence.metered().sequenced(record::StreamPosition {
                    seq_num: 9,
                    timestamp: 13,
                }),
                trim.metered().sequenced(record::StreamPosition {
                    seq_num: 10,
                    timestamp: 14,
                }),
            ]
            .into_iter()
            .collect(),
            tail: Some(record::StreamPosition {
                seq_num: 11,
                timestamp: 15,
            }),
        }
    }

    #[test]
    fn serialized_batch_matches_existing_json_shape() {
        let batch = fixture_batch();

        for format in [Format::Raw, Format::Base64] {
            let expected =
                serde_json::to_value(ReadBatch::encode(format, batch.clone())).expect("json");
            let actual = serde_json::to_value(serialize_read_batch(format, &batch)).expect("json");
            assert_eq!(actual, expected);
        }
    }
}
