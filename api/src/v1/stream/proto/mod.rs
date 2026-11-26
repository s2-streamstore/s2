use bytes::BufMut;
use s2_common::record;

use crate::data::EncodeProto;

include!("s2.v1.rs");

/// Wrapper that encodes supported `s2_common` stream responses directly into protobuf wire bytes
/// without materializing intermediate generated protobuf structs (`Vec<proto::SequencedRecord>`,
/// `Vec<proto::Header>`).
#[derive(Debug)]
pub struct Direct<T>(pub T);

fn header_encoded_len(name: &[u8], value: &[u8]) -> usize {
    let mut len = 0;
    if !name.is_empty() {
        len += prost::encoding::key_len(1)
            + prost::encoding::encoded_len_varint(name.len() as u64)
            + name.len();
    }
    if !value.is_empty() {
        len += prost::encoding::key_len(2)
            + prost::encoding::encoded_len_varint(value.len() as u64)
            + value.len();
    }
    len
}

fn encode_header_raw(name: &[u8], value: &[u8], buf: &mut impl BufMut) {
    if !name.is_empty() {
        prost::encoding::encode_key(1, prost::encoding::WireType::LengthDelimited, buf);
        prost::encoding::encode_varint(name.len() as u64, buf);
        buf.put_slice(name);
    }
    if !value.is_empty() {
        prost::encoding::encode_key(2, prost::encoding::WireType::LengthDelimited, buf);
        prost::encoding::encode_varint(value.len() as u64, buf);
        buf.put_slice(value);
    }
}

fn stream_position_encoded_len(pos: record::StreamPosition) -> usize {
    let mut len = 0;
    if pos.seq_num != 0 {
        len += prost::encoding::uint64::encoded_len(1, &pos.seq_num);
    }
    if pos.timestamp != 0 {
        len += prost::encoding::uint64::encoded_len(2, &pos.timestamp);
    }
    len
}

fn encode_stream_position_raw(pos: record::StreamPosition, buf: &mut impl BufMut) {
    if pos.seq_num != 0 {
        prost::encoding::uint64::encode(1, &pos.seq_num, buf);
    }
    if pos.timestamp != 0 {
        prost::encoding::uint64::encode(2, &pos.timestamp, buf);
    }
}

fn sequenced_record_encoded_len(rec: &record::SequencedRecord) -> usize {
    let (pos, inner) = rec.parts();
    let mut len = 0;
    if pos.seq_num != 0 {
        len += prost::encoding::uint64::encoded_len(1, &pos.seq_num);
    }
    if pos.timestamp != 0 {
        len += prost::encoding::uint64::encoded_len(2, &pos.timestamp);
    }
    match inner {
        record::Record::Envelope(env) => {
            for h in env.headers() {
                let hlen = header_encoded_len(h.name.as_ref(), h.value.as_ref());
                len += prost::encoding::key_len(3)
                    + prost::encoding::encoded_len_varint(hlen as u64)
                    + hlen;
            }
            let body = env.body();
            if !body.is_empty() {
                len += prost::encoding::key_len(4)
                    + prost::encoding::encoded_len_varint(body.len() as u64)
                    + body.len();
            }
        }
        record::Record::Command(cmd) => {
            let op_id = cmd.op().to_id();
            let hlen = header_encoded_len(&[], op_id);
            len += prost::encoding::key_len(3)
                + prost::encoding::encoded_len_varint(hlen as u64)
                + hlen;
            let body_len = match cmd {
                record::CommandRecord::Fence(token) => token.len(),
                record::CommandRecord::Trim(_) => std::mem::size_of::<u64>(),
            };
            if body_len != 0 {
                len += prost::encoding::key_len(4)
                    + prost::encoding::encoded_len_varint(body_len as u64)
                    + body_len;
            }
        }
    }
    len
}

fn encode_sequenced_record_raw(rec: &record::SequencedRecord, buf: &mut impl BufMut) {
    let (pos, inner) = rec.parts();
    if pos.seq_num != 0 {
        prost::encoding::uint64::encode(1, &pos.seq_num, buf);
    }
    if pos.timestamp != 0 {
        prost::encoding::uint64::encode(2, &pos.timestamp, buf);
    }
    match inner {
        record::Record::Envelope(env) => {
            for h in env.headers() {
                let hlen = header_encoded_len(h.name.as_ref(), h.value.as_ref());
                prost::encoding::encode_key(3, prost::encoding::WireType::LengthDelimited, buf);
                prost::encoding::encode_varint(hlen as u64, buf);
                encode_header_raw(h.name.as_ref(), h.value.as_ref(), buf);
            }
            let body = env.body();
            if !body.is_empty() {
                prost::encoding::encode_key(4, prost::encoding::WireType::LengthDelimited, buf);
                prost::encoding::encode_varint(body.len() as u64, buf);
                buf.put_slice(body.as_ref());
            }
        }
        record::Record::Command(cmd) => {
            let op_id = cmd.op().to_id();
            let hlen = header_encoded_len(&[], op_id);
            prost::encoding::encode_key(3, prost::encoding::WireType::LengthDelimited, buf);
            prost::encoding::encode_varint(hlen as u64, buf);
            encode_header_raw(&[], op_id, buf);
            match cmd {
                record::CommandRecord::Fence(token) => {
                    let body = token.as_bytes();
                    if !body.is_empty() {
                        prost::encoding::encode_key(
                            4,
                            prost::encoding::WireType::LengthDelimited,
                            buf,
                        );
                        prost::encoding::encode_varint(body.len() as u64, buf);
                        buf.put_slice(body);
                    }
                }
                record::CommandRecord::Trim(trim_point) => {
                    let body = trim_point.to_be_bytes();
                    prost::encoding::encode_key(4, prost::encoding::WireType::LengthDelimited, buf);
                    prost::encoding::encode_varint(body.len() as u64, buf);
                    buf.put_slice(&body);
                }
            }
        }
    }
}

fn read_batch_encoded_len(
    records: &[record::SequencedRecord],
    tail: Option<record::StreamPosition>,
) -> usize {
    let mut len = 0;
    for rec in records {
        let rlen = sequenced_record_encoded_len(rec);
        len +=
            prost::encoding::key_len(1) + prost::encoding::encoded_len_varint(rlen as u64) + rlen;
    }
    if let Some(pos) = tail {
        let plen = stream_position_encoded_len(pos);
        len +=
            prost::encoding::key_len(2) + prost::encoding::encoded_len_varint(plen as u64) + plen;
    }
    len
}

fn encode_read_batch_raw(
    records: &[record::SequencedRecord],
    tail: Option<record::StreamPosition>,
    buf: &mut impl BufMut,
) {
    for rec in records {
        let rlen = sequenced_record_encoded_len(rec);
        prost::encoding::encode_key(1, prost::encoding::WireType::LengthDelimited, buf);
        prost::encoding::encode_varint(rlen as u64, buf);
        encode_sequenced_record_raw(rec, buf);
    }
    if let Some(pos) = tail {
        let plen = stream_position_encoded_len(pos);
        prost::encoding::encode_key(2, prost::encoding::WireType::LengthDelimited, buf);
        prost::encoding::encode_varint(plen as u64, buf);
        encode_stream_position_raw(pos, buf);
    }
}

impl EncodeProto for Direct<s2_common::stream::ReadBatch> {
    fn encoded_len(&self) -> usize {
        read_batch_encoded_len(self.0.records.as_slice(), self.0.tail)
    }

    fn encode_raw(&self, buf: &mut impl BufMut) {
        encode_read_batch_raw(self.0.records.as_slice(), self.0.tail, buf);
    }
}

impl EncodeProto for Direct<s2_common::stream::ReadSessionOutput> {
    fn encoded_len(&self) -> usize {
        match &self.0 {
            s2_common::stream::ReadSessionOutput::Heartbeat(tail) => {
                read_batch_encoded_len(&[], Some(*tail))
            }
            s2_common::stream::ReadSessionOutput::Batch(batch) => {
                read_batch_encoded_len(batch.records.as_slice(), batch.tail)
            }
        }
    }

    fn encode_raw(&self, buf: &mut impl BufMut) {
        match &self.0 {
            s2_common::stream::ReadSessionOutput::Heartbeat(tail) => {
                encode_read_batch_raw(&[], Some(*tail), buf);
            }
            s2_common::stream::ReadSessionOutput::Batch(batch) => {
                encode_read_batch_raw(batch.records.as_slice(), batch.tail, buf);
            }
        }
    }
}

impl From<record::StreamPosition> for StreamPosition {
    fn from(record::StreamPosition { seq_num, timestamp }: record::StreamPosition) -> Self {
        Self { seq_num, timestamp }
    }
}

impl From<Header> for record::Header {
    fn from(Header { name, value }: Header) -> Self {
        Self { name, value }
    }
}

impl From<record::Header> for Header {
    fn from(record::Header { name, value }: record::Header) -> Self {
        Self { name, value }
    }
}

impl TryFrom<AppendRecord> for s2_common::stream::AppendRecord {
    type Error = s2_common::ValidationError;

    fn try_from(
        AppendRecord {
            timestamp,
            headers,
            body,
        }: AppendRecord,
    ) -> Result<Self, Self::Error> {
        Ok(Self::try_from(s2_common::stream::AppendRecordParts {
            timestamp,
            record: record::Record::try_from_parts(
                headers.into_iter().map(Into::into).collect(),
                body,
            )
            .map_err(|e| e.to_string())?
            .into(),
        })?)
    }
}

impl TryFrom<AppendInput> for s2_common::stream::AppendInput {
    type Error = s2_common::ValidationError;

    fn try_from(
        AppendInput {
            records,
            match_seq_num,
            fencing_token,
        }: AppendInput,
    ) -> Result<Self, Self::Error> {
        let records = records
            .into_iter()
            .map(s2_common::stream::AppendRecord::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            records: s2_common::stream::AppendRecordBatch::try_from(records)?,
            match_seq_num,
            fencing_token: fencing_token.map(TryInto::try_into).transpose()?,
        })
    }
}

impl From<s2_common::stream::AppendAck> for AppendAck {
    fn from(
        s2_common::stream::AppendAck { start, end, tail }: s2_common::stream::AppendAck,
    ) -> Self {
        Self {
            start: Some(start.into()),
            end: Some(end.into()),
            tail: Some(tail.into()),
        }
    }
}

impl From<record::SequencedRecord> for SequencedRecord {
    fn from(record: record::SequencedRecord) -> Self {
        let (record::StreamPosition { seq_num, timestamp }, record) = record.into_parts();
        let (headers, body) = record.into_parts();
        Self {
            seq_num,
            timestamp,
            headers: headers.into_iter().map(Into::into).collect(),
            body,
        }
    }
}

impl From<s2_common::stream::ReadBatch> for ReadBatch {
    fn from(batch: s2_common::stream::ReadBatch) -> Self {
        Self {
            records: batch.records.into_iter().map(Into::into).collect(),
            tail: batch.tail.map(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use prost::Message as _;
    use s2_common::{
        record::{
            CommandRecord, EnvelopeRecord, FencingToken, Header as CommonHeader, Metered, Record,
            SequencedRecord as CommonSequencedRecord, StreamPosition as CommonStreamPosition,
        },
        stream::{ReadBatch as CommonReadBatch, ReadSessionOutput},
    };

    use super::*;

    fn assert_direct_batch_matches_prost(batch: CommonReadBatch) {
        let expected_proto = ReadBatch::from(batch.clone());
        let expected_bytes = expected_proto.encode_to_vec();

        let direct = Direct(batch.clone());
        let encoded_len = direct.encoded_len();
        assert_eq!(encoded_len, expected_bytes.len());
        let mut actual_bytes = Vec::with_capacity(encoded_len);
        direct.encode_raw(&mut actual_bytes);
        assert_eq!(actual_bytes, expected_bytes);

        let direct_out = Direct(ReadSessionOutput::Batch(batch));
        assert_eq!(direct_out.encoded_len(), expected_bytes.len());
        let mut actual_out_bytes = Vec::with_capacity(expected_bytes.len());
        direct_out.encode_raw(&mut actual_out_bytes);
        assert_eq!(actual_out_bytes, expected_bytes);
    }

    #[test]
    fn direct_read_batch_and_output_match_prost_byte_for_byte() {
        // Heartbeats (including zero position).
        for tail in [
            CommonStreamPosition {
                seq_num: 0,
                timestamp: 0,
            },
            CommonStreamPosition {
                seq_num: 42,
                timestamp: 1_700_000_000,
            },
            CommonStreamPosition {
                seq_num: u64::MAX,
                timestamp: u64::MAX,
            },
        ] {
            let expected = ReadBatch {
                records: vec![],
                tail: Some(tail.into()),
            }
            .encode_to_vec();
            let direct = Direct(ReadSessionOutput::Heartbeat(tail));
            assert_eq!(direct.encoded_len(), expected.len());
            let mut actual = Vec::with_capacity(expected.len());
            direct.encode_raw(&mut actual);
            assert_eq!(actual, expected);
        }

        // Hand-crafted edge cases: empty batch, zero seq/ts, EnvelopeRecord with empty body,
        // >=128-byte headers (multi-byte varint), CommandRecord::Fence (empty + non-empty),
        // CommandRecord::Trim (0 + u64::MAX), tail None & Some.
        let edge_records = vec![
            CommonSequencedRecord::new(
                CommonStreamPosition {
                    seq_num: 0,
                    timestamp: 0,
                },
                Record::Envelope(EnvelopeRecord::try_from_parts(vec![], Bytes::new()).unwrap()),
            ),
            CommonSequencedRecord::new(
                CommonStreamPosition {
                    seq_num: 1,
                    timestamp: 0,
                },
                Record::Envelope(
                    EnvelopeRecord::try_from_parts(
                        vec![
                            CommonHeader {
                                name: Bytes::from(vec![b'k'; 160]),
                                value: Bytes::from(vec![b'v'; 200]),
                            },
                            CommonHeader {
                                name: Bytes::from_static(b"empty-val"),
                                value: Bytes::new(),
                            },
                        ],
                        Bytes::from(vec![0xAB; 256]),
                    )
                    .unwrap(),
                ),
            ),
            CommonSequencedRecord::new(
                CommonStreamPosition {
                    seq_num: 2,
                    timestamp: 99,
                },
                Record::Command(CommandRecord::Fence(FencingToken::try_from("").unwrap())),
            ),
            CommonSequencedRecord::new(
                CommonStreamPosition {
                    seq_num: 3,
                    timestamp: 100,
                },
                Record::Command(CommandRecord::Fence(
                    FencingToken::try_from("fence-tok-1").unwrap(),
                )),
            ),
            CommonSequencedRecord::new(
                CommonStreamPosition {
                    seq_num: 4,
                    timestamp: u64::MAX,
                },
                Record::Command(CommandRecord::Trim(0)),
            ),
            CommonSequencedRecord::new(
                CommonStreamPosition {
                    seq_num: u64::MAX,
                    timestamp: 123_456,
                },
                Record::Command(CommandRecord::Trim(u64::MAX)),
            ),
        ];

        assert_direct_batch_matches_prost(CommonReadBatch {
            records: Metered::from(Vec::new()),
            tail: None,
        });
        assert_direct_batch_matches_prost(CommonReadBatch {
            records: Metered::from(edge_records.clone()),
            tail: None,
        });
        assert_direct_batch_matches_prost(CommonReadBatch {
            records: Metered::from(edge_records),
            tail: Some(CommonStreamPosition {
                seq_num: 5,
                timestamp: 999,
            }),
        });

        // Deterministic randomized property check across 200 varied ReadBatch shapes.
        let mut seed: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for _ in 0..200 {
            let num_records = (next_u64() % 10) as usize;
            let mut records = Vec::with_capacity(num_records);
            for _ in 0..num_records {
                let pos = CommonStreamPosition {
                    seq_num: match next_u64() % 4 {
                        0 => 0,
                        1 => 1,
                        2 => u64::MAX,
                        _ => next_u64(),
                    },
                    timestamp: match next_u64() % 4 {
                        0 => 0,
                        1 => 1,
                        2 => u64::MAX,
                        _ => next_u64(),
                    },
                };
                let rec = match next_u64() % 6 {
                    0 => Record::Command(CommandRecord::Trim(next_u64())),
                    1 => {
                        let flen = (next_u64() % 16) as usize;
                        let tok: String = (0..flen)
                            .map(|_| (b'a' + (next_u64() % 26) as u8) as char)
                            .collect();
                        Record::Command(CommandRecord::Fence(FencingToken::try_from(tok).unwrap()))
                    }
                    _ => {
                        let body_len = match next_u64() % 6 {
                            0 => 0,
                            1 => 1,
                            2 => 127,
                            3 => 128,
                            _ => (next_u64() % 512) as usize,
                        };
                        let body: Vec<u8> =
                            (0..body_len).map(|_| (next_u64() & 0xFF) as u8).collect();
                        let num_headers = (next_u64() % 5) as usize;
                        let mut headers = Vec::with_capacity(num_headers);
                        for _ in 0..num_headers {
                            let nlen = (next_u64() % 16) as usize + 1;
                            let vlen = match next_u64() % 5 {
                                0 => 0,
                                1 => 150,
                                _ => (next_u64() % 24) as usize,
                            };
                            let name: Vec<u8> =
                                (0..nlen).map(|_| (next_u64() & 0xFF) as u8).collect();
                            let value: Vec<u8> =
                                (0..vlen).map(|_| (next_u64() & 0xFF) as u8).collect();
                            headers.push(CommonHeader {
                                name: Bytes::from(name),
                                value: Bytes::from(value),
                            });
                        }
                        Record::Envelope(
                            EnvelopeRecord::try_from_parts(headers, Bytes::from(body)).unwrap(),
                        )
                    }
                };
                records.push(CommonSequencedRecord::new(pos, rec));
            }
            let tail = match next_u64() % 3 {
                0 => None,
                1 => Some(CommonStreamPosition {
                    seq_num: 0,
                    timestamp: 0,
                }),
                _ => Some(CommonStreamPosition {
                    seq_num: next_u64(),
                    timestamp: next_u64(),
                }),
            };
            assert_direct_batch_matches_prost(CommonReadBatch {
                records: Metered::from(records),
                tail,
            });
        }
    }
}
