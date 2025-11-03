use compact_str::ToCompactString;
use s2_common::{record, types};

include!("s2.v1.rs");

impl From<StreamPosition> for types::stream::StreamPosition {
    fn from(StreamPosition { seq_num, timestamp }: StreamPosition) -> Self {
        Self { seq_num, timestamp }
    }
}

impl From<types::stream::StreamPosition> for StreamPosition {
    fn from(
        types::stream::StreamPosition { seq_num, timestamp }: types::stream::StreamPosition,
    ) -> Self {
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

impl TryFrom<AppendRecord> for types::stream::AppendRecord {
    type Error = types::ValidationError;

    fn try_from(
        AppendRecord {
            timestamp,
            headers,
            body,
        }: AppendRecord,
    ) -> Result<Self, Self::Error> {
        Ok(Self::try_from(types::stream::AppendRecordParts {
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

impl TryFrom<AppendInput> for types::stream::AppendInput {
    type Error = types::ValidationError;

    fn try_from(
        AppendInput {
            records,
            match_seq_num,
            fencing_token,
        }: AppendInput,
    ) -> Result<Self, Self::Error> {
        let records = records
            .into_iter()
            .map(types::stream::AppendRecord::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            records: types::stream::AppendRecordBatch::try_from(records)?,
            match_seq_num,
            fencing_token: fencing_token
                .as_deref()
                .map(|s| s.to_compact_string().try_into())
                .transpose()?,
        })
    }
}

impl From<types::stream::AppendInput> for AppendInput {
    fn from(
        types::stream::AppendInput {
            records,
            match_seq_num,
            fencing_token,
        }: types::stream::AppendInput,
    ) -> Self {
        let records = records
            .into_iter()
            .map(|record| {
                let types::stream::AppendRecordParts { timestamp, record } = record.into();
                let (headers, body) = record.into_inner().into_parts();
                AppendRecord {
                    timestamp,
                    headers: headers.into_iter().map(Into::into).collect(),
                    body,
                }
            })
            .collect();

        Self {
            records,
            match_seq_num,
            fencing_token: fencing_token.as_ref().map(|t| t.to_string()),
        }
    }
}

impl From<types::stream::AppendAck> for AppendAck {
    fn from(types::stream::AppendAck { start, end, tail }: types::stream::AppendAck) -> Self {
        Self {
            start: Some(start.into()),
            end: Some(end.into()),
            tail: Some(tail.into()),
        }
    }
}

impl From<AppendAck> for types::stream::AppendAck {
    fn from(AppendAck { start, end, tail }: AppendAck) -> Self {
        Self {
            start: start.unwrap_or_default().into(),
            end: end.unwrap_or_default().into(),
            tail: tail.unwrap_or_default().into(),
        }
    }
}

impl From<record::SequencedRecord> for SequencedRecord {
    fn from(
        record::SequencedRecord {
            seq_num,
            timestamp,
            record,
        }: record::SequencedRecord,
    ) -> Self {
        let (headers, body) = record.into_parts();
        Self {
            seq_num,
            timestamp,
            headers: headers.into_iter().map(Into::into).collect(),
            body,
        }
    }
}

impl TryFrom<SequencedRecord> for record::SequencedRecord {
    type Error = types::ValidationError;

    fn try_from(
        SequencedRecord {
            seq_num,
            timestamp,
            headers,
            body,
        }: SequencedRecord,
    ) -> Result<Self, Self::Error> {
        let record =
            record::Record::try_from_parts(headers.into_iter().map(Into::into).collect(), body)
                .map_err(|e| e.to_string())?;

        Ok(Self {
            seq_num,
            timestamp,
            record,
        })
    }
}

impl From<types::stream::ReadBatch> for ReadBatch {
    fn from(batch: types::stream::ReadBatch) -> Self {
        Self {
            records: batch.records.into_iter().map(Into::into).collect(),
            tail: batch.tail.map(Into::into),
        }
    }
}

impl TryFrom<ReadBatch> for types::stream::ReadBatch {
    type Error = types::ValidationError;

    fn try_from(batch: ReadBatch) -> Result<Self, Self::Error> {
        let records: Vec<_> = batch
            .records
            .into_iter()
            .map(record::SequencedRecord::try_from)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            records: records.into(),
            tail: batch.tail.map(Into::into),
        })
    }
}
