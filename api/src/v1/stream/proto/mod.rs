use compact_str::ToCompactString;
use s2_common::record;

use crate::v1::config;

include!("s2.v1.rs");

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

impl StorageClass {
    /// Decode a raw enumeration value, treating unknown and unspecified values as unset.
    fn decode_opt(value: i32) -> Option<config::StorageClass> {
        match Self::try_from(value).ok()? {
            Self::Unspecified => None,
            Self::Standard => Some(config::StorageClass::Standard),
            Self::Express => Some(config::StorageClass::Express),
        }
    }
}

impl From<config::StorageClass> for StorageClass {
    fn from(value: config::StorageClass) -> Self {
        match value {
            config::StorageClass::Standard => Self::Standard,
            config::StorageClass::Express => Self::Express,
        }
    }
}

impl TimestampingMode {
    /// Decode a raw enumeration value, treating unknown and unspecified values as unset.
    fn decode_opt(value: i32) -> Option<config::TimestampingMode> {
        match Self::try_from(value).ok()? {
            Self::Unspecified => None,
            Self::ClientPrefer => Some(config::TimestampingMode::ClientPrefer),
            Self::ClientRequire => Some(config::TimestampingMode::ClientRequire),
            Self::Arrival => Some(config::TimestampingMode::Arrival),
        }
    }
}

impl From<config::TimestampingMode> for TimestampingMode {
    fn from(value: config::TimestampingMode) -> Self {
        match value {
            config::TimestampingMode::ClientPrefer => Self::ClientPrefer,
            config::TimestampingMode::ClientRequire => Self::ClientRequire,
            config::TimestampingMode::Arrival => Self::Arrival,
        }
    }
}

impl From<TimestampingConfig> for config::TimestampingConfig {
    fn from(TimestampingConfig { mode, uncapped }: TimestampingConfig) -> Self {
        Self {
            mode: mode.and_then(TimestampingMode::decode_opt),
            uncapped,
        }
    }
}

impl From<config::TimestampingConfig> for TimestampingConfig {
    fn from(config::TimestampingConfig { mode, uncapped }: config::TimestampingConfig) -> Self {
        Self {
            mode: mode.map(|mode| TimestampingMode::from(mode) as i32),
            uncapped,
        }
    }
}

impl From<DeleteOnEmptyConfig> for config::DeleteOnEmptyConfig {
    fn from(DeleteOnEmptyConfig { min_age_secs }: DeleteOnEmptyConfig) -> Self {
        Self { min_age_secs }
    }
}

impl From<config::DeleteOnEmptyConfig> for DeleteOnEmptyConfig {
    fn from(config::DeleteOnEmptyConfig { min_age_secs }: config::DeleteOnEmptyConfig) -> Self {
        Self { min_age_secs }
    }
}

impl From<stream_config::RetentionPolicy> for config::RetentionPolicy {
    fn from(value: stream_config::RetentionPolicy) -> Self {
        match value {
            stream_config::RetentionPolicy::Age(age) => Self::Age(age),
            stream_config::RetentionPolicy::Infinite(_) => {
                Self::Infinite(config::InfiniteRetention {})
            }
        }
    }
}

impl From<config::RetentionPolicy> for stream_config::RetentionPolicy {
    fn from(value: config::RetentionPolicy) -> Self {
        match value {
            config::RetentionPolicy::Age(age) => Self::Age(age),
            config::RetentionPolicy::Infinite(_) => {
                Self::Infinite(stream_config::InfiniteRetention {})
            }
        }
    }
}

impl From<StreamConfig> for config::StreamConfig {
    fn from(
        StreamConfig {
            storage_class,
            timestamping,
            delete_on_empty,
            retention_policy,
        }: StreamConfig,
    ) -> Self {
        Self {
            storage_class: storage_class.and_then(StorageClass::decode_opt),
            retention_policy: retention_policy.map(Into::into),
            timestamping: timestamping.map(Into::into),
            delete_on_empty: delete_on_empty.map(Into::into),
        }
    }
}

impl From<config::StreamConfig> for StreamConfig {
    fn from(
        config::StreamConfig {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        }: config::StreamConfig,
    ) -> Self {
        Self {
            storage_class: storage_class.map(|class| StorageClass::from(class) as i32),
            retention_policy: retention_policy.map(Into::into),
            timestamping: timestamping.map(Into::into),
            delete_on_empty: delete_on_empty.map(Into::into),
        }
    }
}

impl TryFrom<AppendInput> for s2_common::stream::AppendMessage {
    type Error = s2_common::ValidationError;

    fn try_from(
        AppendInput {
            records,
            match_seq_num,
            fencing_token,
            create_stream_config,
        }: AppendInput,
    ) -> Result<Self, Self::Error> {
        let records = records
            .into_iter()
            .map(s2_common::stream::AppendRecord::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            input: s2_common::stream::AppendInput {
                records: s2_common::stream::AppendRecordBatch::try_from(records)?,
                match_seq_num,
                fencing_token: fencing_token
                    .as_deref()
                    .map(|s| s.to_compact_string().try_into())
                    .transpose()?,
            },
            create_stream_config: create_stream_config
                .map(|proto_config| config::StreamConfig::from(proto_config).try_into())
                .transpose()?
                .unwrap_or_default(),
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
