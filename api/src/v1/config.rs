use std::time::Duration;

use s2_common::{maybe::Maybe, types};
use serde::{Deserialize, Serialize};
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

#[rustfmt::skip]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum StorageClass {
    /// Append tail latency under 500 ms.
    Standard,
    /// Append tail latency under 50 ms.
    Express,
}

impl From<StorageClass> for types::config::StorageClass {
    fn from(value: StorageClass) -> Self {
        match value {
            StorageClass::Express => Self::Express,
            StorageClass::Standard => Self::Standard,
        }
    }
}

impl From<types::config::StorageClass> for StorageClass {
    fn from(value: types::config::StorageClass) -> Self {
        match value {
            types::config::StorageClass::Express => Self::Express,
            types::config::StorageClass::Standard => Self::Standard,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RetentionPolicy {
    /// Age in seconds for automatic trimming of records older than this threshold.
    /// This must be set to a value greater than 0 seconds.
    Age(u64),
    /// Retain records unless explicitly trimmed.
    Infinite(InfiniteRetention)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub struct InfiniteRetention {}

impl TryFrom<RetentionPolicy> for types::config::RetentionPolicy {
    type Error = types::ValidationError;

    fn try_from(value: RetentionPolicy) -> Result<Self, Self::Error> {
        match value {
            RetentionPolicy::Age(0) => Err(types::ValidationError(
                "Age must be greater than 0 seconds".to_string(),
            )),
            RetentionPolicy::Age(age) => Ok(Self::Age(Duration::from_secs(age))),
            RetentionPolicy::Infinite(_) => Ok(Self::Infinite()),
        }
    }
}

impl From<types::config::RetentionPolicy> for RetentionPolicy {
    fn from(value: types::config::RetentionPolicy) -> Self {
        match value {
            types::config::RetentionPolicy::Age(age) => Self::Age(age.as_secs()),
            types::config::RetentionPolicy::Infinite() => Self::Infinite(InfiniteRetention {}),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum TimestampingMode {
    /// Prefer client-specified timestamp if present otherwise use arrival time.
    #[default]
    ClientPrefer,
    /// Require a client-specified timestamp and reject the append if it is missing.
    ClientRequire,
    /// Use the arrival time and ignore any client-specified timestamp.
    Arrival,
}

impl From<TimestampingMode> for types::config::TimestampingMode {
    fn from(value: TimestampingMode) -> Self {
        match value {
            TimestampingMode::ClientPrefer => Self::ClientPrefer,
            TimestampingMode::ClientRequire => Self::ClientRequire,
            TimestampingMode::Arrival => Self::Arrival,
        }
    }
}

impl From<types::config::TimestampingMode> for TimestampingMode {
    fn from(value: types::config::TimestampingMode) -> Self {
        match value {
            types::config::TimestampingMode::ClientPrefer => Self::ClientPrefer,
            types::config::TimestampingMode::ClientRequire => Self::ClientRequire,
            types::config::TimestampingMode::Arrival => Self::Arrival,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct TimestampingConfig {
    /// Timestamping mode for appends that influences how timestamps are handled.
    pub mode: Option<TimestampingMode>,
    /// Allow client-specified timestamps to exceed the arrival time.
    /// If this is `false` or not set, client timestamps will be capped at the arrival time.
    pub uncapped: Option<bool>,
}

impl TimestampingConfig {
    pub fn to_opt(config: types::config::OptionalTimestampingConfig) -> Option<Self> {
        let config = TimestampingConfig {
            mode: config.mode.map(Into::into),
            uncapped: config.uncapped,
        };
        if config == Self::default() {
            None
        } else {
            Some(config)
        }
    }
}

impl From<types::config::TimestampingConfig> for TimestampingConfig {
    fn from(value: types::config::TimestampingConfig) -> Self {
        Self {
            mode: Some(value.mode.into()),
            uncapped: Some(value.uncapped),
        }
    }
}

impl From<TimestampingConfig> for types::config::OptionalTimestampingConfig {
    fn from(value: TimestampingConfig) -> Self {
        Self {
            mode: value.mode.map(Into::into),
            uncapped: value.uncapped,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct TimestampingReconfiguration {
    /// Timestamping mode for appends that influences how timestamps are handled.
    #[serde(default, skip_serializing_if = "Maybe::is_unspecified")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<TimestampingMode>))]
    pub mode: Maybe<Option<TimestampingMode>>,
    /// Allow client-specified timestamps to exceed the arrival time.
    #[serde(default, skip_serializing_if = "Maybe::is_unspecified")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<bool>))]
    pub uncapped: Maybe<Option<bool>>,
}

impl From<TimestampingReconfiguration> for types::config::TimestampingReconfiguration {
    fn from(value: TimestampingReconfiguration) -> Self {
        Self {
            mode: value.mode.map_opt(Into::into),
            uncapped: value.uncapped,
        }
    }
}

impl From<types::config::TimestampingReconfiguration> for TimestampingReconfiguration {
    fn from(value: types::config::TimestampingReconfiguration) -> Self {
        Self {
            mode: value.mode.map_opt(Into::into),
            uncapped: value.uncapped,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct DeleteOnEmptyConfig {
    /// Minimum age in seconds before an empty stream can be deleted.
    /// Set to 0 (default) to disable delete-on-empty (don't delete automatically).
    #[serde(default)]
    pub min_age_secs: u64,
}

impl DeleteOnEmptyConfig {
    pub fn to_opt(config: types::config::OptionalDeleteOnEmptyConfig) -> Option<Self> {
        let min_age = config.min_age.unwrap_or_default();
        if min_age > Duration::ZERO {
            Some(DeleteOnEmptyConfig {
                min_age_secs: min_age.as_secs(),
            })
        } else {
            None
        }
    }
}

impl From<types::config::DeleteOnEmptyConfig> for DeleteOnEmptyConfig {
    fn from(value: types::config::DeleteOnEmptyConfig) -> Self {
        Self {
            min_age_secs: value.min_age.as_secs(),
        }
    }
}

impl From<DeleteOnEmptyConfig> for types::config::DeleteOnEmptyConfig {
    fn from(value: DeleteOnEmptyConfig) -> Self {
        Self {
            min_age: Duration::from_secs(value.min_age_secs),
        }
    }
}

impl From<DeleteOnEmptyConfig> for types::config::OptionalDeleteOnEmptyConfig {
    fn from(value: DeleteOnEmptyConfig) -> Self {
        Self {
            min_age: Some(Duration::from_secs(value.min_age_secs)),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct DeleteOnEmptyReconfiguration {
    /// Minimum age in seconds before an empty stream can be deleted.
    /// Set to 0 to disable delete-on-empty (don't delete automatically).
    #[serde(default, skip_serializing_if = "Maybe::is_unspecified")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<u64>))]
    pub min_age_secs: Maybe<Option<u64>>,
}

impl From<DeleteOnEmptyReconfiguration> for types::config::DeleteOnEmptyReconfiguration {
    fn from(value: DeleteOnEmptyReconfiguration) -> Self {
        Self {
            min_age: value.min_age_secs.map_opt(Duration::from_secs),
        }
    }
}

impl From<types::config::DeleteOnEmptyReconfiguration> for DeleteOnEmptyReconfiguration {
    fn from(value: types::config::DeleteOnEmptyReconfiguration) -> Self {
        Self {
            min_age_secs: value.min_age.map_opt(|d| d.as_secs()),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct StreamConfig {
    /// Storage class for recent writes.
    pub storage_class: Option<StorageClass>,
    /// Retention policy for the stream.
    /// If unspecified, the default is to retain records for 7 days.
    pub retention_policy: Option<RetentionPolicy>,
    /// Timestamping behavior.
    pub timestamping: Option<TimestampingConfig>,
    /// Delete-on-empty configuration.
    #[serde(default)]
    pub delete_on_empty: Option<DeleteOnEmptyConfig>,
}

impl StreamConfig {
    pub fn to_opt(config: types::config::OptionalStreamConfig) -> Option<Self> {
        let types::config::OptionalStreamConfig {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = config;

        let config = StreamConfig {
            storage_class: storage_class.map(Into::into),
            retention_policy: retention_policy.map(Into::into),
            timestamping: TimestampingConfig::to_opt(timestamping),
            delete_on_empty: DeleteOnEmptyConfig::to_opt(delete_on_empty),
        };
        if config == Self::default() {
            None
        } else {
            Some(config)
        }
    }
}

impl From<types::config::StreamConfig> for StreamConfig {
    fn from(value: types::config::StreamConfig) -> Self {
        let types::config::StreamConfig {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = value;

        Self {
            storage_class: Some(storage_class.into()),
            retention_policy: Some(retention_policy.into()),
            timestamping: Some(timestamping.into()),
            delete_on_empty: Some(delete_on_empty.into()),
        }
    }
}

impl TryFrom<StreamConfig> for types::config::OptionalStreamConfig {
    type Error = types::ValidationError;

    fn try_from(value: StreamConfig) -> Result<Self, Self::Error> {
        let StreamConfig {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = value;

        let retention_policy = match retention_policy {
            None => None,
            Some(policy) => Some(policy.try_into()?),
        };

        Ok(Self {
            storage_class: storage_class.map(Into::into),
            retention_policy,
            timestamping: timestamping.map(Into::into).unwrap_or_default(),
            delete_on_empty: delete_on_empty.map(Into::into).unwrap_or_default(),
        })
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct StreamReconfiguration {
    /// Storage class for recent writes.
    #[serde(default, skip_serializing_if = "Maybe::is_unspecified")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<StorageClass>))]
    pub storage_class: Maybe<Option<StorageClass>>,
    /// Retention policy for the stream.
    /// If unspecified, the default is to retain records for 7 days.
    #[serde(default, skip_serializing_if = "Maybe::is_unspecified")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<RetentionPolicy>))]
    pub retention_policy: Maybe<Option<RetentionPolicy>>,
    /// Timestamping behavior.
    #[serde(default, skip_serializing_if = "Maybe::is_unspecified")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<TimestampingReconfiguration>))]
    pub timestamping: Maybe<Option<TimestampingReconfiguration>>,
    /// Delete-on-empty configuration.
    #[serde(default, skip_serializing_if = "Maybe::is_unspecified")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<DeleteOnEmptyReconfiguration>))]
    pub delete_on_empty: Maybe<Option<DeleteOnEmptyReconfiguration>>,
}

impl TryFrom<StreamReconfiguration> for types::config::StreamReconfiguration {
    type Error = types::ValidationError;

    fn try_from(value: StreamReconfiguration) -> Result<Self, Self::Error> {
        let StreamReconfiguration {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = value;

        Ok(Self {
            storage_class: storage_class.map_opt(Into::into),
            retention_policy: retention_policy.try_map_opt(TryInto::try_into)?,
            timestamping: timestamping.map_opt(Into::into),
            delete_on_empty: delete_on_empty.map_opt(Into::into),
        })
    }
}

impl From<types::config::StreamReconfiguration> for StreamReconfiguration {
    fn from(value: types::config::StreamReconfiguration) -> Self {
        let types::config::StreamReconfiguration {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = value;

        Self {
            storage_class: storage_class.map_opt(Into::into),
            retention_policy: retention_policy.map_opt(Into::into),
            timestamping: timestamping.map_opt(Into::into),
            delete_on_empty: delete_on_empty.map_opt(Into::into),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct BasinConfig {
    /// Default stream configuration.
    pub default_stream_config: Option<StreamConfig>,
    /// Create stream on append if it doesn't exist, using the default stream configuration.
    #[serde(default)]
    pub create_stream_on_append: bool,
    /// Create stream on read if it doesn't exist, using the default stream configuration.
    #[serde(default)]
    pub create_stream_on_read: bool,
}

impl TryFrom<BasinConfig> for types::config::BasinConfig {
    type Error = types::ValidationError;

    fn try_from(value: BasinConfig) -> Result<Self, Self::Error> {
        let BasinConfig {
            default_stream_config,
            create_stream_on_append,
            create_stream_on_read,
        } = value;

        Ok(Self {
            default_stream_config: match default_stream_config {
                Some(config) => config.try_into()?,
                None => Default::default(),
            },
            create_stream_on_append,
            create_stream_on_read,
        })
    }
}

impl From<types::config::BasinConfig> for BasinConfig {
    fn from(value: types::config::BasinConfig) -> Self {
        let types::config::BasinConfig {
            default_stream_config,
            create_stream_on_append,
            create_stream_on_read,
        } = value;

        Self {
            default_stream_config: StreamConfig::to_opt(default_stream_config),
            create_stream_on_append,
            create_stream_on_read,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct BasinReconfiguration {
    /// Basin configuration.
    #[serde(default, skip_serializing_if = "Maybe::is_unspecified")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<StreamReconfiguration>))]
    pub default_stream_config: Maybe<Option<StreamReconfiguration>>,
    /// Create a stream on append.
    #[serde(default, skip_serializing_if = "Maybe::is_unspecified")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<bool>))]
    pub create_stream_on_append: Maybe<bool>,
    /// Create a stream on read.
    #[serde(default, skip_serializing_if = "Maybe::is_unspecified")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<bool>))]
    pub create_stream_on_read: Maybe<bool>,
}

impl TryFrom<BasinReconfiguration> for types::config::BasinReconfiguration {
    type Error = types::ValidationError;

    fn try_from(value: BasinReconfiguration) -> Result<Self, Self::Error> {
        let BasinReconfiguration {
            default_stream_config,
            create_stream_on_append,
            create_stream_on_read,
        } = value;

        Ok(Self {
            default_stream_config: default_stream_config.try_map_opt(TryInto::try_into)?,
            create_stream_on_append: create_stream_on_append.map(Into::into),
            create_stream_on_read: create_stream_on_read.map(Into::into),
        })
    }
}

impl From<types::config::BasinReconfiguration> for BasinReconfiguration {
    fn from(value: types::config::BasinReconfiguration) -> Self {
        let types::config::BasinReconfiguration {
            default_stream_config,
            create_stream_on_append,
            create_stream_on_read,
        } = value;

        Self {
            default_stream_config: default_stream_config.map_opt(Into::into),
            create_stream_on_append: create_stream_on_append.map(Into::into),
            create_stream_on_read: create_stream_on_read.map(Into::into),
        }
    }
}
