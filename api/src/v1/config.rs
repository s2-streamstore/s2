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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn gen_storage_class() -> impl Strategy<Value = StorageClass> {
        prop_oneof![Just(StorageClass::Standard), Just(StorageClass::Express)]
    }

    fn gen_timestamping_mode() -> impl Strategy<Value = TimestampingMode> {
        prop_oneof![
            Just(TimestampingMode::ClientPrefer),
            Just(TimestampingMode::ClientRequire),
            Just(TimestampingMode::Arrival),
        ]
    }

    fn gen_retention_policy() -> impl Strategy<Value = RetentionPolicy> {
        prop_oneof![
            any::<u64>().prop_map(RetentionPolicy::Age),
            Just(RetentionPolicy::Infinite(InfiniteRetention {})),
        ]
    }

    fn gen_timestamping_config() -> impl Strategy<Value = TimestampingConfig> {
        (
            proptest::option::of(gen_timestamping_mode()),
            proptest::option::of(any::<bool>()),
        )
            .prop_map(|(mode, uncapped)| TimestampingConfig { mode, uncapped })
    }

    fn gen_delete_on_empty_config() -> impl Strategy<Value = DeleteOnEmptyConfig> {
        any::<u64>().prop_map(|min_age_secs| DeleteOnEmptyConfig { min_age_secs })
    }

    fn gen_stream_config() -> impl Strategy<Value = StreamConfig> {
        (
            proptest::option::of(gen_storage_class()),
            proptest::option::of(gen_retention_policy()),
            proptest::option::of(gen_timestamping_config()),
            proptest::option::of(gen_delete_on_empty_config()),
        )
            .prop_map(
                |(storage_class, retention_policy, timestamping, delete_on_empty)| StreamConfig {
                    storage_class,
                    retention_policy,
                    timestamping,
                    delete_on_empty,
                },
            )
    }

    fn gen_basin_config() -> impl Strategy<Value = BasinConfig> {
        (
            proptest::option::of(gen_stream_config()),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(
                |(default_stream_config, create_stream_on_append, create_stream_on_read)| {
                    BasinConfig {
                        default_stream_config,
                        create_stream_on_append,
                        create_stream_on_read,
                    }
                },
            )
    }

    fn gen_maybe<T: std::fmt::Debug + Clone + 'static>(
        inner: impl Strategy<Value = T>,
    ) -> impl Strategy<Value = Maybe<Option<T>>> {
        prop_oneof![
            Just(Maybe::Unspecified),
            Just(Maybe::Specified(None)),
            inner.prop_map(|v| Maybe::Specified(Some(v))),
        ]
    }

    fn gen_stream_reconfiguration() -> impl Strategy<Value = StreamReconfiguration> {
        (
            gen_maybe(gen_storage_class()),
            gen_maybe(gen_retention_policy()),
            gen_maybe(gen_timestamping_reconfiguration()),
            gen_maybe(gen_delete_on_empty_reconfiguration()),
        )
            .prop_map(
                |(storage_class, retention_policy, timestamping, delete_on_empty)| {
                    StreamReconfiguration {
                        storage_class,
                        retention_policy,
                        timestamping,
                        delete_on_empty,
                    }
                },
            )
    }

    fn gen_timestamping_reconfiguration() -> impl Strategy<Value = TimestampingReconfiguration> {
        (gen_maybe(gen_timestamping_mode()), gen_maybe(any::<bool>()))
            .prop_map(|(mode, uncapped)| TimestampingReconfiguration { mode, uncapped })
    }

    fn gen_delete_on_empty_reconfiguration() -> impl Strategy<Value = DeleteOnEmptyReconfiguration>
    {
        gen_maybe(any::<u64>())
            .prop_map(|min_age_secs| DeleteOnEmptyReconfiguration { min_age_secs })
    }

    fn gen_basin_reconfiguration() -> impl Strategy<Value = BasinReconfiguration> {
        (
            gen_maybe(gen_stream_reconfiguration()),
            prop_oneof![
                Just(Maybe::Unspecified),
                any::<bool>().prop_map(Maybe::Specified),
            ],
            prop_oneof![
                Just(Maybe::Unspecified),
                any::<bool>().prop_map(Maybe::Specified),
            ],
        )
            .prop_map(
                |(default_stream_config, create_stream_on_append, create_stream_on_read)| {
                    BasinReconfiguration {
                        default_stream_config,
                        create_stream_on_append,
                        create_stream_on_read,
                    }
                },
            )
    }

    fn gen_internal_optional_stream_config()
    -> impl Strategy<Value = types::config::OptionalStreamConfig> {
        (
            proptest::option::of(gen_storage_class()),
            proptest::option::of(gen_retention_policy()),
            proptest::option::of(gen_timestamping_mode()),
            proptest::option::of(any::<bool>()),
            proptest::option::of(any::<u64>()),
        )
            .prop_map(|(sc, rp, ts_mode, ts_uncapped, doe)| {
                types::config::OptionalStreamConfig {
                    storage_class: sc.map(Into::into),
                    retention_policy: rp.map(|rp| match rp {
                        RetentionPolicy::Age(secs) => {
                            types::config::RetentionPolicy::Age(Duration::from_secs(secs))
                        }
                        RetentionPolicy::Infinite(_) => types::config::RetentionPolicy::Infinite(),
                    }),
                    timestamping: types::config::OptionalTimestampingConfig {
                        mode: ts_mode.map(Into::into),
                        uncapped: ts_uncapped,
                    },
                    delete_on_empty: types::config::OptionalDeleteOnEmptyConfig {
                        min_age: doe.map(Duration::from_secs),
                    },
                }
            })
    }

    proptest! {
        #[test]
        fn stream_config_conversion_validates(config in gen_stream_config()) {
            let has_zero_age = matches!(config.retention_policy, Some(RetentionPolicy::Age(0)));
            let result: Result<types::config::OptionalStreamConfig, _> = config.try_into();

            if has_zero_age {
                prop_assert!(result.is_err());
            } else {
                prop_assert!(result.is_ok());
            }
        }

        #[test]
        fn basin_config_conversion_validates(config in gen_basin_config()) {
            let has_invalid_config = config.default_stream_config.as_ref().is_some_and(|sc| {
                matches!(sc.retention_policy, Some(RetentionPolicy::Age(0)))
            });

            let result: Result<types::config::BasinConfig, _> = config.try_into();

            if has_invalid_config {
                prop_assert!(result.is_err());
            } else {
                prop_assert!(result.is_ok());
            }
        }

        #[test]
        fn stream_reconfiguration_conversion_validates(reconfig in gen_stream_reconfiguration()) {
            let has_zero_age = matches!(
                reconfig.retention_policy,
                Maybe::Specified(Some(RetentionPolicy::Age(0)))
            );
            let result: Result<types::config::StreamReconfiguration, _> = reconfig.try_into();

            if has_zero_age {
                prop_assert!(result.is_err());
            } else {
                prop_assert!(result.is_ok());
            }
        }

        #[test]
        fn merge_stream_or_basin_or_default(
            stream in gen_internal_optional_stream_config(),
            basin in gen_internal_optional_stream_config(),
        ) {
            let merged = stream.clone().merge(basin.clone());

            prop_assert_eq!(
                merged.storage_class,
                stream.storage_class.or(basin.storage_class).unwrap_or_default()
            );
            prop_assert_eq!(
                merged.retention_policy,
                stream.retention_policy.or(basin.retention_policy).unwrap_or_default()
            );
            prop_assert_eq!(
                merged.timestamping.mode,
                stream.timestamping.mode.or(basin.timestamping.mode).unwrap_or_default()
            );
            prop_assert_eq!(
                merged.timestamping.uncapped,
                stream.timestamping.uncapped.or(basin.timestamping.uncapped).unwrap_or_default()
            );
            prop_assert_eq!(
                merged.delete_on_empty.min_age,
                stream.delete_on_empty.min_age.or(basin.delete_on_empty.min_age).unwrap_or_default()
            );
        }

        #[test]
        fn reconfigure_unspecified_preserves_base(base in gen_internal_optional_stream_config()) {
            let reconfig = types::config::StreamReconfiguration::default();
            let result = base.clone().reconfigure(reconfig);

            prop_assert_eq!(result.storage_class, base.storage_class);
            prop_assert_eq!(result.retention_policy, base.retention_policy);
            prop_assert_eq!(result.timestamping.mode, base.timestamping.mode);
            prop_assert_eq!(result.timestamping.uncapped, base.timestamping.uncapped);
            prop_assert_eq!(result.delete_on_empty.min_age, base.delete_on_empty.min_age);
        }

        #[test]
        fn reconfigure_specified_none_clears(base in gen_internal_optional_stream_config()) {
            let reconfig = types::config::StreamReconfiguration {
                storage_class: Maybe::Specified(None),
                retention_policy: Maybe::Specified(None),
                timestamping: Maybe::Specified(None),
                delete_on_empty: Maybe::Specified(None),
            };
            let result = base.reconfigure(reconfig);

            prop_assert!(result.storage_class.is_none());
            prop_assert!(result.retention_policy.is_none());
            prop_assert!(result.timestamping.mode.is_none());
            prop_assert!(result.timestamping.uncapped.is_none());
            prop_assert!(result.delete_on_empty.min_age.is_none());
        }

        #[test]
        fn reconfigure_specified_some_sets_value(
            base in gen_internal_optional_stream_config(),
            new_sc in gen_storage_class(),
            new_rp_secs in 1u64..u64::MAX,
        ) {
            let reconfig = types::config::StreamReconfiguration {
                storage_class: Maybe::Specified(Some(new_sc.into())),
                retention_policy: Maybe::Specified(Some(
                    types::config::RetentionPolicy::Age(Duration::from_secs(new_rp_secs))
                )),
                ..Default::default()
            };
            let result = base.reconfigure(reconfig);

            prop_assert_eq!(result.storage_class, Some(new_sc.into()));
            prop_assert_eq!(
                result.retention_policy,
                Some(types::config::RetentionPolicy::Age(Duration::from_secs(new_rp_secs)))
            );
        }

        #[test]
        fn to_opt_returns_none_for_defaults(_unused in Just(())) {
            // default stream config -> None
            prop_assert!(StreamConfig::to_opt(types::config::OptionalStreamConfig::default()).is_none());

            // delete_on_empty: None or Some(ZERO) -> None
            let doe_none = types::config::OptionalDeleteOnEmptyConfig { min_age: None };
            let doe_zero = types::config::OptionalDeleteOnEmptyConfig { min_age: Some(Duration::ZERO) };
            prop_assert!(DeleteOnEmptyConfig::to_opt(doe_none).is_none());
            prop_assert!(DeleteOnEmptyConfig::to_opt(doe_zero).is_none());

            // default timestamping -> None
            prop_assert!(TimestampingConfig::to_opt(types::config::OptionalTimestampingConfig::default()).is_none());
        }

        #[test]
        fn to_opt_returns_some_for_non_defaults(
            sc in gen_storage_class(),
            doe_secs in 1u64..u64::MAX,
            ts_mode in gen_timestamping_mode(),
        ) {
            // non-default storage class -> Some
            let internal = types::config::OptionalStreamConfig {
                storage_class: Some(sc.into()),
                ..Default::default()
            };
            prop_assert!(StreamConfig::to_opt(internal).is_some());

            // non-zero delete_on_empty -> Some
            let internal = types::config::OptionalDeleteOnEmptyConfig {
                min_age: Some(Duration::from_secs(doe_secs)),
            };
            let api = DeleteOnEmptyConfig::to_opt(internal);
            prop_assert!(api.is_some());
            prop_assert_eq!(api.unwrap().min_age_secs, doe_secs);

            // non-default timestamping -> Some
            let internal = types::config::OptionalTimestampingConfig {
                mode: Some(ts_mode.into()),
                uncapped: None,
            };
            prop_assert!(TimestampingConfig::to_opt(internal).is_some());
        }

        #[test]
        fn basin_reconfiguration_conversion_validates(reconfig in gen_basin_reconfiguration()) {
            let has_zero_age = matches!(
                &reconfig.default_stream_config,
                Maybe::Specified(Some(sr)) if matches!(
                    sr.retention_policy,
                    Maybe::Specified(Some(RetentionPolicy::Age(0)))
                )
            );
            let result: Result<types::config::BasinReconfiguration, _> = reconfig.try_into();

            if has_zero_age {
                prop_assert!(result.is_err());
            } else {
                prop_assert!(result.is_ok());
            }
        }

        #[test]
        fn reconfigure_basin_unspecified_preserves(
            base_sc in proptest::option::of(gen_storage_class()),
            base_on_append in any::<bool>(),
            base_on_read in any::<bool>(),
        ) {
            let base = types::config::BasinConfig {
                default_stream_config: types::config::OptionalStreamConfig {
                    storage_class: base_sc.map(Into::into),
                    ..Default::default()
                },
                create_stream_on_append: base_on_append,
                create_stream_on_read: base_on_read,
            };

            let reconfig = types::config::BasinReconfiguration::default();
            let result = base.clone().reconfigure(reconfig);

            prop_assert_eq!(result.default_stream_config.storage_class, base.default_stream_config.storage_class);
            prop_assert_eq!(result.create_stream_on_append, base.create_stream_on_append);
            prop_assert_eq!(result.create_stream_on_read, base.create_stream_on_read);
        }

        #[test]
        fn reconfigure_basin_specified_updates(
            base_on_append in any::<bool>(),
            new_on_append in any::<bool>(),
            new_sc in gen_storage_class(),
        ) {
            let base = types::config::BasinConfig {
                create_stream_on_append: base_on_append,
                ..Default::default()
            };

            let reconfig = types::config::BasinReconfiguration {
                default_stream_config: Maybe::Specified(Some(types::config::StreamReconfiguration {
                    storage_class: Maybe::Specified(Some(new_sc.into())),
                    ..Default::default()
                })),
                create_stream_on_append: Maybe::Specified(new_on_append),
                ..Default::default()
            };
            let result = base.reconfigure(reconfig);

            prop_assert_eq!(result.default_stream_config.storage_class, Some(new_sc.into()));
            prop_assert_eq!(result.create_stream_on_append, new_on_append);
        }

        #[test]
        fn reconfigure_nested_partial_update(
            base_mode in gen_timestamping_mode(),
            base_uncapped in any::<bool>(),
            new_mode in gen_timestamping_mode(),
        ) {
            let base = types::config::OptionalStreamConfig {
                timestamping: types::config::OptionalTimestampingConfig {
                    mode: Some(base_mode.into()),
                    uncapped: Some(base_uncapped),
                },
                ..Default::default()
            };

            let expected_mode: types::config::TimestampingMode = new_mode.into();

            let reconfig = types::config::StreamReconfiguration {
                timestamping: Maybe::Specified(Some(types::config::TimestampingReconfiguration {
                    mode: Maybe::Specified(Some(expected_mode)),
                    uncapped: Maybe::Unspecified,
                })),
                ..Default::default()
            };
            let result = base.reconfigure(reconfig);

            prop_assert_eq!(result.timestamping.mode, Some(expected_mode));
            prop_assert_eq!(result.timestamping.uncapped, Some(base_uncapped));
        }

        #[test]
        fn empty_json_converts_to_all_none(_unused in Just(())) {
            let json = serde_json::json!({});
            let parsed: StreamConfig = serde_json::from_value(json).unwrap();
            let internal: types::config::OptionalStreamConfig = parsed.try_into().unwrap();

            prop_assert!(internal.storage_class.is_none(), "storage_class should be None");
            prop_assert!(internal.retention_policy.is_none(), "retention_policy should be None");
            prop_assert!(internal.timestamping.mode.is_none(), "timestamping.mode should be None");
            prop_assert!(internal.timestamping.uncapped.is_none(), "timestamping.uncapped should be None");
            prop_assert!(internal.delete_on_empty.min_age.is_none(), "delete_on_empty.min_age should be None");
        }
    }
}
