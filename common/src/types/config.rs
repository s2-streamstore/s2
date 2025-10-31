use std::time::Duration;

use enum_ordinalize::Ordinalize;

use crate::maybe::Maybe;

#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    strum::Display,
    strum::IntoStaticStr,
    strum::EnumIter,
    strum::FromRepr,
    strum::EnumString,
    PartialEq,
    Eq,
    Ordinalize,
)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[repr(u8)]
pub enum StorageClass {
    #[strum(serialize = "standard")]
    Standard = 1,
    #[default]
    #[strum(serialize = "express")]
    Express = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionPolicy {
    Age(Duration),
    Infinite(),
}

impl RetentionPolicy {
    pub fn age(&self) -> Option<Duration> {
        match self {
            Self::Age(duration) => Some(*duration),
            Self::Infinite() => None,
        }
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        const ONE_WEEK: Duration = Duration::from_secs(7 * 24 * 60 * 60);

        Self::Age(ONE_WEEK)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TimestampingMode {
    #[default]
    ClientPrefer,
    ClientRequire,
    Arrival,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimestampingConfig {
    pub mode: TimestampingMode,
    pub uncapped: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeleteOnEmptyConfig {
    pub min_age: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamConfig {
    pub storage_class: StorageClass,
    pub retention_policy: RetentionPolicy,
    pub timestamping: TimestampingConfig,
    pub delete_on_empty: DeleteOnEmptyConfig,
}

impl StreamConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_storage_class(self, storage_class: StorageClass) -> Self {
        Self {
            storage_class,
            ..self
        }
    }

    pub fn with_retention_policy(self, retention_policy: RetentionPolicy) -> Self {
        Self {
            retention_policy,
            ..self
        }
    }

    pub fn with_timestamping(self, timestamping: TimestampingConfig) -> Self {
        Self {
            timestamping,
            ..self
        }
    }

    pub fn with_delete_on_empty(self, delete_on_empty: DeleteOnEmptyConfig) -> Self {
        Self {
            delete_on_empty,
            ..self
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TimestampingReconfiguration {
    pub mode: Maybe<Option<TimestampingMode>>,
    pub uncapped: Maybe<Option<bool>>,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteOnEmptyReconfiguration {
    pub min_age: Maybe<Option<Duration>>,
}

#[derive(Debug, Clone, Default)]
pub struct StreamReconfiguration {
    pub storage_class: Maybe<Option<StorageClass>>,
    pub retention_policy: Maybe<Option<RetentionPolicy>>,
    pub timestamping: Maybe<Option<TimestampingReconfiguration>>,
    pub delete_on_empty: Maybe<Option<DeleteOnEmptyReconfiguration>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OptionalTimestampingConfig {
    pub mode: Option<TimestampingMode>,
    pub uncapped: Option<bool>,
}

impl OptionalTimestampingConfig {
    pub fn reconfigure(mut self, reconfiguration: TimestampingReconfiguration) -> Self {
        if let Maybe::Specified(mode) = reconfiguration.mode {
            self.mode = mode;
        }
        if let Maybe::Specified(uncapped) = reconfiguration.uncapped {
            self.uncapped = uncapped;
        }
        self
    }

    pub fn merge(self, basin_defaults: Self) -> TimestampingConfig {
        let mode = self.mode.or(basin_defaults.mode).unwrap_or_default();
        let uncapped = self
            .uncapped
            .or(basin_defaults.uncapped)
            .unwrap_or_default();
        TimestampingConfig { mode, uncapped }
    }
}

impl From<OptionalTimestampingConfig> for TimestampingConfig {
    fn from(value: OptionalTimestampingConfig) -> Self {
        Self {
            mode: value.mode.unwrap_or_default(),
            uncapped: value.uncapped.unwrap_or_default(),
        }
    }
}

impl From<TimestampingConfig> for OptionalTimestampingConfig {
    fn from(value: TimestampingConfig) -> Self {
        Self {
            mode: Some(value.mode),
            uncapped: Some(value.uncapped),
        }
    }
}

impl From<OptionalTimestampingConfig> for TimestampingReconfiguration {
    fn from(value: OptionalTimestampingConfig) -> Self {
        Self {
            mode: value.mode.into(),
            uncapped: value.uncapped.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OptionalDeleteOnEmptyConfig {
    pub min_age: Option<Duration>,
}

impl OptionalDeleteOnEmptyConfig {
    pub fn reconfigure(mut self, reconfiguration: DeleteOnEmptyReconfiguration) -> Self {
        if let Maybe::Specified(min_age) = reconfiguration.min_age {
            self.min_age = min_age;
        }
        self
    }

    pub fn merge(self, basin_defaults: Self) -> DeleteOnEmptyConfig {
        let min_age = self.min_age.or(basin_defaults.min_age).unwrap_or_default();
        DeleteOnEmptyConfig { min_age }
    }
}

impl From<OptionalDeleteOnEmptyConfig> for DeleteOnEmptyConfig {
    fn from(value: OptionalDeleteOnEmptyConfig) -> Self {
        Self {
            min_age: value.min_age.unwrap_or_default(),
        }
    }
}

impl From<DeleteOnEmptyConfig> for OptionalDeleteOnEmptyConfig {
    fn from(value: DeleteOnEmptyConfig) -> Self {
        Self {
            min_age: Some(value.min_age),
        }
    }
}

impl From<OptionalDeleteOnEmptyConfig> for DeleteOnEmptyReconfiguration {
    fn from(value: OptionalDeleteOnEmptyConfig) -> Self {
        Self {
            min_age: value.min_age.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OptionalStreamConfig {
    pub storage_class: Option<StorageClass>,
    pub retention_policy: Option<RetentionPolicy>,
    pub timestamping: OptionalTimestampingConfig,
    pub delete_on_empty: OptionalDeleteOnEmptyConfig,
}

impl OptionalStreamConfig {
    pub fn reconfigure(mut self, reconfiguration: StreamReconfiguration) -> Self {
        let StreamReconfiguration {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = reconfiguration;
        if let Maybe::Specified(storage_class) = storage_class {
            self.storage_class = storage_class;
        }
        if let Maybe::Specified(retention_policy) = retention_policy {
            self.retention_policy = retention_policy;
        }
        if let Maybe::Specified(timestamping) = timestamping {
            self.timestamping = timestamping
                .map(|ts| self.timestamping.reconfigure(ts))
                .unwrap_or_default();
        }
        if let Maybe::Specified(delete_on_empty_reconfig) = delete_on_empty {
            self.delete_on_empty = delete_on_empty_reconfig
                .map(|reconfig| self.delete_on_empty.reconfigure(reconfig))
                .unwrap_or_default();
        }
        self
    }

    pub fn merge(self, basin_defaults: Self) -> StreamConfig {
        let storage_class = self
            .storage_class
            .or(basin_defaults.storage_class)
            .unwrap_or_default();

        let retention_policy = self
            .retention_policy
            .or(basin_defaults.retention_policy)
            .unwrap_or_default();

        let timestamping = self.timestamping.merge(basin_defaults.timestamping);

        let delete_on_empty = self.delete_on_empty.merge(basin_defaults.delete_on_empty);

        StreamConfig {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        }
    }
}

impl From<OptionalStreamConfig> for StreamReconfiguration {
    fn from(value: OptionalStreamConfig) -> Self {
        let OptionalStreamConfig {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = value;

        Self {
            storage_class: storage_class.into(),
            retention_policy: retention_policy.into(),
            timestamping: Some(timestamping.into()).into(),
            delete_on_empty: Some(delete_on_empty.into()).into(),
        }
    }
}

impl From<OptionalStreamConfig> for StreamConfig {
    fn from(value: OptionalStreamConfig) -> Self {
        let OptionalStreamConfig {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = value;

        Self {
            storage_class: storage_class.unwrap_or_default(),
            retention_policy: retention_policy.unwrap_or_default(),
            timestamping: timestamping.into(),
            delete_on_empty: delete_on_empty.into(),
        }
    }
}

impl From<StreamConfig> for OptionalStreamConfig {
    fn from(value: StreamConfig) -> Self {
        let StreamConfig {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = value;

        Self {
            storage_class: Some(storage_class),
            retention_policy: Some(retention_policy),
            timestamping: timestamping.into(),
            delete_on_empty: delete_on_empty.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BasinConfig {
    pub default_stream_config: OptionalStreamConfig,
    pub create_stream_on_append: bool,
    pub create_stream_on_read: bool,
}

impl BasinConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default_stream_config(self, default_stream_config: StreamConfig) -> Self {
        Self {
            default_stream_config: default_stream_config.into(),
            ..self
        }
    }

    pub fn with_create_stream_on_append(self, create_stream_on_append: bool) -> Self {
        Self {
            create_stream_on_append,
            ..self
        }
    }

    pub fn with_create_stream_on_read(self, create_stream_on_read: bool) -> Self {
        Self {
            create_stream_on_read,
            ..self
        }
    }

    pub fn reconfigure(mut self, reconfiguration: BasinReconfiguration) -> Self {
        let BasinReconfiguration {
            default_stream_config,
            create_stream_on_append,
            create_stream_on_read,
        } = reconfiguration;

        if let Maybe::Specified(default_stream_config) = default_stream_config {
            self.default_stream_config = default_stream_config
                .map(|reconfig| self.default_stream_config.reconfigure(reconfig))
                .unwrap_or_default();
        }

        if let Maybe::Specified(create_stream_on_append) = create_stream_on_append {
            self.create_stream_on_append = create_stream_on_append;
        }

        if let Maybe::Specified(create_stream_on_read) = create_stream_on_read {
            self.create_stream_on_read = create_stream_on_read;
        }

        self
    }
}

impl From<BasinConfig> for BasinReconfiguration {
    fn from(value: BasinConfig) -> Self {
        let BasinConfig {
            default_stream_config,
            create_stream_on_append,
            create_stream_on_read,
        } = value;

        Self {
            default_stream_config: Some(default_stream_config.into()).into(),
            create_stream_on_append: create_stream_on_append.into(),
            create_stream_on_read: create_stream_on_read.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BasinReconfiguration {
    pub default_stream_config: Maybe<Option<StreamReconfiguration>>,
    pub create_stream_on_append: Maybe<bool>,
    pub create_stream_on_read: Maybe<bool>,
}
