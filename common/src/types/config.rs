//! Stream and basin configuration types.
//!
//! Each config area (stream, timestamping, delete-on-empty) has three type tiers:
//!
//! - Resolved (`StreamConfig`, `TimestampingConfig`, `DeleteOnEmptyConfig`): All fields are
//!   concrete values. Produced by merging optional configs with defaults using `merge()`.
//!
//! - Optional (`OptionalStreamConfig`, `OptionalTimestampingConfig`,
//!   `OptionalDeleteOnEmptyConfig`): The internal representation, stored in metadata. Fields are
//!   `Option<T>` where `None` means "not set at this layer, fall back to defaults."
//!
//! - Reconfiguration (`StreamReconfiguration`, `TimestampingReconfiguration`,
//!   `DeleteOnEmptyReconfiguration`): Partial updates with PATCH semantics. Most fields are
//!   `Maybe<Option<T>>` with three states: `Unspecified` (don't change), `Specified(None)` (clear
//!   to default), `Specified(Some(v))` (set to value). Collection-valued fields may instead use an
//!   empty collection to mean "clear to default". Applied using `reconfigure()`.
//!
//! Reconfiguration of nested fields (e.g. `timestamping`, `delete_on_empty`,
//! `default_stream_config`) is applied recursively: `Specified(Some(inner_reconfig))`
//! applies the inner reconfiguration to the existing value, while `Specified(None)`
//! clears it to the default.
//!
//! `merge()` resolves optional configs into resolved configs with precedence:
//! stream-level → basin-level → system default (via `Option::or` chaining).
//!
//! The `From<Optional*> for *Reconfiguration` conversions treat every field as
//! `Specified`. These conversions represent "set the config to exactly this state",
//! not "update only the fields that are set."

use std::time::Duration;

use enum_ordinalize::Ordinalize;
use enumset::EnumSet;

use crate::{encryption::EncryptionMode, maybe::Maybe};

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
    Hash,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionConfig {
    pub allowed_modes: EnumSet<EncryptionMode>,
}

pub const DEFAULT_ALLOWED_ENCRYPTION_MODES: EnumSet<EncryptionMode> =
    enumset::enum_set!(EncryptionMode::Plain);

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            allowed_modes: DEFAULT_ALLOWED_ENCRYPTION_MODES,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamConfig {
    pub storage_class: StorageClass,
    pub retention_policy: RetentionPolicy,
    pub timestamping: TimestampingConfig,
    pub delete_on_empty: DeleteOnEmptyConfig,
    pub encryption: EncryptionConfig,
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
pub struct EncryptionReconfiguration {
    pub allowed_modes: Maybe<EnumSet<EncryptionMode>>,
}

#[derive(Debug, Clone, Default)]
pub struct StreamReconfiguration {
    pub storage_class: Maybe<Option<StorageClass>>,
    pub retention_policy: Maybe<Option<RetentionPolicy>>,
    pub timestamping: Maybe<Option<TimestampingReconfiguration>>,
    pub delete_on_empty: Maybe<Option<DeleteOnEmptyReconfiguration>>,
    pub encryption: Maybe<Option<EncryptionReconfiguration>>,
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
pub struct OptionalEncryptionConfig {
    pub allowed_modes: Option<EnumSet<EncryptionMode>>,
}

impl OptionalEncryptionConfig {
    pub fn reconfigure(mut self, reconfiguration: EncryptionReconfiguration) -> Self {
        if let Maybe::Specified(allowed_modes) = reconfiguration.allowed_modes {
            self.allowed_modes = (!allowed_modes.is_empty()).then_some(allowed_modes);
        }
        self
    }

    pub fn merge(self, basin_defaults: Self) -> EncryptionConfig {
        let allowed_modes = self
            .allowed_modes
            .or(basin_defaults.allowed_modes)
            .unwrap_or(DEFAULT_ALLOWED_ENCRYPTION_MODES);
        EncryptionConfig { allowed_modes }
    }
}

impl From<OptionalEncryptionConfig> for EncryptionConfig {
    fn from(value: OptionalEncryptionConfig) -> Self {
        Self {
            allowed_modes: value
                .allowed_modes
                .unwrap_or(DEFAULT_ALLOWED_ENCRYPTION_MODES),
        }
    }
}

impl From<EncryptionConfig> for OptionalEncryptionConfig {
    fn from(value: EncryptionConfig) -> Self {
        Self {
            allowed_modes: Some(value.allowed_modes),
        }
    }
}

impl From<OptionalEncryptionConfig> for EncryptionReconfiguration {
    fn from(value: OptionalEncryptionConfig) -> Self {
        Self {
            allowed_modes: Maybe::Specified(value.allowed_modes.unwrap_or_default()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OptionalStreamConfig {
    pub storage_class: Option<StorageClass>,
    pub retention_policy: Option<RetentionPolicy>,
    pub timestamping: OptionalTimestampingConfig,
    pub delete_on_empty: OptionalDeleteOnEmptyConfig,
    pub encryption: OptionalEncryptionConfig,
}

impl OptionalStreamConfig {
    pub fn reconfigure(mut self, reconfiguration: StreamReconfiguration) -> Self {
        let StreamReconfiguration {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
            encryption,
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
        if let Maybe::Specified(encryption) = encryption {
            self.encryption = encryption
                .map(|enc| self.encryption.reconfigure(enc))
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

        let encryption = self.encryption.merge(basin_defaults.encryption);

        StreamConfig {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
            encryption,
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
            encryption,
        } = value;

        Self {
            storage_class: storage_class.into(),
            retention_policy: retention_policy.into(),
            timestamping: Some(timestamping.into()).into(),
            delete_on_empty: Some(delete_on_empty.into()).into(),
            encryption: Some(encryption.into()).into(),
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
            encryption,
        } = value;

        Self {
            storage_class: storage_class.unwrap_or_default(),
            retention_policy: retention_policy.unwrap_or_default(),
            timestamping: timestamping.into(),
            delete_on_empty: delete_on_empty.into(),
            encryption: encryption.into(),
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
            encryption,
        } = value;

        Self {
            storage_class: Some(storage_class),
            retention_policy: Some(retention_policy),
            timestamping: timestamping.into(),
            delete_on_empty: delete_on_empty.into(),
            encryption: encryption.into(),
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
