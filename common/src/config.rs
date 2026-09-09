//! Stream and basin configuration types.
//!
//! Stream configuration uses three representations:
//!
//! - Resolved (`StreamConfig`, `TimestampingConfig`, `DeleteOnEmptyConfig`): concrete values,
//!   produced by merging optional configs with defaults using `merge()`.
//!
//! - Optional (`OptionalStreamConfig`, `OptionalTimestampingConfig`,
//!   `OptionalDeleteOnEmptyConfig`): partial configuration layers, where `None` means "not set at
//!   this layer; fall back to defaults."
//!
//! - Reconfiguration (`StreamReconfiguration`, `TimestampingReconfiguration`,
//!   `DeleteOnEmptyReconfiguration`): PATCH-style updates applied with `reconfigure()`.
//!
//! Reconfiguration of nested fields (e.g. `timestamping`, `delete_on_empty`,
//! `default_stream_config`) is applied recursively: `Specified(Some(inner_reconfig))`
//! applies the inner reconfiguration to the existing value, while `Specified(None)`
//! clears it to the default.
//!
//! `merge()` resolves optional configs into resolved configs with precedence:
//! stream-level → basin-level → system default (via `Option::or` chaining).
//!
//! Basin config also carries basin-level knobs like `stream_cipher`,
//! `create_stream_on_append`, and `create_stream_on_read`.

use std::{fmt, time::Duration};

use crate::{ValidationError, encryption::EncryptionAlgorithm, maybe::Maybe};

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

    pub fn validate(self) -> Result<Self, ValidationError> {
        match self {
            Self::Age(duration) if duration.is_zero() => Err(ValidationError(
                "age must be greater than 0 seconds".to_string(),
            )),
            policy => Ok(policy),
        }
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        const ONE_WEEK: Duration = Duration::from_secs(7 * 24 * 60 * 60);

        Self::Age(ONE_WEEK)
    }
}

impl fmt::Display for RetentionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Age(age) => write!(f, "age {}", Secs(*age)),
            Self::Infinite() => f.write_str("infinite"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, strum::Display)]
#[strum(serialize_all = "kebab-case")]
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

impl DeleteOnEmptyConfig {
    pub fn min_age(&self) -> Option<Duration> {
        Some(self.min_age).filter(|age| !age.is_zero())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamConfig {
    pub storage_class: StorageClass,
    pub retention_policy: RetentionPolicy,
    pub timestamping: TimestampingConfig,
    pub delete_on_empty: DeleteOnEmptyConfig,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

/// The two sides of a disagreement over a single configuration value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mismatch<T> {
    pub expected: T,
    pub actual: T,
}

impl<T> Mismatch<T> {
    fn map<U>(self, f: impl Fn(T) -> U) -> Mismatch<U> {
        Mismatch {
            expected: f(self.expected),
            actual: f(self.actual),
        }
    }
}

impl<T: fmt::Display> fmt::Display for Mismatch<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected {}, found {}", self.expected, self.actual)
    }
}

/// A field set in an [`OptionalStreamConfig`] that disagrees with the [`StreamConfig`] it was
/// checked against, carrying both sides of the disagreement.
///
/// Produced by [`OptionalStreamConfig::mismatch`]. The `&'static str` conversion yields the
/// path of the offending field (e.g. `timestamping.mode`); `Display` renders the full
/// `<field>: expected <x>, found <y>` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
pub enum StreamConfigMismatch {
    #[strum(serialize = "storage_class")]
    StorageClass(Mismatch<StorageClass>),
    #[strum(serialize = "retention_policy")]
    RetentionPolicy(Mismatch<RetentionPolicy>),
    #[strum(serialize = "timestamping.mode")]
    TimestampingMode(Mismatch<TimestampingMode>),
    #[strum(serialize = "timestamping.uncapped")]
    TimestampingUncapped(Mismatch<bool>),
    #[strum(serialize = "delete_on_empty.min_age")]
    DeleteOnEmptyMinAge(Mismatch<Duration>),
}

impl StreamConfigMismatch {
    /// Path of the mismatched field within a stream configuration.
    pub fn field(&self) -> &'static str {
        self.into()
    }
}

impl fmt::Display for StreamConfigMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field = self.field();
        match *self {
            Self::StorageClass(m) => write!(f, "{field}: {m}"),
            Self::RetentionPolicy(m) => write!(f, "{field}: {m}"),
            Self::TimestampingMode(m) => write!(f, "{field}: {m}"),
            Self::TimestampingUncapped(m) => write!(f, "{field}: {m}"),
            Self::DeleteOnEmptyMinAge(m) => write!(f, "{field}: {}", m.map(Secs)),
        }
    }
}

/// Renders a [`Duration`] as whole seconds, matching how the API expresses config durations.
struct Secs(Duration);

impl fmt::Display for Secs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0.as_secs())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OptionalStreamConfig {
    pub storage_class: Option<StorageClass>,
    pub retention_policy: Option<RetentionPolicy>,
    pub timestamping: OptionalTimestampingConfig,
    pub delete_on_empty: OptionalDeleteOnEmptyConfig,
}

impl OptionalStreamConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let Some(retention_policy) = self.retention_policy {
            retention_policy.validate()?;
        }
        Ok(())
    }

    /// Whether no field is set.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Compare every set field against `actual`, returning the first disagreement in declaration
    /// order. Unset fields are not compared, so an empty config never mismatches.
    pub fn mismatch(&self, actual: &StreamConfig) -> Option<StreamConfigMismatch> {
        use StreamConfigMismatch as M;

        fn differs<T: PartialEq>(expected: Option<T>, actual: T) -> Option<Mismatch<T>> {
            match expected {
                Some(expected) if expected != actual => Some(Mismatch { expected, actual }),
                _ => None,
            }
        }

        let &Self {
            storage_class,
            retention_policy,
            timestamping: OptionalTimestampingConfig { mode, uncapped },
            delete_on_empty: OptionalDeleteOnEmptyConfig { min_age },
        } = self;
        let &StreamConfig {
            storage_class: actual_storage_class,
            retention_policy: actual_retention_policy,
            timestamping:
                TimestampingConfig {
                    mode: actual_mode,
                    uncapped: actual_uncapped,
                },
            delete_on_empty:
                DeleteOnEmptyConfig {
                    min_age: actual_min_age,
                },
        } = actual;

        differs(storage_class, actual_storage_class)
            .map(M::StorageClass)
            .or_else(|| differs(retention_policy, actual_retention_policy).map(M::RetentionPolicy))
            .or_else(|| differs(mode, actual_mode).map(M::TimestampingMode))
            .or_else(|| differs(uncapped, actual_uncapped).map(M::TimestampingUncapped))
            .or_else(|| differs(min_age, actual_min_age).map(M::DeleteOnEmptyMinAge))
    }

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BasinConfig {
    pub default_stream_config: OptionalStreamConfig,
    pub stream_cipher: Option<EncryptionAlgorithm>,
    pub create_stream_on_append: bool,
    pub create_stream_on_read: bool,
}

impl BasinConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.default_stream_config.validate()
    }

    pub fn reconfigure(mut self, reconfiguration: BasinReconfiguration) -> Self {
        let BasinReconfiguration {
            default_stream_config,
            stream_cipher,
            create_stream_on_append,
            create_stream_on_read,
        } = reconfiguration;

        if let Maybe::Specified(default_stream_config) = default_stream_config {
            self.default_stream_config = default_stream_config
                .map(|reconfig| self.default_stream_config.reconfigure(reconfig))
                .unwrap_or_default();
        }

        if let Maybe::Specified(stream_cipher) = stream_cipher {
            self.stream_cipher = stream_cipher;
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

#[derive(Debug, Clone, Default)]
pub struct BasinReconfiguration {
    pub default_stream_config: Maybe<Option<StreamReconfiguration>>,
    pub stream_cipher: Maybe<Option<EncryptionAlgorithm>>,
    pub create_stream_on_append: Maybe<bool>,
    pub create_stream_on_read: Maybe<bool>,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn actual() -> StreamConfig {
        StreamConfig {
            storage_class: StorageClass::Standard,
            retention_policy: RetentionPolicy::Age(Duration::from_secs(604_800)),
            timestamping: TimestampingConfig {
                mode: TimestampingMode::ClientPrefer,
                uncapped: false,
            },
            delete_on_empty: DeleteOnEmptyConfig {
                min_age: Duration::ZERO,
            },
        }
    }

    #[test]
    fn empty_config_is_empty_and_never_mismatches() {
        let empty = OptionalStreamConfig::default();
        assert!(empty.is_empty());
        assert_eq!(empty.mismatch(&actual()), None);
    }

    #[test]
    fn matching_set_fields_do_not_mismatch() {
        let matching: OptionalStreamConfig = actual().into();
        assert!(!matching.is_empty());
        assert_eq!(matching.mismatch(&actual()), None);
    }

    #[rstest]
    #[case::storage_class(
        OptionalStreamConfig { storage_class: Some(StorageClass::Express), ..Default::default() },
        "storage_class: expected express, found standard",
    )]
    #[case::retention_policy(
        OptionalStreamConfig {
            retention_policy: Some(RetentionPolicy::Infinite()),
            ..Default::default()
        },
        "retention_policy: expected infinite, found age 604800s",
    )]
    #[case::timestamping_mode(
        OptionalStreamConfig {
            timestamping: OptionalTimestampingConfig {
                mode: Some(TimestampingMode::Arrival),
                uncapped: None,
            },
            ..Default::default()
        },
        "timestamping.mode: expected arrival, found client-prefer",
    )]
    #[case::timestamping_uncapped(
        OptionalStreamConfig {
            timestamping: OptionalTimestampingConfig { mode: None, uncapped: Some(true) },
            ..Default::default()
        },
        "timestamping.uncapped: expected true, found false",
    )]
    #[case::delete_on_empty_min_age(
        OptionalStreamConfig {
            delete_on_empty: OptionalDeleteOnEmptyConfig {
                min_age: Some(Duration::from_secs(300)),
            },
            ..Default::default()
        },
        "delete_on_empty.min_age: expected 300s, found 0s",
    )]
    fn mismatch_reports_expected_and_found(
        #[case] requested: OptionalStreamConfig,
        #[case] message: &str,
    ) {
        let mismatch = requested.mismatch(&actual()).expect("should mismatch");
        assert_eq!(mismatch.to_string(), message);
        let (field, _) = message.split_once(':').unwrap();
        assert_eq!(mismatch.field(), field);
    }

    #[test]
    fn mismatch_reports_first_differing_field_in_declaration_order() {
        let requested = OptionalStreamConfig {
            storage_class: Some(StorageClass::Standard),
            retention_policy: Some(RetentionPolicy::Age(Duration::from_secs(3600))),
            delete_on_empty: OptionalDeleteOnEmptyConfig {
                min_age: Some(Duration::from_secs(300)),
            },
            ..Default::default()
        };
        assert!(matches!(
            requested.mismatch(&actual()),
            Some(StreamConfigMismatch::RetentionPolicy(_))
        ));
    }
}
