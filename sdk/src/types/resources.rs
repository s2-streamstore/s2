use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::Stream;
use jiff::Timestamp;
use s2_api::v1::{self as api, MaybeKnown};
use s2_common::{
    ValidationError,
    basin::{BasinName, BasinNamePrefix, BasinNameStartAfter},
    location::LocationName,
    maybe::Maybe,
    stream::{StreamName, StreamNamePrefix, StreamNameStartAfter},
};

use super::whole_seconds;
use crate::error::RequestError;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// A page of values.
pub struct Page<T> {
    /// Values in this page.
    pub values: Vec<T>,
    /// Whether there are more pages.
    pub has_more: bool,
}

impl<T> Page<T> {
    pub(crate) fn from_api<U: Into<T>>(values: Vec<U>, has_more: bool) -> Self {
        Self {
            values: values.into_iter().map(Into::into).collect(),
            has_more,
        }
    }
}

/// Paginated stream of values returned by `list_all_*` operations.
///
/// Implements [`futures_core::Stream`] and provides an inherent [`next`](Self::next) method for
/// iterating without importing `StreamExt`.
#[must_use = "streams do nothing unless polled"]
pub struct ListStream<T>(Pin<Box<dyn Send + Stream<Item = Result<T, RequestError>>>>);

impl<T> ListStream<T> {
    pub(crate) fn new(
        stream: impl Stream<Item = Result<T, RequestError>> + Send + 'static,
    ) -> Self {
        Self(Box::pin(stream))
    }

    /// Return the next item from the stream, or `None` when pagination finishes.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe and can be used inside [`tokio::select!`].
    pub async fn next(&mut self) -> Option<Result<T, RequestError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }
}

impl<T> fmt::Debug for ListStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListStream").finish_non_exhaustive()
    }
}

impl<T> Stream for ListStream<T> {
    type Item = Result<T, RequestError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

/// Desired change to an optional configuration field in a reconfiguration request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Reconfigure<T> {
    /// Leave the existing value unchanged.
    #[default]
    Unchanged,
    /// Set the field to a new value.
    Set(T),
    /// Reset the field to the server default.
    Reset,
}

impl<T> Reconfigure<T> {
    /// Convert from `&Reconfigure<T>` to `Reconfigure<&T>`.
    pub fn as_ref(&self) -> Reconfigure<&T> {
        match self {
            Self::Unchanged => Reconfigure::Unchanged,
            Self::Set(v) => Reconfigure::Set(v),
            Self::Reset => Reconfigure::Reset,
        }
    }

    /// Map a `Reconfigure<T>` to `Reconfigure<U>` by applying a function to a `Set` value.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Reconfigure<U> {
        match self {
            Self::Unchanged => Reconfigure::Unchanged,
            Self::Set(v) => Reconfigure::Set(f(v)),
            Self::Reset => Reconfigure::Reset,
        }
    }

    pub(crate) fn into_maybe(self) -> Maybe<Option<T>> {
        match self {
            Self::Unchanged => Maybe::Unspecified,
            Self::Set(v) => Maybe::Specified(Some(v)),
            Self::Reset => Maybe::Specified(None),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
/// Encryption algorithm.
pub enum EncryptionAlgorithm {
    /// AEGIS-256
    Aegis256,
    /// AES-256-GCM
    Aes256Gcm,
    /// An algorithm this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl From<MaybeKnown<api::config::EncryptionAlgorithm>> for EncryptionAlgorithm {
    fn from(value: MaybeKnown<api::config::EncryptionAlgorithm>) -> Self {
        match value {
            MaybeKnown::Known(api::config::EncryptionAlgorithm::Aegis256) => Self::Aegis256,
            MaybeKnown::Known(api::config::EncryptionAlgorithm::Aes256Gcm) => Self::Aes256Gcm,
            MaybeKnown::Unknown(name) => Self::Unknown(name),
        }
    }
}

impl From<EncryptionAlgorithm> for MaybeKnown<api::config::EncryptionAlgorithm> {
    fn from(value: EncryptionAlgorithm) -> Self {
        match value {
            EncryptionAlgorithm::Aegis256 => api::config::EncryptionAlgorithm::Aegis256.into(),
            EncryptionAlgorithm::Aes256Gcm => api::config::EncryptionAlgorithm::Aes256Gcm.into(),
            EncryptionAlgorithm::Unknown(name) => Self::Unknown(name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Retention policy for records in a stream.
pub enum RetentionPolicy {
    /// Age in seconds. Must be greater than `0`. Records older than this age are automatically
    /// trimmed.
    Age(u64),
    /// Records are retained indefinitely unless explicitly trimmed.
    Infinite,
    /// A policy this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl RetentionPolicy {
    /// Create an age-based retention policy from a whole-second [`Duration`].
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `age` has sub-second precision.
    pub fn age(age: Duration) -> Result<Self, ValidationError> {
        Ok(Self::Age(whole_seconds(age, "retention_age")?))
    }
}

impl From<MaybeKnown<api::config::RetentionPolicy>> for RetentionPolicy {
    fn from(value: MaybeKnown<api::config::RetentionPolicy>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
        match value {
            api::config::RetentionPolicy::Age(secs) => RetentionPolicy::Age(secs),
            api::config::RetentionPolicy::Infinite(_) => RetentionPolicy::Infinite,
        }
    }
}

impl From<RetentionPolicy> for MaybeKnown<api::config::RetentionPolicy> {
    fn from(value: RetentionPolicy) -> Self {
        let known = match value {
            RetentionPolicy::Age(secs) => api::config::RetentionPolicy::Age(secs),
            RetentionPolicy::Infinite => {
                api::config::RetentionPolicy::Infinite(api::config::InfiniteRetention {})
            }
            RetentionPolicy::Unknown(name) => return Self::Unknown(name),
        };
        Self::Known(known)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Timestamping mode for appends that influences how timestamps are handled.
pub enum TimestampingMode {
    /// Prefer client-specified timestamp if present otherwise use arrival time.
    ClientPrefer,
    /// Require a client-specified timestamp and reject the append if it is missing.
    ClientRequire,
    /// Use the arrival time and ignore any client-specified timestamp.
    Arrival,
    /// A mode this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl From<MaybeKnown<api::config::TimestampingMode>> for TimestampingMode {
    fn from(value: MaybeKnown<api::config::TimestampingMode>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
        match value {
            api::config::TimestampingMode::ClientPrefer => TimestampingMode::ClientPrefer,
            api::config::TimestampingMode::ClientRequire => TimestampingMode::ClientRequire,
            api::config::TimestampingMode::Arrival => TimestampingMode::Arrival,
        }
    }
}

impl From<TimestampingMode> for MaybeKnown<api::config::TimestampingMode> {
    fn from(value: TimestampingMode) -> Self {
        let known = match value {
            TimestampingMode::ClientPrefer => api::config::TimestampingMode::ClientPrefer,
            TimestampingMode::ClientRequire => api::config::TimestampingMode::ClientRequire,
            TimestampingMode::Arrival => api::config::TimestampingMode::Arrival,
            TimestampingMode::Unknown(name) => return Self::Unknown(name),
        };
        Self::Known(known)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Configuration for timestamping behavior.
pub struct TimestampingConfig {
    /// Timestamping mode for appends that influences how timestamps are handled.
    ///
    /// Defaults to [`ClientPrefer`](TimestampingMode::ClientPrefer).
    pub mode: Option<TimestampingMode>,
    /// Whether client-specified timestamps are allowed to exceed the arrival time.
    ///
    /// Defaults to `false` (client timestamps are capped at the arrival time).
    pub uncapped: Option<bool>,
}

impl TimestampingConfig {
    /// Create a new [`TimestampingConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the timestamping mode for appends that influences how timestamps are handled.
    pub fn with_mode(self, mode: TimestampingMode) -> Self {
        Self {
            mode: Some(mode),
            ..self
        }
    }

    /// Set whether client-specified timestamps are allowed to exceed the arrival time.
    pub fn with_uncapped(self, uncapped: bool) -> Self {
        Self {
            uncapped: Some(uncapped),
            ..self
        }
    }
}

impl From<api::config::TimestampingConfig> for TimestampingConfig {
    fn from(value: api::config::TimestampingConfig) -> Self {
        Self {
            mode: value.mode.map(Into::into),
            uncapped: value.uncapped,
        }
    }
}

impl From<TimestampingConfig> for api::config::TimestampingConfig {
    fn from(value: TimestampingConfig) -> Self {
        Self {
            mode: value.mode.map(Into::into),
            uncapped: value.uncapped,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[must_use]
/// Configuration for automatically deleting a stream when it becomes empty.
pub struct DeleteOnEmptyConfig {
    min_age_secs: u64,
}

impl DeleteOnEmptyConfig {
    /// Create a new [`DeleteOnEmptyConfig`] with default settings (`0s`, disabling automatic
    /// deletion).
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the minimum age before an empty stream can be deleted (`Duration::ZERO` disables
    /// automatic deletion).
    pub fn min_age(&self) -> Duration {
        Duration::from_secs(self.min_age_secs)
    }

    /// Set the minimum age before an empty stream can be deleted.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `min_age` has sub-second precision.
    pub fn with_min_age(self, min_age: Duration) -> Result<Self, ValidationError> {
        Ok(Self {
            min_age_secs: whole_seconds(min_age, "delete_on_empty.min_age")?,
        })
    }
}

impl From<api::config::DeleteOnEmptyConfig> for DeleteOnEmptyConfig {
    fn from(value: api::config::DeleteOnEmptyConfig) -> Self {
        Self {
            min_age_secs: value.min_age_secs,
        }
    }
}

impl From<DeleteOnEmptyConfig> for api::config::DeleteOnEmptyConfig {
    fn from(value: DeleteOnEmptyConfig) -> Self {
        Self {
            min_age_secs: value.min_age_secs,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
/// Configuration for a stream.
pub struct StreamConfig {
    /// [Storage class](https://s2.dev/docs/storage-classes) for the stream.
    pub storage_class: Option<String>,
    /// Retention policy for records in the stream.
    ///
    /// Defaults to `7 days` of retention.
    pub retention_policy: Option<RetentionPolicy>,
    /// Configuration for timestamping behavior.
    ///
    /// See [`TimestampingConfig`] for defaults.
    pub timestamping: Option<TimestampingConfig>,
    /// Configuration for automatically deleting the stream when it becomes empty.
    ///
    /// See [`DeleteOnEmptyConfig`] for defaults.
    pub delete_on_empty: Option<DeleteOnEmptyConfig>,
}

impl StreamConfig {
    /// Create a new [`StreamConfig`] with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the storage class for the stream.
    #[must_use]
    pub fn with_storage_class(self, storage_class: impl Into<String>) -> Self {
        Self {
            storage_class: Some(storage_class.into()),
            ..self
        }
    }

    /// Set the retention policy for records in the stream.
    #[must_use]
    pub fn with_retention_policy(self, retention_policy: RetentionPolicy) -> Self {
        Self {
            retention_policy: Some(retention_policy),
            ..self
        }
    }

    /// Set the configuration for timestamping behavior.
    #[must_use]
    pub fn with_timestamping(self, timestamping: TimestampingConfig) -> Self {
        Self {
            timestamping: Some(timestamping),
            ..self
        }
    }

    /// Set the configuration for automatically deleting the stream when it becomes empty.
    #[must_use]
    pub fn with_delete_on_empty(self, delete_on_empty: DeleteOnEmptyConfig) -> Self {
        Self {
            delete_on_empty: Some(delete_on_empty),
            ..self
        }
    }
}

impl From<api::config::StreamConfig> for StreamConfig {
    fn from(value: api::config::StreamConfig) -> Self {
        Self {
            storage_class: value.storage_class,
            retention_policy: value.retention_policy.map(Into::into),
            timestamping: value.timestamping.map(Into::into),
            delete_on_empty: value.delete_on_empty.map(Into::into),
        }
    }
}

impl From<StreamConfig> for api::config::StreamConfig {
    fn from(value: StreamConfig) -> Self {
        Self {
            storage_class: value.storage_class,
            retention_policy: value.retention_policy.map(Into::into),
            timestamping: value.timestamping.map(Into::into),
            delete_on_empty: value.delete_on_empty.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
/// Configuration for a basin.
pub struct BasinConfig {
    /// Default configuration for all streams in the basin.
    ///
    /// See [`StreamConfig`] for defaults.
    pub default_stream_config: Option<StreamConfig>,
    /// Encryption algorithm to apply to newly created streams in the basin.
    pub stream_cipher: Option<EncryptionAlgorithm>,
    /// Whether to create stream on append if it doesn't exist using default stream configuration.
    ///
    /// Defaults to `false`.
    pub create_stream_on_append: bool,
    /// Whether to create stream on read if it doesn't exist using default stream configuration.
    ///
    /// Defaults to `false`.
    pub create_stream_on_read: bool,
}

impl BasinConfig {
    /// Create a new [`BasinConfig`] with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default configuration for all streams in the basin.
    #[must_use]
    pub fn with_default_stream_config(self, config: StreamConfig) -> Self {
        Self {
            default_stream_config: Some(config),
            ..self
        }
    }

    /// Set the encryption algorithm to apply to newly created streams in the basin.
    #[must_use]
    pub fn with_stream_cipher(self, stream_cipher: EncryptionAlgorithm) -> Self {
        Self {
            stream_cipher: Some(stream_cipher),
            ..self
        }
    }

    /// Set whether to create stream on append if it doesn't exist using default stream
    /// configuration.
    #[must_use]
    pub fn with_create_stream_on_append(self, create_stream_on_append: bool) -> Self {
        Self {
            create_stream_on_append,
            ..self
        }
    }

    /// Set whether to create stream on read if it doesn't exist using default stream configuration.
    #[must_use]
    pub fn with_create_stream_on_read(self, create_stream_on_read: bool) -> Self {
        Self {
            create_stream_on_read,
            ..self
        }
    }
}

impl From<api::config::BasinConfig> for BasinConfig {
    fn from(value: api::config::BasinConfig) -> Self {
        Self {
            default_stream_config: value.default_stream_config.map(Into::into),
            stream_cipher: value.stream_cipher.map(Into::into),
            create_stream_on_append: value.create_stream_on_append,
            create_stream_on_read: value.create_stream_on_read,
        }
    }
}

impl From<BasinConfig> for api::config::BasinConfig {
    fn from(value: BasinConfig) -> Self {
        Self {
            default_stream_config: value.default_stream_config.map(Into::into),
            stream_cipher: value.stream_cipher.map(Into::into),
            create_stream_on_append: value.create_stream_on_append,
            create_stream_on_read: value.create_stream_on_read,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Input for [`create_basin`](crate::S2::create_basin) operation.
pub struct CreateBasinInput {
    /// Basin name.
    pub name: BasinName,
    /// Configuration for the basin.
    ///
    /// See [`BasinConfig`] for defaults.
    pub config: Option<BasinConfig>,
    /// Location of the basin.
    ///
    /// If omitted when creating, uses the default location for the account.
    pub location: Option<LocationName>,
}

impl CreateBasinInput {
    /// Create a new [`CreateBasinInput`] with the given basin name.
    pub fn new(name: BasinName) -> Self {
        Self {
            name,
            config: None,
            location: None,
        }
    }

    /// Set the configuration for the basin.
    pub fn with_config(self, config: BasinConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }

    /// Set the location of the basin.
    pub fn with_location(self, location: LocationName) -> Self {
        Self {
            location: Some(location),
            ..self
        }
    }
}

impl From<CreateBasinInput> for api::basin::CreateBasinRequest {
    fn from(value: CreateBasinInput) -> Self {
        Self {
            basin: value.name,
            config: value.config.map(Into::into),
            location: value.location,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Input for [`ensure_basin`](crate::S2::ensure_basin) operation.
pub struct EnsureBasinInput {
    /// Basin name.
    pub name: BasinName,
    /// Desired full configuration for the basin.
    ///
    /// Unlike [`reconfigure_basin`](crate::S2::reconfigure_basin), omitted fields are reset to
    /// their server defaults when ensuring an existing basin.
    pub config: Option<BasinConfig>,
    /// Location of the basin.
    ///
    /// If omitted when creating, uses the default location for the account. Cannot be changed once
    /// set.
    pub location: Option<LocationName>,
}

impl EnsureBasinInput {
    /// Create a new [`EnsureBasinInput`] with the given basin name.
    pub fn new(name: BasinName) -> Self {
        Self {
            name,
            config: None,
            location: None,
        }
    }

    /// Set the full desired configuration for the basin (omitted fields reset to defaults).
    pub fn with_config(self, config: BasinConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }

    /// Set the location of the basin.
    pub fn with_location(self, location: LocationName) -> Self {
        Self {
            location: Some(location),
            ..self
        }
    }

    pub(crate) fn into_parts(self) -> (BasinName, Option<api::basin::EnsureBasinRequest>) {
        let request = if self.config.is_some() || self.location.is_some() {
            Some(api::basin::EnsureBasinRequest {
                config: self.config.map(Into::into),
                location: self.location,
            })
        } else {
            None
        };
        (self.name, request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Output for `ensure` operations ([`ensure_basin`](crate::S2::ensure_basin),
/// [`ensure_stream`](crate::S2Basin::ensure_stream)).
pub enum EnsureOutput<T> {
    /// Resource created.
    Created(T),
    /// Resource already existed, and its config was updated.
    Updated(T),
    /// Resource already existed, and its config is unchanged.
    Noop(T),
}

impl<T> EnsureOutput<T> {
    /// Return a reference to the resource info regardless of whether it was created, updated, or
    /// unchanged.
    pub fn inner(&self) -> &T {
        match self {
            Self::Created(info) | Self::Updated(info) | Self::Noop(info) => info,
        }
    }

    /// Consume this output and return the resource info.
    pub fn into_inner(self) -> T {
        match self {
            Self::Created(info) | Self::Updated(info) | Self::Noop(info) => info,
        }
    }

    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> EnsureOutput<U> {
        match self {
            Self::Created(info) => EnsureOutput::Created(f(info)),
            Self::Updated(info) => EnsureOutput::Updated(f(info)),
            Self::Noop(info) => EnsureOutput::Noop(f(info)),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Input for [`list_basins`](crate::S2::list_basins) operation.
pub struct ListBasinsInput {
    /// Filter basins whose names begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: BasinNamePrefix,
    /// Filter basins whose names are lexicographically greater than this value.
    ///
    /// Defaults to `""`.
    pub start_after: BasinNameStartAfter,
    /// Number of basins to return in a page. Will be clamped to a maximum of `1000`.
    ///
    /// Defaults to `1000`.
    pub limit: Option<usize>,
}

impl ListBasinsInput {
    /// Create a new [`ListBasinsInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the prefix used to filter basins whose names begin with this value.
    pub fn with_prefix(self, prefix: BasinNamePrefix) -> Self {
        Self { prefix, ..self }
    }

    /// Set the value used to filter basins whose names are lexicographically greater than this
    /// value.
    pub fn with_start_after(self, start_after: BasinNameStartAfter) -> Self {
        Self {
            start_after,
            ..self
        }
    }

    /// Set the limit on number of basins to return in a page.
    pub fn with_limit(self, limit: usize) -> Self {
        Self {
            limit: Some(limit),
            ..self
        }
    }
}

impl From<ListBasinsInput> for api::basin::ListBasinsRequest {
    fn from(value: ListBasinsInput) -> Self {
        Self {
            prefix: Some(value.prefix),
            start_after: Some(value.start_after),
            limit: value.limit,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Input for [`list_all_basins`](crate::S2::list_all_basins) operation.
pub struct ListAllBasinsInput {
    /// Filter basins whose names begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: BasinNamePrefix,
    /// Filter basins whose names are lexicographically greater than this value.
    ///
    /// Defaults to `""`.
    pub start_after: BasinNameStartAfter,
    /// Whether to include basins that are being deleted.
    ///
    /// Defaults to `false`.
    pub include_deleted: bool,
}

impl ListAllBasinsInput {
    /// Create a new [`ListAllBasinsInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the prefix used to filter basins whose names begin with this value.
    pub fn with_prefix(self, prefix: BasinNamePrefix) -> Self {
        Self { prefix, ..self }
    }

    /// Set the value used to filter basins whose names are lexicographically greater than this
    /// value.
    pub fn with_start_after(self, start_after: BasinNameStartAfter) -> Self {
        Self {
            start_after,
            ..self
        }
    }

    /// Set whether to include basins that are being deleted.
    pub fn with_include_deleted(self, include_deleted: bool) -> Self {
        Self {
            include_deleted,
            ..self
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Basin information.
pub struct BasinInfo {
    /// Basin name.
    pub name: BasinName,
    /// Location of the basin.
    pub location: Option<LocationName>,
    /// Creation time.
    pub created_at: Timestamp,
    /// Deletion time if the basin is being deleted.
    pub deleted_at: Option<Timestamp>,
}

impl From<api::basin::BasinInfo> for BasinInfo {
    fn from(value: api::basin::BasinInfo) -> Self {
        Self {
            name: value.name,
            location: value.location,
            created_at: value.created_at,
            deleted_at: value.deleted_at,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
/// Reconfiguration for [`TimestampingConfig`].
pub struct TimestampingReconfiguration {
    mode: Reconfigure<TimestampingMode>,
    uncapped: Reconfigure<bool>,
}

impl TimestampingReconfiguration {
    /// Create a new [`TimestampingReconfiguration`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the configured change for [`mode`](TimestampingConfig::mode).
    pub fn mode(&self) -> Reconfigure<&TimestampingMode> {
        self.mode.as_ref()
    }

    /// Return the configured change for [`uncapped`](TimestampingConfig::uncapped).
    pub fn uncapped(&self) -> Reconfigure<bool> {
        self.uncapped
    }

    /// Set the override for the existing [`mode`](TimestampingConfig::mode).
    pub fn with_mode(self, mode: TimestampingMode) -> Self {
        Self {
            mode: Reconfigure::Set(mode),
            ..self
        }
    }

    /// Reset [`mode`](TimestampingConfig::mode) to the server default.
    pub fn reset_mode(self) -> Self {
        Self {
            mode: Reconfigure::Reset,
            ..self
        }
    }

    /// Set the override for the existing [`uncapped`](TimestampingConfig::uncapped).
    pub fn with_uncapped(self, uncapped: bool) -> Self {
        Self {
            uncapped: Reconfigure::Set(uncapped),
            ..self
        }
    }

    /// Reset [`uncapped`](TimestampingConfig::uncapped) to the server default.
    pub fn reset_uncapped(self) -> Self {
        Self {
            uncapped: Reconfigure::Reset,
            ..self
        }
    }
}

impl From<TimestampingReconfiguration> for api::config::TimestampingReconfiguration {
    fn from(value: TimestampingReconfiguration) -> Self {
        Self {
            mode: value.mode.map(Into::into).into_maybe(),
            uncapped: value.uncapped.into_maybe(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[must_use]
/// Reconfiguration for [`DeleteOnEmptyConfig`].
pub struct DeleteOnEmptyReconfiguration {
    min_age_secs: Reconfigure<u64>,
}

impl DeleteOnEmptyReconfiguration {
    /// Create a new [`DeleteOnEmptyReconfiguration`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the configured change for [`min_age`](DeleteOnEmptyConfig::min_age).
    pub fn min_age(&self) -> Reconfigure<Duration> {
        self.min_age_secs.map(Duration::from_secs)
    }

    /// Set the override for the existing [`min_age`](DeleteOnEmptyConfig::min_age).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `min_age` has sub-second precision.
    pub fn with_min_age(self, min_age: Duration) -> Result<Self, ValidationError> {
        Ok(Self {
            min_age_secs: Reconfigure::Set(whole_seconds(min_age, "delete_on_empty.min_age")?),
        })
    }

    /// Reset [`min_age`](DeleteOnEmptyConfig::min_age) to the server default.
    pub fn reset_min_age(self) -> Self {
        Self {
            min_age_secs: Reconfigure::Reset,
        }
    }
}

impl From<DeleteOnEmptyReconfiguration> for api::config::DeleteOnEmptyReconfiguration {
    fn from(value: DeleteOnEmptyReconfiguration) -> Self {
        Self {
            min_age_secs: value.min_age_secs.into_maybe(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
/// Reconfiguration for [`StreamConfig`].
pub struct StreamReconfiguration {
    storage_class: Reconfigure<String>,
    retention_policy: Reconfigure<RetentionPolicy>,
    timestamping: Reconfigure<TimestampingReconfiguration>,
    delete_on_empty: Reconfigure<DeleteOnEmptyReconfiguration>,
}

impl StreamReconfiguration {
    /// Create a new [`StreamReconfiguration`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the configured change for [`storage_class`](StreamConfig::storage_class).
    pub fn storage_class(&self) -> Reconfigure<&str> {
        self.storage_class.as_ref().map(String::as_str)
    }

    /// Return the configured change for [`retention_policy`](StreamConfig::retention_policy).
    pub fn retention_policy(&self) -> Reconfigure<&RetentionPolicy> {
        self.retention_policy.as_ref()
    }

    /// Return the configured change for [`timestamping`](StreamConfig::timestamping).
    pub fn timestamping(&self) -> Reconfigure<&TimestampingReconfiguration> {
        self.timestamping.as_ref()
    }

    /// Return the configured change for [`delete_on_empty`](StreamConfig::delete_on_empty).
    pub fn delete_on_empty(&self) -> Reconfigure<&DeleteOnEmptyReconfiguration> {
        self.delete_on_empty.as_ref()
    }

    /// Set the override for the existing [`storage_class`](StreamConfig::storage_class).
    pub fn with_storage_class(self, storage_class: impl Into<String>) -> Self {
        Self {
            storage_class: Reconfigure::Set(storage_class.into()),
            ..self
        }
    }

    /// Reset [`storage_class`](StreamConfig::storage_class) to the server default.
    pub fn reset_storage_class(self) -> Self {
        Self {
            storage_class: Reconfigure::Reset,
            ..self
        }
    }

    /// Set the override for the existing [`retention_policy`](StreamConfig::retention_policy).
    pub fn with_retention_policy(self, retention_policy: RetentionPolicy) -> Self {
        Self {
            retention_policy: Reconfigure::Set(retention_policy),
            ..self
        }
    }

    /// Reset [`retention_policy`](StreamConfig::retention_policy) to the server default.
    pub fn reset_retention_policy(self) -> Self {
        Self {
            retention_policy: Reconfigure::Reset,
            ..self
        }
    }

    /// Set the override for the existing [`timestamping`](StreamConfig::timestamping).
    pub fn with_timestamping(self, timestamping: TimestampingReconfiguration) -> Self {
        Self {
            timestamping: Reconfigure::Set(timestamping),
            ..self
        }
    }

    /// Reset [`timestamping`](StreamConfig::timestamping) to the server default.
    pub fn reset_timestamping(self) -> Self {
        Self {
            timestamping: Reconfigure::Reset,
            ..self
        }
    }

    /// Set the override for the existing [`delete_on_empty`](StreamConfig::delete_on_empty).
    pub fn with_delete_on_empty(self, delete_on_empty: DeleteOnEmptyReconfiguration) -> Self {
        Self {
            delete_on_empty: Reconfigure::Set(delete_on_empty),
            ..self
        }
    }

    /// Reset [`delete_on_empty`](StreamConfig::delete_on_empty) to the server default.
    pub fn reset_delete_on_empty(self) -> Self {
        Self {
            delete_on_empty: Reconfigure::Reset,
            ..self
        }
    }
}

impl From<StreamReconfiguration> for api::config::StreamReconfiguration {
    fn from(value: StreamReconfiguration) -> Self {
        Self {
            storage_class: value.storage_class.into_maybe(),
            retention_policy: value.retention_policy.map(Into::into).into_maybe(),
            timestamping: value.timestamping.map(Into::into).into_maybe(),
            delete_on_empty: value.delete_on_empty.map(Into::into).into_maybe(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
/// Reconfiguration for [`BasinConfig`].
pub struct BasinReconfiguration {
    default_stream_config: Reconfigure<StreamReconfiguration>,
    stream_cipher: Reconfigure<EncryptionAlgorithm>,
    create_stream_on_append: Reconfigure<bool>,
    create_stream_on_read: Reconfigure<bool>,
}

impl BasinReconfiguration {
    /// Create a new [`BasinReconfiguration`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the configured change for
    /// [`default_stream_config`](BasinConfig::default_stream_config).
    pub fn default_stream_config(&self) -> Reconfigure<&StreamReconfiguration> {
        self.default_stream_config.as_ref()
    }

    /// Return the configured change for [`stream_cipher`](BasinConfig::stream_cipher).
    pub fn stream_cipher(&self) -> Reconfigure<&EncryptionAlgorithm> {
        self.stream_cipher.as_ref()
    }

    /// Return the configured change for
    /// [`create_stream_on_append`](BasinConfig::create_stream_on_append).
    pub fn create_stream_on_append(&self) -> Reconfigure<bool> {
        self.create_stream_on_append
    }

    /// Return the configured change for
    /// [`create_stream_on_read`](BasinConfig::create_stream_on_read).
    pub fn create_stream_on_read(&self) -> Reconfigure<bool> {
        self.create_stream_on_read
    }

    /// Set the override for the existing
    /// [`default_stream_config`](BasinConfig::default_stream_config).
    pub fn with_default_stream_config(self, config: StreamReconfiguration) -> Self {
        Self {
            default_stream_config: Reconfigure::Set(config),
            ..self
        }
    }

    /// Reset [`default_stream_config`](BasinConfig::default_stream_config) to the server default.
    pub fn reset_default_stream_config(self) -> Self {
        Self {
            default_stream_config: Reconfigure::Reset,
            ..self
        }
    }

    /// Set the override for the existing [`stream_cipher`](BasinConfig::stream_cipher).
    pub fn with_stream_cipher(self, stream_cipher: EncryptionAlgorithm) -> Self {
        Self {
            stream_cipher: Reconfigure::Set(stream_cipher),
            ..self
        }
    }

    /// Reset [`stream_cipher`](BasinConfig::stream_cipher) to the server default.
    pub fn reset_stream_cipher(self) -> Self {
        Self {
            stream_cipher: Reconfigure::Reset,
            ..self
        }
    }

    /// Set the override for the existing
    /// [`create_stream_on_append`](BasinConfig::create_stream_on_append).
    pub fn with_create_stream_on_append(self, create_stream_on_append: bool) -> Self {
        Self {
            create_stream_on_append: Reconfigure::Set(create_stream_on_append),
            ..self
        }
    }

    /// Reset [`create_stream_on_append`](BasinConfig::create_stream_on_append) to the server
    /// default.
    pub fn reset_create_stream_on_append(self) -> Self {
        Self {
            create_stream_on_append: Reconfigure::Reset,
            ..self
        }
    }

    /// Set the override for the existing
    /// [`create_stream_on_read`](BasinConfig::create_stream_on_read).
    pub fn with_create_stream_on_read(self, create_stream_on_read: bool) -> Self {
        Self {
            create_stream_on_read: Reconfigure::Set(create_stream_on_read),
            ..self
        }
    }

    /// Reset [`create_stream_on_read`](BasinConfig::create_stream_on_read) to the server default.
    pub fn reset_create_stream_on_read(self) -> Self {
        Self {
            create_stream_on_read: Reconfigure::Reset,
            ..self
        }
    }
}

impl From<BasinReconfiguration> for api::config::BasinReconfiguration {
    fn from(value: BasinReconfiguration) -> Self {
        Self {
            default_stream_config: value.default_stream_config.map(Into::into).into_maybe(),
            stream_cipher: value.stream_cipher.map(Into::into).into_maybe(),
            create_stream_on_append: value.create_stream_on_append.into_maybe(),
            create_stream_on_read: value.create_stream_on_read.into_maybe(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// AWS PrivateLink details for a location.
///
/// See [`PrivateNet`].
pub struct AwsPrivateNet {
    /// Endpoint service name, for creating a VPC endpoint.
    pub service_name: String,
    /// Private DNS name of the endpoint service. With private DNS enabled on the VPC endpoint,
    /// it resolves to the endpoint, and can be used as the account endpoint so that account
    /// requests also go over PrivateLink.
    pub private_dns_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// How the account can reach a location over a private network. Exactly one kind applies.
pub enum PrivateNet {
    /// AWS PrivateLink.
    Aws(AwsPrivateNet),
    /// A kind this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl From<MaybeKnown<api::location::PrivateNet>> for PrivateNet {
    fn from(value: MaybeKnown<api::location::PrivateNet>) -> Self {
        match value {
            MaybeKnown::Known(api::location::PrivateNet::Aws(aws)) => Self::Aws(AwsPrivateNet {
                service_name: aws.service_name,
                private_dns_name: aws.private_dns_name,
            }),
            MaybeKnown::Unknown(name) => Self::Unknown(name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Location information.
pub struct LocationInfo {
    /// Location name.
    pub name: LocationName,
    /// Location represents a private placement, limited by account.
    pub is_private: bool,
    /// [Storage classes](https://s2.dev/docs/storage-classes) available to the account in this
    /// location.
    pub storage_classes: Option<Vec<String>>,
    /// Default [storage class](https://s2.dev/docs/storage-classes) for this location.
    pub default_storage_class: Option<String>,
    /// [Private networking](https://s2.dev/docs/platform/private-networking) details for the
    /// account in this location, which can differ between accounts.
    /// `None` until the account has a basin in this location, and when the location cannot be
    /// reached over a private network.
    pub private_net: Option<PrivateNet>,
}

impl From<api::location::LocationInfo> for LocationInfo {
    fn from(value: api::location::LocationInfo) -> Self {
        Self {
            name: value.name,
            is_private: value.is_private,
            storage_classes: value.storage_classes,
            default_storage_class: value.default_storage_class,
            private_net: value.private_net.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Input for [`list_streams`](crate::S2Basin::list_streams) operation.
pub struct ListStreamsInput {
    /// Filter streams whose names begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: StreamNamePrefix,
    /// Filter streams whose names are lexicographically greater than this value.
    ///
    /// Defaults to `""`.
    pub start_after: StreamNameStartAfter,
    /// Number of streams to return in a page. Will be clamped to a maximum of `1000`.
    ///
    /// Defaults to `1000`.
    pub limit: Option<usize>,
}

impl ListStreamsInput {
    /// Create a new [`ListStreamsInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the prefix used to filter streams whose names begin with this value.
    pub fn with_prefix(self, prefix: StreamNamePrefix) -> Self {
        Self { prefix, ..self }
    }

    /// Set the value used to filter streams whose names are lexicographically greater than this
    /// value.
    pub fn with_start_after(self, start_after: StreamNameStartAfter) -> Self {
        Self {
            start_after,
            ..self
        }
    }

    /// Set the limit on number of streams to return in a page.
    pub fn with_limit(self, limit: usize) -> Self {
        Self {
            limit: Some(limit),
            ..self
        }
    }
}

impl From<ListStreamsInput> for api::stream::ListStreamsRequest {
    fn from(value: ListStreamsInput) -> Self {
        Self {
            prefix: Some(value.prefix),
            start_after: Some(value.start_after),
            limit: value.limit,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Input for [`list_all_streams`](crate::S2Basin::list_all_streams) operation.
pub struct ListAllStreamsInput {
    /// Filter streams whose names begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: StreamNamePrefix,
    /// Filter streams whose names are lexicographically greater than this value.
    ///
    /// Defaults to `""`.
    pub start_after: StreamNameStartAfter,
    /// Whether to include streams that are being deleted.
    ///
    /// Defaults to `false`.
    pub include_deleted: bool,
}

impl ListAllStreamsInput {
    /// Create a new [`ListAllStreamsInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the prefix used to filter streams whose names begin with this value.
    pub fn with_prefix(self, prefix: StreamNamePrefix) -> Self {
        Self { prefix, ..self }
    }

    /// Set the value used to filter streams whose names are lexicographically greater than this
    /// value.
    pub fn with_start_after(self, start_after: StreamNameStartAfter) -> Self {
        Self {
            start_after,
            ..self
        }
    }

    /// Set whether to include streams that are being deleted.
    pub fn with_include_deleted(self, include_deleted: bool) -> Self {
        Self {
            include_deleted,
            ..self
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Stream information.
pub struct StreamInfo {
    /// Stream name.
    pub name: StreamName,
    /// Creation time.
    pub created_at: Timestamp,
    /// Deletion time if the stream is being deleted.
    pub deleted_at: Option<Timestamp>,
    /// Encryption algorithm for this stream, if encryption is enabled.
    pub cipher: Option<EncryptionAlgorithm>,
}

impl From<api::stream::StreamInfo> for StreamInfo {
    fn from(value: api::stream::StreamInfo) -> Self {
        Self {
            name: value.name,
            created_at: value.created_at,
            deleted_at: value.deleted_at,
            cipher: value.cipher.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Input for [`create_stream`](crate::S2Basin::create_stream) operation.
pub struct CreateStreamInput {
    /// Stream name.
    pub name: StreamName,
    /// Configuration for the stream.
    ///
    /// See [`StreamConfig`] for defaults.
    pub config: Option<StreamConfig>,
}

impl CreateStreamInput {
    /// Create a new [`CreateStreamInput`] with the given stream name.
    pub fn new(name: StreamName) -> Self {
        Self { name, config: None }
    }

    /// Set the configuration for the stream.
    pub fn with_config(self, config: StreamConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }
}

impl From<CreateStreamInput> for api::stream::CreateStreamRequest {
    fn from(value: CreateStreamInput) -> Self {
        Self {
            stream: value.name,
            config: value.config.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Input for [`ensure_stream`](crate::S2Basin::ensure_stream) operation.
pub struct EnsureStreamInput {
    /// Stream name.
    pub name: StreamName,
    /// Desired full configuration for the stream.
    ///
    /// Unlike [`reconfigure_stream`](crate::S2Basin::reconfigure_stream), omitted fields are reset
    /// to their defaults (inheriting the basin's default stream configuration) when ensuring an
    /// existing stream.
    pub config: Option<StreamConfig>,
}

impl EnsureStreamInput {
    /// Create a new [`EnsureStreamInput`] with the given stream name.
    pub fn new(name: StreamName) -> Self {
        Self { name, config: None }
    }

    /// Set the full desired configuration for the stream (omitted fields reset to defaults).
    pub fn with_config(self, config: StreamConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }

    pub(crate) fn into_parts(self) -> (StreamName, Option<api::config::StreamConfig>) {
        (self.name, self.config.map(Into::into))
    }
}
