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
    basin::{BasinName, BasinNamePrefix, BasinNameStartAfter},
    location::LocationName,
    maybe::Maybe,
    stream::{StreamName, StreamNamePrefix, StreamNameStartAfter},
};

use super::whole_seconds;
use crate::error::{RequestError, ValidationError};

/// A page of values.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Page<T> {
    /// Values in this page.
    pub values: Vec<T>,
    /// Whether there are more pages.
    pub has_more: bool,
}

impl<T> Page<T> {
    /// Construct a page of values.
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(values: Vec<T>, has_more: bool) -> Self {
        Self { values, has_more }
    }

    pub(crate) fn from_api<U>(values: Vec<U>, has_more: bool, map: impl FnMut(U) -> T) -> Self {
        Self {
            values: values.into_iter().map(map).collect(),
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
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
    #[must_use]
    pub fn as_ref(&self) -> Reconfigure<&T> {
        match self {
            Self::Unchanged => Reconfigure::Unchanged,
            Self::Set(v) => Reconfigure::Set(v),
            Self::Reset => Reconfigure::Reset,
        }
    }

    /// Map a `Reconfigure<T>` to `Reconfigure<U>` by applying a function to a `Set` value.
    #[must_use]
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

/// Encryption algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncryptionAlgorithm {
    /// AEGIS-256
    Aegis256,
    /// AES-256-GCM
    Aes256Gcm,
    /// An algorithm this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl EncryptionAlgorithm {
    /// Return the wire name of this encryption algorithm.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Aegis256 => "aegis-256",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Unknown(name) => name,
        }
    }

    pub(crate) fn from_api(value: MaybeKnown<api::config::EncryptionAlgorithm>) -> Self {
        match value {
            MaybeKnown::Known(api::config::EncryptionAlgorithm::Aegis256) => Self::Aegis256,
            MaybeKnown::Known(api::config::EncryptionAlgorithm::Aes256Gcm) => Self::Aes256Gcm,
            MaybeKnown::Unknown(name) => Self::Unknown(name),
        }
    }

    pub(crate) fn into_api(self) -> MaybeKnown<api::config::EncryptionAlgorithm> {
        match self {
            Self::Aegis256 => api::config::EncryptionAlgorithm::Aegis256.into(),
            Self::Aes256Gcm => api::config::EncryptionAlgorithm::Aes256Gcm.into(),
            Self::Unknown(name) => MaybeKnown::Unknown(name),
        }
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Retention policy for records in a stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RetentionPolicy {
    /// Age in seconds. Records older than this age are automatically trimmed.
    ///
    /// The server requires a value greater than `0`; validation of positivity is left to the
    /// server.
    Age(u64),
    /// Records are retained indefinitely unless explicitly trimmed.
    Infinite,
    /// A policy this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl RetentionPolicy {
    /// Create an age-based retention policy from a whole-second [`Duration`].
    ///
    /// The SDK checks whole-second precision and leaves positivity validation (`> 0`) to the
    /// server.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `age` has sub-second precision.
    pub fn age(age: Duration) -> Result<Self, ValidationError> {
        Ok(Self::Age(whole_seconds(age, "retention_age")?))
    }

    pub(crate) fn from_api(value: MaybeKnown<api::config::RetentionPolicy>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
        match value {
            api::config::RetentionPolicy::Age(secs) => Self::Age(secs),
            api::config::RetentionPolicy::Infinite(_) => Self::Infinite,
        }
    }

    pub(crate) fn into_api(self) -> MaybeKnown<api::config::RetentionPolicy> {
        let known = match self {
            Self::Age(secs) => api::config::RetentionPolicy::Age(secs),
            Self::Infinite => {
                api::config::RetentionPolicy::Infinite(api::config::InfiniteRetention {})
            }
            Self::Unknown(name) => return MaybeKnown::Unknown(name),
        };
        MaybeKnown::Known(known)
    }
}

/// Timestamping mode for appends that influences how timestamps are handled.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TimestampingMode {
    /// Prefer client-specified timestamp if present otherwise use arrival time.
    #[default]
    ClientPrefer,
    /// Require a client-specified timestamp and reject the append if it is missing.
    ClientRequire,
    /// Use the arrival time and ignore any client-specified timestamp.
    Arrival,
    /// A mode this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl TimestampingMode {
    /// Return the wire name of this timestamping mode.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::ClientPrefer => "client-prefer",
            Self::ClientRequire => "client-require",
            Self::Arrival => "arrival",
            Self::Unknown(name) => name,
        }
    }

    pub(crate) fn from_api(value: MaybeKnown<api::config::TimestampingMode>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
        match value {
            api::config::TimestampingMode::ClientPrefer => Self::ClientPrefer,
            api::config::TimestampingMode::ClientRequire => Self::ClientRequire,
            api::config::TimestampingMode::Arrival => Self::Arrival,
        }
    }

    pub(crate) fn into_api(self) -> MaybeKnown<api::config::TimestampingMode> {
        let known = match self {
            Self::ClientPrefer => api::config::TimestampingMode::ClientPrefer,
            Self::ClientRequire => api::config::TimestampingMode::ClientRequire,
            Self::Arrival => api::config::TimestampingMode::Arrival,
            Self::Unknown(name) => return MaybeKnown::Unknown(name),
        };
        MaybeKnown::Known(known)
    }
}

impl fmt::Display for TimestampingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration for timestamping behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct TimestampingConfig {
    mode: Option<TimestampingMode>,
    uncapped: Option<bool>,
}

impl TimestampingConfig {
    /// Create a new [`TimestampingConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the configured timestamping mode, if set.
    ///
    /// Server defaults to [`TimestampingMode::ClientPrefer`].
    #[must_use]
    pub fn mode(&self) -> Option<&TimestampingMode> {
        self.mode.as_ref()
    }

    /// Return whether client-specified timestamps are allowed to exceed the arrival time, if set.
    ///
    /// Server defaults to `false`.
    #[must_use]
    pub fn uncapped(&self) -> Option<bool> {
        self.uncapped
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

    pub(crate) fn from_api(value: api::config::TimestampingConfig) -> Self {
        Self {
            mode: value.mode.map(TimestampingMode::from_api),
            uncapped: value.uncapped,
        }
    }

    pub(crate) fn into_api(self) -> api::config::TimestampingConfig {
        api::config::TimestampingConfig {
            mode: self.mode.map(TimestampingMode::into_api),
            uncapped: self.uncapped,
        }
    }
}

/// Configuration for automatically deleting a stream when it becomes empty.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[must_use]
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
    #[must_use]
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

    pub(crate) fn from_api(value: api::config::DeleteOnEmptyConfig) -> Self {
        Self {
            min_age_secs: value.min_age_secs,
        }
    }

    pub(crate) fn into_api(self) -> api::config::DeleteOnEmptyConfig {
        api::config::DeleteOnEmptyConfig {
            min_age_secs: self.min_age_secs,
        }
    }
}

/// Configuration for a stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct StreamConfig {
    storage_class: Option<String>,
    retention_policy: Option<RetentionPolicy>,
    timestamping: Option<TimestampingConfig>,
    delete_on_empty: Option<DeleteOnEmptyConfig>,
}

impl StreamConfig {
    /// Create a new [`StreamConfig`] with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the [storage class](https://s2.dev/docs/storage-classes) for the stream, if set.
    #[must_use]
    pub fn storage_class(&self) -> Option<&str> {
        self.storage_class.as_deref()
    }

    /// Return the retention policy for records in the stream, if set.
    ///
    /// Server defaults to `7 days`.
    #[must_use]
    pub fn retention_policy(&self) -> Option<&RetentionPolicy> {
        self.retention_policy.as_ref()
    }

    /// Return the timestamping configuration, if set.
    #[must_use]
    pub fn timestamping(&self) -> Option<&TimestampingConfig> {
        self.timestamping.as_ref()
    }

    /// Return the delete-on-empty configuration, if set.
    #[must_use]
    pub fn delete_on_empty(&self) -> Option<DeleteOnEmptyConfig> {
        self.delete_on_empty
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

    pub(crate) fn from_api(value: api::config::StreamConfig) -> Self {
        Self {
            storage_class: value.storage_class,
            retention_policy: value.retention_policy.map(RetentionPolicy::from_api),
            timestamping: value.timestamping.map(TimestampingConfig::from_api),
            delete_on_empty: value.delete_on_empty.map(DeleteOnEmptyConfig::from_api),
        }
    }

    pub(crate) fn into_api(self) -> api::config::StreamConfig {
        api::config::StreamConfig {
            storage_class: self.storage_class,
            retention_policy: self.retention_policy.map(RetentionPolicy::into_api),
            timestamping: self.timestamping.map(TimestampingConfig::into_api),
            delete_on_empty: self.delete_on_empty.map(DeleteOnEmptyConfig::into_api),
        }
    }
}

/// Configuration for a basin.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct BasinConfig {
    default_stream_config: Option<StreamConfig>,
    stream_cipher: Option<EncryptionAlgorithm>,
    create_stream_on_append: bool,
    create_stream_on_read: bool,
}

impl BasinConfig {
    /// Create a new [`BasinConfig`] with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the default configuration for streams in the basin, if set.
    #[must_use]
    pub fn default_stream_config(&self) -> Option<&StreamConfig> {
        self.default_stream_config.as_ref()
    }

    /// Return the encryption algorithm applied to newly created streams in the basin, if set.
    #[must_use]
    pub fn stream_cipher(&self) -> Option<&EncryptionAlgorithm> {
        self.stream_cipher.as_ref()
    }

    /// Return whether streams are automatically created on append.
    #[must_use]
    pub fn create_stream_on_append(&self) -> bool {
        self.create_stream_on_append
    }

    /// Return whether streams are automatically created on read.
    #[must_use]
    pub fn create_stream_on_read(&self) -> bool {
        self.create_stream_on_read
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

    pub(crate) fn from_api(value: api::config::BasinConfig) -> Self {
        Self {
            default_stream_config: value.default_stream_config.map(StreamConfig::from_api),
            stream_cipher: value.stream_cipher.map(EncryptionAlgorithm::from_api),
            create_stream_on_append: value.create_stream_on_append,
            create_stream_on_read: value.create_stream_on_read,
        }
    }

    pub(crate) fn into_api(self) -> api::config::BasinConfig {
        api::config::BasinConfig {
            default_stream_config: self.default_stream_config.map(StreamConfig::into_api),
            stream_cipher: self.stream_cipher.map(EncryptionAlgorithm::into_api),
            create_stream_on_append: self.create_stream_on_append,
            create_stream_on_read: self.create_stream_on_read,
        }
    }
}

/// Input for [`create_basin`](crate::S2::create_basin) operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct CreateBasinInput {
    name: BasinName,
    config: Option<BasinConfig>,
    location: Option<LocationName>,
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

    /// Return the basin name.
    #[must_use]
    pub fn name(&self) -> &BasinName {
        &self.name
    }

    /// Return the basin configuration, if set.
    #[must_use]
    pub fn config(&self) -> Option<&BasinConfig> {
        self.config.as_ref()
    }

    /// Return the basin location, if set.
    #[must_use]
    pub fn location(&self) -> Option<&LocationName> {
        self.location.as_ref()
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

    pub(crate) fn into_api(self) -> api::basin::CreateBasinRequest {
        api::basin::CreateBasinRequest {
            basin: self.name,
            config: self.config.map(BasinConfig::into_api),
            location: self.location,
        }
    }
}

/// Input for [`ensure_basin`](crate::S2::ensure_basin) operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct EnsureBasinInput {
    name: BasinName,
    config: Option<BasinConfig>,
    location: Option<LocationName>,
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

    /// Return the basin name.
    #[must_use]
    pub fn name(&self) -> &BasinName {
        &self.name
    }

    /// Return the desired full configuration for the basin, if set.
    #[must_use]
    pub fn config(&self) -> Option<&BasinConfig> {
        self.config.as_ref()
    }

    /// Return the basin location, if set.
    #[must_use]
    pub fn location(&self) -> Option<&LocationName> {
        self.location.as_ref()
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
                config: self.config.map(BasinConfig::into_api),
                location: self.location,
            })
        } else {
            None
        };
        (self.name, request)
    }
}

/// Output for `ensure` operations ([`ensure_basin`](crate::S2::ensure_basin),
/// [`ensure_stream`](crate::S2Basin::ensure_stream)).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    #[must_use]
    pub fn inner(&self) -> &T {
        match self {
            Self::Created(info) | Self::Updated(info) | Self::Noop(info) => info,
        }
    }

    /// Consume this output and return the resource info.
    #[must_use]
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

/// Input for [`list_basins`](crate::S2::list_basins) operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct ListBasinsInput {
    prefix: BasinNamePrefix,
    start_after: BasinNameStartAfter,
    limit: Option<usize>,
}

impl ListBasinsInput {
    /// Create a new [`ListBasinsInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the prefix filter.
    #[must_use]
    pub fn prefix(&self) -> &BasinNamePrefix {
        &self.prefix
    }

    /// Return the pagination cursor (`start_after`).
    #[must_use]
    pub fn start_after(&self) -> &BasinNameStartAfter {
        &self.start_after
    }

    /// Return the page size limit, if set.
    #[must_use]
    pub fn limit(&self) -> Option<usize> {
        self.limit
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

    pub(crate) fn set_start_after(&mut self, start_after: BasinNameStartAfter) {
        self.start_after = start_after;
    }

    pub(crate) fn into_api(self) -> api::basin::ListBasinsRequest {
        api::basin::ListBasinsRequest {
            prefix: Some(self.prefix),
            start_after: Some(self.start_after),
            limit: self.limit,
        }
    }
}

/// Input for [`list_all_basins`](crate::S2::list_all_basins) operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct ListAllBasinsInput {
    prefix: BasinNamePrefix,
    start_after: BasinNameStartAfter,
    include_deleted: bool,
}

impl ListAllBasinsInput {
    /// Create a new [`ListAllBasinsInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the prefix filter.
    #[must_use]
    pub fn prefix(&self) -> &BasinNamePrefix {
        &self.prefix
    }

    /// Return the pagination cursor (`start_after`).
    #[must_use]
    pub fn start_after(&self) -> &BasinNameStartAfter {
        &self.start_after
    }

    /// Return whether basins that are being deleted are included.
    #[must_use]
    pub fn include_deleted(&self) -> bool {
        self.include_deleted
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

    pub(crate) fn into_parts(self) -> (ListBasinsInput, bool) {
        (
            ListBasinsInput::new()
                .with_prefix(self.prefix)
                .with_start_after(self.start_after),
            self.include_deleted,
        )
    }
}

/// Basin information.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

impl BasinInfo {
    /// Construct a [`BasinInfo`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(name: BasinName, created_at: Timestamp) -> Self {
        Self {
            name,
            location: None,
            created_at,
            deleted_at: None,
        }
    }

    /// Set the basin location.
    #[must_use]
    pub fn with_location(mut self, location: LocationName) -> Self {
        self.location = Some(location);
        self
    }

    /// Set the deletion timestamp.
    #[must_use]
    pub fn with_deleted_at(mut self, deleted_at: Timestamp) -> Self {
        self.deleted_at = Some(deleted_at);
        self
    }

    pub(crate) fn from_api(value: api::basin::BasinInfo) -> Self {
        Self {
            name: value.name,
            location: value.location,
            created_at: value.created_at,
            deleted_at: value.deleted_at,
        }
    }
}

/// Reconfiguration for [`TimestampingConfig`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
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
    #[must_use]
    pub fn mode(&self) -> Reconfigure<&TimestampingMode> {
        self.mode.as_ref()
    }

    /// Return the configured change for [`uncapped`](TimestampingConfig::uncapped).
    #[must_use]
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

    pub(crate) fn into_api(self) -> api::config::TimestampingReconfiguration {
        api::config::TimestampingReconfiguration {
            mode: self.mode.map(TimestampingMode::into_api).into_maybe(),
            uncapped: self.uncapped.into_maybe(),
        }
    }
}

/// Reconfiguration for [`DeleteOnEmptyConfig`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct DeleteOnEmptyReconfiguration {
    min_age_secs: Reconfigure<u64>,
}

impl DeleteOnEmptyReconfiguration {
    /// Create a new [`DeleteOnEmptyReconfiguration`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the configured change for [`min_age`](DeleteOnEmptyConfig::min_age).
    #[must_use]
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

    pub(crate) fn into_api(self) -> api::config::DeleteOnEmptyReconfiguration {
        api::config::DeleteOnEmptyReconfiguration {
            min_age_secs: self.min_age_secs.into_maybe(),
        }
    }
}

/// Reconfiguration for [`StreamConfig`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
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
    #[must_use]
    pub fn storage_class(&self) -> Reconfigure<&str> {
        self.storage_class.as_ref().map(String::as_str)
    }

    /// Return the configured change for [`retention_policy`](StreamConfig::retention_policy).
    #[must_use]
    pub fn retention_policy(&self) -> Reconfigure<&RetentionPolicy> {
        self.retention_policy.as_ref()
    }

    /// Return the configured change for [`timestamping`](StreamConfig::timestamping).
    #[must_use]
    pub fn timestamping(&self) -> Reconfigure<&TimestampingReconfiguration> {
        self.timestamping.as_ref()
    }

    /// Return the configured change for [`delete_on_empty`](StreamConfig::delete_on_empty).
    #[must_use]
    pub fn delete_on_empty(&self) -> Reconfigure<DeleteOnEmptyReconfiguration> {
        self.delete_on_empty
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

    pub(crate) fn into_api(self) -> api::config::StreamReconfiguration {
        api::config::StreamReconfiguration {
            storage_class: self.storage_class.into_maybe(),
            retention_policy: self
                .retention_policy
                .map(RetentionPolicy::into_api)
                .into_maybe(),
            timestamping: self
                .timestamping
                .map(TimestampingReconfiguration::into_api)
                .into_maybe(),
            delete_on_empty: self
                .delete_on_empty
                .map(DeleteOnEmptyReconfiguration::into_api)
                .into_maybe(),
        }
    }
}

/// Reconfiguration for [`BasinConfig`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
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
    #[must_use]
    pub fn default_stream_config(&self) -> Reconfigure<&StreamReconfiguration> {
        self.default_stream_config.as_ref()
    }

    /// Return the configured change for [`stream_cipher`](BasinConfig::stream_cipher).
    #[must_use]
    pub fn stream_cipher(&self) -> Reconfigure<&EncryptionAlgorithm> {
        self.stream_cipher.as_ref()
    }

    /// Return the configured change for
    /// [`create_stream_on_append`](BasinConfig::create_stream_on_append).
    #[must_use]
    pub fn create_stream_on_append(&self) -> Reconfigure<bool> {
        self.create_stream_on_append
    }

    /// Return the configured change for
    /// [`create_stream_on_read`](BasinConfig::create_stream_on_read).
    #[must_use]
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

    pub(crate) fn into_api(self) -> api::config::BasinReconfiguration {
        api::config::BasinReconfiguration {
            default_stream_config: self
                .default_stream_config
                .map(StreamReconfiguration::into_api)
                .into_maybe(),
            stream_cipher: self
                .stream_cipher
                .map(EncryptionAlgorithm::into_api)
                .into_maybe(),
            create_stream_on_append: self.create_stream_on_append.into_maybe(),
            create_stream_on_read: self.create_stream_on_read.into_maybe(),
        }
    }
}

/// AWS PrivateLink details for a location.
///
/// See [`PrivateNet`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AwsPrivateNet {
    /// Endpoint service name, for creating a VPC endpoint.
    pub service_name: String,
    /// Private DNS name of the endpoint service. With private DNS enabled on the VPC endpoint,
    /// it resolves to the endpoint, and can be used as the account endpoint so that account
    /// requests also go over PrivateLink.
    pub private_dns_name: Option<String>,
}

impl AwsPrivateNet {
    /// Construct an [`AwsPrivateNet`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            private_dns_name: None,
        }
    }

    /// Set the private DNS name.
    #[must_use]
    pub fn with_private_dns_name(mut self, private_dns_name: impl Into<String>) -> Self {
        self.private_dns_name = Some(private_dns_name.into());
        self
    }
}

/// How the account can reach a location over a private network. Exactly one kind applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrivateNet {
    /// AWS PrivateLink.
    Aws(AwsPrivateNet),
    /// A kind this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl PrivateNet {
    pub(crate) fn from_api(value: MaybeKnown<api::location::PrivateNet>) -> Self {
        match value {
            MaybeKnown::Known(api::location::PrivateNet::Aws(aws)) => Self::Aws(AwsPrivateNet {
                service_name: aws.service_name,
                private_dns_name: aws.private_dns_name,
            }),
            MaybeKnown::Unknown(name) => Self::Unknown(name),
        }
    }
}

/// Location information.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

impl LocationInfo {
    /// Construct a [`LocationInfo`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(name: LocationName, is_private: bool) -> Self {
        Self {
            name,
            is_private,
            storage_classes: None,
            default_storage_class: None,
            private_net: None,
        }
    }

    /// Set the storage classes available in this location.
    #[must_use]
    pub fn with_storage_classes(
        mut self,
        storage_classes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.storage_classes = Some(storage_classes.into_iter().map(Into::into).collect());
        self
    }

    /// Set the default storage class for this location.
    #[must_use]
    pub fn with_default_storage_class(mut self, default_storage_class: impl Into<String>) -> Self {
        self.default_storage_class = Some(default_storage_class.into());
        self
    }

    /// Set the private networking details for this location.
    #[must_use]
    pub fn with_private_net(mut self, private_net: PrivateNet) -> Self {
        self.private_net = Some(private_net);
        self
    }

    pub(crate) fn from_api(value: api::location::LocationInfo) -> Self {
        Self {
            name: value.name,
            is_private: value.is_private,
            storage_classes: value.storage_classes,
            default_storage_class: value.default_storage_class,
            private_net: value.private_net.map(PrivateNet::from_api),
        }
    }
}

/// Input for [`list_streams`](crate::S2Basin::list_streams) operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct ListStreamsInput {
    prefix: StreamNamePrefix,
    start_after: StreamNameStartAfter,
    limit: Option<usize>,
}

impl ListStreamsInput {
    /// Create a new [`ListStreamsInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the prefix filter.
    #[must_use]
    pub fn prefix(&self) -> &StreamNamePrefix {
        &self.prefix
    }

    /// Return the pagination cursor (`start_after`).
    #[must_use]
    pub fn start_after(&self) -> &StreamNameStartAfter {
        &self.start_after
    }

    /// Return the page size limit, if set.
    #[must_use]
    pub fn limit(&self) -> Option<usize> {
        self.limit
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

    pub(crate) fn set_start_after(&mut self, start_after: StreamNameStartAfter) {
        self.start_after = start_after;
    }

    pub(crate) fn into_api(self) -> api::stream::ListStreamsRequest {
        api::stream::ListStreamsRequest {
            prefix: Some(self.prefix),
            start_after: Some(self.start_after),
            limit: self.limit,
        }
    }
}

/// Input for [`list_all_streams`](crate::S2Basin::list_all_streams) operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct ListAllStreamsInput {
    prefix: StreamNamePrefix,
    start_after: StreamNameStartAfter,
    include_deleted: bool,
}

impl ListAllStreamsInput {
    /// Create a new [`ListAllStreamsInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the prefix filter.
    #[must_use]
    pub fn prefix(&self) -> &StreamNamePrefix {
        &self.prefix
    }

    /// Return the pagination cursor (`start_after`).
    #[must_use]
    pub fn start_after(&self) -> &StreamNameStartAfter {
        &self.start_after
    }

    /// Return whether streams that are being deleted are included.
    #[must_use]
    pub fn include_deleted(&self) -> bool {
        self.include_deleted
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

    pub(crate) fn into_parts(self) -> (ListStreamsInput, bool) {
        (
            ListStreamsInput::new()
                .with_prefix(self.prefix)
                .with_start_after(self.start_after),
            self.include_deleted,
        )
    }
}

/// Stream information.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

impl StreamInfo {
    /// Construct a [`StreamInfo`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(name: StreamName, created_at: Timestamp) -> Self {
        Self {
            name,
            created_at,
            deleted_at: None,
            cipher: None,
        }
    }

    /// Set the deletion timestamp.
    #[must_use]
    pub fn with_deleted_at(mut self, deleted_at: Timestamp) -> Self {
        self.deleted_at = Some(deleted_at);
        self
    }

    /// Set the stream encryption algorithm.
    #[must_use]
    pub fn with_cipher(mut self, cipher: EncryptionAlgorithm) -> Self {
        self.cipher = Some(cipher);
        self
    }

    pub(crate) fn from_api(value: api::stream::StreamInfo) -> Self {
        Self {
            name: value.name,
            created_at: value.created_at,
            deleted_at: value.deleted_at,
            cipher: value.cipher.map(EncryptionAlgorithm::from_api),
        }
    }
}

/// Input for [`create_stream`](crate::S2Basin::create_stream) operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct CreateStreamInput {
    name: StreamName,
    config: Option<StreamConfig>,
}

impl CreateStreamInput {
    /// Create a new [`CreateStreamInput`] with the given stream name.
    pub fn new(name: StreamName) -> Self {
        Self { name, config: None }
    }

    /// Return the stream name.
    #[must_use]
    pub fn name(&self) -> &StreamName {
        &self.name
    }

    /// Return the stream configuration, if set.
    #[must_use]
    pub fn config(&self) -> Option<&StreamConfig> {
        self.config.as_ref()
    }

    /// Set the configuration for the stream.
    pub fn with_config(self, config: StreamConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }

    pub(crate) fn into_api(self) -> api::stream::CreateStreamRequest {
        api::stream::CreateStreamRequest {
            stream: self.name,
            config: self.config.map(StreamConfig::into_api),
        }
    }
}

/// Input for [`ensure_stream`](crate::S2Basin::ensure_stream) operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct EnsureStreamInput {
    name: StreamName,
    config: Option<StreamConfig>,
}

impl EnsureStreamInput {
    /// Create a new [`EnsureStreamInput`] with the given stream name.
    pub fn new(name: StreamName) -> Self {
        Self { name, config: None }
    }

    /// Return the stream name.
    #[must_use]
    pub fn name(&self) -> &StreamName {
        &self.name
    }

    /// Return the desired full configuration for the stream, if set.
    #[must_use]
    pub fn config(&self) -> Option<&StreamConfig> {
        self.config.as_ref()
    }

    /// Set the full desired configuration for the stream (omitted fields reset to defaults).
    pub fn with_config(self, config: StreamConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }

    pub(crate) fn into_parts(self) -> (StreamName, Option<api::config::StreamConfig>) {
        (self.name, self.config.map(StreamConfig::into_api))
    }
}
