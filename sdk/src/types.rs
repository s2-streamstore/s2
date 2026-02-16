//! Types relevant to [`S2`](crate::S2), [`S2Basin`](crate::S2Basin), and
//! [`S2Stream`](crate::S2Stream).
use std::{
    collections::HashSet,
    env::VarError,
    fmt,
    num::NonZeroU32,
    ops::{Deref, RangeTo},
    pin::Pin,
    str::FromStr,
    time::Duration,
};

use bytes::Bytes;
use http::{
    header::HeaderValue,
    uri::{Authority, Scheme},
};
use rand::RngExt;
use s2_api::{v1 as api, v1::stream::s2s::CompressionAlgorithm};
pub use s2_common::caps::RECORD_BATCH_MAX;
/// Validation error.
pub use s2_common::types::ValidationError;
/// Access token ID.
///
/// **Note:** It must be unique to the account and between 1 and 96 bytes in length.
pub use s2_common::types::access::AccessTokenId;
/// See [`ListAccessTokensInput::prefix`].
pub use s2_common::types::access::AccessTokenIdPrefix;
/// See [`ListAccessTokensInput::start_after`].
pub use s2_common::types::access::AccessTokenIdStartAfter;
/// Basin name.
///
/// **Note:** It must be globally unique and between 8 and 48 bytes in length. It can only
/// comprise lowercase letters, numbers, and hyphens. It cannot begin or end with a hyphen.
pub use s2_common::types::basin::BasinName;
/// See [`ListBasinsInput::prefix`].
pub use s2_common::types::basin::BasinNamePrefix;
/// See [`ListBasinsInput::start_after`].
pub use s2_common::types::basin::BasinNameStartAfter;
/// Stream name.
///
/// **Note:** It must be unique to the basin and between 1 and 512 bytes in length.
pub use s2_common::types::stream::StreamName;
/// See [`ListStreamsInput::prefix`].
pub use s2_common::types::stream::StreamNamePrefix;
/// See [`ListStreamsInput::start_after`].
pub use s2_common::types::stream::StreamNameStartAfter;

pub(crate) const ONE_MIB: u32 = 1024 * 1024;

use s2_common::{maybe::Maybe, record::MAX_FENCING_TOKEN_LENGTH};
use secrecy::SecretString;

use crate::api::{ApiError, ApiErrorResponse};

/// An RFC 3339 datetime.
///
/// It can be created in either of the following ways:
/// - Parse an RFC 3339 datetime string using [`FromStr`] or [`str::parse`].
/// - Convert from [`time::OffsetDateTime`] using [`TryFrom`]/[`TryInto`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct S2DateTime(time::OffsetDateTime);

impl TryFrom<time::OffsetDateTime> for S2DateTime {
    type Error = ValidationError;

    fn try_from(dt: time::OffsetDateTime) -> Result<Self, Self::Error> {
        dt.format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| ValidationError(format!("not a valid RFC 3339 datetime: {e}")))?;
        Ok(Self(dt))
    }
}

impl From<S2DateTime> for time::OffsetDateTime {
    fn from(dt: S2DateTime) -> Self {
        dt.0
    }
}

impl FromStr for S2DateTime {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map(Self)
            .map_err(|e| ValidationError(format!("not a valid RFC 3339 datetime: {e}")))
    }
}

impl fmt::Display for S2DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .format(&time::format_description::well_known::Rfc3339)
                .expect("RFC3339 formatting should not fail for S2DateTime")
        )
    }
}

/// Authority for connecting to an S2 basin.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BasinAuthority {
    /// Parent zone for basins. DNS is used to route to the correct cell for the basin.
    ParentZone(Authority),
    /// Direct cell authority. Basin is expected to be hosted by this cell.
    Direct(Authority),
}

/// Account endpoint.
#[derive(Debug, Clone)]
pub struct AccountEndpoint {
    scheme: Scheme,
    authority: Authority,
}

impl AccountEndpoint {
    /// Create a new [`AccountEndpoint`] with the given endpoint.
    pub fn new(endpoint: &str) -> Result<Self, ValidationError> {
        endpoint.parse()
    }
}

impl FromStr for AccountEndpoint {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, authority) = match s.find("://") {
            Some(idx) => {
                let scheme: Scheme = s[..idx]
                    .parse()
                    .map_err(|_| "invalid account endpoint scheme".to_string())?;
                (scheme, &s[idx + 3..])
            }
            None => (Scheme::HTTPS, s),
        };
        Ok(Self {
            scheme,
            authority: authority
                .parse()
                .map_err(|e| format!("invalid account endpoint authority: {e}"))?,
        })
    }
}

/// Basin endpoint.
#[derive(Debug, Clone)]
pub struct BasinEndpoint {
    scheme: Scheme,
    authority: BasinAuthority,
}

impl BasinEndpoint {
    /// Create a new [`BasinEndpoint`] with the given endpoint.
    pub fn new(endpoint: &str) -> Result<Self, ValidationError> {
        endpoint.parse()
    }
}

impl FromStr for BasinEndpoint {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, authority) = match s.find("://") {
            Some(idx) => {
                let scheme: Scheme = s[..idx]
                    .parse()
                    .map_err(|_| "invalid basin endpoint scheme".to_string())?;
                (scheme, &s[idx + 3..])
            }
            None => (Scheme::HTTPS, s),
        };
        let authority = if let Some(authority) = authority.strip_prefix("{basin}.") {
            BasinAuthority::ParentZone(
                authority
                    .parse()
                    .map_err(|e| format!("invalid basin endpoint authority: {e}"))?,
            )
        } else {
            BasinAuthority::Direct(
                authority
                    .parse()
                    .map_err(|e| format!("invalid basin endpoint authority: {e}"))?,
            )
        };
        Ok(Self { scheme, authority })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Endpoints for the S2 environment.
pub struct S2Endpoints {
    pub(crate) scheme: Scheme,
    pub(crate) account_authority: Authority,
    pub(crate) basin_authority: BasinAuthority,
}

impl S2Endpoints {
    /// Create a new [`S2Endpoints`] with the given account and basin endpoints.
    pub fn new(
        account_endpoint: AccountEndpoint,
        basin_endpoint: BasinEndpoint,
    ) -> Result<Self, ValidationError> {
        if account_endpoint.scheme != basin_endpoint.scheme {
            return Err("account and basin endpoints must have the same scheme".into());
        }
        Ok(Self {
            scheme: account_endpoint.scheme,
            account_authority: account_endpoint.authority,
            basin_authority: basin_endpoint.authority,
        })
    }

    /// Create a new [`S2Endpoints`] from environment variables.
    ///
    /// The following environment variables are expected to be set:
    /// - `S2_ACCOUNT_ENDPOINT` - Account-level endpoint.
    /// - `S2_BASIN_ENDPOINT` - Basin-level endpoint.
    pub fn from_env() -> Result<Self, ValidationError> {
        let account_endpoint: AccountEndpoint = match std::env::var("S2_ACCOUNT_ENDPOINT") {
            Ok(endpoint) => endpoint.parse()?,
            Err(VarError::NotPresent) => return Err("S2_ACCOUNT_ENDPOINT env var not set".into()),
            Err(VarError::NotUnicode(_)) => {
                return Err("S2_ACCOUNT_ENDPOINT is not valid unicode".into());
            }
        };

        let basin_endpoint: BasinEndpoint = match std::env::var("S2_BASIN_ENDPOINT") {
            Ok(endpoint) => endpoint.parse()?,
            Err(VarError::NotPresent) => return Err("S2_BASIN_ENDPOINT env var not set".into()),
            Err(VarError::NotUnicode(_)) => {
                return Err("S2_BASIN_ENDPOINT is not valid unicode".into());
            }
        };

        if account_endpoint.scheme != basin_endpoint.scheme {
            return Err(
                "S2_ACCOUNT_ENDPOINT and S2_BASIN_ENDPOINT must have the same scheme".into(),
            );
        }

        Ok(Self {
            scheme: account_endpoint.scheme,
            account_authority: account_endpoint.authority,
            basin_authority: basin_endpoint.authority,
        })
    }

    pub(crate) fn for_aws() -> Self {
        Self {
            scheme: Scheme::HTTPS,
            account_authority: "aws.s2.dev".try_into().expect("valid authority"),
            basin_authority: BasinAuthority::ParentZone(
                "b.aws.s2.dev".try_into().expect("valid authority"),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// Compression algorithm for request and response bodies.
pub enum Compression {
    /// No compression.
    None,
    /// Gzip compression.
    Gzip,
    /// Zstd compression.
    Zstd,
}

impl From<Compression> for CompressionAlgorithm {
    fn from(value: Compression) -> Self {
        match value {
            Compression::None => CompressionAlgorithm::None,
            Compression::Gzip => CompressionAlgorithm::Gzip,
            Compression::Zstd => CompressionAlgorithm::Zstd,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
/// Retry policy for [`append`](crate::S2Stream::append) and
/// [`append_session`](crate::S2Stream::append_session) operations.
pub enum AppendRetryPolicy {
    /// Retry all appends. Use when duplicate records on the stream are acceptable.
    All,
    /// Only retry appends that include [`match_seq_num`](AppendInput::match_seq_num).
    NoSideEffects,
}

impl AppendRetryPolicy {
    pub(crate) fn is_compliant(&self, input: &AppendInput) -> bool {
        match self {
            Self::All => true,
            Self::NoSideEffects => input.match_seq_num.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Configuration for retrying requests in case of transient failures.
///
/// Exponential backoff with jitter is the retry strategy. Below is the pseudocode for the strategy:
/// ```text
/// base_delay = min(min_base_delay · 2ⁿ, max_base_delay)    (n = retry attempt, starting from 0)
///     jitter = rand[0, base_delay]
///     delay  = base_delay + jitter
/// ````
pub struct RetryConfig {
    /// Total number of attempts including the initial try. A value of `1` means no retries.
    ///
    /// Defaults to `3`.
    pub max_attempts: NonZeroU32,
    /// Minimum base delay for retries.
    ///
    /// Defaults to `100ms`.
    pub min_base_delay: Duration,
    /// Maximum base delay for retries.
    ///
    /// Defaults to `1s`.
    pub max_base_delay: Duration,
    /// Retry policy for [`append`](crate::S2Stream::append) and
    /// [`append_session`](crate::S2Stream::append_session) operations.
    ///
    /// Defaults to `All`.
    pub append_retry_policy: AppendRetryPolicy,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: NonZeroU32::new(3).expect("valid non-zero u32"),
            min_base_delay: Duration::from_millis(100),
            max_base_delay: Duration::from_secs(1),
            append_retry_policy: AppendRetryPolicy::All,
        }
    }
}

impl RetryConfig {
    /// Create a new [`RetryConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn max_retries(&self) -> u32 {
        self.max_attempts.get() - 1
    }

    /// Set the total number of attempts including the initial try.
    pub fn with_max_attempts(self, max_attempts: NonZeroU32) -> Self {
        Self {
            max_attempts,
            ..self
        }
    }

    /// Set the minimum base delay for retries.
    pub fn with_min_base_delay(self, min_base_delay: Duration) -> Self {
        Self {
            min_base_delay,
            ..self
        }
    }

    /// Set the maximum base delay for retries.
    pub fn with_max_base_delay(self, max_base_delay: Duration) -> Self {
        Self {
            max_base_delay,
            ..self
        }
    }

    /// Set the retry policy for [`append`](crate::S2Stream::append) and
    /// [`append_session`](crate::S2Stream::append_session) operations.
    pub fn with_append_retry_policy(self, append_retry_policy: AppendRetryPolicy) -> Self {
        Self {
            append_retry_policy,
            ..self
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Configuration for [`S2`](crate::S2).
pub struct S2Config {
    pub(crate) access_token: SecretString,
    pub(crate) endpoints: S2Endpoints,
    pub(crate) connection_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) retry: RetryConfig,
    pub(crate) compression: Compression,
    pub(crate) user_agent: HeaderValue,
    pub(crate) insecure_skip_cert_verification: bool,
}

impl S2Config {
    /// Create a new [`S2Config`] with the given access token and default settings.
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into().into(),
            endpoints: S2Endpoints::for_aws(),
            connection_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            retry: RetryConfig::new(),
            compression: Compression::None,
            user_agent: concat!("s2-sdk-rust/", env!("CARGO_PKG_VERSION"))
                .parse()
                .expect("valid user agent"),
            insecure_skip_cert_verification: false,
        }
    }

    /// Set the S2 endpoints to connect to.
    pub fn with_endpoints(self, endpoints: S2Endpoints) -> Self {
        Self { endpoints, ..self }
    }

    /// Set the timeout for establishing a connection to the server.
    ///
    /// Defaults to `3s`.
    pub fn with_connection_timeout(self, connection_timeout: Duration) -> Self {
        Self {
            connection_timeout,
            ..self
        }
    }

    /// Set the timeout for requests.
    ///
    /// Defaults to `5s`.
    pub fn with_request_timeout(self, request_timeout: Duration) -> Self {
        Self {
            request_timeout,
            ..self
        }
    }

    /// Set the retry configuration for requests.
    ///
    /// See [`RetryConfig`] for defaults.
    pub fn with_retry(self, retry: RetryConfig) -> Self {
        Self { retry, ..self }
    }

    /// Set the compression algorithm for requests and responses.
    ///
    /// Defaults to no compression.
    pub fn with_compression(self, compression: Compression) -> Self {
        Self {
            compression,
            ..self
        }
    }

    /// Skip TLS certificate verification (insecure).
    ///
    /// This is useful for connecting to endpoints with self-signed certificates
    /// or certificates that don't match the hostname (similar to `curl -k`).
    ///
    /// # Warning
    ///
    /// This disables certificate verification and should only be used for
    /// testing or development purposes. **Never use this in production.**
    ///
    /// Defaults to `false`.
    pub fn with_insecure_skip_cert_verification(self, skip: bool) -> Self {
        Self {
            insecure_skip_cert_verification: skip,
            ..self
        }
    }

    #[doc(hidden)]
    #[cfg(feature = "_hidden")]
    pub fn with_user_agent(self, user_agent: impl Into<String>) -> Result<Self, ValidationError> {
        let user_agent = user_agent
            .into()
            .parse()
            .map_err(|e| ValidationError(format!("invalid user agent: {e}")))?;
        Ok(Self { user_agent, ..self })
    }
}

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
    pub(crate) fn new(values: impl Into<Vec<T>>, has_more: bool) -> Self {
        Self {
            values: values.into(),
            has_more,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Storage class for recent appends.
pub enum StorageClass {
    /// Standard storage class that offers append latencies under `500ms`.
    Standard,
    /// Express storage class that offers append latencies under `50ms`.
    Express,
}

impl From<api::config::StorageClass> for StorageClass {
    fn from(value: api::config::StorageClass) -> Self {
        match value {
            api::config::StorageClass::Standard => StorageClass::Standard,
            api::config::StorageClass::Express => StorageClass::Express,
        }
    }
}

impl From<StorageClass> for api::config::StorageClass {
    fn from(value: StorageClass) -> Self {
        match value {
            StorageClass::Standard => api::config::StorageClass::Standard,
            StorageClass::Express => api::config::StorageClass::Express,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Retention policy for records in a stream.
pub enum RetentionPolicy {
    /// Age in seconds. Records older than this age are automatically trimmed.
    Age(u64),
    /// Records are retained indefinitely unless explicitly trimmed.
    Infinite,
}

impl From<api::config::RetentionPolicy> for RetentionPolicy {
    fn from(value: api::config::RetentionPolicy) -> Self {
        match value {
            api::config::RetentionPolicy::Age(secs) => RetentionPolicy::Age(secs),
            api::config::RetentionPolicy::Infinite(_) => RetentionPolicy::Infinite,
        }
    }
}

impl From<RetentionPolicy> for api::config::RetentionPolicy {
    fn from(value: RetentionPolicy) -> Self {
        match value {
            RetentionPolicy::Age(secs) => api::config::RetentionPolicy::Age(secs),
            RetentionPolicy::Infinite => {
                api::config::RetentionPolicy::Infinite(api::config::InfiniteRetention {})
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Timestamping mode for appends that influences how timestamps are handled.
pub enum TimestampingMode {
    /// Prefer client-specified timestamp if present otherwise use arrival time.
    ClientPrefer,
    /// Require a client-specified timestamp and reject the append if it is missing.
    ClientRequire,
    /// Use the arrival time and ignore any client-specified timestamp.
    Arrival,
}

impl From<api::config::TimestampingMode> for TimestampingMode {
    fn from(value: api::config::TimestampingMode) -> Self {
        match value {
            api::config::TimestampingMode::ClientPrefer => TimestampingMode::ClientPrefer,
            api::config::TimestampingMode::ClientRequire => TimestampingMode::ClientRequire,
            api::config::TimestampingMode::Arrival => TimestampingMode::Arrival,
        }
    }
}

impl From<TimestampingMode> for api::config::TimestampingMode {
    fn from(value: TimestampingMode) -> Self {
        match value {
            TimestampingMode::ClientPrefer => api::config::TimestampingMode::ClientPrefer,
            TimestampingMode::ClientRequire => api::config::TimestampingMode::ClientRequire,
            TimestampingMode::Arrival => api::config::TimestampingMode::Arrival,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
/// Configuration for timestamping behavior.
pub struct TimestampingConfig {
    /// Timestamping mode for appends that influences how timestamps are handled.
    ///
    /// Defaults to [`ClientPrefer`](TimestampingMode::ClientPrefer).
    pub mode: Option<TimestampingMode>,
    /// Whether client-specified timestamps are allowed to exceed the arrival time.
    ///
    /// Defaults to `false` (client timestamps are capped at the arrival time).
    pub uncapped: bool,
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
        Self { uncapped, ..self }
    }
}

impl From<api::config::TimestampingConfig> for TimestampingConfig {
    fn from(value: api::config::TimestampingConfig) -> Self {
        Self {
            mode: value.mode.map(Into::into),
            uncapped: value.uncapped.unwrap_or_default(),
        }
    }
}

impl From<TimestampingConfig> for api::config::TimestampingConfig {
    fn from(value: TimestampingConfig) -> Self {
        Self {
            mode: value.mode.map(Into::into),
            uncapped: Some(value.uncapped),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
/// Configuration for automatically deleting a stream when it becomes empty.
pub struct DeleteOnEmptyConfig {
    /// Minimum age in seconds before an empty stream can be deleted.
    ///
    /// Defaults to `0` (disables automatic deletion).
    pub min_age_secs: u64,
}

impl DeleteOnEmptyConfig {
    /// Create a new [`DeleteOnEmptyConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the minimum age in seconds before an empty stream can be deleted.
    pub fn with_min_age(self, min_age: Duration) -> Self {
        Self {
            min_age_secs: min_age.as_secs(),
        }
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
    /// Storage class for the stream.
    ///
    /// Defaults to [`Express`](StorageClass::Express).
    pub storage_class: Option<StorageClass>,
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
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the storage class for the stream.
    pub fn with_storage_class(self, storage_class: StorageClass) -> Self {
        Self {
            storage_class: Some(storage_class),
            ..self
        }
    }

    /// Set the retention policy for records in the stream.
    pub fn with_retention_policy(self, retention_policy: RetentionPolicy) -> Self {
        Self {
            retention_policy: Some(retention_policy),
            ..self
        }
    }

    /// Set the configuration for timestamping behavior.
    pub fn with_timestamping(self, timestamping: TimestampingConfig) -> Self {
        Self {
            timestamping: Some(timestamping),
            ..self
        }
    }

    /// Set the configuration for automatically deleting the stream when it becomes empty.
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
            storage_class: value.storage_class.map(Into::into),
            retention_policy: value.retention_policy.map(Into::into),
            timestamping: value.timestamping.map(Into::into),
            delete_on_empty: value.delete_on_empty.map(Into::into),
        }
    }
}

impl From<StreamConfig> for api::config::StreamConfig {
    fn from(value: StreamConfig) -> Self {
        Self {
            storage_class: value.storage_class.map(Into::into),
            retention_policy: value.retention_policy.map(Into::into),
            timestamping: value.timestamping.map(Into::into),
            delete_on_empty: value.delete_on_empty.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Configuration for a basin.
pub struct BasinConfig {
    /// Default configuration for all streams in the basin.
    ///
    /// See [`StreamConfig`] for defaults.
    pub default_stream_config: Option<StreamConfig>,
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
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default configuration for all streams in the basin.
    pub fn with_default_stream_config(self, config: StreamConfig) -> Self {
        Self {
            default_stream_config: Some(config),
            ..self
        }
    }

    /// Set whether to create stream on append if it doesn't exist using default stream
    /// configuration.
    pub fn with_create_stream_on_append(self, create_stream_on_append: bool) -> Self {
        Self {
            create_stream_on_append,
            ..self
        }
    }

    /// Set whether to create stream on read if it doesn't exist using default stream configuration.
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
            create_stream_on_append: value.create_stream_on_append,
            create_stream_on_read: value.create_stream_on_read,
        }
    }
}

impl From<BasinConfig> for api::config::BasinConfig {
    fn from(value: BasinConfig) -> Self {
        Self {
            default_stream_config: value.default_stream_config.map(Into::into),
            create_stream_on_append: value.create_stream_on_append,
            create_stream_on_read: value.create_stream_on_read,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Scope of a basin.
pub enum BasinScope {
    /// AWS `us-east-1` region.
    AwsUsEast1,
}

impl From<api::basin::BasinScope> for BasinScope {
    fn from(value: api::basin::BasinScope) -> Self {
        match value {
            api::basin::BasinScope::AwsUsEast1 => BasinScope::AwsUsEast1,
        }
    }
}

impl From<BasinScope> for api::basin::BasinScope {
    fn from(value: BasinScope) -> Self {
        match value {
            BasinScope::AwsUsEast1 => api::basin::BasinScope::AwsUsEast1,
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`create_basin`](crate::S2::create_basin) operation.
pub struct CreateBasinInput {
    /// Basin name.
    pub name: BasinName,
    /// Configuration for the basin.
    ///
    /// See [`BasinConfig`] for defaults.
    pub config: Option<BasinConfig>,
    /// Scope of the basin.
    ///
    /// Defaults to [`AwsUsEast1`](BasinScope::AwsUsEast1).
    pub scope: Option<BasinScope>,
    idempotency_token: String,
}

impl CreateBasinInput {
    /// Create a new [`CreateBasinInput`] with the given basin name.
    pub fn new(name: BasinName) -> Self {
        Self {
            name,
            config: None,
            scope: None,
            idempotency_token: idempotency_token(),
        }
    }

    /// Set the configuration for the basin.
    pub fn with_config(self, config: BasinConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }

    /// Set the scope of the basin.
    pub fn with_scope(self, scope: BasinScope) -> Self {
        Self {
            scope: Some(scope),
            ..self
        }
    }
}

impl From<CreateBasinInput> for (api::basin::CreateBasinRequest, String) {
    fn from(value: CreateBasinInput) -> Self {
        (
            api::basin::CreateBasinRequest {
                basin: value.name,
                config: value.config.map(Into::into),
                scope: value.scope.map(Into::into),
            },
            value.idempotency_token,
        )
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Input for [`list_basins`](crate::S2::list_basins) operation.
pub struct ListBasinsInput {
    /// Filter basins whose names begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: BasinNamePrefix,
    /// Filter basins whose names are lexicographically greater than this value.
    ///
    /// **Note:** It must be greater than or equal to [`prefix`](ListBasinsInput::prefix).
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

#[derive(Debug, Clone, Default)]
/// Input for [`S2::list_all_basins`](crate::S2::list_all_basins).
pub struct ListAllBasinsInput {
    /// Filter basins whose names begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: BasinNamePrefix,
    /// Filter basins whose names are lexicographically greater than this value.
    ///
    /// **Note:** It must be greater than or equal to [`prefix`](ListAllBasinsInput::prefix).
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
/// Current state of a basin.
pub enum BasinState {
    /// Active
    Active,
    /// Creating
    Creating,
    /// Deleting
    Deleting,
}

impl From<api::basin::BasinState> for BasinState {
    fn from(value: api::basin::BasinState) -> Self {
        match value {
            api::basin::BasinState::Active => BasinState::Active,
            api::basin::BasinState::Creating => BasinState::Creating,
            api::basin::BasinState::Deleting => BasinState::Deleting,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Basin information.
pub struct BasinInfo {
    /// Basin name.
    pub name: BasinName,
    /// Scope of the basin.
    pub scope: Option<BasinScope>,
    /// Current state of the basin.
    pub state: BasinState,
}

impl From<api::basin::BasinInfo> for BasinInfo {
    fn from(value: api::basin::BasinInfo) -> Self {
        Self {
            name: value.name,
            scope: value.scope.map(Into::into),
            state: value.state.into(),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`delete_basin`](crate::S2::delete_basin) operation.
pub struct DeleteBasinInput {
    /// Basin name.
    pub name: BasinName,
    /// Whether to ignore `Not Found` error if the basin doesn't exist.
    pub ignore_not_found: bool,
}

impl DeleteBasinInput {
    /// Create a new [`DeleteBasinInput`] with the given basin name.
    pub fn new(name: BasinName) -> Self {
        Self {
            name,
            ignore_not_found: false,
        }
    }

    /// Set whether to ignore `Not Found` error if the basin is not existing.
    pub fn with_ignore_not_found(self, ignore_not_found: bool) -> Self {
        Self {
            ignore_not_found,
            ..self
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Reconfiguration for [`TimestampingConfig`].
pub struct TimestampingReconfiguration {
    /// Override for the existing [`mode`](TimestampingConfig::mode).
    pub mode: Maybe<Option<TimestampingMode>>,
    /// Override for the existing [`uncapped`](TimestampingConfig::uncapped) setting.
    pub uncapped: Maybe<Option<bool>>,
}

impl TimestampingReconfiguration {
    /// Create a new [`TimestampingReconfiguration`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the override for the existing [`mode`](TimestampingConfig::mode).
    pub fn with_mode(self, mode: TimestampingMode) -> Self {
        Self {
            mode: Maybe::Specified(Some(mode)),
            ..self
        }
    }

    /// Set the override for the existing [`uncapped`](TimestampingConfig::uncapped).
    pub fn with_uncapped(self, uncapped: bool) -> Self {
        Self {
            uncapped: Maybe::Specified(Some(uncapped)),
            ..self
        }
    }
}

impl From<TimestampingReconfiguration> for api::config::TimestampingReconfiguration {
    fn from(value: TimestampingReconfiguration) -> Self {
        Self {
            mode: value.mode.map(|m| m.map(Into::into)),
            uncapped: value.uncapped,
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Reconfiguration for [`DeleteOnEmptyConfig`].
pub struct DeleteOnEmptyReconfiguration {
    /// Override for the existing [`min_age_secs`](DeleteOnEmptyConfig::min_age_secs).
    pub min_age_secs: Maybe<Option<u64>>,
}

impl DeleteOnEmptyReconfiguration {
    /// Create a new [`DeleteOnEmptyReconfiguration`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the override for the existing [`min_age_secs`](DeleteOnEmptyConfig::min_age_secs).
    pub fn with_min_age(self, min_age: Duration) -> Self {
        Self {
            min_age_secs: Maybe::Specified(Some(min_age.as_secs())),
        }
    }
}

impl From<DeleteOnEmptyReconfiguration> for api::config::DeleteOnEmptyReconfiguration {
    fn from(value: DeleteOnEmptyReconfiguration) -> Self {
        Self {
            min_age_secs: value.min_age_secs,
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Reconfiguration for [`StreamConfig`].
pub struct StreamReconfiguration {
    /// Override for the existing [`storage_class`](StreamConfig::storage_class).
    pub storage_class: Maybe<Option<StorageClass>>,
    /// Override for the existing [`retention_policy`](StreamConfig::retention_policy).
    pub retention_policy: Maybe<Option<RetentionPolicy>>,
    /// Override for the existing [`timestamping`](StreamConfig::timestamping).
    pub timestamping: Maybe<Option<TimestampingReconfiguration>>,
    /// Override for the existing [`delete_on_empty`](StreamConfig::delete_on_empty).
    pub delete_on_empty: Maybe<Option<DeleteOnEmptyReconfiguration>>,
}

impl StreamReconfiguration {
    /// Create a new [`StreamReconfiguration`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the override for the existing [`storage_class`](StreamConfig::storage_class).
    pub fn with_storage_class(self, storage_class: StorageClass) -> Self {
        Self {
            storage_class: Maybe::Specified(Some(storage_class)),
            ..self
        }
    }

    /// Set the override for the existing [`retention_policy`](StreamConfig::retention_policy).
    pub fn with_retention_policy(self, retention_policy: RetentionPolicy) -> Self {
        Self {
            retention_policy: Maybe::Specified(Some(retention_policy)),
            ..self
        }
    }

    /// Set the override for the existing [`timestamping`](StreamConfig::timestamping).
    pub fn with_timestamping(self, timestamping: TimestampingReconfiguration) -> Self {
        Self {
            timestamping: Maybe::Specified(Some(timestamping)),
            ..self
        }
    }

    /// Set the override for the existing [`delete_on_empty`](StreamConfig::delete_on_empty).
    pub fn with_delete_on_empty(self, delete_on_empty: DeleteOnEmptyReconfiguration) -> Self {
        Self {
            delete_on_empty: Maybe::Specified(Some(delete_on_empty)),
            ..self
        }
    }
}

impl From<StreamReconfiguration> for api::config::StreamReconfiguration {
    fn from(value: StreamReconfiguration) -> Self {
        Self {
            storage_class: value.storage_class.map(|m| m.map(Into::into)),
            retention_policy: value.retention_policy.map(|m| m.map(Into::into)),
            timestamping: value.timestamping.map(|m| m.map(Into::into)),
            delete_on_empty: value.delete_on_empty.map(|m| m.map(Into::into)),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Reconfiguration for [`BasinConfig`].
pub struct BasinReconfiguration {
    /// Override for the existing [`default_stream_config`](BasinConfig::default_stream_config).
    pub default_stream_config: Maybe<Option<StreamReconfiguration>>,
    /// Override for the existing
    /// [`create_stream_on_append`](BasinConfig::create_stream_on_append).
    pub create_stream_on_append: Maybe<bool>,
    /// Override for the existing [`create_stream_on_read`](BasinConfig::create_stream_on_read).
    pub create_stream_on_read: Maybe<bool>,
}

impl BasinReconfiguration {
    /// Create a new [`BasinReconfiguration`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the override for the existing
    /// [`default_stream_config`](BasinConfig::default_stream_config).
    pub fn with_default_stream_config(self, config: StreamReconfiguration) -> Self {
        Self {
            default_stream_config: Maybe::Specified(Some(config)),
            ..self
        }
    }

    /// Set the override for the existing
    /// [`create_stream_on_append`](BasinConfig::create_stream_on_append).
    pub fn with_create_stream_on_append(self, create_stream_on_append: bool) -> Self {
        Self {
            create_stream_on_append: Maybe::Specified(create_stream_on_append),
            ..self
        }
    }

    /// Set the override for the existing
    /// [`create_stream_on_read`](BasinConfig::create_stream_on_read).
    pub fn with_create_stream_on_read(self, create_stream_on_read: bool) -> Self {
        Self {
            create_stream_on_read: Maybe::Specified(create_stream_on_read),
            ..self
        }
    }
}

impl From<BasinReconfiguration> for api::config::BasinReconfiguration {
    fn from(value: BasinReconfiguration) -> Self {
        Self {
            default_stream_config: value.default_stream_config.map(|m| m.map(Into::into)),
            create_stream_on_append: value.create_stream_on_append,
            create_stream_on_read: value.create_stream_on_read,
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`reconfigure_basin`](crate::S2::reconfigure_basin) operation.
pub struct ReconfigureBasinInput {
    /// Basin name.
    pub name: BasinName,
    /// Reconfiguration for [`BasinConfig`].
    pub config: BasinReconfiguration,
}

impl ReconfigureBasinInput {
    /// Create a new [`ReconfigureBasinInput`] with the given basin name and reconfiguration.
    pub fn new(name: BasinName, config: BasinReconfiguration) -> Self {
        Self { name, config }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Input for [`list_access_tokens`](crate::S2::list_access_tokens) operation.
pub struct ListAccessTokensInput {
    /// Filter access tokens whose IDs begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: AccessTokenIdPrefix,
    /// Filter access tokens whose IDs are lexicographically greater than this value.
    ///
    /// **Note:** It must be greater than or equal to [`prefix`](ListAccessTokensInput::prefix).
    ///
    /// Defaults to `""`.
    pub start_after: AccessTokenIdStartAfter,
    /// Number of access tokens to return in a page. Will be clamped to a maximum of `1000`.
    ///
    /// Defaults to `1000`.
    pub limit: Option<usize>,
}

impl ListAccessTokensInput {
    /// Create a new [`ListAccessTokensInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the prefix used to filter access tokens whose IDs begin with this value.
    pub fn with_prefix(self, prefix: AccessTokenIdPrefix) -> Self {
        Self { prefix, ..self }
    }

    /// Set the value used to filter access tokens whose IDs are lexicographically greater than this
    /// value.
    pub fn with_start_after(self, start_after: AccessTokenIdStartAfter) -> Self {
        Self {
            start_after,
            ..self
        }
    }

    /// Set the limit on number of access tokens to return in a page.
    pub fn with_limit(self, limit: usize) -> Self {
        Self {
            limit: Some(limit),
            ..self
        }
    }
}

impl From<ListAccessTokensInput> for api::access::ListAccessTokensRequest {
    fn from(value: ListAccessTokensInput) -> Self {
        Self {
            prefix: Some(value.prefix),
            start_after: Some(value.start_after),
            limit: value.limit,
        }
    }
}

#[derive(Debug, Clone, Default)]
/// Input for [`S2::list_all_access_tokens`](crate::S2::list_all_access_tokens).
pub struct ListAllAccessTokensInput {
    /// Filter access tokens whose IDs begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: AccessTokenIdPrefix,
    /// Filter access tokens whose IDs are lexicographically greater than this value.
    ///
    /// **Note:** It must be greater than or equal to [`prefix`](ListAllAccessTokensInput::prefix).
    ///
    /// Defaults to `""`.
    pub start_after: AccessTokenIdStartAfter,
}

impl ListAllAccessTokensInput {
    /// Create a new [`ListAllAccessTokensInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the prefix used to filter access tokens whose IDs begin with this value.
    pub fn with_prefix(self, prefix: AccessTokenIdPrefix) -> Self {
        Self { prefix, ..self }
    }

    /// Set the value used to filter access tokens whose IDs are lexicographically greater than
    /// this value.
    pub fn with_start_after(self, start_after: AccessTokenIdStartAfter) -> Self {
        Self {
            start_after,
            ..self
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Access token information.
pub struct AccessTokenInfo {
    /// Access token ID.
    pub id: AccessTokenId,
    /// Expiration time.
    pub expires_at: S2DateTime,
    /// Whether to automatically prefix stream names during creation and strip the prefix during
    /// listing.
    pub auto_prefix_streams: bool,
    /// Scope of the access token.
    pub scope: AccessTokenScope,
}

impl TryFrom<api::access::AccessTokenInfo> for AccessTokenInfo {
    type Error = ValidationError;

    fn try_from(value: api::access::AccessTokenInfo) -> Result<Self, Self::Error> {
        let expires_at = value
            .expires_at
            .map(S2DateTime::try_from)
            .transpose()?
            .ok_or_else(|| ValidationError::from("missing expires_at"))?;
        Ok(Self {
            id: value.id,
            expires_at,
            auto_prefix_streams: value.auto_prefix_streams.unwrap_or(false),
            scope: value.scope.into(),
        })
    }
}

#[derive(Debug, Clone)]
/// Pattern for matching basins.
///
/// See [`AccessTokenScope::basins`].
pub enum BasinMatcher {
    /// Match no basins.
    None,
    /// Match exactly this basin.
    Exact(BasinName),
    /// Match all basins with this prefix.
    Prefix(BasinNamePrefix),
}

#[derive(Debug, Clone)]
/// Pattern for matching streams.
///
/// See [`AccessTokenScope::streams`].
pub enum StreamMatcher {
    /// Match no streams.
    None,
    /// Match exactly this stream.
    Exact(StreamName),
    /// Match all streams with this prefix.
    Prefix(StreamNamePrefix),
}

#[derive(Debug, Clone)]
/// Pattern for matching access tokens.
///
/// See [`AccessTokenScope::access_tokens`].
pub enum AccessTokenMatcher {
    /// Match no access tokens.
    None,
    /// Match exactly this access token.
    Exact(AccessTokenId),
    /// Match all access tokens with this prefix.
    Prefix(AccessTokenIdPrefix),
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Permissions indicating allowed operations.
pub struct ReadWritePermissions {
    /// Read permission.
    ///
    /// Defaults to `false`.
    pub read: bool,
    /// Write permission.
    ///
    /// Defaults to `false`.
    pub write: bool,
}

impl ReadWritePermissions {
    /// Create a new [`ReadWritePermissions`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create read-only permissions.
    pub fn read_only() -> Self {
        Self {
            read: true,
            write: false,
        }
    }

    /// Create write-only permissions.
    pub fn write_only() -> Self {
        Self {
            read: false,
            write: true,
        }
    }

    /// Create read-write permissions.
    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
        }
    }
}

impl From<ReadWritePermissions> for api::access::ReadWritePermissions {
    fn from(value: ReadWritePermissions) -> Self {
        Self {
            read: Some(value.read),
            write: Some(value.write),
        }
    }
}

impl From<api::access::ReadWritePermissions> for ReadWritePermissions {
    fn from(value: api::access::ReadWritePermissions) -> Self {
        Self {
            read: value.read.unwrap_or_default(),
            write: value.write.unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Permissions at the operation group level.
///
/// See [`AccessTokenScope::op_group_perms`].
pub struct OperationGroupPermissions {
    /// Account-level access permissions.
    ///
    /// Defaults to `None`.
    pub account: Option<ReadWritePermissions>,
    /// Basin-level access permissions.
    ///
    /// Defaults to `None`.
    pub basin: Option<ReadWritePermissions>,
    /// Stream-level access permissions.
    ///
    /// Defaults to `None`.
    pub stream: Option<ReadWritePermissions>,
}

impl OperationGroupPermissions {
    /// Create a new [`OperationGroupPermissions`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create read-only permissions for all groups.
    pub fn read_only_all() -> Self {
        Self {
            account: Some(ReadWritePermissions::read_only()),
            basin: Some(ReadWritePermissions::read_only()),
            stream: Some(ReadWritePermissions::read_only()),
        }
    }

    /// Create write-only permissions for all groups.
    pub fn write_only_all() -> Self {
        Self {
            account: Some(ReadWritePermissions::write_only()),
            basin: Some(ReadWritePermissions::write_only()),
            stream: Some(ReadWritePermissions::write_only()),
        }
    }

    /// Create read-write permissions for all groups.
    pub fn read_write_all() -> Self {
        Self {
            account: Some(ReadWritePermissions::read_write()),
            basin: Some(ReadWritePermissions::read_write()),
            stream: Some(ReadWritePermissions::read_write()),
        }
    }

    /// Set account-level access permissions.
    pub fn with_account(self, account: ReadWritePermissions) -> Self {
        Self {
            account: Some(account),
            ..self
        }
    }

    /// Set basin-level access permissions.
    pub fn with_basin(self, basin: ReadWritePermissions) -> Self {
        Self {
            basin: Some(basin),
            ..self
        }
    }

    /// Set stream-level access permissions.
    pub fn with_stream(self, stream: ReadWritePermissions) -> Self {
        Self {
            stream: Some(stream),
            ..self
        }
    }
}

impl From<OperationGroupPermissions> for api::access::PermittedOperationGroups {
    fn from(value: OperationGroupPermissions) -> Self {
        Self {
            account: value.account.map(Into::into),
            basin: value.basin.map(Into::into),
            stream: value.stream.map(Into::into),
        }
    }
}

impl From<api::access::PermittedOperationGroups> for OperationGroupPermissions {
    fn from(value: api::access::PermittedOperationGroups) -> Self {
        Self {
            account: value.account.map(Into::into),
            basin: value.basin.map(Into::into),
            stream: value.stream.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Individual operation that can be permitted.
///
/// See [`AccessTokenScope::ops`].
pub enum Operation {
    /// List basins.
    ListBasins,
    /// Create a basin.
    CreateBasin,
    /// Get basin configuration.
    GetBasinConfig,
    /// Delete a basin.
    DeleteBasin,
    /// Reconfigure a basin.
    ReconfigureBasin,
    /// List access tokens.
    ListAccessTokens,
    /// Issue an access token.
    IssueAccessToken,
    /// Revoke an access token.
    RevokeAccessToken,
    /// Get account metrics.
    GetAccountMetrics,
    /// Get basin metrics.
    GetBasinMetrics,
    /// Get stream metrics.
    GetStreamMetrics,
    /// List streams.
    ListStreams,
    /// Create a stream.
    CreateStream,
    /// Get stream configuration.
    GetStreamConfig,
    /// Delete a stream.
    DeleteStream,
    /// Reconfigure a stream.
    ReconfigureStream,
    /// Check the tail of a stream.
    CheckTail,
    /// Append records to a stream.
    Append,
    /// Read records from a stream.
    Read,
    /// Trim records on a stream.
    Trim,
    /// Set the fencing token on a stream.
    Fence,
}

impl From<Operation> for api::access::Operation {
    fn from(value: Operation) -> Self {
        match value {
            Operation::ListBasins => api::access::Operation::ListBasins,
            Operation::CreateBasin => api::access::Operation::CreateBasin,
            Operation::DeleteBasin => api::access::Operation::DeleteBasin,
            Operation::ReconfigureBasin => api::access::Operation::ReconfigureBasin,
            Operation::GetBasinConfig => api::access::Operation::GetBasinConfig,
            Operation::IssueAccessToken => api::access::Operation::IssueAccessToken,
            Operation::RevokeAccessToken => api::access::Operation::RevokeAccessToken,
            Operation::ListAccessTokens => api::access::Operation::ListAccessTokens,
            Operation::ListStreams => api::access::Operation::ListStreams,
            Operation::CreateStream => api::access::Operation::CreateStream,
            Operation::DeleteStream => api::access::Operation::DeleteStream,
            Operation::GetStreamConfig => api::access::Operation::GetStreamConfig,
            Operation::ReconfigureStream => api::access::Operation::ReconfigureStream,
            Operation::CheckTail => api::access::Operation::CheckTail,
            Operation::Append => api::access::Operation::Append,
            Operation::Read => api::access::Operation::Read,
            Operation::Trim => api::access::Operation::Trim,
            Operation::Fence => api::access::Operation::Fence,
            Operation::GetAccountMetrics => api::access::Operation::AccountMetrics,
            Operation::GetBasinMetrics => api::access::Operation::BasinMetrics,
            Operation::GetStreamMetrics => api::access::Operation::StreamMetrics,
        }
    }
}

impl From<api::access::Operation> for Operation {
    fn from(value: api::access::Operation) -> Self {
        match value {
            api::access::Operation::ListBasins => Operation::ListBasins,
            api::access::Operation::CreateBasin => Operation::CreateBasin,
            api::access::Operation::DeleteBasin => Operation::DeleteBasin,
            api::access::Operation::ReconfigureBasin => Operation::ReconfigureBasin,
            api::access::Operation::GetBasinConfig => Operation::GetBasinConfig,
            api::access::Operation::IssueAccessToken => Operation::IssueAccessToken,
            api::access::Operation::RevokeAccessToken => Operation::RevokeAccessToken,
            api::access::Operation::ListAccessTokens => Operation::ListAccessTokens,
            api::access::Operation::ListStreams => Operation::ListStreams,
            api::access::Operation::CreateStream => Operation::CreateStream,
            api::access::Operation::DeleteStream => Operation::DeleteStream,
            api::access::Operation::GetStreamConfig => Operation::GetStreamConfig,
            api::access::Operation::ReconfigureStream => Operation::ReconfigureStream,
            api::access::Operation::CheckTail => Operation::CheckTail,
            api::access::Operation::Append => Operation::Append,
            api::access::Operation::Read => Operation::Read,
            api::access::Operation::Trim => Operation::Trim,
            api::access::Operation::Fence => Operation::Fence,
            api::access::Operation::AccountMetrics => Operation::GetAccountMetrics,
            api::access::Operation::BasinMetrics => Operation::GetBasinMetrics,
            api::access::Operation::StreamMetrics => Operation::GetStreamMetrics,
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Scope of an access token.
///
/// **Note:** The final set of permitted operations is the union of [`ops`](AccessTokenScope::ops)
/// and the operations permitted by [`op_group_perms`](AccessTokenScope::op_group_perms). Also, the
/// final set must not be empty.
///
/// See [`IssueAccessTokenInput::scope`].
pub struct AccessTokenScopeInput {
    basins: Option<BasinMatcher>,
    streams: Option<StreamMatcher>,
    access_tokens: Option<AccessTokenMatcher>,
    op_group_perms: Option<OperationGroupPermissions>,
    ops: HashSet<Operation>,
}

impl AccessTokenScopeInput {
    /// Create a new [`AccessTokenScopeInput`] with the given permitted operations.
    pub fn from_ops(ops: impl IntoIterator<Item = Operation>) -> Self {
        Self {
            basins: None,
            streams: None,
            access_tokens: None,
            op_group_perms: None,
            ops: ops.into_iter().collect(),
        }
    }

    /// Create a new [`AccessTokenScopeInput`] with the given operation group permissions.
    pub fn from_op_group_perms(op_group_perms: OperationGroupPermissions) -> Self {
        Self {
            basins: None,
            streams: None,
            access_tokens: None,
            op_group_perms: Some(op_group_perms),
            ops: HashSet::default(),
        }
    }

    /// Set the permitted operations.
    pub fn with_ops(self, ops: impl IntoIterator<Item = Operation>) -> Self {
        Self {
            ops: ops.into_iter().collect(),
            ..self
        }
    }

    /// Set the access permissions at the operation group level.
    pub fn with_op_group_perms(self, op_group_perms: OperationGroupPermissions) -> Self {
        Self {
            op_group_perms: Some(op_group_perms),
            ..self
        }
    }

    /// Set the permitted basins.
    ///
    /// Defaults to no basins.
    pub fn with_basins(self, basins: BasinMatcher) -> Self {
        Self {
            basins: Some(basins),
            ..self
        }
    }

    /// Set the permitted streams.
    ///
    /// Defaults to no streams.
    pub fn with_streams(self, streams: StreamMatcher) -> Self {
        Self {
            streams: Some(streams),
            ..self
        }
    }

    /// Set the permitted access tokens.
    ///
    /// Defaults to no access tokens.
    pub fn with_access_tokens(self, access_tokens: AccessTokenMatcher) -> Self {
        Self {
            access_tokens: Some(access_tokens),
            ..self
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Scope of an access token.
pub struct AccessTokenScope {
    /// Permitted basins.
    pub basins: Option<BasinMatcher>,
    /// Permitted streams.
    pub streams: Option<StreamMatcher>,
    /// Permitted access tokens.
    pub access_tokens: Option<AccessTokenMatcher>,
    /// Permissions at the operation group level.
    pub op_group_perms: Option<OperationGroupPermissions>,
    /// Permitted operations.
    pub ops: HashSet<Operation>,
}

impl From<api::access::AccessTokenScope> for AccessTokenScope {
    fn from(value: api::access::AccessTokenScope) -> Self {
        Self {
            basins: value.basins.map(|rs| match rs {
                api::access::ResourceSet::Exact(api::access::MaybeEmpty::NonEmpty(e)) => {
                    BasinMatcher::Exact(e)
                }
                api::access::ResourceSet::Exact(api::access::MaybeEmpty::Empty) => {
                    BasinMatcher::None
                }
                api::access::ResourceSet::Prefix(p) => BasinMatcher::Prefix(p),
            }),
            streams: value.streams.map(|rs| match rs {
                api::access::ResourceSet::Exact(api::access::MaybeEmpty::NonEmpty(e)) => {
                    StreamMatcher::Exact(e)
                }
                api::access::ResourceSet::Exact(api::access::MaybeEmpty::Empty) => {
                    StreamMatcher::None
                }
                api::access::ResourceSet::Prefix(p) => StreamMatcher::Prefix(p),
            }),
            access_tokens: value.access_tokens.map(|rs| match rs {
                api::access::ResourceSet::Exact(api::access::MaybeEmpty::NonEmpty(e)) => {
                    AccessTokenMatcher::Exact(e)
                }
                api::access::ResourceSet::Exact(api::access::MaybeEmpty::Empty) => {
                    AccessTokenMatcher::None
                }
                api::access::ResourceSet::Prefix(p) => AccessTokenMatcher::Prefix(p),
            }),
            op_group_perms: value.op_groups.map(Into::into),
            ops: value
                .ops
                .map(|ops| ops.into_iter().map(Into::into).collect())
                .unwrap_or_default(),
        }
    }
}

impl From<AccessTokenScopeInput> for api::access::AccessTokenScope {
    fn from(value: AccessTokenScopeInput) -> Self {
        Self {
            basins: value.basins.map(|rs| match rs {
                BasinMatcher::None => {
                    api::access::ResourceSet::Exact(api::access::MaybeEmpty::Empty)
                }
                BasinMatcher::Exact(e) => {
                    api::access::ResourceSet::Exact(api::access::MaybeEmpty::NonEmpty(e))
                }
                BasinMatcher::Prefix(p) => api::access::ResourceSet::Prefix(p),
            }),
            streams: value.streams.map(|rs| match rs {
                StreamMatcher::None => {
                    api::access::ResourceSet::Exact(api::access::MaybeEmpty::Empty)
                }
                StreamMatcher::Exact(e) => {
                    api::access::ResourceSet::Exact(api::access::MaybeEmpty::NonEmpty(e))
                }
                StreamMatcher::Prefix(p) => api::access::ResourceSet::Prefix(p),
            }),
            access_tokens: value.access_tokens.map(|rs| match rs {
                AccessTokenMatcher::None => {
                    api::access::ResourceSet::Exact(api::access::MaybeEmpty::Empty)
                }
                AccessTokenMatcher::Exact(e) => {
                    api::access::ResourceSet::Exact(api::access::MaybeEmpty::NonEmpty(e))
                }
                AccessTokenMatcher::Prefix(p) => api::access::ResourceSet::Prefix(p),
            }),
            op_groups: value.op_group_perms.map(Into::into),
            ops: if value.ops.is_empty() {
                None
            } else {
                Some(value.ops.into_iter().map(Into::into).collect())
            },
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`issue_access_token`](crate::S2::issue_access_token).
pub struct IssueAccessTokenInput {
    /// Access token ID.
    pub id: AccessTokenId,
    /// Expiration time.
    ///
    /// Defaults to the expiration time of requestor's access token passed via
    /// [`S2Config`](S2Config::new).
    pub expires_at: Option<S2DateTime>,
    /// Whether to automatically prefix stream names during creation and strip the prefix during
    /// listing.
    ///
    /// **Note:** [`scope.streams`](AccessTokenScopeInput::with_streams) must be set with the
    /// prefix.
    ///
    /// Defaults to `false`.
    pub auto_prefix_streams: bool,
    /// Scope of the token.
    pub scope: AccessTokenScopeInput,
}

impl IssueAccessTokenInput {
    /// Create a new [`IssueAccessTokenInput`] with the given id and scope.
    pub fn new(id: AccessTokenId, scope: AccessTokenScopeInput) -> Self {
        Self {
            id,
            expires_at: None,
            auto_prefix_streams: false,
            scope,
        }
    }

    /// Set the expiration time.
    pub fn with_expires_at(self, expires_at: S2DateTime) -> Self {
        Self {
            expires_at: Some(expires_at),
            ..self
        }
    }

    /// Set whether to automatically prefix stream names during creation and strip the prefix during
    /// listing.
    pub fn with_auto_prefix_streams(self, auto_prefix_streams: bool) -> Self {
        Self {
            auto_prefix_streams,
            ..self
        }
    }
}

impl From<IssueAccessTokenInput> for api::access::AccessTokenInfo {
    fn from(value: IssueAccessTokenInput) -> Self {
        Self {
            id: value.id,
            expires_at: value.expires_at.map(Into::into),
            auto_prefix_streams: value.auto_prefix_streams.then_some(true),
            scope: value.scope.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Interval to accumulate over for timeseries metric sets.
pub enum TimeseriesInterval {
    /// Minute.
    Minute,
    /// Hour.
    Hour,
    /// Day.
    Day,
}

impl From<TimeseriesInterval> for api::metrics::TimeseriesInterval {
    fn from(value: TimeseriesInterval) -> Self {
        match value {
            TimeseriesInterval::Minute => api::metrics::TimeseriesInterval::Minute,
            TimeseriesInterval::Hour => api::metrics::TimeseriesInterval::Hour,
            TimeseriesInterval::Day => api::metrics::TimeseriesInterval::Day,
        }
    }
}

impl From<api::metrics::TimeseriesInterval> for TimeseriesInterval {
    fn from(value: api::metrics::TimeseriesInterval) -> Self {
        match value {
            api::metrics::TimeseriesInterval::Minute => TimeseriesInterval::Minute,
            api::metrics::TimeseriesInterval::Hour => TimeseriesInterval::Hour,
            api::metrics::TimeseriesInterval::Day => TimeseriesInterval::Day,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
/// Time range as Unix epoch seconds.
pub struct TimeRange {
    /// Start timestamp (inclusive).
    pub start: u32,
    /// End timestamp (exclusive).
    pub end: u32,
}

impl TimeRange {
    /// Create a new [`TimeRange`] with the given start and end timestamps.
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
/// Time range as Unix epoch seconds and accumulation interval.
pub struct TimeRangeAndInterval {
    /// Start timestamp (inclusive).
    pub start: u32,
    /// End timestamp (exclusive).
    pub end: u32,
    /// Interval to accumulate over for timeseries metric sets.
    ///
    /// Default is dependent on the requested metric set.
    pub interval: Option<TimeseriesInterval>,
}

impl TimeRangeAndInterval {
    /// Create a new [`TimeRangeAndInterval`] with the given start and end timestamps.
    pub fn new(start: u32, end: u32) -> Self {
        Self {
            start,
            end,
            interval: None,
        }
    }

    /// Set the interval to accumulate over for timeseries metric sets.
    pub fn with_interval(self, interval: TimeseriesInterval) -> Self {
        Self {
            interval: Some(interval),
            ..self
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// Account metric set to return.
pub enum AccountMetricSet {
    /// Returns a [`LabelMetric`] representing all basins which had at least one stream within the
    /// specified time range.
    ActiveBasins(TimeRange),
    /// Returns [`AccumulationMetric`]s, one per account operation type.
    ///
    /// Each metric represents a timeseries of the number of operations, with one accumulated value
    /// per interval over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to [`hour`](TimeseriesInterval::Hour).
    AccountOps(TimeRangeAndInterval),
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`get_account_metrics`](crate::S2::get_account_metrics) operation.
pub struct GetAccountMetricsInput {
    /// Metric set to return.
    pub set: AccountMetricSet,
}

impl GetAccountMetricsInput {
    /// Create a new [`GetAccountMetricsInput`] with the given account metric set.
    pub fn new(set: AccountMetricSet) -> Self {
        Self { set }
    }
}

impl From<GetAccountMetricsInput> for api::metrics::AccountMetricSetRequest {
    fn from(value: GetAccountMetricsInput) -> Self {
        let (set, start, end, interval) = match value.set {
            AccountMetricSet::ActiveBasins(args) => (
                api::metrics::AccountMetricSet::ActiveBasins,
                args.start,
                args.end,
                None,
            ),
            AccountMetricSet::AccountOps(args) => (
                api::metrics::AccountMetricSet::AccountOps,
                args.start,
                args.end,
                args.interval,
            ),
        };
        Self {
            set,
            start: Some(start),
            end: Some(end),
            interval: interval.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// Basin metric set to return.
pub enum BasinMetricSet {
    /// Returns a [`GaugeMetric`] representing a timeseries of total stored bytes across all streams
    /// in the basin, with one observed value for each hour over the requested time range.
    Storage(TimeRange),
    /// Returns [`AccumulationMetric`]s, one per storage class (standard, express).
    ///
    /// Each metric represents a timeseries of the number of append operations across all streams
    /// in the basin, with one accumulated value per interval over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to
    /// [`minute`](TimeseriesInterval::Minute).
    AppendOps(TimeRangeAndInterval),
    /// Returns [`AccumulationMetric`]s, one per read type (unary, streaming).
    ///
    /// Each metric represents a timeseries of the number of read operations across all streams
    /// in the basin, with one accumulated value per interval over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to
    /// [`minute`](TimeseriesInterval::Minute).
    ReadOps(TimeRangeAndInterval),
    /// Returns an [`AccumulationMetric`] representing a timeseries of total read bytes
    /// across all streams in the basin, with one accumulated value per interval
    /// over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to
    /// [`minute`](TimeseriesInterval::Minute).
    ReadThroughput(TimeRangeAndInterval),
    /// Returns an [`AccumulationMetric`] representing a timeseries of total appended bytes
    /// across all streams in the basin, with one accumulated value per interval
    /// over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to
    /// [`minute`](TimeseriesInterval::Minute).
    AppendThroughput(TimeRangeAndInterval),
    /// Returns [`AccumulationMetric`]s, one per basin operation type.
    ///
    /// Each metric represents a timeseries of the number of operations, with one accumulated value
    /// per interval over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to [`hour`](TimeseriesInterval::Hour).
    BasinOps(TimeRangeAndInterval),
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`get_basin_metrics`](crate::S2::get_basin_metrics) operation.
pub struct GetBasinMetricsInput {
    /// Basin name.
    pub name: BasinName,
    /// Metric set to return.
    pub set: BasinMetricSet,
}

impl GetBasinMetricsInput {
    /// Create a new [`GetBasinMetricsInput`] with the given basin name and metric set.
    pub fn new(name: BasinName, set: BasinMetricSet) -> Self {
        Self { name, set }
    }
}

impl From<GetBasinMetricsInput> for (BasinName, api::metrics::BasinMetricSetRequest) {
    fn from(value: GetBasinMetricsInput) -> Self {
        let (set, start, end, interval) = match value.set {
            BasinMetricSet::Storage(args) => (
                api::metrics::BasinMetricSet::Storage,
                args.start,
                args.end,
                None,
            ),
            BasinMetricSet::AppendOps(args) => (
                api::metrics::BasinMetricSet::AppendOps,
                args.start,
                args.end,
                args.interval,
            ),
            BasinMetricSet::ReadOps(args) => (
                api::metrics::BasinMetricSet::ReadOps,
                args.start,
                args.end,
                args.interval,
            ),
            BasinMetricSet::ReadThroughput(args) => (
                api::metrics::BasinMetricSet::ReadThroughput,
                args.start,
                args.end,
                args.interval,
            ),
            BasinMetricSet::AppendThroughput(args) => (
                api::metrics::BasinMetricSet::AppendThroughput,
                args.start,
                args.end,
                args.interval,
            ),
            BasinMetricSet::BasinOps(args) => (
                api::metrics::BasinMetricSet::BasinOps,
                args.start,
                args.end,
                args.interval,
            ),
        };
        (
            value.name,
            api::metrics::BasinMetricSetRequest {
                set,
                start: Some(start),
                end: Some(end),
                interval: interval.map(Into::into),
            },
        )
    }
}

#[derive(Debug, Clone, Copy)]
/// Stream metric set to return.
pub enum StreamMetricSet {
    /// Returns a [`GaugeMetric`] representing a timeseries of total stored bytes for the stream,
    /// with one observed value for each minute over the requested time range.
    Storage(TimeRange),
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`get_stream_metrics`](crate::S2::get_stream_metrics) operation.
pub struct GetStreamMetricsInput {
    /// Basin name.
    pub basin_name: BasinName,
    /// Stream name.
    pub stream_name: StreamName,
    /// Metric set to return.
    pub set: StreamMetricSet,
}

impl GetStreamMetricsInput {
    /// Create a new [`GetStreamMetricsInput`] with the given basin name, stream name and metric
    /// set.
    pub fn new(basin_name: BasinName, stream_name: StreamName, set: StreamMetricSet) -> Self {
        Self {
            basin_name,
            stream_name,
            set,
        }
    }
}

impl From<GetStreamMetricsInput> for (BasinName, StreamName, api::metrics::StreamMetricSetRequest) {
    fn from(value: GetStreamMetricsInput) -> Self {
        let (set, start, end, interval) = match value.set {
            StreamMetricSet::Storage(args) => (
                api::metrics::StreamMetricSet::Storage,
                args.start,
                args.end,
                None,
            ),
        };
        (
            value.basin_name,
            value.stream_name,
            api::metrics::StreamMetricSetRequest {
                set,
                start: Some(start),
                end: Some(end),
                interval,
            },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Unit in which metric values are measured.
pub enum MetricUnit {
    /// Size in bytes.
    Bytes,
    /// Number of operations.
    Operations,
}

impl From<api::metrics::MetricUnit> for MetricUnit {
    fn from(value: api::metrics::MetricUnit) -> Self {
        match value {
            api::metrics::MetricUnit::Bytes => MetricUnit::Bytes,
            api::metrics::MetricUnit::Operations => MetricUnit::Operations,
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Single named value.
pub struct ScalarMetric {
    /// Metric name.
    pub name: String,
    /// Unit for the metric value.
    pub unit: MetricUnit,
    /// Metric value.
    pub value: f64,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Named series of `(timestamp, value)` datapoints, each representing an accumulation over a
/// specified interval.
pub struct AccumulationMetric {
    /// Timeseries name.
    pub name: String,
    /// Unit for the accumulated values.
    pub unit: MetricUnit,
    /// The interval at which datapoints are accumulated.
    pub interval: TimeseriesInterval,
    /// Series of `(timestamp, value)` datapoints. Each datapoint represents the accumulated
    /// `value` for the time period starting at the `timestamp` (in Unix epoch seconds), spanning
    /// one `interval`.
    pub values: Vec<(u32, f64)>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Named series of `(timestamp, value)` datapoints, each representing an instantaneous value.
pub struct GaugeMetric {
    /// Timeseries name.
    pub name: String,
    /// Unit for the instantaneous values.
    pub unit: MetricUnit,
    /// Series of `(timestamp, value)` datapoints. Each datapoint represents the `value` at the
    /// instant of the `timestamp` (in Unix epoch seconds).
    pub values: Vec<(u32, f64)>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Set of string labels.
pub struct LabelMetric {
    /// Label name.
    pub name: String,
    /// Label values.
    pub values: Vec<String>,
}

#[derive(Debug, Clone)]
/// Individual metric in a returned metric set.
pub enum Metric {
    /// Single named value.
    Scalar(ScalarMetric),
    /// Named series of `(timestamp, value)` datapoints, each representing an accumulation over a
    /// specified interval.
    Accumulation(AccumulationMetric),
    /// Named series of `(timestamp, value)` datapoints, each representing an instantaneous value.
    Gauge(GaugeMetric),
    /// Set of string labels.
    Label(LabelMetric),
}

impl From<api::metrics::Metric> for Metric {
    fn from(value: api::metrics::Metric) -> Self {
        match value {
            api::metrics::Metric::Scalar(sm) => Metric::Scalar(ScalarMetric {
                name: sm.name.into(),
                unit: sm.unit.into(),
                value: sm.value,
            }),
            api::metrics::Metric::Accumulation(am) => Metric::Accumulation(AccumulationMetric {
                name: am.name.into(),
                unit: am.unit.into(),
                interval: am.interval.into(),
                values: am.values,
            }),
            api::metrics::Metric::Gauge(gm) => Metric::Gauge(GaugeMetric {
                name: gm.name.into(),
                unit: gm.unit.into(),
                values: gm.values,
            }),
            api::metrics::Metric::Label(lm) => Metric::Label(LabelMetric {
                name: lm.name.into(),
                values: lm.values,
            }),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Input for [`list_streams`](crate::S2Basin::list_streams) operation.
pub struct ListStreamsInput {
    /// Filter streams whose names begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: StreamNamePrefix,
    /// Filter streams whose names are lexicographically greater than this value.
    ///
    /// **Note:** It must be greater than or equal to [`prefix`](ListStreamsInput::prefix).
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

#[derive(Debug, Clone, Default)]
/// Input for [`S2Basin::list_all_streams`](crate::S2Basin::list_all_streams).
pub struct ListAllStreamsInput {
    /// Filter streams whose names begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: StreamNamePrefix,
    /// Filter streams whose names are lexicographically greater than this value.
    ///
    /// **Note:** It must be greater than or equal to [`prefix`](ListAllStreamsInput::prefix).
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

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Stream information.
pub struct StreamInfo {
    /// Stream name.
    pub name: StreamName,
    /// Creation time.
    pub created_at: S2DateTime,
    /// Deletion time if the stream is being deleted.
    pub deleted_at: Option<S2DateTime>,
}

impl TryFrom<api::stream::StreamInfo> for StreamInfo {
    type Error = ValidationError;

    fn try_from(value: api::stream::StreamInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            created_at: value.created_at.try_into()?,
            deleted_at: value.deleted_at.map(S2DateTime::try_from).transpose()?,
        })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`create_stream`](crate::S2Basin::create_stream) operation.
pub struct CreateStreamInput {
    /// Stream name.
    pub name: StreamName,
    /// Configuration for the stream.
    ///
    /// See [`StreamConfig`] for defaults.
    pub config: Option<StreamConfig>,
    idempotency_token: String,
}

impl CreateStreamInput {
    /// Create a new [`CreateStreamInput`] with the given stream name.
    pub fn new(name: StreamName) -> Self {
        Self {
            name,
            config: None,
            idempotency_token: idempotency_token(),
        }
    }

    /// Set the configuration for the stream.
    pub fn with_config(self, config: StreamConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }
}

impl From<CreateStreamInput> for (api::stream::CreateStreamRequest, String) {
    fn from(value: CreateStreamInput) -> Self {
        (
            api::stream::CreateStreamRequest {
                stream: value.name,
                config: value.config.map(Into::into),
            },
            value.idempotency_token,
        )
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input of [`delete_stream`](crate::S2Basin::delete_stream) operation.
pub struct DeleteStreamInput {
    /// Stream name.
    pub name: StreamName,
    /// Whether to ignore `Not Found` error if the stream doesn't exist.
    pub ignore_not_found: bool,
}

impl DeleteStreamInput {
    /// Create a new [`DeleteStreamInput`] with the given stream name.
    pub fn new(name: StreamName) -> Self {
        Self {
            name,
            ignore_not_found: false,
        }
    }

    /// Set whether to ignore `Not Found` error if the stream doesn't exist.
    pub fn with_ignore_not_found(self, ignore_not_found: bool) -> Self {
        Self {
            ignore_not_found,
            ..self
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`reconfigure_stream`](crate::S2Basin::reconfigure_stream) operation.
pub struct ReconfigureStreamInput {
    /// Stream name.
    pub name: StreamName,
    /// Reconfiguration for [`StreamConfig`].
    pub config: StreamReconfiguration,
}

impl ReconfigureStreamInput {
    /// Create a new [`ReconfigureStreamInput`] with the given stream name and reconfiguration.
    pub fn new(name: StreamName, config: StreamReconfiguration) -> Self {
        Self { name, config }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Token for fencing appends to a stream.
///
/// **Note:** It must not exceed 36 bytes in length.
///
/// See [`CommandRecord::fence`] and [`AppendInput::fencing_token`].
pub struct FencingToken(String);

impl FencingToken {
    /// Generate a random alphanumeric fencing token of `n` bytes.
    pub fn generate(n: usize) -> Result<Self, ValidationError> {
        rand::rng()
            .sample_iter(&rand::distr::Alphanumeric)
            .take(n)
            .map(char::from)
            .collect::<String>()
            .parse()
    }
}

impl FromStr for FencingToken {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_FENCING_TOKEN_LENGTH {
            return Err(ValidationError(format!(
                "fencing token exceeds {MAX_FENCING_TOKEN_LENGTH} bytes in length",
            )));
        }
        Ok(FencingToken(s.to_string()))
    }
}

impl std::fmt::Display for FencingToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for FencingToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
/// A position in a stream.
pub struct StreamPosition {
    /// Sequence number assigned by the service.
    pub seq_num: u64,
    /// Timestamp. When assigned by the service, represents milliseconds since Unix epoch.
    /// User-specified timestamps are passed through as-is.
    pub timestamp: u64,
}

impl std::fmt::Display for StreamPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "seq_num={}, timestamp={}", self.seq_num, self.timestamp)
    }
}

impl From<api::stream::proto::StreamPosition> for StreamPosition {
    fn from(value: api::stream::proto::StreamPosition) -> Self {
        Self {
            seq_num: value.seq_num,
            timestamp: value.timestamp,
        }
    }
}

impl From<api::stream::StreamPosition> for StreamPosition {
    fn from(value: api::stream::StreamPosition) -> Self {
        Self {
            seq_num: value.seq_num,
            timestamp: value.timestamp,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
/// A name-value pair.
pub struct Header {
    /// Name.
    pub name: Bytes,
    /// Value.
    pub value: Bytes,
}

impl Header {
    /// Create a new [`Header`] with the given name and value.
    pub fn new(name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl From<Header> for api::stream::proto::Header {
    fn from(value: Header) -> Self {
        Self {
            name: value.name,
            value: value.value,
        }
    }
}

impl From<api::stream::proto::Header> for Header {
    fn from(value: api::stream::proto::Header) -> Self {
        Self {
            name: value.name,
            value: value.value,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
/// A record to append.
pub struct AppendRecord {
    body: Bytes,
    headers: Vec<Header>,
    timestamp: Option<u64>,
}

impl AppendRecord {
    fn validate(self) -> Result<Self, ValidationError> {
        if self.metered_bytes() > RECORD_BATCH_MAX.bytes {
            Err(ValidationError(format!(
                "metered_bytes: {} exceeds {}",
                self.metered_bytes(),
                RECORD_BATCH_MAX.bytes
            )))
        } else {
            Ok(self)
        }
    }

    /// Create a new [`AppendRecord`] with the given record body.
    pub fn new(body: impl Into<Bytes>) -> Result<Self, ValidationError> {
        let record = Self {
            body: body.into(),
            headers: Vec::default(),
            timestamp: None,
        };
        record.validate()
    }

    /// Set the headers for this record.
    pub fn with_headers(
        self,
        headers: impl IntoIterator<Item = Header>,
    ) -> Result<Self, ValidationError> {
        let record = Self {
            headers: headers.into_iter().collect(),
            ..self
        };
        record.validate()
    }

    /// Set the timestamp for this record.
    ///
    /// Precise semantics depend on [`StreamConfig::timestamping`].
    pub fn with_timestamp(self, timestamp: u64) -> Self {
        Self {
            timestamp: Some(timestamp),
            ..self
        }
    }

    /// Get the body of this record.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Get the headers of this record.
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Get the timestamp of this record.
    pub fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }
}

impl From<AppendRecord> for api::stream::proto::AppendRecord {
    fn from(value: AppendRecord) -> Self {
        Self {
            timestamp: value.timestamp,
            headers: value.headers.into_iter().map(Into::into).collect(),
            body: value.body,
        }
    }
}

/// Metered byte size calculation.
///
/// Formula for a record:
/// ```text
/// 8 + 2 * len(headers) + sum(len(h.name) + len(h.value) for h in headers) + len(body)
/// ```
pub trait MeteredBytes {
    /// Returns the metered byte size.
    fn metered_bytes(&self) -> usize;
}

macro_rules! metered_bytes_impl {
    ($ty:ty) => {
        impl MeteredBytes for $ty {
            fn metered_bytes(&self) -> usize {
                8 + (2 * self.headers.len())
                    + self
                        .headers
                        .iter()
                        .map(|h| h.name.len() + h.value.len())
                        .sum::<usize>()
                    + self.body.len()
            }
        }
    };
}

metered_bytes_impl!(AppendRecord);

#[derive(Debug, Clone)]
/// A batch of records to append atomically.
///
/// **Note:** It must contain at least `1` record and no more than `1000`.
/// The total size of the batch must not exceed `1MiB` in metered bytes.
///
/// See [`AppendRecordBatches`](crate::batching::AppendRecordBatches) and
/// [`AppendInputs`](crate::batching::AppendInputs) for convenient and automatic batching of records
/// that takes care of the abovementioned constraints.
pub struct AppendRecordBatch {
    records: Vec<AppendRecord>,
    metered_bytes: usize,
}

impl AppendRecordBatch {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            records: Vec::with_capacity(capacity),
            metered_bytes: 0,
        }
    }

    pub(crate) fn push(&mut self, record: AppendRecord) {
        self.metered_bytes += record.metered_bytes();
        self.records.push(record);
    }

    /// Try to create an [`AppendRecordBatch`] from an iterator of [`AppendRecord`]s.
    pub fn try_from_iter<I>(iter: I) -> Result<Self, ValidationError>
    where
        I: IntoIterator<Item = AppendRecord>,
    {
        let mut records = Vec::new();
        let mut metered_bytes = 0;

        for record in iter {
            metered_bytes += record.metered_bytes();
            records.push(record);

            if metered_bytes > RECORD_BATCH_MAX.bytes {
                return Err(ValidationError(format!(
                    "batch size in metered bytes ({metered_bytes}) exceeds {}",
                    RECORD_BATCH_MAX.bytes
                )));
            }

            if records.len() > RECORD_BATCH_MAX.count {
                return Err(ValidationError(format!(
                    "number of records in the batch exceeds {}",
                    RECORD_BATCH_MAX.count
                )));
            }
        }

        if records.is_empty() {
            return Err(ValidationError("batch is empty".into()));
        }

        Ok(Self {
            records,
            metered_bytes,
        })
    }
}

impl Deref for AppendRecordBatch {
    type Target = [AppendRecord];

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

impl MeteredBytes for AppendRecordBatch {
    fn metered_bytes(&self) -> usize {
        self.metered_bytes
    }
}

#[derive(Debug, Clone)]
/// Command to signal an operation.
pub enum Command {
    /// Fence operation.
    Fence {
        /// Fencing token.
        fencing_token: FencingToken,
    },
    /// Trim operation.
    Trim {
        /// Trim point.
        trim_point: u64,
    },
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Command record for signaling operations to the service.
///
/// See [here](https://s2.dev/docs/rest/records/overview#command-records) for more information.
pub struct CommandRecord {
    /// Command to signal an operation.
    pub command: Command,
    /// Timestamp for this record.
    pub timestamp: Option<u64>,
}

impl CommandRecord {
    const FENCE: &[u8] = b"fence";
    const TRIM: &[u8] = b"trim";

    /// Create a fence command record with the given fencing token.
    ///
    /// Fencing is strongly consistent, and subsequent appends that specify a
    /// fencing token will fail if it does not match.
    pub fn fence(fencing_token: FencingToken) -> Self {
        Self {
            command: Command::Fence { fencing_token },
            timestamp: None,
        }
    }

    /// Create a trim command record with the given trim point.
    ///
    /// Trim point is the desired earliest sequence number for the stream.
    ///
    /// Trimming is eventually consistent, and trimmed records may be visible
    /// for a brief period.
    pub fn trim(trim_point: u64) -> Self {
        Self {
            command: Command::Trim { trim_point },
            timestamp: None,
        }
    }

    /// Set the timestamp for this record.
    pub fn with_timestamp(self, timestamp: u64) -> Self {
        Self {
            timestamp: Some(timestamp),
            ..self
        }
    }
}

impl From<CommandRecord> for AppendRecord {
    fn from(value: CommandRecord) -> Self {
        let (header_value, body) = match value.command {
            Command::Fence { fencing_token } => (
                CommandRecord::FENCE,
                Bytes::copy_from_slice(fencing_token.as_bytes()),
            ),
            Command::Trim { trim_point } => (
                CommandRecord::TRIM,
                Bytes::copy_from_slice(&trim_point.to_be_bytes()),
            ),
        };
        Self {
            body,
            headers: vec![Header::new("", header_value)],
            timestamp: value.timestamp,
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Input for [`append`](crate::S2Stream::append) operation and
/// [`AppendSession::submit`](crate::append_session::AppendSession::submit).
pub struct AppendInput {
    /// Batch of records to append atomically.
    pub records: AppendRecordBatch,
    /// Expected sequence number for the first record in the batch.
    ///
    /// If unspecified, no matching is performed. If specified and mismatched, the append fails.
    pub match_seq_num: Option<u64>,
    /// Fencing token to match against the stream's current fencing token.
    ///
    /// If unspecified, no matching is performed. If specified and mismatched,
    /// the append fails. A stream defaults to `""` as its fencing token.
    pub fencing_token: Option<FencingToken>,
}

impl AppendInput {
    /// Create a new [`AppendInput`] with the given batch of records.
    pub fn new(records: AppendRecordBatch) -> Self {
        Self {
            records,
            match_seq_num: None,
            fencing_token: None,
        }
    }

    /// Set the expected sequence number for the first record in the batch.
    pub fn with_match_seq_num(self, match_seq_num: u64) -> Self {
        Self {
            match_seq_num: Some(match_seq_num),
            ..self
        }
    }

    /// Set the fencing token to match against the stream's current fencing token.
    pub fn with_fencing_token(self, fencing_token: FencingToken) -> Self {
        Self {
            fencing_token: Some(fencing_token),
            ..self
        }
    }
}

impl From<AppendInput> for api::stream::proto::AppendInput {
    fn from(value: AppendInput) -> Self {
        Self {
            records: value.records.iter().cloned().map(Into::into).collect(),
            match_seq_num: value.match_seq_num,
            fencing_token: value.fencing_token.map(|t| t.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Acknowledgement for an [`AppendInput`].
pub struct AppendAck {
    /// Sequence number and timestamp of the first record that was appended.
    pub start: StreamPosition,
    /// Sequence number of the last record that was appended + 1, and timestamp of the last record
    /// that was appended.
    ///
    /// The difference between `end.seq_num` and `start.seq_num` will be the number of records
    /// appended.
    pub end: StreamPosition,
    /// Sequence number that will be assigned to the next record on the stream, and timestamp of
    /// the last record on the stream.
    ///
    /// This can be greater than the `end` position in case of concurrent appends.
    pub tail: StreamPosition,
}

impl From<api::stream::proto::AppendAck> for AppendAck {
    fn from(value: api::stream::proto::AppendAck) -> Self {
        Self {
            start: value.start.unwrap_or_default().into(),
            end: value.end.unwrap_or_default().into(),
            tail: value.tail.unwrap_or_default().into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// Starting position for reading from a stream.
pub enum ReadFrom {
    /// Read from this sequence number.
    SeqNum(u64),
    /// Read from this timestamp.
    Timestamp(u64),
    /// Read from N records before the tail.
    TailOffset(u64),
}

impl Default for ReadFrom {
    fn default() -> Self {
        Self::SeqNum(0)
    }
}

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
/// Where to start reading.
pub struct ReadStart {
    /// Starting position.
    ///
    /// Defaults to reading from sequence number `0`.
    pub from: ReadFrom,
    /// Whether to start from tail if the requested starting position is beyond it.
    ///
    /// Defaults to `false` (errors if position is beyond tail).
    pub clamp_to_tail: bool,
}

impl ReadStart {
    /// Create a new [`ReadStart`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the starting position.
    pub fn with_from(self, from: ReadFrom) -> Self {
        Self { from, ..self }
    }

    /// Set whether to start from tail if the requested starting position is beyond it.
    pub fn with_clamp_to_tail(self, clamp_to_tail: bool) -> Self {
        Self {
            clamp_to_tail,
            ..self
        }
    }
}

impl From<ReadStart> for api::stream::ReadStart {
    fn from(value: ReadStart) -> Self {
        let (seq_num, timestamp, tail_offset) = match value.from {
            ReadFrom::SeqNum(n) => (Some(n), None, None),
            ReadFrom::Timestamp(t) => (None, Some(t), None),
            ReadFrom::TailOffset(o) => (None, None, Some(o)),
        };
        Self {
            seq_num,
            timestamp,
            tail_offset,
            clamp: if value.clamp_to_tail {
                Some(true)
            } else {
                None
            },
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Limits on how much to read.
pub struct ReadLimits {
    /// Limit on number of records.
    ///
    /// Defaults to `1000` for non-streaming read.
    pub count: Option<usize>,
    /// Limit on total metered bytes of records.
    ///
    /// Defaults to `1MiB` for non-streaming read.
    pub bytes: Option<usize>,
}

impl ReadLimits {
    /// Create a new [`ReadLimits`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the limit on number of records.
    pub fn with_count(self, count: usize) -> Self {
        Self {
            count: Some(count),
            ..self
        }
    }

    /// Set the limit on total metered bytes of records.
    pub fn with_bytes(self, bytes: usize) -> Self {
        Self {
            bytes: Some(bytes),
            ..self
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// When to stop reading.
pub struct ReadStop {
    /// Limits on how much to read.
    ///
    /// See [`ReadLimits`] for defaults.
    pub limits: ReadLimits,
    /// Timestamp at which to stop (exclusive).
    ///
    /// Defaults to `None`.
    pub until: Option<RangeTo<u64>>,
    /// Duration in seconds to wait for new records before stopping. Will be clamped to `60`
    /// seconds for [`read`](crate::S2Stream::read).
    ///
    /// Defaults to:
    /// - `0` (no wait) for [`read`](crate::S2Stream::read).
    /// - `0` (no wait) for [`read_session`](crate::S2Stream::read_session) if `limits` or `until`
    ///   is specified.
    /// - Infinite wait for [`read_session`](crate::S2Stream::read_session) if neither `limits` nor
    ///   `until` is specified.
    pub wait: Option<u32>,
}

impl ReadStop {
    /// Create a new [`ReadStop`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the limits on how much to read.
    pub fn with_limits(self, limits: ReadLimits) -> Self {
        Self { limits, ..self }
    }

    /// Set the timestamp at which to stop (exclusive).
    pub fn with_until(self, until: RangeTo<u64>) -> Self {
        Self {
            until: Some(until),
            ..self
        }
    }

    /// Set the duration in seconds to wait for new records before stopping.
    pub fn with_wait(self, wait: u32) -> Self {
        Self {
            wait: Some(wait),
            ..self
        }
    }
}

impl From<ReadStop> for api::stream::ReadEnd {
    fn from(value: ReadStop) -> Self {
        Self {
            count: value.limits.count,
            bytes: value.limits.bytes,
            until: value.until.map(|r| r.end),
            wait: value.wait,
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Input for [`read`](crate::S2Stream::read) and [`read_session`](crate::S2Stream::read_session)
/// operations.
pub struct ReadInput {
    /// Where to start reading.
    ///
    /// See [`ReadStart`] for defaults.
    pub start: ReadStart,
    /// When to stop reading.
    ///
    /// See [`ReadStop`] for defaults.
    pub stop: ReadStop,
    /// Whether to filter out command records from the stream when reading.
    ///
    /// Defaults to `false`.
    pub ignore_command_records: bool,
}

impl ReadInput {
    /// Create a new [`ReadInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set where to start reading.
    pub fn with_start(self, start: ReadStart) -> Self {
        Self { start, ..self }
    }

    /// Set when to stop reading.
    pub fn with_stop(self, stop: ReadStop) -> Self {
        Self { stop, ..self }
    }

    /// Set whether to filter out command records from the stream when reading.
    pub fn with_ignore_command_records(self, ignore_command_records: bool) -> Self {
        Self {
            ignore_command_records,
            ..self
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Record that is durably sequenced on a stream.
pub struct SequencedRecord {
    /// Sequence number assigned to this record.
    pub seq_num: u64,
    /// Body of this record.
    pub body: Bytes,
    /// Headers for this record.
    pub headers: Vec<Header>,
    /// Timestamp for this record.
    pub timestamp: u64,
}

impl SequencedRecord {
    /// Whether this is a command record.
    pub fn is_command_record(&self) -> bool {
        self.headers.len() == 1 && *self.headers[0].name == *b""
    }
}

impl From<api::stream::proto::SequencedRecord> for SequencedRecord {
    fn from(value: api::stream::proto::SequencedRecord) -> Self {
        Self {
            seq_num: value.seq_num,
            body: value.body,
            headers: value.headers.into_iter().map(Into::into).collect(),
            timestamp: value.timestamp,
        }
    }
}

metered_bytes_impl!(SequencedRecord);

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Batch of records returned by [`read`](crate::S2Stream::read) or streamed by
/// [`read_session`](crate::S2Stream::read_session).
pub struct ReadBatch {
    /// Records that are durably sequenced on the stream.
    ///
    /// It can be empty only for a [`read`](crate::S2Stream::read) operation when:
    /// - the [`stop condition`](ReadInput::stop) was already met, or
    /// - all records in the batch were command records and
    ///   [`ignore_command_records`](ReadInput::ignore_command_records) was set to `true`.
    pub records: Vec<SequencedRecord>,
    /// Sequence number that will be assigned to the next record on the stream, and timestamp of
    /// the last record.
    ///
    /// It will only be present when reading recent records.
    pub tail: Option<StreamPosition>,
}

impl ReadBatch {
    pub(crate) fn from_api(
        batch: api::stream::proto::ReadBatch,
        ignore_command_records: bool,
    ) -> Self {
        Self {
            records: batch
                .records
                .into_iter()
                .map(Into::into)
                .filter(|sr: &SequencedRecord| !ignore_command_records || !sr.is_command_record())
                .collect(),
            tail: batch.tail.map(Into::into),
        }
    }
}

/// A [`Stream`](futures::Stream) of values of type `Result<T, S2Error>`.
pub type Streaming<T> = Pin<Box<dyn Send + futures::Stream<Item = Result<T, S2Error>>>>;

#[derive(Debug, Clone, thiserror::Error)]
/// Why an append condition check failed.
pub enum AppendConditionFailed {
    #[error("fencing token mismatch, expected: {0}")]
    /// Fencing token did not match. Contains the expected fencing token.
    FencingTokenMismatch(FencingToken),
    #[error("sequence number mismatch, expected: {0}")]
    /// Sequence number did not match. Contains the expected sequence number.
    SeqNumMismatch(u64),
}

impl From<api::stream::AppendConditionFailed> for AppendConditionFailed {
    fn from(value: api::stream::AppendConditionFailed) -> Self {
        match value {
            api::stream::AppendConditionFailed::FencingTokenMismatch(token) => {
                AppendConditionFailed::FencingTokenMismatch(FencingToken(token.to_string()))
            }
            api::stream::AppendConditionFailed::SeqNumMismatch(seq) => {
                AppendConditionFailed::SeqNumMismatch(seq)
            }
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
/// Errors from S2 operations.
pub enum S2Error {
    #[error("{0}")]
    /// Client-side error.
    Client(String),
    #[error(transparent)]
    /// Validation error.
    Validation(#[from] ValidationError),
    #[error("{0}")]
    /// Append condition check failed. Contains the failure reason.
    AppendConditionFailed(AppendConditionFailed),
    #[error("read from an unwritten position. current tail: {0}")]
    /// Read from an unwritten position. Contains the current tail.
    ReadUnwritten(StreamPosition),
    #[error("{0}")]
    /// Other server-side error.
    Server(ErrorResponse),
}

impl From<ApiError> for S2Error {
    fn from(err: ApiError) -> Self {
        match err {
            ApiError::ReadUnwritten(tail_response) => {
                Self::ReadUnwritten(tail_response.tail.into())
            }
            ApiError::AppendConditionFailed(condition_failed) => {
                Self::AppendConditionFailed(condition_failed.into())
            }
            ApiError::Server(_, response) => Self::Server(response.into()),
            other => Self::Client(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{code}: {message}")]
#[non_exhaustive]
/// Error response from S2 server.
pub struct ErrorResponse {
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
}

impl From<ApiErrorResponse> for ErrorResponse {
    fn from(response: ApiErrorResponse) -> Self {
        Self {
            code: response.code,
            message: response.message,
        }
    }
}

fn idempotency_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
