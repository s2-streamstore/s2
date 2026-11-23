use std::{
    env::VarError,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "_hidden")]
use async_trait::async_trait;
use base64ct::{Base64, Encoding};
use http::{
    HeaderMap,
    header::HeaderValue,
    uri::{Authority, Scheme},
};
use rustls::crypto::CryptoProvider;
use s2_api::v1::stream::s2s::CompressionAlgorithm;
use s2_common::basin::BasinName;
use secrecy::{ExposeSecret, SecretBox, SecretString};

use crate::error::ValidationError;

#[cfg(feature = "_hidden")]
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
#[doc(hidden)]
pub struct AccessTokenProviderError {
    message: String,
    retryable: bool,
}

#[cfg(feature = "_hidden")]
impl AccessTokenProviderError {
    /// Create a provider error that should be retried with normal SDK backoff.
    pub fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }

    /// Create a provider error that should be returned immediately.
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }

    pub(crate) fn is_retryable(&self) -> bool {
        self.retryable
    }
}

#[cfg(feature = "_hidden")]
#[async_trait]
#[doc(hidden)]
pub trait AccessTokenProvider: fmt::Debug + Send + Sync {
    /// Return an access token for the next request attempt.
    async fn access_token(&self) -> Result<String, AccessTokenProviderError>;

    /// Notify the provider that S2 rejected an access token.
    fn invalidate_access_token(&self, _rejected_access_token: &str) {}
}

#[derive(Clone)]
pub(crate) enum AccessToken {
    Static(SecretString),
    #[cfg(feature = "_hidden")]
    Provider(Arc<dyn AccessTokenProvider>),
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(_) => formatter.write_str("Static(<redacted>)"),
            #[cfg(feature = "_hidden")]
            Self::Provider(_) => formatter.write_str("Provider(<redacted>)"),
        }
    }
}

/// Client-supplied encryption key for server-side encryption.
///
/// Represents non-empty raw key bytes encoded as standard padded base64 for the
/// `s2-encryption-key` header. Construct from raw key bytes with [`from_bytes`](Self::from_bytes)
/// or from base64 text with [`from_base64`](Self::from_base64) / [`FromStr`]. Key length
/// validation is left to the server, since the required length depends on the stream's cipher.
#[derive(Clone)]
#[must_use]
pub struct EncryptionKey(SecretString);

impl EncryptionKey {
    /// Construct an [`EncryptionKey`] from raw key bytes.
    ///
    /// Takes a byte slice rather than `impl AsRef<[u8]>` so a base64 `&str` cannot be
    /// accidentally double-encoded; use [`from_base64`](Self::from_base64) or [`str::parse`] for
    /// base64-encoded keys.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `bytes` is empty.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.is_empty() {
            return Err(ValidationError("encryption key must not be empty".into()));
        }
        Ok(Self(SecretString::from(Base64::encode_string(bytes))))
    }

    /// Construct an [`EncryptionKey`] from standard padded base64 text (ignoring surrounding
    /// whitespace).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `encoded` is empty or not valid standard padded base64.
    pub fn from_base64(encoded: impl AsRef<str>) -> Result<Self, ValidationError> {
        let trimmed = encoded.as_ref().trim();
        if trimmed.is_empty() {
            return Err(ValidationError("encryption key must not be empty".into()));
        }
        let _decoded = SecretBox::from(Base64::decode_vec(trimmed).map_err(|_| {
            ValidationError("encryption key must be valid standard padded base64".into())
        })?);
        Ok(Self(SecretString::from(trimmed.to_owned())))
    }

    /// Encode this key as a sensitive HTTP header value for `s2-encryption-key`.
    pub(crate) fn to_header_value(&self) -> HeaderValue {
        let mut value = HeaderValue::from_str(self.0.expose_secret())
            .expect("base64-encoded encryption key is a valid HTTP header value");
        value.set_sensitive(true);
        value
    }
}

impl FromStr for EncryptionKey {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base64(s)
    }
}

impl TryFrom<&str> for EncryptionKey {
    type Error = ValidationError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_base64(s)
    }
}

impl TryFrom<String> for EncryptionKey {
    type Error = ValidationError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_base64(s)
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionKey(<redacted>)")
    }
}

/// Authority for connecting to an S2 basin.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum BasinAuthority {
    /// Parent zone for basins. DNS is used to route to the correct cell for the basin.
    ParentZone(Authority),
    /// Direct cell authority. Basin is expected to be hosted by this cell.
    Direct(Authority),
}

fn parse_endpoint_scheme_and_rest<'a>(
    s: &'a str,
    kind: &str,
) -> Result<(Scheme, &'a str), ValidationError> {
    let (scheme, rest) = match s.find("://") {
        Some(idx) => {
            let scheme: Scheme = s[..idx]
                .parse()
                .map_err(|_| format!("invalid {kind} endpoint scheme"))?;
            if scheme != Scheme::HTTP && scheme != Scheme::HTTPS {
                return Err(format!(
                    "invalid {kind} endpoint scheme: only http and https are supported"
                )
                .into());
            }
            (scheme, &s[idx + 3..])
        }
        None => (Scheme::HTTPS, s),
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    Ok((scheme, rest))
}

fn parse_endpoint_authority(authority: &str, kind: &str) -> Result<Authority, String> {
    if authority.is_empty() {
        return Err(format!("invalid {kind} endpoint authority: empty"));
    }
    if authority.contains('@') {
        return Err(format!(
            "invalid {kind} endpoint authority: user info is not allowed"
        ));
    }
    if authority.ends_with(':') {
        return Err(format!(
            "invalid {kind} endpoint authority: port cannot be empty"
        ));
    }
    let parsed: Authority = authority.parse().map_err(|e| {
        // A bare IPv6 address has several colons, which `Authority` cannot tell
        // apart from the port separator.
        if !authority.contains('[') && authority.matches(':').count() > 1 {
            format!(
                "invalid {kind} endpoint authority: {e}; IPv6 addresses must be enclosed in \
                 brackets, e.g. [::1]:8080"
            )
        } else {
            format!("invalid {kind} endpoint authority: {e}")
        }
    })?;
    if parsed.host().is_empty() {
        return Err(format!("invalid {kind} endpoint authority: empty host"));
    }
    // Userinfo (`@`) is already rejected above, so any suffix beyond `host()` is a `:port`.
    // `Authority::port_u16()` returns `None` for out-of-range ports (e.g. `:99999`), so require a
    // parsed non-zero `u16` whenever a port suffix is present (`C3`).
    if parsed.as_str().len() != parsed.host().len() && !parsed.port_u16().is_some_and(|p| p != 0) {
        return Err(format!(
            "invalid {kind} endpoint authority: port must be between 1 and 65535"
        ));
    }
    validate_endpoint_host(parsed.host(), kind)?;
    Ok(parsed)
}

fn validate_endpoint_host(host: &str, kind: &str) -> Result<(), String> {
    if host.starts_with('[') || host.ends_with(']') {
        let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
            return Err(format!(
                "invalid {kind} endpoint host `{host}`: malformed bracketed IPv6 literal"
            ));
        };
        inner
            .parse::<Ipv6Addr>()
            .map_err(|_| format!("invalid {kind} endpoint host `{host}`: invalid IPv6 address"))?;
        return Ok(());
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    if is_valid_dns_name(host) {
        return Ok(());
    }
    Err(format!(
        "invalid {kind} endpoint host `{host}`: must be a DNS name or IP address"
    ))
}

fn is_valid_dns_name(host: &str) -> bool {
    let dns = host.strip_suffix('.').unwrap_or(host);
    if dns.is_empty() || dns.len() > 253 {
        return false;
    }
    dns.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
            && (bytes[bytes.len() - 1].is_ascii_alphanumeric() || bytes[bytes.len() - 1] == b'_')
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
    })
}

/// Whether the authority's host is an IP address (`127.0.0.1`, `[::1]`) rather than a DNS name.
fn is_ip_literal(authority: &Authority) -> bool {
    let host = authority.host();
    if host.starts_with('[') || host.ends_with(']') {
        return true;
    }
    host.parse::<IpAddr>().is_ok()
}

/// Account endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct AccountEndpoint {
    pub(super) scheme: Scheme,
    pub(super) authority: Authority,
}

impl AccountEndpoint {
    /// Create a new [`AccountEndpoint`] with the given endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if the scheme, host, or port is invalid.
    pub fn new(endpoint: impl AsRef<str>) -> Result<Self, ValidationError> {
        endpoint.as_ref().parse()
    }
}

impl FromStr for AccountEndpoint {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, authority) = parse_endpoint_scheme_and_rest(s, "account")?;
        Ok(Self {
            scheme,
            authority: parse_endpoint_authority(authority, "account")?,
        })
    }
}

impl TryFrom<&str> for AccountEndpoint {
    type Error = ValidationError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for AccountEndpoint {
    type Error = ValidationError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for AccountEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.authority)
    }
}

/// Basin endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct BasinEndpoint {
    pub(super) scheme: Scheme,
    pub(super) authority: BasinAuthority,
}

impl BasinEndpoint {
    /// Create a new [`BasinEndpoint`] with the given endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if the scheme, host, or port is invalid, or if the `{basin}.`
    /// placeholder is used with an IP address (which cannot have basin subdomains).
    pub fn new(endpoint: impl AsRef<str>) -> Result<Self, ValidationError> {
        endpoint.as_ref().parse()
    }
}

impl FromStr for BasinEndpoint {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, authority) = parse_endpoint_scheme_and_rest(s, "basin")?;
        let authority = if let Some(authority) = authority.strip_prefix("{basin}.") {
            let zone = parse_endpoint_authority(authority, "basin")?;
            if is_ip_literal(&zone) {
                return Err(format!(
                    "invalid basin endpoint: the {{basin}}. placeholder requires a DNS name, but \
                     {} is an IP address; remove the placeholder to connect to the address \
                     directly",
                    zone.host()
                )
                .into());
            }
            BasinAuthority::ParentZone(zone)
        } else {
            BasinAuthority::Direct(parse_endpoint_authority(authority, "basin")?)
        };
        Ok(Self { scheme, authority })
    }
}

impl TryFrom<&str> for BasinEndpoint {
    type Error = ValidationError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for BasinEndpoint {
    type Error = ValidationError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for BasinEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.authority {
            BasinAuthority::ParentZone(zone) => write!(f, "{}://{{basin}}.{zone}", self.scheme),
            BasinAuthority::Direct(authority) => write!(f, "{}://{authority}", self.scheme),
        }
    }
}

/// Endpoints for the S2 environment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct S2Endpoints {
    pub(crate) scheme: Scheme,
    pub(crate) account_authority: Authority,
    pub(crate) basin_authority: BasinAuthority,
}

impl Default for S2Endpoints {
    fn default() -> Self {
        Self::for_cloud()
    }
}

impl fmt::Display for S2Endpoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.basin_authority {
            BasinAuthority::ParentZone(zone) => write!(
                f,
                "account={}://{}, basin={}://{{basin}}.{zone}",
                self.scheme, self.account_authority, self.scheme
            ),
            BasinAuthority::Direct(authority) => write!(
                f,
                "account={}://{}, basin={}://{authority}",
                self.scheme, self.account_authority, self.scheme
            ),
        }
    }
}

impl S2Endpoints {
    /// Create a new [`S2Endpoints`] with the given account and basin endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if the two endpoints do not use the same scheme.
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

    /// Create endpoints for a single account and basin endpoint.
    ///
    /// This is useful for S2-compatible services that expose both APIs at one endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `endpoint` is not a valid endpoint.
    pub fn for_endpoint(endpoint: impl AsRef<str>) -> Result<Self, ValidationError> {
        let account = AccountEndpoint::new(endpoint)?;
        Ok(Self {
            scheme: account.scheme,
            account_authority: account.authority.clone(),
            basin_authority: BasinAuthority::Direct(account.authority),
        })
    }

    /// Create a new [`S2Endpoints`] from environment variables.
    ///
    /// Reads `S2_ACCOUNT_ENDPOINT` and `S2_BASIN_ENDPOINT`. Empty values are treated as unset.
    /// If neither variable is set, returns the default S2 Cloud endpoints ([`Self::for_cloud`]).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if only one endpoint variable is set, or if either endpoint is
    /// invalid or mismatched.
    pub fn from_env() -> Result<Self, ValidationError> {
        Self::from_env_inner(|key| std::env::var(key))
    }

    /// Create a new [`S2Endpoints`] from a custom environment variable lookup function.
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    pub fn from_env_with<F>(var: F) -> Result<Self, ValidationError>
    where
        F: FnMut(&str) -> Result<String, VarError>,
    {
        Self::from_env_inner(var)
    }

    pub(crate) fn from_env_inner<F>(mut var: F) -> Result<Self, ValidationError>
    where
        F: FnMut(&str) -> Result<String, VarError>,
    {
        let read_opt = |name: &str, var: &mut F| -> Result<Option<String>, ValidationError> {
            match var(name) {
                Ok(value) if value.is_empty() => Ok(None),
                Ok(value) => Ok(Some(value)),
                Err(VarError::NotPresent) => Ok(None),
                Err(VarError::NotUnicode(_)) => Err(format!("{name} is not valid unicode").into()),
            }
        };

        let account = read_opt("S2_ACCOUNT_ENDPOINT", &mut var)?;
        let basin = read_opt("S2_BASIN_ENDPOINT", &mut var)?;

        match (account, basin) {
            (None, None) => Ok(Self::for_cloud()),
            (Some(_), None) => Err("S2_ACCOUNT_ENDPOINT is set without S2_BASIN_ENDPOINT".into()),
            (None, Some(_)) => Err("S2_BASIN_ENDPOINT is set without S2_ACCOUNT_ENDPOINT".into()),
            (Some(account), Some(basin)) => Self::new(account.parse()?, basin.parse()?),
        }
    }

    /// Return the default S2 Cloud endpoints.
    pub fn for_cloud() -> Self {
        Self {
            scheme: Scheme::HTTPS,
            account_authority: "a.s2.dev".try_into().expect("valid authority"),
            basin_authority: BasinAuthority::ParentZone(
                "b.s2.dev".try_into().expect("valid authority"),
            ),
        }
    }

    /// Return the resolved origin for account requests (e.g. `https://a.s2.dev`).
    #[must_use]
    pub fn account_origin(&self) -> String {
        format!("{}://{}", self.scheme, self.account_authority)
    }

    /// Return the resolved origin for requests targeting `basin`.
    #[must_use]
    pub fn basin_origin(&self, basin: &BasinName) -> String {
        match &self.basin_authority {
            BasinAuthority::ParentZone(zone) => format!("{}://{basin}.{zone}", self.scheme),
            BasinAuthority::Direct(authority) => format!("{}://{authority}", self.scheme),
        }
    }

    /// Whether basin requests must send the `s2-basin` header.
    #[must_use]
    pub fn uses_basin_header(&self) -> bool {
        matches!(self.basin_authority, BasinAuthority::Direct(_))
    }
}

/// Compression algorithm for request and response bodies.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Compression {
    /// No compression.
    #[default]
    None,
    /// Gzip compression.
    Gzip,
    /// Zstd compression.
    Zstd,
}

impl Compression {
    /// Return the wire/setting name of this compression algorithm.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
        }
    }

    pub(crate) fn into_api(self) -> CompressionAlgorithm {
        match self {
            Self::None => CompressionAlgorithm::None,
            Self::Gzip => CompressionAlgorithm::Gzip,
            Self::Zstd => CompressionAlgorithm::Zstd,
        }
    }
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Retry policy for [`append`](crate::S2Stream::append) and
/// [`append_session`](crate::S2Stream::append_session) operations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppendRetryPolicy {
    /// Retry all appends. Use when duplicate records on the stream are acceptable.
    #[default]
    All,
    /// Retry only when the failed attempt certainly had no side effects.
    ///
    /// Retries only after a definite error (where
    /// [`has_no_side_effects()`](crate::error::AppendError::has_no_side_effects) is `true`) or
    /// when no unacked request/batch bytes were sent on the failed attempt.
    NoSideEffects,
}

impl AppendRetryPolicy {
    /// Return the setting name of this retry policy.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::NoSideEffects => "no_side_effects",
        }
    }
}

impl fmt::Display for AppendRetryPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration for retrying requests in case of transient failures.
///
/// Exponential backoff with jitter is the retry strategy. Below is the pseudocode for the strategy:
/// ```text
/// base_delay = min(min_base_delay · 2ⁿ, max_base_delay)    (n = retry attempt, starting from 0)
///     jitter = rand[0, base_delay]
///     delay  = base_delay + jitter
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct RetryConfig {
    pub(crate) max_attempts: NonZeroU32,
    pub(crate) min_base_delay: Duration,
    pub(crate) max_base_delay: Duration,
    pub(crate) append_retry_policy: AppendRetryPolicy,
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

    /// Return the total number of attempts including the initial try.
    #[must_use]
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts.get()
    }

    /// Return the minimum base delay for retries.
    #[must_use]
    pub fn min_base_delay(&self) -> Duration {
        self.min_base_delay
    }

    /// Return the maximum base delay for retries.
    #[must_use]
    pub fn max_base_delay(&self) -> Duration {
        self.max_base_delay
    }

    /// Return the retry policy for append operations.
    #[must_use]
    pub fn append_retry_policy(&self) -> AppendRetryPolicy {
        self.append_retry_policy
    }

    /// Set the total number of attempts including the initial try.
    ///
    /// Defaults to `3`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `max_attempts` is `0`.
    pub fn with_max_attempts(self, max_attempts: u32) -> Result<Self, ValidationError> {
        let max_attempts = NonZeroU32::new(max_attempts)
            .ok_or_else(|| ValidationError("max_attempts must be at least 1".into()))?;
        Ok(Self {
            max_attempts,
            ..self
        })
    }

    /// Set the minimum base delay for retries.
    ///
    /// Defaults to `100ms`.
    pub fn with_min_base_delay(self, min_base_delay: Duration) -> Self {
        Self {
            min_base_delay,
            ..self
        }
    }

    /// Set the maximum base delay for retries.
    ///
    /// Defaults to `1s`.
    pub fn with_max_base_delay(self, max_base_delay: Duration) -> Self {
        Self {
            max_base_delay,
            ..self
        }
    }

    /// Set the retry policy for [`append`](crate::S2Stream::append) and
    /// [`append_session`](crate::S2Stream::append_session) operations.
    ///
    /// Defaults to [`AppendRetryPolicy::All`].
    pub fn with_append_retry_policy(self, append_retry_policy: AppendRetryPolicy) -> Self {
        Self {
            append_retry_policy,
            ..self
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        if self.min_base_delay > self.max_base_delay {
            return Err("min_base_delay must not exceed max_base_delay".into());
        }
        Ok(())
    }
}

/// Overrides for the HTTP/2 transport used by pooled connections.
///
/// Unset knobs keep the SDK defaults: 50 concurrent requests per connection,
/// 4 MiB per-stream receive window, and a connection receive window of at least
/// 256 MiB (automatically scaled up to `max_concurrent_requests × stream_receive_window`,
/// capped at [`Self::MAX_RECEIVE_WINDOW`], when left unset so paused read sessions on a
/// shared connection cannot exhaust the connection window and stall sibling appends or
/// unary calls). Receive windows bound unconsumed server-to-client DATA only; they do not
/// affect append throughput, which is governed by the server's receive windows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct Http2Config {
    pub(crate) max_concurrent_requests: Option<usize>,
    pub(crate) stream_receive_window: Option<u32>,
    pub(crate) connection_receive_window: Option<u32>,
}

impl Http2Config {
    /// Stream limit advertised by S2 servers per HTTP/2 connection.
    pub const MAX_CONCURRENT_REQUESTS: usize = 100;

    /// Maximum HTTP/2 flow-control window in bytes (`2^31 - 1`).
    pub const MAX_RECEIVE_WINDOW: u32 = i32::MAX as u32;

    /// Minimum HTTP/2 connection receive window in bytes.
    ///
    /// The connection window cannot be shrunk below the protocol default.
    pub const MIN_CONNECTION_RECEIVE_WINDOW: u32 = 65_535;

    /// Start from the SDK defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the configured per-connection concurrent request cap, if overridden.
    #[must_use]
    pub fn max_concurrent_requests(&self) -> Option<usize> {
        self.max_concurrent_requests
    }

    /// Return the configured initial per-stream receive window in bytes, if overridden.
    #[must_use]
    pub fn stream_receive_window(&self) -> Option<u32> {
        self.stream_receive_window
    }

    /// Return the configured connection-level receive window in bytes, if overridden.
    #[must_use]
    pub fn connection_receive_window(&self) -> Option<u32> {
        self.connection_receive_window
    }

    /// Cap concurrent requests per pooled connection.
    ///
    /// The cap includes unary requests and streaming sessions until their
    /// bodies finish or are dropped. Additional requests use another pooled
    /// connection.
    ///
    /// # Errors
    ///
    /// Must be between 1 and [`Self::MAX_CONCURRENT_REQUESTS`]. Requests beyond
    /// the server's stream limit would queue on the connection instead of
    /// spilling over to another one.
    pub fn with_max_concurrent_requests(
        self,
        max_concurrent_requests: usize,
    ) -> Result<Self, ValidationError> {
        if !(1..=Self::MAX_CONCURRENT_REQUESTS).contains(&max_concurrent_requests) {
            return Err(format!(
                "HTTP/2 concurrent request limit must be between 1 and {}",
                Self::MAX_CONCURRENT_REQUESTS
            )
            .into());
        }
        Ok(Self {
            max_concurrent_requests: Some(max_concurrent_requests),
            ..self
        })
    }

    /// Set the initial per-stream receive window in bytes.
    ///
    /// # Errors
    ///
    /// Must be between 1 and [`Self::MAX_RECEIVE_WINDOW`].
    pub fn with_stream_receive_window(
        self,
        stream_receive_window: u32,
    ) -> Result<Self, ValidationError> {
        if !(1..=Self::MAX_RECEIVE_WINDOW).contains(&stream_receive_window) {
            return Err("HTTP/2 stream receive window must be between 1 and 2^31 - 1 bytes".into());
        }
        Ok(Self {
            stream_receive_window: Some(stream_receive_window),
            ..self
        })
    }

    /// Set the connection-level receive window in bytes, shared by all streams
    /// on the connection.
    ///
    /// # Errors
    ///
    /// Must be between [`Self::MIN_CONNECTION_RECEIVE_WINDOW`] and
    /// [`Self::MAX_RECEIVE_WINDOW`].
    pub fn with_connection_receive_window(
        self,
        connection_receive_window: u32,
    ) -> Result<Self, ValidationError> {
        if !(Self::MIN_CONNECTION_RECEIVE_WINDOW..=Self::MAX_RECEIVE_WINDOW)
            .contains(&connection_receive_window)
        {
            return Err(
                "HTTP/2 connection receive window must be between 65,535 and 2^31 - 1 bytes".into(),
            );
        }
        Ok(Self {
            connection_receive_window: Some(connection_receive_window),
            ..self
        })
    }
}

/// Configuration for [`S2`](crate::S2).
#[derive(Clone)]
#[must_use]
pub struct S2Config {
    pub(crate) access_token: AccessToken,
    pub(crate) endpoints: S2Endpoints,
    pub(crate) http2: Http2Config,
    pub(crate) connection_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) retry: RetryConfig,
    pub(crate) compression: Compression,
    pub(crate) user_agent: HeaderValue,
    pub(crate) default_headers: HeaderMap,
    pub(crate) insecure_skip_cert_verification: bool,
    pub(crate) rustls_crypto_provider: Option<Arc<CryptoProvider>>,
}

impl fmt::Debug for S2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S2Config")
            .field("access_token", &self.access_token)
            .field("endpoints", &self.endpoints)
            .field("http2", &self.http2)
            .field("connection_timeout", &self.connection_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("retry", &self.retry)
            .field("compression", &self.compression)
            .field("user_agent", &self.user_agent)
            .field(
                "insecure_skip_cert_verification",
                &self.insecure_skip_cert_verification,
            )
            .field(
                "rustls_crypto_provider",
                &self.rustls_crypto_provider.as_ref().map(|_| ".."),
            )
            .finish_non_exhaustive()
    }
}

impl S2Config {
    /// Create a new [`S2Config`] with the given access token and default settings.
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            access_token: AccessToken::Static(access_token.into().into()),
            endpoints: S2Endpoints::for_cloud(),
            http2: Http2Config::new(),
            connection_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            retry: RetryConfig::new(),
            compression: Compression::None,
            user_agent: concat!("s2-sdk-rust/", env!("CARGO_PKG_VERSION"))
                .parse()
                .expect("valid user agent"),
            default_headers: HeaderMap::new(),
            insecure_skip_cert_verification: false,
            rustls_crypto_provider: None,
        }
    }

    /// Create a new [`S2Config`] from environment variables.
    ///
    /// Reads `S2_ACCESS_TOKEN`, and optionally `S2_ACCOUNT_ENDPOINT` and `S2_BASIN_ENDPOINT`
    /// (empty endpoint variables are treated as unset; if one is set, both must be set).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `S2_ACCESS_TOKEN` is missing, empty, or invalid, or if the
    /// endpoint variables are incomplete or invalid.
    pub fn from_env() -> Result<Self, ValidationError> {
        Self::from_env_inner(|key| std::env::var(key))
    }

    /// Create a new [`S2Config`] from a custom environment variable lookup function.
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    pub fn from_env_with<F>(var: F) -> Result<Self, ValidationError>
    where
        F: FnMut(&str) -> Result<String, VarError>,
    {
        Self::from_env_inner(var)
    }

    fn from_env_inner<F>(mut var: F) -> Result<Self, ValidationError>
    where
        F: FnMut(&str) -> Result<String, VarError>,
    {
        let access_token = match var("S2_ACCESS_TOKEN") {
            Ok(token) => token,
            Err(VarError::NotPresent) => return Err("S2_ACCESS_TOKEN env var not set".into()),
            Err(VarError::NotUnicode(_)) => {
                return Err("S2_ACCESS_TOKEN is not valid unicode".into());
            }
        };
        crate::api::authorization_header(&access_token)?;
        let endpoints = S2Endpoints::from_env_inner(var)?;
        Ok(Self::new(access_token).with_endpoints(endpoints))
    }

    /// Return the configured endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &S2Endpoints {
        &self.endpoints
    }

    /// Return the configured HTTP/2 transport settings.
    pub fn http2(&self) -> Http2Config {
        self.http2
    }

    /// Return the timeout for establishing a connection to the server.
    #[must_use]
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    /// Return the timeout for requests.
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Return the retry configuration.
    pub fn retry(&self) -> RetryConfig {
        self.retry
    }

    /// Return the compression algorithm for requests and responses.
    #[must_use]
    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// Return whether TLS certificate verification is disabled.
    #[must_use]
    pub fn insecure_skip_cert_verification(&self) -> bool {
        self.insecure_skip_cert_verification
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        self.retry.validate()
    }

    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    pub fn with_access_token_provider(self, provider: impl AccessTokenProvider + 'static) -> Self {
        Self {
            access_token: AccessToken::Provider(Arc::new(provider)),
            ..self
        }
    }

    /// Set the S2 endpoints to connect to.
    pub fn with_endpoints(self, endpoints: S2Endpoints) -> Self {
        Self { endpoints, ..self }
    }

    /// Set additional HTTP headers to send with every request.
    ///
    /// These headers apply to account, basin, and stream operations, including
    /// retries and streaming requests. SDK-generated headers, such as
    /// authorization and basin routing, take precedence over these defaults.
    /// Calling this method again replaces the previous set of default headers.
    ///
    /// `Accept-Encoding` defaults are used only when [`Compression::None`] is
    /// configured; otherwise the SDK sets the header to the configured
    /// compression algorithm.
    ///
    /// Headers are sent to all configured S2 endpoints. Use
    /// [`HeaderValue::set_sensitive`] for values that should be redacted in debug
    /// output. Do not use these defaults for per-request identifiers, since the
    /// same values are reused across requests.
    ///
    /// # Errors
    ///
    /// Returns an error if `default_headers` contains `Content-Type`,
    /// `Content-Encoding`, `Content-Length`, or `Transfer-Encoding`.
    /// The SDK controls request format and body framing.
    /// Use [`Self::with_compression`] to configure request body encoding.
    #[cfg(feature = "_hidden")]
    #[doc(hidden)]
    pub fn with_default_headers(self, default_headers: HeaderMap) -> Result<Self, ValidationError> {
        if default_headers.contains_key(http::header::CONTENT_ENCODING) {
            return Err(ValidationError(
                "Content-Encoding cannot be set in default headers; use S2Config::with_compression instead"
                    .into(),
            ));
        }
        for name in [
            http::header::CONTENT_TYPE,
            http::header::CONTENT_LENGTH,
            http::header::TRANSFER_ENCODING,
        ] {
            if default_headers.contains_key(&name) {
                return Err(ValidationError(format!(
                    "{name} cannot be set in default headers; the SDK controls request format and body framing"
                )));
            }
        }
        Ok(Self {
            default_headers,
            ..self
        })
    }

    /// Override HTTP/2 transport settings for pooled connections.
    ///
    /// Defaults to [`Http2Config::new()`].
    pub fn with_http2(self, http2: Http2Config) -> Self {
        Self { http2, ..self }
    }

    /// Set the timeout for establishing a connection to the server.
    ///
    /// Defaults to `3s`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `connection_timeout` is zero.
    pub fn with_connection_timeout(
        self,
        connection_timeout: Duration,
    ) -> Result<Self, ValidationError> {
        if connection_timeout.is_zero() {
            return Err("connection_timeout must be greater than zero".into());
        }
        Ok(Self {
            connection_timeout,
            ..self
        })
    }

    /// Set the timeout for requests.
    ///
    /// Defaults to `5s`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `request_timeout` is zero.
    pub fn with_request_timeout(self, request_timeout: Duration) -> Result<Self, ValidationError> {
        if request_timeout.is_zero() {
            return Err("request_timeout must be greater than zero".into());
        }
        Ok(Self {
            request_timeout,
            ..self
        })
    }

    /// Set the retry configuration for requests.
    ///
    /// See [`RetryConfig`] for defaults.
    pub fn with_retry(self, retry: RetryConfig) -> Self {
        Self { retry, ..self }
    }

    /// Set the compression algorithm for requests and responses.
    ///
    /// Defaults to [`Compression::None`].
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

    /// Use a specific rustls crypto provider for SDK TLS connections.
    ///
    /// When not set explicitly on [`S2Config`], HTTPS connections resolve a provider in this
    /// order:
    ///
    /// 1. Rustls's process-global default provider ([`CryptoProvider::get_default`], installed via
    ///    [`CryptoProvider::install_default`]), if one has been installed.
    /// 2. Compile-time crate feature fallback: `rustls-aws-lc-rs` (enabled by default), then
    ///    `rustls-ring`.
    /// 3. Otherwise, client initialization returns a [`ValidationError`] for HTTPS endpoints.
    ///
    /// Use this method to override the process-global or feature-default provider for a single
    /// client (for example, to select a custom [`CryptoProvider`] or pick between `aws-lc-rs` and
    /// `ring`).
    pub fn with_rustls_crypto_provider(self, provider: impl Into<Arc<CryptoProvider>>) -> Self {
        Self {
            rustls_crypto_provider: Some(provider.into()),
            ..self
        }
    }

    /// Use rustls's `aws-lc-rs` crypto provider.
    ///
    /// Requires the `rustls-aws-lc-rs` crate feature.
    #[cfg(feature = "rustls-aws-lc-rs")]
    pub fn with_rustls_aws_lc_rs_crypto_provider(self) -> Self {
        self.with_rustls_crypto_provider(rustls::crypto::aws_lc_rs::default_provider())
    }

    /// Use rustls's `ring` crypto provider.
    ///
    /// Requires the `rustls-ring` crate feature.
    #[cfg(feature = "rustls-ring")]
    pub fn with_rustls_ring_crypto_provider(self) -> Self {
        self.with_rustls_crypto_provider(rustls::crypto::ring::default_provider())
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
