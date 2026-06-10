use std::{fmt::Debug, num::NonZeroUsize, ops::Deref, str::FromStr};

use compact_str::{CompactString, ToCompactString};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub values: Vec<T>,
    pub has_more: bool,
}

impl<T> Page<T> {
    pub fn new_empty() -> Self {
        Self {
            values: Vec::new(),
            has_more: false,
        }
    }

    pub fn new(values: impl Into<Vec<T>>, has_more: bool) -> Self {
        Self {
            values: values.into(),
            has_more,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ListLimit(NonZeroUsize);

impl ListLimit {
    pub const MAX: ListLimit = Self(NonZeroUsize::new(1000).unwrap());

    pub fn get(&self) -> NonZeroUsize {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0.get()
    }
}

impl Default for ListLimit {
    fn default() -> Self {
        Self::MAX
    }
}

impl From<usize> for ListLimit {
    fn from(value: usize) -> Self {
        NonZeroUsize::new(value)
            .and_then(|n| (n <= Self::MAX.0).then_some(Self(n)))
            .unwrap_or_default()
    }
}

impl From<ListLimit> for usize {
    fn from(value: ListLimit) -> Self {
        value.as_usize()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ListItemsRequest<P, S> {
    pub prefix: P,
    pub start_after: S,
    pub limit: ListLimit,
}

/// Mode for provisioning a resource.
///
/// Provisioning either creates a new resource with create-only semantics, or ensures that
/// a resource exists with the requested config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionMode {
    /// Create a new resource only.
    ///
    /// HTTP POST semantics: idempotent if a request token is provided and the resource was
    /// previously created using the same token and config.
    CreateOnly {
        /// Optional request token used to make create retries idempotent.
        request_token: Option<RequestToken>,
    },
    /// Ensure a resource exists with the requested config.
    ///
    /// HTTP PUT semantics: always idempotent. Defaults are applied before validation. When the
    /// resource already exists, its stored config is set to the effective requested config unless
    /// it already matches.
    Ensure,
}

/// Result of provisioning a resource.
///
/// Indicates whether provisioning created, updated, or skipped writing a resource.
/// All variants hold the resource's current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionResult<T> {
    /// Resource was newly created.
    Created(T),
    /// Resource already existed and now matches the requested config.
    Updated(T),
    /// Resource already existed and no write was performed.
    Noop(T),
}

impl<T> ProvisionResult<T> {
    /// Borrow the inner value regardless of variant.
    pub fn inner(&self) -> &T {
        match self {
            Self::Created(t) | Self::Updated(t) | Self::Noop(t) => t,
        }
    }

    /// Unwrap the inner value regardless of variant.
    pub fn into_inner(self) -> T {
        match self {
            Self::Created(t) | Self::Updated(t) | Self::Noop(t) => t,
        }
    }

    /// Map the inner value while preserving the provisioning outcome.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> ProvisionResult<U> {
        match self {
            Self::Created(t) => ProvisionResult::Created(f(t)),
            Self::Updated(t) => ProvisionResult::Updated(f(t)),
            Self::Noop(t) => ProvisionResult::Noop(f(t)),
        }
    }

    /// Fallibly map the inner value while preserving the provisioning outcome.
    pub fn try_map<U, E>(self, f: impl FnOnce(T) -> Result<U, E>) -> Result<ProvisionResult<U>, E> {
        match self {
            Self::Created(t) => Ok(ProvisionResult::Created(f(t)?)),
            Self::Updated(t) => Ok(ProvisionResult::Updated(f(t)?)),
            Self::Noop(t) => Ok(ProvisionResult::Noop(f(t)?)),
        }
    }
}
pub static REQUEST_TOKEN_HEADER: http::HeaderName =
    http::HeaderName::from_static("s2-request-token");

pub static PROVISION_RESULT_HEADER: http::HeaderName =
    http::HeaderName::from_static("s2-provision-result");

pub const MAX_REQUEST_TOKEN_LENGTH: usize = 36;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("request token was longer than {MAX_REQUEST_TOKEN_LENGTH} bytes in length: {0}")]
pub struct RequestTokenTooLongError(pub usize);

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct RequestToken(CompactString);

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for RequestToken {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .max_length(Some(MAX_REQUEST_TOKEN_LENGTH))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for RequestToken {}

impl serde::Serialize for RequestToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for RequestToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        RequestToken::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for RequestToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<CompactString> for RequestToken {
    type Error = RequestTokenTooLongError;

    fn try_from(input: CompactString) -> Result<Self, Self::Error> {
        if input.len() > MAX_REQUEST_TOKEN_LENGTH {
            return Err(RequestTokenTooLongError(input.len()));
        }
        Ok(RequestToken(input))
    }
}

impl FromStr for RequestToken {
    type Err = RequestTokenTooLongError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_compact_string().try_into()
    }
}

impl From<RequestToken> for CompactString {
    fn from(token: RequestToken) -> Self {
        token.0
    }
}

impl AsRef<str> for RequestToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for RequestToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl crate::http::ParseableHeader for RequestToken {
    fn name() -> &'static http::HeaderName {
        &REQUEST_TOKEN_HEADER
    }
}
