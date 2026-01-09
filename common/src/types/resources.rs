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
    const MAX: NonZeroUsize = NonZeroUsize::new(1000).unwrap();

    pub fn get(&self) -> NonZeroUsize {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0.get()
    }
}

impl Default for ListLimit {
    fn default() -> Self {
        Self(Self::MAX)
    }
}

impl From<usize> for ListLimit {
    fn from(value: usize) -> Self {
        Self(NonZeroUsize::new(value).unwrap_or(Self::MAX).min(Self::MAX))
    }
}

impl From<ListLimit> for usize {
    fn from(value: ListLimit) -> Self {
        value.as_usize()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ListItemsRequestParts<P, S> {
    pub prefix: P,
    pub start_after: S,
    pub limit: ListLimit,
}

#[derive(Debug, Clone, Default)]
pub struct ListItemsRequest<P, S>(ListItemsRequestParts<P, S>)
where
    P: Default,
    S: Default;

impl<P, S> ListItemsRequest<P, S>
where
    P: Default,
    S: Default,
{
    pub fn parts(&self) -> &ListItemsRequestParts<P, S> {
        &self.0
    }
}

impl<P, S> From<ListItemsRequest<P, S>> for ListItemsRequestParts<P, S>
where
    P: Default,
    S: Default,
{
    fn from(ListItemsRequest(parts): ListItemsRequest<P, S>) -> Self {
        parts
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("`start_after` must be greater than or equal to the `prefix`")]
pub struct StartAfterLessThanPrefixError;

impl<P, S> TryFrom<ListItemsRequestParts<P, S>> for ListItemsRequest<P, S>
where
    P: Deref<Target = str> + Default,
    S: Deref<Target = str> + Default,
{
    type Error = StartAfterLessThanPrefixError;

    fn try_from(parts: ListItemsRequestParts<P, S>) -> Result<Self, Self::Error> {
        let start_after: &str = &parts.start_after;
        let prefix: &str = &parts.prefix;

        if !start_after.is_empty() && !prefix.is_empty() && start_after < prefix {
            return Err(StartAfterLessThanPrefixError);
        }

        Ok(Self(parts))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateMode {
    /// Create a new resource.
    ///
    /// HTTP POST semantics – idempotent if a request token is provided and the resource was
    /// previously created using the same token.
    CreateOnly(Option<RequestToken>),
    /// Create a new resource or reconfigure if the resource already exists.
    ///
    /// HTTP PUT semantics – always idempotent.
    CreateOrReconfigure,
}

pub static REQUEST_TOKEN_HEADER: http::HeaderName =
    http::HeaderName::from_static("s2-request-token");

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
