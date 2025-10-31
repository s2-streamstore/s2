use std::{marker::PhantomData, ops::Deref, str::FromStr};

use compact_str::{CompactString, ToCompactString};
use enumset::{EnumSet, EnumSetType};

use super::{
    ValidationError,
    basin::{BasinName, BasinNamePrefix},
    stream::{StreamName, StreamNamePrefix},
    strings::{IdProps, PrefixProps, StartAfterProps, StrProps},
};
use crate::{caps, types::resources::ListItemsRequest};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct AccessTokenIdStr<T: StrProps>(CompactString, PhantomData<T>);

#[cfg(feature = "utoipa")]
impl<T> utoipa::PartialSchema for AccessTokenIdStr<T>
where
    T: StrProps,
{
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .min_length((!T::IS_PREFIX).then_some(1))
            .max_length(Some(Self::MAX_LENGTH))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl<T> utoipa::ToSchema for AccessTokenIdStr<T> where T: StrProps {}

impl<T: StrProps> serde::Serialize for AccessTokenIdStr<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, T: StrProps> serde::Deserialize<'de> for AccessTokenIdStr<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

impl<T: StrProps> AccessTokenIdStr<T> {
    const MAX_LENGTH: usize = caps::MAX_TOKEN_ID_LEN;
}

impl<T: StrProps> AsRef<str> for AccessTokenIdStr<T> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<T: StrProps> Deref for AccessTokenIdStr<T> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: StrProps> TryFrom<CompactString> for AccessTokenIdStr<T> {
    type Error = ValidationError;

    fn try_from(name: CompactString) -> Result<Self, Self::Error> {
        if !T::IS_PREFIX && name.is_empty() {
            return Err(format!("Access token {} must not be empty", T::FIELD_NAME).into());
        }

        if name.len() > Self::MAX_LENGTH {
            return Err(format!(
                "Access token {} must not exceed {} characters in length",
                T::FIELD_NAME,
                Self::MAX_LENGTH
            )
            .into());
        }

        Ok(Self(name, PhantomData))
    }
}

impl<T: StrProps> FromStr for AccessTokenIdStr<T> {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_compact_string().try_into()
    }
}

impl<T: StrProps> std::fmt::Debug for AccessTokenIdStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> std::fmt::Display for AccessTokenIdStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> From<AccessTokenIdStr<T>> for CompactString {
    fn from(value: AccessTokenIdStr<T>) -> Self {
        value.0
    }
}

pub type AccessTokenId = AccessTokenIdStr<IdProps>;

pub type AccessTokenIdPrefix = AccessTokenIdStr<PrefixProps>;

impl Default for AccessTokenIdPrefix {
    fn default() -> Self {
        AccessTokenIdStr(CompactString::default(), PhantomData)
    }
}

impl From<AccessTokenId> for AccessTokenIdPrefix {
    fn from(value: AccessTokenId) -> Self {
        Self(value.0, PhantomData)
    }
}

pub type AccessTokenIdStartAfter = AccessTokenIdStr<StartAfterProps>;

impl Default for AccessTokenIdStartAfter {
    fn default() -> Self {
        AccessTokenIdStr(CompactString::default(), PhantomData)
    }
}

#[derive(Debug, Hash, EnumSetType, strum::EnumCount)]
pub enum Operation {
    ListBasins = 1,
    CreateBasin = 2,
    DeleteBasin = 3,
    ReconfigureBasin = 4,
    GetBasinConfig = 5,
    IssueAccessToken = 6,
    RevokeAccessToken = 7,
    ListAccessTokens = 8,
    ListStreams = 9,
    CreateStream = 10,
    DeleteStream = 11,
    GetStreamConfig = 12,
    ReconfigureStream = 13,
    CheckTail = 14,
    Append = 15,
    Read = 16,
    Trim = 17,
    Fence = 18,
    AccountMetrics = 19,
    BasinMetrics = 20,
    StreamMetrics = 21,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum ResourceSet<E, P> {
    #[default]
    None,
    Exact(E),
    Prefix(P),
}

pub type BasinResourceSet = ResourceSet<BasinName, BasinNamePrefix>;
pub type StreamResourceSet = ResourceSet<StreamName, StreamNamePrefix>;
pub type AccessTokenResourceSet = ResourceSet<AccessTokenId, AccessTokenIdPrefix>;

#[derive(Debug, Clone, Copy, Default)]
pub struct ReadWritePermissions {
    pub read: bool,
    pub write: bool,
}

impl ReadWritePermissions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_read(self, read: bool) -> Self {
        Self { read, ..self }
    }

    pub fn with_write(self, write: bool) -> Self {
        Self { write, ..self }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PermittedOperationGroups {
    pub account: ReadWritePermissions,
    pub basin: ReadWritePermissions,
    pub stream: ReadWritePermissions,
}

impl PermittedOperationGroups {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_account(self, account: ReadWritePermissions) -> Self {
        Self { account, ..self }
    }

    pub fn with_basin(self, basin: ReadWritePermissions) -> Self {
        Self { basin, ..self }
    }

    pub fn with_stream(self, stream: ReadWritePermissions) -> Self {
        Self { stream, ..self }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AccessTokenScope {
    pub basins: BasinResourceSet,
    pub streams: StreamResourceSet,
    pub access_tokens: AccessTokenResourceSet,
    pub op_groups: PermittedOperationGroups,
    pub ops: EnumSet<Operation>,
}

impl AccessTokenScope {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_basins(self, basins: BasinResourceSet) -> Self {
        Self { basins, ..self }
    }

    pub fn with_streams(self, streams: StreamResourceSet) -> Self {
        Self { streams, ..self }
    }

    pub fn with_tokens(self, access_tokens: AccessTokenResourceSet) -> Self {
        Self {
            access_tokens,
            ..self
        }
    }

    pub fn with_op_groups(self, op_groups: PermittedOperationGroups) -> Self {
        Self { op_groups, ..self }
    }

    pub fn with_ops(self, ops: impl IntoIterator<Item = Operation>) -> Self {
        Self {
            ops: ops.into_iter().collect(),
            ..self
        }
    }

    pub fn with_op(self, op: Operation) -> Self {
        let mut ops = self.ops;
        ops.insert(op);
        Self { ops, ..self }
    }
}

#[derive(Debug, Clone)]
pub struct AccessTokenInfo {
    pub id: AccessTokenId,
    pub expires_at: time::OffsetDateTime,
    pub auto_prefix_streams: bool,
    pub scope: AccessTokenScope,
}

#[derive(Debug, Clone)]
pub struct IssueAccessTokenRequest {
    pub id: AccessTokenId,
    pub expires_at: Option<time::OffsetDateTime>,
    pub auto_prefix_streams: bool,
    pub scope: AccessTokenScope,
}

impl IssueAccessTokenRequest {
    pub fn new(id: impl AsRef<str>) -> Result<Self, ValidationError> {
        Ok(Self {
            id: id.as_ref().parse()?,
            expires_at: None,
            auto_prefix_streams: false,
            scope: AccessTokenScope::default(),
        })
    }

    pub fn with_expires_at(self, expires_at: time::OffsetDateTime) -> Self {
        Self {
            expires_at: Some(expires_at),
            ..self
        }
    }

    pub fn with_auto_prefix_streams(self, auto_prefix_streams: bool) -> Self {
        Self {
            auto_prefix_streams,
            ..self
        }
    }

    pub fn with_scope(self, scope: AccessTokenScope) -> Self {
        Self { scope, ..self }
    }
}

pub type ListAccessTokensRequest = ListItemsRequest<AccessTokenIdPrefix, AccessTokenIdStartAfter>;
