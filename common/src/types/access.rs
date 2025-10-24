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
pub struct AccessTokenStr<T: StrProps>(CompactString, PhantomData<T>);

impl<T: StrProps> serde::Serialize for AccessTokenStr<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, T: StrProps> serde::Deserialize<'de> for AccessTokenStr<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CompactString::from(s)
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl<T: StrProps> AccessTokenStr<T> {
    const MAX_LENGTH: usize = caps::MAX_TOKEN_ID_LEN;
}

impl<T: StrProps> AsRef<str> for AccessTokenStr<T> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<T: StrProps> Deref for AccessTokenStr<T> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: StrProps> TryFrom<CompactString> for AccessTokenStr<T> {
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

impl<T: StrProps> FromStr for AccessTokenStr<T> {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_compact_string().try_into()
    }
}

impl<T: StrProps> std::fmt::Debug for AccessTokenStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> std::fmt::Display for AccessTokenStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> From<AccessTokenStr<T>> for CompactString {
    fn from(value: AccessTokenStr<T>) -> Self {
        value.0
    }
}

pub type AccessTokenId = AccessTokenStr<IdProps>;

pub type AccessTokenIdPrefix = AccessTokenStr<PrefixProps>;

impl Default for AccessTokenIdPrefix {
    fn default() -> Self {
        "".parse().expect("empty prefix is valid")
    }
}

pub type AccessTokenIdStartAfter = AccessTokenStr<StartAfterProps>;

impl Default for AccessTokenIdStartAfter {
    fn default() -> Self {
        "".parse().expect("empty start_after is valid")
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

#[derive(
    rkyv::Archive,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
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

#[derive(Debug, Clone, Default)]
pub struct PermittedOperationGroups {
    pub account: ReadWritePermissions,
    pub basin: ReadWritePermissions,
    pub stream: ReadWritePermissions,
}

#[derive(Debug, Clone, Default)]
pub struct AccessTokenScope {
    pub basins: BasinResourceSet,
    pub streams: StreamResourceSet,
    pub access_tokens: AccessTokenResourceSet,
    pub op_groups: PermittedOperationGroups,
    pub ops: EnumSet<Operation>,
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

pub type ListAccessTokensRequest = ListItemsRequest<AccessTokenIdPrefix, AccessTokenIdStartAfter>;
