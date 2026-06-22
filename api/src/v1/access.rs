use s2_common::{
    self,
    access::{AccessTokenId, AccessTokenIdPrefix, AccessTokenIdStartAfter},
    basin::{BasinName, BasinNamePrefix},
    stream::{StreamName, StreamNamePrefix},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum MaybeEmpty<T> {
    Empty,
    NonEmpty(T),
}

impl<T: Serialize> Serialize for MaybeEmpty<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::NonEmpty(v) => v.serialize(serializer),
            Self::Empty => serializer.serialize_str(""),
        }
    }
}

impl<'de, T> Deserialize<'de> for MaybeEmpty<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            Ok(MaybeEmpty::Empty)
        } else {
            T::deserialize(serde::de::value::StringDeserializer::new(s)).map(MaybeEmpty::NonEmpty)
        }
    }
}

use time::OffsetDateTime;

#[rustfmt::skip]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    /// List basins.
    ListBasins,
    /// Create a basin.
    CreateBasin,
    /// Delete a basin.
    DeleteBasin,
    /// Reconfigure a basin.
    ReconfigureBasin,
    /// Get basin configuration.
    GetBasinConfig,
    /// Issue an access token.
    IssueAccessToken,
    /// Revoke an access token.
    RevokeAccessToken,
    /// List access tokens.
    ListAccessTokens,
    /// List streams.
    ListStreams,
    /// Create a stream.
    CreateStream,
    /// Delete a stream.
    DeleteStream,
    /// Get stream configuration.
    GetStreamConfig,
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
    /// Retrieve account-level metrics.
    AccountMetrics,
    /// Retrieve basin-level metrics.
    BasinMetrics,
    /// Retrieve stream-level metrics.
    StreamMetrics,
    /// List locations.
    ListLocations,
    /// Get the default location.
    GetDefaultLocation,
    /// Set the default location.
    SetDefaultLocation,
}

impl From<Operation> for s2_common::access::Operation {
    fn from(value: Operation) -> Self {
        match value {
            Operation::ListBasins => Self::ListBasins,
            Operation::CreateBasin => Self::CreateBasin,
            Operation::DeleteBasin => Self::DeleteBasin,
            Operation::ReconfigureBasin => Self::ReconfigureBasin,
            Operation::GetBasinConfig => Self::GetBasinConfig,
            Operation::IssueAccessToken => Self::IssueAccessToken,
            Operation::RevokeAccessToken => Self::RevokeAccessToken,
            Operation::ListAccessTokens => Self::ListAccessTokens,
            Operation::ListStreams => Self::ListStreams,
            Operation::CreateStream => Self::CreateStream,
            Operation::DeleteStream => Self::DeleteStream,
            Operation::GetStreamConfig => Self::GetStreamConfig,
            Operation::ReconfigureStream => Self::ReconfigureStream,
            Operation::CheckTail => Self::CheckTail,
            Operation::Append => Self::Append,
            Operation::Read => Self::Read,
            Operation::Trim => Self::Trim,
            Operation::Fence => Self::Fence,
            Operation::AccountMetrics => Self::AccountMetrics,
            Operation::BasinMetrics => Self::BasinMetrics,
            Operation::StreamMetrics => Self::StreamMetrics,
            Operation::ListLocations => Self::ListLocations,
            Operation::GetDefaultLocation => Self::GetDefaultLocation,
            Operation::SetDefaultLocation => Self::SetDefaultLocation,
        }
    }
}

impl From<s2_common::access::Operation> for Operation {
    fn from(value: s2_common::access::Operation) -> Self {
        use s2_common::access::Operation::*;
        match value {
            ListBasins => Self::ListBasins,
            CreateBasin => Self::CreateBasin,
            DeleteBasin => Self::DeleteBasin,
            ReconfigureBasin => Self::ReconfigureBasin,
            GetBasinConfig => Self::GetBasinConfig,
            IssueAccessToken => Self::IssueAccessToken,
            RevokeAccessToken => Self::RevokeAccessToken,
            ListAccessTokens => Self::ListAccessTokens,
            ListStreams => Self::ListStreams,
            CreateStream => Self::CreateStream,
            DeleteStream => Self::DeleteStream,
            GetStreamConfig => Self::GetStreamConfig,
            ReconfigureStream => Self::ReconfigureStream,
            CheckTail => Self::CheckTail,
            Append => Self::Append,
            Read => Self::Read,
            Trim => Self::Trim,
            Fence => Self::Fence,
            AccountMetrics => Self::AccountMetrics,
            BasinMetrics => Self::BasinMetrics,
            StreamMetrics => Self::StreamMetrics,
            ListLocations => Self::ListLocations,
            GetDefaultLocation => Self::GetDefaultLocation,
            SetDefaultLocation => Self::SetDefaultLocation,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AccessTokenInfo {
    /// Access token ID.
    pub id: AccessTokenId,
    /// Expiration time in RFC 3339 format.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub expires_at: OffsetDateTime,
    /// Namespace streams based on the configured stream-level scope.
    pub auto_prefix_streams: bool,
    /// Access token scope.
    pub scope: AccessTokenScope,
}

impl From<s2_common::access::AccessTokenInfo> for AccessTokenInfo {
    fn from(value: s2_common::access::AccessTokenInfo) -> Self {
        Self {
            id: value.id,
            expires_at: value.expires_at,
            auto_prefix_streams: value.auto_prefix_streams,
            scope: value.scope.into(),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct IssueAccessTokenRequest {
    /// Access token ID.
    /// It must be unique to the account and between 1 and 96 bytes in length.
    pub id: AccessTokenId,
    /// Expiration time in RFC 3339 format.
    /// If not set, the expiration will be set to that of the requestor's token.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// Namespace streams based on the configured stream-level scope, which must be a prefix.
    /// Stream name arguments will be automatically prefixed, and the prefix will be stripped when listing streams.
    #[cfg_attr(feature = "utoipa", schema(value_type = bool, default = false, required = false))]
    pub auto_prefix_streams: Option<bool>,
    /// Access token scope.
    pub scope: AccessTokenScope,
}

impl TryFrom<IssueAccessTokenRequest> for s2_common::access::IssueAccessTokenRequest {
    type Error = s2_common::ValidationError;

    fn try_from(value: IssueAccessTokenRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            expires_at: value.expires_at,
            auto_prefix_streams: value.auto_prefix_streams.unwrap_or_default(),
            scope: value.scope.try_into()?,
        })
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AccessTokenScope {
    /// Basin names allowed.
    pub basins: Option<ResourceSet<MaybeEmpty<BasinName>, BasinNamePrefix>>,
    /// Stream names allowed.
    pub streams: Option<ResourceSet<MaybeEmpty<StreamName>, StreamNamePrefix>>,
    /// Token IDs allowed.
    pub access_tokens:  Option<ResourceSet<MaybeEmpty<AccessTokenId>, AccessTokenIdPrefix>>,
    /// Access permissions at operation group level.
    pub op_groups: Option<PermittedOperationGroups>,
    /// Operations allowed for the token.
    /// A union of allowed operations and groups is used as an effective set of allowed operations.
    #[cfg_attr(feature = "utoipa", schema(required = false))]
    pub ops: Option<Vec<Operation>>,
}

impl TryFrom<AccessTokenScope> for s2_common::access::AccessTokenScope {
    type Error = s2_common::ValidationError;

    fn try_from(value: AccessTokenScope) -> Result<Self, Self::Error> {
        let AccessTokenScope {
            basins,
            streams,
            access_tokens,
            op_groups,
            ops,
        } = value;

        Ok(Self {
            basins: basins.map(Into::into).unwrap_or_default(),
            streams: streams.map(Into::into).unwrap_or_default(),
            access_tokens: access_tokens.map(Into::into).unwrap_or_default(),
            op_groups: op_groups.map(Into::into).unwrap_or_default(),
            ops: ops
                .map(|o| {
                    o.into_iter()
                        .map(s2_common::access::Operation::from)
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

impl From<s2_common::access::AccessTokenScope> for AccessTokenScope {
    fn from(value: s2_common::access::AccessTokenScope) -> Self {
        let s2_common::access::AccessTokenScope {
            basins,
            streams,
            access_tokens,
            op_groups,
            ops,
        } = value;

        Self {
            basins: ResourceSet::to_opt(basins),
            streams: ResourceSet::to_opt(streams),
            access_tokens: ResourceSet::to_opt(access_tokens),
            op_groups: Some(op_groups.into()),
            ops: Some(ops.into_iter().map(Operation::from).collect()),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ResourceSet<E, P> {
    /// Match only the resource with this exact name.
    /// Use an empty string to match no resources.
    #[cfg_attr(feature = "utoipa", schema(title = "exact", value_type = String))]
    Exact(E),
    /// Match all resources that start with this prefix.
    /// Use an empty string to match all resource.
    #[cfg_attr(feature = "utoipa", schema(title = "prefix", value_type = String))]
    Prefix(P),
}

impl<E, P> ResourceSet<MaybeEmpty<E>, P> {
    pub fn to_opt(rs: s2_common::access::ResourceSet<E, P>) -> Option<Self> {
        match rs {
            s2_common::access::ResourceSet::None => None,
            s2_common::access::ResourceSet::Exact(e) => {
                Some(ResourceSet::Exact(MaybeEmpty::NonEmpty(e)))
            }
            s2_common::access::ResourceSet::Prefix(p) => Some(ResourceSet::Prefix(p)),
        }
    }
}

impl<E, P> From<ResourceSet<MaybeEmpty<E>, P>> for s2_common::access::ResourceSet<E, P> {
    fn from(value: ResourceSet<MaybeEmpty<E>, P>) -> Self {
        match value {
            ResourceSet::Exact(MaybeEmpty::Empty) => Self::None,
            ResourceSet::Exact(MaybeEmpty::NonEmpty(e)) => Self::Exact(e),
            ResourceSet::Prefix(p) => Self::Prefix(p),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PermittedOperationGroups {
    /// Account-level access permissions.
    pub account: Option<ReadWritePermissions>,
    /// Basin-level access permissions.
    pub basin: Option<ReadWritePermissions>,
    /// Stream-level access permissions.
    pub stream: Option<ReadWritePermissions>,
}

impl From<PermittedOperationGroups> for s2_common::access::PermittedOperationGroups {
    fn from(value: PermittedOperationGroups) -> Self {
        let PermittedOperationGroups {
            account,
            basin,
            stream,
        } = value;

        Self {
            account: account.map(Into::into).unwrap_or_default(),
            basin: basin.map(Into::into).unwrap_or_default(),
            stream: stream.map(Into::into).unwrap_or_default(),
        }
    }
}

impl From<s2_common::access::PermittedOperationGroups> for PermittedOperationGroups {
    fn from(value: s2_common::access::PermittedOperationGroups) -> Self {
        let s2_common::access::PermittedOperationGroups {
            account,
            basin,
            stream,
        } = value;

        Self {
            account: Some(account.into()),
            basin: Some(basin.into()),
            stream: Some(stream.into()),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ReadWritePermissions {
    /// Read permission.
    #[cfg_attr(feature = "utoipa", schema(value_type = bool, default = false, required = false))]
    pub read: Option<bool>,
    /// Write permission.
    #[cfg_attr(feature = "utoipa", schema(value_type = bool, default = false, required = false))]
    pub write: Option<bool>,
}

impl From<ReadWritePermissions> for s2_common::access::ReadWritePermissions {
    fn from(value: ReadWritePermissions) -> Self {
        let ReadWritePermissions { read, write } = value;

        Self {
            read: read.unwrap_or_default(),
            write: write.unwrap_or_default(),
        }
    }
}

impl From<s2_common::access::ReadWritePermissions> for ReadWritePermissions {
    fn from(value: s2_common::access::ReadWritePermissions) -> Self {
        let s2_common::access::ReadWritePermissions { read, write } = value;

        Self {
            read: Some(read),
            write: Some(write),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct ListAccessTokensRequest {
    /// Filter to access tokens whose IDs begin with this prefix.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub prefix: Option<AccessTokenIdPrefix>,
    /// Filter to access tokens whose IDs lexicographically start after this string.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub start_after: Option<AccessTokenIdStartAfter>,
    /// Number of results, up to a maximum of 1000.
    #[cfg_attr(feature = "utoipa", param(value_type = usize, maximum = 1000, default = 1000, required = false))]
    pub limit: Option<usize>,
}

super::impl_list_request_conversions!(
    ListAccessTokensRequest,
    AccessTokenIdPrefix,
    AccessTokenIdStartAfter
);

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ListAccessTokensResponse {
    /// Matching access tokens.
    #[cfg_attr(feature = "utoipa", schema(max_items = 1000))]
    pub access_tokens: Vec<AccessTokenInfo>,
    /// Indicates that there are more access tokens that match the criteria.
    pub has_more: bool,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct IssueAccessTokenResponse {
    /// Created access token.
    pub access_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_exact_converts_to_resource_set_none() {
        let json = serde_json::json!({
            "id": "test-token",
            "scope": {
                "streams": {"exact": ""},
                "basins": {"exact": ""},
                "access_tokens": {"exact": ""}
            }
        });

        let parsed: IssueAccessTokenRequest = serde_json::from_value(json).unwrap();
        let internal: s2_common::access::IssueAccessTokenRequest = parsed.try_into().unwrap();

        assert!(matches!(
            internal.scope.streams,
            s2_common::access::ResourceSet::None
        ));
        assert!(matches!(
            internal.scope.basins,
            s2_common::access::ResourceSet::None
        ));
        assert!(matches!(
            internal.scope.access_tokens,
            s2_common::access::ResourceSet::None
        ));
    }

    #[test]
    fn missing_scope_fields_default_to_resource_set_none() {
        let json = serde_json::json!({
            "id": "test-token",
            "scope": {}
        });

        let parsed: IssueAccessTokenRequest = serde_json::from_value(json).unwrap();
        let internal: s2_common::access::IssueAccessTokenRequest = parsed.try_into().unwrap();

        assert!(matches!(
            internal.scope.streams,
            s2_common::access::ResourceSet::None
        ));
        assert!(matches!(
            internal.scope.basins,
            s2_common::access::ResourceSet::None
        ));
        assert!(matches!(
            internal.scope.access_tokens,
            s2_common::access::ResourceSet::None
        ));
    }

    #[test]
    fn issue_access_token_request_converts_explicit_fields() {
        let json = serde_json::json!({
            "id": "test-token",
            "expires_at": "2026-06-22T02:04:00Z",
            "auto_prefix_streams": true,
            "scope": {
                "streams": {"prefix": "tenant-a/"},
                "ops": ["append"]
            }
        });

        let parsed: IssueAccessTokenRequest = serde_json::from_value(json).unwrap();
        let internal: s2_common::access::IssueAccessTokenRequest = parsed.try_into().unwrap();

        assert_eq!(internal.id.as_ref(), "test-token");
        assert!(internal.expires_at.is_some());
        assert!(internal.auto_prefix_streams);
        assert!(matches!(
            internal.scope.streams,
            s2_common::access::ResourceSet::Prefix(_)
        ));
        assert!(
            internal
                .scope
                .ops
                .contains(s2_common::access::Operation::Append)
        );
    }
}
