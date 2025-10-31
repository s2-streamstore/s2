use s2_common::types::{
    self,
    access::{AccessTokenId, AccessTokenIdPrefix},
    basin::{BasinName, BasinNamePrefix},
    stream::{StreamName, StreamNamePrefix},
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Iso8601};
#[cfg(feature = "utoipa")]
use utoipa::{IntoParams, ToSchema};

#[rustfmt::skip]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
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
}

impl From<Operation> for types::access::Operation {
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
        }
    }
}

impl From<types::access::Operation> for Operation {
    fn from(value: types::access::Operation) -> Self {
        use types::access::Operation::*;
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
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct AccessTokenInfo {
    /// Access token ID.
    /// It must be unique to the account and between 1 and 96 bytes in length.
    pub id: types::access::AccessTokenId,
    /// Expiration time in ISO 8601 format.
    /// If not set, the expiration will be set to that of the requestor's token.
    #[cfg_attr(feature = "utoipa", schema(format = Time))]
    pub expires_at: Option<String>,
    /// Namespace streams based on the configured stream-level scope, which must be a prefix.
    /// Stream name arguments will be automatically prefixed, and the prefix will be stripped when listing streams.
    #[cfg_attr(feature = "utoipa", schema(value_type = bool, default = false, required = false))]
    pub auto_prefix_streams: Option<bool>,
    /// Access token scope.
    pub scope: AccessTokenScope,
}

impl TryFrom<AccessTokenInfo> for types::access::IssueAccessTokenRequest {
    type Error = types::ValidationError;

    fn try_from(value: AccessTokenInfo) -> Result<Self, Self::Error> {
        let AccessTokenInfo {
            id,
            expires_at,
            auto_prefix_streams,
            scope,
        } = value;

        Ok(Self {
            id,
            expires_at: expires_at
                .map(|e| OffsetDateTime::parse(&e, &Iso8601::DEFAULT))
                .transpose()
                .map_err(|_| "Invalid ISO-8601 formatted `expires_at` time")?,
            auto_prefix_streams: auto_prefix_streams.unwrap_or_default(),
            scope: scope.try_into()?,
        })
    }
}

impl From<types::access::AccessTokenInfo> for AccessTokenInfo {
    fn from(value: types::access::AccessTokenInfo) -> Self {
        let types::access::AccessTokenInfo {
            id,
            expires_at,
            auto_prefix_streams,
            scope,
        } = value;

        Self {
            id,
            expires_at: Some(
                expires_at
                    .format(&Iso8601::DEFAULT)
                    .expect("valid iso8601 time"),
            ),
            auto_prefix_streams: Some(auto_prefix_streams),
            scope: scope.into(),
        }
    }
}

impl From<types::access::IssueAccessTokenRequest> for AccessTokenInfo {
    fn from(value: types::access::IssueAccessTokenRequest) -> Self {
        let types::access::IssueAccessTokenRequest {
            id,
            expires_at,
            auto_prefix_streams,
            scope,
        } = value;

        Self {
            id,
            expires_at: expires_at
                .map(|e| e.format(&Iso8601::DEFAULT).expect("valid iso8601 time")),
            auto_prefix_streams: Some(auto_prefix_streams),
            scope: scope.into(),
        }
    }
}

impl TryFrom<AccessTokenInfo> for types::access::AccessTokenInfo {
    type Error = types::ValidationError;

    fn try_from(value: AccessTokenInfo) -> Result<Self, Self::Error> {
        let AccessTokenInfo {
            id,
            expires_at,
            auto_prefix_streams,
            scope,
        } = value;

        Ok(Self {
            id,
            expires_at: expires_at.ok_or("Missing `expires_at`").and_then(|e| {
                OffsetDateTime::parse(&e, &Iso8601::DEFAULT)
                    .map_err(|_| "Invalid ISO-8601 formatted `expires_at` time")
            })?,
            auto_prefix_streams: auto_prefix_streams.unwrap_or_default(),
            scope: scope.try_into()?,
        })
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct AccessTokenScope {
    /// Basin names allowed.
    pub basins: Option<ResourceSet<BasinName, BasinNamePrefix>>,
    /// Stream names allowed.
    pub streams: Option<ResourceSet<StreamName, StreamNamePrefix>>,
    /// Token IDs allowed.
    pub access_tokens:  Option<ResourceSet<AccessTokenId, AccessTokenIdPrefix>>,
    /// Access permissions at operation group level.
    pub op_groups: Option<PermittedOperationGroups>,
    /// Operations allowed for the token.
    /// A union of allowed operations and groups is used as an effective set of allowed operations.
    #[cfg_attr(feature = "utoipa", schema(required = false))]
    pub ops: Option<Vec<Operation>>,
}

impl TryFrom<AccessTokenScope> for types::access::AccessTokenScope {
    type Error = types::ValidationError;

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
                .map(|o| o.into_iter().map(types::access::Operation::from).collect())
                .unwrap_or_default(),
        })
    }
}

impl From<types::access::AccessTokenScope> for AccessTokenScope {
    fn from(value: types::access::AccessTokenScope) -> Self {
        let types::access::AccessTokenScope {
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
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
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

impl<E, P> ResourceSet<E, P> {
    pub fn to_opt(rs: types::access::ResourceSet<E, P>) -> Option<Self> {
        match rs {
            types::access::ResourceSet::None => None,
            types::access::ResourceSet::Exact(e) => Some(ResourceSet::Exact(e)),
            types::access::ResourceSet::Prefix(p) => Some(ResourceSet::Prefix(p)),
        }
    }
}

impl<E, P> From<ResourceSet<E, P>> for types::access::ResourceSet<E, P>
where
    E: AsRef<str>,
{
    fn from(value: ResourceSet<E, P>) -> Self {
        match value {
            ResourceSet::Exact(e) if e.as_ref().is_empty() => Self::None,
            ResourceSet::Exact(e) => Self::Exact(e),
            ResourceSet::Prefix(p) => Self::Prefix(p),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PermittedOperationGroups {
    /// Account-level access permissions.
    pub account: Option<ReadWritePermissions>,
    /// Basin-level access permissions.
    pub basin: Option<ReadWritePermissions>,
    /// Stream-level access permissions.
    pub stream: Option<ReadWritePermissions>,
}

impl From<PermittedOperationGroups> for types::access::PermittedOperationGroups {
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

impl From<types::access::PermittedOperationGroups> for PermittedOperationGroups {
    fn from(value: types::access::PermittedOperationGroups) -> Self {
        let types::access::PermittedOperationGroups {
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
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ReadWritePermissions {
    /// Read permission.
    #[cfg_attr(feature = "utoipa", schema(value_type = bool, default = false, required = false))]
    pub read: Option<bool>,
    /// Write permission.
    #[cfg_attr(feature = "utoipa", schema(value_type = bool, default = false, required = false))]
    pub write: Option<bool>,
}

impl From<ReadWritePermissions> for types::access::ReadWritePermissions {
    fn from(value: ReadWritePermissions) -> Self {
        let ReadWritePermissions { read, write } = value;

        Self {
            read: read.unwrap_or_default(),
            write: write.unwrap_or_default(),
        }
    }
}

impl From<types::access::ReadWritePermissions> for ReadWritePermissions {
    fn from(value: types::access::ReadWritePermissions) -> Self {
        let types::access::ReadWritePermissions { read, write } = value;

        Self {
            read: Some(read),
            write: Some(write),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct ListAccessTokensRequest {
    /// Filter to access tokens whose ID begins with this prefix.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub prefix: Option<types::access::AccessTokenIdPrefix>,
    /// Filter to access tokens whose ID lexicographically starts after this string.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub start_after: Option<types::access::AccessTokenIdStartAfter>,
    /// Number of results, up to a maximum of 1000.
    #[cfg_attr(feature = "utoipa", param(value_type = usize, maximum = 1000, default = 1000, required = false))]
    pub limit: Option<usize>,
}

super::impl_list_request_conversions!(
    ListAccessTokensRequest,
    types::access::AccessTokenIdPrefix,
    types::access::AccessTokenIdStartAfter
);

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ListAccessTokensResponse {
    /// Matching access tokens.
    #[cfg_attr(feature = "utoipa", schema(max_items = 1000))]
    pub access_tokens: Vec<AccessTokenInfo>,
    /// Indicates that there are more access tokens that match the criteria.
    pub has_more: bool,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct IssueAccessTokenResponse {
    /// Created access token.
    pub access_token: String,
}
