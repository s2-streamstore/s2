use std::collections::HashSet;

use jiff::Timestamp;
use s2_api::v1::{self as api, MaybeKnown};
use s2_common::{
    ValidationError,
    access::{AccessTokenId, AccessTokenIdPrefix, AccessTokenIdStartAfter},
    basin::{BasinName, BasinNamePrefix},
    network_policy::{NetworkPolicyRef, NetworkPolicySelector},
    stream::{StreamName, StreamNamePrefix},
};

use super::validate_rfc3339_timestamp;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
/// Input for [`list_access_tokens`](crate::S2::list_access_tokens) operation.
pub struct ListAccessTokensInput {
    /// Filter access tokens whose IDs begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: AccessTokenIdPrefix,
    /// Filter access tokens whose IDs are lexicographically greater than this value.
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
/// Input for [`list_all_access_tokens`](crate::S2::list_all_access_tokens) operation.
pub struct ListAllAccessTokensInput {
    /// Filter access tokens whose IDs begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: AccessTokenIdPrefix,
    /// Filter access tokens whose IDs are lexicographically greater than this value.
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Access token information.
pub struct AccessTokenInfo {
    /// Access token ID.
    pub id: AccessTokenId,
    /// Expiration time, or `None` if the token does not expire.
    pub expires_at: Option<Timestamp>,
    /// Whether to automatically prefix stream names during creation and strip the prefix during
    /// listing.
    pub auto_prefix_streams: bool,
    /// Scope of the access token.
    pub scope: AccessTokenScope,
    /// Network policy the token is restricted by, if any.
    pub network_policy: Option<NetworkPolicyRef>,
}

impl From<api::access::AccessTokenInfo> for AccessTokenInfo {
    fn from(value: api::access::AccessTokenInfo) -> Self {
        Self {
            id: value.id,
            expires_at: value.expires_at,
            auto_prefix_streams: value.auto_prefix_streams,
            scope: value.scope.into(),
            network_policy: value.network_policy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// A kind of pattern this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// A kind of pattern this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// A kind of pattern this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    /// List locations.
    ListLocations,
    /// Get the default location.
    GetDefaultLocation,
    /// Set the default location.
    SetDefaultLocation,
    /// List network policies.
    ListNetworkPolicies,
    /// Create a network policy.
    CreateNetworkPolicy,
    /// Get a network policy.
    GetNetworkPolicy,
    /// Delete a network policy.
    DeleteNetworkPolicy,
    /// An operation this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl From<Operation> for MaybeKnown<api::access::Operation> {
    fn from(value: Operation) -> Self {
        let known = match value {
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
            Operation::ListLocations => api::access::Operation::ListLocations,
            Operation::GetDefaultLocation => api::access::Operation::GetDefaultLocation,
            Operation::SetDefaultLocation => api::access::Operation::SetDefaultLocation,
            Operation::ListNetworkPolicies => api::access::Operation::ListNetworkPolicies,
            Operation::CreateNetworkPolicy => api::access::Operation::CreateNetworkPolicy,
            Operation::GetNetworkPolicy => api::access::Operation::GetNetworkPolicy,
            Operation::DeleteNetworkPolicy => api::access::Operation::DeleteNetworkPolicy,
            Operation::Unknown(name) => return Self::Unknown(name),
        };
        Self::Known(known)
    }
}

impl From<MaybeKnown<api::access::Operation>> for Operation {
    fn from(value: MaybeKnown<api::access::Operation>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
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
            api::access::Operation::ListLocations => Operation::ListLocations,
            api::access::Operation::GetDefaultLocation => Operation::GetDefaultLocation,
            api::access::Operation::SetDefaultLocation => Operation::SetDefaultLocation,
            api::access::Operation::ListNetworkPolicies => Operation::ListNetworkPolicies,
            api::access::Operation::CreateNetworkPolicy => Operation::CreateNetworkPolicy,
            api::access::Operation::GetNetworkPolicy => Operation::GetNetworkPolicy,
            api::access::Operation::DeleteNetworkPolicy => Operation::DeleteNetworkPolicy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Scope of an access token.
///
/// **Note:** The final set of permitted operations is the union of [`ops`](Self::ops)
/// and the operations permitted by [`op_group_perms`](Self::op_group_perms). Also, the
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

    /// Return the permitted basins matcher, if any.
    pub fn basins(&self) -> Option<&BasinMatcher> {
        self.basins.as_ref()
    }

    /// Return the permitted streams matcher, if any.
    pub fn streams(&self) -> Option<&StreamMatcher> {
        self.streams.as_ref()
    }

    /// Return the permitted access tokens matcher, if any.
    pub fn access_tokens(&self) -> Option<&AccessTokenMatcher> {
        self.access_tokens.as_ref()
    }

    /// Return the operation group permissions, if any.
    pub fn op_group_perms(&self) -> Option<&OperationGroupPermissions> {
        self.op_group_perms.as_ref()
    }

    /// Return the individually permitted operations.
    pub fn ops(&self) -> &HashSet<Operation> {
        &self.ops
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
        use api::access::{MaybeEmpty, ResourceSet};
        Self {
            basins: value.basins.map(|rs| match rs {
                MaybeKnown::Known(ResourceSet::Exact(MaybeEmpty::NonEmpty(e))) => {
                    BasinMatcher::Exact(e)
                }
                MaybeKnown::Known(ResourceSet::Exact(MaybeEmpty::Empty)) => BasinMatcher::None,
                MaybeKnown::Known(ResourceSet::Prefix(p)) => BasinMatcher::Prefix(p),
                MaybeKnown::Unknown(name) => BasinMatcher::Unknown(name),
            }),
            streams: value.streams.map(|rs| match rs {
                MaybeKnown::Known(ResourceSet::Exact(MaybeEmpty::NonEmpty(e))) => {
                    StreamMatcher::Exact(e)
                }
                MaybeKnown::Known(ResourceSet::Exact(MaybeEmpty::Empty)) => StreamMatcher::None,
                MaybeKnown::Known(ResourceSet::Prefix(p)) => StreamMatcher::Prefix(p),
                MaybeKnown::Unknown(name) => StreamMatcher::Unknown(name),
            }),
            access_tokens: value.access_tokens.map(|rs| match rs {
                MaybeKnown::Known(ResourceSet::Exact(MaybeEmpty::NonEmpty(e))) => {
                    AccessTokenMatcher::Exact(e)
                }
                MaybeKnown::Known(ResourceSet::Exact(MaybeEmpty::Empty)) => {
                    AccessTokenMatcher::None
                }
                MaybeKnown::Known(ResourceSet::Prefix(p)) => AccessTokenMatcher::Prefix(p),
                MaybeKnown::Unknown(name) => AccessTokenMatcher::Unknown(name),
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
        use api::access::{MaybeEmpty, ResourceSet};
        Self {
            basins: value.basins.map(|rs| match rs {
                BasinMatcher::None => ResourceSet::Exact(MaybeEmpty::Empty).into(),
                BasinMatcher::Exact(e) => ResourceSet::Exact(MaybeEmpty::NonEmpty(e)).into(),
                BasinMatcher::Prefix(p) => ResourceSet::Prefix(p).into(),
                BasinMatcher::Unknown(name) => MaybeKnown::Unknown(name),
            }),
            streams: value.streams.map(|rs| match rs {
                StreamMatcher::None => ResourceSet::Exact(MaybeEmpty::Empty).into(),
                StreamMatcher::Exact(e) => ResourceSet::Exact(MaybeEmpty::NonEmpty(e)).into(),
                StreamMatcher::Prefix(p) => ResourceSet::Prefix(p).into(),
                StreamMatcher::Unknown(name) => MaybeKnown::Unknown(name),
            }),
            access_tokens: value.access_tokens.map(|rs| match rs {
                AccessTokenMatcher::None => ResourceSet::Exact(MaybeEmpty::Empty).into(),
                AccessTokenMatcher::Exact(e) => ResourceSet::Exact(MaybeEmpty::NonEmpty(e)).into(),
                AccessTokenMatcher::Prefix(p) => ResourceSet::Prefix(p).into(),
                AccessTokenMatcher::Unknown(name) => MaybeKnown::Unknown(name),
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// Input for [`issue_access_token`](crate::S2::issue_access_token).
pub struct IssueAccessTokenInput {
    id: AccessTokenId,
    expires_at: Option<Timestamp>,
    auto_prefix_streams: bool,
    scope: AccessTokenScopeInput,
    network_policy: Option<NetworkPolicySelector>,
}

impl IssueAccessTokenInput {
    /// Create a new [`IssueAccessTokenInput`] with the given id and scope.
    pub fn new(id: AccessTokenId, scope: AccessTokenScopeInput) -> Self {
        Self {
            id,
            expires_at: None,
            auto_prefix_streams: false,
            scope,
            network_policy: None,
        }
    }

    /// Return the access token ID.
    pub fn id(&self) -> &AccessTokenId {
        &self.id
    }

    /// Return the expiration time, if set.
    pub fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Return whether stream names are automatically prefixed during creation and stripped during
    /// listing.
    pub fn auto_prefix_streams(&self) -> bool {
        self.auto_prefix_streams
    }

    /// Return the scope of the token.
    pub fn scope(&self) -> &AccessTokenScopeInput {
        &self.scope
    }

    /// Return the network policy restricting this token, if any.
    pub fn network_policy(&self) -> Option<&NetworkPolicySelector> {
        self.network_policy.as_ref()
    }

    /// Set the network policy to restrict the token by.
    ///
    /// A slug binds the token to the policy that currently holds it. If the requestor's token is
    /// itself restricted, this must be omitted or name the same policy, which the new token
    /// inherits.
    pub fn with_network_policy(self, network_policy: impl Into<NetworkPolicySelector>) -> Self {
        Self {
            network_policy: Some(network_policy.into()),
            ..self
        }
    }

    /// Set the expiration time.
    ///
    /// Defaults to the expiration time of the requestor's access token passed via
    /// [`S2Config::new`](crate::types::S2Config::new).
    ///
    /// Accepts timestamps from `0000-01-01T00:00:00Z` through [`Timestamp::MAX`]
    /// (`9999-12-30T22:00:00.999999999Z`).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `expires_at` precedes year `0000` (outside the RFC 3339
    /// year range).
    pub fn with_expires_at(self, expires_at: Timestamp) -> Result<Self, ValidationError> {
        let expires_at = validate_rfc3339_timestamp(expires_at)?;
        Ok(Self {
            expires_at: Some(expires_at),
            ..self
        })
    }

    /// Set whether to automatically prefix stream names during creation and strip the prefix during
    /// listing.
    ///
    /// **Note:** [`scope.streams`](AccessTokenScopeInput::with_streams) must be set with a prefix.
    pub fn with_auto_prefix_streams(self, auto_prefix_streams: bool) -> Self {
        Self {
            auto_prefix_streams,
            ..self
        }
    }
}

impl From<IssueAccessTokenInput> for api::access::IssueAccessTokenRequest {
    fn from(value: IssueAccessTokenInput) -> Self {
        Self {
            id: value.id,
            expires_at: value.expires_at,
            auto_prefix_streams: value.auto_prefix_streams.then_some(true),
            scope: value.scope.into(),
            network_policy: value.network_policy,
        }
    }
}
