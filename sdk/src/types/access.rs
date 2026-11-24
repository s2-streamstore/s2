use std::{collections::HashSet, fmt};

use jiff::Timestamp;
use s2_api::v1::{self as api, MaybeKnown};
use s2_common::{
    access::{AccessTokenId, AccessTokenIdPrefix, AccessTokenIdStartAfter},
    basin::{BasinName, BasinNamePrefix},
    network_policy::{NetworkPolicyRef, NetworkPolicySelector},
    stream::{StreamName, StreamNamePrefix},
};

use super::{Page, validate_rfc3339_timestamp};
use crate::error::ValidationError;

/// Input for [`list_access_tokens`](crate::S2::list_access_tokens) operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct ListAccessTokensInput {
    prefix: AccessTokenIdPrefix,
    start_after: AccessTokenIdStartAfter,
    limit: Option<usize>,
}

impl ListAccessTokensInput {
    /// Create a new [`ListAccessTokensInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the prefix filter.
    #[must_use]
    pub fn prefix(&self) -> &AccessTokenIdPrefix {
        &self.prefix
    }

    /// Return the pagination cursor (`start_after`).
    #[must_use]
    pub fn start_after(&self) -> &AccessTokenIdStartAfter {
        &self.start_after
    }

    /// Return the page size limit, if set.
    #[must_use]
    pub fn limit(&self) -> Option<usize> {
        self.limit
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

    /// Set the limit on number of access tokens to return in a page (default and maximum: 1000).
    pub fn with_limit(self, limit: usize) -> Self {
        Self {
            limit: Some(limit),
            ..self
        }
    }

    pub(crate) fn set_start_after(&mut self, start_after: AccessTokenIdStartAfter) {
        self.start_after = start_after;
    }

    pub(crate) fn into_api(self) -> api::access::ListAccessTokensRequest {
        api::access::ListAccessTokensRequest {
            prefix: (!self.prefix.is_empty()).then_some(self.prefix),
            start_after: (!self.start_after.is_empty()).then_some(self.start_after),
            limit: self.limit,
        }
    }
}

/// Input for [`list_all_access_tokens`](crate::S2::list_all_access_tokens) operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct ListAllAccessTokensInput {
    prefix: AccessTokenIdPrefix,
    start_after: AccessTokenIdStartAfter,
}

impl ListAllAccessTokensInput {
    /// Create a new [`ListAllAccessTokensInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the prefix filter.
    #[must_use]
    pub fn prefix(&self) -> &AccessTokenIdPrefix {
        &self.prefix
    }

    /// Return the pagination cursor (`start_after`).
    #[must_use]
    pub fn start_after(&self) -> &AccessTokenIdStartAfter {
        &self.start_after
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

    pub(crate) fn into_list_input(self) -> ListAccessTokensInput {
        ListAccessTokensInput::new()
            .with_prefix(self.prefix)
            .with_start_after(self.start_after)
    }
}

/// Access token information.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

impl Page<AccessTokenInfo> {
    /// Return the `start_after` cursor for fetching the next page, if more pages remain.
    ///
    /// Returns `None` when [`has_more`](Self::has_more) is `false` or [`values`](Self::values) is
    /// empty.
    #[must_use]
    pub fn next_start_after(&self) -> Option<AccessTokenIdStartAfter> {
        self.has_more
            .then(|| self.values.last().map(|info| info.id.clone().into()))
            .flatten()
    }
}

impl AccessTokenInfo {
    /// Construct an [`AccessTokenInfo`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(id: AccessTokenId, scope: AccessTokenScope) -> Self {
        Self {
            id,
            expires_at: None,
            auto_prefix_streams: false,
            scope,
            network_policy: None,
        }
    }

    /// Set the expiration timestamp.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set whether stream names are auto-prefixed.
    #[must_use]
    pub fn with_auto_prefix_streams(mut self, auto_prefix_streams: bool) -> Self {
        self.auto_prefix_streams = auto_prefix_streams;
        self
    }

    /// Set the bound network policy reference.
    #[must_use]
    pub fn with_network_policy(mut self, network_policy: NetworkPolicyRef) -> Self {
        self.network_policy = Some(network_policy);
        self
    }

    pub(crate) fn from_api(value: api::access::AccessTokenInfo) -> Self {
        Self {
            id: value.id,
            expires_at: value.expires_at,
            auto_prefix_streams: value.auto_prefix_streams,
            scope: AccessTokenScope::from_api(value.scope),
            network_policy: value.network_policy,
        }
    }
}

/// Pattern for matching basins.
///
/// See [`AccessTokenScope::basins`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BasinMatcher {
    /// Match no basins.
    #[default]
    None,
    /// Match exactly this basin.
    Exact(BasinName),
    /// Match all basins with this prefix.
    Prefix(BasinNamePrefix),
    /// A kind of pattern this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl BasinMatcher {
    /// Match all basins (equivalent to an empty prefix).
    #[must_use]
    pub fn all() -> Self {
        Self::Prefix(BasinNamePrefix::default())
    }
}

/// Pattern for matching streams.
///
/// See [`AccessTokenScope::streams`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StreamMatcher {
    /// Match no streams.
    #[default]
    None,
    /// Match exactly this stream.
    Exact(StreamName),
    /// Match all streams with this prefix.
    Prefix(StreamNamePrefix),
    /// A kind of pattern this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl StreamMatcher {
    /// Match all streams (equivalent to an empty prefix).
    #[must_use]
    pub fn all() -> Self {
        Self::Prefix(StreamNamePrefix::default())
    }
}

/// Pattern for matching access tokens.
///
/// See [`AccessTokenScope::access_tokens`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessTokenMatcher {
    /// Match no access tokens.
    #[default]
    None,
    /// Match exactly this access token.
    Exact(AccessTokenId),
    /// Match all access tokens with this prefix.
    Prefix(AccessTokenIdPrefix),
    /// A kind of pattern this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl AccessTokenMatcher {
    /// Match all access tokens (equivalent to an empty prefix).
    #[must_use]
    pub fn all() -> Self {
        Self::Prefix(AccessTokenIdPrefix::default())
    }
}

/// Permissions indicating allowed operations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct ReadWritePermissions {
    read: bool,
    write: bool,
}

impl ReadWritePermissions {
    /// Create a new [`ReadWritePermissions`] with default values (`read = false`, `write = false`).
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

    /// Return whether read permission is granted.
    #[must_use]
    pub fn read(&self) -> bool {
        self.read
    }

    /// Return whether write permission is granted.
    #[must_use]
    pub fn write(&self) -> bool {
        self.write
    }

    /// Set read permission.
    pub fn with_read(self, read: bool) -> Self {
        Self { read, ..self }
    }

    /// Set write permission.
    pub fn with_write(self, write: bool) -> Self {
        Self { write, ..self }
    }

    pub(crate) fn from_api(value: api::access::ReadWritePermissions) -> Self {
        Self {
            read: value.read.unwrap_or_default(),
            write: value.write.unwrap_or_default(),
        }
    }

    pub(crate) fn into_api(self) -> api::access::ReadWritePermissions {
        api::access::ReadWritePermissions {
            read: Some(self.read),
            write: Some(self.write),
        }
    }
}

/// Permissions at the operation group level.
///
/// See [`AccessTokenScope::op_group_perms`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct OperationGroupPermissions {
    account: Option<ReadWritePermissions>,
    basin: Option<ReadWritePermissions>,
    stream: Option<ReadWritePermissions>,
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

    /// Return account-level access permissions, if set.
    #[must_use]
    pub fn account(&self) -> Option<ReadWritePermissions> {
        self.account
    }

    /// Return basin-level access permissions, if set.
    #[must_use]
    pub fn basin(&self) -> Option<ReadWritePermissions> {
        self.basin
    }

    /// Return stream-level access permissions, if set.
    #[must_use]
    pub fn stream(&self) -> Option<ReadWritePermissions> {
        self.stream
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

    pub(crate) fn from_api(value: api::access::PermittedOperationGroups) -> Self {
        Self {
            account: value.account.map(ReadWritePermissions::from_api),
            basin: value.basin.map(ReadWritePermissions::from_api),
            stream: value.stream.map(ReadWritePermissions::from_api),
        }
    }

    pub(crate) fn into_api(self) -> api::access::PermittedOperationGroups {
        api::access::PermittedOperationGroups {
            account: self.account.map(ReadWritePermissions::into_api),
            basin: self.basin.map(ReadWritePermissions::into_api),
            stream: self.stream.map(ReadWritePermissions::into_api),
        }
    }
}

/// Individual operation that can be permitted.
///
/// See [`AccessTokenScope::ops`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
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

macro_rules! map_operations {
    ($($sdk:ident => ($api:ident, $wire:literal)),* $(,)?) => {
        impl Operation {
            /// Return the kebab-case wire name of this operation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$sdk => $wire,)*
                    Self::Unknown(name) => name,
                }
            }

            pub(crate) fn from_api(value: MaybeKnown<api::access::Operation>) -> Self {
                match value {
                    MaybeKnown::Known(op) => match op {
                        $(api::access::Operation::$api => Self::$sdk,)*
                    },
                    MaybeKnown::Unknown(name) => Self::Unknown(name),
                }
            }

            pub(crate) fn into_api(self) -> MaybeKnown<api::access::Operation> {
                match self {
                    $(Self::$sdk => MaybeKnown::Known(api::access::Operation::$api),)*
                    Self::Unknown(name) => MaybeKnown::Unknown(name),
                }
            }
        }
    };
}

map_operations! {
    ListBasins => (ListBasins, "list-basins"),
    CreateBasin => (CreateBasin, "create-basin"),
    DeleteBasin => (DeleteBasin, "delete-basin"),
    ReconfigureBasin => (ReconfigureBasin, "reconfigure-basin"),
    GetBasinConfig => (GetBasinConfig, "get-basin-config"),
    IssueAccessToken => (IssueAccessToken, "issue-access-token"),
    RevokeAccessToken => (RevokeAccessToken, "revoke-access-token"),
    ListAccessTokens => (ListAccessTokens, "list-access-tokens"),
    ListStreams => (ListStreams, "list-streams"),
    CreateStream => (CreateStream, "create-stream"),
    DeleteStream => (DeleteStream, "delete-stream"),
    GetStreamConfig => (GetStreamConfig, "get-stream-config"),
    ReconfigureStream => (ReconfigureStream, "reconfigure-stream"),
    CheckTail => (CheckTail, "check-tail"),
    Append => (Append, "append"),
    Read => (Read, "read"),
    Trim => (Trim, "trim"),
    Fence => (Fence, "fence"),
    GetAccountMetrics => (AccountMetrics, "account-metrics"),
    GetBasinMetrics => (BasinMetrics, "basin-metrics"),
    GetStreamMetrics => (StreamMetrics, "stream-metrics"),
    ListLocations => (ListLocations, "list-locations"),
    GetDefaultLocation => (GetDefaultLocation, "get-default-location"),
    SetDefaultLocation => (SetDefaultLocation, "set-default-location"),
    ListNetworkPolicies => (ListNetworkPolicies, "list-network-policies"),
    CreateNetworkPolicy => (CreateNetworkPolicy, "create-network-policy"),
    GetNetworkPolicy => (GetNetworkPolicy, "get-network-policy"),
    DeleteNetworkPolicy => (DeleteNetworkPolicy, "delete-network-policy"),
}

impl AsRef<str> for Operation {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

macro_rules! impl_resource_matcher_conversions {
    ($($matcher:ident($exact:ty, $prefix:ty)),* $(,)?) => {
        $(
            impl $matcher {
                pub(crate) fn from_api(
                    value: MaybeKnown<
                        api::access::ResourceSet<api::access::MaybeEmpty<$exact>, $prefix>,
                    >,
                ) -> Self {
                    use api::access::{MaybeEmpty, ResourceSet};
                    match value {
                        MaybeKnown::Known(ResourceSet::Exact(MaybeEmpty::NonEmpty(e))) => {
                            Self::Exact(e)
                        }
                        MaybeKnown::Known(ResourceSet::Exact(MaybeEmpty::Empty)) => Self::None,
                        MaybeKnown::Known(ResourceSet::Prefix(p)) => Self::Prefix(p),
                        MaybeKnown::Unknown(name) => Self::Unknown(name),
                    }
                }

                pub(crate) fn into_api(
                    self,
                ) -> MaybeKnown<api::access::ResourceSet<api::access::MaybeEmpty<$exact>, $prefix>>
                {
                    use api::access::{MaybeEmpty, ResourceSet};
                    match self {
                        Self::None => ResourceSet::Exact(MaybeEmpty::Empty).into(),
                        Self::Exact(e) => ResourceSet::Exact(MaybeEmpty::NonEmpty(e)).into(),
                        Self::Prefix(p) => ResourceSet::Prefix(p).into(),
                        Self::Unknown(name) => MaybeKnown::Unknown(name),
                    }
                }
            }
        )*
    };
}

impl_resource_matcher_conversions! {
    BasinMatcher(BasinName, BasinNamePrefix),
    StreamMatcher(StreamName, StreamNamePrefix),
    AccessTokenMatcher(AccessTokenId, AccessTokenIdPrefix),
}

/// Scope of an access token.
///
/// **Note:** When issuing a token, the final set of permitted operations is the union of
/// [`ops`](Self::ops) and the operations permitted by [`op_group_perms`](Self::op_group_perms),
/// and must not be empty.
///
/// See [`IssueAccessTokenInput::scope`] and [`AccessTokenInfo::scope`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[must_use]
pub struct AccessTokenScope {
    basins: BasinMatcher,
    streams: StreamMatcher,
    access_tokens: AccessTokenMatcher,
    op_group_perms: Option<OperationGroupPermissions>,
    ops: HashSet<Operation>,
}

impl AccessTokenScope {
    /// Create a new empty [`AccessTokenScope`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new [`AccessTokenScope`] with the given permitted operations.
    pub fn from_ops(ops: impl IntoIterator<Item = Operation>) -> Self {
        Self::new().with_ops(ops)
    }

    /// Create a new [`AccessTokenScope`] with the given operation group permissions.
    pub fn from_op_group_perms(op_group_perms: OperationGroupPermissions) -> Self {
        Self::new().with_op_group_perms(op_group_perms)
    }

    /// Return the permitted basins matcher (defaults to [`BasinMatcher::None`]).
    #[must_use]
    pub fn basins(&self) -> &BasinMatcher {
        &self.basins
    }

    /// Return the permitted streams matcher (defaults to [`StreamMatcher::None`]).
    #[must_use]
    pub fn streams(&self) -> &StreamMatcher {
        &self.streams
    }

    /// Return the permitted access tokens matcher (defaults to [`AccessTokenMatcher::None`]).
    #[must_use]
    pub fn access_tokens(&self) -> &AccessTokenMatcher {
        &self.access_tokens
    }

    /// Return the operation group permissions, if any.
    #[must_use]
    pub fn op_group_perms(&self) -> Option<OperationGroupPermissions> {
        self.op_group_perms
    }

    /// Return the individually permitted operations.
    #[must_use]
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
    /// Defaults to [`BasinMatcher::None`].
    pub fn with_basins(self, basins: BasinMatcher) -> Self {
        Self { basins, ..self }
    }

    /// Set the permitted streams.
    ///
    /// Defaults to [`StreamMatcher::None`].
    pub fn with_streams(self, streams: StreamMatcher) -> Self {
        Self { streams, ..self }
    }

    /// Set the permitted access tokens.
    ///
    /// Defaults to [`AccessTokenMatcher::None`].
    pub fn with_access_tokens(self, access_tokens: AccessTokenMatcher) -> Self {
        Self {
            access_tokens,
            ..self
        }
    }

    pub(crate) fn from_api(value: api::access::AccessTokenScope) -> Self {
        Self {
            basins: value.basins.map(BasinMatcher::from_api).unwrap_or_default(),
            streams: value
                .streams
                .map(StreamMatcher::from_api)
                .unwrap_or_default(),
            access_tokens: value
                .access_tokens
                .map(AccessTokenMatcher::from_api)
                .unwrap_or_default(),
            op_group_perms: value.op_groups.map(OperationGroupPermissions::from_api),
            ops: value
                .ops
                .map(|ops| ops.into_iter().map(Operation::from_api).collect())
                .unwrap_or_default(),
        }
    }

    pub(crate) fn into_api(self) -> api::access::AccessTokenScope {
        api::access::AccessTokenScope {
            basins: (!matches!(self.basins, BasinMatcher::None)).then(|| self.basins.into_api()),
            streams: (!matches!(self.streams, StreamMatcher::None))
                .then(|| self.streams.into_api()),
            access_tokens: (!matches!(self.access_tokens, AccessTokenMatcher::None))
                .then(|| self.access_tokens.into_api()),
            op_groups: self.op_group_perms.map(OperationGroupPermissions::into_api),
            ops: if self.ops.is_empty() {
                None
            } else {
                Some(self.ops.into_iter().map(Operation::into_api).collect())
            },
        }
    }
}

/// Input for [`issue_access_token`](crate::S2::issue_access_token).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct IssueAccessTokenInput {
    id: AccessTokenId,
    expires_at: Option<Timestamp>,
    auto_prefix_streams: bool,
    scope: AccessTokenScope,
    network_policy: Option<NetworkPolicySelector>,
}

impl IssueAccessTokenInput {
    /// Create a new [`IssueAccessTokenInput`] with the given id and scope.
    pub fn new(id: AccessTokenId, scope: AccessTokenScope) -> Self {
        Self {
            id,
            expires_at: None,
            auto_prefix_streams: false,
            scope,
            network_policy: None,
        }
    }

    /// Return the access token ID.
    #[must_use]
    pub fn id(&self) -> &AccessTokenId {
        &self.id
    }

    /// Return the expiration time, if set.
    #[must_use]
    pub fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Return whether stream names are automatically prefixed during creation and stripped during
    /// listing.
    #[must_use]
    pub fn auto_prefix_streams(&self) -> bool {
        self.auto_prefix_streams
    }

    /// Return the scope of the token.
    #[must_use]
    pub fn scope(&self) -> &AccessTokenScope {
        &self.scope
    }

    /// Return the network policy restricting this token, if any.
    #[must_use]
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
    /// [`S2Config::new`](crate::S2Config::new).
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
    /// **Note:** [`scope.streams`](AccessTokenScope::with_streams) must be set with a prefix.
    pub fn with_auto_prefix_streams(self, auto_prefix_streams: bool) -> Self {
        Self {
            auto_prefix_streams,
            ..self
        }
    }

    pub(crate) fn into_api(self) -> api::access::IssueAccessTokenRequest {
        api::access::IssueAccessTokenRequest {
            id: self.id,
            expires_at: self.expires_at,
            auto_prefix_streams: self.auto_prefix_streams.then_some(true),
            scope: self.scope.into_api(),
            network_policy: self.network_policy,
        }
    }
}
