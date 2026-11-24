use jiff::Timestamp;
use s2_api::v1::{self as api, MaybeKnown};
use s2_common::network_policy::{
    Cidr, NetworkPolicyRef, NetworkPolicySlug, NetworkPolicySlugPrefix,
    NetworkPolicySlugStartAfter, VpcEndpointId,
};

use super::Page;

/// Input for [`list_network_policies`](crate::S2::list_network_policies) operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct ListNetworkPoliciesInput {
    prefix: NetworkPolicySlugPrefix,
    start_after: NetworkPolicySlugStartAfter,
    limit: Option<usize>,
}

impl ListNetworkPoliciesInput {
    /// Create a new [`ListNetworkPoliciesInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the prefix filter.
    #[must_use]
    pub fn prefix(&self) -> &NetworkPolicySlugPrefix {
        &self.prefix
    }

    /// Return the pagination cursor (`start_after`).
    #[must_use]
    pub fn start_after(&self) -> &NetworkPolicySlugStartAfter {
        &self.start_after
    }

    /// Return the page size limit, if set.
    #[must_use]
    pub fn limit(&self) -> Option<usize> {
        self.limit
    }

    /// Set the prefix used to filter network policies whose slugs begin with this value.
    pub fn with_prefix(self, prefix: NetworkPolicySlugPrefix) -> Self {
        Self { prefix, ..self }
    }

    /// Set the value used to filter network policies whose slugs are lexicographically greater
    /// than this value.
    pub fn with_start_after(self, start_after: NetworkPolicySlugStartAfter) -> Self {
        Self {
            start_after,
            ..self
        }
    }

    /// Set the limit on number of network policies to return in a page (default and maximum: 1000).
    pub fn with_limit(self, limit: usize) -> Self {
        Self {
            limit: Some(limit),
            ..self
        }
    }

    pub(crate) fn set_start_after(&mut self, start_after: NetworkPolicySlugStartAfter) {
        self.start_after = start_after;
    }

    pub(crate) fn into_api(self) -> api::network_policy::ListNetworkPoliciesRequest {
        api::network_policy::ListNetworkPoliciesRequest {
            prefix: (!self.prefix.is_empty()).then_some(self.prefix),
            start_after: (!self.start_after.is_empty()).then_some(self.start_after),
            limit: self.limit,
        }
    }
}

/// Input for [`list_all_network_policies`](crate::S2::list_all_network_policies) operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct ListAllNetworkPoliciesInput {
    prefix: NetworkPolicySlugPrefix,
    start_after: NetworkPolicySlugStartAfter,
}

impl ListAllNetworkPoliciesInput {
    /// Create a new [`ListAllNetworkPoliciesInput`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the prefix filter.
    #[must_use]
    pub fn prefix(&self) -> &NetworkPolicySlugPrefix {
        &self.prefix
    }

    /// Return the pagination cursor (`start_after`).
    #[must_use]
    pub fn start_after(&self) -> &NetworkPolicySlugStartAfter {
        &self.start_after
    }

    /// Set the prefix used to filter network policies whose slugs begin with this value.
    pub fn with_prefix(self, prefix: NetworkPolicySlugPrefix) -> Self {
        Self { prefix, ..self }
    }

    /// Set the value used to filter network policies whose slugs are lexicographically greater
    /// than this value.
    pub fn with_start_after(self, start_after: NetworkPolicySlugStartAfter) -> Self {
        Self {
            start_after,
            ..self
        }
    }

    pub(crate) fn into_list_input(self) -> ListNetworkPoliciesInput {
        ListNetworkPoliciesInput::new()
            .with_prefix(self.prefix)
            .with_start_after(self.start_after)
    }
}

/// Input for [`create_network_policy`](crate::S2::create_network_policy) operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct CreateNetworkPolicyInput {
    slug: NetworkPolicySlug,
    policy: NetworkPolicy,
}

impl CreateNetworkPolicyInput {
    /// Create a new [`CreateNetworkPolicyInput`] with the given slug and policy.
    pub fn new(slug: NetworkPolicySlug, policy: NetworkPolicy) -> Self {
        Self { slug, policy }
    }

    /// Return the network policy slug.
    #[must_use]
    pub fn slug(&self) -> &NetworkPolicySlug {
        &self.slug
    }

    /// Return the network policy rules.
    #[must_use]
    pub fn policy(&self) -> &NetworkPolicy {
        &self.policy
    }

    pub(crate) fn into_api(self) -> api::network_policy::CreateNetworkPolicyRequest {
        api::network_policy::CreateNetworkPolicyRequest {
            slug: self.slug,
            policy: self.policy.into_api(),
        }
    }
}

/// What a token may be used from over the public path. Exactly one kind applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PublicNetPolicy {
    /// Source addresses, between 1 and 32.
    Cidrs(Vec<Cidr>),
    /// A policy this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl PublicNetPolicy {
    /// Construct a [`PublicNetPolicy::Cidrs`] from an iterator of CIDRs (between 1 and 32).
    #[must_use]
    pub fn cidrs(cidrs: impl IntoIterator<Item = Cidr>) -> Self {
        Self::Cidrs(cidrs.into_iter().collect())
    }

    pub(crate) fn from_api(value: MaybeKnown<api::network_policy::PublicNetPolicy>) -> Self {
        match value {
            MaybeKnown::Known(api::network_policy::PublicNetPolicy::Cidrs(cidrs)) => {
                Self::Cidrs(cidrs)
            }
            MaybeKnown::Unknown(name) => Self::Unknown(name),
        }
    }

    pub(crate) fn into_api(self) -> MaybeKnown<api::network_policy::PublicNetPolicy> {
        match self {
            Self::Cidrs(cidrs) => {
                MaybeKnown::Known(api::network_policy::PublicNetPolicy::Cidrs(cidrs))
            }
            Self::Unknown(name) => MaybeKnown::Unknown(name),
        }
    }
}

/// AWS VPC endpoints a token may be used through.
///
/// See [`PrivateNetPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct AwsPrivateNetPolicy {
    vpce_ids: Vec<VpcEndpointId>,
}

impl AwsPrivateNetPolicy {
    /// Create a new [`AwsPrivateNetPolicy`] with the given VPC endpoint IDs (between 1 and 32).
    pub fn new(vpce_ids: impl IntoIterator<Item = VpcEndpointId>) -> Self {
        Self {
            vpce_ids: vpce_ids.into_iter().collect(),
        }
    }

    /// Return the permitted VPC endpoint IDs.
    #[must_use]
    pub fn vpce_ids(&self) -> &[VpcEndpointId] {
        &self.vpce_ids
    }
}

/// Private networks a token may be used through. Exactly one kind applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrivateNetPolicy {
    /// AWS PrivateLink.
    Aws(AwsPrivateNetPolicy),
    /// A policy this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl From<AwsPrivateNetPolicy> for PrivateNetPolicy {
    fn from(aws: AwsPrivateNetPolicy) -> Self {
        Self::Aws(aws)
    }
}

impl PrivateNetPolicy {
    pub(crate) fn from_api(value: MaybeKnown<api::network_policy::PrivateNetPolicy>) -> Self {
        match value {
            MaybeKnown::Known(api::network_policy::PrivateNetPolicy::Aws(aws)) => {
                Self::Aws(AwsPrivateNetPolicy {
                    vpce_ids: aws.vpce_ids,
                })
            }
            MaybeKnown::Unknown(name) => Self::Unknown(name),
        }
    }

    pub(crate) fn into_api(self) -> MaybeKnown<api::network_policy::PrivateNetPolicy> {
        match self {
            Self::Aws(aws) => MaybeKnown::Known(api::network_policy::PrivateNetPolicy::Aws(
                api::network_policy::AwsPrivateNetPolicy {
                    vpce_ids: aws.vpce_ids,
                },
            )),
            Self::Unknown(name) => MaybeKnown::Unknown(name),
        }
    }
}

/// Restriction a network policy applies to the tokens bound to it: a [`PublicNetPolicy`] for the
/// public path, a [`PrivateNetPolicy`] for private networks, or both. A path without one is
/// closed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct NetworkPolicy {
    public_net: Option<PublicNetPolicy>,
    private_net: Option<PrivateNetPolicy>,
}

impl NetworkPolicy {
    /// Create a new [`NetworkPolicy`] with both paths closed. At least one must be set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the public network policy, if set.
    #[must_use]
    pub fn public_net(&self) -> Option<&PublicNetPolicy> {
        self.public_net.as_ref()
    }

    /// Return the private network policy, if set.
    #[must_use]
    pub fn private_net(&self) -> Option<&PrivateNetPolicy> {
        self.private_net.as_ref()
    }

    /// Set what the tokens may be used from over the public path.
    pub fn with_public_net(self, public_net: PublicNetPolicy) -> Self {
        Self {
            public_net: Some(public_net),
            ..self
        }
    }

    /// Set the private networks the tokens may be used through.
    pub fn with_private_net(self, private_net: impl Into<PrivateNetPolicy>) -> Self {
        Self {
            private_net: Some(private_net.into()),
            ..self
        }
    }

    pub(crate) fn from_api(value: api::network_policy::NetworkPolicy) -> Self {
        Self {
            public_net: value.public_net.map(PublicNetPolicy::from_api),
            private_net: value.private_net.map(PrivateNetPolicy::from_api),
        }
    }

    pub(crate) fn into_api(self) -> api::network_policy::NetworkPolicy {
        api::network_policy::NetworkPolicy {
            public_net: self.public_net.map(PublicNetPolicy::into_api),
            private_net: self.private_net.map(PrivateNetPolicy::into_api),
        }
    }
}

/// Network policy information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NetworkPolicyInfo {
    /// Full reference, `<slug>.<nonce>`, which access tokens are bound to.
    pub id: NetworkPolicyRef,
    /// Creation time.
    pub created_at: Timestamp,
    /// The restriction.
    pub policy: NetworkPolicy,
}

impl Page<NetworkPolicyInfo> {
    /// Return the `start_after` cursor for fetching the next page, if more pages remain.
    ///
    /// Returns `None` when [`has_more`](Self::has_more) is `false` or [`values`](Self::values) is
    /// empty.
    #[must_use]
    pub fn next_start_after(&self) -> Option<NetworkPolicySlugStartAfter> {
        self.has_more
            .then(|| self.values.last().map(|info| info.id.slug().clone().into()))
            .flatten()
    }
}

impl NetworkPolicyInfo {
    /// Construct a [`NetworkPolicyInfo`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(id: NetworkPolicyRef, created_at: Timestamp, policy: NetworkPolicy) -> Self {
        Self {
            id,
            created_at,
            policy,
        }
    }

    pub(crate) fn from_api(value: api::network_policy::NetworkPolicyInfo) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            policy: NetworkPolicy::from_api(value.policy),
        }
    }
}
