use jiff::Timestamp;
use s2_api::v1::{self as api, MaybeKnown};
use s2_common::network_policy::{
    Cidr, NetworkPolicyRef, NetworkPolicySlugPrefix, NetworkPolicySlugStartAfter, VpcEndpointId,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Input for [`list_network_policies`](crate::S2::list_network_policies) operation.
pub struct ListNetworkPoliciesInput {
    /// Filter network policies whose slugs begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: NetworkPolicySlugPrefix,
    /// Filter network policies whose slugs are lexicographically greater than this value.
    ///
    /// Defaults to `""`.
    pub start_after: NetworkPolicySlugStartAfter,
    /// Number of network policies to return in a page. Will be clamped to a maximum of `1000`.
    ///
    /// Defaults to `1000`.
    pub limit: Option<usize>,
}

impl ListNetworkPoliciesInput {
    /// Create a new [`ListNetworkPoliciesInput`] with default values.
    pub fn new() -> Self {
        Self::default()
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

    /// Set the limit on number of network policies to return in a page.
    pub fn with_limit(self, limit: usize) -> Self {
        Self {
            limit: Some(limit),
            ..self
        }
    }
}

impl From<ListNetworkPoliciesInput> for api::network_policy::ListNetworkPoliciesRequest {
    fn from(value: ListNetworkPoliciesInput) -> Self {
        Self {
            prefix: Some(value.prefix),
            start_after: Some(value.start_after),
            limit: value.limit,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Input for [`list_all_network_policies`](crate::S2::list_all_network_policies) operation.
pub struct ListAllNetworkPoliciesInput {
    /// Filter network policies whose slugs begin with this value.
    ///
    /// Defaults to `""`.
    pub prefix: NetworkPolicySlugPrefix,
    /// Filter network policies whose slugs are lexicographically greater than this value.
    ///
    /// Defaults to `""`.
    pub start_after: NetworkPolicySlugStartAfter,
}

impl ListAllNetworkPoliciesInput {
    /// Create a new [`ListAllNetworkPoliciesInput`] with default values.
    pub fn new() -> Self {
        Self::default()
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// What a token may be used from over the public path. Exactly one kind applies.
pub enum PublicNetPolicy {
    /// Source addresses, between 1 and 32.
    Cidrs(Vec<Cidr>),
    /// A policy this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl From<MaybeKnown<api::network_policy::PublicNetPolicy>> for PublicNetPolicy {
    fn from(value: MaybeKnown<api::network_policy::PublicNetPolicy>) -> Self {
        match value {
            MaybeKnown::Known(api::network_policy::PublicNetPolicy::Cidrs(cidrs)) => {
                Self::Cidrs(cidrs)
            }
            MaybeKnown::Unknown(name) => Self::Unknown(name),
        }
    }
}

impl From<PublicNetPolicy> for MaybeKnown<api::network_policy::PublicNetPolicy> {
    fn from(value: PublicNetPolicy) -> Self {
        match value {
            PublicNetPolicy::Cidrs(cidrs) => {
                Self::Known(api::network_policy::PublicNetPolicy::Cidrs(cidrs))
            }
            PublicNetPolicy::Unknown(name) => Self::Unknown(name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// AWS VPC endpoints a token may be used through.
///
/// See [`PrivateNetPolicy`].
pub struct AwsPrivateNetPolicy {
    /// VPC endpoint IDs, between 1 and 32.
    pub vpce_ids: Vec<VpcEndpointId>,
}

impl AwsPrivateNetPolicy {
    /// Create a new [`AwsPrivateNetPolicy`] with the given VPC endpoint IDs.
    pub fn new(vpce_ids: impl IntoIterator<Item = VpcEndpointId>) -> Self {
        Self {
            vpce_ids: vpce_ids.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Private networks a token may be used through. Exactly one kind applies.
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

impl From<MaybeKnown<api::network_policy::PrivateNetPolicy>> for PrivateNetPolicy {
    fn from(value: MaybeKnown<api::network_policy::PrivateNetPolicy>) -> Self {
        match value {
            MaybeKnown::Known(api::network_policy::PrivateNetPolicy::Aws(aws)) => {
                Self::Aws(AwsPrivateNetPolicy {
                    vpce_ids: aws.vpce_ids,
                })
            }
            MaybeKnown::Unknown(name) => Self::Unknown(name),
        }
    }
}

impl From<PrivateNetPolicy> for MaybeKnown<api::network_policy::PrivateNetPolicy> {
    fn from(value: PrivateNetPolicy) -> Self {
        match value {
            PrivateNetPolicy::Aws(aws) => Self::Known(api::network_policy::PrivateNetPolicy::Aws(
                api::network_policy::AwsPrivateNetPolicy {
                    vpce_ids: aws.vpce_ids,
                },
            )),
            PrivateNetPolicy::Unknown(name) => Self::Unknown(name),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
/// Restriction a network policy applies to the tokens bound to it: a [`PublicNetPolicy`] for the
/// public path, a [`PrivateNetPolicy`] for private networks, or both. A path without one is
/// closed.
pub struct NetworkPolicy {
    /// Governs requests arriving over the public path.
    pub public_net: Option<PublicNetPolicy>,
    /// Governs requests arriving through a private network.
    pub private_net: Option<PrivateNetPolicy>,
}

impl NetworkPolicy {
    /// Create a new [`NetworkPolicy`] with both paths closed. At least one must be set.
    pub fn new() -> Self {
        Self::default()
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
}

impl From<NetworkPolicy> for api::network_policy::NetworkPolicy {
    fn from(value: NetworkPolicy) -> Self {
        Self {
            public_net: value.public_net.map(Into::into),
            private_net: value.private_net.map(Into::into),
        }
    }
}

impl From<api::network_policy::NetworkPolicy> for NetworkPolicy {
    fn from(value: api::network_policy::NetworkPolicy) -> Self {
        Self {
            public_net: value.public_net.map(Into::into),
            private_net: value.private_net.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Network policy information.
pub struct NetworkPolicyInfo {
    /// Full reference, `<slug>.<nonce>`, which access tokens are bound to.
    pub id: NetworkPolicyRef,
    /// Creation time.
    pub created_at: Timestamp,
    /// The restriction.
    pub policy: NetworkPolicy,
}

impl From<api::network_policy::NetworkPolicyInfo> for NetworkPolicyInfo {
    fn from(value: api::network_policy::NetworkPolicyInfo) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            policy: value.policy.into(),
        }
    }
}
