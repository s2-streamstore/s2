use jiff::Timestamp;
use s2_common::{
    self,
    network_policy::{
        Cidr, NetworkPolicyRef, NetworkPolicySelector, NetworkPolicySlug, NetworkPolicySlugPrefix,
        NetworkPolicySlugStartAfter, VpcEndpointId,
    },
};
use serde::{Deserialize, Serialize};

use super::MaybeKnown;

/// What a token may be used from over the public path. Exactly one kind applies.
#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum PublicNetPolicy {
    /// Source addresses that may use the token. Between 1 and 32.
    Cidrs(Vec<Cidr>),
}

impl From<PublicNetPolicy> for s2_common::network_policy::PublicNetPolicy {
    fn from(value: PublicNetPolicy) -> Self {
        match value {
            PublicNetPolicy::Cidrs(cidrs) => Self::Cidrs(cidrs),
        }
    }
}

impl From<s2_common::network_policy::PublicNetPolicy> for PublicNetPolicy {
    fn from(value: s2_common::network_policy::PublicNetPolicy) -> Self {
        match value {
            s2_common::network_policy::PublicNetPolicy::Cidrs(cidrs) => Self::Cidrs(cidrs),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AwsPrivateNetPolicy {
    /// AWS VPC endpoint IDs through which the token may be used.
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(required = true, min_items = 1, max_items = 32))]
    pub vpce_ids: Vec<VpcEndpointId>,
}

/// Private networks a token may be used through. Exactly one kind applies.
#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum PrivateNetPolicy {
    /// AWS PrivateLink.
    Aws(AwsPrivateNetPolicy),
}

/// What a token may be used from, per path. At least one of `public_net` and `private_net` must
/// be set.
#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct NetworkPolicy {
    /// Governs requests arriving over the public path.
    /// When omitted, the token cannot be used over the public path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<PublicNetPolicy>))]
    pub public_net: Option<MaybeKnown<PublicNetPolicy>>,
    /// Governs requests arriving through a private network.
    /// When omitted, the token cannot be used through a private network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<PrivateNetPolicy>))]
    pub private_net: Option<MaybeKnown<PrivateNetPolicy>>,
}

impl TryFrom<PrivateNetPolicy> for s2_common::network_policy::PrivateNetPolicy {
    type Error = s2_common::ValidationError;

    fn try_from(value: PrivateNetPolicy) -> Result<Self, Self::Error> {
        match value {
            PrivateNetPolicy::Aws(aws) => {
                s2_common::network_policy::AwsPrivateNetPolicy::new(aws.vpce_ids).map(Self::Aws)
            }
        }
    }
}

impl From<s2_common::network_policy::PrivateNetPolicy> for PrivateNetPolicy {
    fn from(value: s2_common::network_policy::PrivateNetPolicy) -> Self {
        match value {
            s2_common::network_policy::PrivateNetPolicy::Aws(aws) => {
                Self::Aws(AwsPrivateNetPolicy {
                    vpce_ids: aws.vpce_ids().to_vec(),
                })
            }
        }
    }
}

impl TryFrom<NetworkPolicy> for s2_common::network_policy::NetworkPolicy {
    type Error = s2_common::ValidationError;

    fn try_from(value: NetworkPolicy) -> Result<Self, Self::Error> {
        let NetworkPolicy {
            public_net,
            private_net,
        } = value;
        Self::new(
            public_net
                .map(|public_net| public_net.known().map(Into::into))
                .transpose()?,
            private_net
                .map(|private_net| private_net.known()?.try_into())
                .transpose()?,
        )
    }
}

impl From<s2_common::network_policy::NetworkPolicy> for NetworkPolicy {
    fn from(value: s2_common::network_policy::NetworkPolicy) -> Self {
        Self {
            public_net: value
                .public_net()
                .cloned()
                .map(|public_net| MaybeKnown::Known(public_net.into())),
            private_net: value
                .private_net()
                .cloned()
                .map(|private_net| MaybeKnown::Known(private_net.into())),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct NetworkPolicyInfo {
    /// Full reference, `<slug>.<nonce>`, which access tokens are bound to.
    pub id: NetworkPolicyRef,
    /// Slug chosen at creation.
    pub slug: NetworkPolicySlug,
    /// Creation time in RFC 3339 format.
    #[cfg_attr(feature = "utoipa", schema(value_type = String, format = DateTime))]
    pub created_at: Timestamp,
    /// The restriction.
    pub policy: NetworkPolicy,
}

impl From<s2_common::network_policy::NetworkPolicyInfo> for NetworkPolicyInfo {
    fn from(value: s2_common::network_policy::NetworkPolicyInfo) -> Self {
        Self {
            slug: value.id.slug().clone(),
            id: value.id,
            created_at: value.created_at,
            policy: value.policy.into(),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateNetworkPolicyRequest {
    /// Slug, unique to the account. Up to 96 characters of letters, digits, `-` and `_`.
    pub slug: NetworkPolicySlug,
    /// The restriction. Policies are immutable; create a new one to change it.
    pub policy: NetworkPolicy,
}

impl TryFrom<CreateNetworkPolicyRequest> for s2_common::network_policy::CreateNetworkPolicyRequest {
    type Error = s2_common::ValidationError;

    fn try_from(value: CreateNetworkPolicyRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            slug: value.slug,
            policy: value.policy.try_into()?,
        })
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct ListNetworkPoliciesRequest {
    /// Filter to policies whose slugs begin with this prefix.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub prefix: Option<NetworkPolicySlugPrefix>,
    /// Filter to policies whose slugs lexicographically start after this string.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub start_after: Option<NetworkPolicySlugStartAfter>,
    /// Number of results, up to a maximum of 1000.
    #[cfg_attr(feature = "utoipa", param(value_type = usize, maximum = 1000, default = 1000, required = false))]
    pub limit: Option<usize>,
}

super::impl_list_request_conversions!(
    ListNetworkPoliciesRequest,
    NetworkPolicySlugPrefix,
    NetworkPolicySlugStartAfter
);

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ListNetworkPoliciesResponse {
    /// Matching network policies.
    #[cfg_attr(feature = "utoipa", schema(max_items = 1000))]
    pub network_policies: Vec<NetworkPolicyInfo>,
    /// Indicates that there are more network policies that match the criteria.
    pub has_more: bool,
}

#[rustfmt::skip]
#[derive(Debug)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Path))]
pub struct NetworkPolicySelectorPathSegment {
    /// Network policy slug, or full `<slug>.<nonce>` reference.
    #[cfg_attr(feature = "utoipa", param(value_type = String))]
    pub id: NetworkPolicySelector,
}
