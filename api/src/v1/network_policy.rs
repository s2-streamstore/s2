use s2_common::{
    self,
    network_policy::{
        Cidr, NetworkPolicyRef, NetworkPolicySelector, NetworkPolicySlug, NetworkPolicySlugPrefix,
        NetworkPolicySlugStartAfter, VpcEndpointId,
    },
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CidrPolicy {
    /// Source addresses that may use the token.
    #[cfg_attr(feature = "utoipa", schema(min_items = 1, max_items = 32))]
    pub allow: Vec<Cidr>,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PrivateNetPolicy {
    /// AWS VPC endpoint IDs through which the token may be used.
    #[cfg_attr(feature = "utoipa", schema(min_items = 1, max_items = 32))]
    pub vpce_ids: Vec<VpcEndpointId>,
}

/// What a token may be used from, per path. At least one of `cidr` and `private_net` must be set.
#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct NetworkPolicy {
    /// Governs requests arriving over the public path, by source address.
    /// When omitted, the token cannot be used over the public path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<CidrPolicy>,
    /// Governs requests arriving through a private network, by VPC endpoint.
    /// When omitted, the token cannot be used through a private network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_net: Option<PrivateNetPolicy>,
}

impl TryFrom<NetworkPolicy> for s2_common::network_policy::NetworkPolicy {
    type Error = s2_common::ValidationError;

    fn try_from(value: NetworkPolicy) -> Result<Self, Self::Error> {
        let NetworkPolicy { cidr, private_net } = value;
        Self::new(
            cidr.map(|cidr| s2_common::network_policy::CidrPolicy::new(cidr.allow))
                .transpose()?,
            private_net
                .map(|private_net| {
                    s2_common::network_policy::PrivateNetPolicy::new(private_net.vpce_ids)
                })
                .transpose()?,
        )
    }
}

impl From<s2_common::network_policy::NetworkPolicy> for NetworkPolicy {
    fn from(value: s2_common::network_policy::NetworkPolicy) -> Self {
        Self {
            cidr: value.cidr().map(|cidr| CidrPolicy {
                allow: cidr.allow().to_vec(),
            }),
            private_net: value.private_net().map(|private_net| PrivateNetPolicy {
                vpce_ids: private_net.vpce_ids().to_vec(),
            }),
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
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
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
