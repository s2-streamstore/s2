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
    /// Source addresses that may use the token. When omitted, any address not denied may.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(min_items = 1, max_items = 100))]
    pub allow: Option<Vec<Cidr>>,
    /// Source addresses that may not use the token, even if allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(min_items = 1, max_items = 100))]
    pub deny: Option<Vec<Cidr>>,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PrivateNetPolicy {
    /// AWS VPC endpoint IDs through which the token may be used.
    #[cfg_attr(feature = "utoipa", schema(min_items = 1, max_items = 100))]
    pub vpce_ids: Vec<VpcEndpointId>,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// Restrict the token to public clients by source address.
    /// Connections through a private network are rejected.
    Cidr(CidrPolicy),
    /// Restrict the token to connections through the listed VPC endpoints.
    PrivateNet(PrivateNetPolicy),
}

impl TryFrom<NetworkPolicy> for s2_common::network_policy::NetworkPolicy {
    type Error = s2_common::ValidationError;

    fn try_from(value: NetworkPolicy) -> Result<Self, Self::Error> {
        Ok(match value {
            NetworkPolicy::Cidr(CidrPolicy { allow, deny }) => {
                Self::Cidr(s2_common::network_policy::CidrPolicy::new(allow, deny)?)
            }
            NetworkPolicy::PrivateNet(PrivateNetPolicy { vpce_ids }) => {
                Self::PrivateNet(s2_common::network_policy::PrivateNetPolicy::new(vpce_ids)?)
            }
        })
    }
}

impl From<s2_common::network_policy::NetworkPolicy> for NetworkPolicy {
    fn from(value: s2_common::network_policy::NetworkPolicy) -> Self {
        match value {
            s2_common::network_policy::NetworkPolicy::Cidr(policy) => Self::Cidr(CidrPolicy {
                allow: policy.allow().map(<[Cidr]>::to_vec),
                deny: policy.deny().map(<[Cidr]>::to_vec),
            }),
            s2_common::network_policy::NetworkPolicy::PrivateNet(policy) => {
                Self::PrivateNet(PrivateNetPolicy {
                    vpce_ids: policy.vpce_ids().to_vec(),
                })
            }
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

#[rustfmt::skip]
#[derive(Debug)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Path))]
pub struct NetworkPolicyRefPathSegment {
    /// Full `<slug>.<nonce>` network policy reference.
    pub id: NetworkPolicyRef,
}
