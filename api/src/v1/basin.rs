use s2_common::{
    self,
    basin::{BasinName, BasinNamePrefix, BasinNameStartAfter},
    location::LocationName,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::config::BasinConfig;

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct ListBasinsRequest {
    /// Filter to basins whose names begin with this prefix.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub prefix: Option<BasinNamePrefix>,
    /// Filter to basins whose names lexicographically start after this string.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub start_after: Option<BasinNameStartAfter>,
    /// Number of results, up to a maximum of 1000.
    #[cfg_attr(feature = "utoipa", param(value_type = usize, maximum = 1000, default = 1000, required = false))]
    pub limit: Option<usize>,
}

super::impl_list_request_conversions!(ListBasinsRequest, BasinNamePrefix, BasinNameStartAfter);

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ListBasinsResponse {
    /// Matching basins.
    #[cfg_attr(feature = "utoipa", schema(max_items = 1000))]
    pub basins: Vec<BasinInfo>,
    /// Indicates that there are more basins that match the criteria.
    pub has_more: bool,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct BasinInfo {
    /// Basin name.
    pub name: BasinName,
    /// Basin location.
    pub location: Option<LocationName>,
    /// Creation time in RFC 3339 format.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Deletion time in RFC 3339 format, if the basin is being deleted.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub deleted_at: Option<OffsetDateTime>,
    /// Deprecated basin state inferred from `deleted_at`.
    #[cfg_attr(feature = "utoipa", schema(ignore))]
    pub state: BasinState,
}

impl From<s2_common::basin::BasinInfo> for BasinInfo {
    fn from(value: s2_common::basin::BasinInfo) -> Self {
        let s2_common::basin::BasinInfo {
            name,
            location,
            created_at,
            deleted_at,
        } = value;

        Self {
            name,
            location,
            created_at,
            deleted_at,
            state: basin_state_for_deleted_at(deleted_at.as_ref()),
        }
    }
}

fn basin_state_for_deleted_at(deleted_at: Option<&OffsetDateTime>) -> BasinState {
    if deleted_at.is_some() {
        BasinState::Deleting
    } else {
        BasinState::Active
    }
}

#[derive(Deserialize)]
struct BasinInfoSerde {
    name: BasinName,
    location: Option<LocationName>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    deleted_at: Option<OffsetDateTime>,
}

impl<'de> Deserialize<'de> for BasinInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let BasinInfoSerde {
            name,
            location,
            created_at,
            deleted_at,
        } = BasinInfoSerde::deserialize(deserializer)?;

        let state = basin_state_for_deleted_at(deleted_at.as_ref());

        Ok(Self {
            name,
            location,
            created_at,
            deleted_at,
            state,
        })
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum BasinState {
    /// Basin is active.
    Active,
    /// Basin is being deleted.
    Deleting,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct EnsureBasinRequest {
    /// Basin configuration.
    pub config: Option<BasinConfig>,
    /// Basin location.
    /// If omitted when creating, uses the default location for the account.
    /// This cannot be changed.
    pub location: Option<LocationName>,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateBasinRequest {
    /// Basin name which must be globally unique.
    /// It can be between 8 and 48 bytes in length, and comprise lowercase letters, numbers and hyphens.
    /// It cannot begin or end with a hyphen.
    pub basin: BasinName,
    /// Basin configuration.
    pub config: Option<BasinConfig>,
    /// Basin location.
    /// If omitted when creating, uses the default location for the account.
    pub location: Option<LocationName>,
}
