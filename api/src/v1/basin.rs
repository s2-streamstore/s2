use s2_common::types::{
    self,
    basin::{BasinName, BasinNamePrefix, BasinNameStartAfter},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::config::{BasinConfig, BasinReconfiguration};

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct ListBasinsRequest {
    /// Filter to basins whose names begin with this prefix.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub prefix: Option<BasinNamePrefix>,
    /// Filter to basins whose names lexicographically start after this string.
    /// It must be greater than or equal to the `prefix` if specified.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub start_after: Option<BasinNameStartAfter>,
    /// Number of results, up to a maximum of 1000.
    #[cfg_attr(feature = "utoipa", param(value_type = usize, maximum = 1000, default = 1000, required = false))]
    pub limit: Option<usize>,
}

super::impl_list_request_conversions!(
    ListBasinsRequest,
    types::basin::BasinNamePrefix,
    types::basin::BasinNameStartAfter
);

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
    /// Basin scope.
    pub scope: Option<BasinScope>,
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

impl From<types::basin::BasinInfo> for BasinInfo {
    fn from(value: types::basin::BasinInfo) -> Self {
        let types::basin::BasinInfo {
            name,
            scope,
            created_at,
            deleted_at,
        } = value;

        Self {
            name,
            scope: scope.map(Into::into),
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
    scope: Option<BasinScope>,
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
            scope,
            created_at,
            deleted_at,
        } = BasinInfoSerde::deserialize(deserializer)?;
        let state = basin_state_for_deleted_at(deleted_at.as_ref());

        Ok(Self {
            name,
            scope,
            created_at,
            deleted_at,
            state,
        })
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum BasinScope {
    /// AWS `us-east-1` region.
    #[serde(rename = "aws:us-east-1")]
    AwsUsEast1,
}

impl From<BasinScope> for types::basin::BasinScope {
    fn from(value: BasinScope) -> Self {
        match value {
            BasinScope::AwsUsEast1 => Self::AwsUsEast1,
        }
    }
}

impl From<types::basin::BasinScope> for BasinScope {
    fn from(value: types::basin::BasinScope) -> Self {
        match value {
            types::basin::BasinScope::AwsUsEast1 => Self::AwsUsEast1,
        }
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
pub struct CreateOrReconfigureBasinRequest {
    /// Basin reconfiguration.
    pub config: Option<BasinReconfiguration>,
    /// Basin scope.
    /// This cannot be reconfigured.
    pub scope: Option<BasinScope>,
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
    /// Basin scope.
    pub scope: Option<BasinScope>,
}
