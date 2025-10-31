use s2_common::types::{
    self,
    basin::{BasinName, BasinNamePrefix, BasinNameStartAfter},
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "utoipa")]
use utoipa::{IntoParams, ToSchema};

use super::config::BasinConfig;

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(IntoParams))]
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
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ListBasinsResponse {
    /// Matching basins.
    #[cfg_attr(feature = "utoipa", schema(max_items = 1000))]
    pub basins: Vec<BasinInfo>,
    /// Indicates that there are more basins that match the criteria.
    pub has_more: bool,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct BasinInfo {
    /// Basin name.
    pub name: BasinName,
    /// Basin scope.
    pub scope: BasinScope,
    /// Basin state.
    pub state: BasinState,
}

impl From<types::basin::BasinInfo> for BasinInfo {
    fn from(value: types::basin::BasinInfo) -> Self {
        let types::basin::BasinInfo { name, scope, state } = value;

        Self {
            name,
            scope: scope.into(),
            state: state.into(),
        }
    }
}

impl From<BasinInfo> for types::basin::BasinInfo {
    fn from(value: BasinInfo) -> Self {
        let BasinInfo { name, scope, state } = value;

        Self {
            name,
            scope: scope.into(),
            state: state.into(),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
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
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum BasinState {
    /// Basin is active.
    Active,
    /// Basin is being created.
    Creating,
    /// Basin is being deleted.
    Deleting,
}

impl From<types::basin::BasinState> for BasinState {
    fn from(value: types::basin::BasinState) -> Self {
        match value {
            types::basin::BasinState::Active => Self::Active,
            types::basin::BasinState::Creating => Self::Creating,
            types::basin::BasinState::Deleting => Self::Deleting,
        }
    }
}

impl From<BasinState> for types::basin::BasinState {
    fn from(value: BasinState) -> Self {
        match value {
            BasinState::Active => Self::Active,
            BasinState::Creating => Self::Creating,
            BasinState::Deleting => Self::Deleting,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct CreateOrReconfigureBasinRequest {
    /// Basin configuration.
    pub config: Option<BasinConfig>,
    /// Basin scope.
    /// This cannot be reconfigured.
    #[cfg_attr(feature = "utoipa", schema(value_type = BasinScope, default = "aws:us-east-1", required = false))]
    pub scope: Option<BasinScope>,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct CreateBasinRequest {
    /// Basin name which must be globally unique.
    /// It can be between 8 and 48 characters in length, and comprise lowercase letters, numbers and hyphens.
    /// It cannot begin or end with a hyphen.
    pub basin: BasinName,
    /// Basin configuration.
    pub config: Option<BasinConfig>,
    /// Basin scope.
    #[cfg_attr(feature = "utoipa", schema(value_type = BasinScope, default = "aws:us-east-1", required = false))]
    pub scope: Option<BasinScope>,
}
