use s2_common::types::{
    self,
    scope::{ScopeName, ScopeNamePrefix, ScopeNameStartAfter},
};
use serde::{Deserialize, Serialize};

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct ListScopesRequest {
    /// Filter to scopes whose names begin with this prefix.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub prefix: Option<ScopeNamePrefix>,
    /// Filter to scopes whose names lexicographically start after this string.
    /// It must be greater than or equal to the `prefix` if specified.
    #[cfg_attr(feature = "utoipa", param(value_type = String, default = "", required = false))]
    pub start_after: Option<ScopeNameStartAfter>,
    /// Number of results, up to a maximum of 1000.
    #[cfg_attr(feature = "utoipa", param(value_type = usize, maximum = 1000, default = 1000, required = false))]
    pub limit: Option<usize>,
}

super::impl_list_request_conversions!(
    ListScopesRequest,
    types::scope::ScopeNamePrefix,
    types::scope::ScopeNameStartAfter
);

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ListScopesResponse {
    /// Matching scopes.
    #[cfg_attr(feature = "utoipa", schema(max_items = 1000))]
    pub scopes: Vec<ScopeInfo>,
    /// Indicates that there are more scopes that match the criteria.
    pub has_more: bool,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ScopeInfo {
    /// Scope name.
    pub name: ScopeName,
    /// Scope visibility.
    pub scope_visibility: String,
    /// Scope description.
    pub description: Option<String>,
}

impl From<types::scope::ScopeInfo> for ScopeInfo {
    fn from(value: types::scope::ScopeInfo) -> Self {
        let types::scope::ScopeInfo {
            name,
            scope_visibility,
            description,
        } = value;

        Self {
            name,
            scope_visibility,
            description,
        }
    }
}
