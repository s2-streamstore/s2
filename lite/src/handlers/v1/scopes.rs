use axum::extract::{FromRequest, Query, State};
use s2_api::{data::Json, v1 as v1t};

use crate::{backend::Backend, handlers::v1::error::ServiceError};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::get;
    axum::Router::new().route(super::paths::scopes::LIST, get(list_scopes))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ListArgs {
    #[from_request(via(Query))]
    _request: v1t::scope::ListScopesRequest,
}

/// List scopes.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::scopes::LIST,
    tag = super::paths::scopes::TAG,
    responses(
        (status = 200, body = v1t::scope::ListScopesResponse),
        (status = 400, body = v1t::error::ErrorInfo),
        (status = 403, body = v1t::error::ErrorInfo),
        (status = 408, body = v1t::error::ErrorInfo),
    ),
    params(v1t::scope::ListScopesRequest),
))]
pub async fn list_scopes(
    State(_backend): State<Backend>,
    ListArgs { .. }: ListArgs,
) -> Result<Json<v1t::scope::ListScopesResponse>, ServiceError> {
    Err(ServiceError::NotImplemented)
}
