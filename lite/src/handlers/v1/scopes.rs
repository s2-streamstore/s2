use axum::extract::{FromRequest, Query, State};
use s2_api::{data::Json, v1 as v1t};

use crate::{backend::Backend, handlers::v1::error::ServiceError};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::{get, put};
    axum::Router::new()
        .route(super::paths::scopes::LIST, get(list_scopes))
        .route(super::paths::scopes::DEFAULT, get(get_default_scope))
        .route(super::paths::scopes::DEFAULT, put(set_default_scope))
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

/// Get the default scope.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::scopes::DEFAULT,
    tag = super::paths::scopes::TAG,
    responses(
        (status = 200, body = v1t::scope::GetDefaultScopeResponse),
        (status = 403, body = v1t::error::ErrorInfo),
        (status = 408, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn get_default_scope(
    State(_backend): State<Backend>,
) -> Result<Json<v1t::scope::GetDefaultScopeResponse>, ServiceError> {
    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct SetDefaultArgs {
    #[from_request(via(Json))]
    _request: v1t::scope::SetDefaultScopeRequest,
}

/// Set the default scope.
#[cfg_attr(feature = "utoipa", utoipa::path(
    put,
    path = super::paths::scopes::DEFAULT,
    tag = super::paths::scopes::TAG,
    request_body = v1t::scope::SetDefaultScopeRequest,
    responses(
        (status = 200, body = v1t::scope::GetDefaultScopeResponse),
        (status = 400, body = v1t::error::ErrorInfo),
        (status = 403, body = v1t::error::ErrorInfo),
        (status = 408, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn set_default_scope(
    State(_backend): State<Backend>,
    SetDefaultArgs { .. }: SetDefaultArgs,
) -> Result<Json<v1t::scope::GetDefaultScopeResponse>, ServiceError> {
    Err(ServiceError::NotImplemented)
}
