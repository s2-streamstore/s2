use axum::extract::{FromRequest, Query, State};
use s2_api::{data::Json, v1 as v1t};

use crate::{backend::Backend, handlers::v1::error::ServiceError};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::{get, put};
    axum::Router::new()
        .route(super::paths::locations::LIST, get(list_locations))
        .route(super::paths::locations::DEFAULT, get(get_default_location))
        .route(super::paths::locations::DEFAULT, put(set_default_location))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ListArgs {
    #[from_request(via(Query))]
    _request: v1t::location::ListLocationsRequest,
}

/// List locations.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::locations::LIST,
    tag = super::paths::locations::TAG,
    responses(
        (status = 200, body = Vec<v1t::location::LocationInfo>),
        (status = 400, body = v1t::error::ErrorInfo),
        (status = 403, body = v1t::error::ErrorInfo),
        (status = 408, body = v1t::error::ErrorInfo),
    ),
    params(v1t::location::ListLocationsRequest),
))]
pub async fn list_locations(
    State(_backend): State<Backend>,
    ListArgs { .. }: ListArgs,
) -> Result<Json<Vec<v1t::location::LocationInfo>>, ServiceError> {
    Err(ServiceError::NotImplemented)
}

/// Get the default location.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::locations::DEFAULT,
    tag = super::paths::locations::TAG,
    responses(
        (status = 200, body = v1t::location::GetDefaultLocationResponse),
        (status = 403, body = v1t::error::ErrorInfo),
        (status = 408, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn get_default_location(
    State(_backend): State<Backend>,
) -> Result<Json<v1t::location::GetDefaultLocationResponse>, ServiceError> {
    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct SetDefaultArgs {
    #[from_request(via(Json))]
    _request: v1t::location::SetDefaultLocationRequest,
}

/// Set the default location.
#[cfg_attr(feature = "utoipa", utoipa::path(
    put,
    path = super::paths::locations::DEFAULT,
    tag = super::paths::locations::TAG,
    request_body = v1t::location::SetDefaultLocationRequest,
    responses(
        (status = 200, body = v1t::location::GetDefaultLocationResponse),
        (status = 400, body = v1t::error::ErrorInfo),
        (status = 403, body = v1t::error::ErrorInfo),
        (status = 408, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn set_default_location(
    State(_backend): State<Backend>,
    SetDefaultArgs { .. }: SetDefaultArgs,
) -> Result<Json<v1t::location::GetDefaultLocationResponse>, ServiceError> {
    Err(ServiceError::NotImplemented)
}
