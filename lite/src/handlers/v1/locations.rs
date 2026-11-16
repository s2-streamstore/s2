use axum::extract::{FromRequest, State};
use s2_api::{data::Json, v1 as v1t};

use crate::{backend::Backend, handlers::v1::error::ServiceError};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::{get, put};
    axum::Router::new()
        .route(super::paths::locations::LIST, get(list_locations))
        .route(super::paths::locations::DEFAULT, get(get_default_location))
        .route(super::paths::locations::DEFAULT, put(set_default_location))
}

/// List locations.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::locations::LIST,
    tag = super::paths::locations::TAG,
    responses(
        (status = 200, body = Vec<v1t::location::LocationInfo>),
        (
            status = 400,
            description = "`bad_header` or `bad_query`.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = 403,
            description = "`permission_denied`: the access token does not grant this operation.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = 408,
            description = "`request_timeout`: retry with backoff.",
            body = v1t::error::ErrorInfo,
        ),
    ),
))]
pub async fn list_locations(
    State(_backend): State<Backend>,
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
        (
            status = 403,
            description = "`permission_denied`: the access token does not grant this operation.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = 408,
            description = "`request_timeout`: retry with backoff.",
            body = v1t::error::ErrorInfo,
        ),
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
        (
            status = 400,
            description = "`bad_header` or `bad_json`.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = 403,
            description = "`permission_denied`: the access token does not grant this operation.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = 408,
            description = "`request_timeout`: retry with backoff; the request may or may not have taken effect.",
            body = v1t::error::ErrorInfo,
        ),
    ),
))]
pub async fn set_default_location(
    State(_backend): State<Backend>,
    SetDefaultArgs { .. }: SetDefaultArgs,
) -> Result<Json<v1t::location::GetDefaultLocationResponse>, ServiceError> {
    Err(ServiceError::NotImplemented)
}
