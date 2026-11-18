use axum::extract::{FromRequest, Path, Query, State};
use http::StatusCode;
use s2_api::{data::Json, v1 as v1t};
use s2_common::network_policy::NetworkPolicySelector;

use crate::{backend::Backend, handlers::v1::error::ServiceError};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        .route(
            super::paths::network_policies::LIST,
            get(list_network_policies),
        )
        .route(
            super::paths::network_policies::CREATE,
            post(create_network_policy),
        )
        .route(super::paths::network_policies::GET, get(get_network_policy))
        .route(
            super::paths::network_policies::DELETE,
            delete(delete_network_policy),
        )
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ListArgs {
    #[from_request(via(Query))]
    _request: v1t::network_policy::ListNetworkPoliciesRequest,
}

/// List network policies.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::network_policies::LIST,
    tag = super::paths::network_policies::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::network_policy::ListNetworkPoliciesResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::network_policy::ListNetworkPoliciesRequest),
))]
pub async fn list_network_policies(
    State(_backend): State<Backend>,
    ListArgs { .. }: ListArgs,
) -> Result<Json<v1t::network_policy::ListNetworkPoliciesResponse>, ServiceError> {
    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct CreateArgs {
    #[from_request(via(Json))]
    _request: v1t::network_policy::CreateNetworkPolicyRequest,
}

/// Create a network policy.
#[cfg_attr(feature = "utoipa", utoipa::path(
    post,
    path = super::paths::network_policies::CREATE,
    tag = super::paths::network_policies::TAG,
    request_body = v1t::network_policy::CreateNetworkPolicyRequest,
    responses(
        (status = StatusCode::CREATED, body = v1t::network_policy::NetworkPolicyInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn create_network_policy(
    State(_backend): State<Backend>,
    CreateArgs { .. }: CreateArgs,
) -> Result<(StatusCode, Json<v1t::network_policy::NetworkPolicyInfo>), ServiceError> {
    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct GetArgs {
    #[from_request(via(Path))]
    _selector: NetworkPolicySelector,
}

/// Get a network policy by slug or full reference.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::network_policies::GET,
    tag = super::paths::network_policies::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::network_policy::NetworkPolicyInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::network_policy::NetworkPolicySelectorPathSegment),
))]
pub async fn get_network_policy(
    State(_backend): State<Backend>,
    GetArgs { .. }: GetArgs,
) -> Result<Json<v1t::network_policy::NetworkPolicyInfo>, ServiceError> {
    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct DeleteArgs {
    #[from_request(via(Path))]
    _selector: NetworkPolicySelector,
}

/// Delete a network policy by slug or full reference. It must not be bound to any access token.
#[cfg_attr(feature = "utoipa", utoipa::path(
    delete,
    path = super::paths::network_policies::DELETE,
    tag = super::paths::network_policies::TAG,
    responses(
        (status = StatusCode::NO_CONTENT),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::network_policy::NetworkPolicySelectorPathSegment),
))]
pub async fn delete_network_policy(
    State(_backend): State<Backend>,
    DeleteArgs { .. }: DeleteArgs,
) -> Result<StatusCode, ServiceError> {
    Err(ServiceError::NotImplemented)
}
