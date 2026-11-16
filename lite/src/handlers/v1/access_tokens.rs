use axum::extract::{FromRequest, Path, Query, State};
use http::StatusCode;
use s2_api::{data::Json, v1 as v1t};
use s2_common::access::AccessTokenId;

use crate::{backend::Backend, handlers::v1::error::ServiceError};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        .route(super::paths::access_tokens::LIST, get(list_access_tokens))
        .route(super::paths::access_tokens::ISSUE, post(issue_access_token))
        .route(
            super::paths::access_tokens::REVOKE,
            delete(revoke_access_token),
        )
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ListArgs {
    #[from_request(via(Query))]
    _request: v1t::access::ListAccessTokensRequest,
}

/// List access tokens.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::access_tokens::LIST,
    tag = super::paths::access_tokens::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::access::ListAccessTokensResponse),
        (
            status = StatusCode::BAD_REQUEST,
            description = "`bad_header` or `bad_query`.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "`permission_denied`: the access token does not grant this operation.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = StatusCode::REQUEST_TIMEOUT,
            description = "`request_timeout`: retry with backoff.",
            body = v1t::error::ErrorInfo,
        ),
    ),
    params(v1t::access::ListAccessTokensRequest),
))]
pub async fn list_access_tokens(
    State(_backend): State<Backend>,
    ListArgs { .. }: ListArgs,
) -> Result<Json<v1t::access::ListAccessTokensResponse>, ServiceError> {
    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct IssueArgs {
    #[from_request(via(Json))]
    _request: v1t::access::IssueAccessTokenRequest,
}

/// Issue a new access token.
#[cfg_attr(feature = "utoipa", utoipa::path(
    post,
    path = super::paths::access_tokens::ISSUE,
    tag = super::paths::access_tokens::TAG,
    request_body = v1t::access::IssueAccessTokenRequest,
    responses(
        (
            status = StatusCode::CREATED,
            description = "Access token issued.",
            body = v1t::access::IssueAccessTokenResponse,
        ),
        (
            status = StatusCode::BAD_REQUEST,
            description = "`bad_header` or `bad_json`.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "`permission_denied`: the access token does not grant this operation.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = StatusCode::REQUEST_TIMEOUT,
            description = "`request_timeout`: retry with backoff; the request may or may not have taken effect.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = StatusCode::CONFLICT,
            description = "`resource_already_exists`: an access token with this ID already exists.",
            body = v1t::error::ErrorInfo,
        ),
    ),
))]
pub async fn issue_access_token(
    State(_backend): State<Backend>,
    IssueArgs { .. }: IssueArgs,
) -> Result<(StatusCode, Json<v1t::access::IssueAccessTokenResponse>), ServiceError> {
    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct RevokeArgs {
    #[from_request(via(Path))]
    _id: AccessTokenId,
}

/// Revoke an access token.
#[cfg_attr(feature = "utoipa", utoipa::path(
    delete,
    path = super::paths::access_tokens::REVOKE,
    tag = super::paths::access_tokens::TAG,
    responses(
        (status = StatusCode::NO_CONTENT, description = "Access token revoked."),
        (
            status = StatusCode::BAD_REQUEST,
            description = "`bad_header` or `bad_path`.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "`permission_denied`: the access token does not grant this operation.",
            body = v1t::error::ErrorInfo,
        ),
        (
            status = StatusCode::REQUEST_TIMEOUT,
            description = "`request_timeout`: retry with backoff; the request may or may not have taken effect.",
            body = v1t::error::ErrorInfo,
        ),
    ),
    params(v1t::AccessTokenIdPathSegment),
))]
pub async fn revoke_access_token(
    State(_backend): State<Backend>,
    RevokeArgs { .. }: RevokeArgs,
) -> Result<StatusCode, ServiceError> {
    Err(ServiceError::NotImplemented)
}
