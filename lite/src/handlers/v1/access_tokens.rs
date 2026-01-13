use axum::extract::{FromRequest, Path, Query, State};
use http::StatusCode;
use s2_api::{data::Json, v1 as v1t};
use s2_common::types::access::AccessTokenId;

use crate::{backend::Backend, handlers::v1::error::ServiceError};

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
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
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
    _request: v1t::access::AccessTokenInfo,
}

/// Issue a new access token.
#[cfg_attr(feature = "utoipa", utoipa::path(
    post,
    path = super::paths::access_tokens::ISSUE,
    tag = super::paths::access_tokens::TAG,
    request_body = v1t::access::AccessTokenInfo,
    responses(
        (status = StatusCode::CREATED, body = v1t::access::IssueAccessTokenResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
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
        (status = StatusCode::NO_CONTENT),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::AccessTokenIdPathSegment),
))]
pub async fn revoke_access_token(
    State(_backend): State<Backend>,
    RevokeArgs { .. }: RevokeArgs,
) -> Result<StatusCode, ServiceError> {
    Err(ServiceError::NotImplemented)
}
