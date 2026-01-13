use axum::extract::{FromRequest, Path, Query, State};
use http::StatusCode;
use s2_api::{data::Json, v1 as v1t};
use s2_common::types::access::AccessTokenId;

#[cfg(feature = "utoipa")]
use super::paths;
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
    path = paths::tokens::LIST,
    tag = paths::tokens::TAG,
    operation_id = "list_access_tokens",
    responses(
        (status = StatusCode::OK, body = v1t::access::ListAccessTokensResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::access::ListAccessTokensRequest),
))]
pub async fn list(
    State(_backend): State<Backend>,
    ListArgs { .. }: ListArgs,
) -> Result<Json<v1t::access::ListAccessTokensResponse>, ServiceError> {
    Ok(Json(v1t::access::ListAccessTokensResponse {
        access_tokens: vec![],
        has_more: false,
    }))
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
    path = paths::tokens::ISSUE,
    tag = paths::tokens::TAG,
    operation_id = "issue_access_token",
    request_body = v1t::access::AccessTokenInfo,
    responses(
        (status = StatusCode::CREATED, body = v1t::access::IssueAccessTokenResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn issue(
    State(_backend): State<Backend>,
    IssueArgs { .. }: IssueArgs,
) -> Result<(StatusCode, Json<v1t::access::IssueAccessTokenResponse>), ServiceError> {
    Ok((
        StatusCode::CREATED,
        Json(v1t::access::IssueAccessTokenResponse {
            access_token: "mock-token".to_string(),
        }),
    ))
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
    path = paths::tokens::REVOKE,
    tag = paths::tokens::TAG,
    operation_id = "revoke_access_token",
    responses(
        (status = StatusCode::NO_CONTENT),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::AccessTokenIdPathSegment),
))]
pub async fn revoke(
    State(_backend): State<Backend>,
    RevokeArgs { .. }: RevokeArgs,
) -> Result<StatusCode, ServiceError> {
    Ok(StatusCode::NO_CONTENT)
}
