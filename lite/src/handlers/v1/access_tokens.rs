use axum::extract::{Extension, FromRequest, Path, Query, State};
use base64ct::Encoding;
use http::StatusCode;
use s2_api::{data::Json, v1 as v1t};
use s2_common::types::access::{AccessTokenId, Operation};
use time::OffsetDateTime;

use crate::{
    auth::{self, AuthState},
    backend::Backend,
    handlers::v1::{AppState, error::ServiceError, middleware::AuthenticatedRequest},
};

pub fn router() -> axum::Router<AppState> {
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
///
/// Note: This endpoint is not implemented because Biscuit tokens are stateless.
/// The server does not store issued tokens - they are self-contained and verified
/// cryptographically. To "list" tokens, clients must track tokens they've issued.
/// Revocation is tracked separately (revoked tokens are stored by revocation ID).
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
    State(auth_state): State<AuthState>,
    auth: Option<Extension<AuthenticatedRequest>>,
    ListArgs { .. }: ListArgs,
) -> Result<Json<v1t::access::ListAccessTokensResponse>, ServiceError> {
    // Authorize if auth is enabled
    if let Some(Extension(ref auth_req)) = auth {
        auth::authorize(
            &auth_req.token,
            &auth_req.client_public_key,
            auth_state.root_public_key(),
            None,
            None,
            None,
            Operation::ListAccessTokens,
        )?;
    }

    // Stateless tokens cannot be listed - see docstring above
    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct IssueArgs {
    #[from_request(via(Json))]
    _request: v1t::access::AccessTokenInfo,
}

/// Issue a new access token.
///
/// SECURITY WARNING: This endpoint does NOT validate that the requested scope
/// is a subset of the issuer's scope. A user with IssueAccessToken permission
/// can issue tokens with ANY scope, including scopes they don't have access to.
/// This is effectively root-level access. Only grant IssueAccessToken permission
/// to fully trusted principals.
///
/// For proper privilege-separated delegation, use Biscuit's offline attenuation
/// feature to create narrower-scoped tokens from an existing token.
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
    State(auth_state): State<AuthState>,
    auth: Option<Extension<AuthenticatedRequest>>,
    IssueArgs { _request: request }: IssueArgs,
) -> Result<(StatusCode, Json<v1t::access::IssueAccessTokenResponse>), ServiceError> {
    // Verify token issuance is enabled (requires private key)
    let root_key = auth_state
        .root_key()
        .ok_or(ServiceError::TokenIssuanceDisabled)?;

    // Authorize the operation
    if let Some(Extension(ref auth_req)) = auth {
        auth::authorize(
            &auth_req.token,
            &auth_req.client_public_key,
            auth_state.root_public_key(),
            None,
            None,
            None, // No specific token ID for issue (creating new)
            Operation::IssueAccessToken,
        )?;
    }

    // Require public_key for new auth tokens
    let public_key_str = request
        .public_key
        .ok_or_else(|| ServiceError::Validation("public_key is required".into()))?;

    // Parse client public key
    let client_pubkey = auth::ClientPublicKey::from_base58(&public_key_str)
        .map_err(|e| ServiceError::Validation(format!("invalid public_key: {e}").into()))?;

    // Get expiration (default: 1 hour, max: 1 year)
    let now = OffsetDateTime::now_utc();
    let expires_at = request.expires_at.unwrap_or(now + time::Duration::hours(1));

    let max_expiry = now + time::Duration::days(365);
    if expires_at > max_expiry {
        return Err(ServiceError::Validation(
            "expiration cannot exceed 1 year".into(),
        ));
    }
    if expires_at <= now {
        return Err(ServiceError::Validation(
            "expiration must be in the future".into(),
        ));
    }

    // Convert API scope to internal scope
    let scope: s2_common::types::access::AccessTokenScope = request
        .scope
        .try_into()
        .map_err(|e: s2_common::types::ValidationError| ServiceError::Validation(e))?;

    // Build the Biscuit token
    let biscuit = auth::build_token(root_key, &client_pubkey, expires_at, &scope)?;

    // Serialize to base64
    let token_bytes = biscuit
        .to_vec()
        .map_err(|e| ServiceError::Validation(format!("failed to serialize token: {e}").into()))?;
    let access_token = base64ct::Base64::encode_string(&token_bytes);

    Ok((
        StatusCode::CREATED,
        Json(v1t::access::IssueAccessTokenResponse { access_token }),
    ))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct RevokeArgs {
    #[from_request(via(Path))]
    _id: AccessTokenId,
}

/// Revoke an access token.
///
/// For Biscuit tokens, provide the hex-encoded revocation ID as the token ID.
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
    State(auth_state): State<AuthState>,
    State(backend): State<Backend>,
    auth: Option<Extension<AuthenticatedRequest>>,
    RevokeArgs { _id: id }: RevokeArgs,
) -> Result<StatusCode, ServiceError> {
    // Revocation only makes sense when auth is enabled
    if !auth_state.is_enabled() {
        return Err(ServiceError::NotImplemented);
    }

    // Authorize the operation - pass token ID for access_token_scope checking
    if let Some(Extension(ref auth_req)) = auth {
        auth::authorize(
            &auth_req.token,
            &auth_req.client_public_key,
            auth_state.root_public_key(),
            None,
            None,
            Some(id.as_ref()), // Token ID being revoked for scope checking
            Operation::RevokeAccessToken,
        )?;
    }

    // The ID is treated as a hex-encoded revocation ID
    let revocation_id = hex::decode(id.as_ref())
        .map_err(|_| ServiceError::Validation("invalid revocation_id hex".into()))?;

    // Add to revocation storage
    auth::revoke(backend.db(), &revocation_id).await?;

    Ok(StatusCode::NO_CONTENT)
}
