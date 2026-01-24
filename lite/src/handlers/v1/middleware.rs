//! Authentication middleware for v1 API.

use axum::{
    body::Body,
    extract::{OriginalUri, Request, State},
    middleware::Next,
    response::Response,
};
use base64ct::Encoding;
use http::{Method, header::AUTHORIZATION};

use super::error::ServiceError;
use crate::{
    auth::{self, AuthState, ClientPublicKey, VerifiedToken},
    backend::Backend,
};

/// Extension type for authenticated requests.
///
/// Added to request extensions when auth is enabled and verification succeeds.
#[derive(Clone)]
pub struct AuthenticatedRequest {
    /// The public key that signed the HTTP request.
    pub client_public_key: ClientPublicKey,
    /// The verified Biscuit token.
    pub token: VerifiedToken,
}

/// Application state for auth middleware.
#[derive(Clone)]
pub struct AppState {
    pub backend: Backend,
    pub auth: AuthState,
}

/// Authentication middleware.
///
/// Verifies:
/// 1. Bearer token (Biscuit) from Authorization header
/// 2. RFC 9421 HTTP message signature
/// 3. Token revocation status
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ServiceError> {
    // Skip if auth is disabled
    if !state.auth.is_enabled() {
        return Ok(next.run(request).await);
    }

    let root_public_key = state.auth.root_public_key().unwrap();

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(ServiceError::AuthRequired)?
        .to_str()
        .map_err(|_| ServiceError::AuthRequired)?;

    // Parse Bearer token
    let token_bytes = parse_bearer_token(auth_header)?;

    // Verify Biscuit token
    let verified = auth::verify_token(&token_bytes, root_public_key)?;

    // Check revocation
    if auth::is_revoked(&state.backend.db(), &verified.revocation_ids).await? {
        return Err(ServiceError::TokenRevoked);
    }

    // Verify RFC 9421 signature against any allowed public key
    let method = request.method().clone();
    // Use OriginalUri to get the path BEFORE nested routing strips prefixes
    // (e.g., .nest("/v1", ...) strips "/v1" from the path the middleware sees)
    let path = request
        .extensions()
        .get::<OriginalUri>()
        .map(|uri| uri.path().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    let authority = request
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            request
                .headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_default();

    // Check if request has a body that needs Content-Digest verification
    let has_body = matches!(method, Method::POST | Method::PUT | Method::PATCH)
        && request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|len| len > 0);

    // If request has body and Content-Digest header, verify it
    let (body_bytes, request): (Option<Vec<u8>>, Request<Body>) = if has_body
        && request.headers().contains_key("content-digest")
    {
        // Extract body for verification using axum's limited body reader
        let (parts, body) = request.into_parts();

        // Read body with a reasonable limit (16 MB)
        let body_bytes = axum::body::to_bytes(body, 16 * 1024 * 1024)
            .await
            .map_err(|_| ServiceError::InvalidSignature(auth::SignatureError::DigestMismatch))?;

        // Reconstruct request with body bytes
        let request = Request::from_parts(parts, Body::from(body_bytes.clone()));
        (Some(body_bytes.to_vec()), request)
    } else {
        (None, request)
    };

    // Try each allowed public key until one succeeds
    // This supports delegation: attenuated tokens add new public_key facts
    let mut verified_signer = None;
    for pubkey in &verified.allowed_public_keys {
        if auth::verify_signature(
            &method,
            &path,
            &authority,
            request.headers(),
            body_bytes.as_deref(),
            pubkey,
            state.auth.signature_window_secs(),
        )
        .is_ok()
        {
            verified_signer = Some(pubkey.clone());
            break;
        }
    }

    let client_public_key = verified_signer.ok_or_else(|| {
        ServiceError::InvalidSignature(auth::SignatureError::SignatureInvalid(
            "no allowed public key verified signature".into(),
        ))
    })?;

    // Insert authenticated request into extensions
    let mut request = request;
    request.extensions_mut().insert(AuthenticatedRequest {
        client_public_key,
        token: verified,
    });

    Ok(next.run(request).await)
}

/// Parse a Bearer token from Authorization header.
fn parse_bearer_token(header: &str) -> Result<Vec<u8>, ServiceError> {
    let parts: Vec<&str> = header.splitn(2, ' ').collect();
    if parts.len() != 2 || !parts[0].eq_ignore_ascii_case("bearer") {
        return Err(ServiceError::AuthRequired);
    }

    base64ct::Base64::decode_vec(parts[1]).map_err(|_| ServiceError::AuthRequired)
}

impl axum::extract::FromRef<AppState> for Backend {
    fn from_ref(state: &AppState) -> Self {
        state.backend.clone()
    }
}

impl axum::extract::FromRef<AppState> for AuthState {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}
