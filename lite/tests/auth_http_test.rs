//! HTTP-level integration tests for authentication middleware.
//!
//! These tests verify the middleware behavior for:
//! - Missing auth headers
//! - Invalid tokens
//!
//! Note: Full RFC 9421 signature verification is tested in auth module unit tests.
//! These integration tests verify the HTTP layer integration.

use axum::{Router, body::Body, routing::get};
use base64ct::Encoding;
use http::{Request, StatusCode};
use p256::{SecretKey, elliptic_curve::rand_core::OsRng};
use s2_common::types::access::{
    AccessTokenScope, PermittedOperationGroups, ReadWritePermissions, ResourceSet,
};
use s2_lite::auth::{AuthState, ClientPublicKey, RootKey, build_token};
use time::OffsetDateTime;

fn generate_test_root_key() -> RootKey {
    let secret = SecretKey::random(&mut OsRng);
    let bytes = secret.to_bytes();
    let base58 = bs58::encode(&bytes).into_string();
    RootKey::from_base58(&base58).unwrap()
}

fn generate_test_client_key() -> (SecretKey, ClientPublicKey) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let point = public.to_encoded_point(true);
    let base58 = bs58::encode(point.as_bytes()).into_string();
    let client_pubkey = ClientPublicKey::from_base58(&base58).unwrap();
    (secret, client_pubkey)
}

fn build_test_token(root_key: &RootKey, client_pubkey: &ClientPublicKey) -> String {
    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("test-".parse().unwrap()),
        streams: ResourceSet::Prefix("test-".parse().unwrap()),
        access_tokens: ResourceSet::None,
        op_groups: PermittedOperationGroups {
            account: ReadWritePermissions {
                read: true,
                write: true,
            },
            basin: ReadWritePermissions {
                read: true,
                write: true,
            },
            stream: ReadWritePermissions {
                read: true,
                write: true,
            },
        },
        ops: Default::default(),
    };

    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let biscuit = build_token(root_key, client_pubkey, expires, &scope).unwrap();
    base64ct::Base64::encode_string(&biscuit.to_vec().unwrap())
}

/// Create a test app with auth middleware.
async fn create_test_app(root_key: RootKey) -> Router {
    use axum::middleware::from_fn_with_state;
    use s2_lite::handlers::v1::middleware::{AppState, auth_middleware};

    // Create minimal backend
    let object_store = std::sync::Arc::new(slatedb::object_store::memory::InMemory::new());
    let db = slatedb::Db::builder("test", object_store)
        .build()
        .await
        .unwrap();
    let backend = s2_lite::backend::Backend::new(db, bytesize::ByteSize::b(1));

    let auth_state = AuthState::new(root_key, 300, None);

    let state = AppState {
        backend,
        auth: auth_state,
    };

    Router::new()
        .route("/test", get(|| async { "ok" }))
        .layer(from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}

/// Create a test app with auth disabled.
async fn create_test_app_no_auth() -> Router {
    use axum::middleware::from_fn_with_state;
    use s2_lite::handlers::v1::middleware::{AppState, auth_middleware};

    let object_store = std::sync::Arc::new(slatedb::object_store::memory::InMemory::new());
    let db = slatedb::Db::builder("test", object_store)
        .build()
        .await
        .unwrap();
    let backend = s2_lite::backend::Backend::new(db, bytesize::ByteSize::b(1));

    let auth_state = AuthState::disabled();

    let state = AppState {
        backend,
        auth: auth_state,
    };

    Router::new()
        .route("/test", get(|| async { "ok" }))
        .layer(from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}

#[tokio::test]
async fn test_missing_auth_header_fails() {
    use tower::ServiceExt;

    let root_key = generate_test_root_key();
    let app = create_test_app(root_key).await;

    let request = Request::builder()
        .method("GET")
        .uri("/test")
        .header("host", "localhost")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_malformed_bearer_fails() {
    use tower::ServiceExt;

    let root_key = generate_test_root_key();
    let app = create_test_app(root_key).await;

    // Missing "Bearer " prefix
    let request = Request::builder()
        .method("GET")
        .uri("/test")
        .header("host", "localhost")
        .header("authorization", "NotBearer sometoken")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_invalid_base64_token_fails() {
    use tower::ServiceExt;

    let root_key = generate_test_root_key();
    let app = create_test_app(root_key).await;

    // Invalid base64
    let request = Request::builder()
        .method("GET")
        .uri("/test")
        .header("host", "localhost")
        .header("authorization", "Bearer not-valid-base64!!!")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_token_from_wrong_root_fails() {
    use tower::ServiceExt;

    let root_key = generate_test_root_key();
    let app = create_test_app(root_key).await;

    // Token signed by different root key
    let other_root_key = generate_test_root_key();
    let (_, client_pubkey) = generate_test_client_key();
    let token = build_test_token(&other_root_key, &client_pubkey);

    let request = Request::builder()
        .method("GET")
        .uri("/test")
        .header("host", "localhost")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_valid_token_but_no_signature_fails() {
    use tower::ServiceExt;

    let root_key = generate_test_root_key();
    let (_, client_pubkey) = generate_test_client_key();
    let token = build_test_token(&root_key, &client_pubkey);

    let app = create_test_app(root_key).await;

    // Valid token but missing RFC 9421 signature headers
    let request = Request::builder()
        .method("GET")
        .uri("/test")
        .header("host", "localhost")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // Should fail because signature headers are missing
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_auth_disabled_allows_all() {
    use tower::ServiceExt;

    let app = create_test_app_no_auth().await;

    // No auth headers at all
    let request = Request::builder()
        .method("GET")
        .uri("/test")
        .header("host", "localhost")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // Should succeed because auth is disabled
    assert_eq!(response.status(), StatusCode::OK);
}

// Note: Expired token test removed because build_token() validates
// expiration at build time and rejects past dates. Token expiration
// is enforced by Biscuit's authorizer at verification time.
