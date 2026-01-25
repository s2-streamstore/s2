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

/// Test with ACTUAL HTTP request over the network (not tower::oneshot).
/// This tests the full HTTP stack including hyper parsing.
#[tokio::test]
async fn test_real_http_request_bootstrap_mode() {
    use std::time::{SystemTime, UNIX_EPOCH};

    use biscuit_auth::{
        KeyPair, PrivateKey,
        builder::{Algorithm, BiscuitBuilder},
    };
    use httpsig::prelude::{
        AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
        message_component::{
            HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName,
        },
    };
    use p256::ecdsa::SigningKey;
    use tokio::net::TcpListener;

    // Setup keys
    let root_key_base58 = "ByDGSRM82bqEVQoGYpZzvmmHujrB32UN1sr7WbKN6TPQ";
    let root_key = RootKey::from_base58(root_key_base58).unwrap();
    let key_bytes = bs58::decode(root_key_base58).into_vec().unwrap();
    let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
    let public_key = signing_key.verifying_key();
    let public_key_base58 =
        bs58::encode(public_key.to_encoded_point(true).as_bytes()).into_string();

    // Create token
    let biscuit_private = PrivateKey::from_bytes(&key_bytes, Algorithm::Secp256r1).unwrap();
    let biscuit_keypair = KeyPair::from(&biscuit_private);
    let expires_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    let mut builder = BiscuitBuilder::new();
    builder = builder
        .fact(format!("public_key(\"{}\")", public_key_base58).as_str())
        .unwrap();
    builder = builder
        .fact(format!("expires({})", expires_ts).as_str())
        .unwrap();
    builder = builder
        .check(format!("check if time($t), $t < {}", expires_ts).as_str())
        .unwrap();
    builder = builder.fact("op_group(\"account\", \"read\")").unwrap();
    builder = builder.fact("basin_scope(\"prefix\", \"\")").unwrap();

    let biscuit = builder.build(&biscuit_keypair).unwrap();
    let token_base64 = base64ct::Base64::encode_string(&biscuit.to_vec().unwrap());

    // Start actual HTTP server
    let app = create_test_app(root_key).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("Test server listening on {}", addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Build request
    let url = format!("http://{}/test", addr);
    let authorization = format!("Bearer {}", token_base64);

    // Sign request
    let component_ids: Vec<HttpMessageComponentId> =
        ["@method", "@path", "@authority", "authorization"]
            .iter()
            .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
            .collect();

    // Authority is host:port for non-default port
    let authority = format!("127.0.0.1:{}", addr.port());
    let path = "/test";
    let method = "GET";

    let mut component_lines = Vec::new();
    for id in &component_ids {
        let line = match &id.name {
            HttpMessageComponentName::Derived(derived) => {
                let derived_str: &str = derived.as_ref();
                let value = match derived_str {
                    "@method" => method.to_uppercase(),
                    "@path" => path.to_string(),
                    "@authority" => authority.clone(),
                    other => panic!("unexpected: {}", other),
                };
                format!("\"{}\": {}", derived_str, value)
            }
            HttpMessageComponentName::HttpField(name) => {
                format!("\"{}\": {}", name, authorization)
            }
        };
        let component = HttpMessageComponent::try_from(line.as_str()).unwrap();
        component_lines.push(component);
    }

    let mut sig_params = HttpSignatureParams::try_new(&component_ids).unwrap();
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sig_params.set_created(created);

    let httpsig_secret = SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes).unwrap();
    sig_params.set_key_info(&httpsig_secret);
    sig_params.set_keyid(&public_key_base58);

    let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params).unwrap();
    let sig_headers = signature_base
        .build_signature_headers(&httpsig_secret, Some("sig1"))
        .unwrap();

    println!("Request URL: {}", url);
    println!("Authority signed: {}", authority);
    println!(
        "Signature-Input: {}",
        sig_headers.signature_input_header_value()
    );

    // Make ACTUAL HTTP request using raw TCP
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

    // Build raw HTTP/1.1 request
    let request = format!(
        "GET /test HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: {}\r\n\
         Signature-Input: {}\r\n\
         Signature: {}\r\n\
         Connection: close\r\n\
         \r\n",
        authority,
        authorization,
        sig_headers.signature_input_header_value(),
        sig_headers.signature_header_value()
    );

    println!("=== Raw HTTP Request ===\n{}", request);

    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    println!("=== Raw HTTP Response ===\n{}", response_str);

    assert!(
        response_str.contains("200 OK"),
        "Real HTTP request should succeed, got:\n{}",
        response_str
    );
}

/// Test that request.uri().path() returns path WITHOUT query string
#[tokio::test]
async fn test_uri_path_excludes_query_string() {
    use tower::ServiceExt;

    let app = create_test_app_no_auth().await;

    // Request with query string
    let request = Request::builder()
        .method("GET")
        .uri("/test?foo=bar&baz=qux")
        .header("host", "localhost")
        .body(Body::empty())
        .unwrap();

    // Check what path() returns
    let path = request.uri().path();
    println!("URI: {}", request.uri());
    println!("Path from uri().path(): '{}'", path);

    assert_eq!(path, "/test", "path() should NOT include query string");

    // Also verify the request works
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// Test bootstrap mode: root key is ALSO the client signing key.
/// This is how the CLI works when only root_key is configured.
#[tokio::test]
async fn test_bootstrap_mode_root_key_signs_request() {
    use std::time::{SystemTime, UNIX_EPOCH};

    use biscuit_auth::{
        KeyPair, PrivateKey,
        builder::{Algorithm, BiscuitBuilder},
    };
    use httpsig::prelude::{
        AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
        message_component::{
            HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName,
        },
    };
    use p256::ecdsa::SigningKey;
    use tower::ServiceExt;

    // Use actual root key from config
    let root_key_base58 = "ByDGSRM82bqEVQoGYpZzvmmHujrB32UN1sr7WbKN6TPQ";
    let root_key = RootKey::from_base58(root_key_base58).unwrap();
    let key_bytes = bs58::decode(root_key_base58).into_vec().unwrap();

    // Create signing key (same as CLI does)
    let signing_key = SigningKey::from_slice(&key_bytes).unwrap();

    // Get public key (same as CLI does)
    let public_key = signing_key.verifying_key();
    let public_key_base58 =
        bs58::encode(public_key.to_encoded_point(true).as_bytes()).into_string();
    println!("Root/Signing public key: {}", public_key_base58);

    // Should be pTGh6RCaGt5PcA3evMKB6ZZmsYfALRSPhCH9tq3xzEsW
    assert_eq!(
        public_key_base58,
        "pTGh6RCaGt5PcA3evMKB6ZZmsYfALRSPhCH9tq3xzEsW"
    );

    // Create Biscuit exactly like CLI does in bootstrap mode
    let biscuit_private = PrivateKey::from_bytes(&key_bytes, Algorithm::Secp256r1).unwrap();
    let biscuit_keypair = KeyPair::from(&biscuit_private);

    let expires_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    let mut builder = BiscuitBuilder::new();
    builder = builder
        .fact(format!("public_key(\"{}\")", public_key_base58).as_str())
        .unwrap();
    builder = builder
        .fact(format!("expires({})", expires_ts).as_str())
        .unwrap();
    builder = builder
        .check(format!("check if time($t), $t < {}", expires_ts).as_str())
        .unwrap();
    builder = builder.fact("op_group(\"account\", \"read\")").unwrap();
    builder = builder.fact("op_group(\"account\", \"write\")").unwrap();
    builder = builder.fact("op_group(\"basin\", \"read\")").unwrap();
    builder = builder.fact("op_group(\"basin\", \"write\")").unwrap();
    builder = builder.fact("op_group(\"stream\", \"read\")").unwrap();
    builder = builder.fact("op_group(\"stream\", \"write\")").unwrap();
    builder = builder.fact("basin_scope(\"prefix\", \"\")").unwrap();
    builder = builder.fact("stream_scope(\"prefix\", \"\")").unwrap();
    builder = builder
        .fact("access_token_scope(\"prefix\", \"\")")
        .unwrap();

    let biscuit = builder.build(&biscuit_keypair).unwrap();
    let token_bytes = biscuit.to_vec().unwrap();
    let token_base64 = base64ct::Base64::encode_string(&token_bytes);

    println!(
        "Biscuit block source:\n{}",
        biscuit.print_block_source(0).unwrap()
    );

    let app = create_test_app(root_key).await;

    // Build request components
    let method = "GET";
    let path = "/test";
    let authority = "localhost";
    let authorization = format!("Bearer {}", token_base64);

    // Sign request with same key (bootstrap mode)
    let component_ids: Vec<HttpMessageComponentId> =
        ["@method", "@path", "@authority", "authorization"]
            .iter()
            .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
            .collect();

    let mut component_lines = Vec::new();
    for id in &component_ids {
        let line = match &id.name {
            HttpMessageComponentName::Derived(derived) => {
                let derived_str: &str = derived.as_ref();
                let value = match derived_str {
                    "@method" => method.to_uppercase(),
                    "@path" => path.to_string(),
                    "@authority" => authority.to_string(),
                    other => panic!("unexpected: {}", other),
                };
                format!("\"{}\": {}", derived_str, value)
            }
            HttpMessageComponentName::HttpField(name) => {
                format!("\"{}\": {}", name, authorization)
            }
        };
        let component = HttpMessageComponent::try_from(line.as_str()).unwrap();
        component_lines.push(component);
    }

    let mut sig_params = HttpSignatureParams::try_new(&component_ids).unwrap();
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sig_params.set_created(created);

    let httpsig_secret = SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes).unwrap();
    sig_params.set_key_info(&httpsig_secret);
    sig_params.set_keyid(&public_key_base58);

    let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params).unwrap();
    let sig_headers = signature_base
        .build_signature_headers(&httpsig_secret, Some("sig1"))
        .unwrap();

    println!(
        "Signature-Input: {}",
        sig_headers.signature_input_header_value()
    );

    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", authority)
        .header("authorization", &authorization)
        .header(
            "signature-input",
            sig_headers.signature_input_header_value(),
        )
        .header("signature", sig_headers.signature_header_value())
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    println!("Response status: {}", response.status());

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Bootstrap mode request should succeed"
    );
}

/// Test a fully valid request with proper RFC 9421 signature.
/// This simulates what the CLI/SDK does end-to-end.
#[tokio::test]
async fn test_valid_token_with_valid_signature_succeeds() {
    use std::time::{SystemTime, UNIX_EPOCH};

    use httpsig::prelude::{
        AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
        message_component::{HttpMessageComponent, HttpMessageComponentId},
    };
    use p256::ecdsa::SigningKey;
    use tower::ServiceExt;

    let root_key = generate_test_root_key();
    let (client_secret, client_pubkey) = generate_test_client_key();
    let token = build_test_token(&root_key, &client_pubkey);

    let app = create_test_app(root_key).await;

    // Build request components
    let method = "GET";
    let path = "/test";
    let authority = "localhost";
    let authorization = format!("Bearer {}", token);

    // Sign the request like SDK does
    let component_ids: Vec<HttpMessageComponentId> =
        ["@method", "@path", "@authority", "authorization"]
            .iter()
            .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
            .collect();

    let mut component_lines = Vec::new();
    for id in &component_ids {
        use httpsig::prelude::message_component::HttpMessageComponentName;
        let line = match &id.name {
            HttpMessageComponentName::Derived(derived) => {
                let derived_str: &str = derived.as_ref();
                let value = match derived_str {
                    "@method" => method.to_uppercase(),
                    "@path" => path.to_string(),
                    "@authority" => authority.to_string(),
                    other => panic!("unexpected: {}", other),
                };
                format!("\"{}\": {}", derived_str, value)
            }
            HttpMessageComponentName::HttpField(name) => {
                format!("\"{}\": {}", name, authorization)
            }
        };
        let component = HttpMessageComponent::try_from(line.as_str()).unwrap();
        component_lines.push(component);
    }

    let mut sig_params = HttpSignatureParams::try_new(&component_ids).unwrap();
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sig_params.set_created(created);

    // Create signing key from client secret
    let signing_key = SigningKey::from(&client_secret);
    let key_bytes = signing_key.to_bytes();
    let httpsig_secret = SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes).unwrap();
    sig_params.set_key_info(&httpsig_secret);

    // Use client public key as keyid
    let keyid = client_pubkey.to_base58();
    sig_params.set_keyid(&keyid);

    let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params).unwrap();
    let sig_headers = signature_base
        .build_signature_headers(&httpsig_secret, Some("sig1"))
        .unwrap();

    // Build the request with all headers
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", authority)
        .header("authorization", &authorization)
        .header(
            "signature-input",
            sig_headers.signature_input_header_value(),
        )
        .header("signature", sig_headers.signature_header_value())
        .body(Body::empty())
        .unwrap();

    println!("Authorization: {}", authorization);
    println!(
        "Signature-Input: {}",
        sig_headers.signature_input_header_value()
    );
    println!("Signature: {}", sig_headers.signature_header_value());

    let response = app.oneshot(request).await.unwrap();
    println!("Response status: {}", response.status());

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Valid signed request should succeed"
    );
}

/// Test using "localhost" as authority (like the SDK does for http://localhost).
/// This is the key difference from test_real_http_request_bootstrap_mode which uses IP:PORT.
#[tokio::test]
async fn test_localhost_authority_without_port() {
    use std::time::{SystemTime, UNIX_EPOCH};

    use biscuit_auth::{
        KeyPair, PrivateKey,
        builder::{Algorithm, BiscuitBuilder},
    };
    use httpsig::prelude::{
        AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
        message_component::{
            HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName,
        },
    };
    use p256::ecdsa::SigningKey;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    // Setup keys
    let root_key_base58 = "ByDGSRM82bqEVQoGYpZzvmmHujrB32UN1sr7WbKN6TPQ";
    let root_key = RootKey::from_base58(root_key_base58).unwrap();
    let key_bytes = bs58::decode(root_key_base58).into_vec().unwrap();
    let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
    let public_key = signing_key.verifying_key();
    let public_key_base58 =
        bs58::encode(public_key.to_encoded_point(true).as_bytes()).into_string();

    // Create token
    let biscuit_private = PrivateKey::from_bytes(&key_bytes, Algorithm::Secp256r1).unwrap();
    let biscuit_keypair = KeyPair::from(&biscuit_private);
    let expires_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    let mut builder = BiscuitBuilder::new();
    builder = builder
        .fact(format!("public_key(\"{}\")", public_key_base58).as_str())
        .unwrap();
    builder = builder
        .fact(format!("expires({})", expires_ts).as_str())
        .unwrap();
    builder = builder
        .check(format!("check if time($t), $t < {}", expires_ts).as_str())
        .unwrap();
    builder = builder.fact("op_group(\"account\", \"read\")").unwrap();
    builder = builder.fact("basin_scope(\"prefix\", \"\")").unwrap();

    let biscuit = builder.build(&biscuit_keypair).unwrap();
    let token_base64 = base64ct::Base64::encode_string(&biscuit.to_vec().unwrap());

    // Start server on random port
    let app = create_test_app(root_key).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("Test server listening on {}", addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let authorization = format!("Bearer {}", token_base64);

    // KEY DIFFERENCE: Use "localhost" as authority WITHOUT port
    // This is what happens when SDK connects to http://localhost (port 80 default)
    let authority = "localhost";
    let path = "/test";
    let method = "GET";

    // Sign request
    let component_ids: Vec<HttpMessageComponentId> =
        ["@method", "@path", "@authority", "authorization"]
            .iter()
            .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
            .collect();

    let mut component_lines = Vec::new();
    for id in &component_ids {
        let line = match &id.name {
            HttpMessageComponentName::Derived(derived) => {
                let derived_str: &str = derived.as_ref();
                let value = match derived_str {
                    "@method" => method.to_uppercase(),
                    "@path" => path.to_string(),
                    "@authority" => authority.to_string(),
                    other => panic!("unexpected: {}", other),
                };
                format!("\"{}\": {}", derived_str, value)
            }
            HttpMessageComponentName::HttpField(name) => {
                format!("\"{}\": {}", name, authorization)
            }
        };
        let component = HttpMessageComponent::try_from(line.as_str()).unwrap();
        component_lines.push(component);
    }

    let mut sig_params = HttpSignatureParams::try_new(&component_ids).unwrap();
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sig_params.set_created(created);

    let httpsig_secret = SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes).unwrap();
    sig_params.set_key_info(&httpsig_secret);
    sig_params.set_keyid(&public_key_base58);

    let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params).unwrap();
    let sig_headers = signature_base
        .build_signature_headers(&httpsig_secret, Some("sig1"))
        .unwrap();

    println!("Authority signed: '{}'", authority);
    println!("Host header will be: '{}'", authority);

    // Connect to server but send Host: localhost (without port!)
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: {}\r\n\
         Signature-Input: {}\r\n\
         Signature: {}\r\n\
         Connection: close\r\n\
         \r\n",
        path,
        authority, // "localhost" without port
        authorization,
        sig_headers.signature_input_header_value(),
        sig_headers.signature_header_value()
    );

    println!("=== Request ===\n{}", request);

    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    println!("=== Response ===\n{}", response_str);

    // This should pass - we signed with "localhost" and sent Host: localhost
    assert!(
        response_str.contains("200 OK"),
        "Request with localhost authority should succeed. Got:\n{}",
        response_str
    );
}

/// Test using axum_server (like the live server) instead of axum::serve
#[tokio::test]
async fn test_with_axum_server_localhost_authority() {
    use std::time::{SystemTime, UNIX_EPOCH};

    use biscuit_auth::{
        KeyPair, PrivateKey,
        builder::{Algorithm, BiscuitBuilder},
    };
    use httpsig::prelude::{
        AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
        message_component::{
            HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName,
        },
    };
    use p256::ecdsa::SigningKey;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    // Setup keys
    let root_key_base58 = "ByDGSRM82bqEVQoGYpZzvmmHujrB32UN1sr7WbKN6TPQ";
    let root_key = RootKey::from_base58(root_key_base58).unwrap();
    let key_bytes = bs58::decode(root_key_base58).into_vec().unwrap();
    let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
    let public_key = signing_key.verifying_key();
    let public_key_base58 =
        bs58::encode(public_key.to_encoded_point(true).as_bytes()).into_string();

    // Create token
    let biscuit_private = PrivateKey::from_bytes(&key_bytes, Algorithm::Secp256r1).unwrap();
    let biscuit_keypair = KeyPair::from(&biscuit_private);
    let expires_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    let mut builder = BiscuitBuilder::new();
    builder = builder
        .fact(format!("public_key(\"{}\")", public_key_base58).as_str())
        .unwrap();
    builder = builder
        .fact(format!("expires({})", expires_ts).as_str())
        .unwrap();
    builder = builder
        .check(format!("check if time($t), $t < {}", expires_ts).as_str())
        .unwrap();
    builder = builder.fact("op_group(\"account\", \"read\")").unwrap();
    builder = builder.fact("basin_scope(\"prefix\", \"\")").unwrap();

    let biscuit = builder.build(&biscuit_keypair).unwrap();
    let token_base64 = base64ct::Base64::encode_string(&biscuit.to_vec().unwrap());

    // Start server using axum_server (like the live server does!)
    let app = create_test_app(root_key).await;

    // Get a random port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release the port so axum_server can bind to it

    println!("Starting axum_server on {}", addr);

    let app_clone = app.clone();
    tokio::spawn(async move {
        axum_server::bind(addr)
            .serve(app_clone.into_make_service())
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let authorization = format!("Bearer {}", token_base64);

    // Use "localhost" as authority WITHOUT port (like SDK does for http://localhost)
    let authority = "localhost";
    let path = "/test";
    let method = "GET";

    // Sign request
    let component_ids: Vec<HttpMessageComponentId> =
        ["@method", "@path", "@authority", "authorization"]
            .iter()
            .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
            .collect();

    let mut component_lines = Vec::new();
    for id in &component_ids {
        let line = match &id.name {
            HttpMessageComponentName::Derived(derived) => {
                let derived_str: &str = derived.as_ref();
                let value = match derived_str {
                    "@method" => method.to_uppercase(),
                    "@path" => path.to_string(),
                    "@authority" => authority.to_string(),
                    other => panic!("unexpected: {}", other),
                };
                format!("\"{}\": {}", derived_str, value)
            }
            HttpMessageComponentName::HttpField(name) => {
                format!("\"{}\": {}", name, authorization)
            }
        };
        let component = HttpMessageComponent::try_from(line.as_str()).unwrap();
        component_lines.push(component);
    }

    let mut sig_params = HttpSignatureParams::try_new(&component_ids).unwrap();
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sig_params.set_created(created);

    let httpsig_secret = SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes).unwrap();
    sig_params.set_key_info(&httpsig_secret);
    sig_params.set_keyid(&public_key_base58);

    let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params).unwrap();
    let sig_headers = signature_base
        .build_signature_headers(&httpsig_secret, Some("sig1"))
        .unwrap();

    println!("Authority signed: '{}'", authority);

    // Connect to server
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: {}\r\n\
         Signature-Input: {}\r\n\
         Signature: {}\r\n\
         Connection: close\r\n\
         \r\n",
        path,
        authority,
        authorization,
        sig_headers.signature_input_header_value(),
        sig_headers.signature_header_value()
    );

    println!("=== Request ===\n{}", request);

    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    println!("=== Response ===\n{}", response_str);

    assert!(
        response_str.contains("200 OK"),
        "Request with axum_server should succeed. Got:\n{}",
        response_str
    );
}

/// Test with nested router (like the live server uses)
/// The key issue: when using .nest("/v1", ...), does the middleware see "/v1/basins" or "/basins"?
#[tokio::test]
async fn test_nested_router_path_stripping() {
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::{Router, middleware::from_fn_with_state, routing::get};
    use biscuit_auth::{
        KeyPair, PrivateKey,
        builder::{Algorithm, BiscuitBuilder},
    };
    use httpsig::prelude::{
        AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
        message_component::{
            HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName,
        },
    };
    use p256::ecdsa::SigningKey;
    use s2_lite::handlers::v1::middleware::{AppState, auth_middleware};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    // Setup keys
    let root_key_base58 = "ByDGSRM82bqEVQoGYpZzvmmHujrB32UN1sr7WbKN6TPQ";
    let root_key = RootKey::from_base58(root_key_base58).unwrap();
    let key_bytes = bs58::decode(root_key_base58).into_vec().unwrap();
    let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
    let public_key = signing_key.verifying_key();
    let public_key_base58 =
        bs58::encode(public_key.to_encoded_point(true).as_bytes()).into_string();

    // Create token
    let biscuit_private = PrivateKey::from_bytes(&key_bytes, Algorithm::Secp256r1).unwrap();
    let biscuit_keypair = KeyPair::from(&biscuit_private);
    let expires_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    let mut builder = BiscuitBuilder::new();
    builder = builder
        .fact(format!("public_key(\"{}\")", public_key_base58).as_str())
        .unwrap();
    builder = builder
        .fact(format!("expires({})", expires_ts).as_str())
        .unwrap();
    builder = builder
        .check(format!("check if time($t), $t < {}", expires_ts).as_str())
        .unwrap();
    builder = builder.fact("op_group(\"account\", \"read\")").unwrap();
    builder = builder.fact("basin_scope(\"prefix\", \"\")").unwrap();

    let biscuit = builder.build(&biscuit_keypair).unwrap();
    let token_base64 = base64ct::Base64::encode_string(&biscuit.to_vec().unwrap());

    // Create app with NESTED router structure like the live server
    let object_store = std::sync::Arc::new(slatedb::object_store::memory::InMemory::new());
    let db = slatedb::Db::builder("test", object_store)
        .build()
        .await
        .unwrap();
    let backend = s2_lite::backend::Backend::new(db, bytesize::ByteSize::b(1));
    let auth_state = s2_lite::auth::AuthState::new(root_key, 300, None);

    let app_state = AppState {
        backend,
        auth: auth_state,
    };

    // Create a nested router like the live server
    let nested_routes = Router::new()
        .route("/basins", get(|| async { "ok" }))
        .route_layer(from_fn_with_state(app_state.clone(), auth_middleware));

    let app = Router::new()
        .nest("/v1", nested_routes)
        .with_state(app_state);

    // Start server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("Test server with nested routes listening on {}", addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let authorization = format!("Bearer {}", token_base64);

    // Sign with the FULL path /v1/basins (what the client sends)
    let authority = "localhost";
    let path = "/v1/basins"; // FULL path as sent by client
    let method = "GET";

    let component_ids: Vec<HttpMessageComponentId> =
        ["@method", "@path", "@authority", "authorization"]
            .iter()
            .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
            .collect();

    let mut component_lines = Vec::new();
    for id in &component_ids {
        let line = match &id.name {
            HttpMessageComponentName::Derived(derived) => {
                let derived_str: &str = derived.as_ref();
                let value = match derived_str {
                    "@method" => method.to_uppercase(),
                    "@path" => path.to_string(),
                    "@authority" => authority.to_string(),
                    other => panic!("unexpected: {}", other),
                };
                format!("\"{}\": {}", derived_str, value)
            }
            HttpMessageComponentName::HttpField(name) => {
                format!("\"{}\": {}", name, authorization)
            }
        };
        let component = HttpMessageComponent::try_from(line.as_str()).unwrap();
        component_lines.push(component);
    }

    let mut sig_params = HttpSignatureParams::try_new(&component_ids).unwrap();
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sig_params.set_created(created);

    let httpsig_secret = SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes).unwrap();
    sig_params.set_key_info(&httpsig_secret);
    sig_params.set_keyid(&public_key_base58);

    let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params).unwrap();
    let sig_headers = signature_base
        .build_signature_headers(&httpsig_secret, Some("sig1"))
        .unwrap();

    println!("Path signed: '{}'", path);
    println!("Authority signed: '{}'", authority);

    // Connect and send request with FULL path /v1/basins
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: {}\r\n\
         Signature-Input: {}\r\n\
         Signature: {}\r\n\
         Connection: close\r\n\
         \r\n",
        path, // /v1/basins
        authority,
        authorization,
        sig_headers.signature_input_header_value(),
        sig_headers.signature_header_value()
    );

    println!("=== Request ===\n{}", request);

    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    println!("=== Response ===\n{}", response_str);

    // This will tell us if the nested router strips the /v1 prefix before auth middleware
    assert!(
        response_str.contains("200 OK"),
        "If this fails, the middleware is seeing a different path than what we signed. Got:\n{}",
        response_str
    );
}

/// Test against LIVE server on localhost:80 using raw TCP.
/// Run this with: cargo test test_live_server_localhost -- --nocapture --ignored
#[tokio::test]
#[ignore] // Only run manually when server is running on localhost:80
async fn test_live_server_localhost() {
    use std::time::{SystemTime, UNIX_EPOCH};

    use biscuit_auth::{
        KeyPair, PrivateKey,
        builder::{Algorithm, BiscuitBuilder},
    };
    use httpsig::prelude::{
        AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
        message_component::{
            HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName,
        },
    };
    use p256::ecdsa::SigningKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Setup keys - use the actual root key
    let root_key_base58 = "ByDGSRM82bqEVQoGYpZzvmmHujrB32UN1sr7WbKN6TPQ";
    let key_bytes = bs58::decode(root_key_base58).into_vec().unwrap();
    let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
    let public_key = signing_key.verifying_key();
    let public_key_base58 =
        bs58::encode(public_key.to_encoded_point(true).as_bytes()).into_string();

    println!("Public key: {}", public_key_base58);

    // Create token exactly like CLI does
    let biscuit_private = PrivateKey::from_bytes(&key_bytes, Algorithm::Secp256r1).unwrap();
    let biscuit_keypair = KeyPair::from(&biscuit_private);
    let expires_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    let mut builder = BiscuitBuilder::new();
    builder = builder
        .fact(format!("public_key(\"{}\")", public_key_base58).as_str())
        .unwrap();
    builder = builder
        .fact(format!("expires({})", expires_ts).as_str())
        .unwrap();
    builder = builder
        .check(format!("check if time($t), $t < {}", expires_ts).as_str())
        .unwrap();
    builder = builder.fact("op_group(\"account\", \"read\")").unwrap();
    builder = builder.fact("op_group(\"account\", \"write\")").unwrap();
    builder = builder.fact("basin_scope(\"prefix\", \"\")").unwrap();

    let biscuit = builder.build(&biscuit_keypair).unwrap();

    println!("=== Biscuit block source ===");
    println!("{}", biscuit.print_block_source(0).unwrap());

    let token_base64 = base64ct::Base64::encode_string(&biscuit.to_vec().unwrap());
    let authorization = format!("Bearer {}", token_base64);

    // Sign for localhost (no port - default 80)
    let authority = "localhost";
    let path = "/v1/basins";
    let method = "GET";

    let component_ids: Vec<HttpMessageComponentId> =
        ["@method", "@path", "@authority", "authorization"]
            .iter()
            .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
            .collect();

    let mut component_lines = Vec::new();
    for id in &component_ids {
        let line = match &id.name {
            HttpMessageComponentName::Derived(derived) => {
                let derived_str: &str = derived.as_ref();
                let value = match derived_str {
                    "@method" => method.to_uppercase(),
                    "@path" => path.to_string(),
                    "@authority" => authority.to_string(),
                    other => panic!("unexpected: {}", other),
                };
                format!("\"{}\": {}", derived_str, value)
            }
            HttpMessageComponentName::HttpField(name) => {
                format!("\"{}\": {}", name, authorization)
            }
        };
        let component = HttpMessageComponent::try_from(line.as_str()).unwrap();
        component_lines.push(component);
    }

    let mut sig_params = HttpSignatureParams::try_new(&component_ids).unwrap();
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sig_params.set_created(created);

    let httpsig_secret = SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes).unwrap();
    sig_params.set_key_info(&httpsig_secret);
    sig_params.set_keyid(&public_key_base58);

    let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params).unwrap();
    let sig_headers = signature_base
        .build_signature_headers(&httpsig_secret, Some("sig1"))
        .unwrap();

    println!("=== Signature ===");
    println!("Authority signed: {}", authority);
    println!("Path signed: {}", path);
    println!(
        "Signature-Input: {}",
        sig_headers.signature_input_header_value()
    );

    // Connect to localhost:80
    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:80")
        .await
        .expect("Failed to connect to localhost:80 - is the server running?");

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: {}\r\n\
         Signature-Input: {}\r\n\
         Signature: {}\r\n\
         Connection: close\r\n\
         \r\n",
        path,
        authority,
        authorization,
        sig_headers.signature_input_header_value(),
        sig_headers.signature_header_value()
    );

    println!("=== Request ===\n{}", request);

    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    println!("=== Response ===\n{}", response_str);

    assert!(
        response_str.contains("200 OK"),
        "Should get 200 OK, got:\n{}",
        response_str
    );
}
