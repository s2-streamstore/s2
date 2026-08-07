use std::collections::HashMap;

use axum::{Json, extract::Form, routing::post};

use super::*;
use crate::config::{DEFAULT_ACCOUNT_ENDPOINT, DEFAULT_BASIN_ENDPOINT};

#[derive(Clone)]
struct FakeOAuthState {
    issuer: String,
    requests: Arc<Mutex<Vec<HashMap<String, String>>>>,
}

async fn fake_metadata(State(state): State<FakeOAuthState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/oauth/authorize", state.issuer),
        "token_endpoint": format!("{}/oauth/token", state.issuer),
        "revocation_endpoint": format!("{}/oauth/token/revoke", state.issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["offline_access", "user:org:read"],
        "code_challenge_methods_supported": ["S256"]
    }))
}

async fn fake_token(
    State(state): State<FakeOAuthState>,
    Form(form): Form<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let grant_type = form.get("grant_type").cloned();
    state.requests.lock().unwrap().push(form);
    match grant_type.as_deref() {
        Some("authorization_code") => Json(serde_json::json!({
            "access_token": "first-access",
            "refresh_token": "first-refresh",
            "expires_in": 3600,
            "token_type": "bearer",
            "scope": OAUTH_SCOPES
        })),
        Some("refresh_token") => Json(serde_json::json!({
            "access_token": "second-access",
            "expires_in": 3600,
            "token_type": "bearer",
            "scope": OAUTH_SCOPES
        })),
        _ => Json(serde_json::json!({
            "error": "unsupported_grant_type"
        })),
    }
}

async fn fake_revoke(
    State(state): State<FakeOAuthState>,
    Form(form): Form<HashMap<String, String>>,
) -> StatusCode {
    state.requests.lock().unwrap().push(form);
    StatusCode::OK
}

fn oauth_session() -> OAuthSession {
    OAuthSession {
        issuer: "https://clerk.s2.dev/".to_owned(),
        client_id: "client_123".to_owned(),
        account_endpoint: DEFAULT_ACCOUNT_ENDPOINT.to_owned(),
        basin_endpoint: DEFAULT_BASIN_ENDPOINT.to_owned(),
        credential_id: "credential_123".to_owned(),
        credential_store: CredentialStore::File,
    }
}

fn test_token_set() -> TokenSet {
    TokenSet {
        access_token: "access-token".to_owned().into(),
        refresh_token: "refresh-token".to_owned().into(),
        expires_at: u64::MAX,
    }
}

fn test_jwt(sub: &str, org_id: &str) -> SecretString {
    let payload = serde_json::to_vec(&serde_json::json!({
        "sub": sub,
        "org_id": org_id,
    }))
    .unwrap();
    format!(
        "header.{}.signature",
        Base64UrlUnpadded::encode_string(&payload)
    )
    .into()
}

#[test]
fn replacement_grant_reuse_requires_the_same_known_identity() {
    let previous_session = oauth_session();
    let next_session = oauth_session();
    let mut previous_tokens = test_token_set();
    previous_tokens.access_token = test_jwt("user_1", "org_1");
    let mut next_tokens = test_token_set();
    next_tokens.access_token = test_jwt("user_1", "org_1");

    assert!(oauth_grant_may_be_reused(
        &previous_session,
        Some(&previous_tokens),
        &next_session,
        &next_tokens,
    ));

    next_tokens.access_token = test_jwt("user_1", "org_2");
    assert!(!oauth_grant_may_be_reused(
        &previous_session,
        Some(&previous_tokens),
        &next_session,
        &next_tokens,
    ));
}

#[test]
fn production_browser_credentials_are_bound_to_production_transport() {
    let mut credential = ResolvedCredential {
        access_token: "access".to_owned().into(),
        source: TokenSource::BrowserLogin,
        oauth_session: Some(oauth_session()),
        oauth_tokens: None,
    };
    credential
        .validate_destination(&CliConfig::default())
        .unwrap();

    let custom = CliConfig {
        account_endpoint: Some("https://attacker.example".to_owned()),
        basin_endpoint: Some("https://{basin}.attacker.example".to_owned()),
        ..CliConfig::default()
    };
    assert!(matches!(
        credential.validate_destination(&custom),
        Err(LoginError::UnsafeBrowserDestination)
    ));

    let insecure = CliConfig {
        ssl_no_verify: Some(true),
        ..CliConfig::default()
    };
    assert!(matches!(
        credential.validate_destination(&insecure),
        Err(LoginError::UnsafeBrowserDestination)
    ));

    let staging = CliConfig {
        account_endpoint: Some("https://cell.o-staging.aws.s2.dev".to_owned()),
        basin_endpoint: Some("https://{basin}.b-staging.aws.s2.dev".to_owned()),
        ..CliConfig::default()
    };
    let staging_session = OAuthSession {
        issuer: "https://staging-clerk.example/".to_owned(),
        account_endpoint: staging.account_endpoint.clone().unwrap(),
        basin_endpoint: staging.basin_endpoint.clone().unwrap(),
        ..oauth_session()
    };
    credential.oauth_session = Some(staging_session);
    credential.validate_destination(&staging).unwrap();
    assert!(matches!(
        credential.validate_destination(&custom),
        Err(LoginError::UnsafeBrowserDestination)
    ));

    let loopback = CliConfig {
        account_endpoint: Some("http://127.0.0.1:4243".to_owned()),
        basin_endpoint: Some("http://localhost:4243".to_owned()),
        ..CliConfig::default()
    };
    credential.oauth_session = Some(OAuthSession {
        issuer: "http://127.0.0.1:3000/".to_owned(),
        account_endpoint: loopback.account_endpoint.clone().unwrap(),
        basin_endpoint: loopback.basin_endpoint.clone().unwrap(),
        ..oauth_session()
    });
    credential.validate_destination(&loopback).unwrap();

    assert!(
        validate_endpoint_binding(
            "https://staging-clerk.example",
            "ftp://localhost:4243",
            "ftp://localhost:4243",
            false,
        )
        .is_err()
    );
}

fn metadata() -> AuthorizationServerMetadata {
    serde_json::from_value(serde_json::json!({
        "issuer": "https://clerk.s2.dev",
        "authorization_endpoint": "https://clerk.s2.dev/oauth/authorize",
        "token_endpoint": "https://clerk.s2.dev/oauth/token",
        "revocation_endpoint": "https://clerk.s2.dev/oauth/token/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["offline_access", "user:org:read"],
        "code_challenge_methods_supported": ["S256"]
    }))
    .unwrap()
}

#[test]
fn rfc_7636_pkce_vector() {
    let pkce = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned());
    assert_eq!(
        pkce.challenge,
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn authorization_url_contains_oauth_and_pkce_parameters() {
    let endpoint = Url::parse("https://clerk.s2.dev/oauth/authorize").unwrap();
    let url = authorization_url(
        &endpoint,
        "client_123",
        "http://127.0.0.1:34567/callback",
        "expected-state",
        "challenge",
    );
    let params = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<HashMap<_, _>>();

    assert_eq!(
        params.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        params.get("client_id").map(String::as_str),
        Some("client_123")
    );
    assert_eq!(
        params.get("redirect_uri").map(String::as_str),
        Some("http://127.0.0.1:34567/callback")
    );
    assert_eq!(params.get("scope").map(String::as_str), Some(OAUTH_SCOPES));
    assert_eq!(
        params.get("state").map(String::as_str),
        Some("expected-state")
    );
    assert_eq!(
        params.get("code_challenge").map(String::as_str),
        Some("challenge")
    );
    assert_eq!(
        params.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
}

#[test]
fn validates_clerk_metadata_and_rejects_cross_origin_endpoints() {
    let issuer = Url::parse("https://clerk.s2.dev").unwrap();
    let endpoints = validate_metadata(&issuer, metadata()).unwrap();
    assert_eq!(
        endpoints.revocation.as_str(),
        "https://clerk.s2.dev/oauth/token/revoke"
    );

    let mut malicious = metadata();
    malicious.token_endpoint = "https://attacker.example/token".to_owned();
    assert!(validate_metadata(&issuer, malicious).is_err());

    let mut without_revocation = metadata();
    without_revocation.revocation_endpoint = None;
    assert!(validate_metadata(&issuer, without_revocation).is_err());
}

#[tokio::test]
async fn exchanges_refreshes_and_revokes_with_standard_oauth_forms() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(fake_metadata),
        )
        .route("/oauth/token", post(fake_token))
        .route("/oauth/token/revoke", post(fake_revoke))
        .with_state(FakeOAuthState {
            issuer: issuer.clone(),
            requests: requests.clone(),
        });
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    let http = oauth_http_client().unwrap();
    let issuer_url = oauth_issuer(Some(&issuer)).unwrap();
    let endpoints = discover(&http, &issuer_url).await.unwrap();
    let first = exchange_code(
        &http,
        &endpoints,
        "client_123",
        "http://127.0.0.1:34567/callback",
        "authorization-code",
        "pkce-verifier",
    )
    .await
    .unwrap();
    let second = refresh_token(&http, &endpoints, "client_123", &first.refresh_token)
        .await
        .unwrap();
    revoke_token(&http, &endpoints, "client_123", &second.refresh_token)
        .await
        .unwrap();

    assert_eq!(first.access_token.expose_secret(), "first-access");
    assert_eq!(second.access_token.expose_secret(), "second-access");
    assert_eq!(second.refresh_token.expose_secret(), "first-refresh");
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].get("grant_type").unwrap(), "authorization_code");
        assert_eq!(requests[0].get("code").unwrap(), "authorization-code");
        assert_eq!(requests[0].get("code_verifier").unwrap(), "pkce-verifier");
        assert_eq!(
            requests[0].get("redirect_uri").unwrap(),
            "http://127.0.0.1:34567/callback"
        );
        assert_eq!(requests[1].get("grant_type").unwrap(), "refresh_token");
        assert_eq!(requests[1].get("refresh_token").unwrap(), "first-refresh");
        assert_eq!(requests[2].get("token").unwrap(), "first-refresh");
        assert_eq!(requests[2].get("token_type_hint").unwrap(), "refresh_token");
    }

    server.abort();
    let _ = server.await;
}

#[test]
fn issuer_requires_https_except_on_loopback() {
    assert!(oauth_issuer(Some("https://clerk.s2.dev")).is_ok());
    assert!(oauth_issuer(Some("http://127.0.0.1:3000")).is_ok());
    assert!(oauth_issuer(Some("http://localhost:3000")).is_ok());
    assert!(oauth_issuer(Some("http://clerk.s2.dev")).is_err());
    assert!(oauth_issuer(Some("https://user@clerk.s2.dev")).is_err());
    assert!(oauth_issuer(Some("https://clerk.s2.dev/path")).is_err());
}

#[test]
fn credential_precedence_is_environment_then_explicit_method_then_legacy_fallback() {
    let mut config = CliConfig {
        access_token: Some("static-token".to_owned()),
        auth_method: Some(AuthMethod::BrowserLogin),
        oauth: Some(oauth_session()),
        ..CliConfig::default()
    };

    assert_eq!(
        credential_choice(&config, true).unwrap(),
        CredentialChoice::Environment
    );
    assert_eq!(
        credential_choice(&config, false).unwrap(),
        CredentialChoice::BrowserLogin
    );

    config.auth_method = Some(AuthMethod::AccessToken);
    assert_eq!(
        credential_choice(&config, false).unwrap(),
        CredentialChoice::StoredAccessToken
    );

    config.auth_method = None;
    assert_eq!(
        credential_choice(&config, false).unwrap(),
        CredentialChoice::StoredAccessToken
    );
    config.access_token = None;
    assert_eq!(
        credential_choice(&config, false).unwrap(),
        CredentialChoice::BrowserLogin
    );
}

#[test]
fn oauth_provider_tracks_rejected_tokens_without_exposing_them_in_debug_output() {
    let provider = OAuthAccessTokenProvider::new(oauth_session(), test_token_set());
    provider.invalidate_access_token("rejected-secret-token");

    assert!(
        provider
            .rejected_access_tokens
            .lock()
            .unwrap()
            .contains("rejected-secret-token")
    );
    assert!(!format!("{provider:?}").contains("rejected-secret-token"));
}

#[tokio::test]
async fn callback_rejects_wrong_state_without_consuming_code_receiver() {
    let (sender, receiver) = oneshot::channel();
    let state = CallbackState {
        expected_state: "expected".to_owned(),
        sender: Arc::new(Mutex::new(Some(sender))),
        completion_url: None,
    };

    let rejected = handle_callback(
        State(state.clone()),
        Query(CallbackQuery {
            code: Some("wrong-code".to_owned()),
            error: None,
            error_description: None,
            state: Some("wrong".to_owned()),
        }),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let accepted = handle_callback(
        State(state),
        Query(CallbackQuery {
            code: Some("right-code".to_owned()),
            error: None,
            error_description: None,
            state: Some("expected".to_owned()),
        }),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(accepted.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(
        accepted.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    assert_eq!(receiver.await.unwrap().unwrap(), "right-code");
}

#[tokio::test]
async fn callback_redirects_browser_to_website_without_exposing_code() {
    let (sender, receiver) = oneshot::channel();
    let response = handle_callback(
        State(CallbackState {
            expected_state: "expected".to_owned(),
            sender: Arc::new(Mutex::new(Some(sender))),
            completion_url: Some(Url::parse("https://staging.s2.dev/cli/login").unwrap()),
        }),
        Query(CallbackQuery {
            code: Some("secret-code".to_owned()),
            error: None,
            error_description: None,
            state: Some("expected".to_owned()),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        location,
        "https://staging.s2.dev/cli/login?status=authorized"
    );
    assert!(!location.contains("secret-code"));
    assert_eq!(receiver.await.unwrap().unwrap(), "secret-code");
}

#[tokio::test]
async fn callback_surfaces_provider_denial() {
    let (sender, receiver) = oneshot::channel();
    let denied = handle_callback(
        State(CallbackState {
            expected_state: "expected".to_owned(),
            sender: Arc::new(Mutex::new(Some(sender))),
            completion_url: None,
        }),
        Query(CallbackQuery {
            code: None,
            error: Some("access_denied".to_owned()),
            error_description: Some("The user denied access".to_owned()),
            state: Some("expected".to_owned()),
        }),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        receiver.await.unwrap().unwrap_err(),
        "access_denied: The user denied access"
    );
}

#[test]
fn refresh_token_rotation_is_optional() {
    for (returned, expected) in [(None, "old-refresh"), (Some("new-refresh"), "new-refresh")] {
        let response = TokenResponse {
            access_token: "new-access".to_owned(),
            refresh_token: returned.map(str::to_owned),
            expires_in: 3_600,
            token_type: "Bearer".to_owned(),
            scope: Some(OAUTH_SCOPES.to_owned()),
        };
        let tokens = token_set(response, Some("old-refresh")).unwrap();
        assert_eq!(tokens.refresh_token.expose_secret(), expected);
    }
}

#[test]
fn oauth_errors_do_not_echo_provider_payloads() {
    for (body, expected) in [
        (
            br#"{"error":"invalid_grant","error_description":"super-secret"}"#.as_slice(),
            "invalid_grant",
        ),
        (
            br#"{"error":"super-secret-refresh-token","error_description":"also-secret"}"#
                .as_slice(),
            "unknown error",
        ),
        (
            b"provider accidentally echoed super-secret-refresh-token".as_slice(),
            "unknown error",
        ),
    ] {
        let error = oauth_rejection("token refresh", StatusCode::BAD_REQUEST, body);
        assert!(matches!(
            error,
            LoginError::Rejected { message, .. }
                if message == expected && !message.contains("secret")
        ));
    }
}
