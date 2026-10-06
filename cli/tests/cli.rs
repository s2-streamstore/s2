use std::{
    convert::Infallible,
    net::TcpListener,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};

use assert_cmd::Command;
use base64ct::{Base64UrlUnpadded, Encoding};
use predicates::prelude::*;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

struct TestEnv {
    home: TempDir,
}

struct TestServer {
    endpoint: String,
    handle: JoinHandle<String>,
}

impl TestServer {
    /// Serves one HTTP/2 request and returns the request line and headers it
    /// saw. The client speaks h2 with prior knowledge over cleartext.
    fn start() -> Self {
        Self::start_with(
            axum::http::StatusCode::OK,
            r#"{"basins":[],"has_more":false}"#.to_owned(),
        )
    }

    /// Serves one HTTP/2 request responding with `status` and `body` (sent
    /// verbatim as the response body).
    fn start_with(status: axum::http::StatusCode, body: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let endpoint = format!("http://{}", listener.local_addr().expect("server address"));
        let handle = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(serve_one_request(listener, status, body))
        });
        Self { endpoint, handle }
    }

    fn finish(self) -> String {
        self.handle.join().expect("test server")
    }
}

const TEST_SERVER_TIMEOUT: Duration = Duration::from_secs(10);

async fn serve_one_request(
    listener: TcpListener,
    status: axum::http::StatusCode,
    body: String,
) -> String {
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    let (stream, _) = tokio::time::timeout(TEST_SERVER_TIMEOUT, listener.accept())
        .await
        .expect("timed out waiting for a connection")
        .expect("accept connection");

    let observed = Arc::new(Mutex::new(None));
    let captured = observed.clone();
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let captured = captured.clone();
        let body = body.clone();
        async move {
            let mut rendered = format!("{} {}\r\n", req.method(), req.uri());
            for (name, value) in req.headers() {
                rendered.push_str(name.as_str());
                rendered.push_str(": ");
                rendered.push_str(value.to_str().unwrap_or_default());
                rendered.push_str("\r\n");
            }
            *captured.lock().expect("capture request") = Some(rendered);

            Ok::<_, Infallible>(
                hyper::Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                    .expect("build response"),
            )
        }
    });

    // A client that exits right after its response can reset the connection,
    // so the served result only matters when no request came through.
    let served = tokio::time::timeout(
        TEST_SERVER_TIMEOUT,
        hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service),
    )
    .await;

    let observed = observed.lock().expect("read request").take();
    observed.unwrap_or_else(|| panic!("server received no HTTP/2 request: {served:?}"))
}

impl TestEnv {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().expect("temp home dir"),
        }
    }

    fn s2(&self) -> Command {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("s2"));
        cmd.env("HOME", self.home.path());
        cmd.env("XDG_CONFIG_HOME", self.home.path().join(".config"));
        cmd.env("APPDATA", self.home.path());
        cmd.env("USERPROFILE", self.home.path());
        for key in [
            "S2_ACCESS_TOKEN",
            "S2_ACCOUNT_ENDPOINT",
            "S2_BASIN_ENDPOINT",
            "S2_COMPRESSION",
            "S2_SSL_NO_VERIFY",
        ] {
            cmd.env_remove(key);
        }
        cmd
    }

    fn config_dir(&self) -> std::path::PathBuf {
        #[cfg(windows)]
        return self.home.path().join("s2");
        #[cfg(not(windows))]
        return self.home.path().join(".config/s2");
    }

    fn remember_access_token(&self, token: &str) {
        self.s2()
            .args([
                "auth",
                "access-token",
                "set",
                "--stdin",
                "--insecure-storage",
            ])
            .write_stdin(token)
            .assert()
            .success();
    }
}

#[test]
fn invalid_uri_scheme() {
    TestEnv::new()
        .s2()
        .args(["get-stream-config", "foo://invalid/stream"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("s2://"));
}

#[test]
fn missing_stream_in_uri() {
    TestEnv::new()
        .s2()
        .args(["get-stream-config", "s2://basin-only"])
        .assert()
        .failure();
}

#[test]
fn invalid_basin_name() {
    TestEnv::new()
        .s2()
        .args(["create-basin", "-invalid-name"])
        .assert()
        .failure();
}

#[test]
fn missing_access_token() {
    let env = TestEnv::new();
    let mut cmd = env.s2();
    cmd.args(["list-basins"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("access token"));
}

#[test]
fn access_token_set_requires_stdin_flag_for_non_interactive_input() {
    TestEnv::new()
        .s2()
        .args(["auth", "access-token", "set", "--insecure-storage"])
        .write_stdin("do-not-print-this-token")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("--stdin")
                .and(predicate::str::contains("do-not-print-this-token").not()),
        );
}

#[test]
fn private_file_access_token_authenticates_without_leaking_to_config() {
    let env = TestEnv::new();
    env.remember_access_token("remembered-secret");

    let config_dir = env.config_dir();
    let config = std::fs::read_to_string(config_dir.join("config.toml")).expect("read config");
    assert!(!config.contains("remembered-secret"));
    assert!(config.contains("stored_access_token"));

    let server = TestServer::start();
    env.s2()
        .env("S2_ACCOUNT_ENDPOINT", &server.endpoint)
        .env("S2_BASIN_ENDPOINT", &server.endpoint)
        .args(["list-basins", "--limit", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("remembered-secret").not())
        .stderr(predicate::str::contains("remembered-secret").not());
    let request = server.finish().to_ascii_lowercase();
    assert!(request.contains("authorization: bearer remembered-secret"));
}

#[test]
fn environment_access_token_overrides_a_stored_token() {
    let env = TestEnv::new();
    env.remember_access_token("stored-secret");
    let server = TestServer::start();

    env.s2()
        .env("S2_ACCESS_TOKEN", "environment-secret")
        .env("S2_ACCOUNT_ENDPOINT", &server.endpoint)
        .env("S2_BASIN_ENDPOINT", &server.endpoint)
        .args(["list-basins", "--limit", "1"])
        .assert()
        .success();

    let request = server.finish().to_ascii_lowercase();
    assert!(request.contains("authorization: bearer environment-secret"));
    assert!(!request.contains("stored-secret"));
}

#[test]
fn legacy_plaintext_access_token_can_be_migrated_to_a_private_file() {
    let env = TestEnv::new();
    let config_dir = env.config_dir();
    std::fs::create_dir_all(&config_dir).expect("create config directory");
    let config_path = config_dir.join("config.toml");
    std::fs::write(&config_path, "access_token = \"legacy-secret\"\n").expect("write config");

    env.s2()
        .args(["auth", "access-token", "migrate", "--insecure-storage"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Legacy access token migrated")
                .and(predicate::str::contains("  - Access token saved to:"))
                .and(predicate::str::contains("  - Configuration saved to:"))
                .and(predicate::str::contains("Previous access token replaced").not())
                .and(predicate::str::contains("legacy-secret").not()),
        );

    let config = std::fs::read_to_string(&config_path).expect("read migrated config");
    assert!(!config.contains("legacy-secret"));
    assert!(!config.contains("access_token ="));
    assert!(config.contains("stored_access_token"));
    let credential = std::fs::read_dir(&config_dir)
        .expect("list config directory")
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("access-token-")
        })
        .expect("stored access-token file");
    assert!(
        std::fs::read_to_string(credential.path())
            .expect("read credential")
            .contains("legacy-secret")
    );
}

#[test]
fn removing_a_stored_access_token_deletes_its_local_credential() {
    let env = TestEnv::new();
    env.remember_access_token("removable-secret");
    let config_dir = env.config_dir();

    env.s2()
        .args(["auth", "access-token", "remove"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Access token removed")
                .and(predicate::str::contains("removable-secret").not())
                .and(predicate::str::contains(
                    "This does not revoke the access token.",
                )),
        );

    let config = std::fs::read_to_string(config_dir.join("config.toml")).expect("read config");
    assert!(!config.contains("stored_access_token"));
    assert!(
        std::fs::read_dir(config_dir)
            .expect("list config directory")
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with("access-token-"))
    );
}

#[test]
fn config_commands_never_print_stored_or_legacy_tokens() {
    let stored = TestEnv::new();
    stored.remember_access_token("never-print-stored");
    stored
        .s2()
        .args(["config", "list"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("access_token = <redacted>")
                .and(predicate::str::contains("never-print-stored").not()),
        );
    stored
        .s2()
        .args(["config", "get", "access_token"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("cannot be read")
                .and(predicate::str::contains("never-print-stored").not()),
        );

    let legacy = TestEnv::new();
    let config_dir = legacy.config_dir();
    std::fs::create_dir_all(&config_dir).expect("create config directory");
    std::fs::write(
        config_dir.join("config.toml"),
        "access_token = \"never-print-legacy\"\n",
    )
    .expect("write config");
    legacy
        .s2()
        .args(["config", "list"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("access_token = <redacted>")
                .and(predicate::str::contains("never-print-legacy").not()),
        );
}

#[test]
fn diff_bare_names_require_resource_before_authentication() {
    TestEnv::new()
        .s2()
        .args(["diff", "token-left", "token-right"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Cannot infer a resource type")
                .and(predicate::str::contains("--resource"))
                .and(predicate::str::contains("access token is required").not()),
        );
}

#[test]
fn unknown_subcommand() {
    TestEnv::new()
        .s2()
        .args(["unknown-command"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

#[test]
fn config_list() {
    TestEnv::new()
        .s2()
        .args(["config", "list"])
        .assert()
        .success();
}

#[test]
fn config_set_and_get() {
    let env = TestEnv::new();
    env.s2()
        .args(["config", "set", "compression", "zstd"])
        .assert()
        .success();
    env.s2()
        .args(["config", "get", "compression"])
        .assert()
        .success()
        .stdout(predicate::str::contains("zstd"));
    env.s2()
        .args(["config", "unset", "compression"])
        .assert()
        .success();
}

#[cfg(unix)]
#[test]
fn config_set_writes_private_config() {
    let env = TestEnv::new();
    env.s2()
        .args(["config", "set", "compression", "zstd"])
        .assert()
        .success();

    let config_dir = env.config_dir();
    assert_eq!(mode(&config_dir), 0o700);
    assert_eq!(mode(&config_dir.join("config.toml")), 0o600);
}

#[test]
fn config_get_invalid_key() {
    TestEnv::new()
        .s2()
        .args(["config", "get", "invalid_key"])
        .assert()
        .failure();
}

#[test]
fn config_set_invalid_key() {
    TestEnv::new()
        .s2()
        .args(["config", "set", "invalid_key", "value"])
        .assert()
        .failure();
}

/// An invalid endpoint set via the config file should produce a source-agnostic
/// error message that points to both the config file and the environment
/// variables, without claiming the endpoints were loaded "from environment".
#[test]
fn invalid_endpoint_from_config_file() {
    let env = TestEnv::new();

    // Set up a token and malformed endpoints in the config file (realistic
    // typo: "https//" instead of "https://").
    env.remember_access_token("test-token");
    env.s2()
        .args(["config", "set", "account_endpoint", "https//a.s2.dev"])
        .assert()
        .success();
    env.s2()
        .args(["config", "set", "basin_endpoint", "https//b.s2.dev"])
        .assert()
        .success();

    let assert = env.s2().args(["list-basins"]).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);

    // The error should not misattribute the source to environment variables.
    assert!(
        !stderr.contains("from environment"),
        "stderr should not say 'from environment', got: {stderr}"
    );
    // The error should be source-agnostic.
    assert!(
        stderr.contains("Unable to parse S2 endpoints"),
        "stderr should say 'Unable to parse S2 endpoints', got: {stderr}"
    );
    // Help text should mention the config file path that was actually used.
    assert!(
        stderr.contains("config.toml"),
        "stderr should mention the config file path, got: {stderr}"
    );
    // Help text should mention both environment variable names.
    assert!(
        stderr.contains("S2_ACCOUNT_ENDPOINT") && stderr.contains("S2_BASIN_ENDPOINT"),
        "stderr should mention both S2_ACCOUNT_ENDPOINT and S2_BASIN_ENDPOINT, got: {stderr}"
    );
    // The underlying parse failure detail should still be surfaced.
    assert!(
        stderr.contains("invalid account endpoint"),
        "stderr should contain the underlying parse error, got: {stderr}"
    );
}

/// An invalid endpoint set via environment variables should produce the same
/// source-agnostic error message.
#[test]
fn invalid_endpoint_from_env() {
    let env = TestEnv::new();
    let mut cmd = env.s2();
    cmd.env("S2_ACCESS_TOKEN", "test-token");
    cmd.env("S2_ACCOUNT_ENDPOINT", "https//a.s2.dev");
    cmd.env("S2_BASIN_ENDPOINT", "https//b.s2.dev");

    let assert = cmd.args(["list-basins"]).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);

    assert!(
        !stderr.contains("from environment"),
        "stderr should not say 'from environment', got: {stderr}"
    );
    assert!(
        stderr.contains("Unable to parse S2 endpoints"),
        "stderr should say 'Unable to parse S2 endpoints', got: {stderr}"
    );
    assert!(
        stderr.contains("config.toml"),
        "stderr should mention the config file path, got: {stderr}"
    );
    assert!(
        stderr.contains("S2_ACCOUNT_ENDPOINT") && stderr.contains("S2_BASIN_ENDPOINT"),
        "stderr should mention both S2_ACCOUNT_ENDPOINT and S2_BASIN_ENDPOINT, got: {stderr}"
    );
}

/// When only the basin endpoint is malformed, the parse error for the basin
/// endpoint should still be surfaced with the source-agnostic message.
#[test]
fn invalid_basin_endpoint_from_config_file() {
    let env = TestEnv::new();

    env.remember_access_token("test-token");
    env.s2()
        .args(["config", "set", "account_endpoint", "https://a.s2.dev"])
        .assert()
        .success();
    env.s2()
        .args(["config", "set", "basin_endpoint", "https//b.s2.dev"])
        .assert()
        .success();

    let assert = env.s2().args(["list-basins"]).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);

    assert!(
        !stderr.contains("from environment"),
        "stderr should not say 'from environment', got: {stderr}"
    );
    assert!(
        stderr.contains("Unable to parse S2 endpoints"),
        "stderr should say 'Unable to parse S2 endpoints', got: {stderr}"
    );
    assert!(
        stderr.contains("invalid basin endpoint"),
        "stderr should contain the underlying basin parse error, got: {stderr}"
    );
}

/// When both endpoints parse individually but have mismatched schemes, the
/// `S2Endpoints::new` mismatch error should also use the source-agnostic
/// message rather than blaming the environment.
#[test]
fn mismatched_endpoint_schemes_from_config_file() {
    let env = TestEnv::new();

    env.remember_access_token("test-token");
    env.s2()
        .args(["config", "set", "account_endpoint", "https://a.s2.dev"])
        .assert()
        .success();
    env.s2()
        .args(["config", "set", "basin_endpoint", "http://{basin}.b.s2.dev"])
        .assert()
        .success();

    let assert = env.s2().args(["list-basins"]).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);

    assert!(
        !stderr.contains("from environment"),
        "stderr should not say 'from environment', got: {stderr}"
    );
    assert!(
        stderr.contains("Unable to parse S2 endpoints"),
        "stderr should say 'Unable to parse S2 endpoints', got: {stderr}"
    );
    assert!(
        stderr.contains("same scheme"),
        "stderr should mention the scheme mismatch, got: {stderr}"
    );
}

/// A command that sets only one endpoint should still warn (not error) and use
/// default endpoints, ensuring endpoint validation is not triggered in that
/// path. This guards against regressions in the partial-endpoint warnings.
#[test]
fn only_account_endpoint_set_warns_and_uses_defaults() {
    let env = TestEnv::new();

    env.remember_access_token("test-token");
    env.s2()
        .args(["config", "set", "account_endpoint", "https://a.s2.dev"])
        .assert()
        .success();

    // Should not produce an endpoint parse error; it should warn about the
    // missing basin endpoint and fall back to defaults. Without a reachable
    // server the command will fail, but it must fail with a network/connection
    // error, not an endpoint parse error.
    let assert = env.s2().args(["list-basins"]).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);

    assert!(
        stderr.contains("account endpoint is set but basin endpoint is not"),
        "stderr should warn about the partial endpoint config, got: {stderr}"
    );
    assert!(
        !stderr.contains("Unable to parse S2 endpoints"),
        "stderr should not report an endpoint parse error, got: {stderr}"
    );
}

// --- Auth-error recovery text is source-aware ------------------------------
//
// When the server rejects a request with an auth-class error code
// (`permission_denied` / 403 here) the CLI upgrades the operation error to
// `UnauthorizedAccessToken` and renders source-specific recovery guidance.
// These tests pin the end-to-end behavior: a browser-login user is told to run
// `s2 login` again (not to store an access token), and access-token sources keep
// access-token remediation.

/// OAuth credential `credential_id` used by the browser-login fixtures.
const OAUTH_CREDENTIAL_ID: &str = "test-credential-id";
/// A far-future expiry so the stored OAuth token is always fresh and the CLI
/// never attempts an OAuth refresh (which would require a reachable issuer).
const OAUTH_EXPIRES_AT: u64 = 4_000_000_000;

fn oauth_credential_file_path(config_dir: &std::path::Path) -> PathBuf {
    let digest = Sha256::digest(OAUTH_CREDENTIAL_ID.as_bytes());
    let filename = format!(
        "oauth-{}.json",
        Base64UrlUnpadded::encode_string(digest.as_slice())
    );
    config_dir.join(filename)
}

/// Writes a browser-login configuration (config.toml + stored OAuth credential
/// file) whose credentials point `account`/`basin` endpoints at `endpoint`.
/// The OAuth issuer is a loopback URL that is never contacted for non-refresh
/// flows (a 403 `permission_denied` does not trigger OAuth refresh).
fn install_browser_login(env: &TestEnv, endpoint: &str) {
    let config_dir = env.config_dir();
    std::fs::create_dir_all(&config_dir).expect("create config dir");

    let issuer = "http://127.0.0.1:3000";
    let config_toml = format!(
        "\
account_endpoint = \"{endpoint}\"
basin_endpoint = \"{endpoint}\"

[oauth]
issuer = \"{issuer}\"
client_id = \"test-client\"
account_endpoint = \"{endpoint}\"
basin_endpoint = \"{endpoint}\"
credential_id = \"{OAUTH_CREDENTIAL_ID}\"
credential_store = \"file\"
"
    );
    std::fs::write(config_dir.join("config.toml"), config_toml).expect("write config.toml");

    let stored = serde_json::json!({
        "version": 1,
        "kind": "s2_oauth",
        "credential_id": OAUTH_CREDENTIAL_ID,
        "issuer": issuer,
        "client_id": "test-client",
        "access_token": "fake-access-token",
        "refresh_token": "fake-refresh-token",
        "expires_at": OAUTH_EXPIRES_AT,
    });
    std::fs::write(
        oauth_credential_file_path(&config_dir),
        serde_json::to_vec(&stored).expect("serialize credential"),
    )
    .expect("write credential file");
}

/// A server-encoded S2 error response body for `code`.
fn error_body(code: &str) -> String {
    serde_json::json!({ "code": code, "message": "denied" }).to_string()
}

/// A browser-login user rejected with `permission_denied` is told to re-run
/// `s2 login`, and is never told to store/replace an access token.
#[test]
fn browser_login_permission_denied_shows_login_recovery_not_access_token() {
    let env = TestEnv::new();
    let server = TestServer::start_with(
        axum::http::StatusCode::FORBIDDEN,
        error_body("permission_denied"),
    );
    install_browser_login(&env, &server.endpoint);

    let assert = env
        .s2()
        .args(["list-basins", "--limit", "1"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);

    assert!(
        stderr.contains("browser login"),
        "stderr should name the browser-login token source, got: {stderr}"
    );
    assert!(
        stderr.contains("`s2 login`"),
        "stderr should suggest running `s2 login` again, got: {stderr}"
    );
    // The access-token remediation must not be suggested for a browser-login user.
    assert!(
        !stderr.contains("s2 auth access-token set"),
        "stderr must not suggest storing an access token for browser login, got: {stderr}"
    );
    assert!(
        !stderr.contains("S2_ACCESS_TOKEN"),
        "stderr must not suggest S2_ACCESS_TOKEN for browser login, got: {stderr}"
    );
    // The old hardcoded combined recovery string must be entirely absent.
    assert!(
        !stderr.contains("Store one with `s2 auth access-token set`"),
        "stderr must not render the old access-token-only recovery text, got: {stderr}"
    );
    // The server error must have reached the CLI (it is not auto-refreshed on 403).
    assert!(
        stderr.contains("permission_denied"),
        "stderr should surface the server error code, got: {stderr}"
    );

    // The request was authenticated with the browser-login access token.
    let request = server.finish().to_ascii_lowercase();
    assert!(
        request.contains("authorization: bearer fake-access-token"),
        "request should carry the browser-login access token, got: {request}"
    );
}

/// An access-token (stored) user rejected with `permission_denied` keeps
/// access-token recovery guidance (no regression for access-token sources),
/// and never suggests `s2 login`.
#[test]
fn stored_access_token_permission_denied_keeps_access_token_recovery() {
    let env = TestEnv::new();
    env.remember_access_token("stored-secret");
    let server = TestServer::start_with(
        axum::http::StatusCode::FORBIDDEN,
        error_body("permission_denied"),
    );

    let assert = env
        .s2()
        .env("S2_ACCOUNT_ENDPOINT", &server.endpoint)
        .env("S2_BASIN_ENDPOINT", &server.endpoint)
        .args(["list-basins", "--limit", "1"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);

    assert!(
        stderr.contains("stored access token"),
        "stderr should name the stored-access-token source, got: {stderr}"
    );
    assert!(
        stderr.contains("Run `s2 auth access-token set` to replace it."),
        "stderr should suggest replacing the access token, got: {stderr}"
    );
    assert!(
        !stderr.contains("`s2 login`"),
        "stderr must not suggest `s2 login` for an access-token source, got: {stderr}"
    );
    assert!(
        !stderr.contains("Store one with `s2 auth access-token set`, or set `S2_ACCESS_TOKEN`"),
        "stderr must not render the old combined recovery text, got: {stderr}"
    );

    let request = server.finish().to_ascii_lowercase();
    assert!(
        request.contains("authorization: bearer stored-secret"),
        "request should carry the stored access token, got: {request}"
    );
}
