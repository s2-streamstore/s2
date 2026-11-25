use std::{
    convert::Infallible,
    net::TcpListener,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};

use assert_cmd::Command;
use predicates::prelude::*;
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let endpoint = format!("http://{}", listener.local_addr().expect("server address"));
        let handle = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(serve_one_request(listener))
        });
        Self { endpoint, handle }
    }

    fn finish(self) -> String {
        self.handle.join().expect("test server")
    }
}

const TEST_SERVER_TIMEOUT: Duration = Duration::from_secs(10);

async fn serve_one_request(listener: TcpListener) -> String {
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
        async move {
            let mut rendered = format!("{} {}\r\n", req.method(), req.uri());
            for (name, value) in req.headers() {
                rendered.push_str(name.as_str());
                rendered.push_str(": ");
                rendered.push_str(value.to_str().unwrap_or_default());
                rendered.push_str("\r\n");
            }
            *captured.lock().expect("capture request") = Some(rendered);

            let body = r#"{"basins":[],"has_more":false}"#;
            Ok::<_, Infallible>(
                hyper::Response::builder()
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
            "S2_OAUTH_ISSUER",
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
        .args(["stream", "get", "foo://invalid/stream"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("s2://"));
}

#[test]
fn missing_stream_in_uri() {
    TestEnv::new()
        .s2()
        .args(["stream", "get", "s2://basin-only"])
        .assert()
        .failure();
}

#[test]
fn invalid_basin_name() {
    TestEnv::new()
        .s2()
        .args(["basin", "create", "-invalid-name"])
        .assert()
        .failure();
}

#[test]
fn missing_access_token() {
    let env = TestEnv::new();
    let mut cmd = env.s2();
    cmd.args(["basin", "list"])
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
        .args(["basin", "list", "--limit", "1"])
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
        .args(["basin", "list", "--limit", "1"])
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

/// Top-level help adapts to where the CLI is pointed, and still prints when it cannot tell.
#[test]
fn top_level_help_follows_the_configured_endpoints() {
    const LOCAL: &str = "http://localhost:8080";
    const LAN: &str = "http://192.168.1.10:8080";
    // (account endpoint, basin endpoint), the `Endpoint:` line if any, and whether the
    // walkthrough starts with `s2 login` or with an access token.
    let cases = [
        (None, None, "s2 login"),
        (Some((LOCAL, LOCAL)), Some("localhost:8080"), "ignored"),
        (Some((LAN, LAN)), Some("192.168.1.10:8080"), "<token>"),
        (
            Some(("https://a.s2.dev", "https://{basin}.basins.example")),
            Some("s2.dev, basins at basins.example"),
            "<token>",
        ),
    ];
    for (endpoints, banner, auth) in cases {
        let env = TestEnv::new();
        let mut cmd = env.s2();
        if let Some((account, basin)) = endpoints {
            cmd.env("S2_ACCOUNT_ENDPOINT", account)
                .env("S2_BASIN_ENDPOINT", basin);
        }
        let assert = cmd.arg("--help").assert().success();
        let help = String::from_utf8_lossy(&assert.get_output().stdout);
        let walkthrough = help
            .lines()
            .skip_while(|line| *line != "Get started:")
            .nth(1)
            .unwrap_or_else(|| panic!("no walkthrough in: {help}"));

        assert_eq!(
            help.lines().find(|line| line.starts_with("Endpoint:")),
            banner
                .map(|label| format!("Endpoint: {label} (custom)"))
                .as_deref(),
            "{endpoints:?}"
        );
        assert!(walkthrough.contains(auth), "{endpoints:?}: {walkthrough}");
    }

    // A config file that cannot be read must not take the help down with it.
    let env = TestEnv::new();
    std::fs::create_dir_all(env.config_dir()).expect("config dir");
    std::fs::write(env.config_dir().join("config.toml"), "not = [valid").expect("write config");
    env.s2()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("s2 login"))
        .stdout(predicate::str::contains("Endpoint:").not());
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

    let assert = env.s2().args(["basin", "list"]).assert().failure();
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

    let assert = cmd.args(["basin", "list"]).assert().failure();
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

    let assert = env.s2().args(["basin", "list"]).assert().failure();
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

    let assert = env.s2().args(["basin", "list"]).assert().failure();
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

/// A command that sets only one endpoint should fail closed rather than silently
/// falling back to the default cloud endpoints.
#[test]
fn only_account_endpoint_set_fails_closed() {
    let env = TestEnv::new();

    env.remember_access_token("test-token");
    env.s2()
        .args(["config", "set", "account_endpoint", "https://a.s2.dev"])
        .assert()
        .success();

    let assert = env.s2().args(["basin", "list"]).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    let normalized = stderr
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    assert!(
        normalized.contains("Unable to parse S2 endpoints"),
        "stderr should report an endpoint config error, got: {stderr}"
    );
    assert!(
        normalized.contains("account endpoint is set without basin endpoint"),
        "stderr should explain the missing basin endpoint, got: {stderr}"
    );
}

/// Multi-request HTTP/2 prior-knowledge stub server for end-to-end CLI command tests.
struct StubServer {
    endpoint: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl StubServer {
    fn start(handler: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub server");
        let endpoint = format!("http://{}", listener.local_addr().expect("stub address"));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let handler = Arc::new(handler);
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("stub runtime");
            rt.block_on(async move {
                listener
                    .set_nonblocking(true)
                    .expect("non-blocking stub listener");
                let listener =
                    tokio::net::TcpListener::from_std(listener).expect("tokio stub listener");
                tokio::pin!(shutdown_rx);
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        accepted = listener.accept() => {
                            let Ok((stream, _)) = accepted else { break };
                            let handler = handler.clone();
                            tokio::spawn(async move {
                                let service = hyper::service::service_fn(
                                    move |req: hyper::Request<hyper::body::Incoming>| {
                                        let handler = handler.clone();
                                        async move {
                                            let method = req.method().as_str().to_owned();
                                            let uri = req
                                                .uri()
                                                .path_and_query()
                                                .map(|pq| pq.as_str().to_owned())
                                                .unwrap_or_else(|| "/".to_owned());
                                            let (status, body) = handler(&method, &uri);
                                            Ok::<_, Infallible>(
                                                hyper::Response::builder()
                                                    .status(status)
                                                    .header("content-type", "application/json")
                                                    .body(http_body_util::Full::new(
                                                        bytes::Bytes::from(body),
                                                    ))
                                                    .expect("build stub response"),
                                            )
                                        }
                                    },
                                );
                                let _ = hyper::server::conn::http2::Builder::new(
                                    hyper_util::rt::TokioExecutor::new(),
                                )
                                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                                .await;
                            });
                        }
                    }
                }
            });
        });
        Self {
            endpoint,
            shutdown: Some(shutdown_tx),
            handle: Some(handle),
        }
    }
}

impl Drop for StubServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn diff_stream_vs_basin_defaults_handles_unavailable_discovery() {
    let server = StubServer::start(|method, uri| {
        match (method, uri) {
        ("GET", "/v1/basins/test-basin") => (200, r#"{"default_stream_config":{}}"#.to_owned()),
        ("GET", "/v1/streams/matching") => {
            (200, r#"{"storage_class":"express"}"#.to_owned())
        }
        ("GET", "/v1/streams/different") => (
            200,
            r#"{"storage_class":"express","retention_policy":{"infinite":{}}}"#.to_owned(),
        ),
        ("GET", u) if u.starts_with("/v1/basins?") => (
            200,
            r#"{"basins":[{"name":"test-basin","location":"aws:us-east-1","created_at":"2026-01-01T00:00:00Z","state":"active"}],"has_more":false}"#
                .to_owned(),
        ),
        ("GET", "/v1/locations") => (
            501,
            r#"{"code":"not_implemented","message":"not implemented"}"#.to_owned(),
        ),
        other => panic!("unexpected stub request: {other:?}"),
    }
    });

    let env = TestEnv::new();
    let run = |args: &[&str]| {
        let mut cmd = env.s2();
        cmd.env("S2_ACCESS_TOKEN", "test-token")
            .env("S2_ACCOUNT_ENDPOINT", &server.endpoint)
            .env("S2_BASIN_ENDPOINT", &server.endpoint)
            .args(args);
        cmd
    };

    run(&[
        "diff",
        "s2://test-basin",
        "s2://test-basin/matching",
        "--exit-code",
    ])
    .assert()
    .success()
    .stdout(
        predicate::str::contains("✓ No differences")
            .and(predicate::str::contains("storage_class not compared")),
    );

    let json_matching = run(&[
        "diff",
        "s2://test-basin",
        "s2://test-basin/matching",
        "--output",
        "json",
        "--exit-code",
    ])
    .assert()
    .success();
    let parsed: serde_json::Value =
        serde_json::from_slice(&json_matching.get_output().stdout).expect("valid json");
    assert_eq!(parsed["differences"], serde_json::json!([]));
    assert_eq!(parsed["unresolved"], serde_json::json!(["storage_class"]));

    run(&[
        "diff",
        "s2://test-basin",
        "s2://test-basin/different",
        "--exit-code",
    ])
    .assert()
    .code(1)
    .stdout(
        predicate::str::contains("retention_policy")
            .and(predicate::str::contains("storage_class: not compared")),
    );

    let json_different = run(&[
        "diff",
        "s2://test-basin",
        "s2://test-basin/different",
        "--output",
        "json",
        "--exit-code",
    ])
    .assert()
    .code(1);
    let parsed: serde_json::Value =
        serde_json::from_slice(&json_different.get_output().stdout).expect("valid json");
    assert_eq!(parsed["differences"].as_array().map(Vec::len), Some(1));
    assert_eq!(parsed["differences"][0]["path"], "retention_policy");
    assert_eq!(parsed["unresolved"], serde_json::json!(["storage_class"]));
}

#[test]
fn diff_and_apply_dry_run_use_basin_location_not_account_default() {
    let server = StubServer::start(|method, uri| {
        match (method, uri) {
        ("GET", "/v1/basins/loc-basin") => (200, r#"{"default_stream_config":{}}"#.to_owned()),
        ("GET", "/v1/streams/express-stream") => {
            (200, r#"{"storage_class":"express"}"#.to_owned())
        }
        ("GET", "/v1/streams/standard-stream") => {
            (200, r#"{"storage_class":"standard"}"#.to_owned())
        }
        ("GET", u) if u.starts_with("/v1/basins?") => (
            200,
            r#"{"basins":[{"name":"loc-basin","location":"aws:us-east-1","created_at":"2026-01-01T00:00:00Z","state":"active"}],"has_more":false}"#
                .to_owned(),
        ),
        ("GET", "/v1/locations") => (
            200,
            r#"[{"name":"aws:us-east-1","is_private":false,"default_storage_class":"express"},{"name":"aws:eu-west-1","is_private":false,"default_storage_class":"standard"}]"#
                .to_owned(),
        ),
        ("GET", "/v1/locations/default") => {
            panic!("should resolve from basin's location rather than account default location")
        }
        other => panic!("unexpected stub request: {other:?}"),
    }
    });

    let env = TestEnv::new();
    let run = |args: &[&str]| {
        let mut cmd = env.s2();
        cmd.env("S2_ACCESS_TOKEN", "test-token")
            .env("S2_ACCOUNT_ENDPOINT", &server.endpoint)
            .env("S2_BASIN_ENDPOINT", &server.endpoint)
            .args(args);
        cmd
    };

    run(&[
        "diff",
        "s2://loc-basin",
        "s2://loc-basin/express-stream",
        "--exit-code",
    ])
    .assert()
    .success()
    .stdout(
        predicate::str::contains("✓ No differences")
            .and(predicate::str::contains("not compared").not()),
    );

    run(&[
        "diff",
        "s2://loc-basin",
        "s2://loc-basin/standard-stream",
        "--exit-code",
    ])
    .assert()
    .code(1)
    .stdout(
        predicate::str::contains("storage_class")
            .and(predicate::str::contains("- express"))
            .and(predicate::str::contains("+ standard")),
    );

    let spec_path = env.home.path().join("spec.json");
    std::fs::write(
        &spec_path,
        r#"{"basins":[{"name":"loc-basin","streams":[{"name":"express-stream"}]}]}"#,
    )
    .expect("write spec");

    run(&["apply", "--dry-run", "-f", spec_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("= basin loc-basin").and(predicate::str::contains(
                "= stream loc-basin/express-stream",
            )),
        );
}
