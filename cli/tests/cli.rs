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
        .args(["config", "set", "access_token", "secret"])
        .assert()
        .success();

    let config_dir = env.home.path().join(".config/s2");
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
    env.s2()
        .args(["config", "set", "access_token", "test-token"])
        .assert()
        .success();
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

    env.s2()
        .args(["config", "set", "access_token", "test-token"])
        .assert()
        .success();
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

    env.s2()
        .args(["config", "set", "access_token", "test-token"])
        .assert()
        .success();
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

    env.s2()
        .args(["config", "set", "access_token", "test-token"])
        .assert()
        .success();
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
