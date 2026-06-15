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
