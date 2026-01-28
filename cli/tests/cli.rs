use assert_cmd::Command;
use predicates::prelude::*;

fn s2() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("s2"))
}

#[test]
fn invalid_uri_scheme() {
    s2().args(["get-stream-config", "foo://invalid/stream"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("s2://"));
}

#[test]
fn missing_stream_in_uri() {
    s2().args(["get-stream-config", "s2://basin-only"])
        .assert()
        .failure();
}

#[test]
fn invalid_basin_name() {
    s2().args(["create-basin", "-invalid-name"])
        .assert()
        .failure();
}

#[test]
fn missing_access_token() {
    let mut cmd = s2();
    cmd.env_remove("S2_ACCESS_TOKEN");
    cmd.args(["list-basins"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("access token"));
}

#[test]
fn unknown_subcommand() {
    s2().args(["unknown-command"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

#[test]
fn config_list() {
    s2().args(["config", "list"]).assert().success();
}

#[test]
fn config_set_and_get() {
    s2().args(["config", "set", "compression", "zstd"])
        .assert()
        .success();
    s2().args(["config", "get", "compression"])
        .assert()
        .success()
        .stdout(predicate::str::contains("zstd"));
    s2().args(["config", "unset", "compression"])
        .assert()
        .success();
}

#[test]
fn config_get_invalid_key() {
    s2().args(["config", "get", "invalid_key"])
        .assert()
        .failure();
}

#[test]
fn config_set_invalid_key() {
    s2().args(["config", "set", "invalid_key", "value"])
        .assert()
        .failure();
}
