use std::{
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

fn unique_name(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

fn s2() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("s2"))
}

fn wait_for_basin(basin: &str) {
    for _ in 0..60 {
        if s2()
            .args(["get-basin-config", basin])
            .output()
            .is_ok_and(|o| o.status.success())
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn cleanup_basin(basin: &str) {
    let _ = s2().args(["delete-basin", basin]).output();
}

fn cleanup_stream(basin: &str, stream: &str) {
    let _ = s2()
        .args(["delete-stream", &format!("s2://{basin}/{stream}")])
        .output();
}

fn ensure_test_basin(name: &str) -> String {
    let _ = s2().args(["create-basin", name]).output();
    wait_for_basin(name);
    name.to_string()
}

#[test]
#[serial]
fn list_basins() {
    s2().args(["list-basins", "--limit", "5"])
        .assert()
        .success();
}

#[test]
#[serial]
fn list_basins_with_prefix() {
    s2().args(["list-basins", "--prefix", "test-cli-", "--limit", "5"])
        .assert()
        .success();
}

#[test]
#[serial]
fn create_get_delete_basin() {
    let basin = unique_name("test-cli-basin");

    s2().args(["create-basin", &basin]).assert().success();

    wait_for_basin(&basin);

    s2().args(["get-basin-config", &basin]).assert().success();

    s2().args(["delete-basin", &basin]).assert().success();
}

#[test]
#[serial]
fn create_basin_with_config() {
    let basin = unique_name("test-cli-basin-cfg");

    s2().args([
        "create-basin",
        &basin,
        "--retention-policy",
        "1d",
        "--create-stream-on-append",
    ])
    .assert()
    .success();

    wait_for_basin(&basin);

    s2().args(["get-basin-config", &basin])
        .assert()
        .success()
        .stdout(predicate::str::contains("create_stream_on_append"));

    cleanup_basin(&basin);
}

#[test]
#[serial]
fn reconfigure_basin() {
    let basin = unique_name("test-cli-basin-reconfig");

    s2().args(["create-basin", &basin]).assert().success();
    wait_for_basin(&basin);

    s2().args([
        "reconfigure-basin",
        &basin,
        "--create-stream-on-append",
        "true",
    ])
    .assert()
    .success();

    s2().args(["get-basin-config", &basin])
        .assert()
        .success()
        .stdout(predicate::str::contains("create_stream_on_append"));

    cleanup_basin(&basin);
}

#[test]
#[serial]
fn ls_basins() {
    s2().args(["ls", "--limit", "5"]).assert().success();
}

#[test]
#[serial]
fn delete_nonexistent_basin() {
    s2().args(["delete-basin", "nonexistent-basin-12345"])
        .assert()
        .failure();
}

#[test]
#[serial]
fn get_config_nonexistent_basin() {
    s2().args(["get-basin-config", "nonexistent-basin-12345"])
        .assert()
        .failure();
}

#[test]
#[serial]
fn list_streams() {
    let basin = ensure_test_basin("test-cli-streams");
    s2().args(["list-streams", &basin, "--limit", "5"])
        .assert()
        .success();
}

#[test]
#[serial]
fn list_streams_with_uri() {
    let basin = ensure_test_basin("test-cli-streams");
    s2().args(["list-streams", &format!("s2://{basin}/"), "--limit", "5"])
        .assert()
        .success();
}

#[test]
#[serial]
fn create_get_delete_stream() {
    let basin = ensure_test_basin("test-cli-streams");
    let stream = unique_name("test-stream");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    s2().args(["get-stream-config", &uri]).assert().success();

    s2().args(["delete-stream", &uri]).assert().success();
}

#[test]
#[serial]
fn create_stream_with_config() {
    let basin = ensure_test_basin("test-cli-streams");
    let stream = unique_name("test-stream-cfg");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri, "--retention-policy", "7d"])
        .assert()
        .success();
    s2().args(["get-stream-config", &uri]).assert().success();

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn reconfigure_stream() {
    let basin = ensure_test_basin("test-cli-streams");
    let stream = unique_name("test-stream-reconfig");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();
    s2().args(["reconfigure-stream", &uri, "--retention-policy", "14d"])
        .assert()
        .success();

    s2().args(["get-stream-config", &uri])
        .assert()
        .success()
        .stdout(predicate::str::contains("14d").or(predicate::str::contains("1209600")));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn ls_streams() {
    let basin = ensure_test_basin("test-cli-streams");
    s2().args(["ls", &basin, "--limit", "5"]).assert().success();
}

#[test]
#[serial]
fn check_tail() {
    let basin = ensure_test_basin("test-cli-streams");
    let stream = unique_name("test-stream-tail");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();
    s2().args(["check-tail", &uri])
        .assert()
        .success()
        .stdout(predicate::str::contains("@"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn delete_nonexistent_stream() {
    let basin = ensure_test_basin("test-cli-streams");
    s2().args([
        "delete-stream",
        &format!("s2://{basin}/nonexistent-stream-12345"),
    ])
    .assert()
    .failure();
}

#[test]
#[serial]
fn append_and_read_text() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-text");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    let temp = tempfile::TempDir::new().unwrap();
    let input = temp.path().join("input.txt");
    {
        let mut f = std::fs::File::create(&input).unwrap();
        writeln!(f, "hello world").unwrap();
        writeln!(f, "line two").unwrap();
    }

    s2().args([
        "append",
        &uri,
        "--format",
        "text",
        "--input",
        input.to_str().unwrap(),
    ])
    .assert()
    .success();

    s2().args([
        "read",
        &uri,
        "--seq-num",
        "0",
        "--count",
        "2",
        "--format",
        "text",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("hello world"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn append_and_read_json() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-json");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    let temp = tempfile::TempDir::new().unwrap();
    let input = temp.path().join("input.json");
    {
        let mut f = std::fs::File::create(&input).unwrap();
        writeln!(f, r#"{{"body": "record one"}}"#).unwrap();
        writeln!(f, r#"{{"body": "record two"}}"#).unwrap();
    }

    s2().args([
        "append",
        &uri,
        "--format",
        "json",
        "--input",
        input.to_str().unwrap(),
    ])
    .assert()
    .success();

    s2().args([
        "read",
        &uri,
        "--seq-num",
        "0",
        "--count",
        "2",
        "--format",
        "json",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("record one"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn append_from_stdin() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-stdin");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    s2().args(["append", &uri, "--format", "text", "--input", "-"])
        .write_stdin("stdin record\n")
        .assert()
        .success();

    s2().args([
        "read",
        &uri,
        "--seq-num",
        "0",
        "--count",
        "1",
        "--format",
        "text",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("stdin record"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn tail_stream() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-tail");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    let temp = tempfile::TempDir::new().unwrap();
    let input = temp.path().join("input.txt");
    {
        let mut f = std::fs::File::create(&input).unwrap();
        for i in 1..=5 {
            writeln!(f, "record {i}").unwrap();
        }
    }

    s2().args([
        "append",
        &uri,
        "--format",
        "text",
        "--input",
        input.to_str().unwrap(),
    ])
    .assert()
    .success();

    s2().args(["tail", &uri, "-n", "3", "--format", "text"])
        .assert()
        .success()
        .stdout(predicate::str::contains("record 5"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn read_with_tail_offset() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-offset");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    let temp = tempfile::TempDir::new().unwrap();
    let input = temp.path().join("input.txt");
    {
        let mut f = std::fs::File::create(&input).unwrap();
        for i in 1..=10 {
            writeln!(f, "record {i}").unwrap();
        }
    }

    s2().args([
        "append",
        &uri,
        "--format",
        "text",
        "--input",
        input.to_str().unwrap(),
    ])
    .assert()
    .success();

    s2().args([
        "read",
        &uri,
        "--tail-offset",
        "3",
        "--count",
        "3",
        "--format",
        "text",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("record 8"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn trim_stream() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-trim");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    let temp = tempfile::TempDir::new().unwrap();
    let input = temp.path().join("input.txt");
    {
        let mut f = std::fs::File::create(&input).unwrap();
        for i in 1..=5 {
            writeln!(f, "record {i}").unwrap();
        }
    }

    s2().args([
        "append",
        &uri,
        "--format",
        "text",
        "--input",
        input.to_str().unwrap(),
    ])
    .assert()
    .success();

    s2().args(["trim", &uri, "3"])
        .assert()
        .success()
        .stderr(predicate::str::contains("@"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn fence_stream() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-fence");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    s2().args(["fence", &uri, "my-token"])
        .assert()
        .success()
        .stderr(predicate::str::contains("@"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn append_with_fencing_token() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-fence-append");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();
    s2().args(["fence", &uri, "writer-1"]).assert().success();

    s2().args([
        "append",
        &uri,
        "--format",
        "text",
        "--input",
        "-",
        "--fencing-token",
        "writer-1",
    ])
    .write_stdin("fenced record\n")
    .assert()
    .success();

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn list_basins_with_start_after() {
    s2().args([
        "list-basins",
        "--start-after",
        "a",
        "--limit",
        "5",
        "--no-auto-paginate",
    ])
    .assert()
    .success();
}

#[test]
#[serial]
fn list_streams_with_start_after() {
    let basin = ensure_test_basin("test-cli-streams");
    s2().args([
        "list-streams",
        &basin,
        "--start-after",
        "a",
        "--limit",
        "5",
        "--no-auto-paginate",
    ])
    .assert()
    .success();
}

#[test]
#[serial]
fn create_basin_with_storage_class() {
    let basin = unique_name("test-cli-basin-sc");

    let output = s2()
        .args(["create-basin", &basin, "--storage-class", "express"])
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("tier") || stderr.contains("unavailable") {
            return;
        }
        panic!("create-basin failed: {stderr}");
    }

    wait_for_basin(&basin);

    s2().args(["get-basin-config", &basin])
        .assert()
        .success()
        .stdout(predicate::str::contains("express").or(predicate::str::contains("Express")));

    cleanup_basin(&basin);
}

#[test]
#[serial]
fn create_basin_with_timestamping() {
    let basin = unique_name("test-cli-basin-ts");

    s2().args([
        "create-basin",
        &basin,
        "--timestamping-mode",
        "client-require",
    ])
    .assert()
    .success();

    wait_for_basin(&basin);
    cleanup_basin(&basin);
}

#[test]
#[serial]
fn create_basin_with_create_stream_on_read() {
    let basin = unique_name("test-cli-basin-csor");

    s2().args(["create-basin", &basin, "--create-stream-on-read"])
        .assert()
        .success();

    wait_for_basin(&basin);

    s2().args(["get-basin-config", &basin])
        .assert()
        .success()
        .stdout(predicate::str::contains("create_stream_on_read"));

    cleanup_basin(&basin);
}

#[test]
#[serial]
fn create_stream_with_storage_class() {
    let basin = ensure_test_basin("test-cli-streams");
    let stream = unique_name("test-stream-sc");
    let uri = format!("s2://{basin}/{stream}");

    let output = s2()
        .args(["create-stream", &uri, "--storage-class", "express"])
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("tier") || stderr.contains("unavailable") {
            return;
        }
        panic!("create-stream failed: {stderr}");
    }

    s2().args(["get-stream-config", &uri])
        .assert()
        .success()
        .stdout(predicate::str::contains("express").or(predicate::str::contains("Express")));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn create_stream_with_timestamping() {
    let basin = ensure_test_basin("test-cli-streams");
    let stream = unique_name("test-stream-ts");
    let uri = format!("s2://{basin}/{stream}");

    s2().args([
        "create-stream",
        &uri,
        "--timestamping-mode",
        "client-prefer",
    ])
    .assert()
    .success();

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn append_with_match_seq_num() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-match");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    s2().args([
        "append",
        &uri,
        "--format",
        "text",
        "--input",
        "-",
        "--match-seq-num",
        "0",
    ])
    .write_stdin("first record\n")
    .assert()
    .success();

    s2().args([
        "append",
        &uri,
        "--format",
        "text",
        "--input",
        "-",
        "--match-seq-num",
        "0",
    ])
    .write_stdin("should fail\n")
    .assert()
    .failure();

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn append_and_read_json_base64() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-b64");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    s2().args(["append", &uri, "--format", "json-base64", "--input", "-"])
        .write_stdin("{\"body\": \"aGVsbG8gd29ybGQ=\"}\n")
        .assert()
        .success();

    s2().args([
        "read",
        &uri,
        "--seq-num",
        "0",
        "--count",
        "1",
        "--format",
        "json-base64",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("aGVsbG8gd29ybGQ="));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn read_with_bytes_limit() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-bytes");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    let temp = tempfile::TempDir::new().unwrap();
    let input = temp.path().join("input.txt");
    {
        let mut f = std::fs::File::create(&input).unwrap();
        for i in 1..=100 {
            writeln!(f, "record number {i}").unwrap();
        }
    }

    s2().args([
        "append",
        &uri,
        "--format",
        "text",
        "--input",
        input.to_str().unwrap(),
    ])
    .assert()
    .success();

    s2().args([
        "read",
        &uri,
        "--seq-num",
        "0",
        "--bytes",
        "50",
        "--format",
        "text",
    ])
    .assert()
    .success();

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn read_with_ago() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-ago");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    s2().args(["append", &uri, "--format", "text", "--input", "-"])
        .write_stdin("recent record\n")
        .assert()
        .success();

    s2().args([
        "read", &uri, "--ago", "1h", "--count", "1", "--format", "text",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("recent record"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn read_to_file() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-file");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    s2().args(["append", &uri, "--format", "text", "--input", "-"])
        .write_stdin("file output test\n")
        .assert()
        .success();

    let temp = tempfile::TempDir::new().unwrap();
    let output = temp.path().join("output.txt");

    s2().args([
        "read",
        &uri,
        "--seq-num",
        "0",
        "--count",
        "1",
        "--format",
        "text",
        "--output",
        output.to_str().unwrap(),
    ])
    .assert()
    .success();

    let content = std::fs::read_to_string(&output).unwrap();
    assert!(content.contains("file output test"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn append_wrong_fencing_token_fails() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-wrong-fence");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();
    s2().args(["fence", &uri, "correct-token"])
        .assert()
        .success();

    s2().args([
        "append",
        &uri,
        "--format",
        "text",
        "--input",
        "-",
        "--fencing-token",
        "wrong-token",
    ])
    .write_stdin("should fail\n")
    .assert()
    .failure();

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn reconfigure_basin_storage_class() {
    let basin = unique_name("test-cli-basin-reconfig-sc");

    s2().args(["create-basin", &basin]).assert().success();
    wait_for_basin(&basin);

    let output = s2()
        .args(["reconfigure-basin", &basin, "--storage-class", "express"])
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("tier") || stderr.contains("unavailable") {
            cleanup_basin(&basin);
            return;
        }
        cleanup_basin(&basin);
        panic!("reconfigure-basin failed: {stderr}");
    }

    s2().args(["get-basin-config", &basin])
        .assert()
        .success()
        .stdout(predicate::str::contains("express").or(predicate::str::contains("Express")));

    cleanup_basin(&basin);
}

#[test]
#[serial]
fn reconfigure_stream_timestamping() {
    let basin = ensure_test_basin("test-cli-streams");
    let stream = unique_name("test-stream-reconfig-ts");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();
    s2().args(["reconfigure-stream", &uri, "--timestamping-mode", "arrival"])
        .assert()
        .success();

    s2().args(["get-stream-config", &uri])
        .assert()
        .success()
        .stdout(predicate::str::contains("arrival").or(predicate::str::contains("Arrival")));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn read_with_timestamp() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-ts-read");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    s2().args(["append", &uri, "--format", "text", "--input", "-"])
        .write_stdin("timestamp test record\n")
        .assert()
        .success();

    s2().args([
        "read",
        &uri,
        "--timestamp",
        "0",
        "--count",
        "1",
        "--format",
        "text",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("timestamp test record"));

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn trim_with_fencing_token() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-trim-fence");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    let temp = tempfile::TempDir::new().unwrap();
    let input = temp.path().join("input.txt");
    {
        let mut f = std::fs::File::create(&input).unwrap();
        for i in 1..=5 {
            writeln!(f, "record {i}").unwrap();
        }
    }

    s2().args([
        "append",
        &uri,
        "--format",
        "text",
        "--input",
        input.to_str().unwrap(),
    ])
    .assert()
    .success();

    s2().args(["fence", &uri, "trim-token"]).assert().success();

    s2().args(["trim", &uri, "3", "--fencing-token", "trim-token"])
        .assert()
        .success();

    s2().args(["trim", &uri, "4", "--fencing-token", "wrong-token"])
        .assert()
        .failure();

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn fence_with_existing_token() {
    let basin = ensure_test_basin("test-cli-data");
    let stream = unique_name("test-data-fence-existing");
    let uri = format!("s2://{basin}/{stream}");

    s2().args(["create-stream", &uri]).assert().success();

    s2().args(["fence", &uri, "token-v1"]).assert().success();

    s2().args(["fence", &uri, "token-v2", "--fencing-token", "token-v1"])
        .assert()
        .success();

    s2().args(["fence", &uri, "token-v3", "--fencing-token", "wrong-token"])
        .assert()
        .failure();

    cleanup_stream(&basin, &stream);
}

#[test]
#[serial]
fn bench_stream() {
    let basin = ensure_test_basin("test-cli-data");

    s2().args([
        "bench",
        &basin,
        "--duration",
        "1s",
        "--target-mibps",
        "1",
        "--catchup-delay",
        "0s",
    ])
    .assert()
    .success();
}
