use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command as ProcessCommand, Stdio},
    time::{Duration, Instant},
};

use assert_cmd::Command;
use tempfile::TempDir;

fn base_command(home: &Path) -> ProcessCommand {
    let mut cmd = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("s2"));
    cmd.env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("APPDATA", home)
        .env("USERPROFILE", home)
        .env("NO_COLOR", "1")
        .env("RUST_LOG", "warn");
    cmd
}

fn command(home: &Path) -> Command {
    let mut cmd = Command::from_std(base_command(home));
    cmd.timeout(Duration::from_secs(30));
    cmd
}

#[test]
fn wal_store_requires_a_persistent_main_store_and_one_backend() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["lite", "--wal-bucket", "wal"],
        vec!["lite", "--wal-local-root", "wal"],
        vec![
            "lite",
            "--bucket",
            "main",
            "--wal-bucket",
            "wal",
            "--wal-local-root",
            "wal",
        ],
        vec!["lite", "--bucket", "main", "--local-root", "main"],
    ] {
        command(home.path()).args(args).assert().failure().code(2);
    }
    command(home.path())
        .env("S2LITE_WAL_BUCKET", "wal")
        .args(["lite"])
        .assert()
        .failure()
        .code(2);
}

struct Server {
    child: Child,
    address: SocketAddr,
}

impl Server {
    fn start(root: &Path, attempt: &str) -> Self {
        for bind_attempt in 0.. {
            let log_path = root.join(format!("server-{attempt}-{bind_attempt}.log"));
            match Self::spawn(root, &log_path) {
                Ok(server) => return server,
                Err(log) if bind_attempt < 5 && log.contains("Address already in use") => {
                    continue;
                }
                Err(log) => panic!("Server exited before becoming healthy: {log}"),
            }
        }
        unreachable!()
    }

    fn spawn(root: &Path, log_path: &Path) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let log = File::create(log_path).unwrap();
        let mut cmd = base_command(root);
        cmd.args([
            "lite",
            "--path",
            "db",
            "--port",
            &address.port().to_string(),
            "--local-root",
        ])
        .arg(root.join("main"))
        .env("S2LITE_WAL_LOCAL_ROOT", root.join("wal"))
        .env("SL8_FLUSH_INTERVAL", "1ms")
        .env("SL8_L0_SST_SIZE_BYTES", "65536");
        let child = cmd
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut server = Self { child, address };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if server.child.try_wait().unwrap().is_some() {
                return Err(fs::read_to_string(log_path).unwrap());
            }
            if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100))
            {
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut response = [0; 256];
                if stream
                    .write_all(
                        b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )
                    .is_ok()
                    && let Ok(n) = stream.read(&mut response)
                    && response[..n].starts_with(b"HTTP/1.1 200")
                {
                    return Ok(server);
                }
            }
            assert!(
                Instant::now() < deadline,
                "Server did not become healthy: {}",
                fs::read_to_string(log_path).unwrap()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn client(&self, root: &Path, args: &[&str], input: Option<&str>) -> String {
        let endpoint = format!("http://{}", self.address);
        let mut cmd = command(root);
        cmd.env("S2_ACCOUNT_ENDPOINT", &endpoint)
            .env("S2_BASIN_ENDPOINT", &endpoint)
            .env("S2_ACCESS_TOKEN", "test")
            .args(args);
        if let Some(input) = input {
            cmd.write_stdin(input);
        }
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn crash(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn has_sst(path: &Path) -> bool {
    fs::read_dir(path).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|entry| entry.path().extension().is_some_and(|ext| ext == "sst"))
    })
}

#[test]
fn separate_wal_routes_files_and_recovers_acknowledged_records_after_restart() {
    let root: TempDir = tempfile::tempdir().unwrap();
    let mut server = Server::start(root.path(), "before");
    server.client(root.path(), &["create-basin", "wal-test"], None);
    server.client(
        root.path(),
        &["create-stream", "s2://wal-test/recovery"],
        None,
    );
    let mut input = (0..64)
        .map(|i| format!("record-{i}-{}\n", "x".repeat(4096)))
        .collect::<String>();
    server.client(
        root.path(),
        &["append", "s2://wal-test/recovery"],
        Some(&input),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !has_sst(&root.path().join("main/db/compacted")) {
        assert!(Instant::now() < deadline, "Main-store SST was not flushed");
        std::thread::sleep(Duration::from_millis(25));
    }
    // Leave a final small write in the WAL after the earlier data reaches L0.
    let last = "last-acknowledged-record\n";
    server.client(
        root.path(),
        &["append", "s2://wal-test/recovery"],
        Some(last),
    );
    input.push_str(last);
    assert!(has_sst(&root.path().join("wal/db/wal")));
    assert!(!root.path().join("main/db/wal").exists());
    assert!(!root.path().join("wal/db/compacted").exists());
    assert!(!root.path().join("wal/db/manifest").exists());
    server.crash();
    let restarted = Server::start(root.path(), "after");
    let read = restarted.client(
        root.path(),
        &[
            "read",
            "s2://wal-test/recovery",
            "--seq-num",
            "0",
            "--count",
            "65",
        ],
        None,
    );
    assert_eq!(read, input);
}
