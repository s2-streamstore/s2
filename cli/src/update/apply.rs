//! `s2 update`: bring the CLI up to date using the strategy that matches how
//! it was installed (see [`super::channel`]).
//!
//! - Install script or manual GitHub download (`InstallScript`, `GithubRelease`): on Unix, download
//!   the release artifact for this exact target, verify its SHA-256 against the release's
//!   `SHA256SUMS`, and atomically replace the running binary in place; on Windows, print exact
//!   manual replacement instructions because a running executable cannot be replaced safely.
//! - Homebrew or Cargo: the package manager owns the binary, so print its upgrade command (or run
//!   it with `--yes` where the running executable can be replaced).
//! - Docker or source build: nothing to replace; explain how to update.

use std::{
    fmt,
    io::{Cursor, IsTerminal, Read, Write},
    path::Path,
    time::Duration,
};

use colored::Colorize;
use semver::Version;
use sha2::{Digest, Sha256};

use super::channel::{self, InstallChannel};
use crate::cli::UpdateArgs;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Target triple this binary was built for, stamped by `build.rs`.
const TARGET: &str = env!("S2_TARGET");
const CLI_TAG_PREFIX: &str = "s2-cli-v";
const CHECKSUMS_ASSET: &str = "SHA256SUMS";
const DOCS_URL: &str = "https://s2.dev/docs/quickstart#get-started-with-the-cli";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("could not locate the running executable: {0}")]
    CurrentExe(#[source] std::io::Error),
    #[error("could not determine the latest release; is GitHub reachable?")]
    LatestUnavailable,
    #[error("failed to build HTTP client: {0}")]
    Http(#[source] reqwest::Error),
    #[error("release {0} does not publish {CHECKSUMS_ASSET}; install manually from {DOCS_URL}")]
    ChecksumsUnavailable(Version),
    #[error("{CHECKSUMS_ASSET} has no entry for {0}")]
    ChecksumMissing(String),
    #[error("failed to download {0}: {1}")]
    Download(String, #[source] reqwest::Error),
    #[error("checksum mismatch for {asset}: expected {expected}, computed {actual}")]
    ChecksumMismatch {
        asset: String,
        expected: String,
        actual: String,
    },
    #[error("could not read the release archive: {0}")]
    Archive(String),
    #[error("release archive did not contain {0}")]
    BinaryNotInArchive(String),
    #[error(
        "could not replace {path}: {source}\n\
         (need write access to its directory; re-run with sufficient permissions)"
    )]
    Install {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[cfg(windows)]
    #[error(
        "automatic in-place replacement is disabled on Windows; \
         install the release manually after s2 exits"
    )]
    WindowsInPlaceUnsupported,
    #[error("failed to run `{0}`: {1}")]
    Spawn(String, #[source] std::io::Error),
    #[error("`{0}` exited with a non-zero status")]
    CommandFailed(String),
}

/// Entry point for the `update` subcommand.
pub async fn run(args: &UpdateArgs) -> Result<(), UpdateError> {
    let channel = channel::detect();
    let current = Version::parse(CURRENT_VERSION).expect("crate version is valid semver");

    if args.check {
        return report_status(channel, &current).await;
    }

    let target = super::fetch_latest()
        .await
        .ok_or(UpdateError::LatestUnavailable)?;

    // Explicit --skip just records the marker and does nothing else.
    if args.skip {
        return do_skip(&target);
    }

    if target <= current {
        println!("s2-cli {current} is already up to date.");
        return Ok(());
    }

    let action = match plan_update(channel, &target, cfg!(not(windows))) {
        Plan::Mutate(action) => action,
        Plan::Advise(advice) => {
            print!("{}", advice.render(&target, &repo()));
            return Ok(());
        }
    };

    // Describe what upgrading entails before asking.
    println!("s2-cli {current} → {target}  (installed via {channel})");
    if let Mutation::Run(command) = &action {
        println!("This will run: {}", command.to_string().cyan());
    }

    // Confirm interactively, unless --yes was given. Never block on a prompt
    // when there is no terminal to answer it (e.g. CI, piped input).
    let choice = if args.yes {
        Choice::Yes
    } else if std::io::stdin().is_terminal() {
        prompt_choice("Update now?")
    } else {
        match &action {
            Mutation::InPlace => println!("Re-run with {} to update in place.", "--yes".cyan()),
            Mutation::Run(command) => println!(
                "Run {} yourself, or re-run with {}.",
                command.to_string().cyan(),
                "--yes".cyan()
            ),
        }
        return Ok(());
    };

    match choice {
        Choice::Yes => match action {
            Mutation::InPlace => in_place_update(channel, &target).await,
            Mutation::Run(command) => run_command(&command),
        },
        Choice::Skip => do_skip(&target),
        Choice::No => {
            println!("Cancelled; no changes made.");
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Mutate(Mutation),
    Advise(Advice),
}

/// A change this process can safely make.
#[derive(Debug, PartialEq, Eq)]
enum Mutation {
    /// Download the release artifact and replace the binary in place.
    InPlace,
    /// Delegate to a package manager's upgrade command.
    Run(CommandSpec),
}

/// Guidance for channels this process must not mutate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Advice {
    Docker,
    SourceBuild,
    WindowsCargo,
    WindowsRelease,
}

impl Advice {
    fn render(self, target: &Version, repo: &str) -> String {
        let tag = format!("{CLI_TAG_PREFIX}{target}");
        match self {
            Self::Docker => format!(
                "This is the Docker build of s2-cli. Pull the exact image on the host:\n\
                 \x20   docker pull ghcr.io/s2-streamstore/s2:{target}\n\
                 The running container was not changed.\n"
            ),
            Self::SourceBuild => format!(
                "This s2-cli was built from source. Check out {tag} and rebuild,\n\
                 or install the exact release from:\n\
                 \x20   https://github.com/{repo}/releases/tag/{tag}\n\
                 The running binary was not changed.\n"
            ),
            Self::WindowsCargo => format!(
                "Cargo cannot replace the running s2.exe on Windows.\n\
                 After s2 exits, run:\n\
                 \x20   {}\n\
                 The running binary was not changed.\n",
                cargo_install_command(target),
            ),
            Self::WindowsRelease => format!(
                "Automatic in-place replacement is disabled on Windows.\n\
                 After s2 exits, download {asset} and {CHECKSUMS_ASSET} from:\n\
                 \x20   https://github.com/{repo}/releases/tag/{tag}\n\
                 The running binary was not changed.\n",
                asset = asset_name(),
            ),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CommandSpec {
    program: &'static str,
    args: Vec<String>,
}

impl CommandSpec {
    fn new(program: &'static str, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

impl fmt::Display for CommandSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.program)?;
        for arg in &self.args {
            write!(f, " {arg}")?;
        }
        Ok(())
    }
}

fn cargo_install_command(target: &Version) -> CommandSpec {
    CommandSpec::new(
        "cargo",
        [
            "install".to_string(),
            "--locked".to_string(),
            "--force".to_string(),
            "--version".to_string(),
            target.to_string(),
            "s2-cli".to_string(),
        ],
    )
}

fn plan_update(
    channel: InstallChannel,
    target: &Version,
    running_executable_replaceable: bool,
) -> Plan {
    match channel {
        InstallChannel::InstallScript | InstallChannel::GithubRelease => {
            if running_executable_replaceable {
                Plan::Mutate(Mutation::InPlace)
            } else {
                Plan::Advise(Advice::WindowsRelease)
            }
        }
        InstallChannel::Cargo if !running_executable_replaceable => {
            Plan::Advise(Advice::WindowsCargo)
        }
        InstallChannel::Cargo => Plan::Mutate(Mutation::Run(cargo_install_command(target))),
        InstallChannel::Homebrew => Plan::Mutate(Mutation::Run(CommandSpec::new(
            "brew",
            ["upgrade", "s2-streamstore/s2/s2"],
        ))),
        InstallChannel::Docker => Plan::Advise(Advice::Docker),
        InstallChannel::SourceBuild => Plan::Advise(Advice::SourceBuild),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Choice {
    Yes,
    No,
    Skip,
}

/// Map a raw answer to a choice; `None` means "unrecognized, ask again".
/// An empty line (bare Enter) takes the default, yes.
fn parse_choice(input: &str) -> Option<Choice> {
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "y" | "yes" => Some(Choice::Yes),
        "n" | "no" => Some(Choice::No),
        "s" | "skip" => Some(Choice::Skip),
        _ => None,
    }
}

/// Ask the user to confirm: yes (default), no, or skip. Enter accepts the
/// default; EOF (Ctrl-D) cancels rather than accepting.
fn prompt_choice(question: &str) -> Choice {
    loop {
        print!("{question} [{}/n/s] ", "Y".bold());
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) | Err(_) => return Choice::No,
            Ok(_) => {}
        }
        match parse_choice(&line) {
            Some(choice) => return choice,
            None => println!(
                "Please answer {} (yes), {} (no), or {} (skip).",
                "y".cyan(),
                "n".cyan(),
                "s".cyan()
            ),
        }
    }
}

fn do_skip(target: &Version) -> Result<(), UpdateError> {
    if super::skip_version(target) {
        println!("Won't remind you about s2-cli {target} again.");
    }
    Ok(())
}

/// Run a package manager's upgrade command (Homebrew, Cargo).
fn run_command(command: &CommandSpec) -> Result<(), UpdateError> {
    println!("Running: {}", command.to_string().cyan());
    let status = std::process::Command::new(command.program)
        .args(&command.args)
        .status()
        .map_err(|e| UpdateError::Spawn(command.program.to_string(), e))?;
    if !status.success() {
        return Err(UpdateError::CommandFailed(command.to_string()));
    }
    Ok(())
}

async fn report_status(channel: InstallChannel, current: &Version) -> Result<(), UpdateError> {
    let latest = super::fetch_latest()
        .await
        .ok_or(UpdateError::LatestUnavailable)?;
    println!("Installed: {current} (via {channel})");
    println!("Latest:    {latest}");
    if &latest > current {
        println!("Run {} to upgrade.", "s2 update".cyan());
    } else {
        println!("You are on the latest release.");
    }
    Ok(())
}

/// Download, verify, and swap the binary in place.
async fn in_place_update(channel: InstallChannel, target: &Version) -> Result<(), UpdateError> {
    let exe = std::env::current_exe().map_err(UpdateError::CurrentExe)?;
    let asset = asset_name();
    let base = format!(
        "https://github.com/{repo}/releases/download/{CLI_TAG_PREFIX}{target}",
        repo = repo(),
    );
    let client = reqwest::Client::builder()
        .user_agent(channel::user_agent())
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .map_err(UpdateError::Http)?;

    println!("Downloading s2-cli {target} for {TARGET}...");

    let sums = get_text(&client, &format!("{base}/{CHECKSUMS_ASSET}"))
        .await
        .map_err(|_| UpdateError::ChecksumsUnavailable(target.clone()))?;
    let expected =
        checksum_for(&sums, &asset).ok_or_else(|| UpdateError::ChecksumMissing(asset.clone()))?;

    let archive = get_bytes(&client, &format!("{base}/{asset}"))
        .await
        .map_err(|e| UpdateError::Download(asset.clone(), e))?;

    let actual = sha256_hex(&archive);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(UpdateError::ChecksumMismatch {
            asset,
            expected: expected.to_string(),
            actual,
        });
    }

    let binary = extract_named(&archive, binary_name())?;
    install_binary(&exe, &binary)?;

    // Keep the receipt's recorded version current so detection stays correct.
    if channel == InstallChannel::InstallScript {
        write_receipt(&exe, target);
    }

    println!("{} s2-cli is now {target}.", "Updated:".green().bold());
    Ok(())
}

/// Write `binary` next to the running executable and atomically swap it into
/// place. Writing into the target directory first surfaces a permission error
/// cleanly and keeps the swap on one filesystem.
#[cfg(not(windows))]
fn install_binary(exe: &Path, binary: &[u8]) -> Result<(), UpdateError> {
    let map_err = |source| UpdateError::Install {
        path: exe.display().to_string(),
        source,
    };
    let dir = exe.parent().unwrap_or_else(|| Path::new("."));
    let staged = dir.join(format!(".s2-update-{}.tmp", uuid::Uuid::new_v4()));

    // A random name plus create_new prevents a pre-existing file or symlink
    // from being followed and truncated with the updater's privileges.
    let mut staged_file = open_new_staged_file(&staged).map_err(map_err)?;
    if let Err(e) = staged_file.write_all(binary) {
        drop(staged_file);
        let _ = std::fs::remove_file(&staged);
        return Err(map_err(e));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = staged_file.set_permissions(std::fs::Permissions::from_mode(0o755)) {
            drop(staged_file);
            let _ = std::fs::remove_file(&staged);
            return Err(map_err(e));
        }
    }
    drop(staged_file);

    let result = self_replace::self_replace(&staged).map_err(map_err);
    let _ = std::fs::remove_file(&staged);
    result
}

#[cfg(not(windows))]
fn open_new_staged_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(windows)]
fn install_binary(_exe: &Path, _binary: &[u8]) -> Result<(), UpdateError> {
    Err(UpdateError::WindowsInPlaceUnsupported)
}

fn write_receipt(exe: &Path, version: &Version) {
    let Some(dir) = exe.parent() else {
        return;
    };
    let receipt = format!(
        "{{\n  \"channel\": \"install-script\",\n  \"version\": \"{version}\",\n  \"binary_path\": {:?}\n}}\n",
        exe.display().to_string(),
    );
    let _ = std::fs::write(dir.join("s2-receipt.json"), receipt);
}

async fn get_text(client: &reqwest::Client, url: &str) -> Result<String, reqwest::Error> {
    client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

async fn get_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, reqwest::Error> {
    Ok(client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?
        .to_vec())
}

/// Repository to pull releases from; overridable via `S2_REPO` to match
/// `install.sh` (useful for forks and testing).
fn repo() -> String {
    std::env::var("S2_REPO").unwrap_or_else(|_| "s2-streamstore/s2".to_string())
}

fn asset_name() -> String {
    format!("s2-{TARGET}.zip")
}

fn binary_name() -> &'static str {
    if TARGET.contains("windows") {
        "s2.exe"
    } else {
        "s2"
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Find the hash for `asset` in a `shasum`-style `<hash>  <name>` listing.
/// Tolerates the leading `*` that binary-mode checksums prepend to names.
fn checksum_for<'a>(sums: &'a str, asset: &str) -> Option<&'a str> {
    sums.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let hash = fields.next()?;
        let name = fields.next()?;
        (name.trim_start_matches('*') == asset).then_some(hash)
    })
}

/// Extract the entry whose file name is `want` from a zip archive in memory.
fn extract_named(archive_bytes: &[u8], want: &str) -> Result<Vec<u8>, UpdateError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes))
        .map_err(|e| UpdateError::Archive(e.to_string()))?;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| UpdateError::Archive(e.to_string()))?;
        let is_file = entry.is_file();
        let base = entry
            .name()
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("")
            .to_string();
        if is_file && base == want {
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry
                .read_to_end(&mut buf)
                .map_err(|source| UpdateError::Install {
                    path: want.to_string(),
                    source,
                })?;
            return Ok(buf);
        }
    }
    Err(UpdateError::BinaryNotInArchive(want.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prompt_answers() {
        assert_eq!(parse_choice(""), Some(Choice::Yes)); // bare Enter -> default
        assert_eq!(parse_choice("y"), Some(Choice::Yes));
        assert_eq!(parse_choice(" YES\n"), Some(Choice::Yes));
        assert_eq!(parse_choice("n"), Some(Choice::No));
        assert_eq!(parse_choice("No"), Some(Choice::No));
        assert_eq!(parse_choice("s"), Some(Choice::Skip));
        assert_eq!(parse_choice("skip"), Some(Choice::Skip));
        assert_eq!(parse_choice("maybe"), None);
    }

    #[test]
    fn cargo_plan_pins_the_latest_target_as_one_argument() {
        let target = Version::parse("1.2.3-rc.1").unwrap();
        let expected = Plan::Mutate(Mutation::Run(CommandSpec::new(
            "cargo",
            [
                "install",
                "--locked",
                "--force",
                "--version",
                "1.2.3-rc.1",
                "s2-cli",
            ],
        )));

        assert_eq!(plan_update(InstallChannel::Cargo, &target, true), expected);
        assert_eq!(
            plan_update(InstallChannel::Cargo, &target, false),
            Plan::Advise(Advice::WindowsCargo)
        );
        assert!(
            Advice::WindowsCargo
                .render(&target, "example/fork")
                .contains("cargo install --locked --force --version 1.2.3-rc.1 s2-cli")
        );
    }

    #[test]
    fn homebrew_uses_its_upgrade_command() {
        let latest = Version::new(0, 42, 0);
        assert_eq!(
            plan_update(InstallChannel::Homebrew, &latest, true),
            Plan::Mutate(Mutation::Run(CommandSpec::new(
                "brew",
                ["upgrade", "s2-streamstore/s2/s2"],
            )))
        );
    }

    #[test]
    fn advisory_plans_name_the_exact_target_without_mutating() {
        let target = Version::new(0, 40, 0);
        let docker = plan_update(InstallChannel::Docker, &target, true);
        let source = plan_update(InstallChannel::SourceBuild, &target, true);
        let windows = plan_update(InstallChannel::GithubRelease, &target, false);

        assert_eq!(docker, Plan::Advise(Advice::Docker));
        assert!(
            Advice::Docker
                .render(&target, "example/fork")
                .contains("s2:0.40.0")
        );
        assert_eq!(source, Plan::Advise(Advice::SourceBuild));
        assert!(
            Advice::SourceBuild
                .render(&target, "example/fork")
                .contains("example/fork/releases/tag/s2-cli-v0.40.0")
        );
        assert_eq!(windows, Plan::Advise(Advice::WindowsRelease));
        assert!(
            Advice::WindowsRelease
                .render(&target, "example/fork")
                .contains("example/fork/releases/tag/s2-cli-v0.40.0")
        );
    }

    #[test]
    fn release_channels_only_replace_in_place_where_supported() {
        let target = Version::new(0, 42, 0);
        for channel in [InstallChannel::InstallScript, InstallChannel::GithubRelease] {
            assert_eq!(
                plan_update(channel, &target, true),
                Plan::Mutate(Mutation::InPlace)
            );
            assert_eq!(
                plan_update(channel, &target, false),
                Plan::Advise(Advice::WindowsRelease)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn staging_does_not_follow_an_existing_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let protected = dir.path().join("protected");
        let staged = dir.path().join(".s2-update-candidate.tmp");
        std::fs::write(&protected, b"do not overwrite").unwrap();
        symlink(&protected, &staged).unwrap();

        let error = open_new_staged_file(&staged).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&protected).unwrap(), b"do not overwrite");
    }

    #[cfg(windows)]
    #[test]
    fn windows_install_refuses_without_touching_the_executable() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("s2.exe");
        std::fs::write(&exe, b"old binary").unwrap();

        assert!(matches!(
            install_binary(&exe, b"new binary"),
            Err(UpdateError::WindowsInPlaceUnsupported)
        ));
        assert_eq!(std::fs::read(&exe).unwrap(), b"old binary");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn checksum_lookup_by_asset_name() {
        let sums = "\
aaa11111111111111111111111111111111111111111111111111111111111aa  s2-x86_64-apple-darwin.zip
bbb22222222222222222222222222222222222222222222222222222222222bb  s2-aarch64-apple-darwin.zip
ccc33333333333333333333333333333333333333333333333333333333333cc *s2-x86_64-unknown-linux-gnu.zip
";
        assert_eq!(
            checksum_for(sums, "s2-aarch64-apple-darwin.zip"),
            Some("bbb22222222222222222222222222222222222222222222222222222222222bb")
        );
        // Binary-mode `*` prefix on the filename is tolerated.
        assert_eq!(
            checksum_for(sums, "s2-x86_64-unknown-linux-gnu.zip"),
            Some("ccc33333333333333333333333333333333333333333333333333333333333cc")
        );
        assert_eq!(checksum_for(sums, "s2-nonexistent.zip"), None);
    }

    fn zip_with(entry: &str, data: &[u8]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zip::ZipWriter::start_file(&mut writer, entry, opts).unwrap();
            std::io::Write::write_all(&mut writer, data).unwrap();
            writer.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn extracts_named_entry_from_zip() {
        let payload = b"\x7fELF fake binary contents";
        let archive = zip_with("s2", payload);
        assert_eq!(extract_named(&archive, "s2").unwrap(), payload);

        // Entry nested under a directory is matched by base name.
        let nested = zip_with("release/s2", payload);
        assert_eq!(extract_named(&nested, "s2").unwrap(), payload);

        // Missing entry is a clean error, not a panic.
        assert!(matches!(
            extract_named(&archive, "s2.exe"),
            Err(UpdateError::BinaryNotInArchive(_))
        ));
    }
}
