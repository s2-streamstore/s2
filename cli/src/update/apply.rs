//! `s2 update`: bring the CLI up to date using the strategy that matches how
//! it was installed (see [`super::channel`]).
//!
//! - Install script or manual GitHub download (`InstallScript`, `GithubRelease`): download the
//!   release artifact for this exact target, verify its SHA-256 against the release's `SHA256SUMS`,
//!   and atomically replace the running binary in place.
//! - Homebrew or Cargo: the package manager owns the binary, so print its upgrade command (or run
//!   it with `--yes`).
//! - Docker or source build: nothing to replace; explain how to update.

use std::{
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
    #[error("{0:?} is not a valid version")]
    BadVersion(String),
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

    let target = match &args.version {
        Some(v) => parse_version(v)?,
        None => super::fetch_latest()
            .await
            .ok_or(UpdateError::LatestUnavailable)?,
    };

    // Explicit --skip just records the marker and does nothing else.
    if args.skip {
        return do_skip(&target);
    }

    // Only short-circuit when tracking the latest; an explicit --version is
    // always honored (allows reinstalling or downgrading).
    if args.version.is_none() && target <= current {
        println!("s2-cli {current} is already up to date.");
        return Ok(());
    }

    // Channels with no binary we can replace: explain and stop.
    let action = match channel {
        InstallChannel::InstallScript | InstallChannel::GithubRelease => Action::InPlace,
        InstallChannel::Homebrew | InstallChannel::Cargo => Action::Run(
            channel
                .upgrade_command()
                .expect("managed channels always have an upgrade command"),
        ),
        InstallChannel::Docker => {
            println!("This is the Docker build of s2-cli. Pull a newer image tag:");
            println!("    {}", "docker pull ghcr.io/s2-streamstore/s2".cyan());
            return Ok(());
        }
        InstallChannel::SourceBuild => {
            println!("This s2-cli was built from source. Update your checkout and rebuild,");
            println!("or install a release build: {}", DOCS_URL.cyan());
            return Ok(());
        }
    };

    // Describe what upgrading entails before asking.
    println!("s2-cli {current} → {target}  (installed via {channel})");
    if let Action::Run(command) = action {
        println!("This will run: {}", command.cyan());
    }

    // Confirm interactively, unless --yes was given. Never block on a prompt
    // when there is no terminal to answer it (e.g. CI, piped input).
    let choice = if args.yes {
        Choice::Yes
    } else if std::io::stdin().is_terminal() {
        prompt_choice("Update now?")
    } else {
        match action {
            Action::InPlace => println!("Re-run with {} to update in place.", "--yes".cyan()),
            Action::Run(command) => println!(
                "Run {} yourself, or re-run with {}.",
                command.cyan(),
                "--yes".cyan()
            ),
        }
        return Ok(());
    };

    match choice {
        Choice::Yes => match action {
            Action::InPlace => in_place_update(channel, &target).await,
            Action::Run(command) => run_command(command),
        },
        Choice::Skip => do_skip(&target),
        Choice::No => {
            println!("Cancelled; no changes made.");
            Ok(())
        }
    }
}

/// What upgrading this install entails.
#[derive(Clone, Copy)]
enum Action {
    /// Download the release artifact and replace the binary in place.
    InPlace,
    /// Delegate to a package manager's upgrade command.
    Run(&'static str),
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
fn run_command(command: &str) -> Result<(), UpdateError> {
    println!("Running: {}", command.cyan());
    let mut parts = command.split_whitespace();
    let program = parts.next().expect("upgrade command is non-empty");
    let status = std::process::Command::new(program)
        .args(parts)
        .status()
        .map_err(|e| UpdateError::Spawn(program.to_string(), e))?;
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
        .user_agent(concat!("s2-cli/", env!("CARGO_PKG_VERSION")))
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
fn install_binary(exe: &Path, binary: &[u8]) -> Result<(), UpdateError> {
    let map_err = |source| UpdateError::Install {
        path: exe.display().to_string(),
        source,
    };
    let dir = exe.parent().unwrap_or_else(|| Path::new("."));
    let staged = dir.join(format!(".s2-update-{}.tmp", std::process::id()));

    std::fs::write(&staged, binary).map_err(map_err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)) {
            let _ = std::fs::remove_file(&staged);
            return Err(map_err(e));
        }
    }
    let result = self_replace::self_replace(&staged).map_err(map_err);
    let _ = std::fs::remove_file(&staged);
    result
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

/// Accept `1.2.3`, `v1.2.3`, or `s2-cli-v1.2.3`.
fn parse_version(input: &str) -> Result<Version, UpdateError> {
    let trimmed = input
        .strip_prefix(CLI_TAG_PREFIX)
        .or_else(|| input.strip_prefix('v'))
        .unwrap_or(input);
    Version::parse(trimmed).map_err(|_| UpdateError::BadVersion(input.to_string()))
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
    fn parses_version_in_all_forms() {
        for input in ["1.2.3", "v1.2.3", "s2-cli-v1.2.3"] {
            assert_eq!(parse_version(input).unwrap(), Version::new(1, 2, 3));
        }
        assert!(parse_version("not-a-version").is_err());
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
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

    #[test]
    fn asset_and_binary_names_are_consistent() {
        assert!(asset_name().starts_with("s2-"));
        assert!(asset_name().ends_with(".zip"));
        assert!(matches!(binary_name(), "s2" | "s2.exe"));
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
