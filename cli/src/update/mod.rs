//! Once-daily reminder when a newer s2-cli release is available on GitHub,
//! and the `s2 update` command that acts on it (see [`apply`]).

pub mod apply;
pub mod channel;

use std::{
    io::IsTerminal,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub use channel::{long_version, user_agent};
use colored::Colorize;
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

const RELEASES_API_URL: &str =
    "https://api.github.com/repos/s2-streamstore/s2/releases?per_page=50";
const CLI_TAG_PREFIX: &str = "s2-cli-v";
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Timestamp and result of the last release lookup, so at most one lookup
/// (and one reminder) happens per [`CHECK_INTERVAL`].
#[derive(Serialize, Deserialize)]
struct CheckState {
    checked_at: u64,
    latest_version: String,
    /// Version the user asked to stop being reminded about, via
    /// `s2 update --skip`. Reminders resume once a release newer than this
    /// appears.
    #[serde(default)]
    skipped_version: Option<String>,
}

fn state_path() -> Option<PathBuf> {
    let mut path = dirs::cache_dir()?;
    path.push("s2");
    path.push("cli-update-check.toml");
    Some(path)
}

fn load_state(path: &PathBuf) -> Option<CheckState> {
    toml::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn save_state(path: &PathBuf, state: &CheckState) {
    let Ok(contents) = toml::to_string(state) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, contents);
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Start the update check in the background, or return `None` when it should
/// not run:
///
/// - opted out via `S2_NO_UPDATE_CHECK`,
/// - stderr is not a terminal,
/// - running from the Docker image, where the binary is immutable and image tags are pinned
///   deliberately.
pub fn spawn_check() -> Option<JoinHandle<Option<Version>>> {
    if std::env::var_os("S2_NO_UPDATE_CHECK").is_some()
        || !std::io::stderr().is_terminal()
        || channel::detect() == channel::InstallChannel::Docker
    {
        return None;
    }
    Some(tokio::spawn(check()))
}

/// Return the latest released version if it is newer than the current one,
/// has not been skipped, and no check has run within [`CHECK_INTERVAL`].
async fn check() -> Option<Version> {
    let path = state_path()?;
    let now = unix_now();
    let state = load_state(&path);
    if let Some(state) = &state
        && now.saturating_sub(state.checked_at) < CHECK_INTERVAL.as_secs()
    {
        return None;
    }
    let skipped = state.as_ref().and_then(|s| s.skipped_version.clone());
    let fetched = fetch_latest().await;
    // Record the attempt even on fetch failure, so an unreachable GitHub does
    // not turn into a lookup on every invocation. Preserve any skip marker.
    let latest_version = fetched
        .as_ref()
        .map(ToString::to_string)
        .or_else(|| state.map(|s| s.latest_version))
        .unwrap_or_default();
    save_state(
        &path,
        &CheckState {
            checked_at: now,
            latest_version,
            skipped_version: skipped.clone(),
        },
    );
    let latest = fetched?;
    // A skip only silences that exact version; a newer release resumes nagging.
    if skipped.as_deref() == Some(latest.to_string().as_str()) {
        return None;
    }
    let current = Version::parse(CURRENT_VERSION).ok()?;
    (latest > current).then_some(latest)
}

/// Persist a request (from `s2 update --skip`) to stop reminding about
/// `version`. Returns whether the marker was written.
pub fn skip_version(version: &Version) -> bool {
    let Some(path) = state_path() else {
        return false;
    };
    let mut state = load_state(&path).unwrap_or(CheckState {
        checked_at: 0,
        latest_version: version.to_string(),
        skipped_version: None,
    });
    state.skipped_version = Some(version.to_string());
    save_state(&path, &state);
    true
}

pub(crate) async fn fetch_latest() -> Option<Version> {
    #[derive(Deserialize)]
    struct Release {
        tag_name: String,
        prerelease: bool,
        draft: bool,
    }

    let client = reqwest::Client::builder()
        .user_agent(user_agent())
        .timeout(FETCH_TIMEOUT)
        .build()
        .ok()?;
    let body = client
        .get(RELEASES_API_URL)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .text()
        .await
        .ok()?;
    let releases: Vec<Release> = serde_json::from_str(&body).ok()?;
    latest_cli_version(
        releases
            .iter()
            .map(|r| (r.tag_name.as_str(), !r.prerelease && !r.draft)),
    )
}

fn latest_cli_version<'a>(tags: impl IntoIterator<Item = (&'a str, bool)>) -> Option<Version> {
    tags.into_iter()
        .filter(|(_, released)| *released)
        .filter_map(|(tag, _)| tag.strip_prefix(CLI_TAG_PREFIX))
        .filter_map(|v| Version::parse(v).ok())
        .max()
}

/// Await the background check and print a reminder if a newer version exists.
pub async fn notify(check: Option<JoinHandle<Option<Version>>>) {
    let Some(handle) = check else {
        return;
    };
    let Ok(Ok(Some(latest))) = tokio::time::timeout(FETCH_TIMEOUT, handle).await else {
        return;
    };
    eprintln!(
        "\n{} {} {}",
        "A new release of s2-cli is available:".yellow(),
        CURRENT_VERSION.cyan(),
        format!("→ {latest}").cyan(),
    );
    // `s2 update` handles every install channel (in-place upgrade, delegating
    // to a package manager, or explaining how), so it is the one hint to give.
    eprintln!("{} {}", "To upgrade, run:".yellow(), "s2 update".cyan());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_latest_released_cli_tag() {
        let tags = [
            ("s2-cli-v0.38.0", true),
            ("s2-lite-v0.38.0", true),
            ("s2-cli-v0.39.0", false),
            ("s2-cli-v0.38.2", true),
            ("s2-sdk-v0.31.8", true),
            ("s2-cli-v0.38.10", true),
        ];
        assert_eq!(
            latest_cli_version(tags),
            Some(Version::new(0, 38, 10)),
            "highest semver among released s2-cli tags"
        );
        assert_eq!(latest_cli_version([("s2-sdk-v0.31.8", true)]), None);
    }

    #[tokio::test]
    #[ignore = "hits the GitHub API"]
    async fn fetches_latest_cli_release() {
        let latest = fetch_latest().await;
        assert!(latest.is_some(), "expected a released s2-cli version");
    }
}
