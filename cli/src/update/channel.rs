//! Detection of the channel through which the running binary was installed.
//!
//! Sources of truth, in strict order of precedence (each layer only narrows,
//! never overrides an earlier one):
//!
//! 1. Install receipt: an `s2-receipt.json` written by `install.sh` next to the binary. Only
//!    trusted when the binary path recorded in the receipt resolves to the running executable, so a
//!    binary copied elsewhere does not inherit the receipt.
//! 2. Channel-specific build stamp: the `S2_BUILD_CHANNEL` env var baked in at compile time by
//!    build pipelines that know the channel exactly (`docker` in the Dockerfile; `brew` reserved
//!    for brew-flavored artifacts).
//! 3. Environment facts (definitional, not heuristic):
//!    - a resolved executable under a Homebrew cellar was installed by brew;
//!    - one under `$CARGO_INSTALL_ROOT/bin`, `$CARGO_HOME/bin`, or `~/.cargo/bin` was installed by
//!      `cargo install`.
//! 4. Generic `release` stamp from release CI: an official artifact whose installation method is
//!    otherwise unknown, i.e. a manual download from GitHub releases. Weakest stamp on purpose:
//!    today the brew tap repackages these same artifacts, so a Cellar path must win over it.
//! 5. Nothing matched: locally built from source.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use serde::Deserialize;

/// Channel baked into official binaries at build time.
const BUILD_CHANNEL: Option<&str> = option_env!("S2_BUILD_CHANNEL");

/// Name of the receipt file `install.sh` writes next to the binary.
const RECEIPT_FILE: &str = "s2-receipt.json";

/// Receipt `channel` value written by `install.sh`.
const INSTALL_SCRIPT_CHANNEL: &str = "install-script";

/// How the running binary was installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallChannel {
    /// Installed by `install.sh` (a matching receipt is present).
    InstallScript,
    /// Installed via the Homebrew tap.
    Homebrew,
    /// Built and installed by `cargo install`.
    Cargo,
    /// Running from the official Docker image.
    Docker,
    /// Official release artifact, but not installed by `install.sh`:
    /// a manual download from GitHub releases.
    GithubRelease,
    /// Locally built from source.
    SourceBuild,
}

impl fmt::Display for InstallChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InstallScript => "install script",
            Self::Homebrew => "homebrew",
            Self::Cargo => "cargo",
            Self::Docker => "docker",
            Self::GithubRelease => "github release",
            Self::SourceBuild => "source build",
        })
    }
}

impl InstallChannel {
    /// Exact command that upgrades an installation from this channel, when
    /// there is an unambiguous one:
    ///
    /// - Channels without a manager re-run `install.sh` (replaced by `s2 self-update` once that
    ///   exists).
    /// - Managed channels go through their manager, which owns the binary.
    /// - `GithubRelease` and `SourceBuild` have no single right answer, so callers should fall back
    ///   to pointing at the docs.
    pub fn upgrade_command(&self) -> Option<&'static str> {
        match self {
            Self::InstallScript => Some(
                "curl -fsSL https://raw.githubusercontent.com/s2-streamstore/s2/main/install.sh | bash",
            ),
            Self::Homebrew => Some("brew upgrade s2-streamstore/s2/s2"),
            Self::Cargo => Some("cargo install --locked s2-cli"),
            Self::Docker => Some("docker pull ghcr.io/s2-streamstore/s2"),
            Self::GithubRelease | Self::SourceBuild => None,
        }
    }
}

/// Resolve the install channel of the running executable.
///
/// Cached for the lifetime of the process since the answer cannot change.
pub fn detect() -> InstallChannel {
    static CHANNEL: LazyLock<InstallChannel> = LazyLock::new(|| {
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::canonicalize(p).ok());
        resolve(exe.as_deref(), BUILD_CHANNEL)
    });
    *CHANNEL
}

/// Version string for `--version` that includes the detected install
/// channel, e.g. `0.40.1 (via homebrew)`.
pub fn long_version() -> &'static str {
    static VERSION: LazyLock<String> =
        LazyLock::new(|| format!("{} (via {})", env!("CARGO_PKG_VERSION"), detect()));
    &VERSION
}

/// Apply the precedence order documented at the module level.
///
/// `exe` must already be symlink-resolved: Homebrew installs into a keg and
/// symlinks into `bin`, so the raw `current_exe` path would hide the cellar.
fn resolve(exe: Option<&Path>, stamp: Option<&str>) -> InstallChannel {
    if let Some(exe) = exe
        && receipt_matches(exe)
    {
        return InstallChannel::InstallScript;
    }
    match stamp {
        Some("docker") => return InstallChannel::Docker,
        Some("brew") => return InstallChannel::Homebrew,
        _ => {}
    }
    if let Some(exe) = exe {
        if is_homebrew(exe, std::env::var_os("HOMEBREW_CELLAR").map(PathBuf::from)) {
            return InstallChannel::Homebrew;
        }
        if is_cargo(exe, cargo_bin_dirs()) {
            return InstallChannel::Cargo;
        }
    }
    if stamp == Some("release") {
        return InstallChannel::GithubRelease;
    }
    InstallChannel::SourceBuild
}

/// Subset of the receipt `install.sh` writes that detection relies on;
/// unknown fields are ignored so the receipt schema can grow.
#[derive(Deserialize)]
struct Receipt {
    channel: String,
    binary_path: PathBuf,
}

/// Whether a receipt next to `exe` claims `exe` itself was installed by
/// `install.sh`. The recorded path must resolve to the running executable —
/// this is what keeps detection deterministic for copied binaries.
fn receipt_matches(exe: &Path) -> bool {
    let Some(dir) = exe.parent() else {
        return false;
    };
    let Ok(contents) = std::fs::read_to_string(dir.join(RECEIPT_FILE)) else {
        return false;
    };
    let Ok(receipt) = serde_json::from_str::<Receipt>(&contents) else {
        return false;
    };
    receipt.channel == INSTALL_SCRIPT_CHANNEL
        && std::fs::canonicalize(&receipt.binary_path).is_ok_and(|p| p == exe)
}

/// Homebrew always installs into a keg under the cellar (`Cellar` in
/// standard prefixes, `$HOMEBREW_CELLAR` when relocated) and symlinks into
/// `bin`, so a resolved path under the cellar is brew by definition.
fn is_homebrew(exe: &Path, cellar: Option<PathBuf>) -> bool {
    exe.components().any(|c| c.as_os_str() == "Cellar")
        || cellar.is_some_and(|c| exe.starts_with(c))
}

/// Directories where `cargo install` places binaries, in cargo's own
/// resolution order: `$CARGO_INSTALL_ROOT/bin`, `$CARGO_HOME/bin`,
/// `~/.cargo/bin`.
fn cargo_bin_dirs() -> Vec<PathBuf> {
    [
        std::env::var_os("CARGO_INSTALL_ROOT").map(PathBuf::from),
        std::env::var_os("CARGO_HOME").map(PathBuf::from),
        dirs::home_dir().map(|home| home.join(".cargo")),
    ]
    .into_iter()
    .flatten()
    .map(|root| root.join("bin"))
    .collect()
}

/// Whether `exe` lives directly in one of the cargo bin directories.
/// Compares against the symlink-resolved directory as well, since `exe` is
/// canonicalized but `$CARGO_HOME` may be recorded through a symlink.
fn is_cargo(exe: &Path, bin_dirs: Vec<PathBuf>) -> bool {
    let Some(parent) = exe.parent() else {
        return false;
    };
    bin_dirs.into_iter().any(|dir| {
        parent == dir || std::fs::canonicalize(&dir).is_ok_and(|resolved| parent == resolved)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_resolution_without_receipt_or_known_paths() {
        let exe = Path::new("/weird/place/s2");
        assert_eq!(resolve(Some(exe), Some("docker")), InstallChannel::Docker);
        assert_eq!(resolve(Some(exe), Some("brew")), InstallChannel::Homebrew);
        assert_eq!(
            resolve(Some(exe), Some("release")),
            InstallChannel::GithubRelease
        );
        assert_eq!(resolve(Some(exe), None), InstallChannel::SourceBuild);
        assert_eq!(resolve(None, None), InstallChannel::SourceBuild);
    }

    #[test]
    fn cellar_path_wins_over_release_stamp() {
        // Brew currently repackages the release-stamped artifacts, so the
        // environment fact must take precedence over the generic stamp.
        let exe = Path::new("/opt/homebrew/Cellar/s2/0.40.1/bin/s2");
        assert_eq!(
            resolve(Some(exe), Some("release")),
            InstallChannel::Homebrew
        );
    }

    #[test]
    fn homebrew_detection() {
        assert!(is_homebrew(
            Path::new("/opt/homebrew/Cellar/s2/0.40.1/bin/s2"),
            None
        ));
        assert!(is_homebrew(
            Path::new("/home/linuxbrew/.linuxbrew/Cellar/s2/0.40.1/bin/s2"),
            None
        ));
        assert!(is_homebrew(
            Path::new("/custom/kegs/s2/0.40.1/bin/s2"),
            Some(PathBuf::from("/custom/kegs"))
        ));
        assert!(!is_homebrew(Path::new("/Users/me/.s2/bin/s2"), None));
        assert!(!is_homebrew(Path::new("/usr/local/bin/s2"), None));
    }

    #[test]
    fn cargo_detection() {
        let dirs = vec![PathBuf::from("/Users/me/.cargo/bin")];
        assert!(is_cargo(Path::new("/Users/me/.cargo/bin/s2"), dirs.clone()));
        assert!(!is_cargo(Path::new("/Users/me/.s2/bin/s2"), dirs.clone()));
        // Not directly in the bin dir.
        assert!(!is_cargo(Path::new("/Users/me/.cargo/bin/sub/s2"), dirs));
    }

    #[test]
    fn receipt_must_point_at_the_running_executable() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("s2");
        std::fs::write(&exe, "").unwrap();
        let exe = std::fs::canonicalize(&exe).unwrap();

        // No receipt.
        assert!(!receipt_matches(&exe));

        // Matching receipt; extra fields are ignored.
        std::fs::write(
            dir.path().join(RECEIPT_FILE),
            format!(
                r#"{{"channel": "install-script", "version": "0.40.1",
                     "binary_path": {:?}, "installed_at": "2026-07-23T00:00:00Z"}}"#,
                exe
            ),
        )
        .unwrap();
        assert!(receipt_matches(&exe));
        assert_eq!(
            resolve(Some(&exe), Some("release")),
            InstallChannel::InstallScript,
            "receipt takes precedence over the stamp"
        );

        // Receipt pointing at some other binary must not match.
        std::fs::write(
            dir.path().join(RECEIPT_FILE),
            r#"{"channel": "install-script", "binary_path": "/somewhere/else/s2"}"#,
        )
        .unwrap();
        assert!(!receipt_matches(&exe));

        // Receipt for an unknown channel must not match.
        std::fs::write(
            dir.path().join(RECEIPT_FILE),
            format!(r#"{{"channel": "mystery", "binary_path": {exe:?}}}"#),
        )
        .unwrap();
        assert!(!receipt_matches(&exe));
    }
}
