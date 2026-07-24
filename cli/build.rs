//! Records build provenance in the CLI binary:
//! - the target triple, so `s2 update` can pick the matching release artifact;
//! - the exact source commit, for `s2 --version`.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const REVISION_OVERRIDE: &str = "S2_GIT_REV";
const EMBEDDED_REVISION: &str = "S2_GIT_COMMIT";
const UNKNOWN_REVISION: &str = "unknown";

fn main() {
    println!("cargo::rerun-if-env-changed={REVISION_OVERRIDE}");
    println!("cargo::rerun-if-env-changed=S2_BUILD_CHANNEL");

    let target = env::var("TARGET").expect("cargo sets TARGET for build scripts");
    println!("cargo::rustc-env=S2_TARGET={target}");

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR for build scripts"),
    );
    let revision = resolve_revision(&manifest_dir);
    if revision == UNKNOWN_REVISION {
        if env::var("S2_BUILD_CHANNEL").as_deref() == Ok("release") {
            panic!("official release builds must set {REVISION_OVERRIDE} to the source commit");
        }
        println!("cargo::warning=building s2-cli without source commit metadata");
    }
    println!("cargo::rustc-env={EMBEDDED_REVISION}={revision}");
}

fn resolve_revision(manifest_dir: &Path) -> String {
    if let Some(revision) = revision_override() {
        return revision;
    }

    let vcs_info = manifest_dir.join(".cargo_vcs_info.json");
    if let Some(revision) = packaged_revision(&vcs_info) {
        println!("cargo::rerun-if-changed={}", vcs_info.display());
        return revision;
    }

    if let Some(revision) = git_revision(manifest_dir) {
        emit_git_rerun_hints(manifest_dir);
        return revision;
    }

    UNKNOWN_REVISION.to_string()
}

fn revision_override() -> Option<String> {
    match env::var(REVISION_OVERRIDE) {
        Ok(revision) => {
            if revision != UNKNOWN_REVISION {
                assert!(
                    is_full_git_hash(&revision),
                    "{REVISION_OVERRIDE} must be `unknown` or a full 40- or 64-character hexadecimal commit hash"
                );
            }
            Some(revision)
        }
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            panic!("{REVISION_OVERRIDE} must contain valid UTF-8")
        }
    }
}

fn packaged_revision(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let document: serde_json::Value = serde_json::from_str(&contents).ok()?;
    let revision = document.pointer("/git/sha1")?.as_str()?;
    is_full_git_hash(revision).then(|| revision.to_string())
}

fn git_revision(manifest_dir: &Path) -> Option<String> {
    let output = git_output(manifest_dir, &["rev-parse", "--verify", "HEAD"])?;
    is_full_git_hash(&output).then_some(output)
}

fn emit_git_rerun_hints(manifest_dir: &Path) {
    let Some(head) = git_path(manifest_dir, "HEAD") else {
        return;
    };
    println!("cargo::rerun-if-changed={}", head.display());

    // The loose ref file may not exist (e.g. right after `git pack-refs`); cargo
    // treats a registered-but-missing path as always dirty, which errs toward an
    // extra rebuild rather than a stale embedded revision.
    if let Ok(contents) = fs::read_to_string(&head)
        && let Some(reference) = contents.strip_prefix("ref: ").map(str::trim)
    {
        for path in [reference, "packed-refs"] {
            if let Some(path) = git_path(manifest_dir, path) {
                println!("cargo::rerun-if-changed={}", path.display());
            }
        }
    }
}

fn git_path(manifest_dir: &Path, path: &str) -> Option<PathBuf> {
    let path = PathBuf::from(git_output(
        manifest_dir,
        &["rev-parse", "--git-path", path],
    )?);
    Some(if path.is_absolute() {
        path
    } else {
        manifest_dir.join(path)
    })
}

fn git_output(manifest_dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(manifest_dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|output| output.trim().to_string())
        .filter(|output| !output.is_empty())
}

fn is_full_git_hash(revision: &str) -> bool {
    matches!(revision.len(), 40 | 64) && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}
