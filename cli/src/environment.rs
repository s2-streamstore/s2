//! Where and how the CLI is running, for behaviour that depends on it. Detected on each run and
//! never stored.

use crate::{config::CliConfig, login};

/// What the configured endpoints point at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// S2 itself, at its default endpoints.
    S2,
    /// Another endpoint that is not local.
    Custom,
    /// A loopback endpoint, most likely `s2 lite`.
    Local,
}

/// The syntax to use for commands shown to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Posix,
    PowerShell,
}

#[derive(Debug, Clone, Copy)]
pub struct Environment {
    pub target: Target,
    pub shell: Shell,
}

impl Environment {
    pub fn detect(config: &CliConfig) -> Self {
        Self {
            target: Target::detect(config),
            shell: Shell::detect(),
        }
    }
}

impl Target {
    pub fn detect(config: &CliConfig) -> Self {
        if login::uses_default_endpoints(config) {
            Self::S2
        } else if login::uses_loopback_endpoints(config) {
            Self::Local
        } else {
            Self::Custom
        }
    }
}

impl Shell {
    /// PowerShell and `cmd` cannot be told apart without inspecting the parent process, so
    /// Windows is taken to be PowerShell unless a POSIX shell such as Git Bash set `SHELL`.
    pub fn detect() -> Self {
        if cfg!(windows) && std::env::var_os("SHELL").is_none() {
            Self::PowerShell
        } else {
            Self::Posix
        }
    }
}
