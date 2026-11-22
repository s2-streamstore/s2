//! Common types and utilities shared across S2 crates.

pub mod access;
pub mod basin;
pub mod caps;
pub mod config;
pub mod deep_size;
pub mod encryption;
pub mod http;
pub mod location;
pub mod maybe;
pub mod metrics;
pub mod network_policy;
pub mod read_extent;
pub mod record;
pub mod resources;
pub mod stream;
mod strings;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ValidationError(pub String);

impl ValidationError {
    /// Return the human-readable validation error message.
    pub fn message(&self) -> &str {
        &self.0
    }

    /// Whether retrying the operation with the same inputs may succeed (always `false`).
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Whether the failed attempt certainly had no side effects (always `true`).
    pub fn has_no_side_effects(&self) -> bool {
        true
    }
}

impl From<String> for ValidationError {
    fn from(value: String) -> Self {
        ValidationError(value)
    }
}

impl From<&str> for ValidationError {
    fn from(value: &str) -> Self {
        ValidationError(value.to_owned())
    }
}

impl From<record::FencingTokenTooLongError> for ValidationError {
    fn from(e: record::FencingTokenTooLongError) -> Self {
        ValidationError(e.to_string())
    }
}
