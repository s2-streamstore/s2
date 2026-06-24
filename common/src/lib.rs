//! Common types and utilities shared across S2 crates.

pub mod access;
pub mod basin;
pub mod caps;
pub mod config;
pub mod encryption;
pub mod http;
pub mod location;
pub mod maybe;
pub mod metrics;
pub mod read_extent;
pub mod record;
pub mod resources;
pub mod stream;
mod strings;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ValidationError(pub String);

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
