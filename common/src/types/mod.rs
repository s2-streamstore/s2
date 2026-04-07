pub mod access;
pub mod basin;
pub mod config;
pub mod metrics;
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

impl From<crate::record::FencingTokenTooLongError> for ValidationError {
    fn from(e: crate::record::FencingTokenTooLongError) -> Self {
        ValidationError(e.to_string())
    }
}

impl From<resources::StartAfterLessThanPrefixError> for ValidationError {
    fn from(e: resources::StartAfterLessThanPrefixError) -> Self {
        ValidationError(e.to_string())
    }
}
