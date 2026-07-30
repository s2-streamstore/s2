//! Errors returned by the SDK.
//!
//! Operations return the narrowest error type for their surface. Each error exposes
//! `is_retryable()`, `has_no_side_effects()`, `request_error()`, and `server_error()` as
//! applicable, so callers do not need to inspect display strings or unwrap the complete error
//! hierarchy.

pub use http::StatusCode;
pub use s2_api::v1::error::ErrorCode;

pub use crate::{
    api::ClientError,
    session::{
        append::AppendSessionError,
        read::{CaughtUpError, ReadSessionError},
    },
    types::{
        AppendConditionFailed, AppendError, ErrorResponse, ProducerError, ReadError, RequestError,
    },
};
