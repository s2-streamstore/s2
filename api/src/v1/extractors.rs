use std::fmt::Display;

use axum::{
    Json,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use s2_common::header::ExtractableHeader;

use super::ErrorInfo;

#[derive(Debug)]
pub enum HeaderExtractionError {
    MissingHeader(&'static str),
    InvalidUtf8(&'static str),
    InvalidHeaderValue(&'static str, String),
}

impl IntoResponse for HeaderExtractionError {
    fn into_response(self) -> Response {
        let (code, message) = match self {
            HeaderExtractionError::MissingHeader(header) => (
                "header_missing",
                format!("Missing required header: {}", header),
            ),
            HeaderExtractionError::InvalidUtf8(header) => (
                "header_invalid",
                format!("Header {} contains invalid UTF-8", header),
            ),
            HeaderExtractionError::InvalidHeaderValue(header, error) => (
                "header_invalid",
                format!("Invalid header value for {}: {}", header, error),
            ),
        };
        (StatusCode::BAD_REQUEST, Json(ErrorInfo { code, message })).into_response()
    }
}

fn parse_header<T>(parts: &Parts) -> Result<Option<T>, HeaderExtractionError>
where
    T: ExtractableHeader,
    T::Err: Display,
{
    let name = T::name();
    let Some(value) = parts.headers.get(name) else {
        return Ok(None);
    };

    let value_str = value
        .to_str()
        .map_err(|_| HeaderExtractionError::InvalidUtf8(name.as_str()))?;

    let parsed = value_str
        .parse::<T>()
        .map_err(|e| HeaderExtractionError::InvalidHeaderValue(name.as_str(), e.to_string()))?;

    Ok(Some(parsed))
}

#[derive(Debug, Clone)]
pub struct RequiredHeader<T>(pub T);

impl<S, T> FromRequestParts<S> for RequiredHeader<T>
where
    S: Send + Sync,
    T: ExtractableHeader,
    T::Err: Display,
{
    type Rejection = HeaderExtractionError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let value = parse_header(parts)?
            .ok_or_else(|| HeaderExtractionError::MissingHeader(T::name().as_str()))?;
        Ok(RequiredHeader(value))
    }
}

#[derive(Debug, Clone)]
pub struct OptionalHeader<T>(pub Option<T>);

impl<S, T> FromRequestParts<S> for OptionalHeader<T>
where
    S: Send + Sync,
    T: ExtractableHeader,
    T::Err: Display,
{
    type Rejection = HeaderExtractionError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let value = parse_header(parts)?;
        Ok(OptionalHeader(value))
    }
}
