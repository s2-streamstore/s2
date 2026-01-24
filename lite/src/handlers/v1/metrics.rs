use axum::extract::{Extension, FromRequest, Path, Query, State};
use http::header::AUTHORIZATION;
use s2_api::{data::Json, v1 as v1t};
use s2_common::types::{access::Operation, basin::BasinName, stream::StreamName};

use crate::{
    auth::{self, AuthState},
    backend::Backend,
    handlers::v1::{AppState, error::ServiceError, middleware::AuthenticatedRequest},
};

/// Authorize metrics access.
///
/// Authorization logic:
/// 1. If Biscuit auth is enabled (AuthenticatedRequest present) → use Biscuit authorization
/// 2. If Biscuit auth disabled but metrics_token configured → require Bearer token
/// 3. If neither → allow all (metrics are public)
fn authorize_metrics(
    auth_req: Option<&AuthenticatedRequest>,
    auth_state: &AuthState,
    headers: &http::HeaderMap,
    basin: Option<&str>,
    stream: Option<&str>,
    operation: Operation,
) -> Result<(), ServiceError> {
    // If Biscuit auth is enabled, use it
    if let Some(auth) = auth_req {
        return auth::authorize(
            &auth.token,
            &auth.client_public_key,
            basin,
            stream,
            None,
            operation,
        )
        .map_err(ServiceError::from);
    }

    // If metrics token is configured, check it
    if let Some(expected_token) = auth_state.metrics_token() {
        let auth_header = headers
            .get(AUTHORIZATION)
            .ok_or(ServiceError::AuthRequired)?;
        let auth_str = auth_header
            .to_str()
            .map_err(|_| ServiceError::AuthRequired)?;

        // Parse "Bearer <token>"
        let parts: Vec<&str> = auth_str.splitn(2, ' ').collect();
        if parts.len() != 2 || !parts[0].eq_ignore_ascii_case("bearer") {
            return Err(ServiceError::AuthRequired);
        }

        if parts[1] != expected_token {
            return Err(ServiceError::AuthRequired);
        }
    }

    // Neither Biscuit auth nor metrics token → allow all
    Ok(())
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new()
        .route(super::paths::metrics::ACCOUNT, get(account_metrics))
        .route(super::paths::metrics::BASIN, get(basin_metrics))
        .route(super::paths::metrics::STREAM, get(stream_metrics))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct AccountArgs {
    #[from_request(via(Query))]
    _request: v1t::metrics::AccountMetricSetRequest,
}

/// Account-level metrics.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::metrics::ACCOUNT,
    tag = super::paths::metrics::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::metrics::MetricSetResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::metrics::AccountMetricSetRequest)
))]
pub async fn account_metrics(
    State(auth_state): State<AuthState>,
    State(_backend): State<Backend>,
    auth: Option<Extension<AuthenticatedRequest>>,
    headers: http::HeaderMap,
    AccountArgs { .. }: AccountArgs,
) -> Result<Json<v1t::metrics::MetricSetResponse>, ServiceError> {
    authorize_metrics(
        auth.as_ref().map(|e| &e.0),
        &auth_state,
        &headers,
        None,
        None,
        Operation::AccountMetrics,
    )?;
    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct BasinArgs {
    #[from_request(via(Path))]
    _basin: BasinName,
    #[from_request(via(Query))]
    _request: v1t::metrics::BasinMetricSetRequest,
}

/// Basin-level metrics.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::metrics::BASIN,
    tag = super::paths::metrics::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::metrics::MetricSetResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::metrics::BasinMetricSetRequest, v1t::BasinNamePathSegment),
))]
pub async fn basin_metrics(
    State(auth_state): State<AuthState>,
    State(_backend): State<Backend>,
    auth: Option<Extension<AuthenticatedRequest>>,
    headers: http::HeaderMap,
    BasinArgs { _basin: basin, .. }: BasinArgs,
) -> Result<Json<v1t::metrics::MetricSetResponse>, ServiceError> {
    authorize_metrics(
        auth.as_ref().map(|e| &e.0),
        &auth_state,
        &headers,
        Some(basin.as_ref()),
        None,
        Operation::BasinMetrics,
    )?;
    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct StreamArgs {
    #[from_request(via(Path))]
    _basin_and_stream: (BasinName, StreamName),
    #[from_request(via(Query))]
    _request: v1t::metrics::StreamMetricSetRequest,
}

/// Stream-level metrics.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::metrics::STREAM,
    tag = super::paths::metrics::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::metrics::MetricSetResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::metrics::StreamMetricSetRequest, v1t::BasinNamePathSegment, v1t::StreamNamePathSegment),
))]
pub async fn stream_metrics(
    State(auth_state): State<AuthState>,
    State(_backend): State<Backend>,
    auth: Option<Extension<AuthenticatedRequest>>,
    headers: http::HeaderMap,
    StreamArgs {
        _basin_and_stream: (basin, stream),
        ..
    }: StreamArgs,
) -> Result<Json<v1t::metrics::MetricSetResponse>, ServiceError> {
    authorize_metrics(
        auth.as_ref().map(|e| &e.0),
        &auth_state,
        &headers,
        Some(basin.as_ref()),
        Some(stream.as_ref()),
        Operation::StreamMetrics,
    )?;
    Err(ServiceError::NotImplemented)
}
