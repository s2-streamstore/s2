use axum::extract::{FromRequest, Path, Query, State};
#[cfg(feature = "utoipa")]
use http::StatusCode;
use s2_api::{data::Json, v1 as v1t};
use s2_common::types::{basin::BasinName, stream::StreamName};

#[cfg(feature = "utoipa")]
use super::paths;
use crate::{backend::Backend, handlers::v1::error::ServiceError};

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct AccountMetricsArgs {
    #[from_request(via(Query))]
    request: v1t::metrics::AccountMetricSetRequest,
}

/// Account-level metrics.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = paths::metrics::ACCOUNT_METRICS,
    tag = paths::metrics::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::metrics::MetricSetResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::metrics::AccountMetricSetRequest)
))]
pub async fn account_metrics(
    State(_backend): State<Backend>,
    AccountMetricsArgs { request: _ }: AccountMetricsArgs,
) -> Result<Json<v1t::metrics::MetricSetResponse>, ServiceError> {
    Ok(Json(v1t::metrics::MetricSetResponse { values: vec![] }))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct BasinMetricsArgs {
    #[from_request(via(Path))]
    basin: BasinName,
    #[from_request(via(Query))]
    request: v1t::metrics::BasinMetricSetRequest,
}

/// Basin-level metrics.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = paths::metrics::BASIN_METRICS,
    tag = paths::metrics::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::metrics::MetricSetResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::metrics::BasinMetricSetRequest, v1t::BasinNamePathSegment),
))]
pub async fn basin_metrics(
    State(_backend): State<Backend>,
    BasinMetricsArgs {
        basin: _,
        request: _,
    }: BasinMetricsArgs,
) -> Result<Json<v1t::metrics::MetricSetResponse>, ServiceError> {
    Ok(Json(v1t::metrics::MetricSetResponse { values: vec![] }))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct StreamMetricsArgs {
    #[from_request(via(Path))]
    basin_and_stream: (BasinName, StreamName),
    #[from_request(via(Query))]
    request: v1t::metrics::StreamMetricSetRequest,
}

/// Stream-level metrics.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = paths::metrics::STREAM_METRICS,
    tag = paths::metrics::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::metrics::MetricSetResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::metrics::StreamMetricSetRequest, v1t::BasinNamePathSegment, v1t::StreamNamePathSegment),
))]
pub async fn stream_metrics(
    State(_backend): State<Backend>,
    StreamMetricsArgs {
        basin_and_stream: _,
        request: _,
    }: StreamMetricsArgs,
) -> Result<Json<v1t::metrics::MetricSetResponse>, ServiceError> {
    Ok(Json(v1t::metrics::MetricSetResponse { values: vec![] }))
}
