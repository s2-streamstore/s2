use axum::extract::{FromRequest, Path, Query, State};
use s2_api::{data::Json, v1 as v1t};
use s2_common::types::{basin::BasinName, stream::StreamName};

use crate::{backend::Backend, handlers::v1::error::ServiceError};

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
    State(_backend): State<Backend>,
    AccountArgs { .. }: AccountArgs,
) -> Result<Json<v1t::metrics::MetricSetResponse>, ServiceError> {
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
    State(_backend): State<Backend>,
    BasinArgs { .. }: BasinArgs,
) -> Result<Json<v1t::metrics::MetricSetResponse>, ServiceError> {
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
    State(_backend): State<Backend>,
    StreamArgs { .. }: StreamArgs,
) -> Result<Json<v1t::metrics::MetricSetResponse>, ServiceError> {
    Err(ServiceError::NotImplemented)
}
