use axum::extract::{FromRequest, Path, Query, State};
use http::StatusCode;
use s2_api::{
    data::{Json, extract::JsonOpt},
    v1 as v1t,
};
use s2_common::{
    http::extract::{Header, HeaderOpt},
    types::{
        basin::BasinName,
        config::{OptionalStreamConfig, StreamReconfiguration},
        resources::{PROVISION_RESULT_HEADER, Page, ProvisionMode, ProvisionResult, RequestToken},
        stream::{ListStreamsRequest, StreamName},
    },
};

use crate::{backend::Backend, handlers::v1::error::ServiceError};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::{delete, get, patch, post, put};
    axum::Router::new()
        .route(super::paths::streams::LIST, get(list_streams))
        .route(super::paths::streams::CREATE, post(create_stream))
        .route(super::paths::streams::GET_CONFIG, get(get_stream_config))
        .route(super::paths::streams::ENSURE, put(ensure_stream))
        .route(super::paths::streams::DELETE, delete(delete_stream))
        .route(
            super::paths::streams::RECONFIGURE,
            patch(reconfigure_stream),
        )
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ListArgs {
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Query))]
    request: v1t::stream::ListStreamsRequest,
}

/// List streams.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::streams::LIST,
    tag = super::paths::streams::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::stream::ListStreamsResponse),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::stream::ListStreamsRequest),
    servers(
        (url = super::paths::cloud_endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn list_streams(
    State(backend): State<Backend>,
    ListArgs { basin, request }: ListArgs,
) -> Result<Json<v1t::stream::ListStreamsResponse>, ServiceError> {
    let request: ListStreamsRequest = request.try_into()?;
    let Page { values, has_more } = backend.list_streams(basin, request).await?;
    Ok(Json(v1t::stream::ListStreamsResponse {
        streams: values.into_iter().map(Into::into).collect(),
        has_more,
    }))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct CreateArgs {
    request_token: HeaderOpt<RequestToken>,
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Json))]
    request: v1t::stream::CreateStreamRequest,
}

/// Create a stream.
#[cfg_attr(feature = "utoipa", utoipa::path(
    post,
    path = super::paths::streams::CREATE,
    tag = super::paths::streams::TAG,
    params(v1t::S2RequestTokenHeader),
    request_body = v1t::stream::CreateStreamRequest,
    responses(
        (status = StatusCode::CREATED, body = v1t::stream::StreamInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    servers(
        (url = super::paths::cloud_endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn create_stream(
    State(backend): State<Backend>,
    CreateArgs {
        request_token: HeaderOpt(request_token),
        basin,
        request,
    }: CreateArgs,
) -> Result<
    (
        StatusCode,
        [(http::HeaderName, &'static str); 1],
        Json<v1t::stream::StreamInfo>,
    ),
    ServiceError,
> {
    let config: OptionalStreamConfig = request
        .config
        .map(TryInto::try_into)
        .transpose()?
        .unwrap_or_default();
    let info = backend
        .provision_stream(
            basin,
            request.stream,
            config,
            ProvisionMode::CreateOnly { request_token },
        )
        .await?
        .map(Into::into);
    let (outcome, info) = match info {
        ProvisionResult::Created(info) => ("created", info),
        ProvisionResult::Noop(info) => ("noop", info),
        ProvisionResult::Updated(_) => unreachable!("CreateOnly mode never produces Updated"),
    };
    Ok((
        StatusCode::CREATED,
        [(PROVISION_RESULT_HEADER.clone(), outcome)],
        Json(info),
    ))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct GetConfigArgs {
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Path))]
    stream: StreamName,
}

/// Get stream configuration.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::streams::GET_CONFIG,
    tag = super::paths::streams::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::config::StreamConfig),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::StreamNamePathSegment),
    servers(
        (url = super::paths::cloud_endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn get_stream_config(
    State(backend): State<Backend>,
    GetConfigArgs { basin, stream }: GetConfigArgs,
) -> Result<Json<v1t::config::StreamConfig>, ServiceError> {
    let config = backend.get_stream_config(basin, stream).await?;
    Ok(Json(
        v1t::config::StreamConfig::to_opt(config).unwrap_or_default(),
    ))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct EnsureArgs {
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Path))]
    stream: StreamName,
    config: JsonOpt<v1t::config::StreamConfig>,
}

/// Ensure a stream.
#[cfg_attr(feature = "utoipa", utoipa::path(
    put,
    path = super::paths::streams::ENSURE,
    tag = super::paths::streams::TAG,
    request_body = Option<v1t::config::StreamConfig>,
    params(v1t::StreamNamePathSegment),
    responses(
        (status = StatusCode::OK, body = v1t::stream::StreamInfo),
        (status = StatusCode::CREATED, body = v1t::stream::StreamInfo),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    servers(
        (url = super::paths::cloud_endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn ensure_stream(
    State(backend): State<Backend>,
    EnsureArgs {
        basin,
        stream,
        config: JsonOpt(config),
    }: EnsureArgs,
) -> Result<
    (
        StatusCode,
        [(http::HeaderName, &'static str); 1],
        Json<v1t::stream::StreamInfo>,
    ),
    ServiceError,
> {
    let config: OptionalStreamConfig = config
        .map(TryInto::try_into)
        .transpose()?
        .unwrap_or_default();
    let info = backend
        .provision_stream(basin, stream, config, ProvisionMode::Ensure)
        .await?
        .map(Into::into);
    let (status, outcome, info) = match info {
        ProvisionResult::Created(info) => (StatusCode::CREATED, "created", info),
        ProvisionResult::Updated(info) => (StatusCode::OK, "updated", info),
        ProvisionResult::Noop(info) => (StatusCode::OK, "noop", info),
    };
    Ok((
        status,
        [(PROVISION_RESULT_HEADER.clone(), outcome)],
        Json(info),
    ))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct DeleteArgs {
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Path))]
    stream: StreamName,
}

/// Delete a stream.
#[cfg_attr(feature = "utoipa", utoipa::path(
    delete,
    path = super::paths::streams::DELETE,
    tag = super::paths::streams::TAG,
    responses(
        (status = StatusCode::ACCEPTED),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::StreamNamePathSegment),
    servers(
        (url = super::paths::cloud_endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn delete_stream(
    State(backend): State<Backend>,
    DeleteArgs { basin, stream }: DeleteArgs,
) -> Result<StatusCode, ServiceError> {
    backend.delete_stream(basin, stream).await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ReconfigureArgs {
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Path))]
    stream: StreamName,
    #[from_request(via(Json))]
    reconfiguration: v1t::config::StreamReconfiguration,
}

/// Reconfigure a stream.
#[cfg_attr(feature = "utoipa", utoipa::path(
    patch,
    path = super::paths::streams::RECONFIGURE,
    tag = super::paths::streams::TAG,
    request_body = v1t::config::StreamReconfiguration,
    responses(
        (status = StatusCode::OK, body = v1t::config::StreamConfig),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::StreamNamePathSegment),
    servers(
        (url = super::paths::cloud_endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn reconfigure_stream(
    State(backend): State<Backend>,
    ReconfigureArgs {
        basin,
        stream,
        reconfiguration,
    }: ReconfigureArgs,
) -> Result<Json<v1t::config::StreamConfig>, ServiceError> {
    let reconfiguration: StreamReconfiguration = reconfiguration.try_into()?;
    let config = backend
        .reconfigure_stream(basin, stream, reconfiguration)
        .await?;
    Ok(Json(
        v1t::config::StreamConfig::to_opt(config).unwrap_or_default(),
    ))
}
