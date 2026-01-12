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
        resources::{CreateMode, Page, RequestToken},
        stream::{ListStreamsRequest, StreamName},
    },
};

#[cfg(feature = "utoipa")]
use super::paths::{self, endpoints};
use crate::{backend::Backend, handlers::v1::error::ServiceError};

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
    path = paths::streams::LIST,
    tag = paths::streams::TAG,
    operation_id = "list_streams",
    responses(
        (status = StatusCode::OK, body = v1t::stream::ListStreamsResponse),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::stream::ListStreamsRequest),
    servers(
        (url = endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn list(
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
    path = paths::streams::CREATE,
    tag = paths::streams::TAG,
    operation_id = "create_stream",
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
        (url = endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn create(
    State(backend): State<Backend>,
    CreateArgs {
        request_token: HeaderOpt(request_token),
        basin,
        request,
    }: CreateArgs,
) -> Result<(StatusCode, Json<v1t::stream::StreamInfo>), ServiceError> {
    let config: OptionalStreamConfig = request
        .config
        .map(TryInto::try_into)
        .transpose()?
        .unwrap_or_default();
    let info = backend
        .create_stream(
            basin,
            request.stream,
            config,
            CreateMode::CreateOnly(request_token),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(info.into_inner().into())))
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
    path = paths::streams::GET_CONFIG,
    tag = paths::streams::TAG,
    operation_id = "get_stream_config",
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
        (url = endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn get_config(
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
pub struct CreateOrReconfigureArgs {
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Path))]
    stream: StreamName,
    config: JsonOpt<v1t::config::StreamConfig>,
}

/// Create or reconfigure a stream.
#[cfg_attr(feature = "utoipa", utoipa::path(
    put,
    path = paths::streams::CREATE_OR_RECONFIGURE,
    tag = paths::streams::TAG,
    operation_id = "create_or_reconfigure_stream",
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
        (url = endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn create_or_reconfigure(
    State(backend): State<Backend>,
    CreateOrReconfigureArgs {
        basin,
        stream,
        config: JsonOpt(config),
    }: CreateOrReconfigureArgs,
) -> Result<(StatusCode, Json<v1t::stream::StreamInfo>), ServiceError> {
    let config: OptionalStreamConfig = config
        .map(TryInto::try_into)
        .transpose()?
        .unwrap_or_default();
    let info = backend
        .create_stream(basin, stream, config, CreateMode::CreateOrReconfigure)
        .await?;
    let status = if info.is_created() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(info.into_inner().into())))
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
    path = paths::streams::DELETE,
    tag = paths::streams::TAG,
    operation_id = "delete_stream",
    responses(
        (status = StatusCode::ACCEPTED),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::StreamNamePathSegment),
    servers(
        (url = endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn delete(
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
    path = paths::streams::RECONFIGURE,
    tag = paths::streams::TAG,
    operation_id = "reconfigure_stream",
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
        (url = endpoints::BASIN, variables(
            ("basin" = (
                description = "Basin name",
            ))
        ), description = "Endpoint for the basin"),
    )
))]
pub async fn reconfigure(
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
