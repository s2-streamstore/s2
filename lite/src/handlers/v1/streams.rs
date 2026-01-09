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

use crate::{backend::Backend, handlers::v1::error::ServiceError};

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ListArgs {
    #[from_request(via(Header))]
    basin: BasinName,
    #[from_request(via(Query))]
    request: v1t::stream::ListStreamsRequest,
}

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
