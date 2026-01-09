use axum::extract::{FromRequest, Path, Query, State};
use http::StatusCode;
use s2_api::{
    data::{Json, extract::JsonOpt},
    v1 as v1t,
};
use s2_common::{
    http::extract::HeaderOpt,
    types::{
        basin::{BasinName, ListBasinsRequest},
        config::{BasinConfig, BasinReconfiguration},
        resources::{CreateMode, Page, RequestToken},
    },
};

use crate::{backend::Backend, handlers::v1::error::ServiceError};

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ListArgs {
    #[from_request(via(Query))]
    request: v1t::basin::ListBasinsRequest,
}

pub async fn list(
    State(backend): State<Backend>,
    ListArgs { request }: ListArgs,
) -> Result<Json<v1t::basin::ListBasinsResponse>, ServiceError> {
    let request: ListBasinsRequest = request.try_into()?;
    let Page { values, has_more } = backend.list_basins(request).await?;
    Ok(Json(v1t::basin::ListBasinsResponse {
        basins: values.into_iter().map(Into::into).collect(),
        has_more,
    }))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct CreateArgs {
    request_token: HeaderOpt<RequestToken>,
    #[from_request(via(Json))]
    request: v1t::basin::CreateBasinRequest,
}

pub async fn create(
    State(backend): State<Backend>,
    CreateArgs {
        request_token: HeaderOpt(request_token),
        request,
    }: CreateArgs,
) -> Result<(StatusCode, Json<v1t::basin::BasinInfo>), ServiceError> {
    let config: BasinConfig = request
        .config
        .map(TryInto::try_into)
        .transpose()?
        .unwrap_or_default();
    let info = backend
        .create_basin(request.basin, config, CreateMode::CreateOnly(request_token))
        .await?;
    Ok((StatusCode::CREATED, Json(info.into_inner().into())))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct GetConfigArgs {
    #[from_request(via(Path))]
    basin: BasinName,
}

pub async fn get_config(
    State(backend): State<Backend>,
    GetConfigArgs { basin }: GetConfigArgs,
) -> Result<Json<v1t::config::BasinConfig>, ServiceError> {
    let config = backend.get_basin_config(basin).await?;
    Ok(Json(config.into()))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct CreateOrReconfigureArgs {
    #[from_request(via(Path))]
    basin: BasinName,
    request: JsonOpt<v1t::basin::CreateOrReconfigureBasinRequest>,
}

pub async fn create_or_reconfigure(
    State(backend): State<Backend>,
    CreateOrReconfigureArgs {
        basin,
        request: JsonOpt(request),
    }: CreateOrReconfigureArgs,
) -> Result<(StatusCode, Json<v1t::basin::BasinInfo>), ServiceError> {
    let config: BasinConfig = request
        .and_then(|req| req.config)
        .map(TryInto::try_into)
        .transpose()?
        .unwrap_or_default();
    let info = backend
        .create_basin(basin, config, CreateMode::CreateOrReconfigure)
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
    #[from_request(via(Path))]
    basin: BasinName,
}

pub async fn delete(
    State(backend): State<Backend>,
    DeleteArgs { basin }: DeleteArgs,
) -> Result<StatusCode, ServiceError> {
    backend.delete_basin(basin).await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ReconfigureArgs {
    #[from_request(via(Path))]
    basin: BasinName,
    #[from_request(via(Json))]
    reconfiguration: v1t::config::BasinReconfiguration,
}

pub async fn reconfigure(
    State(backend): State<Backend>,
    ReconfigureArgs {
        basin,
        reconfiguration,
    }: ReconfigureArgs,
) -> Result<Json<v1t::config::BasinConfig>, ServiceError> {
    let reconfiguration: BasinReconfiguration = reconfiguration.try_into()?;
    let config = backend.reconfigure_basin(basin, reconfiguration).await?;
    Ok(Json(config.into()))
}
