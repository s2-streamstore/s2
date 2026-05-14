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

use crate::{
    backend::{Backend, EnsureResult},
    handlers::v1::error::ServiceError,
};

pub fn router() -> axum::Router<Backend> {
    use axum::routing::{delete, get, patch, post, put};
    axum::Router::new()
        .route(super::paths::basins::LIST, get(list_basins))
        .route(super::paths::basins::CREATE, post(create_basin))
        .route(super::paths::basins::GET_CONFIG, get(get_basin_config))
        .route(super::paths::basins::ENSURE, put(ensure_basin))
        .route(super::paths::basins::DELETE, delete(delete_basin))
        .route(super::paths::basins::RECONFIGURE, patch(reconfigure_basin))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct ListArgs {
    #[from_request(via(Query))]
    request: v1t::basin::ListBasinsRequest,
}

/// List basins.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::basins::LIST,
    tag = super::paths::basins::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::basin::ListBasinsResponse),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::basin::ListBasinsRequest),
))]
pub async fn list_basins(
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

/// Create a basin.
#[cfg_attr(feature = "utoipa", utoipa::path(
    post,
    path = super::paths::basins::CREATE,
    tag = super::paths::basins::TAG,
    params(v1t::S2RequestTokenHeader),
    request_body = v1t::basin::CreateBasinRequest,
    responses(
        (status = StatusCode::OK, body = v1t::basin::BasinInfo),
        (status = StatusCode::CREATED, body = v1t::basin::BasinInfo),
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn create_basin(
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
        .create_basin(
            request.basin,
            config,
            CreateMode::CreateOnly { request_token },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(info.into_inner().into())))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct GetConfigArgs {
    #[from_request(via(Path))]
    basin: BasinName,
}

/// Get basin configuration.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::basins::GET_CONFIG,
    tag = super::paths::basins::TAG,
    responses(
        (status = StatusCode::OK, body = v1t::config::BasinConfig),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::BasinNamePathSegment),
))]
pub async fn get_basin_config(
    State(backend): State<Backend>,
    GetConfigArgs { basin }: GetConfigArgs,
) -> Result<Json<v1t::config::BasinConfig>, ServiceError> {
    let config = backend.get_basin_config(basin).await?;
    Ok(Json(config.into()))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct EnsureArgs {
    #[from_request(via(Path))]
    basin: BasinName,
    request: JsonOpt<v1t::basin::EnsureBasinRequest>,
}

/// Ensure a basin.
#[cfg_attr(feature = "utoipa", utoipa::path(
    put,
    path = super::paths::basins::ENSURE,
    tag = super::paths::basins::TAG,
    request_body = Option<v1t::basin::EnsureBasinRequest>,
    params(v1t::BasinNamePathSegment),
    responses(
        (status = StatusCode::OK, body = v1t::basin::BasinInfo),
        (status = StatusCode::CREATED, body = v1t::basin::BasinInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn ensure_basin(
    State(backend): State<Backend>,
    EnsureArgs {
        basin,
        request: JsonOpt(request),
    }: EnsureArgs,
) -> Result<(StatusCode, Json<v1t::basin::BasinInfo>), ServiceError> {
    let config: BasinConfig = request
        .and_then(|req| req.config)
        .map(TryInto::try_into)
        .transpose()?
        .unwrap_or_default();
    let info = backend
        .create_basin(basin, config, CreateMode::Ensure)
        .await?;
    let status = match &info {
        EnsureResult::Created(_) => StatusCode::CREATED,
        EnsureResult::Updated(_) => StatusCode::OK,
    };
    Ok((status, Json(info.into_inner().into())))
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct DeleteArgs {
    #[from_request(via(Path))]
    basin: BasinName,
}

/// Delete a basin.
#[cfg_attr(feature = "utoipa", utoipa::path(
    delete,
    path = super::paths::basins::DELETE,
    tag = super::paths::basins::TAG,
    responses(
        (status = StatusCode::ACCEPTED),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::BasinNamePathSegment),
))]
pub async fn delete_basin(
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

/// Reconfigure a basin.
#[cfg_attr(feature = "utoipa", utoipa::path(
    patch,
    path = super::paths::basins::RECONFIGURE,
    tag = super::paths::basins::TAG,
    request_body = v1t::config::BasinReconfiguration,
    responses(
        (status = StatusCode::OK, body = v1t::config::BasinConfig),
        (status = StatusCode::NOT_FOUND, body = v1t::error::ErrorInfo),
        (status = StatusCode::BAD_REQUEST, body = v1t::error::ErrorInfo),
        (status = StatusCode::FORBIDDEN, body = v1t::error::ErrorInfo),
        (status = StatusCode::REQUEST_TIMEOUT, body = v1t::error::ErrorInfo),
    ),
    params(v1t::BasinNamePathSegment),
))]
pub async fn reconfigure_basin(
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
