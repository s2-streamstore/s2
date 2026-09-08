use axum::extract::{FromRequest, Path, Query, State};
use http::StatusCode;
use s2_api::{
    data::{Json, extract::JsonOpt},
    v1 as v1t,
};
use s2_common::{
    basin::BasinName,
    config::{OptionalStreamConfig, StreamReconfiguration},
    http::extract::{Header, HeaderOpt},
    resources::{PROVISION_RESULT_HEADER, Page, ProvisionMode, ProvisionResult, RequestToken},
    stream::{ListStreamsRequest, StreamName},
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
        // Stream names may contain '/', which must be percent-encoded per
        // request. An unencoded '/' makes the path resolve to more segments
        // than any route above expects, which axum's default router would
        // otherwise reject as a bare, bodyless 404. Catch that here and
        // return a `BadPath` error that hints at the fix. This is scoped to
        // one segment past `{stream}` (rather than `/streams/{*rest}`) so it
        // doesn't conflict with the exact single-segment `{stream}` routes
        // above; more specific literal routes (e.g. `.../records`) still win
        // over this wildcard.
        .route(
            "/streams/{stream}/{*rest}",
            axum::routing::any(ambiguous_stream_path),
        )
}

async fn ambiguous_stream_path() -> ServiceError {
    ServiceError::AmbiguousStreamPath
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
    Ok(Json(backend.get_stream_config(basin, stream).await?.into()))
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
        (status = StatusCode::CONFLICT, body = v1t::error::ErrorInfo),
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
    Ok(Json(config.into()))
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use axum::{body, body::Body, http::Request};
    use bytesize::ByteSize;
    use s2_common::basin::BASIN_HEADER;
    use slatedb::{Db, config::Settings, object_store::memory::InMemory};
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use crate::{backend::Backend, handlers};

    async fn create_backend() -> Backend {
        let object_store = Arc::new(InMemory::new());
        let db_path = format!("/tmp/streams-handler-test-{}", Uuid::new_v4());
        let db = Db::builder(db_path, object_store)
            .with_settings(Settings {
                flush_interval: Some(Duration::from_millis(5)),
                ..Default::default()
            })
            .build()
            .await
            .expect("create in-memory db");
        Backend::new(db, ByteSize::mib(10))
    }

    #[tokio::test]
    async fn unencoded_slash_in_stream_name_returns_helpful_bad_path_error() {
        let backend = create_backend().await;
        let app = handlers::router().with_state(backend);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/streams/cdc/products/records?seq_num=0&count=1")
                    .header(BASIN_HEADER.as_str(), "my-basin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["code"], "bad_path");
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("percent-encoded"),
            "unexpected message: {json}"
        );
    }

    #[tokio::test]
    async fn percent_encoded_slash_in_stream_name_reaches_the_records_route() {
        let backend = create_backend().await;
        let app = handlers::router().with_state(backend);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/streams/cdc%2Fproducts/records?seq_num=0&count=1")
                    .header(BASIN_HEADER.as_str(), "my-basin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should complete");

        // The basin/stream don't exist, so this legitimately 404s, but via
        // the records handler's `StreamNotFound`/`BasinNotFound` error body
        // -- not the bare, bodyless 404 from an unmatched route, and not our
        // `BadPath` guard.
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        assert!(!body.is_empty(), "expected a JSON error body, got empty");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_ne!(json["code"], "bad_path");
    }
}
