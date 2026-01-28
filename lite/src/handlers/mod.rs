pub mod v1;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::backend::Backend;

async fn metrics(State(_backend): State<Backend>) -> impl axum::response::IntoResponse {
    let body = crate::metrics::gather();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

async fn ping(State(backend): State<Backend>) -> Response {
    match backend.db_status().await {
        Ok(()) => "pong".into_response(),
        Err(err) => (StatusCode::SERVICE_UNAVAILABLE, format!("db status: {err}")).into_response(),
    }
}

pub fn router() -> axum::Router<Backend> {
    axum::Router::new()
        .route("/ping", axum::routing::get(ping))
        .route("/metrics", axum::routing::get(metrics))
        .nest("/v1", v1::router())
}
