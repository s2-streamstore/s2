use crate::auth::AuthState;

pub mod v1;

async fn metrics() -> impl axum::response::IntoResponse {
    let body = crate::metrics::gather();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

pub fn router(backend: crate::backend::Backend, auth_state: AuthState) -> axum::Router {
    axum::Router::new()
        .route("/ping", axum::routing::get(|| async { "pong" }))
        .route("/metrics", axum::routing::get(metrics))
        .nest("/v1", v1::router(backend, auth_state))
}
