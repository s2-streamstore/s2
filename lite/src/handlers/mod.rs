mod v1;

pub fn router(backend: crate::backend::Backend) -> axum::Router {
    axum::Router::new()
        .route("/ping", axum::routing::get(|| async { "pong" }))
        .nest("/v1", v1::router(backend))
}
