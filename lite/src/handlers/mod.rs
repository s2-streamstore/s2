use axum::http::HeaderValue;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::auth::AuthState;

pub mod v1;

/// Git SHA of the build, set at compile time via environment variable.
pub const GIT_SHA: &str = match option_env!("GIT_SHA") {
    Some(sha) => sha,
    None => "unknown",
};

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
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::HeaderName::from_static("x-git-sha"),
            HeaderValue::from_static(GIT_SHA),
        ))
}
