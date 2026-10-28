//! Static dashboard bundle served at `/dashboard`.
//!
//! The files under `lite/dashboard/` are the built output of
//! <https://github.com/s2-streamstore/s2-dashboard> (`apps/lite`); see
//! `lite/dashboard/VERSION` for the vendored commit. The app talks to this
//! server on the same origin, so no token or CORS configuration is needed.

use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use include_dir::{Dir, include_dir};

static DASHBOARD_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/dashboard");

pub fn router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route("/dashboard", get(index))
        .route("/dashboard/", get(index))
        .route("/dashboard/{*path}", get(asset))
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

fn file_response(path: &str, cache_control: &'static str) -> Option<Response> {
    let file = DASHBOARD_DIR.get_file(path)?;
    Some(
        (
            [
                (header::CONTENT_TYPE, content_type(path)),
                (header::CACHE_CONTROL, cache_control),
            ],
            Body::from(file.contents()),
        )
            .into_response(),
    )
}

/// The SPA shell; always revalidated so a new binary is picked up immediately.
async fn index() -> Response {
    file_response("index.html", "no-cache").unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

/// Bundled asset, or the SPA shell for client-side routes like `/dashboard/basins/<name>`.
async fn asset(Path(path): Path<String>) -> Response {
    if path.starts_with("assets/") {
        return file_response(&path, "public, max-age=3600")
            .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }
    index().await
}
