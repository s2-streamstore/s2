//! Static dashboard bundle served at `/dashboard`.
//!
//! `lite/dashboard/` is a git submodule of
//! <https://github.com/s2-streamstore/s2-dashboard>, pinned to a release tag;
//! only its committed `apps/lite/dist` build is embedded. The app talks to
//! this server on the same origin, so no token or CORS configuration is needed.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use include_dir::{Dir, include_dir};
use serde::Serialize;

static DASHBOARD_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/dashboard/apps/lite/dist");

/// Where the database (or its WAL) lives.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoreInfo {
    Memory,
    Local { root: String },
    S3 { bucket: String },
}

/// How this server was configured at startup, shown on the dashboard's Server page.
#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    pub version: &'static str,
    pub started_at: String,
    pub store: StoreInfo,
    /// Dedicated WAL store, if one was configured.
    pub wal: Option<StoreInfo>,
    /// Base path within the object store.
    pub path: String,
    pub flush_interval_ms: Option<u64>,
    pub tls: &'static str,
    pub port: u16,
    pub cors: bool,
    pub init_file: Option<String>,
    pub append_inflight_bytes: u64,
}

pub fn router<S: Clone + Send + Sync + 'static>(info: &ServerInfo) -> Router<S> {
    let config_json: Arc<str> = serde_json::to_string(info)
        .expect("ServerInfo serializes")
        .into();
    Router::new()
        .route("/dashboard", get(index))
        .route("/dashboard/", get(index))
        .route(
            "/dashboard/config.json",
            get(move || {
                let body = config_json.clone();
                async move {
                    (
                        [
                            (header::CONTENT_TYPE, "application/json"),
                            (header::CACHE_CONTROL, "no-cache"),
                        ],
                        Body::from(body.to_string()),
                    )
                        .into_response()
                }
            }),
        )
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
