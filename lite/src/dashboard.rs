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

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, http::Request};
    use tower::ServiceExt;

    use super::*;

    fn info() -> ServerInfo {
        ServerInfo {
            version: "0.0.0-test",
            started_at: "2026-01-01T00:00:00Z".into(),
            store: StoreInfo::Memory,
            wal: None,
            path: String::new(),
            flush_interval_ms: None,
            tls: "off",
            port: 4243,
            cors: false,
            init_file: None,
            append_inflight_bytes: 0,
        }
    }

    async fn get_path(path: &str) -> (StatusCode, String, String, String) {
        let response = router::<()>(&info())
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let hdr = |name: header::HeaderName| {
            response
                .headers()
                .get(name)
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_default()
        };
        let (content_type, cache) = (hdr(header::CONTENT_TYPE), hdr(header::CACHE_CONTROL));
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (
            status,
            content_type,
            cache,
            String::from_utf8_lossy(&body).into_owned(),
        )
    }

    #[tokio::test]
    async fn serves_bundle_config_and_spa_fallback() {
        let js = DASHBOARD_DIR
            .get_dir("assets")
            .and_then(|dir| {
                dir.files()
                    .find(|f| f.path().extension().is_some_and(|e| e == "js"))
            })
            .expect("bundle has a js asset");
        let js_path = format!("/dashboard/{}", js.path().display());

        let (status, content_type, cache, body) = get_path(&js_path).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "text/javascript; charset=utf-8");
        assert_eq!(cache, "public, max-age=3600");
        assert_eq!(body.as_bytes(), js.contents());

        let (status, _, _, _) = get_path("/dashboard/assets/missing.js").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, content_type, cache, body) = get_path("/dashboard").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "text/html; charset=utf-8");
        assert_eq!(cache, "no-cache");
        assert!(
            body.contains("/dashboard/assets/"),
            "index links its assets"
        );

        let (status, _, _, spa) = get_path("/dashboard/basins/abc/studio").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(spa, body, "client routes get the SPA shell");

        let (status, content_type, cache, body) = get_path("/dashboard/config.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "application/json");
        assert_eq!(cache, "no-cache");
        let config: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(config["store"]["kind"], "memory");
        assert_eq!(config["version"], "0.0.0-test");
    }
}
