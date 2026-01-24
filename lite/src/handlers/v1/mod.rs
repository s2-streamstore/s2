use axum::middleware::from_fn_with_state;
use tower_http::{compression::CompressionLayer, decompression::RequestDecompressionLayer};

use crate::auth::AuthState;

pub mod access_tokens;
pub mod basins;
mod error;
pub mod metrics;
pub mod middleware;
pub mod paths;
pub mod records;
pub mod streams;

pub use middleware::AppState;

const MAX_UNARY_READ_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

pub fn router(backend: crate::backend::Backend, auth_state: AuthState) -> axum::Router {
    // TODO: timeout layer that respects long-poll read wait

    let compress_when = {
        use tower_http::compression::predicate::{NotForContentType, Predicate, SizeAbove};
        SizeAbove::new(1024)
            .and(NotForContentType::SSE)
            .and(NotForContentType::const_new("s2s/proto"))
    };

    let app_state = AppState {
        backend,
        auth: auth_state,
    };

    // All routes protected by auth middleware when enabled
    let protected_routes = axum::Router::new()
        .merge(basins::router())
        .merge(streams::router())
        .merge(records::router())
        .merge(metrics::router())
        .merge(access_tokens::router())
        .route_layer(from_fn_with_state(
            app_state.clone(),
            middleware::auth_middleware,
        ));

    axum::Router::new()
        .merge(protected_routes)
        .with_state(app_state)
        .route_layer((
            CompressionLayer::new().compress_when(compress_when),
            RequestDecompressionLayer::new(),
        ))
}
