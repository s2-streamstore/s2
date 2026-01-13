pub mod access_tokens;
pub mod basins;
mod error;
pub mod metrics;
pub mod paths;
pub mod records;
pub mod streams;

const MAX_UNARY_READ_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

pub fn router(backend: crate::backend::Backend) -> axum::Router {
    use axum::routing::{delete, get, patch, post, put};

    // TODO: timeout layer that respects long-poll read wait

    axum::Router::new()
        // Basin ops
        .route(paths::basins::LIST, get(basins::list_basins))
        .route(paths::basins::CREATE, post(basins::create_basin))
        .route(paths::basins::GET_CONFIG, get(basins::get_basin_config))
        .route(
            paths::basins::CREATE_OR_RECONFIGURE,
            put(basins::create_or_reconfigure_basin),
        )
        .route(paths::basins::DELETE, delete(basins::delete_basin))
        .route(paths::basins::RECONFIGURE, patch(basins::reconfigure_basin))
        // Stream ops
        .route(paths::streams::LIST, get(streams::list_streams))
        .route(paths::streams::CREATE, post(streams::create_stream))
        .route(paths::streams::GET_CONFIG, get(streams::get_stream_config))
        .route(
            paths::streams::CREATE_OR_RECONFIGURE,
            put(streams::create_or_reconfigure_stream),
        )
        .route(paths::streams::DELETE, delete(streams::delete_stream))
        .route(
            paths::streams::RECONFIGURE,
            patch(streams::reconfigure_stream),
        )
        // Record ops
        .route(
            paths::streams::records::CHECK_TAIL,
            get(records::check_tail),
        )
        .route(paths::streams::records::READ, get(records::read))
        .route(paths::streams::records::APPEND, post(records::append))
        // Access token ops
        .route(
            paths::access_tokens::LIST,
            get(access_tokens::list_access_tokens),
        )
        .route(
            paths::access_tokens::ISSUE,
            post(access_tokens::issue_access_token),
        )
        .route(
            paths::access_tokens::REVOKE,
            delete(access_tokens::revoke_access_token),
        )
        // Metric ops
        .route(paths::metrics::ACCOUNT, get(metrics::account_metrics))
        .route(paths::metrics::BASIN, get(metrics::basin_metrics))
        .route(paths::metrics::STREAM, get(metrics::stream_metrics))
        .with_state(backend)
}
