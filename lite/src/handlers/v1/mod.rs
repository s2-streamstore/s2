mod basins;
mod error;
mod records;
mod streams;

const MAX_UNARY_READ_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

pub fn router(backend: crate::backend::Backend) -> axum::Router {
    use axum::routing::{delete, get, patch, post, put};

    // TODO: timeout layer that respects long-poll read wait

    axum::Router::new()
        // Basin ops
        .route("/basins", get(basins::list))
        .route("/basins", post(basins::create))
        .route("/basins/{basin}", get(basins::get_config))
        .route("/basins/{basin}", put(basins::create_or_reconfigure))
        .route("/basins/{basin}", delete(basins::delete))
        .route("/basins/{basin}", patch(basins::reconfigure))
        // Stream ops
        .route("/streams", get(streams::list))
        .route("/streams", post(streams::create))
        .route("/streams/{stream}", get(streams::get_config))
        .route("/streams/{stream}", put(streams::create_or_reconfigure))
        .route("/streams/{stream}", delete(streams::delete))
        .route("/streams/{stream}", patch(streams::reconfigure))
        // Record ops
        .route("/streams/{stream}/records/tail", get(records::check_tail))
        .route("/streams/{stream}/records", get(records::read))
        .route("/streams/{stream}/records", post(records::append))
        .with_state(backend)
}
