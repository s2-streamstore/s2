mod basins;
mod records;
mod streams;

use crate::backend::Backend;

pub fn router(backend: Backend) -> axum::Router {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/streams/{stream}/records/tail", get(records::check_tail))
        .route("/streams/{stream}/records", get(records::read))
        .route("/streams/{stream}/records", post(records::append))
        .with_state(backend)
}
