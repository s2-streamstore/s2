use tower_http::{compression::CompressionLayer, decompression::RequestDecompressionLayer};

use crate::backend::Backend;

pub mod access_tokens;
pub mod basins;
mod error;
pub mod metrics;
pub mod paths;
pub mod records;
pub mod streams;

const MAX_UNARY_READ_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

pub fn router() -> axum::Router<Backend> {
    // TODO: timeout layer that respects long-poll read wait

    let compress_when = {
        use tower_http::compression::predicate::{NotForContentType, Predicate, SizeAbove};
        SizeAbove::new(1024)
            .and(NotForContentType::SSE)
            .and(NotForContentType::const_new("s2s/proto"))
    };

    axum::Router::new()
        .merge(basins::router())
        .merge(streams::router())
        .merge(records::router())
        .merge(access_tokens::router())
        .merge(metrics::router())
        .route_layer((
            CompressionLayer::new().compress_when(compress_when),
            RequestDecompressionLayer::new(),
        ))
}
