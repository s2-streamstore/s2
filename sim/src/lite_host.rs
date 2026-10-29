//! s2-lite, run as a turmoil host.
//!
//! Mirrors `s2_lite::server::run`, but with the pieces the simulation needs to
//! control: the object store is an S3 client wired over the turmoil network to
//! the mock S3 host, and the HTTP server runs on a turmoil listener instead of
//! a real socket.

use std::{sync::Arc, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use bytesize::ByteSize;
use futures::StreamExt;
use s2_lite::{backend::Backend, handlers};
use slatedb::object_store::{self, aws::AmazonS3Builder};
use tracing::{debug, info};

use crate::{object_store_http::TurmoilHttpConnector, s3};

pub const HOST: &str = "s2-lite";
pub const PORT: u16 = 80;

pub fn endpoint() -> String {
    format!("http://{HOST}:{PORT}")
}

/// Server-side faults injected into s2-lite's responses.
#[derive(clap::Args, Debug, Clone, Copy, Default)]
pub struct Faults {
    /// Probability [0, 1) that a response body fails after its first frame,
    /// which hyper surfaces to the client as an HTTP/2 `RST_STREAM`.
    #[arg(long, default_value_t = 0.0, global = true)]
    pub stream_reset_rate: f64,
}

pub async fn serve(faults: Faults) -> turmoil::Result {
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(
        AmazonS3Builder::new()
            .with_bucket_name(s3::BUCKET)
            .with_region("sim")
            .with_endpoint(s3::endpoint())
            .with_allow_http(true)
            // Path-style addressing keeps the turmoil host name ("s3") intact;
            // virtual-hosted style would dial "sim-bucket.s3".
            .with_virtual_hosted_style_request(false)
            .with_access_key_id(s3::ACCESS_KEY)
            .with_secret_access_key(s3::SECRET_KEY)
            .with_http_connector(TurmoilHttpConnector)
            .build()?,
    );

    let db_settings = slatedb::Settings {
        flush_interval: Some(Duration::from_millis(50)),
        ..Default::default()
    };

    let db = slatedb::Db::builder("", store)
        .with_settings(db_settings)
        .build()
        .await?;

    let backend = Backend::new(db, ByteSize::mib(128));
    s2_lite::backend::bgtasks::spawn(&backend);

    let app = handlers::router()
        .with_state(backend)
        .layer(middleware::from_fn(move |req, next| {
            inject_faults(faults, req, next)
        }));

    info!(host = HOST, port = PORT, "s2-lite listening");
    crate::net::serve(PORT, app).await
}

async fn inject_faults(faults: Faults, req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    if faults.stream_reset_rate > 0.0 && fastrand::f64() < faults.stream_reset_rate {
        debug!("injecting response body error");
        return response.map(fail_after_first_frame);
    }
    response
}

/// Passes the body's first data frame through, then fails. hyper resets the
/// stream (`RST_STREAM` `INTERNAL_ERROR`) when a response body errors, so the
/// client sees the reset either while sending the request or mid-response.
fn fail_after_first_frame(body: Body) -> Body {
    let frames = body
        .into_data_stream()
        .take(1)
        .chain(futures::stream::once(async {
            Err::<Bytes, _>(axum::Error::new("injected body error"))
        }));
    Body::from_stream(frames)
}
