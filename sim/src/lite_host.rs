//! s2-lite, run as a turmoil host.
//!
//! Mirrors `s2_lite::server::run`, but with the pieces the simulation needs to
//! control: the object store is an S3 client wired over the turmoil network to
//! the mock S3 host, and the HTTP server runs on a turmoil listener instead of
//! a real socket.

use std::{sync::Arc, time::Duration};

use bytesize::ByteSize;
use s2_lite::{backend::Backend, handlers};
use slatedb::object_store::{self, aws::AmazonS3Builder};
use tracing::info;

use crate::{object_store_http::TurmoilHttpConnector, s3};

pub const HOST: &str = "s2-lite";
pub const PORT: u16 = 80;

pub fn endpoint() -> String {
    format!("http://{HOST}:{PORT}")
}

pub async fn serve() -> turmoil::Result {
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

    let app = handlers::router().with_state(backend);

    info!(host = HOST, port = PORT, "s2-lite listening");
    crate::net::serve(PORT, app).await
}
