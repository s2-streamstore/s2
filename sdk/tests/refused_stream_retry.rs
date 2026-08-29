//! End-to-end regression test for the HTTP/2 REFUSED_STREAM classification fix.
//!
//! Spins up an h2 prior-knowledge server that:
//!   1. RST_STREAM(REFUSED_STREAM)s the very first request, and
//!   2. serves a normal `list_basins` response on the retry.
//!
//! An S2 SDK client (http2_only) pointed at the server must retry the refused
//! request and ultimately succeed. This exercises the full
//! `HttpError -> classify_hyper_source -> classify_h2_error -> ClientError`
//! path against a real h2 connection, which the pure unit tests in
//! `error.rs` cannot reach (hyper::Error has no public constructor).

use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::Response;
use s2_sdk::{
    S2,
    types::{ListBasinsInput, S2Config, S2Endpoints},
};
use tokio::net::TcpListener;

/// `{"basins":[],"has_more":false}` — a valid `ListBasinsResponse` body.
const LIST_BASINS_BODY: &[u8] = br#"{"basins":[],"has_more":false}"#;

async fn run_refused_stream_server(
    listener: TcpListener,
    counter: Arc<AtomicU32>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let (stream, _) = listener.accept().await?;
        let counter = counter.clone();
        tokio::spawn(async move {
            let mut conn = h2::server::handshake(stream).await.expect("h2 handshake");
            while let Some(result) = conn.accept().await {
                let Ok((_request, mut respond)) = result else {
                    break;
                };
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    // First request: refuse the stream prior to any processing,
                    // exactly as RFC 9113 §8.7 describes for REFUSED_STREAM.
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                } else {
                    // Retry: serve a valid empty list_basins response.
                    let response = Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(())
                        .expect("build response");
                    let mut send = respond
                        .send_response(response, false)
                        .expect("send response");
                    send.send_data(Bytes::from_static(LIST_BASINS_BODY), true)
                        .expect("send body");
                }
            }
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_stream_is_retried_by_sdk_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));
    let counter = Arc::new(AtomicU32::new(0));
    let server = tokio::spawn(run_refused_stream_server(listener, counter.clone()));

    let s2 = S2::new(
        S2Config::new("ignored").with_endpoints(S2Endpoints::for_endpoint(&endpoint).unwrap()),
    )
    .expect("client");

    let page = tokio::time::timeout(
        Duration::from_secs(15),
        s2.list_basins(ListBasinsInput::new()),
    )
    .await
    .expect("list_basins did not complete in time")
    .expect("list_basins should succeed after retrying REFUSED_STREAM");

    assert!(page.values.is_empty(), "expected empty basins list");
    assert!(!page.has_more, "expected has_more=false");

    // The server must have seen at least two requests: the refused one and the
    // successful retry. This proves the SDK retried rather than surfacing the
    // (pre-fix) non-retryable ClientError::Other.
    let observed = counter.load(Ordering::SeqCst);
    assert!(
        observed >= 2,
        "expected >=2 server requests (refused + retry), got {observed}",
    );

    server.abort();
    let _ = server.await;
}
