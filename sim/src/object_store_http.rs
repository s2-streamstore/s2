//! An `object_store` HTTP connector that routes requests over the turmoil
//! simulated network, instead of object_store's default reqwest client (which
//! would dial real sockets and escape the simulation).
//!
//! This is what lets s2-lite's slatedb backend talk to the mock S3 host.

use std::time::Duration;

use async_trait::async_trait;
use http_body_util::BodyExt;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use slatedb::object_store::{
    self,
    client::{
        ClientOptions, HttpClient, HttpConnector, HttpError, HttpErrorKind, HttpRequest,
        HttpRequestBody, HttpResponse, HttpService,
    },
};

use crate::net::TurmoilConnector;

/// Factory handed to `AmazonS3Builder::with_http_connector`.
#[derive(Debug, Default)]
pub struct TurmoilHttpConnector;

impl HttpConnector for TurmoilHttpConnector {
    fn connect(&self, _options: &ClientOptions) -> object_store::Result<HttpClient> {
        let client = Client::builder(TokioExecutor::new()).build(TurmoilConnector);
        Ok(HttpClient::new(TurmoilHttpService { client }))
    }
}

#[derive(Debug)]
struct TurmoilHttpService {
    client: Client<TurmoilConnector, HttpRequestBody>,
}

#[async_trait]
impl HttpService for TurmoilHttpService {
    async fn call(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        // Under message loss an in-flight request on an established connection
        // can stall forever (turmoil does not retransmit); time out so the
        // object_store retry layer kicks in. Simulated time, so deterministic.
        const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
        tokio::time::timeout(REQUEST_TIMEOUT, self.call_inner(req))
            .await
            .map_err(|_| {
                HttpError::new(
                    HttpErrorKind::Timeout,
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "request timeout"),
                )
            })?
    }
}

impl TurmoilHttpService {
    async fn call_inner(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        let response = self
            .client
            .request(req)
            .await
            .map_err(|err| HttpError::new(HttpErrorKind::Connect, err))?;
        let (parts, body) = response.into_parts();
        // hyper's `Incoming` body is not `Sync`, which `HttpResponseBody::new`
        // requires; responses in simulation are small, so buffer them.
        let bytes = body
            .collect()
            .await
            .map_err(|err| HttpError::new(HttpErrorKind::Interrupted, err))?
            .to_bytes();
        Ok(HttpResponse::from_parts(parts, bytes.into()))
    }
}
