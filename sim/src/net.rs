//! Networking adapters that bridge hyper/axum onto the turmoil simulated network.

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::{
    client::legacy::connect::{Connected, Connection},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
    service::TowerToHyperService,
};
use tower::Service;
use tracing::debug;
use turmoil::net::{TcpListener, TcpStream};

/// A `hyper_util::client::legacy::connect::Connect` implementation that dials
/// over the turmoil simulated network, resolving turmoil host names.
///
/// Usable both by the s2-sdk (via `S2::new_with_connector`) and by hyper
/// clients embedded in other adapters (see [`crate::object_store_http`]).
#[derive(Debug, Clone)]
pub struct TurmoilConnector;

pub struct TurmoilConnection(TokioIo<TcpStream>);

impl Read for TurmoilConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl Write for TurmoilConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for TurmoilConnection {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl Service<http::Uri> for TurmoilConnector {
    type Response = TurmoilConnection;
    type Error = io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        // Under message loss, a dropped SYN would otherwise hang the connect
        // future forever (turmoil does not retransmit); time out and let the
        // caller retry. Timeouts use simulated time, so this is deterministic.
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| io::Error::other("uri has no host"))?;
            let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
                Some("https") => 443,
                _ => 80,
            });
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("connect timeout: {host}:{port}"),
                    )
                })??;
            Ok(TurmoilConnection(TokioIo::new(stream)))
        })
    }
}

/// Serve an axum router on the turmoil network, on all interfaces of the
/// current turmoil host.
pub async fn serve(port: u16, app: axum::Router) -> turmoil::Result {
    serve_hyper(port, TowerToHyperService::new(app)).await
}

/// Serve a hyper service on the turmoil network, on all interfaces of the
/// current turmoil host.
pub async fn serve_hyper<S, B>(port: u16, service: S) -> turmoil::Result
where
    S: hyper::service::Service<http::Request<hyper::body::Incoming>, Response = http::Response<B>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await
            {
                debug!(%peer, "connection error: {err}");
            }
        });
    }
}
