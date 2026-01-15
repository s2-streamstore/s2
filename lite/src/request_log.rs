use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use axum::{body::Body, extract::Request, response::Response};
use http::StatusCode;
use tower::{Layer, Service};
use tracing::{Level, Span, field, info_span};

/// Header name for basin context.
const BASIN_HEADER: &str = "s2-basin";

/// Layer that provides detailed per-request logging with context on status
/// and how the request finished.
#[derive(Clone, Debug, Default)]
pub struct RequestLogLayer;

impl RequestLogLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RequestLogLayer {
    type Service = RequestLogService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestLogService { inner }
    }
}

/// Service that wraps requests with detailed logging.
#[derive(Clone, Debug)]
pub struct RequestLogService<S> {
    inner: S,
}

impl<S> Service<Request> for RequestLogService<S>
where
    S: Service<Request, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = RequestLogFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let start = Instant::now();

        // Extract request details for logging.
        let method = req.method().clone();
        let uri = req.uri().clone();
        let path = uri.path().to_string();
        let query = uri.query().map(|q| q.to_string());

        // Extract optional context from headers.
        let basin = req
            .headers()
            .get(BASIN_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Extract stream from path if present (e.g., /v1/streams/{stream}/...).
        let stream = extract_stream_from_path(&path);

        // Create the request span with all available context.
        let span = info_span!(
            "request",
            method = %method,
            path = %path,
            query = query.as_deref().unwrap_or(""),
            basin = basin.as_deref().unwrap_or(""),
            stream = stream.as_deref().unwrap_or(""),
            status = field::Empty,
            latency_ms = field::Empty,
            error_code = field::Empty,
        );

        let future = {
            let _guard = span.enter();
            self.inner.call(req)
        };

        RequestLogFuture {
            future,
            span,
            start,
        }
    }
}

/// Future that completes the request and logs the result.
#[pin_project::pin_project]
pub struct RequestLogFuture<F> {
    #[pin]
    future: F,
    span: Span,
    start: Instant,
}

impl<F, E> Future for RequestLogFuture<F>
where
    F: Future<Output = Result<Response<Body>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let _guard = this.span.enter();

        match this.future.poll(cx) {
            Poll::Ready(result) => {
                let latency_ms = this.start.elapsed().as_millis() as u64;
                this.span.record("latency_ms", latency_ms);

                match &result {
                    Ok(response) => {
                        let status = response.status();
                        this.span.record("status", status.as_u16());

                        // Extract error code from response body for error responses.
                        let error_code = response
                            .headers()
                            .get("x-s2-error-code")
                            .and_then(|v| v.to_str().ok());

                        if let Some(code) = error_code {
                            this.span.record("error_code", code);
                        }

                        log_request_completion(status, latency_ms, error_code);
                    }
                    Err(_) => {
                        this.span.record("status", 500_u16);
                        tracing::error!(latency_ms, "request failed with internal error");
                    }
                }

                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Log the request completion at the appropriate level based on status.
fn log_request_completion(status: StatusCode, latency_ms: u64, error_code: Option<&str>) {
    let level = status_to_log_level(status);

    match level {
        Level::ERROR => {
            tracing::error!(
                status = status.as_u16(),
                latency_ms,
                error_code = error_code.unwrap_or(""),
                "request completed with error"
            );
        }
        Level::WARN => {
            tracing::warn!(
                status = status.as_u16(),
                latency_ms,
                error_code = error_code.unwrap_or(""),
                "request completed with client error"
            );
        }
        _ => {
            tracing::info!(
                status = status.as_u16(),
                latency_ms,
                "request completed successfully"
            );
        }
    }
}

/// Map status code to appropriate log level.
fn status_to_log_level(status: StatusCode) -> Level {
    if status.is_server_error() {
        Level::ERROR
    } else if status.is_client_error() {
        Level::WARN
    } else {
        Level::INFO
    }
}

/// Extract stream name from path segments.
/// Matches patterns like /v1/streams/{stream}/records or /v1/streams/{stream}.
fn extract_stream_from_path(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // Look for "streams" followed by a stream name.
    for (i, segment) in segments.iter().enumerate() {
        if *segment == "streams" {
            if let Some(stream) = segments.get(i + 1) {
                // Skip if it looks like a sub-resource keyword.
                if *stream != "records" && *stream != "tail" {
                    return Some((*stream).to_string());
                }
            }
        }
    }
    None
}
