/*!
Rust SDK for [S2](https://s2.dev/).

The Rust SDK provides ergonomic wrappers and utilities to interact with the
[S2 API](https://s2.dev/docs/rest/records/overview). It targets conformance with
the [S2 SDK Specification](https://github.com/s2-streamstore/s2-specs/blob/main/sdk/spec.md),
Revision 1 (Draft).

# Getting started

1. Ensure you have added [tokio](https://crates.io/crates/tokio) as a dependency:
   ```bash
   cargo add tokio --features full
   ```

1. Add the `s2-sdk` dependency to your project:

   ```bash
   cargo add s2-sdk
   ```

1. Generate an access token by logging into the web console at [s2.dev](https://s2.dev/dashboard),
   then export `S2_ACCESS_TOKEN`.

1. Perform an operation:

   ```no_run
   use s2_sdk::{S2, types::ListBasinsInput};

   #[tokio::main]
   async fn main() -> Result<(), Box<dyn std::error::Error>> {
       let s2 = S2::from_env()?;
       let page = s2.list_basins(ListBasinsInput::new()).await?;
       println!("My basins: {:?}", page.values);
       Ok(())
   }
   ```

See [`S2`] for account-level operations, [`S2Basin`] for basin-level operations,
and [`S2Stream`] for stream-level operations.

# Architecture & Core Concepts

## Client Handles & Lifecycle

[`S2`], [`S2Basin`], and [`S2Stream`] are lightweight, cheaply cloneable handles backed by a shared
HTTP/2 connection pool:

* Use [`S2::from_env`] (reads `S2_ACCESS_TOKEN` and optional `S2_ACCOUNT_ENDPOINT` /
  `S2_BASIN_ENDPOINT`) or [`S2::new`] with [`S2Config`] to create a client.
* Use `with_retry` on [`S2::with_retry`], [`S2Basin::with_retry`], or [`S2Stream::with_retry`] to
  derive a handle with an overridden [`RetryConfig`](types::RetryConfig) while sharing the parent
  client's HTTP/2 connection pool and [`S2::close`] lifecycle.
* Call [`S2::close`] to abort active sessions and in-flight requests and close pooled connections
  immediately. Dropping [`S2`] without calling `close()` keeps the underlying pool alive until all
  derived handles and sessions are dropped.
* Single-page listings (`list_*`) return a [`Page`](types::Page) with a typed `next_start_after()`
  cursor helper; full listings (`list_all_*`) return a lazy [`ListStream`](types::ListStream)
  (`Unpin` + `Stream` with an inherent `.next().await` method).

## Appending Records

Choose the append surface that matches your workload:

* **Unary**: [`S2Stream::append`] (or [`S2Stream::append_with_stream_config`] when creating a
  stream on append) sends a single [`AppendInput`](types::AppendInput) batch.
* **High-throughput producer**: [`S2Stream::producer`] returns a [`Producer`](producer::Producer)
  that batches individual [`AppendRecord`](types::AppendRecord)s according to
  [`ProducerConfig`](producer::ProducerConfig) (linger, batch size/count limits, backpressure,
  fencing token, and auto-incrementing `match_seq_num`). Call [`Producer::flush`](producer::Producer::flush)
  to wait for previously accepted records, observe live queue depth and progress via
  [`unacked_bytes`](producer::Producer::unacked_bytes),
  [`unacked_records`](producer::Producer::unacked_records), and
  [`acked_records`](producer::Producer::acked_records), and call
  [`Producer::close`](producer::Producer::close) before dropping so buffered batches are flushed
  cleanly.
* **Pre-batched pipelining**: [`S2Stream::append_session`] returns an
  [`AppendSession`](append_session::AppendSession) for submitting pre-formed
  [`AppendInput`](types::AppendInput)s with backpressure ([`reserve`](append_session::AppendSession::reserve)
  / [`submit`](append_session::AppendSession::submit)) and live depth accessors
  ([`unacked_bytes`](append_session::AppendSession::unacked_bytes),
  [`unacked_batches`](append_session::AppendSession::unacked_batches)). Standalone batching helpers
  live in [`batching`] ([`Batcher`](batching::Batcher), [`TryBatcher`](batching::TryBatcher),
  [`batch_iter`](batching::batch_iter), and [`try_batch_iter`](batching::try_batch_iter)).

## Reading Records

* **Unary**: [`S2Stream::read`] fetches a single [`ReadBatch`](types::ReadBatch) configured via
  [`ReadInput`](types::ReadInput) (or a [`ReadStart`](types::ReadStart) directly).
* **Continuous sessions**: [`S2Stream::read_session`] yields individual
  [`SequencedRecord`](types::SequencedRecord)s via [`ReadSession`](read_session::ReadSession), and
  [`S2Stream::read_batch_session`] yields server batches via
  [`ReadBatchSession`](read_session::ReadBatchSession). Both open synchronously, expose an
  inherent `.next().await` method (as well as [`futures_core::Stream`]), reconnect automatically
  according to [`ReadSessionConfig`](read_session::ReadSessionConfig), and provide
  [`ReadSessionState`](read_session::ReadSessionState) / [`caught_up`](read_session::ReadSession::caught_up)
  for concurrent progress observation. (Note: [`caught_up`](read_session::ReadSession::caught_up)
  only observes session progress and does not drive reading; always poll `.next()` concurrently.)

## Error Handling

Every operation returns the narrowest flat error enum for its surface:

* [`RequestError`](error::RequestError) — account, basin, stream-management, and metrics ops
* [`ReadError`](error::ReadError) / [`ReadSessionError`](error::ReadSessionError) — `check_tail`, unary reads, and opening/iterating continuous read sessions
* [`AppendError`](error::AppendError) / [`AppendSessionError`](error::AppendSessionError) — unary appends, and opening/using append sessions and producers
* [`ValidationError`](error::ValidationError) — returned by client constructors, [`with_retry`](S2::with_retry), standalone batchers, and validated value types

All of these convert into [`S2Error`]; [`S2Error`] and the five operation error enums expose
[`is_retryable`](S2Error::is_retryable),
[`has_no_side_effects`](S2Error::has_no_side_effects),
[`server_error`](S2Error::server_error), [`known_code`](S2Error::known_code), and
[`has_error_code`](S2Error::has_error_code), and wrapper-bearing enums also expose
[`root_cause`](S2Error::root_cause) to unwrap nested [`IndefiniteAppend`](S2Error::IndefiniteAppend)
and [`SessionClosed`](S2Error::SessionClosed) wrappers.

## Reconfiguration

[`BasinReconfiguration`](types::BasinReconfiguration) and
[`StreamReconfiguration`](types::StreamReconfiguration) represent every optional field as
[`Reconfigure<T>`](types::Reconfigure) (`Unchanged`, `Set(T)`, or `Reset`), with `with_*` and
`reset_*` builders so omitted fields are never accidentally cleared.

# Examples

We have curated a bunch of examples in the
[repository](https://github.com/s2-streamstore/s2/tree/main/sdk/examples)
demonstrating how to use the SDK effectively:

* [List all basins](https://github.com/s2-streamstore/s2/blob/main/sdk/examples/list_all_basins.rs)
* [Explicit stream trimming](https://github.com/s2-streamstore/s2/blob/main/sdk/examples/explicit_trim.rs)
* [Producer](https://github.com/s2-streamstore/s2/blob/main/sdk/examples/producer.rs)
* [Consumer](https://github.com/s2-streamstore/s2/blob/main/sdk/examples/consumer.rs)
* [Caught-up read session](https://github.com/s2-streamstore/s2/blob/main/sdk/examples/caught_up.rs)
* and many more...

This documentation is generated using
[`rustdoc-scrape-examples`](https://doc.rust-lang.org/rustdoc/scraped-examples.html),
so you will be able to see snippets from examples right here in the
documentation.

# TLS features

By default, `s2-sdk` enables `rustls-aws-lc-rs` and `rustls-native-roots` (using the host OS trust
store). Optional features:

* `rustls-ring`: use `ring` instead of `aws-lc-rs`
  (`default-features = false, features = ["rustls-ring", "rustls-native-roots"]`).
* `rustls-webpki-roots`: bundle Mozilla's root CA certificates (`webpki-roots`) for minimal
  containers (such as `FROM scratch` or distroless) without system CA bundles. When both
  `rustls-native-roots` and `rustls-webpki-roots` are enabled, the SDK tries native roots first and
  falls back to `webpki-roots` if no native roots are available.
* Provider resolution order for HTTPS endpoints:
  1. An explicit provider set on [`S2Config`] (`with_rustls_crypto_provider`,
     `with_rustls_aws_lc_rs_crypto_provider`, or `with_rustls_ring_crypto_provider`).
  2. Rustls's process-global default installed via [`CryptoProvider::install_default`](types::CryptoProvider::install_default) (for
     example, a FIPS-validated provider).
  3. Compile-time feature fallback (`rustls-aws-lc-rs`, then `rustls-ring`).

  Plaintext `http://` endpoints do not require a TLS provider. When building with
  `default-features = false`, enable at least one root-store feature (`rustls-native-roots` or
  `rustls-webpki-roots`) for HTTPS endpoints, plus a crypto provider (via feature,
  [`CryptoProvider::install_default`](types::CryptoProvider::install_default), or [`S2Config::with_rustls_crypto_provider`]).

# Integration tests with s2-lite

Use [`s2-testcontainers`](https://docs.rs/s2-testcontainers/latest/s2_testcontainers/)
to start `s2-lite` from the S2 Docker image and get an SDK client/config without
manual Docker port allocation, endpoint plumbing, or health polling. See the
[`s2_lite` example](https://github.com/s2-streamstore/s2/blob/main/testcontainers/examples/s2_lite.rs)
for the canonical setup.

# Feedback

We use [GitHub Issues](https://github.com/s2-streamstore/s2/issues)
to track feature requests and issues with the SDK. If you wish to provide
feedback, report a bug or request a feature, feel free to open a GitHub
issue.

# Quick Links

* [S2 Website](https://s2.dev)
* [S2 Documentation](https://s2.dev/docs)
* [CHANGELOG](https://github.com/s2-streamstore/s2/blob/main/sdk/CHANGELOG.md)
*/

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/s2-streamstore/s2/main/assets/s2-black.png"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/s2-streamstore/s2/main/assets/s2-black.png"
)]
#![warn(missing_docs)]

mod api;
mod cancel;
mod client;
mod reconnect;
mod send_gate;
mod session;

pub mod batching;
pub mod error;
mod ops;
pub mod producer;
mod retry;
pub mod types;

pub use error::S2Error;
pub use ops::{S2, S2Basin, S2Stream};
pub use types::{S2Config, S2Endpoints};
/// Append session for pipelining multiple appends with backpressure control.
///
/// See [`AppendSession`](append_session::AppendSession).
pub mod append_session {
    pub use crate::session::append::{
        AppendSession, AppendSessionConfig, BatchSubmitPermit, BatchSubmitTicket,
    };
}
/// Continuous read sessions for streaming records or batches with automatic reconnect.
///
/// See [`ReadSession`](read_session::ReadSession) and
/// [`ReadBatchSession`](read_session::ReadBatchSession).
pub mod read_session {
    pub use crate::session::read::{
        CaughtUp, ReadBatchSession, ReadSession, ReadSessionConfig, ReadSessionRetryPolicy,
        ReadSessionState,
    };
}
