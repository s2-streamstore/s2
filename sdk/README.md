<div align="center">
  <p>
    <!-- Light mode logo -->
    <a href="https://s2.dev#gh-light-mode-only">
      <img src="https://raw.githubusercontent.com/s2-streamstore/s2/main/assets/s2-black.png" height="60">
    </a>
    <!-- Dark mode logo -->
    <a href="https://s2.dev#gh-dark-mode-only">
      <img src="https://raw.githubusercontent.com/s2-streamstore/s2/main/assets/s2-white.png" height="60">
    </a>
  </p>

  <h1>Rust SDK for S2</h1>

  <p>
    <!-- Crates.io -->
    <a href="https://crates.io/crates/s2-sdk"><img src="https://img.shields.io/crates/v/s2-sdk.svg" /></a>
    <!-- Docs.rs -->
    <a href="https://docs.rs/s2-sdk/latest/s2_sdk/"><img src="https://img.shields.io/docsrs/s2-sdk" /></a>
    <!-- GitHub Actions (CI) -->
    <a href="https://github.com/s2-streamstore/s2/actions?query=branch%3Amain++"><img src="https://github.com/s2-streamstore/s2/actions/workflows/ci.yml/badge.svg" /></a>
    <!-- Discord (chat) -->
    <a href="https://discord.gg/vTCs7kMkAf"><img src="https://img.shields.io/discord/1209937852528599092?logo=discord" /></a>
    <!-- LICENSE -->
    <a href="https://github.com/s2-streamstore/s2/blob/main/LICENSE"><img src="https://img.shields.io/github/license/s2-streamstore/s2" /></a>
  </p>
</div>

The Rust SDK provides an ergonomic interface and utilities to interact with the
[S2 API](https://s2.dev/docs/rest/records/overview). It targets conformance with
the [S2 SDK Specification](https://github.com/s2-streamstore/s2-specs/blob/main/sdk/spec.md), Revision 1 (Draft).

## Getting started

1. Ensure you have added [tokio](https://crates.io/crates/tokio) as a dependency:
   ```bash
   cargo add tokio --features full
   ```

1. Add the `s2-sdk` dependency to your project:
   ```bash
   cargo add s2-sdk
   ```

1. Generate an access token by logging into the web console at
   [s2.dev](https://s2.dev/dashboard), then export `S2_ACCESS_TOKEN`.

1. Perform an operation:
   ```rust
   use s2_sdk::{S2, types::ListBasinsInput};

   #[tokio::main]
   async fn main() -> Result<(), Box<dyn std::error::Error>> {
       let s2 = S2::from_env()?;
       let page = s2.list_basins(ListBasinsInput::new()).await?;
       println!("My basins: {:?}", page.values);
       Ok(())
   }
   ```

## Overview

- **Handles & lifecycle**: `S2` -> `S2Basin` -> `S2Stream` are cheaply cloneable handles sharing a pooled HTTP/2 transport. Use `S2::from_env()` (reads `S2_ACCESS_TOKEN`, plus optional `S2_ACCOUNT_ENDPOINT` / `S2_BASIN_ENDPOINT`) or `S2::new(S2Config::new(...))`, and call `s2.close()` to tear down active sessions and connections immediately.
- **Appending**: Use `stream.append(...)` for unary batches, `stream.producer(ProducerConfig::new())?` for automatic record batching with linger/backpressure (`submit`, `flush`, `close`), or `stream.append_session(AppendSessionConfig::new())?` for pre-batched pipelining (with standalone `batching::{Batcher, TryBatcher, batch_iter, try_batch_iter}`).
- **Reading**: Use `stream.read(ReadStart::SeqNum(0))` (or `ReadInput::new()...`) for unary reads, or `stream.read_session(ReadStart::SeqNum(0), ReadSessionConfig::new())?` (`SequencedRecord`s) / `stream.read_batch_session(...)` (`ReadBatch`es) for continuous streaming with automatic reconnect and `.caught_up()` / `.state()` progress tracking (always poll `.next()` concurrently with `.caught_up()`).
- **Errors**: Each operation returns its narrow error enum (`RequestError`, `ReadError`, `AppendError`, `AppendSessionError`, `ReadSessionError`), all convertible into `S2Error`, with `.is_retryable()`, `.has_no_side_effects()`, `.server_error()`, `.known_code()`, and `.has_error_code(...)`.
- **Reconfiguration**: `BasinReconfiguration` and `StreamReconfiguration` use `Reconfigure<T>` (`Unchanged` / `Set` / `Reset`) with `with_*` and `reset_*` builders.

## TLS Features

By default, `s2-sdk` enables `rustls-aws-lc-rs` and `rustls-native-roots` (host OS trust store).

- `rustls-ring`: use `ring` instead of `aws-lc-rs` (`default-features = false, features = ["rustls-ring", "rustls-native-roots"]`).
- `rustls-webpki-roots`: bundle Mozilla's root CA certificates for minimal containers (`FROM scratch`, distroless) without system CA bundles. When enabled alongside `rustls-native-roots`, native roots are tried first with automatic fallback to `webpki-roots`.
- Provider resolution order for HTTPS endpoints: (1) an explicit provider on `S2Config` (`with_rustls_crypto_provider(...)`, `with_rustls_aws_lc_rs_crypto_provider()`, or `with_rustls_ring_crypto_provider()`), (2) rustls's process-global default installed via `CryptoProvider::install_default()` (such as a FIPS provider), then (3) the compile-time feature fallback (`rustls-aws-lc-rs`, then `rustls-ring`). Plaintext `http://` endpoints do not require a TLS provider.

## Upgrading to Revision 1

Notable breaking changes when upgrading from pre-Revision 1 releases:

- **Errors**: Replaced monolithic `S2Error` variants with 5 flat operation error enums (`RequestError`, `ReadError`, `AppendError`, `AppendSessionError`, `ReadSessionError`) plus catch-all `S2Error` (re-exported at crate root alongside `S2Config` and `S2Endpoints`) wrapping canonical leaf error structs. Constructors (`S2::new`, `S2::from_env`) return `s2_sdk::error::ValidationError`.
- **Reading**: Renamed `ReadFrom` to `ReadStart`; flattened `ReadInput` (`with_start`, `with_clamp`, `with_count`, `with_bytes`, `with_until`, `with_wait`, `with_stream_config`) and `read` / `read_session` / `read_batch_session` accept `impl Into<ReadInput>` (including `ReadStart` directly); moved `ReadSessionConfig` / `ReadSessionRetryPolicy` to `s2_sdk::read_session`; made `read_session()` / `read_batch_session()` synchronous (`read_session()` now yields individual `SequencedRecord`s) with inherent `.next().await` and `ReadSessionState`.
- **Appending & batching**: Replaced `AppendRecordBatches` / `AppendInputs` with `BatcherConfig`, `Batcher<S>`, `TryBatcher<S>`, `batching::batch_iter`, `batching::try_batch_iter`, and flattened `ProducerConfig`; `BatchLimits` now describes `RECORD_BATCH_MAX`; `max_unacked_bytes` / `max_unacked_batches` / `reserve(...)` use `usize`. `AppendSession` and `Producer` open lazily, `close(&self)` is idempotent, `abort(&self)` aborts explicitly, `AppendInput` and `CommandRecord` use private-field builders/getters, and unary `stream_config` moved to `S2Stream::append_with_stream_config`.
- **Management & types**: Replaced `Maybe` with `Reconfigure<T>` + `reset_*` helpers; unified all input/config structs on private fields + getters + `with_*` builders; collapsed `AccessTokenScopeInput` into `AccessTokenScope`; wrapped `create_network_policy` in `CreateNetworkPolicyInput`; replaced `EncryptionKey::new` with `EncryptionKey::from_bytes` / `from_base64`; renamed `S2Stream::basin()` to `S2Stream::basin_name()`; replaced `Streaming<T>` with concrete `ListStream<T>`; migrated timestamps from `time::OffsetDateTime` to `jiff::Timestamp`; removed `compact_str::CompactString` and internal `s2_api` `From` conversions from public APIs.

## Examples

The [`examples`](./examples) directory in this repository contains a variety of
example use cases demonstrating how to use the SDK effectively.

You might have to set one or more of these env vars based on the example you run:

```bash
export S2_ACCESS_TOKEN="<YOUR_ACCESS_TOKEN>"
export S2_BASIN="<YOUR_BASIN_NAME>"
export S2_STREAM="<YOUR_STREAM_NAME>"
export S2_ENCRYPTION_KEY="<YOUR_ENCRYPTION_KEY>"
# Optional custom endpoints (for example, local s2-lite):
# export S2_ACCOUNT_ENDPOINT="http://localhost:8080"
# export S2_BASIN_ENDPOINT="http://localhost:8080"
cargo run -p s2-sdk --example <example_name>
```

## SDK Docs and Reference

Head over to [docs.rs](https://docs.rs/s2-sdk/latest/s2_sdk/) for
detailed documentation and crate reference.

## Feedback

We use [Github Issues](https://github.com/s2-streamstore/s2/issues) to
track feature requests and issues with the SDK. If you wish to provide feedback,
report a bug or request a feature, feel free to open a Github issue.

## Contributing

Developers are welcome to submit Pull Requests on the repository. If there is
no tracking issue for the bug or feature request corresponding to the PR, we
encourage you to open one for discussion before submitting the PR.

## Reach out to us

Join our [Discord](https://discord.gg/vTCs7kMkAf) server. We would love to hear
from you.

You can also email us at [hi@s2.dev](mailto:hi@s2.dev).

## License

This project is licensed under the [MIT License](https://github.com/s2-streamstore/s2/blob/main/LICENSE).
