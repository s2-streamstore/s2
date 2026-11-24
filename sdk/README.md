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

- **Handles & lifecycle**: `S2` -> `S2Basin` -> `S2Stream` are cheaply cloneable handles sharing a pooled HTTP/2 transport. Use `S2::from_env()` (reads `S2_ACCESS_TOKEN`, plus optional `S2_ACCOUNT_ENDPOINT` / `S2_BASIN_ENDPOINT`) or `S2::new(S2Config::new(...))`, override per-handle retry settings without duplicating pools via `.with_retry(RetryConfig)` on `S2`/`S2Basin`/`S2Stream`, and call `s2.close()` to tear down active sessions and connections immediately. Single-page `list_*` calls return `Page<T>` (with `.next_start_after()`), while `list_all_*` calls return a lazy `ListStream<T>`.
- **Appending**: Use `stream.append(...)` for unary batches, `stream.producer(ProducerConfig::new())?` for automatic record batching with linger/backpressure (`submit`, `flush`, `close`, plus non-blocking `unacked_bytes` / `unacked_records` / `acked_records`), or `stream.append_session(AppendSessionConfig::new())?` for pre-batched pipelining (`unacked_bytes` / `unacked_batches`, plus standalone `batching::{Batcher, TryBatcher, batch_iter, try_batch_iter}`).
- **Reading**: Use `stream.read(ReadStart::SeqNum(0))` (or `ReadInput::new()...`) for unary reads, or `stream.read_session(ReadStart::SeqNum(0), ReadSessionConfig::new())?` (`SequencedRecord`s) / `stream.read_batch_session(...)` (`ReadBatch`es) for continuous streaming with automatic reconnect and `.caught_up()` / `.state()` progress tracking (always poll `.next()` concurrently with `.caught_up()`).
- **Errors**: Each operation returns its narrow error enum (`RequestError`, `ReadError`, `AppendError`, `AppendSessionError`, `ReadSessionError`), all convertible into `S2Error`, with `.is_retryable()`, `.has_no_side_effects()`, `.server_error()`, `.known_code()`, and `.has_error_code(...)`. Session/producer openers return `ClientClosedError` if the client was closed, and client constructors / `.with_retry(...)` return `ValidationError`.
- **Reconfiguration**: `BasinReconfiguration` and `StreamReconfiguration` use `Reconfigure<T>` (`Unchanged` / `Set` / `Reset`) with `with_*` and `reset_*` builders.
- **Integration testing**: Use [`s2-testcontainers`](https://crates.io/crates/s2-testcontainers) to run local `s2-lite` containers in tests without manual Docker or endpoint plumbing.

## TLS Features

By default, `s2-sdk` enables `rustls-aws-lc-rs` and `rustls-native-roots` (host OS trust store).

- `rustls-ring`: use `ring` instead of `aws-lc-rs` (`default-features = false, features = ["rustls-ring", "rustls-native-roots"]`).
- `rustls-webpki-roots`: bundle Mozilla's root CA certificates for minimal containers (`FROM scratch`, distroless) without system CA bundles. When enabled alongside `rustls-native-roots`, native roots are tried first with automatic fallback to `webpki-roots`.
- Provider resolution order for HTTPS endpoints: (1) an explicit provider on `S2Config` (`with_rustls_crypto_provider(...)`, `with_rustls_aws_lc_rs_crypto_provider()`, or `with_rustls_ring_crypto_provider()`), (2) rustls's process-global default installed via `CryptoProvider::install_default()` (such as a FIPS provider), then (3) the compile-time feature fallback (`rustls-aws-lc-rs`, then `rustls-ring`). When building with `default-features = false`, enable at least one root-store feature (`rustls-native-roots` or `rustls-webpki-roots`) for HTTPS endpoints. Plaintext `http://` endpoints do not require a TLS provider.

## Examples

The [`examples`](https://github.com/s2-streamstore/s2/tree/main/sdk/examples) directory in this repository contains a variety of
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

We use [GitHub Issues](https://github.com/s2-streamstore/s2/issues) to
track feature requests and issues with the SDK. If you wish to provide feedback,
report a bug or request a feature, feel free to open a GitHub issue.

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
