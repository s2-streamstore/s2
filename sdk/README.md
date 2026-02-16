<div align="center">
  <p>
    <!-- Light mode logo -->
    <a href="https://s2.dev#gh-light-mode-only">
      <img src="../assets/s2-black.png" height="60">
    </a>
    <!-- Dark mode logo -->
    <a href="https://s2.dev#gh-dark-mode-only">
      <img src="../assets/s2-white.png" height="60">
    </a>
  </p>

  <h1>Rust SDK for S2</h1>

  <p>
    <!-- Crates.io -->
    <a href="https://crates.io/crates/s2-sdk"><img src="https://img.shields.io/crates/v/s2-sdk.svg" /></a>
    <!-- Docs.rs -->
    <a href="https://docs.rs/s2-sdk/latest/s2_sdk/"><img src="https://img.shields.io/docsrs/s2-sdk" /></a>
    <!-- Github Actions (CI) -->
    <a href="https://github.com/s2-streamstore/s2/actions?query=branch%3Amain++"><img src="https://github.com/s2-streamstore/s2/actions/workflows/ci.yml/badge.svg" /></a>
    <!-- Discord (chat) -->
    <a href="https://discord.gg/vTCs7kMkAf"><img src="https://img.shields.io/discord/1209937852528599092?logo=discord" /></a>
    <!-- LICENSE -->
    <a href="../LICENSE"><img src="https://img.shields.io/github/license/s2-streamstore/s2" /></a>
  </p>
</div>

The Rust SDK provides ergonomic interface and utilities to interact with the
[S2 API](https://s2.dev/docs/rest/records/overview).

## Getting started

1. Ensure you have added [tokio](https://crates.io/crates/tokio) and [futures](https://crates.io/crates/futures) as dependencies.
   ```bash
   cargo add tokio --features full
   cargo add futures
   ```

1. Add the `s2-sdk` dependency to your project:
   ```bash
   cargo add s2-sdk
   ```

1. Generate an access token by logging into the web console at
   [s2.dev](https://s2.dev/dashboard).

1. Perform an operation.
   ```rust
    use s2_sdk::{
        S2,
        types::{ListBasinsInput, S2Config},
    };

    #[tokio::main]
    async fn main() -> Result<(), Box<dyn std::error::Error>> {
        let s2 = S2::new(S2Config::new("<YOUR_ACCESS_TOKEN>"))?;
        let page = s2.list_basins(ListBasinsInput::new()).await?;
        println!("My basins: {:?}", page.values);
        Ok(())
    }
   ```

## Examples

The [`examples`](./examples) directory in this repository contains a variety of
example use cases demonstrating how to use the SDK effectively.

You might have to set either one or all of these env vars based on the example you run.

```bash
export S2_ACCESS_TOKEN="<YOUR_ACCESS_TOKEN>"
export S2_BASIN="<YOUR_BASIN_NAME>"
export S2_STREAM="<YOUR_STREAM_NAME>"
cargo run --example <example_name>
```

## SDK Docs and Reference

Head over to [docs.rs](https://docs.rs/s2-sdk/latest/s2_sdk/) for
detailed documentation and crate reference.

## Feedback

We use [Github Issues](https://github.com/s2-streamstore/s2/issues) to
track feature requests and issues with the SDK. If you wish to provide feedback,
report a bug or request a feature, feel free to open a Github issue.

### Contributing

Developers are welcome to submit Pull Requests on the repository. If there is
no tracking issue for the bug or feature request corresponding to the PR, we
encourage you to open one for discussion before submitting the PR.

## Reach out to us

Join our [Discord](https://discord.gg/vTCs7kMkAf) server. We would love to hear
from you.

You can also email us at [hi@s2.dev](mailto:hi@s2.dev).

## License

This project is licensed under the [MIT License](../LICENSE).
