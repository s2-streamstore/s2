# s2-testcontainers

Testcontainers helpers for running `s2-lite` from the existing S2 CLI image in Rust integration tests.

```rust
use s2_testcontainers::S2Lite;

#[tokio::test]
async fn test_with_s2_lite() -> s2_testcontainers::Result<()> {
    let s2 = S2Lite::start().await?;

    let client = s2.client()?;
    let basin = s2.ensure_basin("test-basin").await?;
    let stream = s2.ensure_stream(&basin, "test-stream").await?;

    // Use `client`, `basin`, `stream`, and `s2.endpoint()`.
    Ok(())
}
```

For lower-level composition with `testcontainers`, `s2_lite_image()` returns a container request for `ghcr.io/s2-streamstore/s2` with the `lite` subcommand configured:

```rust
use s2_testcontainers::{s2_config_for_endpoint, s2_lite_image};

let request = s2_lite_image();
let config = s2_config_for_endpoint("http://localhost:8080", "ignored").unwrap();
```
