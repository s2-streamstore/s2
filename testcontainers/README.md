# s2-testcontainers

Testcontainers helpers for running `s2-lite` in Rust integration tests.

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

For lower-level composition with `testcontainers`:

```rust
use s2_testcontainers::{s2_config_for_endpoint, s2_lite_image};

let image = s2_lite_image();
let config = s2_config_for_endpoint("http://localhost:8080", "ignored").unwrap();
```
