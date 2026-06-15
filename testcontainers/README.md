# s2-testcontainers

Testcontainers helpers for the S2 Docker image, with a paved path for `s2-lite` integration tests.

See [`examples/s2_lite.rs`](examples/s2_lite.rs) for a complete example that
starts `s2-lite`, builds an SDK client, and ensures a basin/stream.

For lower-level composition with `testcontainers`, use `s2_image()` for the raw S2 Docker image or `s2_lite_image()` for a container request with the `lite` subcommand configured:

```rust
use s2_testcontainers::{s2_config_for_endpoint, s2_image, s2_lite_image};

let image = s2_image();
let request = s2_lite_image();
let config = s2_config_for_endpoint("http://localhost:8080", "ignored").unwrap();
```
