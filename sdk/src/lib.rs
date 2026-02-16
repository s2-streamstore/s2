/*!
Rust SDK for [S2](https://s2.dev/).

The Rust SDK provides ergonomic wrappers and utilities to interact with the
[S2 API](https://s2.dev/docs/rest/records/overview).

# Getting started

1. Ensure you have added [tokio](https://crates.io/crates/tokio) and [futures](https://crates.io/crates/futures) as dependencies.
   ```bash
   cargo add tokio --features full
   cargo add futures
   ```

1. Add the `s2-sdk` dependency to your project:

   ```bash
   cargo add s2-sdk
   ```

1. Generate an access token by logging into the web console at [s2.dev](https://s2.dev/dashboard).

1. Perform an operation.

   ```no_run
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

See [`S2`] for account-level operations, [`S2Basin`] for basin-level operations,
and [`S2Stream`] for stream-level operations.

# Examples

We have curated a bunch of examples in the
[repository](https://github.com/s2-streamstore/s2/tree/main/sdk/examples)
demonstrating how to use the SDK effectively:

* [List all basins](https://github.com/s2-streamstore/s2/blob/main/sdk/examples/list_all_basins.rs)
* [Explicit stream trimming](https://github.com/s2-streamstore/s2/blob/main/sdk/examples/explicit_trim.rs)
* [Producer](https://github.com/s2-streamstore/s2/blob/main/sdk/examples/producer.rs)
* [Consumer](https://github.com/s2-streamstore/s2/blob/main/sdk/examples/consumer.rs)
* and many more...

This documentation is generated using
[`rustdoc-scrape-examples`](https://doc.rust-lang.org/rustdoc/scraped-examples.html),
so you will be able to see snippets from examples right here in the
documentation.

# Feedback

We use [Github Issues](https://github.com/s2-streamstore/s2/issues)
to track feature requests and issues with the SDK. If you wish to provide
feedback, report a bug or request a feature, feel free to open a Github
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

#[rustfmt::skip]
mod api;
mod client;
mod session;

pub mod batching;
mod ops;
pub mod producer;
mod retry;
pub mod types;

pub use ops::{S2, S2Basin, S2Stream};
/// Append session for pipelining multiple appends with backpressure control.
///
/// See [`AppendSession`](append_session::AppendSession).
pub mod append_session {
    pub use crate::session::append::{
        AppendSession, AppendSessionConfig, BatchSubmitPermit, BatchSubmitTicket,
    };
}
