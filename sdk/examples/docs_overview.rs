//! Documentation examples for SDK Overview page.
//!
//! Run with: cargo run --example docs_overview

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ANCHOR: create-client
    use s2_sdk::{S2, types::S2Config};

    let client = S2::new(S2Config::new(std::env::var("S2_ACCESS_TOKEN")?))?;

    let basin = client.basin("my-basin".parse()?);
    let stream = basin.stream("my-stream".parse()?);
    // ANCHOR_END: create-client

    println!("Created client for stream: {:?}", stream);
    Ok(())
}
