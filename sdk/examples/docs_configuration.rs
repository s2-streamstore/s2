//! Documentation examples for Configuration page.
//!
//! Run with: cargo run -p s2-sdk --example docs_configuration

use std::time::Duration;

use s2_sdk::{
    S2,
    types::{RetryConfig, S2Config, S2Endpoints},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example: Custom endpoints (e.g., for s2-lite local dev)
    {
        // ANCHOR: custom-endpoints
        let client = S2::new(
            S2Config::new("local-token")
                .with_endpoints(S2Endpoints::for_endpoint("http://localhost:8080")?),
        )?;
        // ANCHOR_END: custom-endpoints
        println!("Created client with custom endpoints: {:?}", client);
    }

    // Example: Configuration from environment variables
    if std::env::var("S2_ACCESS_TOKEN").is_ok() {
        // ANCHOR: env-endpoints
        // Reads S2_ACCESS_TOKEN and optional S2_ACCOUNT_ENDPOINT / S2_BASIN_ENDPOINT.
        let client = S2::from_env()?;
        // ANCHOR_END: env-endpoints
        println!("Created client from environment: {:?}", client);
    }

    // Example: Custom retry configuration
    {
        let access_token = std::env::var("S2_ACCESS_TOKEN").unwrap_or_else(|_| "demo".into());
        // ANCHOR: retry-config
        let client = S2::new(
            S2Config::new(access_token).with_retry(
                RetryConfig::new()
                    .with_max_attempts(5)
                    .with_min_base_delay(Duration::from_millis(100))
                    .with_max_base_delay(Duration::from_secs(2)),
            ),
        )?;
        // ANCHOR_END: retry-config
        println!("Created client with retry config: {:?}", client);
    }

    // Example: Custom timeout configuration
    {
        let access_token = std::env::var("S2_ACCESS_TOKEN").unwrap_or_else(|_| "demo".into());
        // ANCHOR: timeout-config
        let client = S2::new(
            S2Config::new(access_token)
                .with_connection_timeout(Duration::from_secs(5))
                .with_request_timeout(Duration::from_secs(10)),
        )?;
        // ANCHOR_END: timeout-config
        println!("Created client with timeout config: {:?}", client);
    }

    Ok(())
}
