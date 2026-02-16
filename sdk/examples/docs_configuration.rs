//! Documentation examples for Configuration page.
//!
//! Run with: cargo run --example docs_configuration

use std::{num::NonZeroU32, time::Duration};

use s2_sdk::{
    S2,
    types::{AccountEndpoint, BasinEndpoint, RetryConfig, S2Config, S2Endpoints},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example: Custom endpoints (e.g., for s2-lite local dev)
    {
        let token = "local-token".to_string();
        // ANCHOR: custom-endpoints
        let endpoints = S2Endpoints::new(
            AccountEndpoint::new("http://localhost:8080")?,
            BasinEndpoint::new("http://localhost:8080")?,
        )?;

        let client = S2::new(S2Config::new(token).with_endpoints(endpoints))?;
        // ANCHOR_END: custom-endpoints
        println!("Created client with custom endpoints: {:?}", client);
    }

    // Example: Custom retry configuration
    {
        let token = std::env::var("S2_ACCESS_TOKEN").unwrap_or_else(|_| "demo".into());
        // ANCHOR: retry-config
        let client = S2::new(
            S2Config::new(token).with_retry(
                RetryConfig::new()
                    .with_max_attempts(NonZeroU32::new(5).unwrap())
                    .with_min_base_delay(Duration::from_millis(100))
                    .with_max_base_delay(Duration::from_secs(2)),
            ),
        )?;
        // ANCHOR_END: retry-config
        println!("Created client with retry config: {:?}", client);
    }

    // Example: Custom timeout configuration
    {
        let token = std::env::var("S2_ACCESS_TOKEN").unwrap_or_else(|_| "demo".into());
        // ANCHOR: timeout-config
        let client = S2::new(
            S2Config::new(token)
                .with_connection_timeout(Duration::from_secs(5))
                .with_request_timeout(Duration::from_secs(10)),
        )?;
        // ANCHOR_END: timeout-config
        println!("Created client with timeout config: {:?}", client);
    }

    Ok(())
}
