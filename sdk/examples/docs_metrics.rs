//! Documentation examples for Metrics page.
//!
//! Run with: cargo run -p s2-sdk --example docs_metrics

use std::time::Duration;

use s2_sdk::{
    S2,
    types::{AccountMetricSet, BasinMetricSet, StreamMetricSet, TimeRange, Timestamp},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = S2::from_env()?;

    // ANCHOR: metrics
    let now = Timestamp::now();
    let thirty_days_ago = now - Duration::from_secs(30 * 24 * 3600);
    let six_hours_ago = now - Duration::from_secs(6 * 3600);
    let hour_ago = now - Duration::from_secs(3600);

    // Account-level: active basins over the last 30 days
    let account_metrics = client
        .get_account_metrics(AccountMetricSet::ActiveBasins(TimeRange::new(
            thirty_days_ago,
            now,
        )?))
        .await?;

    // Basin-level: storage usage with hourly resolution
    let basin_metrics = client
        .get_basin_metrics(
            "my-events".parse()?,
            BasinMetricSet::Storage(TimeRange::new(six_hours_ago, now)?),
        )
        .await?;

    // Stream-level: storage for a specific stream
    let stream_metrics = client
        .get_stream_metrics(
            "my-events".parse()?,
            "user-actions".parse()?,
            StreamMetricSet::Storage(TimeRange::new(hour_ago, now)?),
        )
        .await?;
    // ANCHOR_END: metrics

    println!(
        "{:?} {:?} {:?}",
        account_metrics, basin_metrics, stream_metrics
    );

    Ok(())
}
