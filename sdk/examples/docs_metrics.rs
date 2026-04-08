//! Documentation examples for Metrics page.
//!
//! Run with: cargo run --example docs_metrics

use s2_sdk::{
    S2,
    types::{
        AccountMetricSet, BasinMetricSet, GetAccountMetricsInput, GetBasinMetricsInput,
        GetStreamMetricsInput, S2Config, StreamMetricSet, TimeRange,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let access_token = std::env::var("S2_ACCESS_TOKEN")?;
    let client = S2::new(S2Config::new(access_token))?;

    // ANCHOR: metrics
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as u32;
    let thirty_days_ago = now - 30 * 24 * 3600;
    let six_hours_ago = now - 6 * 3600;
    let hour_ago = now - 3600;

    // Account-level: active basins over the last 30 days
    let account_metrics = client
        .get_account_metrics(GetAccountMetricsInput::new(AccountMetricSet::ActiveBasins(
            TimeRange::new(thirty_days_ago, now),
        )))
        .await?;

    // Basin-level: storage usage with hourly resolution
    let basin_metrics = client
        .get_basin_metrics(GetBasinMetricsInput::new(
            "events".parse()?,
            BasinMetricSet::Storage(TimeRange::new(six_hours_ago, now)),
        ))
        .await?;

    // Stream-level: storage for a specific stream
    let stream_metrics = client
        .get_stream_metrics(GetStreamMetricsInput::new(
            "events".parse()?,
            "user-actions".parse()?,
            StreamMetricSet::Storage(TimeRange::new(hour_ago, now)),
        ))
        .await?;
    // ANCHOR_END: metrics

    println!(
        "{:?} {:?} {:?}",
        account_metrics, basin_metrics, stream_metrics
    );

    Ok(())
}
