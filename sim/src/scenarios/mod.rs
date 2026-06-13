//! Simulation scenarios, selected via CLI subcommand.
//!
//! A scenario is an async fn run as the turmoil client named "workload"; the
//! simulation ends when it returns. Hosts (s3, s2-lite) are registered by
//! `main` and shared by all scenarios.

pub mod linearizable;
pub mod smoke;

use std::time::Duration;

use s2_sdk::{
    S2, S2Stream,
    types::{
        AppendRetryPolicy, BasinName, EnsureBasinInput, EnsureStreamInput, RetryConfig, S2Config,
        S2Endpoints, StreamName,
    },
};

use crate::{lite_host, net};

pub const BASIN: &str = "sim-basin";
pub const STREAM: &str = "sim-stream";

/// Provisioning runs before the workload and races s2-lite's startup (which
/// can itself be slowed by injected network faults), so retry for a while.
const PROVISION_ATTEMPTS: usize = 100;
const PROVISION_RETRY_DELAY: Duration = Duration::from_millis(250);

/// An SDK client that connects to the s2-lite host over the turmoil network.
pub fn s2_client() -> eyre::Result<S2> {
    let endpoints = S2Endpoints::new(
        lite_host::endpoint().parse()?,
        lite_host::endpoint().parse()?,
    )?;
    // The default `AppendRetryPolicy::All` re-sends appends whose outcome is
    // unknown, which can lead to duplicated records. For linearizability model
    // checking, every workload operation must make at most one effective
    // attempt; maybe-applied failures are recorded as indefinite.
    //
    // Retry attempts must stay bounded: under injected faults the server can
    // wedge permanently (a finding in itself!), and unbounded retries would
    // then keep the simulation running forever. A failed op is fine — the
    // workload records it and the checker models it.
    let retry = RetryConfig::new().with_append_retry_policy(AppendRetryPolicy::NoSideEffects);
    Ok(S2::new_with_connector(
        S2Config::new("unused-token")
            .with_endpoints(endpoints)
            .with_retry(retry),
        net::TurmoilConnector,
    )?)
}

/// Create the scenario's basin and stream, returning a stream handle.
///
/// Uses the idempotent `ensure_*` operations with retries: requests (or their
/// responses) may be lost to injected faults, and a `create_*` retry after a
/// lost response would fail with "already exists".
pub async fn provision_stream() -> eyre::Result<S2Stream> {
    let s2 = s2_client()?;
    let basin_name: BasinName = BASIN.parse()?;
    let stream_name: StreamName = STREAM.parse()?;
    let basin = s2.basin(basin_name.clone());

    retry(|| s2.ensure_basin(EnsureBasinInput::new(basin_name.clone()))).await?;
    retry(|| basin.ensure_stream(EnsureStreamInput::new(stream_name.clone()))).await?;
    Ok(basin.stream(stream_name))
}

async fn retry<T, F>(mut op: impl FnMut() -> F) -> Result<T, s2_sdk::types::S2Error>
where
    F: Future<Output = Result<T, s2_sdk::types::S2Error>>,
{
    let mut attempts = 0;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) if attempts < PROVISION_ATTEMPTS => {
                attempts += 1;
                tracing::debug!(%err, attempts, "provisioning attempt failed, retrying");
                tokio::time::sleep(PROVISION_RETRY_DELAY).await;
            }
            Err(err) => return Err(err),
        }
    }
}
