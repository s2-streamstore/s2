//! Simulation scenarios, selected via CLI subcommand.
//!
//! A scenario is an async fn run as the turmoil client named "workload"; the
//! simulation ends when it returns. Hosts (s3, s2-lite) are registered by
//! `main` and shared by all scenarios.

pub mod linearizable;
pub mod smoke;

use std::num::NonZeroU32;

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

/// An SDK client that connects to the s2-lite host over the turmoil network.
pub fn s2_client() -> eyre::Result<S2> {
    let endpoints = S2Endpoints::new(
        lite_host::endpoint().parse()?,
        lite_host::endpoint().parse()?,
    )?;
    // The default `AppendRetryPolicy::All` re-sends appends whose outcome is
    // unknown, which can load to duplicated records. For linearizability model checking,
    // we need to discard use of any client which experiences an indefinite failure.
    let retry = RetryConfig::new()
        .with_append_retry_policy(AppendRetryPolicy::NoSideEffects)
        .with_max_attempts(NonZeroU32::MAX);
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

    s2.ensure_basin(EnsureBasinInput::new(basin_name.clone()))
        .await?;
    basin
        .ensure_stream(EnsureStreamInput::new(stream_name.clone()))
        .await?;
    Ok(basin.stream(stream_name))
}
