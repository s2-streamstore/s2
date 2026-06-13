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

/// Provisioning races s2-lite's startup, which under injected faults can take a
/// while; it needs a much larger retry budget than workload operations.
const PROVISION_ATTEMPTS: u32 = 30;

fn client(retry: RetryConfig) -> eyre::Result<S2> {
    let endpoints = S2Endpoints::new(
        lite_host::endpoint().parse()?,
        lite_host::endpoint().parse()?,
    )?;
    Ok(S2::new_with_connector(
        S2Config::new("unused-token")
            .with_endpoints(endpoints)
            .with_retry(retry),
        net::TurmoilConnector,
    )?)
}

/// The workload's SDK client.
///
/// Retries are deliberately bounded (SDK default): under injected faults the
/// server can wedge, and a workload op that can't complete should surface as an
/// error the workload records and the checker models — not retry forever.
///
/// `AppendRetryPolicy::NoSideEffects` is required for linearizability: the
/// default `All` re-sends appends of unknown outcome, which can duplicate
/// records. Here an append makes at most one effective attempt; a maybe-applied
/// failure is recorded as indefinite.
pub fn s2_client() -> eyre::Result<S2> {
    client(RetryConfig::new().with_append_retry_policy(AppendRetryPolicy::NoSideEffects))
}

/// Create the scenario's basin and stream, returning a stream handle for the
/// workload to drive.
///
/// Provisioning uses a separate client with a large retry budget to outlast
/// s2-lite's startup, and the idempotent `ensure_*` operations so a retry after
/// a lost response is safe (a `create_*` retry would fail with "already
/// exists"). The returned stream handle, by contrast, is on the bounded
/// [`s2_client`] so the workload's own operations don't inherit provisioning's
/// generous retries.
pub async fn provision_stream() -> eyre::Result<S2Stream> {
    let basin_name: BasinName = BASIN.parse()?;
    let stream_name: StreamName = STREAM.parse()?;

    let retry =
        RetryConfig::new().with_max_attempts(NonZeroU32::new(PROVISION_ATTEMPTS).expect("nonzero"));
    let provisioner = client(retry)?;
    provisioner
        .ensure_basin(EnsureBasinInput::new(basin_name.clone()))
        .await?;
    provisioner
        .basin(basin_name.clone())
        .ensure_stream(EnsureStreamInput::new(stream_name.clone()))
        .await?;

    Ok(s2_client()?.basin(basin_name).stream(stream_name))
}
