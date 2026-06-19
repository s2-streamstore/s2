//! Deterministic simulation testing for s2-lite.
//!
//! Runs turmoil hosts on a simulated network:
//! - `s3`: a mock S3 service (see [`s3`])
//! - `s2-lite`: the lite server, slatedb backend pointed at the mock S3
//! - `workload`: a scenario driving s2-sdk clients against the lite server (see [`scenarios`])
//!
//! Determinism relies on `mad-turmoil` (shadowed clocks and entropy via libc
//! interposition, a global seeded RNG) plus `--cfg tokio_unstable` so turmoil
//! can seed tokio's internal RNG. A determinism "meta test" (`sim meta`) runs
//! the same seed twice and requires byte-identical output.

mod history;
mod lite_host;
mod meta;
mod net;
mod object_store_http;
mod s3;
mod scenarios;

use std::time::{Duration, SystemTime};

use clap::Parser;
use rand::{SeedableRng, rngs::StdRng};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(about = "Deterministic simulation testing for s2-lite")]
struct Args {
    /// RNG seed; the same seed must yield an identical simulation.
    #[arg(long, env = "SIM_SEED", default_value_t = 0, global = true)]
    seed: u64,

    /// Probability [0, 1) of network message loss.
    #[arg(long, default_value_t = 0.0, global = true)]
    fail_rate: f64,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
enum Cmd {
    /// Create/append/read smoke test.
    Smoke,
    /// Concurrent clients recording an operation history for the
    /// linearizability checker (s2-verification / s2-porcupine).
    Linearizable(scenarios::linearizable::Config),
    /// Determinism meta-test: run the given simulation twice and require
    /// byte-identical output (e.g. `sim meta linearizable --seed 42`).
    Meta(meta::MetaArgs),
}

fn main() -> eyre::Result<()> {
    // A compile-time check would be nicer, but would break workspace-wide
    // builds (`just test` / `just clippy`) that don't set the flag.
    if cfg!(not(tokio_unstable)) {
        eyre::bail!(
            "must be built with RUSTFLAGS=\"--cfg tokio_unstable\" so turmoil can seed tokio's \
             internal RNG; use `just sim`"
        );
    }

    let args = Args::parse();

    if let Cmd::Meta(meta) = args.cmd {
        // The meta harness only spawns child processes; it must not install
        // simulated clocks or otherwise behave like a simulation itself.
        init_tracing();
        return meta::run(meta, args.seed, args.fail_rate);
    }

    // Keep shadowed clocks installed for the lifetime of the simulation, so
    // wall-clock reads inside lite/slatedb/sdk observe simulated time.
    let _clocks_guard = mad_turmoil::time::SimClocksGuard::init();
    mad_turmoil::rand::set_rng(StdRng::seed_from_u64(args.seed));
    fastrand::seed(args.seed);

    init_tracing();
    info!(?args, "starting simulation");

    let mut sim = init_sim(args.seed, args.fail_rate);

    sim.host(s3::HOST, || async {
        s3::serve().await.inspect_err(log_host_exit(s3::HOST))
    });
    sim.host(lite_host::HOST, || async {
        lite_host::serve()
            .await
            .inspect_err(log_host_exit(lite_host::HOST))
    });

    match args.cmd {
        Cmd::Meta(_) => unreachable!("handled above"),
        Cmd::Smoke => {
            sim.client("workload", scenarios::smoke::workload());
            run(sim)?;
        }
        Cmd::Linearizable(config) => {
            let (history_tx, mut history_rx) = tokio::sync::mpsc::unbounded_channel();
            sim.client(
                "workload",
                scenarios::linearizable::workload(config, history_tx),
            );
            run(sim)?;
            let path = history::save(&mut history_rx, args.seed)?;
            info!(
                "check linearizability with: s2-porcupine -file={}",
                path.display()
            );
        }
    }

    info!("simulation completed");
    Ok(())
}

fn run(mut sim: turmoil::Sim<'_>) -> eyre::Result<()> {
    sim.run()
        .map_err(|err| eyre::eyre!("simulation failed: {err}"))
}

fn init_sim(seed: u64, fail_rate: f64) -> turmoil::Sim<'static> {
    let mut builder = turmoil::Builder::new();
    builder
        .rng_seed(seed)
        // Backstop: a wedged system (e.g. a server stuck erroring forever
        // while clients still have ops to attempt) should fail the simulation
        // deterministically instead of running unbounded. Scenarios complete
        // in simulated minutes; leave generous headroom for fault backoffs.
        .simulation_duration(Duration::from_secs(4 * 60 * 60))
        .min_message_latency(Duration::from_millis(2))
        .max_message_latency(Duration::from_millis(30))
        .tcp_capacity(10_000)
        .tick_duration(Duration::from_millis(1))
        .epoch(SystemTime::UNIX_EPOCH);
    if fail_rate > 0.0 {
        builder.fail_rate(fail_rate);
    }
    builder.build()
}

fn log_host_exit(host: &str) -> impl Fn(&Box<dyn std::error::Error>) + use<'_> {
    move |err| tracing::error!(host, "host exited with error: {err}")
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_timer(SimStepTimeFormat))
        .init();
}

/// Timestamps log lines with simulated elapsed time and an event ordinal
/// instead of wall-clock time, keeping output stable across runs of the same
/// seed (a prerequisite for the determinism meta test).
struct SimStepTimeFormat;

impl tracing_subscriber::fmt::time::FormatTime for SimStepTimeFormat {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        static EVENT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let event = EVENT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let step = turmoil::sim_elapsed().unwrap_or_default().as_millis();
        write!(w, "[s{step} e{event}]")
    }
}
