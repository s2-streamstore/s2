#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(author, version, about = "S2 Lite")]
struct Args {
    #[command(flatten)]
    lite: s2_lite::server::LiteArgs,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    s2_lite::server::run(args.lite).await
}
