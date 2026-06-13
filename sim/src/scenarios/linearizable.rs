//! Concurrent clients recording an operation history for linearizability
//! checking.
//!
//! The workload logic lives in `s2_verification::history`: each logical client
//! randomly mixes appends, reads, and check-tails against one stream, emitting
//! a `LabeledEvent` at every operation start and finish. Appends that fail
//! *indefinitely* (the client cannot know whether the records became durable)
//! are deferred and flushed only after all clients finish — the checker treats
//! them as "may or may not have happened".
//!
//! The resulting `history.<seed>.jsonl` is verified offline by the Porcupine
//! model in s2-verification (`s2-porcupine -file=...`).

use std::sync::{Arc, atomic::AtomicU64};

use s2_verification::history::{LabeledEvent, client, fencing_token_client, match_seq_num_client};
use tokio::sync::{Barrier, mpsc::UnboundedSender};
use tracing::info;

#[derive(clap::Args, Debug, Clone)]
pub struct Config {
    /// Number of concurrent logical clients.
    #[arg(long, default_value_t = 3)]
    pub clients: usize,

    /// Operations attempted per client.
    #[arg(long, default_value_t = 50)]
    pub ops_per_client: usize,
}

pub async fn workload(
    config: Config,
    history_tx: UnboundedSender<LabeledEvent>,
) -> turmoil::Result {
    let stream = super::provision_stream().await.map_err(|e| e.to_string())?;
    info!(basin = super::BASIN, stream = super::STREAM, "provisioned");

    let client_ids = Arc::new(AtomicU64::new(0));
    let op_ids = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(config.clients));

    let mut tasks = Vec::new();
    for i in 0..config.clients {
        let stream = stream.clone();
        let client_ids = client_ids.clone();
        let op_ids = op_ids.clone();
        let history_tx = history_tx.clone();
        let barrier = barrier.clone();
        let num_ops = config.ops_per_client;
        tasks.push(tokio::spawn(async move {
            let tx = history_tx.clone();
            let deferred = match i % 3 {
                0 => client(num_ops, stream, client_ids, op_ids, tx).await,
                1 => match_seq_num_client(num_ops, stream, client_ids, op_ids, tx).await,
                _ => fencing_token_client(num_ops, stream, client_ids, op_ids, tx).await,
            }
            .map_err(|e| e.to_string())?;
            info!(task = i, deferred = deferred.len(), "client workflow done");

            // Hold deferred (indefinite-failure) events until every client is
            // done issuing operations, so they land at the end of the history.
            barrier.wait().await;
            for event in deferred {
                history_tx.send(event).map_err(|e| e.to_string())?;
            }
            Ok::<_, String>(())
        }));
    }

    for task in tasks {
        task.await??;
    }
    Ok(())
}
