//! Collection of operation histories for offline linearizability checking.

use std::{
    fs::File,
    io::{BufWriter, Write as _},
    path::PathBuf,
};

use s2_verification::history::LabeledEvent;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::info;

/// Drain all buffered events and write them as JSONL to `history.<seed>.jsonl`
/// in the current directory.
///
/// Call after the simulation has completed: every sender has hung up by then,
/// so everything the workload emitted is sitting in the channel.
pub fn save(rx: &mut UnboundedReceiver<LabeledEvent>, seed: u64) -> eyre::Result<PathBuf> {
    let path = PathBuf::from(format!("history.{seed}.jsonl"));
    let mut file = BufWriter::new(File::create(&path)?);
    let mut events = 0u64;
    while let Ok(event) = rx.try_recv() {
        serde_json::to_writer(&mut file, &event)?;
        file.write_all(b"\n")?;
        events += 1;
    }
    file.flush()?;
    info!(events, path = %path.display(), "history saved");
    Ok(path)
}
