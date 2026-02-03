use std::{error::Error, future::Future, time::Duration};

use tokio::sync::broadcast;
use tracing::warn;

use crate::backend::Backend;

mod basin_deletion;
mod stream_trim;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BgtaskTrigger {
    BasinDeletion,
    StreamTrim,
}

pub fn spawn(backend: &Backend) {
    spawn_bgtask(
        "stream-trim",
        Duration::from_secs(30),
        &[BgtaskTrigger::StreamTrim],
        backend.bgtask_trigger_subscribe(),
        move |backend| backend.clone().tick_stream_trim(),
        backend.clone(),
    );
    spawn_bgtask(
        "basin-deletion",
        Duration::from_secs(30),
        &[BgtaskTrigger::BasinDeletion],
        backend.bgtask_trigger_subscribe(),
        move |backend| backend.clone().tick_basin_deletion(),
        backend.clone(),
    );
}

fn spawn_bgtask<Tick, Fut, E>(
    name: &'static str,
    interval: Duration,
    triggers: &'static [BgtaskTrigger],
    mut trigger_rx: broadcast::Receiver<BgtaskTrigger>,
    tick: Tick,
    backend: Backend,
) where
    Tick: Fn(&Backend) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<bool, E>> + Send,
    E: Error + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    run_tick(name, &tick, &backend).await;
                }
                res = trigger_rx.recv() => {
                    match res {
                        Ok(trigger)  => {
                            if triggers.contains(&trigger) {
                                run_tick(name, &tick, &backend).await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }
    });
}

async fn run_tick<Tick, Fut, E>(task: &'static str, tick: &Tick, backend: &Backend)
where
    Tick: Fn(&Backend) -> Fut + Send + Sync,
    Fut: Future<Output = Result<bool, E>> + Send,
    E: Error + Send + Sync,
{
    loop {
        match tick(backend).await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(error) => {
                warn!(task, %error, "bgtask tick failed");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use bytesize::ByteSize;
    use slatedb::object_store::memory::InMemory;

    use super::*;

    pub(super) async fn test_backend() -> Backend {
        let object_store = Arc::new(InMemory::new());
        let db = slatedb::Db::builder("/test", object_store)
            .build()
            .await
            .unwrap();
        Backend::new(db, ByteSize::mib(10))
    }

    #[tokio::test]
    async fn run_tick_repeats_until_done() {
        let backend = test_backend().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let tick = {
            let calls = Arc::clone(&calls);
            move |_backend: &Backend| {
                let calls = Arc::clone(&calls);
                async move {
                    let count = calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<bool, std::io::Error>(count < 2)
                }
            }
        };

        run_tick("test", &tick, &backend).await;

        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
