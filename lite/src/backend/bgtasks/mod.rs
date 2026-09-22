use std::{error::Error, future::Future, pin::Pin, time::Duration};

use tokio::{sync::broadcast, time::Instant};
use tracing::{info, warn};

use crate::backend::Backend;

mod basin_deletion;
mod stream_doe;
mod stream_trim;

/// Keep draining the backlog while work completes. A page where every item
/// conflicts waits for the next tick instead of retrying in a tight loop.
#[derive(Default)]
struct PageProgress {
    has_more: bool,
    completed: bool,
}

impl PageProgress {
    fn record<T, E>(
        &mut self,
        result: Result<T, E>,
        is_conflict: fn(&E) -> bool,
    ) -> Result<Option<T>, E> {
        match result {
            Ok(value) => {
                self.completed = true;
                Ok(Some(value))
            }
            Err(err) if is_conflict(&err) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn should_continue(&self) -> bool {
        self.has_more && self.completed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BgtaskTrigger {
    BasinDeletion,
    StreamDeleteOnEmpty,
    StreamTrim,
}

pub fn spawn(backend: &Backend) {
    spawn_bgtask(
        "stream-trim",
        Duration::from_secs(60),
        &[BgtaskTrigger::StreamTrim],
        backend.bgtask_trigger_subscribe(),
        move |backend| backend.clone().tick_stream_trim(),
        backend.clone(),
    );
    spawn_bgtask(
        "stream-delete-on-empty",
        Duration::from_secs(60),
        &[BgtaskTrigger::StreamDeleteOnEmpty],
        backend.bgtask_trigger_subscribe(),
        move |backend| backend.clone().tick_stream_doe(),
        backend.clone(),
    );
    spawn_bgtask(
        "basin-deletion",
        Duration::from_secs(60),
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
        let sleep = tokio::time::sleep(jittered_delay(interval));
        tokio::pin!(sleep);
        let reset_sleep = |sleep: &mut Pin<&mut tokio::time::Sleep>| {
            sleep
                .as_mut()
                .reset(Instant::now() + jittered_delay(interval));
        };
        loop {
            tokio::select! {
                _ = &mut sleep => {
                    run_tick(name, &tick, &backend).await;
                    reset_sleep(&mut sleep);
                }
                res = trigger_rx.recv() => {
                    match res {
                        Ok(trigger)  => {
                            if triggers.contains(&trigger) {
                                run_tick(name, &tick, &backend).await;
                                reset_sleep(&mut sleep);
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(
                                task = name,
                                skipped,
                                "bgtask trigger channel lagged, running tick immediately"
                            );
                            run_tick(name, &tick, &backend).await;
                            reset_sleep(&mut sleep);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!(task = name, "bgtask trigger channel closed, exiting");
                            break;
                        }
                    }
                }
            }
        }
    });
}

fn jittered_delay(interval: Duration) -> Duration {
    if interval.is_zero() {
        return interval;
    }
    let max_jitter = interval / 10;
    let max_ms = max_jitter.as_millis() as i64;
    if max_ms == 0 {
        return interval;
    }
    let jitter_ms = rand::random_range(-max_ms..=max_ms);
    if jitter_ms >= 0 {
        interval + Duration::from_millis(jitter_ms as u64)
    } else {
        interval - Duration::from_millis((-jitter_ms) as u64)
    }
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
                warn!(task, %error, error_source = error.source().map(|s| s.to_string()), "bgtask tick failed");
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

    #[rstest::rstest]
    #[case::partial_page(false, 1, 2)]
    #[case::backlog(true, 3, 4)]
    #[tokio::test]
    async fn conflicts_drain_productive_pages_and_defer_unproductive_ones(
        #[case] has_more: bool,
        #[case] expected_calls: usize,
        #[case] expected_completed: usize,
    ) {
        use futures::{StreamExt, stream};

        use crate::backend::error::{
            DeleteStreamError, StreamDeleteOnEmptyError, TransactionConflictError,
        };

        let backend = test_backend().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let tick = {
            let calls = calls.clone();
            let completed = completed.clone();
            move |_backend: &Backend| {
                let calls = calls.clone();
                let completed = completed.clone();
                async move {
                    let page = calls.fetch_add(1, Ordering::SeqCst);
                    assert!(
                        page < 3,
                        "a fully conflicted page must wait for the next tick"
                    );
                    let mut progress = PageProgress {
                        has_more,
                        ..Default::default()
                    };
                    let mut results = stream::iter(0..3)
                        .map(|i| async move {
                            // Two mixed pages can make progress despite a
                            // recurring conflict. The third page cannot.
                            if i == 0 || page == 2 {
                                Err(StreamDeleteOnEmptyError::DeleteStream(
                                    DeleteStreamError::TransactionConflict(
                                        TransactionConflictError,
                                    ),
                                ))
                            } else {
                                tokio::task::yield_now().await;
                                Ok(())
                            }
                        })
                        .buffer_unordered(2);
                    while let Some(result) = results.next().await {
                        if progress
                            .record(result, StreamDeleteOnEmptyError::is_transaction_conflict)?
                            .is_some()
                        {
                            completed.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    Ok::<_, StreamDeleteOnEmptyError>(progress.should_continue())
                }
            }
        };
        run_tick("test", &tick, &backend).await;
        assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
        assert_eq!(completed.load(Ordering::SeqCst), expected_completed);
        backend.close().await.unwrap();
    }

    #[test]
    fn page_preserves_non_conflict_errors() {
        use crate::backend::error::StorageError;

        let mut progress = PageProgress {
            has_more: true,
            ..Default::default()
        };
        let error = StorageError::InvariantViolation("broken state".into());
        assert!(matches!(
            progress.record::<(), _>(Err(error), StorageError::is_transaction_conflict),
            Err(StorageError::InvariantViolation(_))
        ));
    }
}
