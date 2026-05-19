use std::{error::Error, future::Future, pin::Pin, time::Duration};

use tokio::{sync::broadcast, time::Instant};
use tracing::warn;

use crate::backend::Backend;

mod basin_deletion;
mod stream_doe;
mod stream_trim;

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
                warn!(task, %error, "bgtask tick failed");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fmt,
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use bytesize::ByteSize;
    use chrono::{DateTime, Utc};
    use slatedb::object_store::memory::InMemory;
    use slatedb_common::{DefaultSystemClock, SystemClock, SystemClockTicker};

    use super::*;

    pub(super) struct FixedCreateTsClock {
        create_ts: DateTime<Utc>,
        sleep_clock: DefaultSystemClock,
    }

    impl FixedCreateTsClock {
        pub(super) fn new(create_ts_millis: i64) -> Self {
            Self {
                create_ts: DateTime::from_timestamp_millis(create_ts_millis)
                    .expect("valid test timestamp"),
                sleep_clock: DefaultSystemClock::new(),
            }
        }
    }

    impl fmt::Debug for FixedCreateTsClock {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("FixedCreateTsClock")
                .field("create_ts", &self.create_ts)
                .finish_non_exhaustive()
        }
    }

    impl SystemClock for FixedCreateTsClock {
        fn now(&self) -> DateTime<Utc> {
            self.create_ts
        }

        fn sleep<'a>(
            &'a self,
            duration: Duration,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            self.sleep_clock.sleep(duration)
        }

        fn ticker<'a>(&'a self, duration: Duration) -> SystemClockTicker<'a> {
            SystemClockTicker::new(self, duration)
        }
    }

    pub(super) async fn test_backend() -> Backend {
        let object_store = Arc::new(InMemory::new());
        let db = slatedb::Db::builder("/test", object_store)
            .build()
            .await
            .unwrap();
        Backend::new(db, ByteSize::mib(10))
    }

    pub(super) async fn test_backend_with_create_ts(create_ts_millis: i64) -> Backend {
        let object_store = Arc::new(InMemory::new());
        let db = slatedb::Db::builder("/test", object_store)
            .with_system_clock(Arc::new(FixedCreateTsClock::new(create_ts_millis)))
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
