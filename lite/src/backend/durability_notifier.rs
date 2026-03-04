use std::{collections::VecDeque, sync::Arc};

use parking_lot::Mutex;
use slatedb::{CloseReason, DbStatus};
use tokio::sync::watch;

type Callback = Box<dyn FnOnce(Result<u64, CloseReason>) + Send + 'static>;

#[derive(Clone)]
pub(super) struct DurabilityNotifier {
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    closed_reason: Option<CloseReason>,
    last_durable_seq: u64,
    waiters: VecDeque<Waiter>,
}

struct Waiter {
    durable_seq: u64,
    callback: Callback,
}

fn waiters_are_sorted(waiters: &VecDeque<Waiter>) -> bool {
    let mut prev = None;
    for waiter in waiters {
        if let Some(prev_target) = prev
            && prev_target > waiter.durable_seq
        {
            return false;
        }
        prev = Some(waiter.durable_seq);
    }
    true
}

impl DurabilityNotifier {
    pub fn spawn(db: &slatedb::Db) -> Self {
        let status_rx = db.subscribe();
        let initial_durable_seq = status_rx.borrow().durable_seq;
        let state = Arc::new(Mutex::new(State {
            closed_reason: None,
            last_durable_seq: initial_durable_seq,
            waiters: VecDeque::new(),
        }));
        tokio::spawn(run_notifier(status_rx, state.clone()));
        Self { state }
    }

    pub fn subscribe(
        &self,
        target_durable_seq: u64,
        callback: impl FnOnce(Result<u64, CloseReason>) + Send + 'static,
    ) {
        let mut state = self.state.lock();
        if let Some(reason) = state.closed_reason {
            drop(state);
            callback(Err(reason));
            return;
        }
        if state.last_durable_seq >= target_durable_seq {
            let durable_seq = state.last_durable_seq;
            drop(state);
            callback(Ok(durable_seq));
            return;
        }
        let waiter = Waiter {
            durable_seq: target_durable_seq,
            callback: Box::new(callback),
        };
        let insert_pos = state
            .waiters
            .iter()
            .rposition(|w| w.durable_seq <= target_durable_seq)
            .map_or(0, |idx| idx + 1);
        state.waiters.insert(insert_pos, waiter);
        debug_assert!(waiters_are_sorted(&state.waiters));
    }
}

async fn run_notifier(mut status_rx: watch::Receiver<DbStatus>, state: Arc<Mutex<State>>) {
    loop {
        if status_rx.changed().await.is_err() {
            close_with_reason(state.as_ref(), CloseReason::Clean);
            return;
        }
        let status = status_rx.borrow().clone();
        notify_waiters(state.as_ref(), status.durable_seq);
        if let Some(close_reason) = status.close_reason {
            close_with_reason(state.as_ref(), close_reason);
            return;
        }
    }
}

fn notify_waiters(state: &Mutex<State>, durable_seq: u64) {
    let ready = {
        let mut state = state.lock();
        if durable_seq <= state.last_durable_seq {
            return;
        }
        state.last_durable_seq = durable_seq;
        debug_assert!(waiters_are_sorted(&state.waiters));
        let split = state
            .waiters
            .partition_point(|w| w.durable_seq <= durable_seq);
        state.waiters.drain(..split).collect::<Vec<_>>()
    };
    for waiter in ready {
        (waiter.callback)(Ok(durable_seq));
    }
}

fn close_with_reason(state: &Mutex<State>, reason: CloseReason) {
    let pending = {
        let mut state = state.lock();
        let prev = state.closed_reason.replace(reason);
        assert!(prev.is_none());
        std::mem::take(&mut state.waiters)
    };
    for waiter in pending {
        (waiter.callback)(Err(reason));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            mpsc::{self, TryRecvError},
        },
        time::Duration,
    };

    use super::*;

    fn test_notifier(last_durable_seq: u64) -> DurabilityNotifier {
        DurabilityNotifier {
            state: Arc::new(Mutex::new(State {
                closed_reason: None,
                last_durable_seq,
                waiters: VecDeque::new(),
            })),
        }
    }

    #[test]
    fn subscribe_immediate_when_target_already_durable() {
        let notifier = test_notifier(42);
        let (tx, rx) = mpsc::channel();
        notifier.subscribe(7, move |res| {
            tx.send(res).expect("send callback result");
        });
        let res = rx
            .recv_timeout(Duration::from_millis(100))
            .expect("callback should run");
        assert_eq!(res.expect("durable result"), 42);
        assert!(notifier.state.lock().waiters.is_empty());
    }

    #[test]
    fn notify_waiters_releases_only_ready_targets() {
        let state = Arc::new(Mutex::new(State {
            closed_reason: None,
            last_durable_seq: 0,
            waiters: VecDeque::new(),
        }));

        let (tx5, rx5) = mpsc::channel();
        state.lock().waiters.push_back(Waiter {
            durable_seq: 5,
            callback: Box::new(move |res| {
                tx5.send(res).expect("send callback result");
            }),
        });

        let (tx8, rx8) = mpsc::channel();
        state.lock().waiters.push_back(Waiter {
            durable_seq: 8,
            callback: Box::new(move |res| {
                tx8.send(res).expect("send callback result");
            }),
        });

        notify_waiters(state.as_ref(), 5);

        let res5 = rx5
            .recv_timeout(Duration::from_millis(100))
            .expect("ready waiter should run");
        assert_eq!(res5.expect("durable result"), 5);
        assert!(matches!(rx8.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(
            state
                .lock()
                .waiters
                .iter()
                .map(|w| w.durable_seq)
                .collect::<Vec<_>>(),
            vec![8]
        );
    }

    #[test]
    fn waiters_are_kept_sorted_when_insertions_arrive_out_of_order() {
        let notifier = test_notifier(0);

        notifier.subscribe(10, |_| {});
        notifier.subscribe(5, |_| {});
        notifier.subscribe(7, |_| {});

        assert_eq!(
            notifier
                .state
                .lock()
                .waiters
                .iter()
                .map(|w| w.durable_seq)
                .collect::<Vec<_>>(),
            vec![5, 7, 10]
        );
    }

    #[test]
    fn close_with_reason_fails_all_pending_waiters() {
        let state = Arc::new(Mutex::new(State {
            closed_reason: None,
            last_durable_seq: 0,
            waiters: VecDeque::new(),
        }));

        let (tx5, rx5) = mpsc::channel();
        state.lock().waiters.push_back(Waiter {
            durable_seq: 5,
            callback: Box::new(move |res| {
                tx5.send(res).expect("send callback result");
            }),
        });

        let (tx8, rx8) = mpsc::channel();
        state.lock().waiters.push_back(Waiter {
            durable_seq: 8,
            callback: Box::new(move |res| {
                tx8.send(res).expect("send callback result");
            }),
        });

        close_with_reason(state.as_ref(), CloseReason::Clean);

        let err5 = rx5
            .recv_timeout(Duration::from_millis(100))
            .expect("callback should run")
            .expect_err("close should fail waiter");
        let err8 = rx8
            .recv_timeout(Duration::from_millis(100))
            .expect("callback should run")
            .expect_err("close should fail waiter");
        assert_eq!(err5, CloseReason::Clean);
        assert_eq!(err8, CloseReason::Clean);
        let state = state.lock();
        assert!(state.waiters.is_empty());
        assert_eq!(state.closed_reason, Some(CloseReason::Clean));
    }

    #[test]
    fn subscribe_after_close_returns_error_immediately() {
        let notifier = test_notifier(0);
        close_with_reason(notifier.state.as_ref(), CloseReason::Clean);

        let (tx, rx) = mpsc::channel();
        notifier.subscribe(1, move |res| {
            tx.send(res).expect("send callback result");
        });

        let err = rx
            .recv_timeout(Duration::from_millis(100))
            .expect("callback should run")
            .expect_err("closed notifier should fail immediately");
        assert_eq!(err, CloseReason::Clean);
        assert!(notifier.state.lock().waiters.is_empty());
    }
}
