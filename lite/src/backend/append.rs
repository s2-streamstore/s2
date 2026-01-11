use std::{
    collections::VecDeque,
    ops::{DerefMut as _, Range, RangeTo},
    sync::Arc,
    time::Instant,
};

use futures::{FutureExt as _, Stream, StreamExt as _, stream::FuturesOrdered};
use s2_common::{
    record::{MeteredSize as _, SeqNum, StreamPosition},
    types::{
        basin::BasinName,
        stream::{AppendAck, AppendInput, StreamName},
    },
};
use tokio::sync::oneshot;

use super::Backend;
use crate::{
    backend::error::{AppendError, AppendErrorInternal, StorageError},
    metrics,
};

// N.B. Ultimately capped by streamer::MAX_INFLIGHT_APPENDS
const MAX_INFLIGHT_BATCHES: usize = 100;
const MAX_INFLIGHT_BYTES: usize = 10 * 1024 * 1024;

impl Backend {
    pub async fn append(
        &self,
        basin: BasinName,
        stream: StreamName,
        input: AppendInput,
    ) -> Result<AppendAck, AppendError> {
        metrics::observe_append_batch_size(input.records.metered_size(), input.records.len());
        let start = Instant::now();
        let client = self
            .streamer_client_with_auto_create::<AppendError>(&basin, &stream, |config| {
                config.create_stream_on_append
            })
            .await?;
        let ack = client.append(input, None).await?;
        metrics::observe_append_ack_latency(start.elapsed());
        Ok(ack)
    }

    pub async fn append_session(
        self,
        basin: BasinName,
        stream: StreamName,
        inputs: impl Stream<Item = AppendInput>,
    ) -> Result<impl Stream<Item = Result<AppendAck, AppendError>>, AppendError> {
        let client = self.streamer_client(&basin, &stream).await?;
        let session = SessionHandle::new();
        Ok(async_stream::stream! {
            tokio::pin!(inputs);
            let mut futs = FuturesOrdered::new();
            let mut inflight_bytes = 0;
            loop {
                tokio::select! {
                    Some(input) = inputs.next(), if (
                        futs.len() < MAX_INFLIGHT_BATCHES
                        && inflight_bytes <= MAX_INFLIGHT_BYTES
                    ) => {
                        let metered_size = input.records.metered_size();
                        metrics::observe_append_batch_size(input.records.len(), metered_size);
                        inflight_bytes += metered_size;
                        let start = Instant::now();
                        let fut = client
                            .append(input, Some(session.clone()))
                            .map(move |res| (metered_size, start, res));
                        futs.push_back(fut);
                    }
                    Some((metered_size, start, res)) = futs.next() => {
                        inflight_bytes -= metered_size;
                        if res.is_ok() {
                            metrics::observe_append_ack_latency(start.elapsed());
                        }
                        yield res.map_err(AppendError::from);
                    }
                    else => {
                        break;
                    }
                }
            }
        })
    }
}

#[derive(Debug)]
struct SessionState {
    last_ack_end: RangeTo<SeqNum>,
    poisoned: bool,
}

#[derive(Debug, Clone)]
pub struct SessionHandle(Arc<parking_lot::Mutex<SessionState>>);

impl SessionHandle {
    pub fn new() -> Self {
        Self(Arc::new(parking_lot::Mutex::new(SessionState {
            last_ack_end: ..SeqNum::MIN,
            poisoned: false,
        })))
    }
}

#[must_use]
pub fn admit(
    tx: oneshot::Sender<Result<AppendAck, AppendErrorInternal>>,
    session: Option<SessionHandle>,
) -> Option<Ticket> {
    if tx.is_closed() {
        return None;
    }
    match session {
        None => Some(Ticket { tx, session: None }),
        Some(session) => {
            let session = session.0.lock_arc();
            if session.poisoned {
                None
            } else {
                Some(Ticket {
                    tx,
                    session: Some(session),
                })
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct PendingAppends {
    queue: VecDeque<BlockedReplySender>,
    next_ack_pos: Option<StreamPosition>,
}

impl PendingAppends {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            next_ack_pos: None,
        }
    }

    pub fn next_ack_pos(&self) -> Option<StreamPosition> {
        self.next_ack_pos
    }

    pub fn accept(&mut self, ticket: Ticket, ack_range: Range<StreamPosition>) {
        if let Some(prev_pos) = self.next_ack_pos.replace(StreamPosition {
            seq_num: ack_range.end.seq_num,
            timestamp: ack_range.end.timestamp,
        }) {
            assert_eq!(ack_range.start.seq_num, prev_pos.seq_num);
            assert!(ack_range.start.timestamp >= prev_pos.timestamp);
        }
        let sender = ticket.accept(ack_range);
        if let Some(prev) = self.queue.back() {
            assert!(prev.durability_dependency.end < sender.durability_dependency.end);
        }
        self.queue.push_back(sender);
    }

    pub fn reject(&mut self, ticket: Ticket, err: AppendErrorInternal, stable_pos: StreamPosition) {
        if let Some(sender) = ticket.reject(err, stable_pos) {
            let dd = sender.durability_dependency;
            let insert_pos = self
                .queue
                .partition_point(|x| x.durability_dependency.end <= dd.end);
            self.queue.insert(insert_pos, sender);
        }
    }

    pub fn on_stable(&mut self, stable_pos: StreamPosition) {
        let completable = self
            .queue
            .iter()
            .take_while(|sender| sender.durability_dependency.end <= stable_pos.seq_num)
            .count();
        for sender in self.queue.drain(..completable) {
            sender.unblock(Ok(stable_pos));
        }
    }

    pub fn on_durability_failed(self, err: slatedb::Error) {
        let err = StorageError::from(err);
        for sender in self.queue {
            sender.unblock(Err(err.clone()));
        }
    }
}

pub struct Ticket {
    tx: oneshot::Sender<Result<AppendAck, AppendErrorInternal>>,
    session: Option<parking_lot::ArcMutexGuard<parking_lot::RawMutex, SessionState>>,
}

impl Ticket {
    #[must_use]
    fn accept(self, ack_range: Range<StreamPosition>) -> BlockedReplySender {
        let durability_dependency = ..ack_range.end.seq_num;
        if let Some(mut session) = self.session {
            let session = session.deref_mut();
            assert!(!session.poisoned, "thanks to typestate");
            session.last_ack_end = durability_dependency;
        }
        BlockedReplySender {
            reply: Ok(ack_range),
            durability_dependency,
            tx: self.tx,
        }
    }

    #[must_use]
    fn reject(
        self,
        append_err: AppendErrorInternal,
        stable_pos: StreamPosition,
    ) -> Option<BlockedReplySender> {
        let mut durability_dependency =
            if let AppendErrorInternal::ConditionFailed(cond_fail) = &append_err {
                cond_fail.durability_dependency()
            } else {
                ..0
            };
        if let Some(mut session) = self.session {
            let session = session.deref_mut();
            assert!(!session.poisoned, "thanks to typestate");
            session.poisoned = true;
            durability_dependency = ..durability_dependency.end.max(session.last_ack_end.end);
        }
        if durability_dependency.end <= stable_pos.seq_num {
            let _ = self.tx.send(Err(append_err));
            None
        } else {
            Some(BlockedReplySender {
                reply: Err(append_err),
                durability_dependency,
                tx: self.tx,
            })
        }
    }
}

#[derive(Debug)]
struct BlockedReplySender {
    reply: Result<Range<StreamPosition>, AppendErrorInternal>,
    durability_dependency: RangeTo<SeqNum>,
    tx: oneshot::Sender<Result<AppendAck, AppendErrorInternal>>,
}

impl BlockedReplySender {
    fn unblock(self, stable_pos: Result<StreamPosition, StorageError>) {
        let reply = match stable_pos {
            Ok(tail) => {
                assert!(self.durability_dependency.end <= tail.seq_num);
                self.reply.map(|ack| AppendAck {
                    start: ack.start,
                    end: ack.end,
                    tail,
                })
            }
            Err(e) => Err(e.into()),
        };
        let _ = self.tx.send(reply);
    }
}
