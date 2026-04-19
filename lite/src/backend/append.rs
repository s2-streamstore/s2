use std::{
    collections::VecDeque,
    ops::{DerefMut as _, Range, RangeTo},
    sync::Arc,
};

use futures::{Stream, StreamExt as _, future::OptionFuture, stream::FuturesOrdered};
use s2_common::{
    encryption::{EncryptionKey, EncryptionSpec},
    record::{SeqNum, StreamPosition},
    types::{
        basin::BasinName,
        stream::{AppendAck, AppendInput, StreamName},
    },
};
use tokio::sync::oneshot;

use super::{Backend, StreamHandle};
use crate::backend::error::{
    AppendError, AppendErrorInternal, StorageError, StreamerMissingInActionError,
};

impl Backend {
    pub async fn open_for_append(
        &self,
        basin: &BasinName,
        stream: &StreamName,
        encryption_key: Option<EncryptionKey>,
    ) -> Result<StreamHandle, AppendError> {
        self.stream_handle_with_auto_create::<AppendError>(
            basin,
            stream,
            |config| config.create_stream_on_append,
            |cipher| Ok(EncryptionSpec::resolve(cipher, encryption_key)?),
        )
        .await
    }
}

impl StreamHandle {
    pub async fn append(self, input: AppendInput) -> Result<AppendAck, AppendError> {
        let StreamHandle {
            backend,
            basin,
            stream,
            mut client,
            encryption,
            ..
        } = self;
        let input = input.encrypt(&encryption, client.stream_id().as_bytes());
        let ack = match client.clone().append_permit_owned(input.clone()).await {
            Ok(permit) => match permit.submit().await {
                Ok(ack) => ack,
                Err(AppendErrorInternal::StreamerMissingInActionError(_)) => {
                    refresh_append_streamer_client(&backend, &basin, &stream, &mut client).await?;
                    client.append_permit_owned(input).await?.submit().await?
                }
                Err(e) => Err(e)?,
            },
            Err(StreamerMissingInActionError) => {
                refresh_append_streamer_client(&backend, &basin, &stream, &mut client).await?;
                client.append_permit_owned(input).await?.submit().await?
            }
        };
        Ok(ack)
    }

    pub fn append_session<S>(self, inputs: S) -> impl Stream<Item = Result<AppendAck, AppendError>>
    where
        S: Stream<Item = AppendInput>,
    {
        let StreamHandle {
            backend,
            basin,
            stream,
            mut client,
            encryption,
            ..
        } = self;
        let stream_id = client.stream_id();
        let session = SessionHandle::new();
        async_stream::stream! {
            tokio::pin!(inputs);
            let mut pending_input = None;
            let mut permit_opt = None;
            let mut append_futs = FuturesOrdered::new();
            let mut inflight_inputs: VecDeque<AppendInput> = VecDeque::new();
            'session: loop {
                tokio::select! {
                    Some(input) = inputs.next(), if permit_opt.is_none() && pending_input.is_none() => {
                        if client.is_dead() {
                            if let Err(e) = refresh_append_streamer_client(&backend, &basin, &stream, &mut client).await {
                                yield Err(e);
                                break;
                            }
                        }
                        let encrypted = input.clone().encrypt(&encryption, stream_id.as_bytes());
                        pending_input = Some(input);
                        permit_opt = Some(Box::pin(client.clone().append_permit_owned(encrypted)));
                    }
                    Some(res) = OptionFuture::from(permit_opt.as_mut()) => {
                        permit_opt = None;
                        match res {
                            Ok(permit) => {
                                let input = pending_input.take().expect("permit must correspond to a pending input");
                                inflight_inputs.push_back(input);
                                append_futs.push_back(permit.submit_session(session.clone()));
                            }
                            Err(StreamerMissingInActionError) => {
                                if let Err(e) = refresh_append_streamer_client(&backend, &basin, &stream, &mut client).await {
                                    yield Err(e);
                                    break;
                                }
                                let input = pending_input.as_ref().expect("failed permit must preserve input").clone();
                                let encrypted = input.encrypt(&encryption, stream_id.as_bytes());
                                permit_opt = Some(Box::pin(client.clone().append_permit_owned(encrypted)));
                            }
                        }
                    }
                    Some(res) = append_futs.next(), if !append_futs.is_empty() => {
                        let input = inflight_inputs.pop_front().expect("inflight input for yielded submit");
                        match res {
                            Ok(ack) => {
                                yield Ok(ack);
                            }
                            Err(AppendErrorInternal::StreamerMissingInActionError(_)) => {
                                // Streamer died after permit acquisition but before the append
                                // was durably enqueued. Drain any remaining in-flight work in
                                // order, then resubmit the lost inputs against a fresh client.
                                let mut retry_inputs: VecDeque<AppendInput> = VecDeque::new();
                                retry_inputs.push_back(input);
                                while let Some(res) = append_futs.next().await {
                                    let input = inflight_inputs.pop_front().expect("inflight input for yielded submit");
                                    match res {
                                        Ok(ack) => yield Ok(ack),
                                        Err(AppendErrorInternal::StreamerMissingInActionError(_)) => {
                                            retry_inputs.push_back(input);
                                        }
                                        Err(e) => {
                                            yield Err(e.into());
                                            break 'session;
                                        }
                                    }
                                }
                                if let Some(permit_fut) = permit_opt.take() {
                                    let _ = permit_fut.await;
                                    let input = pending_input.take().expect("permit must correspond to pending input");
                                    retry_inputs.push_back(input);
                                }
                                if let Err(e) = refresh_append_streamer_client(&backend, &basin, &stream, &mut client).await {
                                    yield Err(e);
                                    break 'session;
                                }
                                for retry_input in retry_inputs {
                                    let encrypted = retry_input.clone().encrypt(&encryption, stream_id.as_bytes());
                                    let permit = match client.clone().append_permit_owned(encrypted).await {
                                        Ok(permit) => permit,
                                        Err(e) => {
                                            yield Err(e.into());
                                            break 'session;
                                        }
                                    };
                                    match permit.submit_session(session.clone()).await {
                                        Ok(ack) => yield Ok(ack),
                                        Err(e) => {
                                            yield Err(e.into());
                                            break 'session;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                yield Err(e.into());
                                break;
                            }
                        }
                    }
                    else => {
                        break;
                    }
                }
            }
        }
    }
}

async fn refresh_append_streamer_client(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    client: &mut super::streamer::StreamerClient,
) -> Result<(), AppendError> {
    *client = backend.streamer_client(basin, stream).await?;
    Ok(())
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
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
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
        // Lots of small appends could cause this,
        // as we bound only on total bytes not num batches.
        if self.queue.capacity() >= 4 * self.queue.len() {
            self.queue.shrink_to(self.queue.len() * 2);
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
