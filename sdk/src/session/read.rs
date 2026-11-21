use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use async_stream::{stream, try_stream};
use futures_util::{
    StreamExt,
    future::{FutureExt, Shared},
};
use s2_api::v1::stream::{ReadEnd, ReadStart};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout},
};
use tracing::debug;

use crate::{
    api::{ApiError, BasinClient, retry_builder},
    error::{AbortedError, ErrorContext, ReadSessionError, SessionClosedError, TimeoutError},
    reconnect::{AdvisedReconnects, ReconnectAdvice},
    retry::RetryBackoff,
    session::StreamHeaders,
    types::{
        AccessTokenMode, MeteredBytes, ReadBatch, ReadInput, ReadSessionConfig,
        ReadSessionRetryPolicy, StreamName, StreamPosition,
    },
};

#[derive(Debug, thiserror::Error)]
enum ReadSessionFailure {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    HeartbeatTimeout(#[from] TimeoutError),
}

impl ReadSessionFailure {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Api(err) => err.is_retryable(),
            Self::HeartbeatTimeout(_) => true,
        }
    }

    fn is_authentication_error(&self) -> bool {
        matches!(self, Self::Api(error) if error.is_authentication_error())
    }

    fn is_server_draining(&self) -> bool {
        matches!(self, Self::Api(error) if error.is_server_draining())
    }

    fn into_error(self, context: &ErrorContext) -> ReadSessionError {
        match self {
            Self::Api(error) => ReadSessionError::from(error).with_context(context),
            Self::HeartbeatTimeout(error) => ReadSessionError::Timeout(error).with_context(context),
        }
    }
}

/// The server heartbeats a tailing read session at a randomized gap of at most
/// 15 seconds (<https://s2.dev/docs/api/protocol#data-flow>), plus some buffer.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(20);

type InternalStreaming<R> =
    Pin<Box<dyn Send + futures_core::Stream<Item = Result<R, ReadSessionError>>>>;

/// An item from a single read connection.
enum ReadItem {
    Batch(ReadBatch),
    /// The server advised reconnecting and the response ended cleanly.
    ///
    /// Always the last item of a connection, emitted after the batch it rode
    /// in on, so the resume position already accounts for that batch.
    ReconnectAdvised,
}

type CaughtUpResult = Result<StreamPosition, ReadSessionError>;

#[derive(Clone)]
enum CaughtUpFuture {
    Pending {
        rx: Shared<oneshot::Receiver<CaughtUpResult>>,
        context: ErrorContext,
    },
    Ready(CaughtUpResult),
}

impl Future for CaughtUpFuture {
    type Output = CaughtUpResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Pending { rx, context } => match Pin::new(rx).poll(cx) {
                Poll::Ready(Ok(result)) => Poll::Ready(result),
                Poll::Ready(Err(_)) => Poll::Ready(Err(ReadSessionError::SessionClosed(
                    SessionClosedError::new(None, context.clone()),
                ))),
                Poll::Pending => Poll::Pending,
            },
            Self::Ready(result) => Poll::Ready(result.clone()),
        }
    }
}

struct CaughtUpState {
    /// Latest reported tail we've fully delivered, if currently caught up.
    tail: Option<StreamPosition>,
    /// Once set, the session has ended.
    terminal: bool,
    /// Fires the current caught-up future.
    tx: Option<oneshot::Sender<CaughtUpResult>>,
    /// The future handed out by `caught_up()`.
    future: CaughtUpFuture,
    context: ErrorContext,
}

impl CaughtUpState {
    fn new(context: ErrorContext) -> Self {
        let (tx, future) = pending_catch_up(context.clone());
        Self {
            tail: None,
            terminal: false,
            tx: Some(tx),
            future,
            context,
        }
    }

    fn is_caught_up(&self) -> bool {
        self.tail.is_some()
    }

    fn future(&self) -> CaughtUpFuture {
        self.future.clone()
    }

    fn set_behind(&mut self) {
        if self.terminal || self.tail.take().is_none() {
            return;
        }
        let (tx, future) = pending_catch_up(self.context.clone());
        self.tx = Some(tx);
        self.future = future;
    }

    fn set_caught_up(&mut self, tail: StreamPosition) {
        if self.terminal || self.tail == Some(tail) {
            return;
        }
        self.tail = Some(tail);
        self.complete(Ok(tail));
    }

    fn end(&mut self, error: Option<ReadSessionError>) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        if let Some(error) = error {
            self.tail = None;
            self.complete(Err(error));
        } else if self.tail.is_none() {
            self.complete(Err(ReadSessionError::SessionClosed(
                SessionClosedError::new(None, self.context.clone()),
            )));
        }
    }

    fn complete(&mut self, result: CaughtUpResult) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(result);
        } else {
            self.future = CaughtUpFuture::Ready(result);
        }
    }
}

fn pending_catch_up(context: ErrorContext) -> (oneshot::Sender<CaughtUpResult>, CaughtUpFuture) {
    let (tx, rx) = oneshot::channel();
    (
        tx,
        CaughtUpFuture::Pending {
            rx: rx.shared(),
            context,
        },
    )
}

struct ReadUpdate {
    batch: Option<ReadBatch>,
    caught_up_tail: Option<StreamPosition>,
    resume_seq_num: Option<u64>,
}

impl ReadUpdate {
    fn behind() -> Self {
        Self {
            batch: None,
            caught_up_tail: None,
            resume_seq_num: None,
        }
    }

    fn from_batch(batch: ReadBatch) -> Self {
        let resume_seq_num = resume_seq_num_after_batch(&batch);
        let caught_up_tail = batch.tail.filter(|tail| {
            batch.records.is_empty()
                || batch
                    .records
                    .last()
                    .is_some_and(|record| record.seq_num.checked_add(1) == Some(tail.seq_num))
        });

        Self {
            batch: (!batch.records.is_empty()).then_some(batch),
            caught_up_tail,
            resume_seq_num,
        }
    }
}

/// A continuous stream of read batches.
pub struct ReadSession {
    updates: InternalStreaming<ReadUpdate>,
    state: CaughtUpState,
    resume_seq_num: Option<u64>,
}

impl ReadSession {
    fn new(
        updates: InternalStreaming<ReadUpdate>,
        resume_seq_num: Option<u64>,
        context: ErrorContext,
    ) -> Self {
        Self {
            updates,
            state: CaughtUpState::new(context),
            resume_seq_num,
        }
    }

    /// Return the absolute sequence number from which the session would resume after a retry.
    ///
    /// An unclamped absolute starting sequence number is available immediately. A timestamp,
    /// tail-relative, or clamped start returns `None` until the session receives a record or a
    /// reported tail. The returned value is the sequence number of the next record the session
    /// expects. It advances as the session is polled.
    pub fn resume_seq_num(&self) -> Option<u64> {
        self.resume_seq_num
    }

    /// Return whether all records through the latest reported tail were delivered.
    ///
    /// A later batch that does not reach a reported tail or a reconnect resets it. Use
    /// [`S2Stream::check_tail`](crate::S2Stream::check_tail) for the current tail.
    pub fn is_caught_up(&self) -> bool {
        self.state.is_caught_up()
    }

    /// Return a future for the current or next caught-up tail.
    ///
    /// Continue polling the read session while awaiting this future; the future does not drive
    /// reads itself. It is ready immediately when the session is already caught up and remains
    /// pending across retries. Once it resolves, its returned tail never changes. If the session
    /// later falls behind, call `caught_up()` again to wait for the next catch-up. The future
    /// returns [`ReadSessionError`] if the session fails or closes before catching up.
    pub fn caught_up(
        &self,
    ) -> impl Future<Output = Result<StreamPosition, ReadSessionError>>
    + Clone
    + Send
    + Sync
    + Unpin
    + 'static {
        self.state.future()
    }
}

impl futures_core::Stream for ReadSession {
    type Item = Result<ReadBatch, ReadSessionError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.updates.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(update))) => {
                    if let Some(resume_seq_num) = update.resume_seq_num {
                        self.resume_seq_num = Some(resume_seq_num);
                    }
                    if let Some(tail) = update.caught_up_tail {
                        self.state.set_caught_up(tail);
                    } else {
                        self.state.set_behind();
                    }
                    if let Some(batch) = update.batch {
                        return Poll::Ready(Some(Ok(batch)));
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    self.state.end(Some(error.clone()));
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    self.state.end(None);
                    return Poll::Ready(None);
                }
            }
        }
    }
}

impl Drop for ReadSession {
    fn drop(&mut self) {
        self.state.end(None);
    }
}

pub async fn read_session(
    client: BasinClient,
    name: StreamName,
    headers: StreamHeaders,
    input: ReadInput,
    config: ReadSessionConfig,
) -> Result<ReadSession, ReadSessionError> {
    let context = ErrorContext::stream("read_session", client.name.as_ref(), name.as_ref(), true);
    let shutdown = client.shutdown_signal();
    let ReadInput {
        start,
        stop,
        stream_config: _,
    } = input;
    let mut start: ReadStart = start.into();
    let mut end: ReadEnd = stop.into();
    let retry_policy = config.retry_policy;
    let mut retry_backoff = retry_builder(&client.config.retry).build();
    let access_token_mode = client.config.access_token.mode();
    let baseline_wait = end.wait;
    let mut last_tail_at: Option<Instant> = None;
    let mut advised_reconnects = AdvisedReconnects::default();
    let initial_resume_seq_num = if start.clamp == Some(true) {
        None
    } else {
        start.seq_num
    };

    let mut retries_since_reset: u32 = 0;
    let mut initial_attempts: u32 = 0;
    let batches = loop {
        if shutdown.is_closed() {
            return Err(ReadSessionError::Aborted(AbortedError::new(
                "client closed",
                context.clone(),
            )));
        }
        end.wait = remaining_wait(baseline_wait, last_tail_at);
        let attempt_num = retries_since_reset + 1;
        let open_res = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                return Err(ReadSessionError::Aborted(AbortedError::new(
                    "client closed",
                    context.clone(),
                )));
            }
            res = session_inner(
                client.clone(),
                name.clone(),
                headers.clone(),
                start.clone(),
                end.clone(),
                ReconnectAdvice::default(),
                advised_reconnects,
                context.clone(),
                attempt_num,
            ) => res,
        };
        match open_res {
            Ok(batches) => {
                break batches;
            }
            Err(err) => {
                initial_attempts += 1;
                if let Some(backoff) =
                    retry_delay(&err, &mut retry_backoff, retry_policy, access_token_mode)
                {
                    retries_since_reset += 1;
                    let aborted = tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => true,
                        _ = tokio::time::sleep(backoff) => false,
                    };
                    if aborted {
                        return Err(ReadSessionError::Aborted(AbortedError::new(
                            "client closed",
                            context.clone(),
                        )));
                    }
                    continue;
                }
                return Err(err.into_error(&context.clone().with_attempts(initial_attempts)));
            }
        }
    };

    let stream_context = context.clone();
    let updates = Box::pin(stream! {
        let mut batches: Option<ReadItemStream> = Some(batches);
        let mut attempts: u32 = initial_attempts;
        let mut retries_since_reset: u32 = retries_since_reset;
        let mut made_progress_in_attempt = false;

        loop {
            if shutdown.is_closed() {
                yield Err(ReadSessionError::Aborted(AbortedError::new(
                    "client closed",
                    stream_context.clone(),
                )));
                break;
            }

            if batches.is_none() {
                end.wait = remaining_wait(baseline_wait, last_tail_at);
                let attempt_num = retries_since_reset + 1;
                let open_res = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        yield Err(ReadSessionError::Aborted(AbortedError::new(
                            "client closed",
                            stream_context.clone(),
                        )));
                        break;
                    }
                    res = session_inner(
                        client.clone(),
                        name.clone(),
                        headers.clone(),
                        start.clone(),
                        end.clone(),
                        ReconnectAdvice::default(),
                        advised_reconnects,
                        stream_context.clone(),
                        attempt_num,
                    ) => res,
                };
                match open_res {
                    Ok(b) => {
                        batches = Some(b);
                        made_progress_in_attempt = false;
                    }
                    Err(err) => {
                        attempts += 1;
                        if let Some(backoff) =
                            retry_delay(
                                &err,
                                &mut retry_backoff,
                                retry_policy,
                                access_token_mode,
                            )
                        {
                            retries_since_reset += 1;
                            let aborted = tokio::select! {
                                biased;
                                _ = shutdown.cancelled() => true,
                                _ = tokio::time::sleep(backoff) => false,
                            };
                            if aborted {
                                yield Err(ReadSessionError::Aborted(AbortedError::new(
                                    "client closed",
                                    stream_context.clone(),
                                )));
                                break;
                            }
                            continue;
                        }
                        yield Err(err.into_error(&stream_context.clone().with_attempts(attempts)));
                        break;
                    }
                }
            }

            let next_item = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    yield Err(ReadSessionError::Aborted(AbortedError::new(
                        "client closed",
                        stream_context.clone(),
                    )));
                    break;
                }
                item = batches
                    .as_mut()
                    .expect("batches should not be None")
                    .next() => item,
            };

            match next_item {
                Some(Ok(ReadItem::ReconnectAdvised)) => {
                    batches = None;
                    // The advised connection was already poisoned when the
                    // advice was first decoded; reconnecting dials a fresh
                    // one. Avoid a useless reconnect for a read that was
                    // already satisfied when the advice arrived.
                    if read_limits_exhausted(&end) {
                        break;
                    }
                    advised_reconnects.record();
                    debug!(
                        resume_seq_num = ?start.seq_num,
                        advised_reconnects = advised_reconnects.count(),
                        "reconnecting read session on server advice"
                    );
                    yield Ok(ReadUpdate::behind());
                    continue;
                }
                Some(Ok(ReadItem::Batch(batch))) => {
                    made_progress_in_attempt = true;
                    if retry_backoff.used() > 0 {
                        retry_backoff.reset();
                    }
                    retries_since_reset = 0;
                    attempts = 0;

                    if batch.tail.is_some() {
                        last_tail_at = Some(Instant::now());
                    }

                    update_resume_start(&mut start, &batch);
                    if let Some(count) = end.count.as_mut() {
                        *count = count.saturating_sub(batch.records.len() as u64)
                    }
                    if let Some(bytes) = end.bytes.as_mut() {
                        *bytes = bytes.saturating_sub(
                            batch
                                .records
                                .iter()
                                .map(|r| r.metered_bytes() as u64)
                                .sum::<u64>(),
                        )
                    }

                    yield Ok(ReadUpdate::from_batch(batch));
                }
                Some(Err(err)) => {
                    batches = None;
                    if err.is_server_draining() && read_limits_exhausted(&end) {
                        break;
                    }
                    if err.is_server_draining() && made_progress_in_attempt {
                        debug!(
                            resume_seq_num = ?start.seq_num,
                            "reconnecting read session while server drains"
                        );
                        yield Ok(ReadUpdate::behind());
                        continue;
                    }
                    attempts += 1;
                    if let Some(backoff) =
                        retry_delay(
                            &err,
                            &mut retry_backoff,
                            retry_policy,
                            access_token_mode,
                        )
                    {
                        retries_since_reset += 1;
                        yield Ok(ReadUpdate::behind());
                        let aborted = tokio::select! {
                            biased;
                            _ = shutdown.cancelled() => true,
                            _ = tokio::time::sleep(backoff) => false,
                        };
                        if aborted {
                            yield Err(ReadSessionError::Aborted(AbortedError::new(
                                "client closed",
                                stream_context.clone(),
                            )));
                            break;
                        }
                        continue;
                    }
                    yield Err(err.into_error(&stream_context.clone().with_attempts(attempts)));
                    break;
                }
                None => break,
            }
        }
    });
    Ok(ReadSession::new(updates, initial_resume_seq_num, context))
}

fn resume_seq_num_after_batch(batch: &ReadBatch) -> Option<u64> {
    batch
        .records
        .last()
        .map(|record| record.seq_num + 1)
        .or_else(|| batch.tail.as_ref().map(|tail| tail.seq_num))
}

/// Advance the absolute start used when reconnecting the read session.
///
/// An empty batch with a reported tail still resolves a relative or timestamp start. Anchoring it
/// prevents a reconnect from evaluating the original start against a newer tail.
fn update_resume_start(start: &mut ReadStart, batch: &ReadBatch) {
    if let Some(seq_num) = resume_seq_num_after_batch(batch) {
        *start = ReadStart {
            seq_num: Some(seq_num),
            timestamp: None,
            tail_offset: None,
            clamp: start.clamp,
        };
    }
}

#[allow(clippy::too_many_arguments)]
type ReadItemStream =
    Pin<Box<dyn Send + futures_core::Stream<Item = Result<ReadItem, ReadSessionFailure>>>>;

#[allow(clippy::too_many_arguments)]
async fn session_inner(
    client: BasinClient,
    name: StreamName,
    headers: StreamHeaders,
    start: ReadStart,
    end: ReadEnd,
    reconnect: ReconnectAdvice,
    advised_reconnects: AdvisedReconnects,
    context: ErrorContext,
    attempt: u32,
) -> Result<ReadItemStream, ReadSessionFailure> {
    let mut batches = client
        .read_session(
            &name,
            start,
            end,
            headers.encryption.as_ref(),
            headers.stream_config.as_ref(),
            reconnect.clone(),
            attempt,
        )
        .await?;

    let mut declined_advice = false;
    Ok(Box::pin(try_stream! {
        loop {
            match timeout(HEARTBEAT_TIMEOUT, batches.next()).await {
                Ok(Some(batch)) => {
                    yield ReadItem::Batch(ReadBatch::from_api(batch?));
                    if reconnect.is_advised() && !declined_advice {
                        if advised_reconnects.should_reconnect() {
                            yield ReadItem::ReconnectAdvised;
                            break;
                        }
                        declined_advice = true;
                    }
                }
                Ok(None) => break,
                Err(_) => Err(ReadSessionFailure::HeartbeatTimeout(TimeoutError::new(
                    "heartbeat timeout",
                    context.clone(),
                )))?,
            }
        }
    }))
}

/// Whether the read's `count` or `bytes` limit has been used up.
fn read_limits_exhausted(end: &ReadEnd) -> bool {
    end.count == Some(0) || end.bytes == Some(0)
}

/// Compute the remaining wait budget for a retry.
///
/// During catchup (tail not yet observed), the full wait is sent.
/// Once tailing, the wait budget is depleted based on time since
/// the last batch with tail info, which approximates how long the
/// server has been in its long polling state.
fn remaining_wait(baseline_wait: Option<u32>, last_tail_at: Option<Instant>) -> Option<u32> {
    baseline_wait.map(|w| match last_tail_at {
        Some(since) => w.saturating_sub(since.elapsed().as_secs() as u32),
        None => w,
    })
}

fn retry_delay(
    err: &ReadSessionFailure,
    backoffs: &mut RetryBackoff,
    retry_policy: ReadSessionRetryPolicy,
    access_token_mode: AccessTokenMode,
) -> Option<Duration> {
    let is_retryable =
        err.is_retryable() || (access_token_mode.is_refreshable() && err.is_authentication_error());
    if !is_retryable {
        debug!(
            %err,
            is_retryable = false,
            retries_exhausted = backoffs.is_exhausted(),
            "not retrying read session"
        );
        return None;
    }

    let backoff = match retry_policy {
        ReadSessionRetryPolicy::Budgeted => backoffs.next(),
        ReadSessionRetryPolicy::Unbounded => Some(backoffs.next_or_max()),
    };
    if let Some(backoff) = backoff {
        debug!(
            %err,
            ?backoff,
            ?retry_policy,
            num_retries_remaining = backoffs.remaining(),
            "retrying read session"
        );
        Some(backoff)
    } else {
        debug!(
            %err,
            is_retryable,
            retries_exhausted = backoffs.is_exhausted(),
            "not retrying read session"
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::{StreamExt, poll, stream};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::UnboundedReceiverStream;

    use super::*;
    use crate::types::{Header, SequencedRecord};

    fn position(seq_num: u64) -> StreamPosition {
        StreamPosition {
            seq_num,
            timestamp: seq_num,
        }
    }

    fn record(seq_num: u64, command: bool) -> SequencedRecord {
        SequencedRecord {
            seq_num,
            timestamp: seq_num,
            body: Bytes::new(),
            headers: if command {
                vec![Header::new("", "fence")]
            } else {
                Vec::new()
            },
        }
    }

    fn batch(records: Vec<SequencedRecord>, tail: Option<StreamPosition>) -> ReadBatch {
        ReadBatch { records, tail }
    }

    #[test]
    fn empty_tail_anchors_relative_resume_start() {
        let mut start = ReadStart {
            seq_num: None,
            timestamp: None,
            tail_offset: Some(0),
            clamp: Some(true),
        };

        update_resume_start(&mut start, &batch(Vec::new(), Some(position(42))));

        assert_eq!(start.seq_num, Some(42));
        assert_eq!(start.timestamp, None);
        assert_eq!(start.tail_offset, None);
        assert_eq!(start.clamp, Some(true));
    }

    fn test_session(
        updates: impl futures_core::Stream<Item = Result<ReadUpdate, ReadSessionError>> + Send + 'static,
    ) -> ReadSession {
        ReadSession::new(
            Box::pin(updates),
            None,
            ErrorContext::default().into_read_only(),
        )
    }

    #[tokio::test]
    async fn empty_tail_exposes_absolute_resume_seq_num() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut session = test_session(UnboundedReceiverStream::new(rx));

        assert_eq!(session.resume_seq_num(), None);
        tx.send(Ok(ReadUpdate::from_batch(batch(
            Vec::new(),
            Some(position(42)),
        ))))
        .unwrap();

        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);

        assert_eq!(session.resume_seq_num(), Some(42));
    }

    #[tokio::test]
    async fn caught_up_follows_delivery_and_pins_tail() {
        let tail = position(2);
        let mut session = test_session(stream::iter([
            Ok(ReadUpdate::from_batch(batch(
                vec![record(0, false), record(1, false)],
                Some(tail),
            ))),
            Ok(ReadUpdate::from_batch(batch(
                vec![record(2, false)],
                Some(position(5)),
            ))),
        ]));
        let caught_up = session.caught_up();
        let mut pending = Box::pin(caught_up.clone());

        assert!(poll!(pending.as_mut()).is_pending());
        assert!(!session.is_caught_up());

        let first = session.next().await.unwrap().unwrap();
        assert_eq!(first.records.len(), 2);
        assert!(session.is_caught_up());
        assert_eq!(session.resume_seq_num(), Some(2));
        let caught_up_while_caught = session.caught_up();

        session.next().await.unwrap().unwrap();
        assert!(!session.is_caught_up());
        assert_eq!(session.resume_seq_num(), Some(3));
        assert_eq!(caught_up.await.unwrap(), tail);
        assert_eq!(caught_up_while_caught.await.unwrap(), tail);
    }

    #[tokio::test]
    async fn heartbeat_waits_for_visible_batch() {
        let tail = position(2);
        let (tx, rx) = mpsc::unbounded_channel();
        let mut session = test_session(UnboundedReceiverStream::new(rx));
        let caught_up = session.caught_up();

        tx.send(Ok(ReadUpdate::from_batch(batch(
            vec![record(0, false), record(1, false)],
            None,
        ))))
        .unwrap();
        tx.send(Ok(ReadUpdate::from_batch(batch(Vec::new(), Some(tail)))))
            .unwrap();

        assert_eq!(session.next().await.unwrap().unwrap().records.len(), 2);
        assert!(!session.is_caught_up());

        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);
        assert!(session.is_caught_up());
        assert_eq!(caught_up.await.unwrap(), tail);
    }

    #[tokio::test]
    async fn unchanged_heartbeat_reuses_caught_up_future() {
        let tail = position(1);
        let (tx, rx) = mpsc::unbounded_channel();
        let mut session = test_session(UnboundedReceiverStream::new(rx));

        tx.send(Ok(ReadUpdate::from_batch(batch(
            vec![record(0, false)],
            Some(tail),
        ))))
        .unwrap();
        session.next().await.unwrap().unwrap();
        let caught_up = session.state.future();

        tx.send(Ok(ReadUpdate::from_batch(batch(Vec::new(), Some(tail)))))
            .unwrap();
        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);

        let CaughtUpFuture::Pending { rx: caught_up, .. } = caught_up else {
            panic!("initial caught-up future should use the pending epoch");
        };
        let CaughtUpFuture::Pending { rx: current, .. } = session.state.future() else {
            panic!("unchanged heartbeat should preserve the pending epoch");
        };
        assert!(caught_up.ptr_eq(&current));
    }

    #[tokio::test]
    async fn caught_up_wait_survives_retry() {
        let first_tail = position(1);
        let tail = position(3);
        let (tx, rx) = mpsc::unbounded_channel();
        let mut session = test_session(UnboundedReceiverStream::new(rx));

        tx.send(Ok(ReadUpdate::from_batch(batch(
            Vec::new(),
            Some(first_tail),
        ))))
        .unwrap();
        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);
        assert!(session.is_caught_up());

        tx.send(Ok(ReadUpdate::behind())).unwrap();
        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);
        assert!(!session.is_caught_up());
        let caught_up = session.caught_up();

        tx.send(Ok(ReadUpdate::behind())).unwrap();
        tx.send(Ok(ReadUpdate::from_batch(batch(Vec::new(), Some(tail)))))
            .unwrap();
        drop(tx);
        assert!(session.next().await.is_none());
        assert_eq!(caught_up.await.unwrap(), tail);
    }

    #[tokio::test]
    async fn clean_end_rejects_wait() {
        let mut session = test_session(stream::empty());
        let caught_up = session.caught_up();

        assert!(session.next().await.is_none());
        assert!(matches!(
            caught_up.await,
            Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
        ));
    }

    #[tokio::test]
    async fn read_error_rejects_wait() {
        let mut session = test_session(stream::iter([Err(ReadSessionError::Timeout(
            TimeoutError::new(
                "heartbeat timeout",
                ErrorContext::default().into_read_only(),
            ),
        ))]));
        let caught_up = session.caught_up();

        let error = session.next().await.unwrap().unwrap_err();
        assert!(error.to_string().contains("heartbeat timeout"));
        assert!(matches!(caught_up.await, Err(ReadSessionError::Timeout(_))));
    }

    #[tokio::test]
    async fn read_error_after_caught_up_preserves_resolved_future() {
        let tail = position(1);
        let mut session = test_session(stream::iter([
            Ok(ReadUpdate::from_batch(batch(
                vec![record(0, false)],
                Some(tail),
            ))),
            Err(ReadSessionError::Timeout(TimeoutError::new(
                "heartbeat timeout",
                ErrorContext::default().into_read_only(),
            ))),
        ]));

        session.next().await.unwrap().unwrap();
        assert!(session.is_caught_up());
        let caught_up = session.caught_up();

        session.next().await.unwrap().unwrap_err();
        assert!(!session.is_caught_up());
        assert_eq!(caught_up.await.unwrap(), tail);
        assert!(matches!(
            session.caught_up().await,
            Err(ReadSessionError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn dropping_session_rejects_wait() {
        let caught_up = {
            let session = test_session(stream::pending());
            session.caught_up()
        };

        assert!(matches!(
            caught_up.await,
            Err(ReadSessionError::SessionClosed(e)) if e.failure().is_none()
        ));
    }
}
