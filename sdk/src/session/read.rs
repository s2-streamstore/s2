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
    error::{ReadError, RequestError},
    reconnect::{
        ADVICE_STREAK_WINDOW, ADVISED_RECONNECT_DELAY, MAX_IMMEDIATE_ADVISED_RECONNECTS,
        ReconnectAdvice,
    },
    retry::RetryBackoff,
    types::{
        AccessTokenMode, EncryptionKey, MeteredBytes, ReadBatch, ReadInput, ReadSessionConfig,
        ReadSessionRetryPolicy, StreamName, StreamPosition,
    },
};

#[derive(Debug, thiserror::Error)]
enum ReadSessionFailure {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("heartbeat timeout")]
    HeartbeatTimeout,
}

impl ReadSessionFailure {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Api(err) => err.is_retryable(),
            Self::HeartbeatTimeout => true,
        }
    }

    fn is_authentication_error(&self) -> bool {
        matches!(self, Self::Api(error) if error.is_authentication_error())
    }
}

/// Errors returned by a read session.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ReadSessionError {
    /// An error with the read request underlying the session.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// The session heartbeat timed out.
    #[error("heartbeat timeout")]
    HeartbeatTimeout,
}

impl ReadSessionError {
    /// Whether retrying the operation is safe or sensible.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Read(error) => error.is_retryable(),
            Self::HeartbeatTimeout => true,
        }
    }

    /// Return the underlying request error, if present.
    pub fn request_error(&self) -> Option<&RequestError> {
        match self {
            Self::Read(error) => error.request_error(),
            Self::HeartbeatTimeout => None,
        }
    }
}

impl From<ReadSessionFailure> for ReadSessionError {
    fn from(error: ReadSessionFailure) -> Self {
        match error {
            ReadSessionFailure::Api(error) => Self::Read(error.into()),
            ReadSessionFailure::HeartbeatTimeout => Self::HeartbeatTimeout,
        }
    }
}

/// The server heartbeats a tailing read session at a randomized gap of at most
/// 15 seconds (<https://s2.dev/docs/api/protocol#data-flow>), plus some buffer.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(20);

type InternalStreaming<R> =
    Pin<Box<dyn Send + futures_core::Stream<Item = Result<R, ReadSessionFailure>>>>;

/// An item from a single read connection.
enum ReadItem {
    Batch(ReadBatch),
    /// The server advised reconnecting and the response ended cleanly.
    ///
    /// Always the last item of a connection, emitted after the batch it rode
    /// in on, so the resume position already accounts for that batch.
    ReconnectAdvised,
}

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
/// Error returned while waiting for a read session to catch up.
pub enum CaughtUpError {
    #[error("read session ended before catching up")]
    /// The session ended before reaching a reported tail.
    SessionClosed,
    #[error(transparent)]
    /// The read failed.
    Read(#[from] ReadSessionError),
}

impl CaughtUpError {
    /// Whether retrying the operation is safe or sensible.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::SessionClosed => false,
            Self::Read(error) => error.is_retryable(),
        }
    }

    /// Return the underlying request error, if present.
    pub fn request_error(&self) -> Option<&RequestError> {
        match self {
            Self::SessionClosed => None,
            Self::Read(error) => error.request_error(),
        }
    }
}

type CaughtUpResult = Result<StreamPosition, CaughtUpError>;

#[derive(Clone)]
enum CaughtUpFuture {
    Pending(Shared<oneshot::Receiver<CaughtUpResult>>),
    Ready(CaughtUpResult),
}

impl Future for CaughtUpFuture {
    type Output = CaughtUpResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Pending(future) => match Pin::new(future).poll(cx) {
                Poll::Ready(Ok(result)) => Poll::Ready(result),
                Poll::Ready(Err(_)) => Poll::Ready(Err(CaughtUpError::SessionClosed)),
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
}

impl CaughtUpState {
    fn new() -> Self {
        let (tx, future) = pending_catch_up();
        Self {
            tail: None,
            terminal: false,
            tx: Some(tx),
            future,
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
        let (tx, future) = pending_catch_up();
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
            self.complete(Err(CaughtUpError::Read(error)));
        } else if self.tail.is_none() {
            self.complete(Err(CaughtUpError::SessionClosed));
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

fn pending_catch_up() -> (oneshot::Sender<CaughtUpResult>, CaughtUpFuture) {
    let (tx, rx) = oneshot::channel();
    (tx, CaughtUpFuture::Pending(rx.shared()))
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

    fn from_batch(mut batch: ReadBatch, ignore_command_records: bool) -> Self {
        let resume_seq_num = resume_seq_num_after_batch(&batch);
        let caught_up_tail = batch.tail.filter(|tail| {
            batch.records.is_empty()
                || batch
                    .records
                    .last()
                    .is_some_and(|record| record.seq_num.checked_add(1) == Some(tail.seq_num))
        });

        if ignore_command_records {
            batch.records.retain(|record| !record.is_command_record());
        }

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
    fn new(updates: InternalStreaming<ReadUpdate>, resume_seq_num: Option<u64>) -> Self {
        Self {
            updates,
            state: CaughtUpState::new(),
            resume_seq_num,
        }
    }

    /// Return the absolute sequence number from which the session would resume after a retry.
    ///
    /// An unclamped absolute starting sequence number is available immediately. A timestamp,
    /// tail-relative, or clamped start returns `None` until the session receives a record or a
    /// reported tail. The returned value is the sequence number of the next record the session
    /// expects. It advances as the session is polled, including across records hidden by
    /// [`ReadInput::ignore_command_records`](crate::types::ReadInput::ignore_command_records).
    pub fn resume_seq_num(&self) -> Option<u64> {
        self.resume_seq_num
    }

    /// Return whether all records through the latest reported tail were delivered.
    ///
    /// A later batch that does not reach a reported tail or a reconnect resets it.
    /// Ignored command records count toward progress. Use
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
    /// returns [`CaughtUpError`] if the session fails or closes before catching up.
    pub fn caught_up(
        &self,
    ) -> impl Future<Output = Result<StreamPosition, CaughtUpError>>
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
                    let error = ReadSessionError::from(error);
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
    encryption: Option<EncryptionKey>,
    input: ReadInput,
    config: ReadSessionConfig,
) -> Result<ReadSession, ReadSessionError> {
    let ReadInput {
        start,
        stop,
        ignore_command_records,
    } = input;
    let mut start: ReadStart = start.into();
    let mut end: ReadEnd = stop.into();
    let retry_policy = config.retry_policy;
    let mut retry_backoff = retry_builder(&client.config.retry).build();
    let access_token_mode = client.config.access_token.mode();
    let baseline_wait = end.wait;
    let mut last_tail_at: Option<Instant> = None;
    let initial_resume_seq_num = if start.clamp == Some(true) {
        None
    } else {
        start.seq_num
    };

    let batches = loop {
        end.wait = remaining_wait(baseline_wait, last_tail_at);
        match session_inner(
            client.clone(),
            name.clone(),
            encryption.clone(),
            start.clone(),
            end.clone(),
            ReconnectAdvice::default(),
        )
        .await
        {
            Ok(batches) => {
                retry_backoff.reset();
                break batches;
            }
            Err(err) => {
                if let Some(backoff) =
                    retry_delay(&err, &mut retry_backoff, retry_policy, access_token_mode)
                {
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                return Err(err.into());
            }
        }
    };

    let updates = Box::pin(stream! {
        let mut batches: Option<InternalStreaming<ReadItem>> = Some(batches);
        let mut advised_reconnect_streak = 0;
        let mut last_advised_reconnect: Option<Instant> = None;

        loop {
            if batches.is_none() {
                end.wait = remaining_wait(baseline_wait, last_tail_at);
                match session_inner(
                    client.clone(),
                    name.clone(),
                    encryption.clone(),
                    start.clone(),
                    end.clone(),
                    ReconnectAdvice::default(),
                ).await {
                    Ok(b) => batches = Some(b),
                    Err(err) => {
                        if let Some(backoff) =
                            retry_delay(
                                &err,
                                &mut retry_backoff,
                                retry_policy,
                                access_token_mode,
                            )
                        {
                            tokio::time::sleep(backoff).await;
                            continue;
                        }
                        yield Err(err);
                        break;
                    }
                }
            }

            match batches
                .as_mut()
                .expect("batches should not be None")
                .next()
                .await
            {
                Some(Ok(ReadItem::ReconnectAdvised)) => {
                    batches = None;
                    // Avoid a useless reconnect for a read that was already
                    // satisfied when the advice arrived.
                    if read_limits_exhausted(&end) {
                        break;
                    }
                    // A new session over a pooled connection would land back on
                    // the draining server, so force a fresh connection first.
                    client.rotate_transport().await;
                    // A drain keeps serving batches, so progress cannot tell a
                    // storm from an ordinary handover. Time can: only advice
                    // that keeps arriving right after reconnecting is paced.
                    if last_advised_reconnect
                        .is_some_and(|at: Instant| at.elapsed() > ADVICE_STREAK_WINDOW)
                    {
                        advised_reconnect_streak = 0;
                    }
                    last_advised_reconnect = Some(Instant::now());
                    advised_reconnect_streak += 1;
                    debug!(
                        resume_seq_num = ?start.seq_num,
                        advised_reconnect_streak,
                        "reconnecting read session on server advice"
                    );
                    yield Ok(ReadUpdate::behind());
                    if advised_reconnect_streak > MAX_IMMEDIATE_ADVISED_RECONNECTS {
                        tokio::time::sleep(ADVISED_RECONNECT_DELAY).await;
                    }
                    continue;
                }
                Some(Ok(ReadItem::Batch(batch))) => {
                    if retry_backoff.used() > 0 {
                        retry_backoff.reset();
                    }

                    if batch.tail.is_some() {
                        last_tail_at = Some(Instant::now());
                    }

                    update_resume_start(&mut start, &batch);
                    if let Some(count) = end.count.as_mut() {
                        *count = count.saturating_sub(batch.records.len())
                    }
                    if let Some(bytes) = end.bytes.as_mut() {
                        *bytes = bytes.saturating_sub(
                            batch.records.iter().map(|r| r.metered_bytes()).sum()
                        )
                    }

                    yield Ok(ReadUpdate::from_batch(batch, ignore_command_records));
                }
                Some(Err(err)) => {
                    batches = None;
                    if let Some(backoff) =
                        retry_delay(
                            &err,
                            &mut retry_backoff,
                            retry_policy,
                            access_token_mode,
                        )
                    {
                        yield Ok(ReadUpdate::behind());
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    yield Err(err);
                    break;
                }
                None => break,
            }
        }
    });
    Ok(ReadSession::new(updates, initial_resume_seq_num))
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

async fn session_inner(
    client: BasinClient,
    name: StreamName,
    encryption: Option<EncryptionKey>,
    start: ReadStart,
    end: ReadEnd,
    reconnect: ReconnectAdvice,
) -> Result<InternalStreaming<ReadItem>, ReadSessionFailure> {
    let mut batches = client
        .read_session(&name, start, end, encryption.as_ref(), reconnect.clone())
        .await?;
    Ok(Box::pin(try_stream! {
        loop {
            match timeout(HEARTBEAT_TIMEOUT, batches.next()).await {
                Ok(Some(batch)) => {
                    yield ReadItem::Batch(ReadBatch::from_api(batch?));
                    if reconnect.is_advised() {
                        yield ReadItem::ReconnectAdvised;
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => Err(ReadSessionFailure::HeartbeatTimeout)?,
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
        ReadSessionRetryPolicy::Indefinite => Some(backoffs.next_or_max()),
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
        updates: impl futures_core::Stream<Item = Result<ReadUpdate, ReadSessionFailure>>
        + Send
        + 'static,
    ) -> ReadSession {
        ReadSession::new(Box::pin(updates), None)
    }

    #[tokio::test]
    async fn empty_tail_exposes_absolute_resume_seq_num() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut session = test_session(UnboundedReceiverStream::new(rx));

        assert_eq!(session.resume_seq_num(), None);
        tx.send(Ok(ReadUpdate::from_batch(
            batch(Vec::new(), Some(position(42))),
            false,
        )))
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
            Ok(ReadUpdate::from_batch(
                batch(vec![record(0, false), record(1, false)], Some(tail)),
                false,
            )),
            Ok(ReadUpdate::from_batch(
                batch(vec![record(2, false)], Some(position(5))),
                false,
            )),
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

        tx.send(Ok(ReadUpdate::from_batch(
            batch(vec![record(0, false), record(1, false)], None),
            false,
        )))
        .unwrap();
        tx.send(Ok(ReadUpdate::from_batch(
            batch(Vec::new(), Some(tail)),
            false,
        )))
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

        tx.send(Ok(ReadUpdate::from_batch(
            batch(vec![record(0, false)], Some(tail)),
            false,
        )))
        .unwrap();
        session.next().await.unwrap().unwrap();
        let caught_up = session.state.future();

        tx.send(Ok(ReadUpdate::from_batch(
            batch(Vec::new(), Some(tail)),
            false,
        )))
        .unwrap();
        let mut next = Box::pin(session.next());
        assert!(poll!(next.as_mut()).is_pending());
        drop(next);

        let CaughtUpFuture::Pending(caught_up) = caught_up else {
            panic!("initial caught-up future should use the pending epoch");
        };
        let CaughtUpFuture::Pending(current) = session.state.future() else {
            panic!("unchanged heartbeat should preserve the pending epoch");
        };
        assert!(caught_up.ptr_eq(&current));
    }

    #[tokio::test]
    async fn filtered_command_counts_toward_caught_up() {
        let tail = position(2);
        let mut session = test_session(stream::iter([
            Ok(ReadUpdate::from_batch(
                batch(vec![record(0, false)], None),
                true,
            )),
            Ok(ReadUpdate::from_batch(
                batch(vec![record(1, true)], Some(tail)),
                true,
            )),
        ]));
        let caught_up = session.caught_up();

        let delivered = session.next().await.unwrap().unwrap();
        assert_eq!(delivered.records.len(), 1);
        assert_eq!(delivered.records[0].seq_num, 0);
        assert!(!session.is_caught_up());

        assert!(session.next().await.is_none());
        assert!(session.is_caught_up());
        assert_eq!(session.resume_seq_num(), Some(2));
        assert_eq!(caught_up.await.unwrap(), tail);
    }

    #[tokio::test]
    async fn caught_up_wait_survives_retry() {
        let first_tail = position(1);
        let tail = position(3);
        let (tx, rx) = mpsc::unbounded_channel();
        let mut session = test_session(UnboundedReceiverStream::new(rx));

        tx.send(Ok(ReadUpdate::from_batch(
            batch(Vec::new(), Some(first_tail)),
            false,
        )))
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
        tx.send(Ok(ReadUpdate::from_batch(
            batch(Vec::new(), Some(tail)),
            false,
        )))
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
        assert!(matches!(caught_up.await, Err(CaughtUpError::SessionClosed)));
    }

    #[tokio::test]
    async fn read_error_rejects_wait() {
        let mut session = test_session(stream::iter([Err(ReadSessionFailure::HeartbeatTimeout)]));
        let caught_up = session.caught_up();

        let error = session.next().await.unwrap().unwrap_err();
        assert_eq!(error.to_string(), "heartbeat timeout");
        assert!(matches!(
            caught_up.await,
            Err(CaughtUpError::Read(ReadSessionError::HeartbeatTimeout))
        ));
    }

    #[tokio::test]
    async fn read_error_after_caught_up_preserves_resolved_future() {
        let tail = position(1);
        let mut session = test_session(stream::iter([
            Ok(ReadUpdate::from_batch(
                batch(vec![record(0, false)], Some(tail)),
                false,
            )),
            Err(ReadSessionFailure::HeartbeatTimeout),
        ]));

        session.next().await.unwrap().unwrap();
        assert!(session.is_caught_up());
        let caught_up = session.caught_up();

        session.next().await.unwrap().unwrap_err();
        assert!(!session.is_caught_up());
        assert_eq!(caught_up.await.unwrap(), tail);
        assert!(matches!(
            session.caught_up().await,
            Err(CaughtUpError::Read(ReadSessionError::HeartbeatTimeout))
        ));
    }

    #[tokio::test]
    async fn dropping_session_rejects_wait() {
        let caught_up = {
            let session = test_session(stream::pending());
            session.caught_up()
        };

        assert!(matches!(caught_up.await, Err(CaughtUpError::SessionClosed)));
    }
}
