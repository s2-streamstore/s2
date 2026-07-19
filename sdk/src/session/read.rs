use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use async_stream::{stream, try_stream};
use futures_util::{
    StreamExt,
    future::{BoxFuture, FutureExt, Shared, ready},
};
use s2_api::v1::stream::{ReadEnd, ReadStart};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout},
};
use tracing::debug;

use crate::{
    api::{ApiError, BasinClient, retry_builder},
    retry::RetryBackoff,
    types::{EncryptionKey, MeteredBytes, ReadBatch, S2Error, StreamName, StreamPosition},
};

#[derive(Debug, thiserror::Error)]
pub enum ReadSessionError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("heartbeat timeout")]
    HeartbeatTimeout,
}

impl ReadSessionError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Api(err) => err.is_retryable(),
            Self::HeartbeatTimeout => true,
        }
    }
}

impl From<ReadSessionError> for S2Error {
    fn from(err: ReadSessionError) -> Self {
        match err {
            ReadSessionError::Api(api_err) => api_err.into(),
            other => S2Error::Client(other.to_string()),
        }
    }
}

pub type Streaming<R> =
    Pin<Box<dyn Send + futures_core::Stream<Item = Result<R, ReadSessionError>>>>;

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
/// Error returned while waiting for a read session to catch up.
pub enum CaughtUpError {
    #[error("read session ended before catching up")]
    /// The session ended before reaching a reported tail.
    SessionClosed,
    #[error(transparent)]
    /// The read failed.
    Read(#[from] S2Error),
}

impl From<CaughtUpError> for S2Error {
    fn from(err: CaughtUpError) -> Self {
        match err {
            CaughtUpError::SessionClosed => {
                Self::Client("read session ended before catching up".into())
            }
            CaughtUpError::Read(err) => err,
        }
    }
}

type CaughtUpResult = Result<StreamPosition, CaughtUpError>;
type SharedCaughtUp = Shared<BoxFuture<'static, CaughtUpResult>>;

/// A future that returns the next caught-up tail.
#[derive(Clone)]
pub struct CaughtUp {
    inner: SharedCaughtUp,
}

impl Future for CaughtUp {
    type Output = CaughtUpResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

struct CaughtUpState {
    tail: Option<StreamPosition>,
    terminal: bool,
    tx: Option<oneshot::Sender<CaughtUpResult>>,
    future: SharedCaughtUp,
}

impl CaughtUpState {
    fn new() -> Self {
        let (tx, future) = pending_caught_up();
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

    fn future(&self) -> CaughtUp {
        CaughtUp {
            inner: self.future.clone(),
        }
    }

    fn set_behind(&mut self) {
        if self.terminal || self.tail.take().is_none() {
            return;
        }
        let (tx, future) = pending_caught_up();
        self.tx = Some(tx);
        self.future = future;
    }

    fn set_caught_up(&mut self, tail: StreamPosition) {
        if self.terminal {
            return;
        }
        self.tail = Some(tail);
        self.complete(Ok(tail));
    }

    fn end(&mut self, error: Option<S2Error>) {
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
            self.future = ready(result).boxed().shared();
        }
    }
}

fn pending_caught_up() -> (oneshot::Sender<CaughtUpResult>, SharedCaughtUp) {
    let (tx, rx) = oneshot::channel();
    let future = async move { rx.await.unwrap_or(Err(CaughtUpError::SessionClosed)) }
        .boxed()
        .shared();
    (tx, future)
}

struct ReadUpdate {
    batch: Option<ReadBatch>,
    caught_up_tail: Option<StreamPosition>,
}

impl ReadUpdate {
    fn behind() -> Self {
        Self {
            batch: None,
            caught_up_tail: None,
        }
    }

    fn from_batch(mut batch: ReadBatch, ignore_command_records: bool) -> Self {
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
        }
    }
}

/// A continuous stream of read batches.
pub struct ReadSession {
    updates: Streaming<ReadUpdate>,
    state: CaughtUpState,
}

impl ReadSession {
    fn new(updates: Streaming<ReadUpdate>) -> Self {
        Self {
            updates,
            state: CaughtUpState::new(),
        }
    }

    /// Return whether all records through the latest reported tail were delivered.
    ///
    /// A later batch that does not reach a reported tail or a reconnect resets it.
    /// Ignored command records count toward progress. Use
    /// [`S2Stream::check_tail`](crate::S2Stream::check_tail) for the current tail.
    pub fn is_caught_up(&self) -> bool {
        self.state.is_caught_up()
    }

    /// Return a future for the next caught-up tail.
    ///
    /// It is ready immediately when already caught up and remains pending across retries.
    /// Keep reading batches while waiting. Call again after falling behind. Returns
    /// [`CaughtUpError`] if the read fails or ends first.
    pub fn caught_up(&self) -> CaughtUp {
        self.state.future()
    }
}

impl futures_core::Stream for ReadSession {
    type Item = Result<ReadBatch, S2Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.updates.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(update))) => {
                    self.state.set_behind();
                    if let Some(tail) = update.caught_up_tail {
                        self.state.set_caught_up(tail);
                    }
                    if let Some(batch) = update.batch {
                        return Poll::Ready(Some(Ok(batch)));
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    let error = S2Error::from(error);
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
    mut start: ReadStart,
    mut end: ReadEnd,
    ignore_command_records: bool,
) -> Result<ReadSession, ReadSessionError> {
    let mut retry_backoff = retry_builder(&client.config.retry).build();
    let baseline_wait = end.wait;
    let mut last_tail_at: Option<Instant> = None;

    let batches = loop {
        end.wait = remaining_wait(baseline_wait, last_tail_at);
        match session_inner(
            client.clone(),
            name.clone(),
            encryption.clone(),
            start.clone(),
            end.clone(),
        )
        .await
        {
            Ok(batches) => {
                retry_backoff.reset();
                break batches;
            }
            Err(err) => {
                if let Some(backoff) = retry_delay(&err, &mut retry_backoff) {
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                return Err(err);
            }
        }
    };

    let updates = Box::pin(stream! {
        let mut batches: Option<Streaming<ReadBatch>> = Some(batches);

        loop {
            if batches.is_none() {
                end.wait = remaining_wait(baseline_wait, last_tail_at);
                match session_inner(
                    client.clone(),
                    name.clone(),
                    encryption.clone(),
                    start.clone(),
                    end.clone(),
                ).await {
                    Ok(b) => batches = Some(b),
                    Err(err) => {
                        if let Some(backoff) = retry_delay(&err, &mut retry_backoff) {
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
                Some(Ok(batch)) => {
                    if retry_backoff.used() > 0 {
                        retry_backoff.reset();
                    }

                    if batch.tail.is_some() {
                        last_tail_at = Some(Instant::now());
                    }

                    if let Some(record) = batch.records.last() {
                        start = ReadStart {
                            seq_num: Some(record.seq_num + 1),
                            timestamp: None,
                            tail_offset: None,
                            clamp: start.clamp,
                        };
                    }
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
                    if let Some(backoff) = retry_delay(&err, &mut retry_backoff) {
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
    Ok(ReadSession::new(updates))
}

async fn session_inner(
    client: BasinClient,
    name: StreamName,
    encryption: Option<EncryptionKey>,
    start: ReadStart,
    end: ReadEnd,
) -> Result<Streaming<ReadBatch>, ReadSessionError> {
    let mut batches = client
        .read_session(&name, start, end, encryption.as_ref())
        .await?;
    Ok(Box::pin(try_stream! {
        loop {
            match timeout(Duration::from_secs(20), batches.next()).await {
                Ok(Some(batch)) => {
                    yield ReadBatch::from_api(batch?);
                }
                Ok(None) => break,
                Err(_) => Err(ReadSessionError::HeartbeatTimeout)?,
            }
        }
    }))
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

fn retry_delay(err: &ReadSessionError, backoffs: &mut RetryBackoff) -> Option<Duration> {
    if err.is_retryable()
        && let Some(backoff) = backoffs.next()
    {
        debug!(
            %err,
            ?backoff,
            num_retries_remaining = backoffs.remaining(),
            "retrying read session"
        );
        Some(backoff)
    } else {
        debug!(
            %err,
            is_retryable = err.is_retryable(),
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

    fn test_session(
        updates: impl futures_core::Stream<Item = Result<ReadUpdate, ReadSessionError>> + Send + 'static,
    ) -> ReadSession {
        ReadSession::new(Box::pin(updates))
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
        let caught_up_while_caught = session.caught_up();

        session.next().await.unwrap().unwrap();
        assert!(!session.is_caught_up());
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
        let mut session = test_session(stream::iter([Err(ReadSessionError::HeartbeatTimeout)]));
        let caught_up = session.caught_up();

        let error = session.next().await.unwrap().unwrap_err();
        assert_eq!(error.to_string(), "heartbeat timeout");
        assert!(matches!(
            caught_up.await,
            Err(CaughtUpError::Read(S2Error::Client(message)))
                if message == "heartbeat timeout"
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
