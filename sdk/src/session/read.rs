use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use async_stream::{stream, try_stream};
use futures_util::StreamExt;
use s2_api::v1::stream::{ReadEnd, ReadStart};
use tokio::{
    sync::watch,
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

#[derive(Debug, Clone, Copy)]
enum CaughtUpState {
    Behind,
    CaughtUp(StreamPosition),
    Ended,
}

/// Read session yielding [`ReadBatch`]es, with automatic resumption on retryable errors.
pub struct ReadSession {
    batches: Pin<Box<dyn Send + futures_core::Stream<Item = Result<ReadBatch, S2Error>>>>,
    caught_up: watch::Receiver<CaughtUpState>,
}

impl ReadSession {
    /// True while the session is at the live tail: every record that existed as of
    /// the last server report has been consumed.
    pub fn is_caught_up(&self) -> bool {
        matches!(*self.caught_up.borrow(), CaughtUpState::CaughtUp(_))
    }

    /// Wait until the session reaches the live tail, returning the last observed
    /// tail position at that moment. Completes immediately if already caught up.
    /// Call again after falling behind to await the next catch-up. A pending
    /// future stays pending across internal retries.
    ///
    /// Errors if the session terminates before reaching the tail, whether due to a
    /// fatal error or a stop condition (count/bytes/until limit) being met.
    ///
    /// The returned future does not borrow the session, so it can be polled
    /// concurrently with record consumption, e.g. in a `select!` arm alongside
    /// [`next`](futures_util::StreamExt::next). Note that the signal advances only
    /// while the session is being polled.
    pub fn caught_up(
        &self,
    ) -> impl Future<Output = Result<StreamPosition, S2Error>> + Send + use<> {
        let mut rx = self.caught_up.clone();
        async move {
            loop {
                match *rx.borrow_and_update() {
                    CaughtUpState::CaughtUp(tail) => return Ok(tail),
                    CaughtUpState::Ended => {
                        return Err(S2Error::Client(
                            "read session ended before catching up".to_owned(),
                        ));
                    }
                    CaughtUpState::Behind => {}
                }
                if rx.changed().await.is_err() {
                    return Err(S2Error::Client(
                        "read session ended before catching up".to_owned(),
                    ));
                }
            }
        }
    }
}

impl futures_core::Stream for ReadSession {
    type Item = Result<ReadBatch, S2Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.batches.as_mut().poll_next(cx)
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
    let (caught_up_tx, caught_up_rx) = watch::channel(CaughtUpState::Behind);

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
                if can_retry(&err, &mut retry_backoff).await {
                    continue;
                }
                return Err(err);
            }
        }
    };

    let batches = stream! {
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
                        if can_retry(&err, &mut retry_backoff).await {
                            continue;
                        }
                        caught_up_tx.send_replace(CaughtUpState::Ended);
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
                Some(Ok(mut batch)) => {
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

                    // Compared before command-record filtering, so a filtered
                    // record at the tail still counts toward being caught up.
                    let caught_up_tail = batch.tail.filter(|tail| {
                        batch
                            .records
                            .last()
                            .is_none_or(|last| last.seq_num + 1 == tail.seq_num)
                    });
                    caught_up_tx.send_replace(match caught_up_tail {
                        Some(tail) => CaughtUpState::CaughtUp(tail),
                        None => CaughtUpState::Behind,
                    });

                    if ignore_command_records {
                        batch.records.retain(|r| !r.is_command_record());
                    }

                    if !batch.records.is_empty() {
                        yield Ok(batch);
                    }
                }
                Some(Err(err)) => {
                    batches = None;
                    if can_retry(&err, &mut retry_backoff).await {
                        caught_up_tx.send_replace(CaughtUpState::Behind);
                        continue;
                    }
                    caught_up_tx.send_replace(CaughtUpState::Ended);
                    yield Err(err);
                    break;
                }
                None => {
                    caught_up_tx.send_if_modified(|state| {
                        if matches!(state, CaughtUpState::Behind) {
                            *state = CaughtUpState::Ended;
                            true
                        } else {
                            false
                        }
                    });
                    break;
                }
            }
        }
    };

    Ok(ReadSession {
        batches: Box::pin(batches.map(|res| res.map_err(S2Error::from))),
        caught_up: caught_up_rx,
    })
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

async fn can_retry(err: &ReadSessionError, backoffs: &mut RetryBackoff) -> bool {
    if err.is_retryable()
        && let Some(backoff) = backoffs.next()
    {
        debug!(
            %err,
            ?backoff,
            num_retries_remaining = backoffs.remaining(),
            "retrying read session"
        );
        tokio::time::sleep(backoff).await;
        true
    } else {
        debug!(
            %err,
            is_retryable = err.is_retryable(),
            retries_exhausted = backoffs.is_exhausted(),
            "not retrying read session"
        );
        false
    }
}
