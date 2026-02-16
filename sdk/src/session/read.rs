use std::{pin::Pin, time::Duration};

use async_stream::{stream, try_stream};
use futures::StreamExt;
use s2_api::v1::stream::{ReadEnd, ReadStart};
use tokio::time::{Instant, timeout};
use tracing::debug;

use crate::{
    api::{ApiError, BasinClient, retry_builder},
    retry::RetryBackoff,
    types::{MeteredBytes, ReadBatch, S2Error, StreamName},
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

pub type Streaming<R> = Pin<Box<dyn Send + futures::Stream<Item = Result<R, ReadSessionError>>>>;

pub async fn read_session(
    client: BasinClient,
    name: StreamName,
    mut start: ReadStart,
    mut end: ReadEnd,
    ignore_command_records: bool,
) -> Result<Streaming<ReadBatch>, ReadSessionError> {
    let mut retry_backoff = retry_builder(&client.config.retry).build();
    let baseline_wait = end.wait;
    let mut last_tail_at: Option<Instant> = None;

    let batches = loop {
        end.wait = remaining_wait(baseline_wait, last_tail_at);
        match session_inner(
            client.clone(),
            name.clone(),
            start.clone(),
            end.clone(),
            ignore_command_records,
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

    Ok(Box::pin(stream! {
        let mut batches: Option<Streaming<ReadBatch>> = Some(batches);

        loop {
            if batches.is_none() {
                end.wait = remaining_wait(baseline_wait, last_tail_at);
                match session_inner(
                    client.clone(),
                    name.clone(),
                    start.clone(),
                    end.clone(),
                    ignore_command_records,
                ).await {
                    Ok(b) => batches = Some(b),
                    Err(err) => {
                        if can_retry(&err, &mut retry_backoff).await {
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

                    yield Ok(batch);
                }
                Some(Err(err)) => {
                    batches = None;
                    if can_retry(&err, &mut retry_backoff).await {
                        continue;
                    }
                    yield Err(err);
                    break;
                }
                None => break,
            }
        }
    }))
}

async fn session_inner(
    client: BasinClient,
    name: StreamName,
    start: ReadStart,
    end: ReadEnd,
    ignore_command_records: bool,
) -> Result<Streaming<ReadBatch>, ReadSessionError> {
    let mut batches = client.read_session(&name, start, end).await?;
    Ok(Box::pin(try_stream! {
        loop {
            match timeout(Duration::from_secs(20), batches.next()).await {
                Ok(Some(batch)) => {
                    let batch = ReadBatch::from_api(batch?, ignore_command_records);
                    if !batch.records.is_empty() {
                        yield batch;
                    }
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
