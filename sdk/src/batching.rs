//! Utilities for batching [AppendRecord]s.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::{Stream, StreamExt};
use s2_common::{caps::RECORD_BATCH_MAX, read_extent::CountOrBytes};
use tokio::time::Instant;

use crate::types::{
    AppendInput, AppendRecord, AppendRecordBatch, FencingToken, MeteredBytes, ValidationError,
};

const RECORD_BATCH_MIN: CountOrBytes = CountOrBytes { count: 1, bytes: 8 };

#[derive(Debug, Clone)]
/// Configuration for batching [`AppendRecord`]s.
pub struct BatchingConfig {
    linger: Duration,
    max_batch_bytes: usize,
    max_batch_records: usize,
}

impl Default for BatchingConfig {
    fn default() -> Self {
        Self {
            linger: Duration::from_millis(5),
            max_batch_bytes: RECORD_BATCH_MAX.bytes,
            max_batch_records: RECORD_BATCH_MAX.count,
        }
    }
}

impl BatchingConfig {
    /// Create a new [`BatchingConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the duration for how long to wait for more records before flushing a batch.
    ///
    /// Defaults to `5ms`.
    pub fn with_linger(self, linger: Duration) -> Self {
        Self { linger, ..self }
    }

    /// Set the maximum metered bytes per batch.
    ///
    /// **Note:** It must be at least `8B` and must not exceed `1MiB`.
    ///
    /// Defaults to `1MiB`.
    pub fn with_max_batch_bytes(self, max_batch_bytes: usize) -> Result<Self, ValidationError> {
        if max_batch_bytes < RECORD_BATCH_MIN.bytes {
            return Err(ValidationError(format!(
                "max_batch_bytes ({max_batch_bytes}) must be at least {}",
                RECORD_BATCH_MIN.bytes
            )));
        }
        if max_batch_bytes > RECORD_BATCH_MAX.bytes {
            return Err(ValidationError(format!(
                "max_batch_bytes ({max_batch_bytes}) must not exceed {}",
                RECORD_BATCH_MAX.bytes
            )));
        }
        Ok(Self {
            max_batch_bytes,
            ..self
        })
    }

    /// Set the maximum number of records per batch.
    ///
    /// **Note:** It must be at least `1` and must not exceed `1000`.
    ///
    /// Defaults to `1000`.
    pub fn with_max_batch_records(self, max_batch_records: usize) -> Result<Self, ValidationError> {
        if max_batch_records < RECORD_BATCH_MIN.count {
            return Err(ValidationError(format!(
                "max_batch_records ({max_batch_records}) must be at least {}",
                RECORD_BATCH_MIN.count
            )));
        }
        if max_batch_records > RECORD_BATCH_MAX.count {
            return Err(ValidationError(format!(
                "max_batch_records ({max_batch_records}) must not exceed {}",
                RECORD_BATCH_MAX.count
            )));
        }
        Ok(Self {
            max_batch_records,
            ..self
        })
    }
}

/// A [`Stream`] that batches [`AppendRecord`]s into [`AppendInput`]s.
pub struct AppendInputs {
    pub(crate) batches: AppendRecordBatches,
    pub(crate) fencing_token: Option<FencingToken>,
    pub(crate) match_seq_num: Option<u64>,
}

impl AppendInputs {
    /// Create a new [`AppendInputs`] with the given records and config.
    pub fn new(
        records: impl Stream<Item = impl Into<AppendRecord> + Send> + Send + Unpin + 'static,
        config: BatchingConfig,
    ) -> Self {
        Self {
            batches: AppendRecordBatches::new(records, config),
            fencing_token: None,
            match_seq_num: None,
        }
    }

    /// Set the fencing token for all [`AppendInput`]s.
    pub fn with_fencing_token(self, fencing_token: FencingToken) -> Self {
        Self {
            fencing_token: Some(fencing_token),
            ..self
        }
    }

    /// Set the match sequence number for the initial [`AppendInput`]. It will be auto-incremented
    /// for the subsequent ones.
    pub fn with_match_seq_num(self, seq_num: u64) -> Self {
        Self {
            match_seq_num: Some(seq_num),
            ..self
        }
    }
}

impl Stream for AppendInputs {
    type Item = Result<AppendInput, ValidationError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.batches.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(batch))) => {
                let match_seq_num = self.match_seq_num;
                if let Some(seq_num) = self.match_seq_num.as_mut() {
                    *seq_num += batch.len() as u64;
                }
                Poll::Ready(Some(Ok(AppendInput {
                    records: batch,
                    match_seq_num,
                    fencing_token: self.fencing_token.clone(),
                })))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A [`Stream`] that batches [`AppendRecord`]s into [`AppendRecordBatch`]es.
pub struct AppendRecordBatches {
    inner: Pin<Box<dyn Stream<Item = Result<AppendRecordBatch, ValidationError>> + Send>>,
}

impl AppendRecordBatches {
    /// Create a new [`AppendRecordBatches`] with the given records and config.
    pub fn new(
        records: impl Stream<Item = impl Into<AppendRecord> + Send> + Send + Unpin + 'static,
        config: BatchingConfig,
    ) -> Self {
        Self {
            inner: Box::pin(append_record_batches(records, config)),
        }
    }
}

impl Stream for AppendRecordBatches {
    type Item = Result<AppendRecordBatch, ValidationError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

fn is_batch_full(config: &BatchingConfig, count: usize, bytes: usize) -> bool {
    count >= config.max_batch_records || bytes >= config.max_batch_bytes
}

fn would_overflow_batch(
    config: &BatchingConfig,
    count: usize,
    bytes: usize,
    record: &AppendRecord,
) -> bool {
    count + 1 > config.max_batch_records || bytes + record.metered_bytes() > config.max_batch_bytes
}

fn append_record_batches(
    mut records: impl Stream<Item = impl Into<AppendRecord> + Send> + Send + Unpin + 'static,
    config: BatchingConfig,
) -> impl Stream<Item = Result<AppendRecordBatch, ValidationError>> + Send + 'static {
    async_stream::try_stream! {
        let mut batch = AppendRecordBatch::with_capacity(config.max_batch_records);
        let mut overflowed_record: Option<AppendRecord> = None;

        let linger_deadline = tokio::time::sleep(config.linger);
        tokio::pin!(linger_deadline);

        'outer: loop {
            let first_record = match overflowed_record.take() {
                Some(record) => record,
                None => match records.next().await {
                    Some(item) => item.into(),
                    None => break,
                },
            };

            let record_bytes = first_record.metered_bytes();
            if record_bytes > config.max_batch_bytes {
                Err(ValidationError(format!(
                    "record size in metered bytes ({record_bytes}) exceeds max_batch_bytes ({})",
                    config.max_batch_bytes
                )))?;
            }
            batch.push(first_record);

            while !is_batch_full(&config, batch.len(), batch.metered_bytes())
                && overflowed_record.is_none()
            {
                if batch.len() == 1 {
                    linger_deadline
                        .as_mut()
                        .reset(Instant::now() + config.linger);
                }

                tokio::select! {
                    next_record = records.next() => {
                        match next_record {
                            Some(record) => {
                                let record: AppendRecord = record.into();
                                if would_overflow_batch(&config, batch.len(), batch.metered_bytes(), &record) {
                                    overflowed_record = Some(record);
                                } else {
                                    batch.push(record);
                                }
                            }
                            None => {
                                yield std::mem::replace(&mut batch, AppendRecordBatch::with_capacity(config.max_batch_records));
                                break 'outer;
                            }
                        }
                    },
                    _ = &mut linger_deadline, if !batch.is_empty() => {
                        break;
                    }
                };
            }

            yield std::mem::replace(
                &mut batch,
                AppendRecordBatch::with_capacity(config.max_batch_records),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use futures::TryStreamExt;

    use super::*;

    #[tokio::test]
    async fn batches_should_be_empty_when_record_stream_is_empty() {
        let batches: Vec<_> = AppendRecordBatches::new(
            futures::stream::iter::<Vec<AppendRecord>>(vec![]),
            BatchingConfig::default(),
        )
        .collect()
        .await;
        assert_eq!(batches.len(), 0);
    }

    #[tokio::test]
    async fn batches_respect_count_limit() -> Result<(), ValidationError> {
        let records: Vec<_> = (0..10)
            .map(|i| AppendRecord::new(format!("record{i}")))
            .collect::<Result<_, _>>()?;
        let config = BatchingConfig::default().with_max_batch_records(3)?;
        let batches: Vec<_> = AppendRecordBatches::new(futures::stream::iter(records), config)
            .try_collect()
            .await?;

        assert_eq!(batches.len(), 4);
        assert_eq!(batches[0].len(), 3);
        assert_eq!(batches[1].len(), 3);
        assert_eq!(batches[2].len(), 3);
        assert_eq!(batches[3].len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn batches_respect_bytes_limit() -> Result<(), ValidationError> {
        let records: Vec<_> = (0..10)
            .map(|i| AppendRecord::new(format!("record{i}")))
            .collect::<Result<_, _>>()?;
        let single_record_bytes = records[0].metered_bytes();
        let max_batch_bytes = single_record_bytes * 3;

        let config = BatchingConfig::default().with_max_batch_bytes(max_batch_bytes)?;
        let batches: Vec<_> = AppendRecordBatches::new(futures::stream::iter(records), config)
            .try_collect()
            .await?;

        assert_eq!(batches.len(), 4);
        assert_eq!(batches[0].metered_bytes(), max_batch_bytes);
        assert_eq!(batches[1].metered_bytes(), max_batch_bytes);
        assert_eq!(batches[2].metered_bytes(), max_batch_bytes);
        assert_eq!(batches[3].metered_bytes(), single_record_bytes);

        Ok(())
    }

    #[tokio::test]
    async fn batching_should_error_when_it_sees_oversized_record() -> Result<(), ValidationError> {
        let record = AppendRecord::new("hello-world")?;
        let record_bytes = record.metered_bytes();
        let max_batch_bytes = 10;

        let config = BatchingConfig::default().with_max_batch_bytes(max_batch_bytes)?;
        let results: Vec<_> = AppendRecordBatches::new(futures::stream::iter(vec![record]), config)
            .collect()
            .await;

        assert_eq!(results.len(), 1);
        assert_matches!(&results[0], Err(err) => {
            assert_eq!(
                err.to_string(),
                format!("record size in metered bytes ({record_bytes}) exceeds max_batch_bytes ({max_batch_bytes})")
            );
        });

        Ok(())
    }
}
