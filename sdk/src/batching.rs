//! Utilities for batching [AppendRecord]s.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::Stream;
use futures_util::{StreamExt, stream};
use s2_common::{
    caps::RECORD_BATCH_MAX,
    read_extent::CountOrBytes,
    record::{Metered, MeteredSize},
};
use tokio::time::Instant;

use crate::types::{
    AppendInput, AppendRecord, AppendRecordBatch, FencingToken, StreamConfig, ValidationError,
};

const RECORD_BATCH_MIN: CountOrBytes = CountOrBytes { count: 1, bytes: 8 };

#[derive(Debug, Clone)]
/// Limits for batching [`AppendRecord`]s.
pub struct BatchLimits {
    max_batch_bytes: usize,
    max_batch_records: usize,
}

impl Default for BatchLimits {
    fn default() -> Self {
        Self {
            max_batch_bytes: RECORD_BATCH_MAX.bytes,
            max_batch_records: RECORD_BATCH_MAX.count,
        }
    }
}

impl BatchLimits {
    /// Create new [`BatchLimits`] with default settings.
    pub fn new() -> Self {
        Self::default()
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

#[derive(Debug, Clone)]
/// Configuration for batching [`AppendRecord`]s.
pub struct BatchingConfig {
    linger: Duration,
    limits: BatchLimits,
}

impl Default for BatchingConfig {
    fn default() -> Self {
        Self {
            linger: Duration::from_millis(5),
            limits: BatchLimits::default(),
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

    /// Set the batch limits.
    pub fn with_limits(self, limits: BatchLimits) -> Self {
        Self { limits, ..self }
    }
}

/// A [`Stream`] that batches [`AppendRecord`]s into [`AppendInput`]s.
pub struct AppendInputs {
    pub(crate) batches: AppendRecordBatches,
    pub(crate) fencing_token: Option<FencingToken>,
    pub(crate) match_seq_num: Option<u64>,
    pub(crate) create_stream_config: Option<StreamConfig>,
}

impl AppendInputs {
    /// Create a new [`AppendInputs`] from pre-batched records.
    pub fn new(batches: AppendRecordBatches) -> Self {
        Self {
            batches,
            fencing_token: None,
            match_seq_num: None,
            create_stream_config: None,
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

    /// Set the stream configuration to apply if an [`AppendInput`] creates the stream on demand.
    pub fn with_create_stream_config(self, create_stream_config: StreamConfig) -> Self {
        Self {
            create_stream_config: Some(create_stream_config),
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
                    create_stream_config: self.create_stream_config.clone(),
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
    /// Create a new [`AppendRecordBatches`] from a record stream and config.
    pub fn from_stream(
        records: impl Stream<Item = impl Into<AppendRecord> + Send> + Send + Unpin + 'static,
        config: BatchingConfig,
    ) -> Self {
        Self {
            inner: Box::pin(append_record_batches(records, config)),
        }
    }

    /// Eagerly batch in-memory records with the given limits.
    ///
    /// The returned value is a stream of validated batches and can be collected
    /// into a `Vec<AppendRecordBatch>` when eager results are needed.
    ///
    /// ```rust
    /// # use s2_sdk::batching::{AppendRecordBatches, BatchLimits};
    /// # use s2_sdk::types::AppendRecord;
    /// let records = [AppendRecord::new("one")?, AppendRecord::new("two")?];
    /// let batches = AppendRecordBatches::from_iter(records, BatchLimits::new())?;
    /// # let _ = batches;
    /// # Ok::<(), s2_sdk::types::ValidationError>(())
    /// ```
    pub fn from_iter(
        records: impl IntoIterator<Item = impl Into<AppendRecord>>,
        limits: BatchLimits,
    ) -> Result<Self, ValidationError> {
        let mut batches = Vec::new();
        let mut batch = Metered::with_capacity(limits.max_batch_records);

        for item in records {
            let record = Metered::from(item.into());
            if record.metered_size() > limits.max_batch_bytes {
                return Err(ValidationError(format!(
                    "record size in metered bytes ({}) exceeds max_batch_bytes ({})",
                    record.metered_size(),
                    limits.max_batch_bytes
                )));
            }

            if !batch.is_empty() && would_overflow_batch(&limits, &batch, &record) {
                batches.push(AppendRecordBatch::from(std::mem::replace(
                    &mut batch,
                    Metered::with_capacity(limits.max_batch_records),
                )));
            }

            batch.push(record);
            if is_batch_full(&limits, &batch) {
                batches.push(AppendRecordBatch::from(std::mem::replace(
                    &mut batch,
                    Metered::with_capacity(limits.max_batch_records),
                )));
            }
        }

        if !batch.is_empty() {
            batches.push(batch.into());
        }

        Ok(Self {
            inner: Box::pin(stream::iter(batches.into_iter().map(Ok))),
        })
    }
}

impl Stream for AppendRecordBatches {
    type Item = Result<AppendRecordBatch, ValidationError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

fn is_batch_full(limits: &BatchLimits, batch: &Metered<Vec<AppendRecord>>) -> bool {
    batch.len() >= limits.max_batch_records || batch.metered_size() >= limits.max_batch_bytes
}

fn would_overflow_batch(
    limits: &BatchLimits,
    batch: &Metered<Vec<AppendRecord>>,
    record: &Metered<AppendRecord>,
) -> bool {
    batch.len() + 1 > limits.max_batch_records
        || batch.metered_size() + record.metered_size() > limits.max_batch_bytes
}

fn append_record_batches(
    mut records: impl Stream<Item = impl Into<AppendRecord> + Send> + Send + Unpin + 'static,
    config: BatchingConfig,
) -> impl Stream<Item = Result<AppendRecordBatch, ValidationError>> + Send + 'static {
    async_stream::try_stream! {
        let mut batch = Metered::with_capacity(config.limits.max_batch_records);
        let mut overflowed_record: Option<Metered<AppendRecord>> = None;

        let linger_deadline = tokio::time::sleep(config.linger);
        tokio::pin!(linger_deadline);

        'outer: loop {
            let first_record = match overflowed_record.take() {
                Some(pair) => pair,
                None => match records.next().await {
                    Some(item) => Metered::from(item.into()),
                    None => break,
                },
            };

            if first_record.metered_size() > config.limits.max_batch_bytes {
                Err(ValidationError(format!(
                    "record size in metered bytes ({}) exceeds max_batch_bytes ({})",
                    first_record.metered_size(),
                    config.limits.max_batch_bytes
                )))?;
            }
            batch.push(first_record);

            while !is_batch_full(&config.limits, &batch) && overflowed_record.is_none() {
                if batch.len() == 1 {
                    linger_deadline
                        .as_mut()
                        .reset(Instant::now() + config.linger);
                }

                tokio::select! {
                    next_record = records.next() => {
                        match next_record {
                            Some(record) => {
                                let record = Metered::from(record.into());
                                if would_overflow_batch(&config.limits, &batch, &record) {
                                    overflowed_record = Some(record);
                                } else {
                                    batch.push(record);
                                }
                            }
                            None => {
                                yield AppendRecordBatch::from(std::mem::replace(
                                    &mut batch,
                                    Metered::with_capacity(config.limits.max_batch_records),
                                ));
                                break 'outer;
                            }
                        }
                    },
                    _ = &mut linger_deadline, if !batch.is_empty() => {
                        break;
                    }
                };
            }

            yield AppendRecordBatch::from(std::mem::replace(
                &mut batch,
                Metered::with_capacity(config.limits.max_batch_records),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use futures_util::TryStreamExt;

    use super::*;
    use crate::types::MeteredBytes as _;

    #[tokio::test]
    async fn batches_should_be_empty_when_record_stream_is_empty() {
        let batches: Vec<_> = AppendRecordBatches::from_stream(
            futures_util::stream::iter::<Vec<AppendRecord>>(vec![]),
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
        let config = BatchingConfig::default()
            .with_limits(BatchLimits::default().with_max_batch_records(3)?);
        let batches: Vec<_> =
            AppendRecordBatches::from_stream(futures_util::stream::iter(records), config)
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

        let config = BatchingConfig::default()
            .with_limits(BatchLimits::default().with_max_batch_bytes(max_batch_bytes)?);
        let batches: Vec<_> =
            AppendRecordBatches::from_stream(futures_util::stream::iter(records), config)
                .try_collect()
                .await?;

        assert_eq!(batches.len(), 4);
        assert_eq!(batches[0].metered_bytes(), max_batch_bytes);
        assert_eq!(batches[1].metered_bytes(), max_batch_bytes);
        assert_eq!(batches[2].metered_bytes(), max_batch_bytes);
        assert_eq!(batches[3].metered_bytes(), single_record_bytes);

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn batches_flush_after_linger_when_stream_remains_open() -> Result<(), ValidationError> {
        let records: Vec<_> = (0..2)
            .map(|i| AppendRecord::new(format!("record{i}")))
            .collect::<Result<_, _>>()?;
        let records = futures_util::stream::iter(records).chain(futures_util::stream::pending());
        let config = BatchingConfig::default().with_linger(Duration::from_millis(5));
        let mut batches = AppendRecordBatches::from_stream(records, config);
        let next_batch = tokio::spawn(async move { batches.next().await });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(6)).await;

        let batch = next_batch.await.unwrap().unwrap()?;
        assert_eq!(batch.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn batching_should_error_when_it_sees_oversized_record() -> Result<(), ValidationError> {
        let record = AppendRecord::new("hello-world")?;
        let record_bytes = record.metered_bytes();
        let max_batch_bytes = 10;

        let config = BatchingConfig::default()
            .with_limits(BatchLimits::default().with_max_batch_bytes(max_batch_bytes)?);
        let results: Vec<_> =
            AppendRecordBatches::from_stream(futures_util::stream::iter(vec![record]), config)
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

    #[tokio::test]
    async fn eager_batches_should_be_empty_when_record_iter_is_empty() {
        let batches =
            AppendRecordBatches::from_iter(std::iter::empty::<AppendRecord>(), BatchLimits::new())
                .unwrap()
                .try_collect::<Vec<_>>()
                .await
                .unwrap();
        assert!(batches.is_empty());
    }

    #[tokio::test]
    async fn eager_batches_respect_count_limit() -> Result<(), ValidationError> {
        let records: Vec<_> = (0..10)
            .map(|i| AppendRecord::new(format!("record{i}")))
            .collect::<Result<_, _>>()?;
        let limits = BatchLimits::new().with_max_batch_records(3)?;
        let batches = AppendRecordBatches::from_iter(records, limits)?
            .try_collect::<Vec<_>>()
            .await?;

        assert_eq!(batches.len(), 4);
        assert_eq!(batches[0].len(), 3);
        assert_eq!(batches[1].len(), 3);
        assert_eq!(batches[2].len(), 3);
        assert_eq!(batches[3].len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn eager_batches_respect_bytes_limit() -> Result<(), ValidationError> {
        let records: Vec<_> = (0..10)
            .map(|i| AppendRecord::new(format!("record{i}")))
            .collect::<Result<_, _>>()?;
        let single_record_bytes = records[0].metered_bytes();
        let max_batch_bytes = single_record_bytes * 3;
        let limits = BatchLimits::new().with_max_batch_bytes(max_batch_bytes)?;
        let batches = AppendRecordBatches::from_iter(records, limits)?
            .try_collect::<Vec<_>>()
            .await?;

        assert_eq!(batches.len(), 4);
        assert_eq!(batches[0].metered_bytes(), max_batch_bytes);
        assert_eq!(batches[1].metered_bytes(), max_batch_bytes);
        assert_eq!(batches[2].metered_bytes(), max_batch_bytes);
        assert_eq!(batches[3].metered_bytes(), single_record_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn eager_batching_should_error_when_record_is_oversized() -> Result<(), ValidationError> {
        let record = AppendRecord::new("hello-world")?;
        let record_bytes = record.metered_bytes();
        let max_batch_bytes = 10;
        let limits = BatchLimits::new().with_max_batch_bytes(max_batch_bytes)?;
        let err = AppendRecordBatches::from_iter([record], limits)
            .err()
            .unwrap();

        assert_eq!(
            err.to_string(),
            format!(
                "record size in metered bytes ({record_bytes}) exceeds max_batch_bytes ({max_batch_bytes})"
            )
        );
        Ok(())
    }
}
