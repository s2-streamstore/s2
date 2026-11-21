//! Utilities for batching [`AppendRecord`]s into [`AppendInput`]s.

use std::{
    convert::Infallible,
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::Stream;
use pin_project_lite::pin_project;
use s2_common::{
    caps::RECORD_BATCH_MAX,
    read_extent::CountOrBytes,
    record::{Metered, MeteredSize},
};
use tokio::time::{Instant, Sleep};

use crate::types::{AppendInput, AppendRecord, AppendRecordBatch, FencingToken, ValidationError};

pub(crate) const RECORD_BATCH_MIN: CountOrBytes = CountOrBytes { count: 1, bytes: 8 };

pub(crate) fn validate_max_batch_bytes(max_batch_bytes: usize) -> Result<usize, ValidationError> {
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
    Ok(max_batch_bytes)
}

pub(crate) fn validate_max_batch_records(
    max_batch_records: usize,
) -> Result<usize, ValidationError> {
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
    Ok(max_batch_records)
}

/// Tracks automatic `match_seq_num` advancement across records and batches (`A5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchSeqState {
    Unset,
    Next(u64),
    Exhausted,
}

impl MatchSeqState {
    pub(crate) fn from_option(seq: Option<u64>) -> Self {
        match seq {
            Some(n) => Self::Next(n),
            None => Self::Unset,
        }
    }

    pub(crate) fn is_exhausted(self) -> bool {
        matches!(self, Self::Exhausted)
    }

    /// Claim the sequence number for the next record and advance state.
    pub(crate) fn claim_next(&mut self) -> Result<Option<u64>, ValidationError> {
        match *self {
            Self::Unset => Ok(None),
            Self::Next(n) => {
                *self = match n.checked_add(1) {
                    Some(next) => Self::Next(next),
                    None => Self::Exhausted,
                };
                Ok(Some(n))
            }
            Self::Exhausted => Err(ValidationError(
                "match_seq_num overflow: sequence number exceeds u64::MAX".into(),
            )),
        }
    }
}

/// Configuration for [`Batcher`] and [`TryBatcher`].
#[derive(Debug, Clone)]
pub struct BatcherConfig {
    linger: Duration,
    max_batch_records: usize,
    max_batch_bytes: usize,
    fencing_token: Option<FencingToken>,
    match_seq_num: Option<u64>,
}

impl Default for BatcherConfig {
    fn default() -> Self {
        Self {
            linger: Duration::from_millis(5),
            max_batch_records: RECORD_BATCH_MAX.count,
            max_batch_bytes: RECORD_BATCH_MAX.bytes,
            fencing_token: None,
            match_seq_num: None,
        }
    }
}

impl BatcherConfig {
    /// Create a new [`BatcherConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set how long to wait after the first record in a batch arrives before flushing it.
    ///
    /// Defaults to `5ms`.
    pub fn with_linger(self, linger: Duration) -> Self {
        Self { linger, ..self }
    }

    /// Set the maximum number of records per batch.
    ///
    /// **Note:** Must be between `1` and `1000`.
    ///
    /// Defaults to `1000`.
    pub fn with_max_batch_records(self, max_batch_records: usize) -> Result<Self, ValidationError> {
        let max_batch_records = validate_max_batch_records(max_batch_records)?;
        Ok(Self {
            max_batch_records,
            ..self
        })
    }

    /// Set the maximum metered bytes per batch.
    ///
    /// **Note:** Must be between `8` bytes and `1MiB`.
    ///
    /// Defaults to `1MiB`.
    pub fn with_max_batch_bytes(self, max_batch_bytes: usize) -> Result<Self, ValidationError> {
        let max_batch_bytes = validate_max_batch_bytes(max_batch_bytes)?;
        Ok(Self {
            max_batch_bytes,
            ..self
        })
    }

    /// Set the fencing token attached to every emitted [`AppendInput`].
    pub fn with_fencing_token(self, fencing_token: FencingToken) -> Self {
        Self {
            fencing_token: Some(fencing_token),
            ..self
        }
    }

    /// Set the starting `match_seq_num` for the first emitted [`AppendInput`].
    ///
    /// Subsequent batches advance by the previous batch's record count.
    pub fn with_match_seq_num(self, match_seq_num: u64) -> Self {
        Self {
            match_seq_num: Some(match_seq_num),
            ..self
        }
    }

    /// Return the configured linger duration.
    pub fn linger(&self) -> Duration {
        self.linger
    }

    /// Return the configured maximum records per batch.
    pub fn max_batch_records(&self) -> usize {
        self.max_batch_records
    }

    /// Return the configured maximum metered bytes per batch.
    pub fn max_batch_bytes(&self) -> usize {
        self.max_batch_bytes
    }

    /// Return the configured fencing token, if any.
    pub fn fencing_token(&self) -> Option<&FencingToken> {
        self.fencing_token.as_ref()
    }

    /// Return the configured starting `match_seq_num`, if any.
    pub fn match_seq_num(&self) -> Option<u64> {
        self.match_seq_num
    }
}

/// Error yielded by [`TryBatcher`] when either the input stream fails or batch validation fails.
#[derive(Debug, thiserror::Error)]
pub enum TryBatchError<E> {
    /// A record exceeded `max_batch_bytes` or advancing `match_seq_num` overflowed `u64`.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// The underlying record stream yielded an error.
    #[error(transparent)]
    Input(E),
}

pin_project! {
    /// A [`Stream`] that batches [`AppendRecord`]s from an infallible record stream into
    /// [`AppendInput`]s.
    ///
    /// Respects `linger`, `max_batch_records`, and `max_batch_bytes`, attaches optional
    /// `fencing_token` and auto-incrementing `match_seq_num`, and applies backpressure by not
    /// polling the input stream while a completed batch awaits consumption.
    pub struct Batcher<S> {
        #[pin]
        records: S,
        core: BatcherCore,
    }
}

impl<S> Batcher<S> {
    /// Create a new [`Batcher`] over an infallible stream of records.
    pub fn new<R>(records: S, config: BatcherConfig) -> Self
    where
        S: Stream<Item = R>,
        R: Into<AppendRecord>,
    {
        Self {
            records,
            core: BatcherCore::new(config),
        }
    }
}

impl Batcher<futures_util::stream::Empty<AppendRecord>> {
    /// Eagerly batch an in-memory iterator of records into [`AppendInput`]s.
    ///
    /// ```rust
    /// # use s2_sdk::batching::{Batcher, BatcherConfig};
    /// # use s2_sdk::types::AppendRecord;
    /// let records = [AppendRecord::new("one")?, AppendRecord::new("two")?];
    /// let inputs = Batcher::from_iter(records, BatcherConfig::new())?;
    /// assert_eq!(inputs.len(), 1);
    /// # Ok::<(), s2_sdk::types::ValidationError>(())
    /// ```
    pub fn from_iter(
        records: impl IntoIterator<Item = impl Into<AppendRecord>>,
        config: BatcherConfig,
    ) -> Result<Vec<AppendInput>, ValidationError> {
        let iter = records.into_iter();
        let initial_cap = iter.size_hint().0.min(config.max_batch_records);
        let mut inputs = Vec::new();
        let mut batch = Metered::with_capacity(initial_cap);
        let mut batch_match_seq: Option<u64> = None;
        let mut match_seq = MatchSeqState::from_option(config.match_seq_num);

        for item in iter {
            let record = Metered::from(item.into());
            validate_record_size(&record, config.max_batch_bytes)?;

            if !batch.is_empty() && would_overflow(&config, &batch, &record) {
                if match_seq.is_exhausted() {
                    return Err(ValidationError(
                        "match_seq_num overflow: sequence number exceeds u64::MAX".into(),
                    ));
                }
                inputs.push(build_input(
                    std::mem::replace(&mut batch, Metered::with_capacity(0)),
                    batch_match_seq.take(),
                    config.fencing_token.as_ref(),
                ));
            }

            let seq = match_seq.claim_next()?;
            if batch.is_empty() {
                batch_match_seq = seq;
            }
            batch.push(record);

            if is_full(&config, &batch) {
                inputs.push(build_input(
                    std::mem::replace(&mut batch, Metered::with_capacity(0)),
                    batch_match_seq.take(),
                    config.fencing_token.as_ref(),
                ));
            }
        }

        if !batch.is_empty() {
            inputs.push(build_input(
                batch,
                batch_match_seq.take(),
                config.fencing_token.as_ref(),
            ));
        }

        Ok(inputs)
    }

    /// Create a [`TryBatcher`] over a fallible stream of `Result<R, E>` records.
    pub fn try_new<S, R, E>(records: S, config: BatcherConfig) -> TryBatcher<S>
    where
        S: Stream<Item = Result<R, E>>,
        R: Into<AppendRecord>,
    {
        TryBatcher {
            records,
            core: BatcherCore::new(config),
        }
    }
}

impl<S, R> Stream for Batcher<S>
where
    S: Stream<Item = R>,
    R: Into<AppendRecord>,
{
    type Item = Result<AppendInput, ValidationError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        match this
            .core
            .poll_next_with(cx, |cx| match this.records.as_mut().poll_next(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(record)) => Poll::Ready(Some(Ok::<_, Infallible>(record.into()))),
            }) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(input))) => Poll::Ready(Some(Ok(input))),
            Poll::Ready(Some(Err(TryBatchError::Validation(err)))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(Some(Err(TryBatchError::Input(never)))) => match never {},
        }
    }
}

pin_project! {
    /// A [`Stream`] that batches records from a fallible stream (`Result<R, E>`) into
    /// [`AppendInput`]s.
    ///
    /// If the input stream yields an error, any partial batch is dropped and the stream terminates
    /// immediately with [`TryBatchError::Input`].
    pub struct TryBatcher<S> {
        #[pin]
        records: S,
        core: BatcherCore,
    }
}

impl<S> TryBatcher<S> {
    /// Create a new [`TryBatcher`] over a fallible stream of records.
    pub fn new<R, E>(records: S, config: BatcherConfig) -> Self
    where
        S: Stream<Item = Result<R, E>>,
        R: Into<AppendRecord>,
    {
        Self {
            records,
            core: BatcherCore::new(config),
        }
    }
}

impl<S, R, E> Stream for TryBatcher<S>
where
    S: Stream<Item = Result<R, E>>,
    R: Into<AppendRecord>,
{
    type Item = Result<AppendInput, TryBatchError<E>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        this.core
            .poll_next_with(cx, |cx| match this.records.as_mut().poll_next(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(Ok(record))) => Poll::Ready(Some(Ok(record.into()))),
                Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            })
    }
}

impl<S> fmt::Debug for Batcher<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Batcher")
            .field("config", &self.core.config)
            .field("buffered_records", &self.core.batch.len())
            .field("done", &self.core.done)
            .finish_non_exhaustive()
    }
}

impl<S> fmt::Debug for TryBatcher<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TryBatcher")
            .field("config", &self.core.config)
            .field("buffered_records", &self.core.batch.len())
            .field("done", &self.core.done)
            .finish_non_exhaustive()
    }
}

struct BatcherCore {
    config: BatcherConfig,
    batch: Metered<Vec<AppendRecord>>,
    batch_match_seq: Option<u64>,
    match_seq: MatchSeqState,
    overflowed_record: Option<Metered<AppendRecord>>,
    linger_sleep: Option<Pin<Box<Sleep>>>,
    linger_armed: bool,
    done: bool,
}

impl BatcherCore {
    fn new(config: BatcherConfig) -> Self {
        let match_seq = MatchSeqState::from_option(config.match_seq_num);
        Self {
            config,
            batch: Metered::with_capacity(0),
            batch_match_seq: None,
            match_seq,
            overflowed_record: None,
            linger_sleep: None,
            linger_armed: false,
            done: false,
        }
    }

    fn arm_linger(&mut self) {
        if self.config.linger.is_zero() {
            return;
        }
        let Some(deadline) = Instant::now().checked_add(self.config.linger) else {
            return;
        };
        match self.linger_sleep.as_mut() {
            Some(sleep) => sleep.as_mut().reset(deadline),
            None => self.linger_sleep = Some(Box::pin(tokio::time::sleep_until(deadline))),
        }
        self.linger_armed = true;
    }

    fn poll_linger_ready(&mut self, cx: &mut Context<'_>) -> bool {
        self.linger_armed
            && self
                .linger_sleep
                .as_mut()
                .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready())
    }

    fn take_batch(&mut self) -> AppendInput {
        self.linger_armed = false;
        let records = std::mem::replace(&mut self.batch, Metered::with_capacity(0));
        build_input(
            records,
            self.batch_match_seq.take(),
            self.config.fencing_token.as_ref(),
        )
    }

    fn fail<E>(
        &mut self,
        err: TryBatchError<E>,
    ) -> Poll<Option<Result<AppendInput, TryBatchError<E>>>> {
        self.batch = Metered::with_capacity(0);
        self.batch_match_seq = None;
        self.overflowed_record = None;
        self.linger_armed = false;
        self.done = true;
        Poll::Ready(Some(Err(err)))
    }

    fn poll_next_with<E>(
        &mut self,
        cx: &mut Context<'_>,
        mut poll_input: impl FnMut(&mut Context<'_>) -> Poll<Option<Result<AppendRecord, E>>>,
    ) -> Poll<Option<Result<AppendInput, TryBatchError<E>>>> {
        if self.done {
            return Poll::Ready(None);
        }

        // Seed from a previously overflowed record before polling the input again.
        if self.batch.is_empty()
            && let Some(record) = self.overflowed_record.take()
        {
            let seq = match self.match_seq.claim_next() {
                Ok(seq) => seq,
                Err(err) => return self.fail(TryBatchError::Validation(err)),
            };
            self.batch_match_seq = seq;
            self.batch.push(record);
            if is_full(&self.config, &self.batch) {
                return Poll::Ready(Some(Ok(self.take_batch())));
            }
            self.arm_linger();
        }

        loop {
            // For positive linger, flush immediately if the linger deadline has already elapsed
            // before pulling another input record. For zero linger, poll ready input records first
            // so burst submissions coalesce into a single batch within the same tick.
            if !self.batch.is_empty() && !self.config.linger.is_zero() && self.poll_linger_ready(cx)
            {
                return Poll::Ready(Some(Ok(self.take_batch())));
            }

            match poll_input(cx) {
                Poll::Ready(Some(Ok(raw_record))) => {
                    let record = Metered::from(raw_record);
                    if let Err(err) = validate_record_size(&record, self.config.max_batch_bytes) {
                        return self.fail(TryBatchError::Validation(err));
                    }

                    if !self.batch.is_empty() && would_overflow(&self.config, &self.batch, &record)
                    {
                        if self.match_seq.is_exhausted() {
                            return self.fail(TryBatchError::Validation(ValidationError(
                                "match_seq_num overflow: sequence number exceeds u64::MAX".into(),
                            )));
                        }
                        self.overflowed_record = Some(record);
                        return Poll::Ready(Some(Ok(self.take_batch())));
                    }

                    let seq = match self.match_seq.claim_next() {
                        Ok(seq) => seq,
                        Err(err) => return self.fail(TryBatchError::Validation(err)),
                    };
                    if self.batch.is_empty() {
                        self.batch_match_seq = seq;
                    }
                    self.batch.push(record);

                    if is_full(&self.config, &self.batch) {
                        return Poll::Ready(Some(Ok(self.take_batch())));
                    }

                    if !self.linger_armed {
                        self.arm_linger();
                    }
                }
                Poll::Ready(Some(Err(err))) => {
                    return self.fail(TryBatchError::Input(err));
                }
                Poll::Ready(None) => {
                    if !self.batch.is_empty() {
                        self.done = true;
                        return Poll::Ready(Some(Ok(self.take_batch())));
                    }
                    self.done = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    if !self.batch.is_empty()
                        && (self.config.linger.is_zero() || self.poll_linger_ready(cx))
                    {
                        return Poll::Ready(Some(Ok(self.take_batch())));
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

fn validate_record_size(
    record: &Metered<AppendRecord>,
    max_batch_bytes: usize,
) -> Result<(), ValidationError> {
    if record.metered_size() > max_batch_bytes {
        return Err(ValidationError(format!(
            "record size in metered bytes ({}) exceeds max_batch_bytes ({max_batch_bytes})",
            record.metered_size(),
        )));
    }
    Ok(())
}

fn is_full(config: &BatcherConfig, batch: &Metered<Vec<AppendRecord>>) -> bool {
    batch.len() >= config.max_batch_records || batch.metered_size() >= config.max_batch_bytes
}

fn would_overflow(
    config: &BatcherConfig,
    batch: &Metered<Vec<AppendRecord>>,
    record: &Metered<AppendRecord>,
) -> bool {
    batch.len() + 1 > config.max_batch_records
        || batch.metered_size() + record.metered_size() > config.max_batch_bytes
}

fn build_input(
    batch: Metered<Vec<AppendRecord>>,
    match_seq_num: Option<u64>,
    fencing_token: Option<&FencingToken>,
) -> AppendInput {
    AppendInput {
        records: AppendRecordBatch::from(batch),
        match_seq_num,
        fencing_token: fencing_token.cloned(),
        stream_config: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use assert_matches::assert_matches;
    use futures_util::{StreamExt, TryStreamExt};

    use super::*;
    use crate::types::MeteredBytes as _;

    #[tokio::test]
    async fn batches_should_be_empty_when_record_stream_is_empty() {
        let batches: Vec<_> = Batcher::new(
            futures_util::stream::iter::<Vec<AppendRecord>>(vec![]),
            BatcherConfig::new(),
        )
        .collect()
        .await;
        assert!(batches.is_empty());
    }

    #[tokio::test]
    async fn batches_respect_count_limit_and_advance_match_seq_num() -> Result<(), ValidationError>
    {
        let records: Vec<_> = (0..10)
            .map(|i| AppendRecord::new(format!("record{i}")))
            .collect::<Result<_, _>>()?;
        let token: FencingToken = "tok".parse()?;
        let config = BatcherConfig::new()
            .with_max_batch_records(3)?
            .with_fencing_token(token.clone())
            .with_match_seq_num(10);
        let inputs: Vec<_> = Batcher::new(futures_util::stream::iter(records), config)
            .try_collect()
            .await?;

        assert_eq!(inputs.len(), 4);
        assert_eq!(inputs[0].records.len(), 3);
        assert_eq!(inputs[0].match_seq_num, Some(10));
        assert_eq!(inputs[0].fencing_token.as_ref(), Some(&token));
        assert_eq!(inputs[1].records.len(), 3);
        assert_eq!(inputs[1].match_seq_num, Some(13));
        assert_eq!(inputs[2].records.len(), 3);
        assert_eq!(inputs[2].match_seq_num, Some(16));
        assert_eq!(inputs[3].records.len(), 1);
        assert_eq!(inputs[3].match_seq_num, Some(19));

        Ok(())
    }

    #[tokio::test]
    async fn batches_respect_bytes_limit() -> Result<(), ValidationError> {
        let records: Vec<_> = (0..10)
            .map(|i| AppendRecord::new(format!("record{i}")))
            .collect::<Result<_, _>>()?;
        let single_record_bytes = records[0].metered_bytes();
        let max_batch_bytes = single_record_bytes * 3;

        let config = BatcherConfig::new().with_max_batch_bytes(max_batch_bytes)?;
        let inputs: Vec<_> = Batcher::new(futures_util::stream::iter(records), config)
            .try_collect()
            .await?;

        assert_eq!(inputs.len(), 4);
        assert_eq!(inputs[0].records.metered_bytes(), max_batch_bytes);
        assert_eq!(inputs[1].records.metered_bytes(), max_batch_bytes);
        assert_eq!(inputs[2].records.metered_bytes(), max_batch_bytes);
        assert_eq!(inputs[3].records.metered_bytes(), single_record_bytes);

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn batches_flush_after_linger_when_stream_remains_open() -> Result<(), ValidationError> {
        let records: Vec<_> = (0..2)
            .map(|i| AppendRecord::new(format!("record{i}")))
            .collect::<Result<_, _>>()?;
        let records = futures_util::stream::iter(records).chain(futures_util::stream::pending());
        let config = BatcherConfig::new().with_linger(Duration::from_millis(5));
        let mut batcher = Batcher::new(records, config);
        let next_batch = tokio::spawn(async move { batcher.next().await });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(6)).await;

        let input = next_batch.await.unwrap().unwrap()?;
        assert_eq!(input.records.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn oversized_record_drops_partial_batch_and_errors_immediately()
    -> Result<(), ValidationError> {
        let small = AppendRecord::new("ok")?; // 10 metered bytes
        let oversized = AppendRecord::new("hello-world-too-big")?;
        let record_bytes = oversized.metered_bytes();
        let max_batch_bytes = 20;

        let config = BatcherConfig::new().with_max_batch_bytes(max_batch_bytes)?;
        let results: Vec<_> =
            Batcher::new(futures_util::stream::iter(vec![small, oversized]), config)
                .collect()
                .await;

        // Partial batch containing `small` MUST be dropped and error surfaced immediately (A5b).
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
    async fn batcher_does_not_read_input_while_completed_batch_waits() -> Result<(), ValidationError>
    {
        let polls = Arc::new(AtomicUsize::new(0));
        let polls_clone = polls.clone();
        let stream = futures_util::stream::poll_fn(move |_cx| {
            let n = polls_clone.fetch_add(1, Ordering::SeqCst);
            if n < 10 {
                Poll::Ready(Some(AppendRecord::new(format!("r{n}")).unwrap()))
            } else {
                Poll::Ready(None)
            }
        });
        let config = BatcherConfig::new().with_max_batch_records(2)?;
        let mut batcher = Batcher::new(stream, config);

        let first = batcher.next().await.unwrap()?;
        assert_eq!(first.records.len(), 2);
        assert_eq!(
            polls.load(Ordering::SeqCst),
            2,
            "A5b: must not read ahead past completed batch"
        );

        let second = batcher.next().await.unwrap()?;
        assert_eq!(second.records.len(), 2);
        assert_eq!(polls.load(Ordering::SeqCst), 4);

        Ok(())
    }

    #[tokio::test]
    async fn match_seq_num_overflow_ends_batcher_with_validation_error()
    -> Result<(), ValidationError> {
        // Exactly reaching u64::MAX is valid.
        let r0 = AppendRecord::new("a")?;
        let r1 = AppendRecord::new("b")?;
        let config = BatcherConfig::new()
            .with_max_batch_records(1)?
            .with_match_seq_num(u64::MAX - 1);
        let inputs: Vec<_> = Batcher::new(
            futures_util::stream::iter(vec![r0.clone(), r1.clone()]),
            config.clone(),
        )
        .try_collect()
        .await?;
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].match_seq_num, Some(u64::MAX - 1));
        assert_eq!(inputs[1].match_seq_num, Some(u64::MAX));

        // Adding a third record overflows u64::MAX.
        let r2 = AppendRecord::new("c")?;
        let results: Vec<_> = Batcher::new(futures_util::stream::iter(vec![r0, r1, r2]), config)
            .collect()
            .await;
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(results[2].is_err());

        Ok(())
    }

    #[tokio::test]
    async fn try_batcher_drops_partial_batch_on_input_error() -> Result<(), ValidationError> {
        let items: Vec<Result<AppendRecord, &'static str>> = vec![
            Ok(AppendRecord::new("ok")?),
            Err("boom"),
            Ok(AppendRecord::new("never-seen")?),
        ];
        let results: Vec<_> =
            Batcher::try_new(futures_util::stream::iter(items), BatcherConfig::new())
                .collect()
                .await;
        assert_eq!(results.len(), 1);
        assert_matches!(results[0], Err(TryBatchError::Input("boom")));
        Ok(())
    }

    #[test]
    fn from_iter_batches_and_validates() -> Result<(), ValidationError> {
        assert!(
            Batcher::from_iter(std::iter::empty::<AppendRecord>(), BatcherConfig::new())?
                .is_empty()
        );
        let records: Vec<_> = (0..5)
            .map(|i| AppendRecord::new(format!("r{i}")))
            .collect::<Result<_, _>>()?;
        let config = BatcherConfig::new()
            .with_max_batch_records(2)?
            .with_match_seq_num(100);
        let inputs = Batcher::from_iter(records, config)?;
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs[0].match_seq_num, Some(100));
        assert_eq!(inputs[1].match_seq_num, Some(102));
        assert_eq!(inputs[2].match_seq_num, Some(104));

        let err = Batcher::from_iter(
            [AppendRecord::new("hello-world")?],
            BatcherConfig::new().with_max_batch_bytes(10)?,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds max_batch_bytes"));
        Ok(())
    }

    #[test]
    fn batcher_constructible_outside_tokio_runtime() {
        let batcher = Batcher::new(
            futures_util::stream::empty::<AppendRecord>(),
            BatcherConfig::new().with_linger(Duration::MAX),
        );
        let debug = format!("{batcher:?}");
        assert!(debug.contains("Batcher"));
    }
}
