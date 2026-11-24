//! Utilities for batching [`AppendRecord`]s into [`AppendInput`]s.

use std::{
    convert::Infallible,
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::{FusedStream, Stream};
use pin_project_lite::pin_project;
use s2_common::read_extent::CountOrBytes;
use tokio::time::{Instant, Sleep};

use crate::{
    error::ValidationError,
    types::{AppendInput, AppendRecord, AppendRecordBatch, FencingToken, RECORD_BATCH_MAX},
};

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

pub(crate) fn validate_record_size(
    metered_bytes: usize,
    max_batch_bytes: usize,
) -> Result<(), ValidationError> {
    if metered_bytes > max_batch_bytes {
        return Err(ValidationError(format!(
            "record size in metered bytes ({metered_bytes}) exceeds max_batch_bytes ({max_batch_bytes})",
        )));
    }
    Ok(())
}

/// Tracks automatic `match_seq_num` advancement across records and batches (`A5`).
///
/// Accepting a record at `seq_num = n` produces a batch whose `end` sequence number is at least
/// `n + 1`, so `n` must be strictly less than `u64::MAX` (`A5`, `D5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchSeqState {
    Unset,
    Next(u64),
    Exhausted,
}

impl MatchSeqState {
    pub(crate) fn from_option(seq: Option<u64>) -> Self {
        match seq {
            Some(u64::MAX) => Self::Exhausted,
            Some(n) => Self::Next(n),
            None => Self::Unset,
        }
    }

    pub(crate) fn is_exhausted(self) -> bool {
        matches!(self, Self::Exhausted)
    }

    pub(crate) fn check_available(self) -> Result<(), ValidationError> {
        if self.is_exhausted() {
            Err(ValidationError(
                "match_seq_num overflow: batch end sequence number exceeds u64::MAX".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Claim the sequence number for the next record and advance state (`A5`).
    pub(crate) fn claim_next(&mut self) -> Result<Option<u64>, ValidationError> {
        self.check_available()?;
        match *self {
            Self::Unset => Ok(None),
            Self::Next(n) => {
                let end = n + 1;
                *self = if end == u64::MAX {
                    Self::Exhausted
                } else {
                    Self::Next(end)
                };
                Ok(Some(n))
            }
            Self::Exhausted => unreachable!("checked above"),
        }
    }
}

/// Configuration for [`Batcher`], [`TryBatcher`], [`batch_iter`], and [`try_batch_iter`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
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

    /// Return the configured linger duration.
    #[must_use]
    pub fn linger(&self) -> Duration {
        self.linger
    }

    /// Return the configured maximum records per batch.
    #[must_use]
    pub fn max_batch_records(&self) -> usize {
        self.max_batch_records
    }

    /// Return the configured maximum metered bytes per batch.
    #[must_use]
    pub fn max_batch_bytes(&self) -> usize {
        self.max_batch_bytes
    }

    /// Return the configured fencing token, if any.
    #[must_use]
    pub fn fencing_token(&self) -> Option<&FencingToken> {
        self.fencing_token.as_ref()
    }

    /// Return the configured starting `match_seq_num`, if any.
    #[must_use]
    pub fn match_seq_num(&self) -> Option<u64> {
        self.match_seq_num
    }

    /// Set how long to wait after the first record in a batch arrives before flushing it.
    ///
    /// Defaults to `5ms`. Ignored by [`batch_iter`] and [`try_batch_iter`].
    pub fn with_linger(self, linger: Duration) -> Self {
        Self { linger, ..self }
    }

    /// Set the maximum number of records per batch.
    ///
    /// Defaults to `1000`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `max_batch_records` is outside `1..=1000`.
    pub fn with_max_batch_records(self, max_batch_records: usize) -> Result<Self, ValidationError> {
        let max_batch_records = validate_max_batch_records(max_batch_records)?;
        Ok(Self {
            max_batch_records,
            ..self
        })
    }

    /// Set the maximum metered bytes per batch.
    ///
    /// Defaults to `1 MiB`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if `max_batch_bytes` is outside `8..=1_048_576`.
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
}

/// Error yielded by [`TryBatcher`] or [`try_batch_iter`] when either the input fails or batch
/// validation fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TryBatchError<E> {
    /// A record exceeded `max_batch_bytes` or advancing `match_seq_num` overflowed `u64`.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// The underlying record source yielded an error.
    #[error(transparent)]
    Input(E),
}

/// Eagerly batch an in-memory iterator of records into [`AppendInput`]s.
///
/// Respects `max_batch_records`, `max_batch_bytes`, `fencing_token`, and auto-incrementing
/// `match_seq_num` from `config` (`linger` does not apply to an already-materialized iterator).
///
/// # Errors
///
/// Returns [`ValidationError`] if any record exceeds `max_batch_bytes` or if advancing
/// `match_seq_num` overflows `u64`.
///
/// ```rust
/// # use s2_sdk::batching::{BatcherConfig, batch_iter};
/// # use s2_sdk::types::AppendRecord;
/// let records = [AppendRecord::new("one")?, AppendRecord::new("two")?];
/// let inputs = batch_iter(records, BatcherConfig::new())?;
/// assert_eq!(inputs.len(), 1);
/// # Ok::<(), s2_sdk::error::ValidationError>(())
/// ```
pub fn batch_iter(
    records: impl IntoIterator<Item = impl Into<AppendRecord>>,
    config: BatcherConfig,
) -> Result<Vec<AppendInput>, ValidationError> {
    match try_batch_iter(records.into_iter().map(Ok::<_, Infallible>), config) {
        Ok(inputs) => Ok(inputs),
        Err(TryBatchError::Validation(err)) => Err(err),
        Err(TryBatchError::Input(never)) => match never {},
    }
}

/// Eagerly batch a fallible in-memory iterator of records into [`AppendInput`]s.
///
/// Respects `max_batch_records`, `max_batch_bytes`, `fencing_token`, and auto-incrementing
/// `match_seq_num` from `config` (`linger` does not apply to an already-materialized iterator).
///
/// # Errors
///
/// Returns [`TryBatchError::Input`] on the first input error, or [`TryBatchError::Validation`] if
/// any record exceeds `max_batch_bytes` or advancing `match_seq_num` overflows `u64`.
pub fn try_batch_iter<R, E>(
    records: impl IntoIterator<Item = Result<R, E>>,
    config: BatcherConfig,
) -> Result<Vec<AppendInput>, TryBatchError<E>>
where
    R: Into<AppendRecord>,
{
    if let Some(ref token) = config.fencing_token {
        token.validate()?;
    }
    let iter = records.into_iter();
    let initial_cap = iter.size_hint().0.min(config.max_batch_records);
    let mut inputs = Vec::new();
    let mut match_seq = MatchSeqState::from_option(config.match_seq_num);
    let mut acc = BatchAccumulator::with_capacity(
        config.max_batch_records,
        config.max_batch_bytes,
        config.fencing_token,
        initial_cap,
    );

    for item in iter {
        let record = item.map_err(TryBatchError::Input)?.into();
        record.validate_for_write()?;
        let record_bytes = record.metered_bytes();
        validate_record_size(record_bytes, config.max_batch_bytes)?;

        if !acc.is_empty() && acc.would_overflow(record_bytes) {
            inputs.push(acc.take());
        }

        let seq = match_seq.claim_next()?;
        acc.push(record, record_bytes, seq);

        if acc.is_full() {
            inputs.push(acc.take());
        }
    }

    if !acc.is_empty() {
        inputs.push(acc.take());
    }

    Ok(inputs)
}

pin_project! {
    /// A [`Stream`] that batches [`AppendRecord`]s from an infallible record stream into
    /// [`AppendInput`]s.
    ///
    /// Respects `linger`, `max_batch_records`, and `max_batch_bytes`, attaches optional
    /// `fencing_token` and auto-incrementing `match_seq_num`, and applies backpressure by not
    /// polling the input stream while a completed batch awaits consumption.
    ///
    /// Provides an inherent [`next`](Self::next) method when `S: Unpin` so callers do not need to
    /// import `StreamExt`.
    #[must_use = "streams do nothing unless polled"]
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

    /// Return the next completed batch, or `None` when the input stream ends.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe and can be used inside [`tokio::select!`].
    pub async fn next<R>(&mut self) -> Option<Result<AppendInput, ValidationError>>
    where
        S: Stream<Item = R> + Unpin,
        R: Into<AppendRecord>,
    {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
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

impl<S, R> FusedStream for Batcher<S>
where
    S: Stream<Item = R>,
    R: Into<AppendRecord>,
{
    fn is_terminated(&self) -> bool {
        self.core.terminated
    }
}

pin_project! {
    /// A [`Stream`] that batches records from a fallible stream (`Result<R, E>`) into
    /// [`AppendInput`]s.
    ///
    /// If the input stream yields an error, any partial batch is dropped and the stream terminates
    /// immediately with [`TryBatchError::Input`].
    ///
    /// Provides an inherent [`next`](Self::next) method when `S: Unpin` so callers do not need to
    /// import `StreamExt`.
    #[must_use = "streams do nothing unless polled"]
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

    /// Return the next completed batch, or `None` when the input stream ends.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe and can be used inside [`tokio::select!`].
    pub async fn next<R, E>(&mut self) -> Option<Result<AppendInput, TryBatchError<E>>>
    where
        S: Stream<Item = Result<R, E>> + Unpin,
        R: Into<AppendRecord>,
    {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
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

impl<S, R, E> FusedStream for TryBatcher<S>
where
    S: Stream<Item = Result<R, E>>,
    R: Into<AppendRecord>,
{
    fn is_terminated(&self) -> bool {
        self.core.terminated
    }
}

impl<S> fmt::Debug for Batcher<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Batcher")
            .field("config", &self.core.config)
            .field("buffered_records", &self.core.acc.len())
            .field("terminated", &self.core.terminated)
            .finish_non_exhaustive()
    }
}

impl<S> fmt::Debug for TryBatcher<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TryBatcher")
            .field("config", &self.core.config)
            .field("buffered_records", &self.core.acc.len())
            .field("terminated", &self.core.terminated)
            .finish_non_exhaustive()
    }
}

pub(crate) struct BatchAccumulator {
    max_batch_records: usize,
    max_batch_bytes: usize,
    fencing_token: Option<FencingToken>,
    records: Vec<AppendRecord>,
    metered_bytes: usize,
    batch_match_seq: Option<u64>,
}

impl BatchAccumulator {
    pub(crate) fn with_capacity(
        max_batch_records: usize,
        max_batch_bytes: usize,
        fencing_token: Option<FencingToken>,
        cap: usize,
    ) -> Self {
        Self {
            max_batch_records,
            max_batch_bytes,
            fencing_token,
            records: Vec::with_capacity(cap),
            metered_bytes: 0,
            batch_match_seq: None,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.records.len() >= self.max_batch_records || self.metered_bytes >= self.max_batch_bytes
    }

    pub(crate) fn would_overflow(&self, record_bytes: usize) -> bool {
        self.records.len() + 1 > self.max_batch_records
            || self.metered_bytes + record_bytes > self.max_batch_bytes
    }

    pub(crate) fn push(
        &mut self,
        record: AppendRecord,
        record_bytes: usize,
        match_seq_num: Option<u64>,
    ) {
        if self.records.is_empty() {
            self.batch_match_seq = match_seq_num;
        }
        self.metered_bytes += record_bytes;
        self.records.push(record);
    }

    pub(crate) fn take(&mut self) -> AppendInput {
        let next_cap = self.records.len().min(self.max_batch_records);
        let records = std::mem::replace(&mut self.records, Vec::with_capacity(next_cap));
        let metered_bytes = std::mem::take(&mut self.metered_bytes);
        let mut input = AppendInput::new(AppendRecordBatch::from_parts(records, metered_bytes));
        if let Some(seq) = self.batch_match_seq.take() {
            input = input.with_match_seq_num(seq);
        }
        if let Some(ref token) = self.fencing_token {
            input = input.with_fencing_token(token.clone());
        }
        input
    }

    pub(crate) fn clear(&mut self) {
        self.records = Vec::new();
        self.metered_bytes = 0;
        self.batch_match_seq = None;
    }
}

/// Reusable linger timer shared by [`BatcherCore`] and [`Producer`](crate::producer::Producer).
///
/// Tracks the logical deadline separately from the Tokio timer wheel so records arriving before
/// the deadline never reset a `Sleep` unnecessarily.
pub(crate) struct Linger {
    duration: Duration,
    deadline: Option<Instant>,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl Linger {
    pub(crate) fn new(duration: Duration) -> Self {
        Self {
            duration,
            deadline: None,
            sleep: None,
        }
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.duration.is_zero()
    }

    pub(crate) fn arm_from(&mut self, started_at: Instant) {
        if !self.duration.is_zero() {
            self.deadline = started_at.checked_add(self.duration);
        }
    }

    pub(crate) fn arm_now(&mut self) {
        self.arm_from(Instant::now());
    }

    pub(crate) fn disarm(&mut self) {
        self.deadline = None;
    }

    pub(crate) fn elapsed(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    fn ensure_sleep(&mut self) -> Option<Pin<&mut Sleep>> {
        let deadline = self.deadline?;
        let sleep = self
            .sleep
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        if sleep.deadline() != deadline {
            sleep.as_mut().reset(deadline);
        }
        Some(sleep.as_mut())
    }

    pub(crate) fn poll_sleep(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(deadline) = self.deadline else {
            return false;
        };
        if Instant::now() >= deadline {
            return true;
        }
        self.ensure_sleep()
            .is_some_and(|sleep| sleep.poll(cx).is_ready())
    }

    pub(crate) fn is_armed(&self) -> bool {
        self.deadline.is_some()
    }

    pub(crate) async fn wait(&mut self) {
        match self.ensure_sleep() {
            Some(sleep) => sleep.await,
            None => std::future::pending().await,
        }
    }
}

struct BatcherCore {
    config: BatcherConfig,
    acc: BatchAccumulator,
    match_seq: MatchSeqState,
    overflowed_record: Option<(AppendRecord, usize, Instant)>,
    linger: Linger,
    exhausted: bool,
    terminated: bool,
}

impl BatcherCore {
    fn new(config: BatcherConfig) -> Self {
        let match_seq = MatchSeqState::from_option(config.match_seq_num);
        let acc = BatchAccumulator::with_capacity(
            config.max_batch_records,
            config.max_batch_bytes,
            config.fencing_token.clone(),
            0,
        );
        let linger = Linger::new(config.linger);
        Self {
            config,
            acc,
            match_seq,
            overflowed_record: None,
            linger,
            exhausted: false,
            terminated: false,
        }
    }

    fn push_record(
        &mut self,
        record: AppendRecord,
        record_bytes: usize,
    ) -> Result<(), ValidationError> {
        let seq = self.match_seq.claim_next()?;
        self.acc.push(record, record_bytes, seq);
        Ok(())
    }

    fn take_batch(&mut self) -> AppendInput {
        self.linger.disarm();
        self.acc.take()
    }

    fn fail<E>(
        &mut self,
        err: TryBatchError<E>,
    ) -> Poll<Option<Result<AppendInput, TryBatchError<E>>>> {
        self.acc.clear();
        self.overflowed_record = None;
        self.linger.disarm();
        self.exhausted = true;
        Poll::Ready(Some(Err(err)))
    }

    fn poll_next_with<E>(
        &mut self,
        cx: &mut Context<'_>,
        mut poll_input: impl FnMut(&mut Context<'_>) -> Poll<Option<Result<AppendRecord, E>>>,
    ) -> Poll<Option<Result<AppendInput, TryBatchError<E>>>> {
        if self.exhausted {
            self.terminated = true;
            return Poll::Ready(None);
        }
        if let Some(ref token) = self.config.fencing_token
            && let Err(err) = token.validate()
        {
            return self.fail(TryBatchError::Validation(err));
        }

        // Seed from a previously overflowed record before polling the input again.
        if self.acc.is_empty()
            && let Some((record, record_bytes, arrived_at)) = self.overflowed_record.take()
        {
            if let Err(err) = self.push_record(record, record_bytes) {
                return self.fail(TryBatchError::Validation(err));
            }
            if self.acc.is_full() {
                return Poll::Ready(Some(Ok(self.take_batch())));
            }
            self.linger.arm_from(arrived_at);
        }

        loop {
            // For positive linger, flush immediately if the linger deadline has already elapsed
            // before pulling another input record (without touching the timer wheel per record).
            // For zero linger, poll ready input records first so burst submissions coalesce into a
            // single batch within the same tick.
            if !self.acc.is_empty() && !self.linger.is_zero() && self.linger.elapsed() {
                return Poll::Ready(Some(Ok(self.take_batch())));
            }

            match poll_input(cx) {
                Poll::Ready(Some(Ok(record))) => {
                    if let Err(err) = record.validate_for_write() {
                        return self.fail(TryBatchError::Validation(err));
                    }
                    let record_bytes = record.metered_bytes();
                    if let Err(err) =
                        validate_record_size(record_bytes, self.config.max_batch_bytes)
                    {
                        return self.fail(TryBatchError::Validation(err));
                    }

                    // Flush any valid pending batch before either overflowing batch limits or
                    // triggering a `match_seq_num` overflow error (`A5b`).
                    if !self.acc.is_empty()
                        && (self.acc.would_overflow(record_bytes) || self.match_seq.is_exhausted())
                    {
                        self.overflowed_record = Some((record, record_bytes, Instant::now()));
                        return Poll::Ready(Some(Ok(self.take_batch())));
                    }

                    let was_empty = self.acc.is_empty();
                    if let Err(err) = self.push_record(record, record_bytes) {
                        return self.fail(TryBatchError::Validation(err));
                    }

                    if self.acc.is_full() {
                        return Poll::Ready(Some(Ok(self.take_batch())));
                    }

                    if was_empty {
                        self.linger.arm_now();
                    }
                }
                Poll::Ready(Some(Err(err))) => {
                    return self.fail(TryBatchError::Input(err));
                }
                Poll::Ready(None) => {
                    if !self.acc.is_empty() {
                        self.exhausted = true;
                        return Poll::Ready(Some(Ok(self.take_batch())));
                    }
                    self.exhausted = true;
                    self.terminated = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    if !self.acc.is_empty() && (self.linger.is_zero() || self.linger.poll_sleep(cx))
                    {
                        return Poll::Ready(Some(Ok(self.take_batch())));
                    }
                    return Poll::Pending;
                }
            }
        }
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

    // spec: r1 A5, A5b
    #[tokio::test]
    async fn batches_respect_count_limit_and_advance_match_seq_num() -> Result<(), ValidationError>
    {
        let empty: Vec<_> = Batcher::new(
            futures_util::stream::iter(Vec::<AppendRecord>::new()),
            BatcherConfig::new(),
        )
        .collect()
        .await;
        assert!(empty.is_empty());

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
        assert_eq!(inputs[0].records().len(), 3);
        assert_eq!(inputs[0].match_seq_num(), Some(10));
        assert_eq!(inputs[0].fencing_token(), Some(&token));
        assert_eq!(inputs[1].records().len(), 3);
        assert_eq!(inputs[1].match_seq_num(), Some(13));
        assert_eq!(inputs[2].records().len(), 3);
        assert_eq!(inputs[2].match_seq_num(), Some(16));
        assert_eq!(inputs[3].records().len(), 1);
        assert_eq!(inputs[3].match_seq_num(), Some(19));

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
        assert_eq!(inputs[0].metered_bytes(), max_batch_bytes);
        assert_eq!(inputs[1].metered_bytes(), max_batch_bytes);
        assert_eq!(inputs[2].metered_bytes(), max_batch_bytes);
        assert_eq!(inputs[3].metered_bytes(), single_record_bytes);

        Ok(())
    }

    // spec: r1 A5, A5b
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
        assert_eq!(input.records().len(), 2);
        Ok(())
    }

    // spec: r1 A5b
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

    // spec: r1 A5b
    #[tokio::test]
    async fn batcher_does_not_read_input_while_completed_batch_waits() -> Result<(), ValidationError>
    {
        let polls = Arc::new(AtomicUsize::new(0));
        let polls_clone = polls.clone();
        let source = futures_util::stream::iter(0..5).map(move |i| {
            polls_clone.fetch_add(1, Ordering::SeqCst);
            AppendRecord::new(format!("r{i}")).unwrap()
        });

        let config = BatcherConfig::new().with_max_batch_records(2)?;
        let mut batcher = Batcher::new(source, config);

        let first = batcher.next().await.unwrap()?;
        assert_eq!(first.records().len(), 2);
        // Must have polled only the 2 records needed for the first batch (A5b backpressure).
        assert_eq!(polls.load(Ordering::SeqCst), 2);

        let second = batcher.next().await.unwrap()?;
        assert_eq!(second.records().len(), 2);
        assert_eq!(polls.load(Ordering::SeqCst), 4);

        let third = batcher.next().await.unwrap()?;
        assert_eq!(third.records().len(), 1);
        assert_eq!(polls.load(Ordering::SeqCst), 5);
        assert!(batcher.next().await.is_none());
        Ok(())
    }

    // spec: r1 A5, A5b
    #[tokio::test]
    async fn match_seq_num_overflow_flushes_valid_batch_then_errors() -> Result<(), ValidationError>
    {
        let records: Vec<_> = (0..3)
            .map(|i| AppendRecord::new(format!("r{i}")))
            .collect::<Result<_, _>>()?;
        let config = BatcherConfig::new()
            .with_max_batch_records(5)?
            .with_match_seq_num(u64::MAX - 2);
        let results: Vec<_> = Batcher::new(futures_util::stream::iter(records), config)
            .collect()
            .await;

        // First two records have seq_num u64::MAX - 2 and u64::MAX - 1 (end = u64::MAX), valid.
        // The third record would push end past u64::MAX, so the valid 2-record batch is
        // emitted first and the third record yields a ValidationError (`A5`, `A5b`).
        assert_eq!(results.len(), 2);
        assert_matches!(&results[0], Ok(input) => {
            assert_eq!(input.records().len(), 2);
            assert_eq!(input.match_seq_num(), Some(u64::MAX - 2));
        });
        assert_matches!(&results[1], Err(err) => {
            assert!(err.to_string().contains("match_seq_num"));
        });

        // Starting directly at u64::MAX overflows on the first record.
        let overflow_first: Vec<_> = Batcher::new(
            futures_util::stream::iter([AppendRecord::new("x")?]),
            BatcherConfig::new().with_match_seq_num(u64::MAX),
        )
        .collect()
        .await;
        assert_eq!(overflow_first.len(), 1);
        assert!(overflow_first[0].is_err());
        Ok(())
    }

    // spec: r1 A5b
    #[tokio::test]
    async fn try_batcher_drops_partial_batch_on_input_error() -> Result<(), ValidationError> {
        let items: Vec<Result<AppendRecord, &'static str>> =
            vec![Ok(AppendRecord::new("ok")?), Err("boom")];
        let mut batcher = TryBatcher::new(futures_util::stream::iter(items), BatcherConfig::new());

        assert!(!batcher.is_terminated());
        assert_matches!(
            batcher.next().await,
            Some(Err(TryBatchError::Input("boom")))
        );
        assert!(!batcher.is_terminated());
        assert!(batcher.next().await.is_none());
        assert!(batcher.is_terminated());
        Ok(())
    }

    #[test]
    fn batch_iter_and_try_batch_iter_batch_in_memory() -> Result<(), ValidationError> {
        let records: Vec<_> = (0..5)
            .map(|i| AppendRecord::new(format!("r{i}")))
            .collect::<Result<_, _>>()?;
        let inputs = batch_iter(
            records.clone(),
            BatcherConfig::new()
                .with_max_batch_records(2)?
                .with_match_seq_num(100),
        )?;
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs[0].match_seq_num(), Some(100));
        assert_eq!(inputs[1].match_seq_num(), Some(102));
        assert_eq!(inputs[2].match_seq_num(), Some(104));

        let err = try_batch_iter([Ok(records[0].clone()), Err("boom")], BatcherConfig::new())
            .unwrap_err();
        assert_eq!(err, TryBatchError::Input("boom"));
        Ok(())
    }
}
