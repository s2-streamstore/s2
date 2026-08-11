//! High-level producer for appending records to streams.
//!
//! See [`Producer`].

use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};

use futures_util::{FutureExt, StreamExt, TryFutureExt, stream::FuturesUnordered};
use s2_common::caps::RECORD_BATCH_MAX;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    api::BasinClient,
    batching::{AppendInputs, AppendRecordBatches, BatchingConfig},
    error::ProducerError,
    session::{AppendPermit, AppendPermits, AppendSessionInternal, BatchSubmitTicket},
    types::{
        AppendAck, AppendRecord, EncryptionKey, FencingToken, MeteredBytes, ONE_MIB, StreamName,
        ValidationError,
    },
};

/// A [`Future`] that resolves to an acknowledgement once the record is appended.
pub struct RecordSubmitTicket {
    rx: oneshot::Receiver<Result<IndexedAppendAck, ProducerError>>,
    terminal_err: Arc<OnceLock<ProducerError>>,
}

impl Future for RecordSubmitTicket {
    type Output = Result<IndexedAppendAck, ProducerError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(res)) => Poll::Ready(res),
            Poll::Ready(Err(_)) => Poll::Ready(Err(self
                .terminal_err
                .get()
                .cloned()
                .unwrap_or(ProducerError::ProducerDropped))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Acknowledgement for an appended record.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IndexedAppendAck {
    /// Sequence number assigned to the record.
    pub seq_num: u64,
    /// Acknowledgement for the containing batch.
    pub batch: AppendAck,
}

impl IndexedAppendAck {
    /// Construct an acknowledgement for an appended record.
    ///
    /// This is intended for building fixtures in downstream tests.
    pub fn new(seq_num: u64, batch: AppendAck) -> Self {
        Self { seq_num, batch }
    }
}

/// Configuration for a [`Producer`].
#[derive(Debug, Clone)]
pub struct ProducerConfig {
    max_unacked_bytes: u32,
    batching: BatchingConfig,
    fencing_token: Option<FencingToken>,
    match_seq_num: Option<u64>,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            max_unacked_bytes: 5 * ONE_MIB,
            batching: BatchingConfig::default(),
            fencing_token: None,
            match_seq_num: None,
        }
    }
}

impl ProducerConfig {
    /// Create a new [`ProducerConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the limit on total metered bytes of unacknowledged [`AppendRecord`]s held in memory.
    ///
    /// **Note:** It must be at least `1MiB`.
    ///
    /// Defaults to `5MiB`.
    pub fn with_max_unacked_bytes(self, max_unacked_bytes: u32) -> Result<Self, ValidationError> {
        if max_unacked_bytes < ONE_MIB {
            return Err(format!("max_unacked_bytes must be at least {ONE_MIB}").into());
        }
        Ok(Self {
            max_unacked_bytes,
            ..self
        })
    }

    /// Set the configuration for batching records into [`AppendInput`](crate::types::AppendInput)s
    /// before appending.
    ///
    /// See [`BatchingConfig`] for defaults.
    pub fn with_batching(self, batching: BatchingConfig) -> Self {
        Self { batching, ..self }
    }

    /// Set the fencing token for all [`AppendInput`](crate::types::AppendInput)s.
    ///
    /// Defaults to `None`.
    pub fn with_fencing_token(self, fencing_token: FencingToken) -> Self {
        Self {
            fencing_token: Some(fencing_token),
            ..self
        }
    }

    /// Set the match sequence number for the initial [`AppendInput`](crate::types::AppendInput). It
    /// will be auto-incremented for subsequent ones.
    ///
    /// Defaults to `None`.
    pub fn with_match_seq_num(self, match_seq_num: u64) -> Self {
        Self {
            match_seq_num: Some(match_seq_num),
            ..self
        }
    }
}

/// High-level interface for submitting individual [`AppendRecord`]s.
///
/// Handles batching of records into [`AppendInput`](crate::types::AppendInput)s automatically based
/// on the provided [`configuration`](ProducerConfig), and uses an append session internally.
pub struct Producer {
    cmd_tx: mpsc::Sender<Command>,
    permits: AppendPermits,
    terminal_err: Arc<OnceLock<ProducerError>>,
    _handle: AbortOnDropHandle<()>,
}

impl Producer {
    pub(crate) fn new(
        client: BasinClient,
        stream: StreamName,
        encryption: Option<EncryptionKey>,
        config: ProducerConfig,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(RECORD_BATCH_MAX.count);
        let permits = AppendPermits::new(None, config.max_unacked_bytes);
        let session = AppendSessionInternal::new(client, stream, encryption);
        let terminal_err = Arc::new(OnceLock::new());
        let _handle = AbortOnDropHandle::new(tokio::spawn(Self::run(
            session,
            config,
            cmd_rx,
            terminal_err.clone(),
        )));
        Self {
            cmd_tx,
            permits,
            terminal_err,
            _handle,
        }
    }

    /// Submit a record for appending.
    ///
    /// Internally, it waits on [`reserve`](Self::reserve), then submits using the permit.
    /// This provides backpressure when the unacknowledged bytes limit is reached.
    /// For explicit control, use [`reserve`](Self::reserve) followed by
    /// [`RecordSubmitPermit::submit`].
    ///
    /// Use [`flush`](Self::flush) to establish a non-terminal durability boundary, and call
    /// [`close`](Self::close) when finished to flush remaining records and release resources.
    pub async fn submit(&self, record: AppendRecord) -> Result<RecordSubmitTicket, ProducerError> {
        let permit = self.reserve(record.metered_bytes() as u32).await?;
        Ok(permit.submit(record))
    }

    /// Reserve capacity for a record to be submitted. Useful in [`select!`](tokio::select) loops
    /// where you want to interleave submission with other async work. See [`submit`](Self::submit)
    /// for a simpler API.
    ///
    /// Waits when the unacknowledged bytes limit is reached, providing explicit backpressure
    /// control. The returned permit must be used to submit the record.
    ///
    /// Reserving capacity does not order a record relative to [`flush`](Self::flush); the record is
    /// ordered when [`RecordSubmitPermit::submit`] is called.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. Internally, it only awaits
    /// [`Semaphore::acquire_many_owned`](tokio::sync::Semaphore::acquire_many_owned) and
    /// [`Sender::reserve_owned`](tokio::sync::mpsc::Sender::reserve_owned), both of which are
    /// cancel safe.
    pub async fn reserve(&self, bytes: u32) -> Result<RecordSubmitPermit, ProducerError> {
        let append_permit = self.permits.acquire(bytes).await;
        let cmd_tx_permit = self
            .cmd_tx
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| self.terminal_err())?;
        Ok(RecordSubmitPermit {
            append_permit,
            cmd_tx_permit,
            terminal_err: self.terminal_err.clone(),
        })
    }

    /// Flush all records ordered before this call and wait for them to become durable.
    ///
    /// This immediately emits the current partial batch without waiting for the configured linger
    /// duration. The producer remains open and can be used for subsequent submissions and flushes.
    /// If there is no preceding work, this completes without submitting an empty batch.
    ///
    /// A record whose [`submit`](Self::submit) call completed before this method began is covered
    /// by the flush. Submissions concurrent with the flush may be ordered on either side of the
    /// boundary; records ordered after it are not included in the durability wait.
    pub async fn flush(&self) -> Result<(), ProducerError> {
        let (done_tx, done_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Flush { done_tx })
            .await
            .map_err(|_| self.terminal_err())?;
        done_rx.await.map_err(|_| self.terminal_err())?
    }

    /// Close the producer and wait for all submitted records to be appended.
    pub async fn close(self) -> Result<(), ProducerError> {
        let (done_tx, done_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Close { done_tx })
            .await
            .map_err(|_| self.terminal_err())?;
        done_rx.await.map_err(|_| self.terminal_err())?
    }

    fn terminal_err(&self) -> ProducerError {
        self.terminal_err
            .get()
            .cloned()
            .unwrap_or(ProducerError::ProducerClosed)
    }

    async fn run(
        session: AppendSessionInternal,
        config: ProducerConfig,
        mut cmd_rx: mpsc::Receiver<Command>,
        terminal_err: Arc<OnceLock<ProducerError>>,
    ) {
        let (record_tx, mut inputs) = Self::batcher(&config, config.match_seq_num);
        let mut record_tx = Some(record_tx);

        let mut pending_batch_acks = FuturesUnordered::new();
        let mut pending_record_acks = VecDeque::new();
        let mut control = PendingControl::default();
        let mut stashed_submission: Option<StashedSubmission> = None;
        let mut submit_fut: Option<SubmitFuture> = None;
        let mut submit_batch_len: Option<usize> = None;
        let mut inputs_exhausted = false;

        loop {
            tokio::select! {
                record_tx_permit = async {
                    record_tx
                        .as_ref()
                        .expect("record_tx should not be None")
                        .reserve()
                        .await
                }, if stashed_submission.is_some() => {
                    let submission = stashed_submission
                        .take()
                        .expect("stashed_submission should not be None");
                    pending_record_acks.push_back(PendingRecordAck {
                        ack_tx: submission.ack_tx,
                        _permit: submission.permit,
                    });
                    record_tx_permit
                        .expect("record_rx should not be closed")
                        .send(submission.record);
                }

                cmd = cmd_rx.recv(), if stashed_submission.is_none() && control.flush_tx.is_none() => {
                    match cmd {
                        Some(Command::Submit { record, ack_tx, permit }) => {
                            if control.close_tx.is_some() {
                                let _ = ack_tx.send(
                                    Err(ProducerError::ProducerClosing)
                                );
                            } else {
                                stashed_submission = Some(StashedSubmission { record, ack_tx, permit });
                            }
                        }
                        Some(Command::Close { done_tx }) => {
                            control.close_tx = Some(done_tx);
                        }
                        Some(Command::Flush { done_tx }) => {
                            if control.close_tx.is_some() {
                                let _ = done_tx.send(Err(ProducerError::ProducerClosing));
                            } else {
                                control.flush_tx = Some(done_tx);
                            }
                        }
                        None => {
                            terminate_producer(
                                ProducerError::ProducerDropped,
                                &terminal_err,
                                &mut pending_batch_acks,
                                &mut pending_record_acks,
                                &mut stashed_submission,
                                &mut control,
                                &mut cmd_rx,
                            )
                            .await;
                            return;
                        }
                    }
                }

                input = inputs.next(), if submit_fut.is_none() && !inputs_exhausted => {
                    match input {
                        Some(Ok(input)) => {
                            submit_batch_len = Some(input.records.len());
                            submit_fut = Some(Box::pin(session.submit(input).map_err(Into::into)));
                        }
                        Some(Err(err)) => {
                            terminate_producer(
                                err.into(),
                                &terminal_err,
                                &mut pending_batch_acks,
                                &mut pending_record_acks,
                                &mut stashed_submission,
                                &mut control,
                                &mut cmd_rx,
                            )
                            .await;
                            return;
                        }
                        None => {
                            inputs_exhausted = true;
                        }
                    }
                }

                ticket = async {
                    submit_fut
                        .as_mut()
                        .expect("submit_fut should not be None")
                        .await
                }, if submit_fut.is_some() => {
                    submit_fut = None;
                    match ticket {
                        Ok(ticket) => {
                            let batch_len = submit_batch_len
                                .take()
                                .expect("submit_batch_len should not be None");
                            pending_batch_acks.push(PendingBatchAck {
                                ticket,
                                pending_record_acks: Some(
                                    pending_record_acks.drain(..batch_len).collect::<Vec<_>>(),
                                ),
                            });
                        }
                        Err(err) => {
                            terminate_producer(
                                err,
                                &terminal_err,
                                &mut pending_batch_acks,
                                &mut pending_record_acks,
                                &mut stashed_submission,
                                &mut control,
                                &mut cmd_rx,
                            )
                            .await;
                            return;
                        }
                    }
                }

                Some((batch_ack, batch_record_acks)) = pending_batch_acks.next() => {
                    let terminal_batch_err = batch_ack.as_ref().err().cloned();
                    dispatch_acks(batch_ack, batch_record_acks);
                    if let Some(err) = terminal_batch_err {
                        terminate_producer(
                            err,
                            &terminal_err,
                            &mut pending_batch_acks,
                            &mut pending_record_acks,
                            &mut stashed_submission,
                            &mut control,
                            &mut cmd_rx,
                        )
                        .await;
                        return;
                    }
                }
            }

            if (control.flush_tx.is_some() || control.close_tx.is_some()) && record_tx.is_some() {
                record_tx = None;
            }

            if control.flush_tx.is_some()
                && inputs_exhausted
                && pending_record_acks.is_empty()
                && pending_batch_acks.is_empty()
                && stashed_submission.is_none()
                && submit_fut.is_none()
            {
                let next_match_seq_num = inputs.match_seq_num;
                let (next_record_tx, next_inputs) = Self::batcher(&config, next_match_seq_num);
                record_tx = Some(next_record_tx);
                inputs = next_inputs;
                inputs_exhausted = false;

                if let Some(done_tx) = control.flush_tx.take() {
                    let _ = done_tx.send(Ok(()));
                }
            }

            if control.close_tx.is_some()
                && control.flush_tx.is_none()
                && pending_record_acks.is_empty()
                && pending_batch_acks.is_empty()
                && stashed_submission.is_none()
                && submit_fut.is_none()
            {
                break;
            }
        }

        let session_close_res = session.close().await;

        if let Some(done_tx) = control.close_tx.take() {
            let _ = done_tx.send(session_close_res.map_err(Into::into));
        }
    }

    fn batcher(
        config: &ProducerConfig,
        match_seq_num: Option<u64>,
    ) -> (mpsc::Sender<AppendRecord>, AppendInputs) {
        let (record_tx, record_rx) = mpsc::channel(RECORD_BATCH_MAX.count);
        let mut inputs = AppendInputs::new(AppendRecordBatches::from_stream(
            ReceiverStream::new(record_rx),
            config.batching.clone(),
        ));
        if let Some(fencing_token) = config.fencing_token.as_ref() {
            inputs = inputs.with_fencing_token(fencing_token.clone());
        }
        if let Some(seq_num) = match_seq_num {
            inputs = inputs.with_match_seq_num(seq_num);
        }
        (record_tx, inputs)
    }
}

/// A permit to submit a record after reserving capacity.
pub struct RecordSubmitPermit {
    append_permit: AppendPermit,
    cmd_tx_permit: mpsc::OwnedPermit<Command>,
    terminal_err: Arc<OnceLock<ProducerError>>,
}

impl RecordSubmitPermit {
    /// Submit the record using this permit.
    pub fn submit(self, record: AppendRecord) -> RecordSubmitTicket {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.cmd_tx_permit.send(Command::Submit {
            record,
            ack_tx,
            permit: self.append_permit,
        });
        RecordSubmitTicket {
            rx: ack_rx,
            terminal_err: self.terminal_err,
        }
    }
}

type SubmitFuture = Pin<Box<dyn Future<Output = Result<BatchSubmitTicket, ProducerError>> + Send>>;

enum Command {
    Submit {
        record: AppendRecord,
        ack_tx: oneshot::Sender<Result<IndexedAppendAck, ProducerError>>,
        permit: AppendPermit,
    },
    Flush {
        done_tx: oneshot::Sender<Result<(), ProducerError>>,
    },
    Close {
        done_tx: oneshot::Sender<Result<(), ProducerError>>,
    },
}

impl Command {
    fn reject(self, err: ProducerError) {
        match self {
            Command::Submit { ack_tx, .. } => {
                let _ = ack_tx.send(Err(err));
            }
            Command::Flush { done_tx } => {
                let _ = done_tx.send(Err(err));
            }
            Command::Close { done_tx } => {
                let _ = done_tx.send(Err(err));
            }
        }
    }
}

struct StashedSubmission {
    record: AppendRecord,
    ack_tx: oneshot::Sender<Result<IndexedAppendAck, ProducerError>>,
    permit: AppendPermit,
}

#[derive(Default)]
struct PendingControl {
    flush_tx: Option<oneshot::Sender<Result<(), ProducerError>>>,
    close_tx: Option<oneshot::Sender<Result<(), ProducerError>>>,
}

struct PendingRecordAck {
    ack_tx: oneshot::Sender<Result<IndexedAppendAck, ProducerError>>,
    _permit: AppendPermit,
}

struct PendingBatchAck {
    ticket: BatchSubmitTicket,
    pending_record_acks: Option<Vec<PendingRecordAck>>,
}

impl Future for PendingBatchAck {
    type Output = (Result<AppendAck, ProducerError>, Vec<PendingRecordAck>);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.ticket).poll(cx) {
            Poll::Ready(batch_ack) => Poll::Ready((
                batch_ack.map_err(Into::into),
                self.pending_record_acks
                    .take()
                    .expect("pending_record_acks should not be None"),
            )),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn dispatch_acks(
    batch_ack: Result<AppendAck, ProducerError>,
    pending_record_acks: Vec<PendingRecordAck>,
) {
    match batch_ack {
        Ok(batch_ack) => {
            for (offset, pending) in pending_record_acks.into_iter().enumerate() {
                let seq_num = batch_ack.start.seq_num + offset as u64;
                let _ = pending.ack_tx.send(Ok(IndexedAppendAck {
                    seq_num,
                    batch: batch_ack.clone(),
                }));
            }
        }
        Err(err) => {
            for pending in pending_record_acks {
                let _ = pending.ack_tx.send(Err(err.clone()));
            }
        }
    }
}

async fn terminate_producer(
    err: ProducerError,
    terminal_err: &OnceLock<ProducerError>,
    pending_batch_acks: &mut FuturesUnordered<PendingBatchAck>,
    pending_record_acks: &mut VecDeque<PendingRecordAck>,
    stashed_submission: &mut Option<StashedSubmission>,
    control: &mut PendingControl,
    cmd_rx: &mut mpsc::Receiver<Command>,
) {
    while let Some((batch_ack, pending_record_acks)) =
        pending_batch_acks.next().now_or_never().flatten()
    {
        dispatch_acks(batch_ack, pending_record_acks);
    }

    let _ = terminal_err.set(err.clone());
    for pending in pending_record_acks.drain(..) {
        let _ = pending.ack_tx.send(Err(err.clone()));
    }
    if let Some(submission) = stashed_submission.take() {
        let _ = submission.ack_tx.send(Err(err.clone()));
    }
    if let Some(done_tx) = control.flush_tx.take() {
        let _ = done_tx.send(Err(err.clone()));
    }
    if let Some(done_tx) = control.close_tx.take() {
        let _ = done_tx.send(Err(err.clone()));
    }
    cmd_rx.close();
    while let Some(cmd) = cmd_rx.recv().await {
        cmd.reject(err.clone());
    }
}
