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

use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use s2_common::caps::RECORD_BATCH_MAX;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    api::BasinClient,
    batching::{AppendInputs, AppendRecordBatches, BatchingConfig},
    session::{AppendPermit, AppendPermits, AppendSessionInternal, BatchSubmitTicket},
    types::{
        AppendAck, AppendRecord, FencingToken, MeteredBytes, ONE_MIB, S2Error, StreamName,
        ValidationError,
    },
};

/// A [`Future`] that resolves to an acknowledgement once the record is appended.
pub struct RecordSubmitTicket {
    rx: oneshot::Receiver<Result<IndexedAppendAck, S2Error>>,
    terminal_err: Arc<OnceLock<S2Error>>,
}

impl Future for RecordSubmitTicket {
    type Output = Result<IndexedAppendAck, S2Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(res)) => Poll::Ready(res),
            Poll::Ready(Err(_)) => Poll::Ready(Err(self
                .terminal_err
                .get()
                .cloned()
                .unwrap_or_else(|| ProducerError::Dropped.into()))),
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
    terminal_err: Arc<OnceLock<S2Error>>,
    _handle: AbortOnDropHandle<()>,
}

impl Producer {
    pub(crate) fn new(client: BasinClient, stream: StreamName, config: ProducerConfig) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(RECORD_BATCH_MAX.count);
        let permits = AppendPermits::new(None, config.max_unacked_bytes);
        let session = AppendSessionInternal::new(client, stream);
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
    /// **Note**: After all submits, you must call [`close`](Self::close) to ensure all records are
    /// appended.
    pub async fn submit(&self, record: AppendRecord) -> Result<RecordSubmitTicket, S2Error> {
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
    /// **Note**: After all submits, you must call [`close`](Self::close) to ensure all records are
    /// appended.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. Internally, it only awaits
    /// [`Semaphore::acquire_many_owned`](tokio::sync::Semaphore::acquire_many_owned) and
    /// [`Sender::reserve_owned`](tokio::sync::mpsc::Sender::reserve_owned), both of which are
    /// cancel safe.
    pub async fn reserve(&self, bytes: u32) -> Result<RecordSubmitPermit, S2Error> {
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

    /// Close the producer and wait for all submitted records to be appended.
    pub async fn close(self) -> Result<(), S2Error> {
        let (done_tx, done_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Close { done_tx })
            .await
            .map_err(|_| self.terminal_err())?;
        done_rx.await.map_err(|_| self.terminal_err())?
    }

    fn terminal_err(&self) -> S2Error {
        self.terminal_err
            .get()
            .cloned()
            .unwrap_or_else(|| ProducerError::Closed.into())
    }

    async fn run(
        session: AppendSessionInternal,
        config: ProducerConfig,
        mut cmd_rx: mpsc::Receiver<Command>,
        terminal_err: Arc<OnceLock<S2Error>>,
    ) {
        let (record_tx, record_rx) = mpsc::channel::<AppendRecord>(RECORD_BATCH_MAX.count);
        let mut inputs = AppendInputs {
            batches: AppendRecordBatches::new(ReceiverStream::new(record_rx), config.batching),
            fencing_token: config.fencing_token,
            match_seq_num: config.match_seq_num,
        };

        let mut pending_acks: VecDeque<PendingRecordAck> = VecDeque::new();
        let mut claimable_tickets: FuturesUnordered<_> = FuturesUnordered::new();
        let mut close_tx: Option<oneshot::Sender<Result<(), S2Error>>> = None;
        let mut stashed_submission: Option<StashedSubmission> = None;
        let mut submit_fut: Option<SubmitFuture> = None;
        let mut submit_batch_len: Option<usize> = None;

        loop {
            tokio::select! {
                record_tx_permit = record_tx.reserve(), if stashed_submission.is_some() => {
                    let submission = stashed_submission
                        .take()
                        .expect("stashed_submission should not be None");
                    pending_acks.push_back(PendingRecordAck {
                        ack_tx: submission.ack_tx,
                        _permit: submission.permit,
                    });
                    record_tx_permit
                        .expect("record_rx should not be closed")
                        .send(submission.record);
                }

                cmd = cmd_rx.recv(), if stashed_submission.is_none() => {
                    match cmd {
                        Some(Command::Submit { record, ack_tx, permit }) => {
                            if close_tx.is_some() {
                                let _ = ack_tx.send(
                                    Err(ProducerError::Closing.into())
                                );
                            } else {
                                stashed_submission = Some(StashedSubmission { record, ack_tx, permit });
                            }
                        }
                        Some(Command::Close { done_tx }) => {
                            close_tx = Some(done_tx);
                        }
                        None => {
                            for pending in pending_acks.drain(..) {
                                let _ = pending.ack_tx.send(Err(ProducerError::Dropped.into()));
                            }
                            return;
                        }
                    }
                }

                input = inputs.next(), if submit_fut.is_none() => {
                    match input.expect("record_tx should not be closed") {
                        Ok(input) => {
                            submit_batch_len = Some(input.records.len());
                            submit_fut = Some(Box::pin(session.submit(input)));
                        }
                        Err(err) => {
                            propagate_terminal_error(
                                err.into(),
                                &terminal_err,
                                &mut pending_acks,
                                &mut stashed_submission,
                                &mut close_tx,
                                &mut cmd_rx,
                            )
                            .await;
                            return;
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
                            claimable_tickets.push(ticket.map({
                                let pending_acks = pending_acks.drain(..batch_len).collect::<Vec<_>>();
                                |batch_ack| (batch_ack, pending_acks)
                            }));
                        }
                        Err(err) => {
                            propagate_terminal_error(
                                err,
                                &terminal_err,
                                &mut pending_acks,
                                &mut stashed_submission,
                                &mut close_tx,
                                &mut cmd_rx,
                            )
                            .await;
                            return;
                        }
                    }
                }

                Some((batch_ack, pending_acks)) = claimable_tickets.next() => {
                    dispatch_acks(batch_ack, pending_acks);
                }
            }

            if close_tx.is_some()
                && pending_acks.is_empty()
                && claimable_tickets.is_empty()
                && stashed_submission.is_none()
                && submit_fut.is_none()
            {
                break;
            }
        }

        let session_close_res = session.close().await;

        if let Some(done_tx) = close_tx.take() {
            let _ = done_tx.send(session_close_res);
        }
    }
}

/// A permit to submit a record after reserving capacity.
pub struct RecordSubmitPermit {
    append_permit: AppendPermit,
    cmd_tx_permit: mpsc::OwnedPermit<Command>,
    terminal_err: Arc<OnceLock<S2Error>>,
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

#[derive(Debug, Clone, thiserror::Error)]
enum ProducerError {
    #[error("producer already closed")]
    Closed,
    #[error("producer is closing")]
    Closing,
    #[error("producer dropped without calling close")]
    Dropped,
}

impl From<ProducerError> for S2Error {
    fn from(err: ProducerError) -> Self {
        S2Error::Client(err.to_string())
    }
}

type SubmitFuture = Pin<Box<dyn Future<Output = Result<BatchSubmitTicket, S2Error>> + Send>>;

enum Command {
    Submit {
        record: AppendRecord,
        ack_tx: oneshot::Sender<Result<IndexedAppendAck, S2Error>>,
        permit: AppendPermit,
    },
    Close {
        done_tx: oneshot::Sender<Result<(), S2Error>>,
    },
}

impl Command {
    fn reject(self, err: S2Error) {
        match self {
            Command::Submit { ack_tx, .. } => {
                let _ = ack_tx.send(Err(err));
            }
            Command::Close { done_tx } => {
                let _ = done_tx.send(Err(err));
            }
        }
    }
}

struct StashedSubmission {
    record: AppendRecord,
    ack_tx: oneshot::Sender<Result<IndexedAppendAck, S2Error>>,
    permit: AppendPermit,
}

struct PendingRecordAck {
    ack_tx: oneshot::Sender<Result<IndexedAppendAck, S2Error>>,
    _permit: AppendPermit,
}

fn dispatch_acks(batch_ack: Result<AppendAck, S2Error>, pending_acks: Vec<PendingRecordAck>) {
    match batch_ack {
        Ok(batch_ack) => {
            for (offset, pending) in pending_acks.into_iter().enumerate() {
                let seq_num = batch_ack.start.seq_num + offset as u64;
                let _ = pending.ack_tx.send(Ok(IndexedAppendAck {
                    seq_num,
                    batch: batch_ack.clone(),
                }));
            }
        }
        Err(err) => {
            for pending in pending_acks {
                let _ = pending.ack_tx.send(Err(err.clone()));
            }
        }
    }
}

async fn propagate_terminal_error(
    err: S2Error,
    terminal_err: &OnceLock<S2Error>,
    pending_acks: &mut VecDeque<PendingRecordAck>,
    stashed_submission: &mut Option<StashedSubmission>,
    close_tx: &mut Option<oneshot::Sender<Result<(), S2Error>>>,
    cmd_rx: &mut mpsc::Receiver<Command>,
) {
    let _ = terminal_err.set(err.clone());
    for pending in pending_acks.drain(..) {
        let _ = pending.ack_tx.send(Err(err.clone()));
    }
    if let Some(submission) = stashed_submission.take() {
        let _ = submission.ack_tx.send(Err(err.clone()));
    }
    if let Some(done_tx) = close_tx.take() {
        let _ = done_tx.send(Err(err.clone()));
    }
    cmd_rx.close();
    while let Some(cmd) = cmd_rx.recv().await {
        cmd.reject(err.clone());
    }
}
