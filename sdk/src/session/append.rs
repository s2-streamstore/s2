use std::{
    collections::VecDeque,
    future::Future,
    num::NonZeroU32,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use futures_util::StreamExt;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    time::Instant,
};
use tokio_muxt::{CoalesceMode, MuxTimer};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::task::AbortOnDropHandle;
use tracing::debug;

use crate::{
    api::{ApiError, BasinClient, Streaming, retry_builder},
    error::{AppendError, RequestError},
    frame_signal::FrameSignal,
    reconnect::{AdvisedReconnects, ReconnectAdvice},
    retry::{AppendRetryError, RetryBackoffBuilder},
    session::StreamHeaders,
    types::{
        AccessTokenMode, AppendAck, AppendInput, AppendRetryPolicy, MeteredBytes, ONE_MIB,
        StreamConfig, StreamName, StreamPosition, ValidationError,
    },
};

/// Errors returned by an append session.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AppendSessionError {
    /// An error with the append request underlying the session.
    #[error(transparent)]
    Append(#[from] AppendError),
    /// An append acknowledgement timed out.
    #[error("append acknowledgement timed out")]
    AckTimeout,
    /// The server disconnected during the session.
    #[error("server disconnected")]
    ServerDisconnected,
    /// The response stream closed while appends were in flight.
    #[error("response stream closed early while appends in flight")]
    StreamClosedEarly,
    /// The session was already closed.
    #[error("session already closed")]
    SessionClosed,
    /// The session is closing.
    #[error("session is closing")]
    SessionClosing,
    /// The session was dropped without being closed.
    #[error("session dropped without calling close")]
    SessionDropped,
    /// The server returned an invalid append acknowledgement.
    #[error("invalid append acknowledgement: {0}")]
    InvalidAck(String),
    /// The final attempt failed definitively, but an earlier attempt may have taken effect,
    /// so the entire append operation is indeterminate.
    #[error(
        "append may have taken effect in an earlier attempt; final attempt failed: {final_attempt_error}"
    )]
    IndefiniteFailure {
        /// The definite error returned by the final attempt.
        #[source]
        final_attempt_error: Box<Self>,
    },
}

impl AppendSessionError {
    /// Whether retrying the operation is safe or sensible.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Append(error) => error.is_retryable(),
            Self::IndefiniteFailure {
                final_attempt_error,
            } => final_attempt_error.is_retryable(),
            Self::AckTimeout | Self::ServerDisconnected => true,
            Self::StreamClosedEarly
            | Self::SessionClosed
            | Self::SessionClosing
            | Self::SessionDropped
            | Self::InvalidAck(_) => false,
        }
    }

    /// Whether retrying the operation cannot duplicate a mutation.
    pub fn has_no_side_effects(&self) -> bool {
        match self {
            Self::Append(error) => error.has_no_side_effects(),
            Self::IndefiniteFailure { .. } => false,
            Self::SessionClosed | Self::SessionClosing => true,
            Self::AckTimeout
            | Self::ServerDisconnected
            | Self::StreamClosedEarly
            | Self::SessionDropped
            | Self::InvalidAck(_) => false,
        }
    }

    /// Return the underlying request error, if present.
    pub fn request_error(&self) -> Option<&RequestError> {
        match self {
            Self::Append(error) => error.request_error(),
            Self::IndefiniteFailure {
                final_attempt_error,
            } => final_attempt_error.request_error(),
            Self::AckTimeout
            | Self::ServerDisconnected
            | Self::StreamClosedEarly
            | Self::SessionClosed
            | Self::SessionClosing
            | Self::SessionDropped
            | Self::InvalidAck(_) => None,
        }
    }

    fn is_authentication_error(&self) -> bool {
        matches!(
            self,
            Self::Append(AppendError::Request(error)) if error.is_authentication_error()
        )
    }

    fn is_server_draining(&self) -> bool {
        matches!(
            self,
            Self::Append(AppendError::Request(error)) if error.is_server_draining()
        )
    }
}

impl AppendRetryError for AppendSessionError {
    fn has_no_side_effects(&self) -> bool {
        Self::has_no_side_effects(self)
    }

    fn into_indefinite_failure(self) -> Self {
        Self::IndefiniteFailure {
            final_attempt_error: Box::new(self),
        }
    }
}

impl From<ApiError> for AppendSessionError {
    fn from(error: ApiError) -> Self {
        Self::Append(error.into())
    }
}

/// The two shared terminal-error locks recorded when an append session fails terminally.
///
/// Both locks are set together by the terminal branch, but they serve distinct purposes and so
/// hold distinct error values:
/// - [`Self::batch`] holds the **raw** final-attempt error. It is the per-batch fallback returned
///   by `submit`/`reserve`/`BatchSubmitTicket` on a dead session for batches that never left the
///   process, so a never-sent batch reports the final attempt's definite `has_no_side_effects()`
///   classification rather than a session-level aggregate from unrelated batches.
/// - [`Self::session`] holds the **session-level summary** — the final attempt's error wrapped in
///   [`AppendSessionError::IndefiniteFailure`] when any inflight append carried prior uncertainty —
///   reported by `close` as the session's overall outcome.
#[derive(Clone)]
struct TerminalErrorLocks {
    batch: Arc<OnceLock<AppendSessionError>>,
    session: Arc<OnceLock<AppendSessionError>>,
}

impl TerminalErrorLocks {
    fn new() -> Self {
        Self {
            batch: Arc::new(OnceLock::new()),
            session: Arc::new(OnceLock::new()),
        }
    }
}

/// A [`Future`] that resolves to an acknowledgement once the batch of records is appended.
pub struct BatchSubmitTicket {
    rx: oneshot::Receiver<Result<AppendAck, AppendSessionError>>,
    terminal_err: Arc<OnceLock<AppendSessionError>>,
}

impl Future for BatchSubmitTicket {
    type Output = Result<AppendAck, AppendSessionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(res)) => Poll::Ready(res),
            Poll::Ready(Err(_)) => Poll::Ready(Err(self
                .terminal_err
                .get()
                .cloned()
                .unwrap_or(AppendSessionError::SessionDropped))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Clone)]
/// Configuration for an [`AppendSession`].
pub struct AppendSessionConfig {
    max_unacked_bytes: u32,
    max_unacked_batches: Option<u32>,
    stream_config: Option<StreamConfig>,
}

impl Default for AppendSessionConfig {
    fn default() -> Self {
        Self {
            max_unacked_bytes: 5 * ONE_MIB,
            max_unacked_batches: None,
            stream_config: None,
        }
    }
}

impl AppendSessionConfig {
    /// Create a new [`AppendSessionConfig`] with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the limit on total metered bytes of unacknowledged [`AppendInput`]s held in memory.
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

    /// Set the limit on number of unacknowledged [`AppendInput`]s held in memory.
    ///
    /// Defaults to no limit.
    pub fn with_max_unacked_batches(self, max_unacked_batches: NonZeroU32) -> Self {
        Self {
            max_unacked_batches: Some(max_unacked_batches.get()),
            ..self
        }
    }

    /// Set the stream configuration to apply if the stream is created on append.
    ///
    /// Unset fields inherit the basin's default stream configuration. Ignored if the stream
    /// already exists.
    ///
    /// Defaults to `None`.
    pub fn with_stream_config(self, stream_config: StreamConfig) -> Self {
        Self {
            stream_config: Some(stream_config),
            ..self
        }
    }

    pub(crate) fn stream_config(&self) -> Option<&StreamConfig> {
        self.stream_config.as_ref()
    }
}

struct SessionState {
    cmd_rx: mpsc::Receiver<Command>,
    inflight_appends: VecDeque<InflightAppend>,
    inflight_bytes: usize,
    close_tx: Option<oneshot::Sender<Result<(), AppendSessionError>>>,
    total_records: usize,
    total_acked_records: usize,
    prev_ack_end: Option<StreamPosition>,
    stashed_submission: Option<StashedSubmission>,
}

impl SessionState {
    fn is_close_complete(&self) -> bool {
        self.close_tx.is_some()
            && self.inflight_appends.is_empty()
            && self.stashed_submission.is_none()
    }
}

/// A session for high-throughput appending with backpressure control. It can be created from
/// [`append_session`](crate::S2Stream::append_session).
///
/// Supports pipelining multiple [`AppendInput`]s while preserving submission order.
pub struct AppendSession {
    cmd_tx: mpsc::Sender<Command>,
    permits: AppendPermits,
    terminal_errors: TerminalErrorLocks,
    _handle: AbortOnDropHandle<()>,
}

impl AppendSession {
    pub(crate) fn new(
        client: BasinClient,
        stream: StreamName,
        headers: StreamHeaders,
        config: AppendSessionConfig,
    ) -> Self {
        let buffer_size = config
            .max_unacked_batches
            .map(|mib| mib as usize)
            .unwrap_or(DEFAULT_CHANNEL_BUFFER_SIZE);
        let (cmd_tx, cmd_rx) = mpsc::channel(buffer_size);
        let permits = AppendPermits::new(config.max_unacked_batches, config.max_unacked_bytes);
        let retry_builder = retry_builder(&client.config.retry);
        let terminal_errors = TerminalErrorLocks::new();
        let handle = AbortOnDropHandle::new(tokio::spawn(run_session_with_retry(
            client,
            stream,
            headers,
            cmd_rx,
            retry_builder,
            buffer_size,
            terminal_errors.clone(),
        )));
        Self {
            cmd_tx,
            permits,
            terminal_errors,
            _handle: handle,
        }
    }

    /// Submit a batch of records for appending.
    ///
    /// Internally, it waits on [`reserve`](Self::reserve), then submits using the permit.
    /// This provides backpressure when inflight limits are reached.
    /// For explicit control, use [`reserve`](Self::reserve) followed by
    /// [`BatchSubmitPermit::submit`].
    ///
    /// **Note**: After all submits, you must call [`close`](Self::close) to ensure all batches are
    /// appended.
    pub async fn submit(
        &self,
        input: AppendInput,
    ) -> Result<BatchSubmitTicket, AppendSessionError> {
        let permit = self.reserve(input.records.metered_bytes() as u32).await?;
        Ok(permit.submit(input))
    }

    /// Reserve capacity for a batch to be submitted. Useful in [`select!`](tokio::select) loops
    /// where you want to interleave submission with other async work. See [`submit`](Self::submit)
    /// for a simpler API.
    ///
    /// Waits when inflight limits are reached, providing explicit backpressure control.
    /// The returned permit must be used to submit the batch.
    ///
    /// **Note**: After all submits, you must call [`close`](Self::close) to ensure all batches are
    /// appended.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. Internally, it only awaits
    /// [`Semaphore::acquire_many_owned`](tokio::sync::Semaphore::acquire_many_owned) and
    /// [`Sender::reserve_owned`](tokio::sync::mpsc::Sender::reserve), both of which are cancel
    /// safe.
    pub async fn reserve(&self, bytes: u32) -> Result<BatchSubmitPermit, AppendSessionError> {
        let append_permit = self.permits.acquire(bytes).await;
        let cmd_tx_permit = self
            .cmd_tx
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| self.terminal_err())?;
        Ok(BatchSubmitPermit {
            append_permit,
            cmd_tx_permit,
            terminal_err: self.terminal_errors.batch.clone(),
        })
    }

    /// Close the session and wait for all submitted batch of records to be appended.
    pub async fn close(self) -> Result<(), AppendSessionError> {
        let (done_tx, done_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Close { done_tx })
            .await
            .map_err(|_| self.terminal_session_err())?;
        done_rx.await.map_err(|_| self.terminal_session_err())??;
        Ok(())
    }

    fn terminal_err(&self) -> AppendSessionError {
        self.terminal_errors
            .batch
            .get()
            .cloned()
            .unwrap_or(AppendSessionError::SessionClosed)
    }

    /// Session-level terminal error reported by [`close`](Self::close): the wrapped summary when
    /// the session ended with prior uncertainty from an inflight append, falling back to the
    /// per-batch terminal error when no session-level summary was recorded.
    fn terminal_session_err(&self) -> AppendSessionError {
        self.terminal_errors
            .session
            .get()
            .cloned()
            .unwrap_or_else(|| self.terminal_err())
    }
}

/// A permit to submit a batch after reserving capacity.
pub struct BatchSubmitPermit {
    append_permit: AppendPermit,
    cmd_tx_permit: mpsc::OwnedPermit<Command>,
    terminal_err: Arc<OnceLock<AppendSessionError>>,
}

impl BatchSubmitPermit {
    /// Submit the batch using this permit.
    pub fn submit(self, input: AppendInput) -> BatchSubmitTicket {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.cmd_tx_permit.send(Command::Submit {
            input,
            ack_tx,
            permit: Some(self.append_permit),
        });
        BatchSubmitTicket {
            rx: ack_rx,
            terminal_err: self.terminal_err,
        }
    }
}

pub(crate) struct AppendSessionInternal {
    cmd_tx: mpsc::Sender<Command>,
    terminal_errors: TerminalErrorLocks,
    _handle: AbortOnDropHandle<()>,
}

impl AppendSessionInternal {
    pub(crate) fn new(client: BasinClient, stream: StreamName, headers: StreamHeaders) -> Self {
        let buffer_size = DEFAULT_CHANNEL_BUFFER_SIZE;
        let (cmd_tx, cmd_rx) = mpsc::channel(buffer_size);
        let retry_builder = retry_builder(&client.config.retry);
        let terminal_errors = TerminalErrorLocks::new();
        let handle = AbortOnDropHandle::new(tokio::spawn(run_session_with_retry(
            client,
            stream,
            headers,
            cmd_rx,
            retry_builder,
            buffer_size,
            terminal_errors.clone(),
        )));
        Self {
            cmd_tx,
            terminal_errors,
            _handle: handle,
        }
    }

    pub(crate) fn submit(
        &self,
        input: AppendInput,
    ) -> impl Future<Output = Result<BatchSubmitTicket, AppendSessionError>> + Send + 'static {
        let cmd_tx = self.cmd_tx.clone();
        let terminal_err = self.terminal_errors.batch.clone();
        async move {
            let (ack_tx, ack_rx) = oneshot::channel();
            cmd_tx
                .send(Command::Submit {
                    input,
                    ack_tx,
                    permit: None,
                })
                .await
                .map_err(|_| {
                    terminal_err
                        .get()
                        .cloned()
                        .unwrap_or(AppendSessionError::SessionClosed)
                })?;
            Ok(BatchSubmitTicket {
                rx: ack_rx,
                terminal_err,
            })
        }
    }

    pub(crate) async fn close(self) -> Result<(), AppendSessionError> {
        let (done_tx, done_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Close { done_tx })
            .await
            .map_err(|_| self.terminal_session_err())?;
        done_rx.await.map_err(|_| self.terminal_session_err())??;
        Ok(())
    }

    fn terminal_err(&self) -> AppendSessionError {
        self.terminal_errors
            .batch
            .get()
            .cloned()
            .unwrap_or(AppendSessionError::SessionClosed)
    }

    /// Session-level terminal error reported by [`close`](Self::close).
    fn terminal_session_err(&self) -> AppendSessionError {
        self.terminal_errors
            .session
            .get()
            .cloned()
            .unwrap_or_else(|| self.terminal_err())
    }
}

#[derive(Debug)]
pub(crate) struct AppendPermit {
    _count: Option<OwnedSemaphorePermit>,
    _bytes: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub(crate) struct AppendPermits {
    count: Option<Arc<Semaphore>>,
    bytes: Arc<Semaphore>,
}

impl AppendPermits {
    pub(crate) fn new(count_permits: Option<u32>, bytes_permits: u32) -> Self {
        Self {
            count: count_permits.map(|permits| Arc::new(Semaphore::new(permits as usize))),
            bytes: Arc::new(Semaphore::new(bytes_permits as usize)),
        }
    }

    pub(crate) async fn acquire(&self, bytes: u32) -> AppendPermit {
        AppendPermit {
            _count: if let Some(count) = self.count.as_ref() {
                Some(
                    count
                        .clone()
                        .acquire_many_owned(1)
                        .await
                        .expect("semaphore should not be closed"),
                )
            } else {
                None
            },
            _bytes: self
                .bytes
                .clone()
                .acquire_many_owned(bytes)
                .await
                .expect("semaphore should not be closed"),
        }
    }
}

async fn run_session_with_retry(
    client: BasinClient,
    stream: StreamName,
    headers: StreamHeaders,
    cmd_rx: mpsc::Receiver<Command>,
    retry_builder: RetryBackoffBuilder,
    buffer_size: usize,
    terminal_errors: TerminalErrorLocks,
) {
    let access_token_mode = client.config.access_token.mode();
    let frame_signal = match client.config.retry.append_retry_policy {
        AppendRetryPolicy::NoSideEffects => Some(FrameSignal::new()),
        AppendRetryPolicy::All => None,
    };

    let mut state = SessionState {
        cmd_rx,
        inflight_appends: VecDeque::new(),
        inflight_bytes: 0,
        close_tx: None,
        total_records: 0,
        total_acked_records: 0,
        prev_ack_end: None,
        stashed_submission: None,
    };
    let mut prev_total_acked_records = 0;
    let mut retry_backoff = retry_builder.build();
    let mut advised_reconnects = AdvisedReconnects::default();

    loop {
        let result = run_session(
            &client,
            &stream,
            &headers,
            &mut state,
            buffer_size,
            &frame_signal,
            advised_reconnects,
        )
        .await;

        match result {
            Ok(SessionOutcome::Closed) => {
                break;
            }
            Ok(SessionOutcome::ReconnectAdvised) => {
                // The advised connection was already poisoned when the advice
                // was first decoded, so reconnecting dials a fresh one.
                advised_reconnects.record();
                debug!(
                    inflight_appends_len = state.inflight_appends.len(),
                    advised_reconnects = advised_reconnects.count(),
                    "reconnecting append session on server advice"
                );
            }
            Err(err) if err.is_server_draining() && state.is_close_complete() => break,
            Err(err) if err.is_server_draining() => {
                advised_reconnects.record();
                debug!(
                    inflight_appends_len = state.inflight_appends.len(),
                    advised_reconnects = advised_reconnects.count(),
                    "reconnecting append session while server drains"
                );
            }
            Err(err) => {
                if prev_total_acked_records < state.total_acked_records {
                    prev_total_acked_records = state.total_acked_records;
                    retry_backoff.reset();
                }

                if is_safe_to_retry(
                    &err,
                    client.config.retry.append_retry_policy,
                    !state.inflight_appends.is_empty(),
                    frame_signal.as_ref(),
                    access_token_mode,
                ) && let Some(backoff) = retry_backoff.next()
                {
                    if err.attempt_may_have_side_effects(frame_signal.as_ref()) {
                        for append in &mut state.inflight_appends {
                            append.prior_uncertainty = true;
                        }
                    }
                    debug!(
                        %err,
                        ?backoff,
                        num_retries_remaining = retry_backoff.remaining(),
                        "retrying append session"
                    );
                    tokio::time::sleep(backoff).await;
                } else {
                    debug!(
                        %err,
                        retries_exhausted = retry_backoff.is_exhausted(),
                        "not retrying append session"
                    );
                    settle_terminal_failure(err, &mut state, &terminal_errors).await;
                    break;
                }
            }
        }
    }

    if let Some(done_tx) = state.close_tx.take() {
        let _ = done_tx.send(Ok(()));
    }
}

/// Settle a terminal append-session failure.
///
/// Records the terminal error in two shared locks with distinct semantics (see
/// [`TerminalErrorLocks`]):
/// - the per-batch lock holds the **raw** final-attempt error, so `submit`/`reserve`/
///   `BatchSubmitTicket` fallbacks on a dead session report a never-sent batch with the final
///   attempt's definite `has_no_side_effects()` classification rather than a session-level
///   aggregate from unrelated batches;
/// - the session-level lock holds the **session-level summary** — the final attempt's error wrapped
///   in [`AppendSessionError::IndefiniteFailure`] when any inflight append carried prior
///   uncertainty — reported by `close`.
///
/// Then resolves every already-buffered batch with the appropriate per-batch error: inflight
/// appends are wrapped per their own `prior_uncertainty`; a stashed (never-sent) submission and
/// buffered `Command::Submit`s get the raw error; the close handshake and buffered
/// `Command::Close`s get the session-level summary. Finally it closes and drains the command
/// channel so subsequent submits fail fast against the per-batch terminal error.
async fn settle_terminal_failure(
    err: AppendSessionError,
    state: &mut SessionState,
    terminal_errors: &TerminalErrorLocks,
) {
    let session_err = err
        .clone()
        .with_prior_uncertainty(state.inflight_appends.iter().any(|a| a.prior_uncertainty));
    let _ = terminal_errors.batch.set(err.clone());
    let _ = terminal_errors.session.set(session_err.clone());

    for inflight_append in state.inflight_appends.drain(..) {
        let error = err
            .clone()
            .with_prior_uncertainty(inflight_append.prior_uncertainty);
        let _ = inflight_append.ack_tx.send(Err(error));
    }

    if let Some(stashed) = state.stashed_submission.take() {
        let _ = stashed.ack_tx.send(Err(err.clone()));
    }

    if let Some(done_tx) = state.close_tx.take() {
        let _ = done_tx.send(Err(session_err.clone()));
    }

    state.cmd_rx.close();
    while let Some(cmd) = state.cmd_rx.recv().await {
        let error = match &cmd {
            Command::Submit { .. } => &err,
            Command::Close { .. } => &session_err,
        };
        cmd.reject(error.clone());
    }
}

/// How a connection attempt ended without failing.
enum SessionOutcome {
    /// Everything submitted was acknowledged and the caller closed the session.
    Closed,
    /// The server advised reconnecting and this connection drained cleanly.
    ReconnectAdvised,
}

async fn run_session(
    client: &BasinClient,
    stream: &StreamName,
    headers: &StreamHeaders,
    state: &mut SessionState,
    buffer_size: usize,
    frame_signal: &Option<FrameSignal>,
    advised_reconnects: AdvisedReconnects,
) -> Result<SessionOutcome, AppendSessionError> {
    if let Some(s) = frame_signal {
        s.reset();
    }

    let reconnect = ReconnectAdvice::default();
    let (input_tx, mut acks) = connect(
        client,
        stream,
        headers,
        buffer_size,
        frame_signal.clone(),
        reconnect.clone(),
    )
    .await?;
    let ack_timeout = client.config.request_timeout;

    if !state.inflight_appends.is_empty() {
        resend(state, &input_tx, &mut acks, ack_timeout).await?;

        if let Some(s) = frame_signal {
            s.reset();
        }

        assert!(state.inflight_appends.is_empty());
        assert_eq!(state.inflight_bytes, 0);
    }

    if state.is_close_complete() {
        return Ok(SessionOutcome::Closed);
    }

    let timer = MuxTimer::<N_TIMER_VARIANTS>::default();
    tokio::pin!(timer);

    let mut declined_advice = false;

    loop {
        if reconnect.is_advised() && state.close_tx.is_none() && !declined_advice {
            if advised_reconnects.should_reconnect() {
                drain_for_reconnect(input_tx, acks, state, timer.as_mut(), ack_timeout).await?;
                return Ok(SessionOutcome::ReconnectAdvised);
            }
            declined_advice = true;
        }

        tokio::select! {
            (event_ord, _deadline) = &mut timer, if timer.is_armed() => {
                match TimerEvent::from(event_ord) {
                    TimerEvent::AckDeadline => {
                        return Err(AppendSessionError::AckTimeout);
                    }
                }
            }

            input_tx_permit = input_tx.reserve(), if state.stashed_submission.is_some() => {
                let input_tx_permit = input_tx_permit
                    .map_err(|_| AppendSessionError::ServerDisconnected)?;
                let submission = state.stashed_submission
                    .take()
                    .expect("stashed_submission should not be None");

                let ack_deadline = Instant::now() + ack_timeout;
                input_tx_permit.send(submission.input.clone());

                state.total_records += submission.input.records.len();
                state.inflight_bytes += submission.input_metered_bytes;

                timer.as_mut().fire_at(
                    TimerEvent::AckDeadline,
                    ack_deadline,
                    CoalesceMode::Earliest,
                );
                state.inflight_appends.push_back(InflightAppend {
                    input: submission.input,
                    input_metered_bytes: submission.input_metered_bytes,
                    ack_tx: submission.ack_tx,
                    ack_deadline,
                    _permit: submission.permit,
                    prior_uncertainty: false,
                });
            }

            cmd = state.cmd_rx.recv(), if state.stashed_submission.is_none() => {
                match cmd {
                    Some(Command::Submit { input, ack_tx, permit }) => {
                        if state.close_tx.is_some() {
                            let _ = ack_tx.send(
                                Err(AppendSessionError::SessionClosing)
                            );
                        } else {
                            let input_metered_bytes = input.records.metered_bytes();
                            state.stashed_submission = Some(StashedSubmission {
                                input,
                                input_metered_bytes,
                                ack_tx,
                                permit,
                            });
                        }
                    }
                    Some(Command::Close { done_tx }) => {
                        state.close_tx = Some(done_tx);
                    }
                    None => {
                        return Err(AppendSessionError::SessionDropped);
                    }
                }
            }

            ack = acks.next() => {
                match ack {
                    Some(Ok(ack)) => {
                        process_ack(
                            ack,
                            state,
                            timer.as_mut(),
                        )?;
                    }
                    Some(Err(err)) => {
                        return Err(err.into());
                    }
                    None => {
                        if !state.inflight_appends.is_empty() || state.stashed_submission.is_some() {
                            return Err(AppendSessionError::StreamClosedEarly);
                        }
                        break;
                    }
                }
            }
        }

        if state.is_close_complete() {
            break;
        }
    }

    assert!(state.inflight_appends.is_empty());
    assert_eq!(state.inflight_bytes, 0);
    assert!(state.stashed_submission.is_none());

    Ok(SessionOutcome::Closed)
}

async fn resend(
    state: &mut SessionState,
    input_tx: &mpsc::Sender<AppendInput>,
    acks: &mut Streaming<AppendAck>,
    ack_timeout: Duration,
) -> Result<(), AppendSessionError> {
    debug!(
        inflight_appends_len = state.inflight_appends.len(),
        inflight_bytes = state.inflight_bytes,
        "resending inflight appends"
    );

    let mut resend_index = 0;
    let mut resend_finished = false;

    let timer = MuxTimer::<N_TIMER_VARIANTS>::default();
    tokio::pin!(timer);

    while !state.inflight_appends.is_empty() {
        tokio::select! {
            (event_ord, _deadline) = &mut timer, if timer.is_armed() => {
                match TimerEvent::from(event_ord) {
                    TimerEvent::AckDeadline => {
                        return Err(AppendSessionError::AckTimeout);
                    }
                }
            }

            input_tx_permit = input_tx.reserve(), if !resend_finished => {
                let input_tx_permit = input_tx_permit
                    .map_err(|_| AppendSessionError::ServerDisconnected)?;

                if let Some(inflight_append) = state.inflight_appends.get_mut(resend_index) {
                    inflight_append.ack_deadline = Instant::now() + ack_timeout;
                    timer.as_mut().fire_at(
                        TimerEvent::AckDeadline,
                        inflight_append.ack_deadline,
                        CoalesceMode::Latest,
                    );
                    input_tx_permit.send(inflight_append.input.clone());
                    resend_index += 1;
                } else {
                    resend_finished = true;
                }
            }

            ack = acks.next() => {
                match ack {
                    Some(Ok(ack)) => {
                        process_ack(
                            ack,
                            state,
                            timer.as_mut(),
                        )?;
                        resend_index = resend_index.checked_sub(1).ok_or_else(|| {
                            AppendSessionError::InvalidAck(
                                "received ack without a corresponding resent append in flight".to_string(),
                            )
                        })?;
                    }
                    Some(Err(err)) => {
                        return Err(err.into());
                    }
                    None => {
                        return Err(AppendSessionError::StreamClosedEarly);
                    }
                }
            }
        }
    }

    assert_eq!(
        resend_index, 0,
        "resend_index should be 0 after resend completes"
    );
    debug!("finished resending inflight appends");
    Ok(())
}

/// Half-close so the server acknowledges everything it accepted and then ends
/// the response cleanly. Every input reaches the server ahead of the request's
/// end, so a clean end with appends still unacknowledged is a truncated
/// response, and nothing is resent.
async fn drain_for_reconnect(
    input_tx: mpsc::Sender<AppendInput>,
    mut acks: Streaming<AppendAck>,
    state: &mut SessionState,
    mut timer: Pin<&mut MuxTimer<N_TIMER_VARIANTS>>,
    ack_timeout: Duration,
) -> Result<(), AppendSessionError> {
    drop(input_tx);
    loop {
        // Bound the wait for the server's end of stream, which is otherwise
        // unbounded once nothing is in flight.
        if !timer.is_armed() {
            timer.as_mut().fire_at(
                TimerEvent::AckDeadline,
                Instant::now() + ack_timeout,
                CoalesceMode::Earliest,
            );
        }

        tokio::select! {
            (event_ord, _deadline) = &mut timer, if timer.is_armed() => {
                match TimerEvent::from(event_ord) {
                    TimerEvent::AckDeadline => {
                        return Err(AppendSessionError::AckTimeout);
                    }
                }
            }

            ack = acks.next() => {
                match ack {
                    Some(Ok(ack)) => {
                        process_ack(ack, state, timer.as_mut())?;
                    }
                    Some(Err(err)) if err.is_server_draining() => {
                        return Ok(());
                    }
                    Some(Err(err)) => {
                        return Err(err.into());
                    }
                    None => {
                        if !state.inflight_appends.is_empty() {
                            return Err(AppendSessionError::StreamClosedEarly);
                        }
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn connect(
    client: &BasinClient,
    stream: &StreamName,
    headers: &StreamHeaders,
    buffer_size: usize,
    frame_signal: Option<FrameSignal>,
    reconnect: ReconnectAdvice,
) -> Result<(mpsc::Sender<AppendInput>, Streaming<AppendAck>), AppendSessionError> {
    let (input_tx, input_rx) = mpsc::channel::<AppendInput>(buffer_size);
    let ack_stream = Box::pin(
        client
            .append_session(
                stream,
                ReceiverStream::new(input_rx).map(|i| i.into()),
                headers.encryption.as_ref(),
                headers.stream_config.as_ref(),
                frame_signal,
                reconnect,
            )
            .await?
            .map(|ack| match ack {
                Ok(ack) => Ok(ack.into()),
                Err(err) => Err(err),
            }),
    );
    Ok((input_tx, ack_stream))
}

fn process_ack(
    ack: AppendAck,
    state: &mut SessionState,
    timer: Pin<&mut MuxTimer<N_TIMER_VARIANTS>>,
) -> Result<(), AppendSessionError> {
    let corresponding_append = state.inflight_appends.pop_front().ok_or_else(|| {
        AppendSessionError::InvalidAck(
            "received ack without a corresponding append in flight".to_string(),
        )
    })?;

    if ack.end.seq_num < ack.start.seq_num {
        return Err(AppendSessionError::InvalidAck(
            "ack end seq_num should be greater than or equal to start seq_num".to_string(),
        ));
    }

    if state
        .prev_ack_end
        .is_some_and(|end| ack.end.seq_num <= end.seq_num)
    {
        return Err(AppendSessionError::InvalidAck(
            "ack end seq_num should be greater than previous ack end".to_string(),
        ));
    }

    let num_acked_records = (ack.end.seq_num - ack.start.seq_num) as usize;
    let expected_records = corresponding_append.input.records.len();
    if num_acked_records != expected_records {
        return Err(AppendSessionError::InvalidAck(format!(
            "acked record count {num_acked_records} does not match submitted batch size {expected_records}"
        )));
    }

    state.total_acked_records += num_acked_records;
    state.inflight_bytes -= corresponding_append.input_metered_bytes;
    state.prev_ack_end = Some(ack.end);

    let _ = corresponding_append.ack_tx.send(Ok(ack));

    if let Some(oldest_append) = state.inflight_appends.front() {
        timer.fire_at(
            TimerEvent::AckDeadline,
            oldest_append.ack_deadline,
            CoalesceMode::Latest,
        );
    } else {
        timer.cancel(TimerEvent::AckDeadline);
        assert_eq!(
            state.total_records, state.total_acked_records,
            "all records should be acked when inflight is empty"
        );
    }

    Ok(())
}

struct StashedSubmission {
    input: AppendInput,
    input_metered_bytes: usize,
    ack_tx: oneshot::Sender<Result<AppendAck, AppendSessionError>>,
    permit: Option<AppendPermit>,
}

struct InflightAppend {
    input: AppendInput,
    input_metered_bytes: usize,
    ack_tx: oneshot::Sender<Result<AppendAck, AppendSessionError>>,
    ack_deadline: Instant,
    _permit: Option<AppendPermit>,
    prior_uncertainty: bool,
}

enum Command {
    Submit {
        input: AppendInput,
        ack_tx: oneshot::Sender<Result<AppendAck, AppendSessionError>>,
        permit: Option<AppendPermit>,
    },
    Close {
        done_tx: oneshot::Sender<Result<(), AppendSessionError>>,
    },
}

impl Command {
    fn reject(self, err: AppendSessionError) {
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

fn is_safe_to_retry(
    err: &AppendSessionError,
    policy: AppendRetryPolicy,
    has_inflight: bool,
    frame_signal: Option<&FrameSignal>,
    access_token_mode: AccessTokenMode,
) -> bool {
    let policy_compliant = match policy {
        AppendRetryPolicy::All => true,
        AppendRetryPolicy::NoSideEffects => {
            !has_inflight || !err.attempt_may_have_side_effects(frame_signal)
        }
    };
    policy_compliant
        && (err.is_retryable()
            || (access_token_mode.is_refreshable() && err.is_authentication_error()))
}

const DEFAULT_CHANNEL_BUFFER_SIZE: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerEvent {
    AckDeadline,
}

const N_TIMER_VARIANTS: usize = 1;

impl From<TimerEvent> for usize {
    fn from(event: TimerEvent) -> Self {
        match event {
            TimerEvent::AckDeadline => 0,
        }
    }
}

impl From<usize> for TimerEvent {
    fn from(value: usize) -> Self {
        match value {
            0 => TimerEvent::AckDeadline,
            _ => panic!("invalid ordinal"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, error::Error};

    use http::StatusCode;
    use tokio::{
        sync::{mpsc, oneshot},
        time::Instant,
    };
    use tokio_util::task::AbortOnDropHandle;

    use super::{
        AppendPermits, AppendSession, AppendSessionError, Command, InflightAppend, SessionState,
        StashedSubmission, TerminalErrorLocks, is_safe_to_retry, settle_terminal_failure,
    };
    use crate::{
        api::{ApiError, ServerErrorBody},
        error::{AppendError, ProducerError, RequestError},
        frame_signal::FrameSignal,
        retry::AppendRetryError,
        types::{AccessTokenMode, AppendInput, AppendRecord, AppendRecordBatch, AppendRetryPolicy},
    };

    fn server_error(status: StatusCode, code: &str) -> AppendSessionError {
        AppendSessionError::Append(AppendError::Request(RequestError::from(ApiError::Server(
            status,
            ServerErrorBody {
                code: code.to_owned(),
                message: "test".to_owned(),
            },
        ))))
    }

    fn append_input(tag: &str) -> AppendInput {
        AppendInput::new(
            AppendRecordBatch::try_from_iter([AppendRecord::new(tag.to_owned()).unwrap()]).unwrap(),
        )
    }

    fn inflight_append(
        tag: &str,
        prior_uncertainty: bool,
    ) -> (
        InflightAppend,
        oneshot::Receiver<Result<crate::types::AppendAck, AppendSessionError>>,
    ) {
        let (ack_tx, ack_rx) = oneshot::channel();
        let append = InflightAppend {
            input: append_input(tag),
            input_metered_bytes: 0,
            ack_tx,
            ack_deadline: Instant::now(),
            _permit: None,
            prior_uncertainty,
        };
        (append, ack_rx)
    }

    fn stashed_submission(
        tag: &str,
    ) -> (
        StashedSubmission,
        oneshot::Receiver<Result<crate::types::AppendAck, AppendSessionError>>,
    ) {
        let (ack_tx, ack_rx) = oneshot::channel();
        let submission = StashedSubmission {
            input: append_input(tag),
            input_metered_bytes: 0,
            ack_tx,
            permit: None,
        };
        (submission, ack_rx)
    }

    #[rstest::rstest]
    #[case(StatusCode::FORBIDDEN, "permission_denied", false, false)]
    #[case(StatusCode::FORBIDDEN, "permission_denied", true, true)]
    #[case(StatusCode::SERVICE_UNAVAILABLE, "unavailable", false, false)]
    #[case(StatusCode::SERVICE_UNAVAILABLE, "unavailable", true, false)]
    #[case(StatusCode::TOO_MANY_REQUESTS, "rate_limited", true, true)]
    #[test]
    fn session_failure_preserves_uncertainty_and_latest_error(
        #[case] status: StatusCode,
        #[case] code: &str,
        #[case] prior_uncertainty: bool,
        #[case] wrapped: bool,
    ) {
        let latest = server_error(status, code);
        let error = latest.clone().with_prior_uncertainty(prior_uncertainty);
        assert_eq!(
            matches!(error, AppendSessionError::IndefiniteFailure { .. }),
            wrapped
        );
        assert_eq!(error.is_retryable(), latest.is_retryable());
        assert_eq!(
            error.has_no_side_effects(),
            !wrapped && latest.has_no_side_effects()
        );
        assert_eq!(
            error.request_error().unwrap().server_error().unwrap().code,
            code
        );
        if wrapped {
            let source = error
                .source()
                .unwrap()
                .downcast_ref::<Box<AppendSessionError>>()
                .unwrap();
            assert_eq!(source.to_string(), latest.to_string());
            assert!(source.has_no_side_effects());
        }

        let producer_error = ProducerError::from(error.clone());
        assert_eq!(producer_error.is_retryable(), error.is_retryable());
        assert_eq!(
            producer_error.has_no_side_effects(),
            error.has_no_side_effects()
        );
        assert_eq!(
            producer_error
                .request_error()
                .unwrap()
                .server_error()
                .unwrap()
                .code,
            code
        );
    }

    #[test]
    fn safe_to_retry_session_all_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let non_retryable = server_error(StatusCode::BAD_REQUEST, "bad_request");
        let policy = AppendRetryPolicy::All;
        let static_mode = AccessTokenMode::Static;

        // All policy — always policy-compliant, just needs retryable.
        assert!(is_safe_to_retry(
            &retryable,
            policy,
            true,
            None,
            static_mode
        ));
        assert!(!is_safe_to_retry(
            &non_retryable,
            policy,
            true,
            None,
            static_mode,
        ));

        let unauthorized = server_error(StatusCode::UNAUTHORIZED, "authn");
        #[cfg(feature = "_hidden")]
        assert!(is_safe_to_retry(
            &unauthorized,
            policy,
            true,
            None,
            AccessTokenMode::Refreshable,
        ));
        assert!(!is_safe_to_retry(
            &unauthorized,
            policy,
            true,
            None,
            static_mode,
        ));

        #[cfg(feature = "_hidden")]
        let unrelated_unauthorized = server_error(StatusCode::UNAUTHORIZED, "other");
        #[cfg(feature = "_hidden")]
        assert!(!is_safe_to_retry(
            &unrelated_unauthorized,
            policy,
            true,
            None,
            AccessTokenMode::Refreshable,
        ));
    }

    #[test]
    fn safe_to_retry_session_no_side_effects_policy() {
        let retryable = server_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let no_side_effect = server_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        let policy = AppendRetryPolicy::NoSideEffects;
        let signal = FrameSignal::new();
        let mode = AccessTokenMode::Static;

        // No inflight — always safe.
        signal.signal();
        assert!(is_safe_to_retry(
            &retryable,
            policy,
            false,
            Some(&signal),
            mode,
        ));

        // Inflight + signal not set — safe (no data sent this attempt).
        signal.reset();
        assert!(is_safe_to_retry(
            &retryable,
            policy,
            true,
            Some(&signal),
            mode,
        ));

        // Inflight + signal set + error with possible side effects — not safe.
        signal.signal();
        assert!(!is_safe_to_retry(
            &retryable,
            policy,
            true,
            Some(&signal),
            mode,
        ));

        // Inflight + signal set + no-side-effect error — safe.
        assert!(is_safe_to_retry(
            &no_side_effect,
            policy,
            true,
            Some(&signal),
            mode,
        ));

        // AckTimeout — retryable but has possible side effects.
        assert!(!is_safe_to_retry(
            &AppendSessionError::AckTimeout,
            policy,
            true,
            Some(&signal),
            mode,
        ));
    }

    #[tokio::test]
    async fn settle_terminal_failure_records_per_batch_and_session_errors() {
        // Final attempt failed definitively (permission_denied: no side effects, not retryable),
        // but an earlier, uncertain attempt of an inflight batch (A) may have taken effect — the
        // exact reachable scenario the bug report identifies (uncertain-then-definite failure
        // with the default `All` retry policy).
        let raw = server_error(StatusCode::FORBIDDEN, "permission_denied");
        assert!(raw.has_no_side_effects());
        assert!(!raw.is_retryable());

        let terminal_errors = TerminalErrorLocks::new();

        // Two inflight appends: A carried prior uncertainty (was sent, may have taken effect);
        // B did not (was not sent before the terminal failure).
        let (inflight_a, ack_a) = inflight_append("a", true);
        let (inflight_b, ack_b) = inflight_append("b", false);

        // A submission stashed but never sent to the server.
        let (stashed, stashed_ack) = stashed_submission("c");

        // A close handshake registered before the terminal failure.
        let (close_done_tx, close_done) = oneshot::channel();

        // Buffered commands that arrive while the terminal branch drains the channel.
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(8);
        let (buffered_submit_ack_tx, buffered_submit_ack) = oneshot::channel();
        cmd_tx
            .send(Command::Submit {
                input: append_input("d"),
                ack_tx: buffered_submit_ack_tx,
                permit: None,
            })
            .await
            .unwrap();
        let (buffered_close_done_tx, buffered_close_done) = oneshot::channel();
        cmd_tx
            .send(Command::Close {
                done_tx: buffered_close_done_tx,
            })
            .await
            .unwrap();
        drop(cmd_tx);

        let mut state = SessionState {
            cmd_rx,
            inflight_appends: [inflight_a, inflight_b].into_iter().collect(),
            inflight_bytes: 0,
            close_tx: Some(close_done_tx),
            total_records: 0,
            total_acked_records: 0,
            prev_ack_end: None,
            stashed_submission: Some(stashed),
        };

        settle_terminal_failure(raw.clone(), &mut state, &terminal_errors).await;

        // `terminal_errors.batch` is the per-batch fallback: the RAW final-attempt error, so a
        // never-sent batch reports the definite classification. This is the core guard against
        // the bug, which stored the wrapped aggregate here instead.
        let stored_batch = terminal_errors.batch.get().unwrap();
        assert!(stored_batch.has_no_side_effects());
        assert!(!matches!(
            stored_batch,
            AppendSessionError::IndefiniteFailure { .. }
        ));
        assert_eq!(stored_batch.to_string(), raw.to_string());

        // `terminal_errors.session` is the session-level summary reported by `close`: wrapped
        // because an inflight append carried prior uncertainty.
        let stored_session = terminal_errors.session.get().unwrap();
        assert!(!stored_session.has_no_side_effects());
        assert!(matches!(
            stored_session,
            AppendSessionError::IndefiniteFailure { .. }
        ));

        // Inflight A (prior uncertainty) is wrapped: it may have taken effect.
        let a_err = ack_a.await.unwrap().unwrap_err();
        assert!(!a_err.has_no_side_effects());
        assert!(matches!(
            a_err,
            AppendSessionError::IndefiniteFailure { .. }
        ));

        // Inflight B (no prior uncertainty) gets the raw definite error.
        let b_err = ack_b.await.unwrap().unwrap_err();
        assert!(b_err.has_no_side_effects());
        assert!(!matches!(
            b_err,
            AppendSessionError::IndefiniteFailure { .. }
        ));

        // The stashed, never-sent submission gets the raw definite error.
        let stashed_err = stashed_ack.await.unwrap().unwrap_err();
        assert!(stashed_err.has_no_side_effects());
        assert!(!matches!(
            stashed_err,
            AppendSessionError::IndefiniteFailure { .. }
        ));

        // The pre-registered close handshake gets the session-level summary.
        let close_err = close_done.await.unwrap().unwrap_err();
        assert!(!close_err.has_no_side_effects());
        assert!(matches!(
            close_err,
            AppendSessionError::IndefiniteFailure { .. }
        ));

        // A buffered `Command::Submit` (never sent) gets the raw definite error.
        let buffered_submit_err = buffered_submit_ack.await.unwrap().unwrap_err();
        assert!(buffered_submit_err.has_no_side_effects());
        assert!(!matches!(
            buffered_submit_err,
            AppendSessionError::IndefiniteFailure { .. }
        ));

        // A buffered `Command::Close` gets the session-level summary.
        let buffered_close_err = buffered_close_done.await.unwrap().unwrap_err();
        assert!(!buffered_close_err.has_no_side_effects());
        assert!(matches!(
            buffered_close_err,
            AppendSessionError::IndefiniteFailure { .. }
        ));

        // Everything buffered was drained; the session is quiesced.
        assert!(state.inflight_appends.is_empty());
        assert!(state.stashed_submission.is_none());
        assert!(state.close_tx.is_none());
    }

    #[tokio::test]
    async fn settle_terminal_failure_without_prior_uncertainty_stores_raw_everywhere() {
        // When no inflight append carried prior uncertainty, neither lock wraps: the per-batch
        // and session-level errors coincide with the raw terminal error.
        let raw = server_error(StatusCode::FORBIDDEN, "permission_denied");
        let terminal_errors = TerminalErrorLocks::new();

        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(1);
        drop(cmd_tx);

        let mut state = SessionState {
            cmd_rx,
            inflight_appends: VecDeque::new(),
            inflight_bytes: 0,
            close_tx: None,
            total_records: 0,
            total_acked_records: 0,
            prev_ack_end: None,
            stashed_submission: None,
        };

        settle_terminal_failure(raw.clone(), &mut state, &terminal_errors).await;

        let stored_batch = terminal_errors.batch.get().unwrap();
        let stored_session = terminal_errors.session.get().unwrap();
        assert!(stored_batch.has_no_side_effects());
        assert!(stored_session.has_no_side_effects());
        assert!(!matches!(
            stored_batch,
            AppendSessionError::IndefiniteFailure { .. }
        ));
        assert!(!matches!(
            stored_session,
            AppendSessionError::IndefiniteFailure { .. }
        ));
        assert_eq!(stored_batch.to_string(), raw.to_string());
        assert_eq!(stored_session.to_string(), raw.to_string());
    }

    #[tokio::test]
    async fn dead_session_submit_reserves_per_batch_error_but_close_reports_session_summary() {
        // Reproduce the post-terminal state the bug report describes: the session task has
        // exited (cmd_rx is dropped, so `reserve`/`submit` fall back to `terminal_err`), with
        // the per-batch lock holding the RAW definite error and the session-level lock holding
        // the wrapped summary — exactly as `settle_terminal_failure` records them.
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(1);
        drop(cmd_rx);

        let terminal_errors = TerminalErrorLocks::new();
        let raw = server_error(StatusCode::FORBIDDEN, "permission_denied");
        let session_summary = raw.clone().with_prior_uncertainty(true);
        assert!(raw.has_no_side_effects());
        assert!(!session_summary.has_no_side_effects());
        terminal_errors.batch.set(raw).unwrap();
        terminal_errors.session.set(session_summary).unwrap();

        let session = AppendSession {
            cmd_tx,
            permits: AppendPermits::new(None, crate::types::ONE_MIB),
            terminal_errors,
            _handle: AbortOnDropHandle::new(tokio::spawn(async {})),
        };

        // A brand-new batch submitted after the session died never left the process: it must
        // report the per-batch (raw, definite) error, not the session-level aggregate.
        let err = session
            .submit(append_input("never-sent"))
            .await
            .err()
            .unwrap();
        assert!(
            err.has_no_side_effects(),
            "never-sent batch must be definite"
        );
        assert!(!matches!(err, AppendSessionError::IndefiniteFailure { .. }));

        // `reserve`, the lower-level vector the report identifies as always-reachable, likewise
        // returns the per-batch raw error.
        let err = session.reserve(128).await.err().unwrap();
        assert!(err.has_no_side_effects());
        assert!(!matches!(err, AppendSessionError::IndefiniteFailure { .. }));

        // `close` on the dead session reports the session-level summary (wrapped).
        let close_err = session.close().await.unwrap_err();
        assert!(!close_err.has_no_side_effects());
        assert!(matches!(
            close_err,
            AppendSessionError::IndefiniteFailure { .. }
        ));
    }

    #[tokio::test]
    async fn batch_submit_ticket_dropped_ack_reports_per_batch_error() {
        // G4: the `BatchSubmitTicket::poll` `Err(_)` arm (the oneshot ack receiver's
        // sender was dropped without a send — e.g. a permit acquired while alive then
        // `submit` after the session task exited and drained `cmd_rx`) returns the
        // per-batch raw `terminal_err`, so a never-sent batch reports the definite
        // classification rather than the session-level aggregate.
        use std::{future::poll_fn, pin::Pin};

        use super::BatchSubmitTicket;

        let terminal_errors = TerminalErrorLocks::new();
        let raw = server_error(StatusCode::FORBIDDEN, "permission_denied");
        let session_summary = raw.clone().with_prior_uncertainty(true);
        assert!(raw.has_no_side_effects());
        assert!(!session_summary.has_no_side_effects());
        terminal_errors.batch.set(raw).unwrap();
        terminal_errors.session.set(session_summary).unwrap();

        // Construct a ticket whose ack sender is dropped without a send (simulating
        // the permit-acquired-then-task-exited window the report describes).
        let (_, ack_rx) = oneshot::channel::<Result<crate::types::AppendAck, AppendSessionError>>();
        // `ack_rx`'s sender is dropped immediately, so polling the ticket yields the
        // `Err(_)` receiver arm.
        let mut ticket = BatchSubmitTicket {
            rx: ack_rx,
            terminal_err: terminal_errors.batch.clone(),
        };

        let err = poll_fn(|cx| Pin::new(&mut ticket).poll(cx))
            .await
            .err()
            .unwrap();
        assert!(
            err.has_no_side_effects(),
            "dropped-ack ticket must report the per-batch definite error: {err}"
        );
        assert!(!matches!(err, AppendSessionError::IndefiniteFailure { .. }));
        assert!(matches!(
            err,
            AppendSessionError::Append(AppendError::Request(RequestError::Server(_)))
        ));
    }
}
