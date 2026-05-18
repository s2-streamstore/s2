use std::{pin::Pin, task::Poll, time::Duration};

use futures::StreamExt;
use s2_common::{
    encryption::EncryptionSpec,
    read_extent::{ReadLimit, ReadUntil},
    record::{Record, SequencedRecord},
    types::{
        basin::BasinName,
        stream::{ReadEnd, ReadFrom, ReadSessionOutput, ReadStart, StreamName},
    },
};
use s2_lite::backend::{Backend, error::ReadError};

use super::encryption_key_for_spec;

pub fn read_all_bounds() -> (ReadStart, ReadEnd) {
    (
        ReadStart {
            from: ReadFrom::SeqNum(0),
            clamp: false,
        },
        ReadEnd {
            limit: ReadLimit::Unbounded,
            until: ReadUntil::Unbounded,
            wait: Some(Duration::ZERO),
        },
    )
}

pub async fn open_read_session(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    start: ReadStart,
    end: ReadEnd,
) -> Pin<Box<impl futures::Stream<Item = Result<ReadSessionOutput, ReadError>> + use<>>> {
    open_read_session_with_encryption(backend, basin, stream, start, end, &EncryptionSpec::Plain)
        .await
}

pub async fn open_read_session_with_encryption(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    start: ReadStart,
    end: ReadEnd,
    encryption: &EncryptionSpec,
) -> Pin<Box<impl futures::Stream<Item = Result<ReadSessionOutput, ReadError>> + use<>>> {
    try_open_read_session_with_encryption(backend, basin, stream, start, end, encryption)
        .await
        .expect("Failed to create read session")
}

pub async fn try_open_read_session(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    start: ReadStart,
    end: ReadEnd,
) -> Result<
    Pin<Box<impl futures::Stream<Item = Result<ReadSessionOutput, ReadError>> + use<>>>,
    ReadError,
> {
    try_open_read_session_with_encryption(
        backend,
        basin,
        stream,
        start,
        end,
        &EncryptionSpec::Plain,
    )
    .await
}

pub async fn try_open_read_session_with_encryption(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    start: ReadStart,
    end: ReadEnd,
    encryption: &EncryptionSpec,
) -> Result<
    Pin<Box<impl futures::Stream<Item = Result<ReadSessionOutput, ReadError>> + use<>>>,
    ReadError,
> {
    let read_session = backend
        .open_for_read(basin, stream, encryption_key_for_spec(encryption))
        .await?
        .read(start, end)
        .await?;
    Ok(Box::pin(read_session))
}

pub async fn advance_time(by: Duration) {
    tokio::time::advance(by).await;
    tokio::task::yield_now().await;
}

pub enum SessionPoll {
    Output(ReadSessionOutput),
    Closed,
    TimedOut,
}

pub struct ClosedSessionOutputs {
    pub outputs: Vec<ReadSessionOutput>,
    pub closed_at: tokio::time::Instant,
}

fn map_session_output(output: Option<Result<ReadSessionOutput, ReadError>>) -> SessionPoll {
    match output {
        Some(Ok(output)) => SessionPoll::Output(output),
        Some(Err(e)) => panic!("Read error: {:?}", e),
        None => SessionPoll::Closed,
    }
}

pub async fn poll_session_with_deadline<S>(
    session: &mut Pin<Box<S>>,
    deadline: tokio::time::Instant,
    advance_step: Option<Duration>,
) -> SessionPoll
where
    S: futures::Stream<Item = Result<ReadSessionOutput, ReadError>>,
{
    if let Some(step) = advance_step {
        let mut pinned_session = session.as_mut();
        let next = pinned_session.next();
        tokio::pin!(next);

        loop {
            let now = tokio::time::Instant::now();
            let Some(remaining) = deadline.checked_duration_since(now) else {
                return SessionPoll::TimedOut;
            };

            if remaining.is_zero() {
                return match futures::poll!(&mut next) {
                    Poll::Ready(output) => map_session_output(output),
                    Poll::Pending => SessionPoll::TimedOut,
                };
            }

            tokio::select! {
                biased;
                output = &mut next => return map_session_output(output),
                () = tokio::time::advance(step.min(remaining)) => {
                    tokio::task::yield_now().await;
                }
            }
        }
    }

    loop {
        let now = tokio::time::Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            return SessionPoll::TimedOut;
        };

        match tokio::time::timeout(
            remaining.min(Duration::from_millis(500)),
            session.as_mut().next(),
        )
        .await
        {
            Ok(output) => return map_session_output(output),
            Err(_) => continue,
        }
    }
}

async fn collect_records_inner<S>(
    session: &mut Pin<Box<S>>,
    timeout: Option<Duration>,
    target_count: Option<usize>,
    advance_step: Option<Duration>,
) -> Vec<SequencedRecord>
where
    S: futures::Stream<Item = Result<ReadSessionOutput, ReadError>>,
{
    let deadline = timeout.map(|timeout| tokio::time::Instant::now() + timeout);
    let mut records = Vec::new();

    loop {
        if let Some(target_count) = target_count
            && records.len() >= target_count
        {
            break;
        }

        let polled = if let Some(deadline) = deadline {
            poll_session_with_deadline(session, deadline, advance_step).await
        } else {
            match session.as_mut().next().await {
                Some(Ok(output)) => SessionPoll::Output(output),
                Some(Err(e)) => panic!("Read error: {:?}", e),
                None => SessionPoll::Closed,
            }
        };

        match polled {
            SessionPoll::Output(ReadSessionOutput::Batch(batch)) => {
                if let Some(target_count) = target_count {
                    let remaining = target_count.saturating_sub(records.len());
                    records.extend(batch.records.iter().take(remaining).cloned());
                    if batch.records.len() >= remaining {
                        break;
                    }
                } else {
                    records.extend(batch.records.iter().cloned());
                }
            }
            SessionPoll::Output(ReadSessionOutput::Heartbeat(_)) => {}
            SessionPoll::Closed | SessionPoll::TimedOut => break,
        }
    }

    records
}

pub async fn collect_records<S>(session: &mut Pin<Box<S>>) -> Vec<SequencedRecord>
where
    S: futures::Stream<Item = Result<ReadSessionOutput, ReadError>>,
{
    collect_records_inner(session, None, None, None).await
}

pub async fn collect_records_until_advanced<S>(
    session: &mut Pin<Box<S>>,
    timeout: Duration,
    target_count: usize,
    advance_step: Duration,
) -> Vec<SequencedRecord>
where
    S: futures::Stream<Item = Result<ReadSessionOutput, ReadError>>,
{
    collect_records_inner(
        session,
        Some(timeout),
        Some(target_count),
        Some(advance_step),
    )
    .await
}

pub async fn expect_heartbeat_advanced<S>(
    session: &mut Pin<Box<S>>,
    timeout: Duration,
    advance_step: Duration,
) where
    S: futures::Stream<Item = Result<ReadSessionOutput, ReadError>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let output = match poll_session_with_deadline(session, deadline, Some(advance_step)).await {
        SessionPoll::Output(output) => output,
        SessionPoll::Closed => panic!("Read session ended unexpectedly"),
        SessionPoll::TimedOut => panic!("Timed out waiting for heartbeat"),
    };

    assert!(
        matches!(output, ReadSessionOutput::Heartbeat(_)),
        "Unexpected first output: {output:?}"
    );
}

pub async fn collect_outputs_until_closed_advanced<S>(
    session: &mut Pin<Box<S>>,
    timeout: Duration,
    advance_step: Duration,
) -> ClosedSessionOutputs
where
    S: futures::Stream<Item = Result<ReadSessionOutput, ReadError>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut outputs = Vec::new();

    loop {
        match poll_session_with_deadline(session, deadline, Some(advance_step)).await {
            SessionPoll::Output(output) => outputs.push(output),
            SessionPoll::Closed => {
                return ClosedSessionOutputs {
                    outputs,
                    closed_at: tokio::time::Instant::now(),
                };
            }
            SessionPoll::TimedOut => panic!("Timed out waiting for read session to close"),
        }
    }
}

pub async fn collect_records_until_closed_advanced<S>(
    session: &mut Pin<Box<S>>,
    timeout: Duration,
    advance_step: Duration,
) -> Vec<SequencedRecord>
where
    S: futures::Stream<Item = Result<ReadSessionOutput, ReadError>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut records = Vec::new();

    loop {
        match poll_session_with_deadline(session, deadline, Some(advance_step)).await {
            SessionPoll::Output(ReadSessionOutput::Batch(batch)) => {
                records.extend(batch.records.iter().cloned());
            }
            SessionPoll::Output(ReadSessionOutput::Heartbeat(_)) => {}
            SessionPoll::Closed => break,
            SessionPoll::TimedOut => panic!("Timed out waiting for read session to close"),
        }
    }

    records
}

pub async fn read_records(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    start: ReadStart,
    end: ReadEnd,
) -> Vec<SequencedRecord> {
    let read_session = open_read_session(backend, basin, stream, start, end).await;
    let mut read_session = Box::pin(read_session);
    collect_records(&mut read_session).await
}

pub async fn read_records_with_encryption(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    start: ReadStart,
    end: ReadEnd,
    encryption: &EncryptionSpec,
) -> Vec<SequencedRecord> {
    let read_session =
        open_read_session_with_encryption(backend, basin, stream, start, end, encryption).await;
    let mut read_session = Box::pin(read_session);
    collect_records(&mut read_session).await
}

pub fn envelope_bodies(records: &[SequencedRecord]) -> Vec<Vec<u8>> {
    records
        .iter()
        .map(|record| match record.inner() {
            Record::Envelope(envelope) => envelope.body().to_vec(),
            other => panic!("Unexpected record type: {:?}", other),
        })
        .collect()
}
