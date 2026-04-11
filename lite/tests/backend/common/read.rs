use std::{pin::Pin, task::Poll, time::Duration};

use futures::StreamExt;
use s2_common::{
    encryption::EncryptionSpec,
    read_extent::{ReadLimit, ReadUntil},
    record::{Record, SequencedRecord},
    types::{
        basin::BasinName,
        stream::{
            ReadBatch, ReadEnd, ReadFrom, ReadStart, StoredReadBatch, StoredReadSessionOutput,
            StreamName,
        },
    },
};
use s2_lite::backend::{Backend, error::ReadError};

pub fn decrypt_plain_batch(batch: StoredReadBatch) -> ReadBatch {
    batch
        .decrypt(&EncryptionSpec::Plain, &[])
        .expect("Failed to decode batch")
}

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

pub async fn first_stored_batch(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
) -> StoredReadBatch {
    let (start, end) = read_all_bounds();
    let read_session = backend
        .read(basin.clone(), stream.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut read_session = Box::pin(read_session);
    match read_session.next().await {
        Some(Ok(StoredReadSessionOutput::Batch(batch))) => batch,
        Some(Ok(other)) => panic!("Unexpected first output: {other:?}"),
        Some(Err(err)) => panic!("Unexpected backend read error: {err:?}"),
        None => panic!("Read session ended without delivering batch"),
    }
}

pub async fn open_read_session(
    backend: &Backend,
    basin: &BasinName,
    stream: &StreamName,
    start: ReadStart,
    end: ReadEnd,
) -> Pin<Box<impl futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>>> {
    let read_session = backend
        .read(basin.clone(), stream.clone(), start, end)
        .await
        .expect("Failed to create read session");
    Box::pin(read_session)
}

pub async fn advance_time(by: Duration) {
    tokio::time::advance(by).await;
    tokio::task::yield_now().await;
}

pub fn decrypt_batch_for_stream(
    batch: StoredReadBatch,
    basin: &BasinName,
    stream: &StreamName,
    encryption: &EncryptionSpec,
) -> ReadBatch {
    let stream_id = s2_lite::backend::StreamId::new(basin, stream);
    batch
        .decrypt(encryption, stream_id.as_bytes())
        .expect("Failed to decode batch")
}

pub enum SessionPoll {
    Output(StoredReadSessionOutput),
    Closed,
    TimedOut,
}

pub struct ClosedSessionOutputs {
    pub outputs: Vec<StoredReadSessionOutput>,
    pub closed_at: tokio::time::Instant,
}

fn map_session_output(output: Option<Result<StoredReadSessionOutput, ReadError>>) -> SessionPoll {
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
    S: futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>,
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

    // The wall-clock polling path is only used by `collect_records` and
    // `collect_records_with_encryption`, which intentionally block without their
    // own timeout budget. Timed callers should use `advance_step` instead. A
    // stuck session here will only surface via the outer test-runner timeout.
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

async fn collect_records_with_decoder<S, D>(
    session: &mut Pin<Box<S>>,
    timeout: Option<Duration>,
    target_count: Option<usize>,
    advance_step: Option<Duration>,
    mut decode_batch: D,
) -> Vec<SequencedRecord>
where
    S: futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>,
    D: FnMut(StoredReadBatch) -> ReadBatch,
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
            SessionPoll::Output(StoredReadSessionOutput::Batch(batch)) => {
                let batch = decode_batch(batch);
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
            SessionPoll::Output(StoredReadSessionOutput::Heartbeat(_)) => {}
            SessionPoll::Closed | SessionPoll::TimedOut => break,
        }
    }

    records
}

pub async fn collect_records<S>(session: &mut Pin<Box<S>>) -> Vec<SequencedRecord>
where
    S: futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>,
{
    collect_records_with_decoder(session, None, None, None, decrypt_plain_batch).await
}

pub async fn collect_records_until_advanced<S>(
    session: &mut Pin<Box<S>>,
    timeout: Duration,
    target_count: usize,
    advance_step: Duration,
) -> Vec<SequencedRecord>
where
    S: futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>,
{
    collect_records_with_decoder(
        session,
        Some(timeout),
        Some(target_count),
        Some(advance_step),
        decrypt_plain_batch,
    )
    .await
}

pub async fn collect_records_with_encryption<S>(
    session: &mut Pin<Box<S>>,
    basin: &BasinName,
    stream: &StreamName,
    encryption: &EncryptionSpec,
) -> Vec<SequencedRecord>
where
    S: futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>,
{
    collect_records_with_decoder(session, None, None, None, |batch| {
        decrypt_batch_for_stream(batch, basin, stream, encryption)
    })
    .await
}

pub async fn expect_heartbeat_advanced<S>(
    session: &mut Pin<Box<S>>,
    timeout: Duration,
    advance_step: Duration,
) where
    S: futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let output = match poll_session_with_deadline(session, deadline, Some(advance_step)).await {
        SessionPoll::Output(output) => output,
        SessionPoll::Closed => panic!("Read session ended unexpectedly"),
        SessionPoll::TimedOut => panic!("Timed out waiting for heartbeat"),
    };

    assert!(
        matches!(output, StoredReadSessionOutput::Heartbeat(_)),
        "Unexpected first output: {output:?}"
    );
}

pub async fn collect_outputs_until_closed_advanced<S>(
    session: &mut Pin<Box<S>>,
    timeout: Duration,
    advance_step: Duration,
) -> ClosedSessionOutputs
where
    S: futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>,
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
    S: futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>,
{
    collect_records_until_closed_with_decoder(session, timeout, advance_step, decrypt_plain_batch)
        .await
}

async fn collect_records_until_closed_with_decoder<S, D>(
    session: &mut Pin<Box<S>>,
    timeout: Duration,
    advance_step: Duration,
    mut decode_batch: D,
) -> Vec<SequencedRecord>
where
    S: futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>,
    D: FnMut(StoredReadBatch) -> ReadBatch,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut records = Vec::new();

    loop {
        match poll_session_with_deadline(session, deadline, Some(advance_step)).await {
            SessionPoll::Output(StoredReadSessionOutput::Batch(batch)) => {
                let batch = decode_batch(batch);
                records.extend(batch.records.iter().cloned());
            }
            SessionPoll::Output(StoredReadSessionOutput::Heartbeat(_)) => {}
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
    let read_session = backend
        .read(basin.clone(), stream.clone(), start, end)
        .await
        .expect("Failed to create read session");
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
    let read_session = backend
        .read(basin.clone(), stream.clone(), start, end)
        .await
        .expect("Failed to create read session");
    let mut read_session = Box::pin(read_session);
    collect_records_with_encryption(&mut read_session, basin, stream, encryption).await
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
