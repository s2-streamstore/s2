use std::time::Duration;

use futures::{Stream, StreamExt as _};
use s2_common::{
    basin::BasinName,
    caps,
    config::OptionalStreamConfig,
    encryption::{EncryptionKey, EncryptionSpec},
    read_extent::{EvaluatedReadLimit, ReadLimit, ReadUntil},
    record::{Metered, MeteredSize as _, SeqNum, StreamPosition, Timestamp},
    stream::{ReadEnd, ReadPosition, ReadSessionOutput, ReadStart, StreamName},
};
use s2_storage::record::{
    StoredReadBatch, StoredReadSessionOutput, StoredSequencedRecord, decrypt_read_session_output,
};
use slatedb::config::{DurabilityLevel, ScanOptions};
use tokio::{sync::broadcast, time::Instant};

use super::{Backend, StreamHandle, core::AutoCreateOn};
use crate::{
    backend::{
        error::{
            CheckTailError, ReadError, StorageError, StreamerMissingInActionError, UnwrittenError,
        },
        kv,
        streamer::GuardedStreamerClient,
    },
    stream_id::StreamId,
};

impl Backend {
    /// Open a stream for a check tail.
    pub async fn open_for_check_tail(
        &self,
        basin: &BasinName,
        stream: &StreamName,
    ) -> Result<StreamHandle, CheckTailError> {
        self.stream_handle_with_auto_create::<CheckTailError>(
            basin,
            stream,
            AutoCreateOn::Read,
            OptionalStreamConfig::default(),
            |_| Ok(EncryptionSpec::Plain),
        )
        .await
    }

    /// Open a stream for a read or read session.
    ///
    /// `stream_config` is applied if the stream is created on read. Unset fields inherit the
    /// basin's default stream configuration. Ignored if the stream already exists.
    pub async fn open_for_read(
        &self,
        basin: &BasinName,
        stream: &StreamName,
        encryption_key: Option<EncryptionKey>,
        stream_config: OptionalStreamConfig,
    ) -> Result<StreamHandle, ReadError> {
        self.stream_handle_with_auto_create::<ReadError>(
            basin,
            stream,
            AutoCreateOn::Read,
            stream_config,
            |cipher| Ok(EncryptionSpec::resolve(cipher, encryption_key)?),
        )
        .await
    }
}

impl StreamHandle {
    pub async fn check_tail(self) -> Result<StreamPosition, CheckTailError> {
        let tail = self.client.check_tail().await?;
        Ok(tail)
    }

    pub async fn read(
        self,
        start: ReadStart,
        end: ReadEnd,
    ) -> Result<impl Stream<Item = Result<ReadSessionOutput, ReadError>> + 'static, ReadError> {
        let stream_id = self.client.stream_id();
        let session = read_session(self.db, self.client, start, end).await?;
        Ok(async_stream::stream! {
            tokio::pin!(session);
            while let Some(output) = session.next().await {
                let output = match output {
                    Ok(output) => {
                        decrypt_read_session_output(output, &self.encryption, stream_id.as_bytes())
                            .map_err(ReadError::from)
                    }
                    Err(err) => Err(err),
                };
                let should_stop = output.is_err();
                yield output;
                if should_stop {
                    break;
                }
            }
        })
    }
}

async fn read_session(
    db: slatedb::Db,
    client: GuardedStreamerClient,
    start: ReadStart,
    end: ReadEnd,
) -> Result<impl Stream<Item = Result<StoredReadSessionOutput, ReadError>> + 'static, ReadError> {
    // An exhausted limit completes even when the requested start is unwritten.
    if end.limit.remaining(0, 0) == EvaluatedReadLimit::Exhausted {
        return Ok(futures::stream::empty().left_stream());
    }
    let stream_id = client.stream_id();
    let tail = client.check_tail().await?;
    let mut state = ReadSessionState {
        start_seq_num: read_start_seq_num(&db, stream_id, start, tail).await?,
        limit: EvaluatedReadLimit::Remaining(end.limit),
        until: end.until,
        wait: end.wait,
        wait_deadline: None,
        tail,
    };
    let session = async_stream::try_stream! {
        'session: while let EvaluatedReadLimit::Remaining(limit) = state.limit {
            if state.start_seq_num < state.tail.seq_num {
                let prefix = kv::stream_record_data::ser_key_prefix(stream_id);
                let start_suffix = kv::stream_record_data::ser_key_suffix(StreamPosition {
                    seq_num: state.start_seq_num,
                    timestamp: 0,
                });
                let end_suffix = kv::stream_record_data::ser_key_suffix(StreamPosition {
                    seq_num: state.tail.seq_num,
                    timestamp: 0,
                });
                let scan_opts = ScanOptions {
                    durability_filter: DurabilityLevel::Remote,
                    read_ahead_bytes: 1024 * 1024,
                    cache_blocks: true,
                    max_fetch_tasks: 8,
                    ..Default::default()
                };
                let mut it = db
                    .scan_prefix_with_options(prefix, start_suffix..end_suffix, &scan_opts)
                    .await?;

                let mut records = Metered::with_capacity(
                    limit.into_allowance(caps::RECORD_BATCH_MAX).count as usize,
                );
                let mut stopped_before_tail = false;

                while let EvaluatedReadLimit::Remaining(limit) = state.limit {
                    let Some(kv) = it.next().await? else {
                        break;
                    };
                    let (deser_stream_id, pos) = kv::stream_record_data::deser_key(kv.key)?;
                    assert_eq!(deser_stream_id, stream_id);

                    let record = kv::stream_record_data::deser_value(kv.value)?.sequenced(pos);

                    if end.until.deny(pos.timestamp)
                        || limit.deny(
                            records.len() as u64 + 1,
                            records.metered_size() as u64 + record.metered_size() as u64,
                        )
                    {
                        stopped_before_tail = true;
                        break;
                    }

                    if records.len() == caps::RECORD_BATCH_MAX.count
                        || records.metered_size() + record.metered_size() > caps::RECORD_BATCH_MAX.bytes
                    {
                        let new_records_buf = Metered::with_capacity(
                            limit
                                .count()
                                .map_or(u64::MAX, |n| n.saturating_sub(records.len() as u64))
                                .min(caps::RECORD_BATCH_MAX.count as u64) as usize,
                        );
                        yield state.on_batch(StoredReadBatch {
                            records: std::mem::replace(&mut records, new_records_buf),
                            tail: None,
                        });
                    }

                    records.push(record);
                }

                if !records.is_empty() {
                    yield state.on_batch(StoredReadBatch {
                        records,
                        tail: None,
                    });
                }
                if stopped_before_tail {
                    break 'session;
                }
                state.start_seq_num = state.tail.seq_num;
            } else {
                assert_eq!(state.start_seq_num, state.tail.seq_num);
                if end.until.deny(state.tail.timestamp) {
                    break 'session;
                }
                let follow_rx = if end.may_follow() {
                    match client.follow(state.start_seq_num).await? {
                        Ok(follow_rx) => {
                            // Only a delivered batch should reset the absolute wait budget.
                            state.arm_wait_deadline_if_unset();
                            (!state.wait_deadline_expired()).then_some(follow_rx)
                        }
                        Err(tail) => {
                            assert!(state.tail.seq_num < tail.seq_num, "tail cannot regress");
                            state.tail = tail;
                            continue 'session;
                        }
                    }
                } else {
                    None
                };
                yield StoredReadSessionOutput::Heartbeat(state.tail);
                let Some(mut follow_rx) = follow_rx else {
                    break 'session;
                };
                while let EvaluatedReadLimit::Remaining(limit) = state.limit {
                    tokio::select! {
                        biased;
                        msg = follow_rx.recv() => {
                            match msg {
                                Ok(mut records) => {
                                    let count = records.len();
                                    let tail = super::streamer::next_pos(&records);
                                    let allowed_count = count_allowed_records(limit, end.until, &records);
                                    if allowed_count > 0 {
                                        yield state.on_batch(StoredReadBatch {
                                            records: records.drain(..allowed_count).collect(),
                                            tail: Some(tail),
                                        });
                                    }
                                    if allowed_count < count {
                                        break 'session;
                                    }
                                    Ok(())
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => {
                                    // Catch up using DB
                                    continue 'session;
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    Err(StreamerMissingInActionError)
                                }
                            }
                        }
                        _ = new_heartbeat_sleep() => {
                            yield StoredReadSessionOutput::Heartbeat(state.tail);
                            Ok(())
                        }
                        _ = wait_sleep_until(state.wait_deadline) => {
                            break 'session;
                        }
                    }?;
                }
            }
        }
    };
    Ok(session.right_stream())
}

async fn read_start_seq_num(
    db: &slatedb::Db,
    stream_id: StreamId,
    start: ReadStart,
    tail: StreamPosition,
) -> Result<SeqNum, ReadError> {
    let mut read_pos = match start.from {
        s2_common::stream::ReadFrom::SeqNum(seq_num) => ReadPosition::SeqNum(seq_num),
        s2_common::stream::ReadFrom::Timestamp(timestamp) => ReadPosition::Timestamp(timestamp),
        s2_common::stream::ReadFrom::TailOffset(tail_offset) => {
            ReadPosition::SeqNum(tail.seq_num.saturating_sub(tail_offset))
        }
    };
    if match read_pos {
        ReadPosition::SeqNum(start_seq_num) => start_seq_num > tail.seq_num,
        ReadPosition::Timestamp(start_timestamp) => start_timestamp > tail.timestamp,
    } {
        if start.clamp {
            read_pos = ReadPosition::SeqNum(tail.seq_num);
        } else {
            return Err(UnwrittenError(tail).into());
        }
    }
    let start_seq_num = match read_pos {
        ReadPosition::SeqNum(start_seq_num) => start_seq_num,
        ReadPosition::Timestamp(start_timestamp) => {
            resolve_timestamp(db, stream_id, start_timestamp)
                .await?
                .map_or(tail.seq_num, |pos| pos.seq_num.min(tail.seq_num))
        }
    };
    Ok(start_seq_num)
}

async fn resolve_timestamp(
    db: &slatedb::Db,
    stream_id: StreamId,
    timestamp: Timestamp,
) -> Result<Option<StreamPosition>, StorageError> {
    let prefix = kv::stream_record_timestamp::ser_key_prefix(stream_id);
    let start_suffix = kv::stream_record_timestamp::ser_key_suffix(StreamPosition {
        seq_num: SeqNum::MIN,
        timestamp,
    });
    let scan_opts = ScanOptions {
        durability_filter: DurabilityLevel::Remote,
        ..Default::default()
    };
    let mut it = db
        .scan_prefix_with_options(prefix, start_suffix.., &scan_opts)
        .await?;
    Ok(match it.next().await? {
        Some(kv) => {
            let (deser_stream_id, pos) = kv::stream_record_timestamp::deser_key(kv.key)?;
            assert_eq!(deser_stream_id, stream_id);
            assert!(pos.timestamp >= timestamp);
            kv::stream_record_timestamp::deser_value(kv.value)?;
            Some(StreamPosition {
                seq_num: pos.seq_num,
                timestamp: pos.timestamp,
            })
        }
        None => None,
    })
}

struct ReadSessionState {
    start_seq_num: u64,
    limit: EvaluatedReadLimit,
    until: ReadUntil,
    wait: Option<Duration>,
    wait_deadline: Option<Instant>,
    tail: StreamPosition,
}

impl ReadSessionState {
    fn arm_wait_deadline_if_unset(&mut self) {
        if self.wait_deadline.is_none() {
            self.reset_wait_deadline();
        }
    }

    fn reset_wait_deadline(&mut self) {
        self.wait_deadline = self.wait.map(|wait| Instant::now() + wait);
    }

    fn wait_deadline_expired(&self) -> bool {
        self.wait_deadline
            .is_some_and(|deadline| deadline <= Instant::now())
    }

    fn on_batch(&mut self, batch: StoredReadBatch) -> StoredReadSessionOutput {
        if let Some(tail) = batch.tail {
            self.tail = tail;
        }
        let last_record = batch.records.last().expect("non-empty");
        let EvaluatedReadLimit::Remaining(limit) = self.limit else {
            panic!("batch after exhausted limit");
        };
        let count = batch.records.len() as u64;
        let bytes = batch.records.metered_size() as u64;
        let last_position = last_record.position();
        assert!(limit.allow(count, bytes));
        assert!(self.until.allow(last_position.timestamp));
        self.start_seq_num = last_position.seq_num + 1;
        self.limit = limit.remaining(count, bytes);
        self.reset_wait_deadline();
        StoredReadSessionOutput::Batch(batch)
    }
}

fn count_allowed_records(
    limit: ReadLimit,
    until: ReadUntil,
    records: &[Metered<StoredSequencedRecord>],
) -> usize {
    let mut acc_size = 0u64;
    let mut acc_count = 0usize;
    for record in records {
        if limit.deny(
            acc_count as u64 + 1,
            acc_size + record.metered_size() as u64,
        ) || until.deny(record.position().timestamp)
        {
            break;
        }
        acc_count += 1;
        acc_size += record.metered_size() as u64;
    }
    acc_count
}

#[cfg(not(test))]
fn new_heartbeat_sleep() -> tokio::time::Sleep {
    tokio::time::sleep(Duration::from_millis(rand::random_range(5_000..15_000)))
}

#[cfg(test)]
fn new_heartbeat_sleep() -> tokio::time::Sleep {
    tokio::time::sleep(Duration::from_millis(rand::random_range(5..15)))
}

async fn wait_sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, task::Poll};

    use bytesize::ByteSize;
    use futures::StreamExt;
    use rstest::rstest;
    use s2_common::{
        basin::BasinName,
        config::{BasinConfig, OptionalStreamConfig},
        read_extent::{ReadLimit, ReadUntil},
        record::{Metered, Record},
        resources::ProvisionMode,
        stream::{
            AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts, ReadEnd, ReadFrom,
            ReadSessionOutput, ReadStart, StreamName,
        },
    };
    use slatedb::{Db, WriteBatch, object_store::memory::InMemory};
    use tokio::time::Instant;

    use super::*;
    use crate::{
        backend::{
            FOLLOWER_MAX_LAG, kv, streamer::DORMANT_TIMEOUT, test_util::DbWriteTestExt as _,
        },
        stream_id::StreamId,
    };

    async fn setup_stream() -> (Backend, BasinName, StreamName) {
        let object_store = Arc::new(InMemory::new());
        let db = Db::builder("/test", object_store).build().await.unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));

        let basin: BasinName = "test-basin".parse().unwrap();
        backend
            .provision_basin(
                basin.clone(),
                BasinConfig::default(),
                ProvisionMode::CreateOnly {
                    request_token: None,
                },
            )
            .await
            .unwrap();
        let stream: StreamName = "test-stream".parse().unwrap();
        backend
            .provision_stream(
                basin.clone(),
                stream.clone(),
                OptionalStreamConfig::default(),
                ProvisionMode::CreateOnly {
                    request_token: None,
                },
            )
            .await
            .unwrap();
        (backend, basin, stream)
    }

    fn append_input(record: Record) -> AppendInput {
        let record: AppendRecord = AppendRecordParts {
            timestamp: None,
            record: Metered::from(record),
        }
        .try_into()
        .unwrap();
        let records: AppendRecordBatch = vec![record].try_into().unwrap();
        AppendInput {
            records,
            match_seq_num: None,
            fencing_token: None,
        }
    }

    fn map_test_output(
        output: Option<Result<ReadSessionOutput, ReadError>>,
    ) -> Option<ReadSessionOutput> {
        match output {
            Some(Ok(output)) => Some(output),
            Some(Err(e)) => panic!("Read error: {e:?}"),
            None => None,
        }
    }

    async fn poll_next_after_advance<S>(
        session: &mut std::pin::Pin<Box<S>>,
        advance_by: Duration,
    ) -> Poll<Option<ReadSessionOutput>>
    where
        S: futures::Stream<Item = Result<ReadSessionOutput, ReadError>>,
    {
        let mut pinned_session = session.as_mut();
        let next = pinned_session.next();
        tokio::pin!(next);

        assert!(
            matches!(futures::poll!(&mut next), Poll::Pending),
            "session unexpectedly yielded before time advanced"
        );

        tokio::time::advance(advance_by).await;
        tokio::task::yield_now().await;

        match futures::poll!(&mut next) {
            Poll::Ready(output) => Poll::Ready(map_test_output(output)),
            Poll::Pending => Poll::Pending,
        }
    }

    #[tokio::test]
    async fn resolve_timestamp_bounded_to_stream() {
        let object_store = Arc::new(InMemory::new());
        let db = Db::builder("/test", object_store).build().await.unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));

        let stream_a: StreamId = [0u8; 32].into();
        let stream_b: StreamId = [1u8; 32].into();

        backend
            .db
            .put(
                kv::stream_record_timestamp::ser_key(
                    stream_a,
                    StreamPosition {
                        seq_num: 0,
                        timestamp: 1000,
                    },
                ),
                kv::stream_record_timestamp::ser_value(),
            )
            .assert_durable()
            .await;
        backend
            .db
            .put(
                kv::stream_record_timestamp::ser_key(
                    stream_b,
                    StreamPosition {
                        seq_num: 0,
                        timestamp: 2000,
                    },
                ),
                kv::stream_record_timestamp::ser_value(),
            )
            .assert_durable()
            .await;

        // Should find record in stream_a
        let result = resolve_timestamp(&backend.db, stream_a, 500).await.unwrap();
        assert_eq!(
            result,
            Some(StreamPosition {
                seq_num: 0,
                timestamp: 1000
            })
        );

        // Should return None, not find stream_b's record
        let result = resolve_timestamp(&backend.db, stream_a, 1500)
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[rstest]
    #[case::all_deleted(1, 0)]
    #[case::trailing_gap(3, 1)]
    #[tokio::test]
    async fn read_emits_tail_heartbeat_across_deleted_gap(
        #[case] total_records: usize,
        #[case] keep_prefix: usize,
    ) {
        let (backend, basin, stream) = setup_stream().await;

        let mut acks = Vec::new();
        for i in 0..total_records {
            let input = append_input(
                Record::try_from_parts(vec![], bytes::Bytes::from(format!("r{i}"))).unwrap(),
            );
            let ack = backend
                .open_for_append(&basin, &stream, None, OptionalStreamConfig::default())
                .await
                .unwrap()
                .append(input)
                .await
                .unwrap();
            acks.push(ack);
        }

        let stream_id = StreamId::new(&basin, &stream);
        let mut batch = WriteBatch::new();
        for ack in &acks[keep_prefix..] {
            batch.delete(kv::stream_record_data::ser_key(stream_id, ack.start));
        }
        backend.db.write(batch).assert_durable().await;

        let expected_tail = acks.last().unwrap().end;
        let session = backend
            .open_for_read(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .read(
                ReadStart {
                    from: ReadFrom::SeqNum(0),
                    clamp: false,
                },
                ReadEnd {
                    limit: ReadLimit::Count(10),
                    until: ReadUntil::Unbounded,
                    wait: None,
                },
            )
            .await
            .unwrap();
        let outputs: Vec<_> = tokio::time::timeout(
            Duration::from_secs(2),
            futures::StreamExt::collect::<Vec<_>>(session),
        )
        .await
        .expect("read should not spin forever")
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

        let (last, prefix) = outputs
            .split_last()
            .expect("expected trailing tail heartbeat");
        assert!(
            matches!(last, ReadSessionOutput::Heartbeat(tail) if *tail == expected_tail),
            "expected trailing Heartbeat({expected_tail:?}), got {outputs:?}"
        );
        let delivered: Vec<u64> = prefix
            .iter()
            .flat_map(|output| match output {
                ReadSessionOutput::Batch(batch) => batch
                    .records
                    .iter()
                    .map(|r| r.position().seq_num)
                    .collect::<Vec<_>>(),
                other => panic!("unexpected non-batch output before trailing heartbeat: {other:?}"),
            })
            .collect();
        assert_eq!(delivered, (0..keep_prefix as u64).collect::<Vec<_>>());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn read_wait_is_not_extended_by_heartbeats() {
        let (backend, basin, stream) = setup_stream().await;

        let wait = Duration::from_millis(30);
        let start = ReadStart {
            from: ReadFrom::SeqNum(0),
            clamp: false,
        };
        let end = ReadEnd {
            limit: ReadLimit::Unbounded,
            until: ReadUntil::Unbounded,
            wait: Some(wait),
        };

        let session = backend
            .open_for_read(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .read(start, end)
            .await
            .unwrap();
        let mut session = Box::pin(session);
        let probe_step = Duration::from_millis(1);
        let first = session
            .as_mut()
            .next()
            .await
            .expect("session should enter follow mode")
            .expect("session should not error");
        assert!(matches!(first, ReadSessionOutput::Heartbeat(_)));

        let started = Instant::now();
        let second = match poll_next_after_advance(&mut session, wait).await {
            Poll::Ready(Some(output)) => output,
            Poll::Ready(None) => panic!("session closed before emitting a follow heartbeat"),
            Poll::Pending => panic!("expected a follow heartbeat before the wait budget expired"),
        };
        assert!(matches!(second, ReadSessionOutput::Heartbeat(_)));

        tokio::task::yield_now().await;
        let closed_at = loop {
            match futures::poll!(session.as_mut().next()) {
                Poll::Ready(Some(Ok(ReadSessionOutput::Heartbeat(_)))) => {}
                Poll::Ready(Some(Ok(output))) => {
                    panic!("unexpected output after wait deadline: {output:?}");
                }
                Poll::Ready(Some(Err(e))) => panic!("Read error: {e:?}"),
                Poll::Ready(None) => break Instant::now(),
                Poll::Pending => panic!("session should close once the wait budget expires"),
            }
        };

        assert!(closed_at >= started + wait);
        assert!(closed_at <= started + wait + probe_step);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn read_wait_is_reset_by_delivered_follow_batch() {
        let (backend, basin, stream) = setup_stream().await;

        let initial_input =
            append_input(Record::try_from_parts(vec![], bytes::Bytes::from("initial")).unwrap());
        backend
            .open_for_append(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .append(initial_input)
            .await
            .unwrap();

        let wait = Duration::from_millis(30);
        let probe_step = Duration::from_millis(1);
        let start = ReadStart {
            from: ReadFrom::SeqNum(0),
            clamp: false,
        };
        let end = ReadEnd {
            limit: ReadLimit::Unbounded,
            until: ReadUntil::Unbounded,
            wait: Some(wait),
        };

        let session = backend
            .open_for_read(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .read(start, end)
            .await
            .unwrap();
        let mut session = Box::pin(session);

        let first = session
            .as_mut()
            .next()
            .await
            .expect("session should yield the initial batch")
            .expect("session should not error");
        let ReadSessionOutput::Batch(batch) = first else {
            panic!("expected initial batch");
        };
        let initial_record = batch
            .records
            .first()
            .expect("batch should contain one record");
        let Record::Envelope(initial_envelope) = initial_record.inner() else {
            panic!("expected plaintext envelope record");
        };
        assert_eq!(initial_envelope.body().as_ref(), b"initial");

        let second = session
            .as_mut()
            .next()
            .await
            .expect("session should enter follow mode")
            .expect("session should not error");
        assert!(matches!(second, ReadSessionOutput::Heartbeat(_)));

        tokio::time::advance(Duration::from_millis(20)).await;
        tokio::task::yield_now().await;

        let follow_input =
            append_input(Record::try_from_parts(vec![], bytes::Bytes::from("follow-1")).unwrap());
        backend
            .open_for_append(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .append(follow_input)
            .await
            .unwrap();

        let follow = session
            .as_mut()
            .next()
            .await
            .expect("session should deliver the live batch")
            .expect("session should not error");
        let reset_at = Instant::now();
        let ReadSessionOutput::Batch(batch) = follow else {
            panic!("expected live batch after append");
        };
        let follow_record = batch
            .records
            .first()
            .expect("batch should contain one record");
        let Record::Envelope(follow_envelope) = follow_record.inner() else {
            panic!("expected plaintext envelope record");
        };
        assert_eq!(follow_envelope.body().as_ref(), b"follow-1");

        tokio::time::advance(wait - probe_step).await;
        tokio::task::yield_now().await;

        loop {
            match futures::poll!(session.as_mut().next()) {
                Poll::Ready(Some(Ok(ReadSessionOutput::Heartbeat(_)))) => {}
                Poll::Ready(Some(Ok(output))) => {
                    panic!("unexpected output before the reset wait deadline: {output:?}");
                }
                Poll::Ready(Some(Err(e))) => panic!("Read error: {e:?}"),
                Poll::Ready(None) => {
                    panic!("session closed before the reset wait budget expired");
                }
                Poll::Pending => break,
            }
        }

        tokio::time::advance(probe_step).await;
        tokio::task::yield_now().await;

        let closed_at = loop {
            match futures::poll!(session.as_mut().next()) {
                Poll::Ready(Some(Ok(ReadSessionOutput::Heartbeat(_)))) => {}
                Poll::Ready(Some(Ok(output))) => {
                    panic!("unexpected output after the reset wait deadline: {output:?}");
                }
                Poll::Ready(Some(Err(e))) => panic!("Read error: {e:?}"),
                Poll::Ready(None) => break Instant::now(),
                Poll::Pending => {
                    panic!("session should close once the reset wait budget expires");
                }
            }
        };

        assert!(closed_at >= reset_at + wait);
        assert!(closed_at <= reset_at + wait + probe_step);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn read_wait_is_not_reset_after_follow_lag_without_catchup_records() {
        let (backend, basin, stream) = setup_stream().await;

        let wait = Duration::from_secs(30);
        let start = ReadStart {
            from: ReadFrom::SeqNum(0),
            clamp: false,
        };
        let end = ReadEnd {
            limit: ReadLimit::Unbounded,
            until: ReadUntil::Unbounded,
            wait: Some(wait),
        };
        let session = backend
            .open_for_read(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .read(start, end)
            .await
            .unwrap();
        let mut session = Box::pin(session);

        let first = session
            .as_mut()
            .next()
            .await
            .expect("session should enter follow mode")
            .expect("session should not error");
        assert!(matches!(first, ReadSessionOutput::Heartbeat(_)));

        let stream_id = StreamId::new(&basin, &stream);
        let mut delete_batch = WriteBatch::new();
        let lagged_appends = FOLLOWER_MAX_LAG + 25;

        for i in 0..lagged_appends {
            let input = append_input(
                Record::try_from_parts(vec![], bytes::Bytes::from(format!("lagged-{i}"))).unwrap(),
            );
            let ack = backend
                .open_for_append(&basin, &stream, None, OptionalStreamConfig::default())
                .await
                .unwrap()
                .append(input)
                .await
                .unwrap();
            delete_batch.delete(kv::stream_record_data::ser_key(stream_id, ack.start));
        }

        backend.db.write(delete_batch).assert_durable().await;

        tokio::time::advance(wait + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let expired_at = Instant::now();
        let next = session
            .as_mut()
            .next()
            .await
            .expect("session should emit trailing tail heartbeat across deleted lag gap")
            .expect("session should not error");
        assert!(
            matches!(next, ReadSessionOutput::Heartbeat(tail) if tail.seq_num == lagged_appends as u64),
            "expected trailing heartbeat at seq_num={lagged_appends}, got {next:?}"
        );
        let closed = session.as_mut().next().await;
        assert!(
            closed.is_none(),
            "session should close immediately once the original wait budget has elapsed"
        );
        assert_eq!(
            Instant::now(),
            expired_at,
            "trailing heartbeat and close must not reset the wait budget"
        );
    }

    #[tokio::test]
    async fn read_start_seq_num_caps_timestamp_resolution_at_snapshot_tail() {
        let object_store = Arc::new(InMemory::new());
        let db = Db::builder("/test", object_store).build().await.unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));
        let stream_id: StreamId = [9u8; 32].into();

        // Simulate a concurrent append at seq_num=5 becoming durable after check_tail() observed
        // tail=(2, 1500) while earlier records < 2 were trimmed/deleted.
        let concurrent_pos = StreamPosition {
            seq_num: 5,
            timestamp: 2000,
        };
        backend
            .db
            .put(
                kv::stream_record_timestamp::ser_key(stream_id, concurrent_pos),
                kv::stream_record_timestamp::ser_value(),
            )
            .assert_durable()
            .await;

        let snapshot_tail = StreamPosition {
            seq_num: 2,
            timestamp: 1500,
        };
        let resolved = read_start_seq_num(
            &backend.db,
            stream_id,
            ReadStart {
                from: ReadFrom::Timestamp(1000),
                clamp: false,
            },
            snapshot_tail,
        )
        .await
        .expect("timestamp within snapshot tail must resolve without error");
        assert_eq!(resolved, snapshot_tail.seq_num);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn read_wait_elapsed_after_db_catchup_emits_tail_heartbeat() {
        let (backend, basin, stream) = setup_stream().await;

        let ack = backend
            .open_for_append(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .append(append_input(
                Record::try_from_parts(vec![], bytes::Bytes::from("initial")).unwrap(),
            ))
            .await
            .unwrap();

        let wait = Duration::from_millis(30);
        let session = backend
            .open_for_read(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .read(
                ReadStart {
                    from: ReadFrom::SeqNum(0),
                    clamp: false,
                },
                ReadEnd {
                    limit: ReadLimit::Unbounded,
                    until: ReadUntil::Unbounded,
                    wait: Some(wait),
                },
            )
            .await
            .unwrap();
        let mut session = Box::pin(session);

        // First pull delivers the non-tailing DB catch-up batch and arms the wait deadline.
        let first = session
            .as_mut()
            .next()
            .await
            .expect("session should yield DB catch-up batch")
            .expect("session should not error");
        assert!(matches!(first, ReadSessionOutput::Batch(ref b) if b.tail.is_none()));

        // Reader stays parked past `wait` before polling again.
        tokio::time::advance(wait + Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        let resumed_at = Instant::now();

        let second = session
            .as_mut()
            .next()
            .await
            .expect("parked reader whose wait elapsed must observe trailing tail heartbeat")
            .expect("session should not error");
        assert!(
            matches!(second, ReadSessionOutput::Heartbeat(tail) if tail == ack.end),
            "expected Heartbeat({:?}), got {second:?}",
            ack.end
        );

        let third = session.as_mut().next().await;
        assert!(
            third.is_none(),
            "session should end cleanly after heartbeat"
        );
        assert_eq!(Instant::now(), resumed_at);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn read_wait_elapsed_after_live_tailing_batch_emits_no_redundant_heartbeat() {
        let (backend, basin, stream) = setup_stream().await;

        // Shorter than test heartbeat sleep (5..15ms) so `wait` expires before any periodic
        // heartbeat fires.
        let wait = Duration::from_millis(2);
        let session = backend
            .open_for_read(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .read(
                ReadStart {
                    from: ReadFrom::SeqNum(0),
                    clamp: false,
                },
                ReadEnd {
                    limit: ReadLimit::Unbounded,
                    until: ReadUntil::Unbounded,
                    wait: Some(wait),
                },
            )
            .await
            .unwrap();
        let mut session = Box::pin(session);

        let first = session
            .as_mut()
            .next()
            .await
            .expect("session should enter follow mode")
            .expect("session should not error");
        assert!(matches!(first, ReadSessionOutput::Heartbeat(tail) if tail == StreamPosition::MIN));

        let ack = backend
            .open_for_append(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .append(append_input(
                Record::try_from_parts(vec![], bytes::Bytes::from("live")).unwrap(),
            ))
            .await
            .unwrap();

        let second = session
            .as_mut()
            .next()
            .await
            .expect("session should yield live batch")
            .expect("session should not error");
        assert!(
            matches!(second, ReadSessionOutput::Batch(ref b) if b.tail == Some(ack.end)),
            "live batch should already carry catching-up tail {:?}, got {second:?}",
            ack.end
        );

        let next = poll_next_after_advance(&mut session, wait + Duration::from_millis(1)).await;
        assert!(
            matches!(next, Poll::Ready(None)),
            "expected clean EOF without redundant trailing heartbeat, got {next:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn unbounded_follow_survives_streamer_dormancy() {
        let (backend, basin, stream) = setup_stream().await;

        let initial_input =
            append_input(Record::try_from_parts(vec![], bytes::Bytes::from("initial")).unwrap());
        backend
            .open_for_append(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .append(initial_input)
            .await
            .unwrap();

        let start = ReadStart {
            from: ReadFrom::SeqNum(0),
            clamp: false,
        };
        let end = ReadEnd {
            limit: ReadLimit::Unbounded,
            until: ReadUntil::Unbounded,
            wait: None,
        };
        let session = backend
            .open_for_read(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .read(start, end)
            .await
            .unwrap();
        let mut session = Box::pin(session);

        let first = session
            .as_mut()
            .next()
            .await
            .expect("session should yield initial batch")
            .expect("session should not error");
        assert!(matches!(first, ReadSessionOutput::Batch(_)));

        let second = session
            .as_mut()
            .next()
            .await
            .expect("session should enter follow mode")
            .expect("session should not error");
        assert!(matches!(second, ReadSessionOutput::Heartbeat(_)));

        tokio::time::advance(DORMANT_TIMEOUT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let follow_input =
            append_input(Record::try_from_parts(vec![], bytes::Bytes::from("follow-1")).unwrap());
        backend
            .open_for_append(&basin, &stream, None, OptionalStreamConfig::default())
            .await
            .unwrap()
            .append(follow_input)
            .await
            .unwrap();

        let next = session
            .as_mut()
            .next()
            .await
            .expect("session should stay open after dormancy")
            .expect("session should not error after dormancy");
        let ReadSessionOutput::Batch(batch) = next else {
            panic!("expected new batch after append");
        };
        assert_eq!(batch.records.len(), 1);
        let record = batch.records.first().expect("batch should have one record");
        let Record::Envelope(envelope) = record.inner() else {
            panic!("expected envelope record");
        };
        assert_eq!(envelope.body().as_ref(), b"follow-1");
    }

    fn append_input_at(record: Record, timestamp: Timestamp) -> AppendInput {
        let record: AppendRecord = AppendRecordParts {
            timestamp: Some(timestamp),
            record: Metered::from(record),
        }
        .try_into()
        .unwrap();
        let records: AppendRecordBatch = vec![record].try_into().unwrap();
        AppendInput {
            records,
            match_seq_num: None,
            fencing_token: None,
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn read_at_tail_with_denied_until_stops_immediately_without_heartbeat_or_wait() {
        let seq = |n| ReadStart {
            from: ReadFrom::SeqNum(n),
            clamp: false,
        };
        let clamped = |n| ReadStart {
            from: ReadFrom::SeqNum(n),
            clamp: true,
        };
        let tail_offset = |n| ReadStart {
            from: ReadFrom::TailOffset(n),
            clamp: false,
        };
        let until_end = |ts, wait| ReadEnd {
            limit: ReadLimit::Unbounded,
            until: ReadUntil::Timestamp(ts),
            wait,
        };
        async fn read_outputs(
            backend: &Backend,
            basin: &BasinName,
            stream: &StreamName,
            start: ReadStart,
            end: ReadEnd,
        ) -> Result<Vec<ReadSessionOutput>, ReadError> {
            let session = backend
                .open_for_read(basin, stream, None, OptionalStreamConfig::default())
                .await?
                .read(start, end)
                .await?;
            session.collect::<Vec<_>>().await.into_iter().collect()
        }

        let (backend, basin, stream) = setup_stream().await;
        let wait_30s = Some(Duration::from_secs(30));

        // 1. Empty stream (tail = (0, 0)): until = 0 stops immediately without heartbeat or wait.
        for (start, wait) in [
            (seq(0), None),
            (tail_offset(0), wait_30s),
            (clamped(5), wait_30s),
        ] {
            let started = Instant::now();
            let outputs = read_outputs(&backend, &basin, &stream, start, until_end(0, wait))
                .await
                .unwrap();
            assert!(outputs.is_empty(), "expected clean EOF, got {outputs:?}");
            assert_eq!(Instant::now(), started, "must not sleep on wait");
        }

        // Empty stream with future-reachable until = 1 still emits tail heartbeat.
        let outputs = read_outputs(&backend, &basin, &stream, seq(0), until_end(1, None))
            .await
            .unwrap();
        assert!(matches!(
            outputs.as_slice(),
            [ReadSessionOutput::Heartbeat(tail)] if *tail == StreamPosition::MIN
        ));

        // Empty stream strictly beyond tail without clamp still returns UnwrittenError first.
        let err = read_outputs(&backend, &basin, &stream, seq(5), until_end(0, None))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ReadError::Unwritten(UnwrittenError(tail)) if tail == StreamPosition::MIN)
        );

        // 2. Active non-empty stream (tail = (2, 2000)).
        for (body, ts) in [(&b"a"[..], 1000u64), (&b"b"[..], 2000u64)] {
            backend
                .open_for_append(&basin, &stream, None, OptionalStreamConfig::default())
                .await
                .unwrap()
                .append(append_input_at(
                    Record::try_from_parts(vec![], bytes::Bytes::from_static(body)).unwrap(),
                    ts,
                ))
                .await
                .unwrap();
        }
        let expected_tail = StreamPosition {
            seq_num: 2,
            timestamp: 2000,
        };

        for (start, until, wait) in [
            (seq(2), 2000, None),
            (seq(2), 1500, wait_30s),
            (tail_offset(0), 2000, wait_30s),
            (clamped(10), 2000, wait_30s),
        ] {
            let started = Instant::now();
            let outputs = read_outputs(&backend, &basin, &stream, start, until_end(until, wait))
                .await
                .unwrap();
            assert!(
                outputs.is_empty(),
                "expected clean EOF for until={until}, got {outputs:?}"
            );
            assert_eq!(Instant::now(), started, "must not sleep on wait");
        }

        // Future-reachable until = 2001 still emits tail heartbeat at tail.
        let outputs = read_outputs(&backend, &basin, &stream, seq(2), until_end(2001, None))
            .await
            .unwrap();
        assert!(matches!(
            outputs.as_slice(),
            [ReadSessionOutput::Heartbeat(tail)] if *tail == expected_tail
        ));

        // Unclamped beyond-tail still returns UnwrittenError even when until <= tail.timestamp.
        let err = read_outputs(&backend, &basin, &stream, seq(10), until_end(1500, None))
            .await
            .unwrap_err();
        assert!(matches!(err, ReadError::Unwritten(UnwrittenError(tail)) if tail == expected_tail));

        // 3. Deleted trailing record whose timestamp was >= until: surviving earlier record is
        //    yielded, then at-tail until check stops immediately without heartbeat or wait.
        let stream_id = StreamId::new(&basin, &stream);
        let mut del = WriteBatch::new();
        del.delete(kv::stream_record_data::ser_key(
            stream_id,
            StreamPosition {
                seq_num: 1,
                timestamp: 2000,
            },
        ));
        backend.db.write(del).assert_durable().await;

        let started = Instant::now();
        let outputs = read_outputs(&backend, &basin, &stream, seq(0), until_end(1500, wait_30s))
            .await
            .unwrap();
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ReadSessionOutput::Batch(batch) if batch.records.len() == 1
                && batch.records[0].position().seq_num == 0
                && batch.tail.is_none()
        ));
        assert_eq!(Instant::now(), started, "must not sleep on wait");
    }
}
