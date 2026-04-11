use std::time::Duration;

use futures::Stream;
use s2_common::{
    caps,
    read_extent::{EvaluatedReadLimit, ReadLimit, ReadUntil},
    record::{Metered, MeteredSize as _, SeqNum, StoredSequencedRecord, StreamPosition, Timestamp},
    types::{
        basin::BasinName,
        stream::{
            ReadEnd, ReadPosition, ReadStart, StoredReadBatch, StoredReadSessionOutput, StreamName,
        },
    },
};
use slatedb::config::{DurabilityLevel, ScanOptions};
use tokio::{sync::broadcast, time::Instant};

use super::Backend;
use crate::{
    backend::{
        error::{
            CheckTailError, ReadError, StorageError, StreamerMissingInActionError, UnwrittenError,
        },
        kv,
    },
    stream_id::StreamId,
};

impl Backend {
    async fn read_start_seq_num(
        &self,
        stream_id: StreamId,
        start: ReadStart,
        end: ReadEnd,
        tail: StreamPosition,
    ) -> Result<SeqNum, ReadError> {
        let mut read_pos = match start.from {
            s2_common::types::stream::ReadFrom::SeqNum(seq_num) => ReadPosition::SeqNum(seq_num),
            s2_common::types::stream::ReadFrom::Timestamp(timestamp) => {
                ReadPosition::Timestamp(timestamp)
            }
            s2_common::types::stream::ReadFrom::TailOffset(tail_offset) => {
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
        if let ReadPosition::SeqNum(start_seq_num) = read_pos
            && start_seq_num == tail.seq_num
            && !end.may_follow()
        {
            return Err(UnwrittenError(tail).into());
        }
        Ok(match read_pos {
            ReadPosition::SeqNum(start_seq_num) => start_seq_num,
            ReadPosition::Timestamp(start_timestamp) => {
                self.resolve_timestamp(stream_id, start_timestamp)
                    .await?
                    .unwrap_or(tail)
                    .seq_num
            }
        })
    }

    pub async fn check_tail(
        &self,
        basin: BasinName,
        stream: StreamName,
    ) -> Result<StreamPosition, CheckTailError> {
        let client = self
            .streamer_client_with_auto_create::<CheckTailError>(&basin, &stream, |config| {
                config.create_stream_on_read
            })
            .await?;
        let tail = client.check_tail().await?;
        Ok(tail)
    }

    pub async fn read(
        &self,
        basin: BasinName,
        stream: StreamName,
        start: ReadStart,
        end: ReadEnd,
    ) -> Result<impl Stream<Item = Result<StoredReadSessionOutput, ReadError>> + 'static, ReadError>
    {
        let client = self
            .streamer_client_with_auto_create::<ReadError>(&basin, &stream, |config| {
                config.create_stream_on_read
            })
            .await?;
        let stream_id = client.stream_id();
        let tail = client.check_tail().await?;
        let mut state = ReadSessionState {
            start_seq_num: self.read_start_seq_num(stream_id, start, end, tail).await?,
            limit: EvaluatedReadLimit::Remaining(end.limit),
            until: end.until,
            wait: end.wait,
            wait_deadline: None,
            tail,
        };
        let db = self.db.clone();
        let session = async_stream::try_stream! {
            'session: while let EvaluatedReadLimit::Remaining(limit) = state.limit {
                if state.start_seq_num < state.tail.seq_num {
                    let start_key = kv::stream_record_data::ser_key(
                        stream_id,
                        StreamPosition {
                            seq_num: state.start_seq_num,
                            timestamp: 0,
                        },
                    );
                    let end_key = kv::stream_record_data::ser_key(
                        stream_id,
                        StreamPosition {
                            seq_num: state.tail.seq_num,
                            timestamp: 0,
                        },
                    );
                    static SCAN_OPTS: ScanOptions = ScanOptions {
                        durability_filter: DurabilityLevel::Remote,
                        dirty: false,
                        read_ahead_bytes: 1024 * 1024,
                        cache_blocks: true,
                        max_fetch_tasks: 8,
                    };
                    let mut it = db
                        .scan_with_options(start_key..end_key, &SCAN_OPTS)
                        .await?;

                    let mut records = Metered::with_capacity(
                        limit.count()
                            .unwrap_or(usize::MAX)
                            .min(caps::RECORD_BATCH_MAX.count),
                    );

                    while let EvaluatedReadLimit::Remaining(limit) = state.limit {
                        let Some(kv) = it.next().await? else {
                            break;
                        };
                        let (deser_stream_id, pos) = kv::stream_record_data::deser_key(kv.key)?;
                        assert_eq!(deser_stream_id, stream_id);

                        let record = kv::stream_record_data::deser_value(kv.value)?.sequenced(pos);

                        if end.until.deny(pos.timestamp)
                            || limit.deny(records.len() + 1, records.metered_size() + record.metered_size()) {
                            if records.is_empty() {
                                break 'session;
                            } else {
                                break;
                            }
                        }

                        if records.len() == caps::RECORD_BATCH_MAX.count
                            || records.metered_size() + record.metered_size() > caps::RECORD_BATCH_MAX.bytes
                        {
                            let new_records_buf = Metered::with_capacity(
                                limit.count()
                                    .map_or(usize::MAX, |n| n.saturating_sub(records.len()))
                                    .min(caps::RECORD_BATCH_MAX.count),
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
                    } else {
                        state.start_seq_num = state.tail.seq_num;
                    }
                } else {
                    assert_eq!(state.start_seq_num, state.tail.seq_num);
                    if !end.may_follow() {
                        break;
                    }
                    match client.follow(state.start_seq_num).await? {
                        Ok(mut follow_rx) => {
                            // Only a delivered batch should reset the absolute wait budget.
                            state.arm_wait_deadline_if_unset();
                            if state.wait_deadline_expired() {
                                break;
                            }
                            yield StoredReadSessionOutput::Heartbeat(state.tail);
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
                        Err(tail) => {
                            assert!(state.tail.seq_num < tail.seq_num, "tail cannot regress");
                            state.tail = tail;
                        }
                    }
                }
            }
        };
        Ok(session)
    }

    pub(super) async fn resolve_timestamp(
        &self,
        stream_id: StreamId,
        timestamp: Timestamp,
    ) -> Result<Option<StreamPosition>, StorageError> {
        let start_key = kv::stream_record_timestamp::ser_key(
            stream_id,
            StreamPosition {
                seq_num: SeqNum::MIN,
                timestamp,
            },
        );
        let end_key = kv::stream_record_timestamp::ser_key(
            stream_id,
            StreamPosition {
                seq_num: SeqNum::MAX,
                timestamp: Timestamp::MAX,
            },
        );
        static SCAN_OPTS: ScanOptions = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            dirty: false,
            read_ahead_bytes: 1,
            cache_blocks: false,
            max_fetch_tasks: 1,
        };
        let mut it = self
            .db
            .scan_with_options(start_key..end_key, &SCAN_OPTS)
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
        let count = batch.records.len();
        let bytes = batch.records.metered_size();
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
    let mut acc_size = 0;
    let mut acc_count = 0;
    for record in records {
        if limit.deny(acc_count + 1, acc_size + record.metered_size())
            || until.deny(record.position().timestamp)
        {
            break;
        }
        acc_count += 1;
        acc_size += record.metered_size();
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
    use s2_common::{
        read_extent::{ReadLimit, ReadUntil},
        record::{Metered, Record, StoredRecord},
        types::{
            basin::BasinName,
            config::{BasinConfig, OptionalStreamConfig},
            resources::CreateMode,
            stream::{
                ReadEnd, ReadFrom, ReadStart, StoredAppendInput, StoredAppendRecord,
                StoredAppendRecordBatch, StoredAppendRecordParts, StoredReadSessionOutput,
            },
        },
    };
    use slatedb::{Db, WriteBatch, config::WriteOptions, object_store::memory::InMemory};
    use tokio::time::Instant;

    use super::*;
    use crate::{
        backend::{FOLLOWER_MAX_LAG, kv, streamer::DORMANT_TIMEOUT},
        stream_id::StreamId,
    };

    fn stored_append_input(record: Record) -> StoredAppendInput {
        let record: StoredAppendRecord = StoredAppendRecordParts {
            timestamp: None,
            record: Metered::from(StoredRecord::from(record)),
        }
        .try_into()
        .unwrap();
        let records: StoredAppendRecordBatch = vec![record].try_into().unwrap();
        StoredAppendInput {
            records,
            match_seq_num: None,
            fencing_token: None,
        }
    }

    fn map_test_output(
        output: Option<Result<StoredReadSessionOutput, ReadError>>,
    ) -> Option<StoredReadSessionOutput> {
        match output {
            Some(Ok(output)) => Some(output),
            Some(Err(e)) => panic!("Read error: {e:?}"),
            None => None,
        }
    }

    async fn poll_next_after_advance<S>(
        session: &mut std::pin::Pin<Box<S>>,
        advance_by: Duration,
    ) -> Poll<Option<StoredReadSessionOutput>>
    where
        S: futures::Stream<Item = Result<StoredReadSessionOutput, ReadError>>,
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
            .await
            .unwrap();
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
            .await
            .unwrap();

        // Should find record in stream_a
        let result = backend.resolve_timestamp(stream_a, 500).await.unwrap();
        assert_eq!(
            result,
            Some(StreamPosition {
                seq_num: 0,
                timestamp: 1000
            })
        );

        // Should return None, not find stream_b's record
        let result = backend.resolve_timestamp(stream_a, 1500).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn read_completes_when_all_records_deleted() {
        let object_store = Arc::new(InMemory::new());
        let db = Db::builder("/test", object_store).build().await.unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));

        let basin: BasinName = "test-basin".parse().unwrap();
        backend
            .create_basin(
                basin.clone(),
                BasinConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();
        let stream: s2_common::types::stream::StreamName = "test-stream".parse().unwrap();
        backend
            .create_stream(
                basin.clone(),
                stream.clone(),
                OptionalStreamConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();

        let input =
            stored_append_input(Record::try_from_parts(vec![], bytes::Bytes::from("x")).unwrap());
        let ack = backend
            .append(basin.clone(), stream.clone(), input)
            .await
            .unwrap();
        assert!(ack.end.seq_num > 0);

        let stream_id = StreamId::new(&basin, &stream);
        let mut batch = WriteBatch::new();
        batch.delete(kv::stream_record_data::ser_key(stream_id, ack.start));
        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        backend
            .db
            .write_with_options(batch, &WRITE_OPTS)
            .await
            .unwrap();

        let start = ReadStart {
            from: ReadFrom::SeqNum(0),
            clamp: false,
        };
        let end = ReadEnd {
            limit: ReadLimit::Count(10),
            until: ReadUntil::Unbounded,
            wait: None,
        };
        let session = backend.read(basin, stream, start, end).await.unwrap();
        let records: Vec<_> = tokio::time::timeout(
            Duration::from_secs(2),
            futures::StreamExt::collect::<Vec<_>>(session),
        )
        .await
        .expect("read should not spin forever");
        assert!(records.into_iter().all(|r| r.is_ok()));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn read_wait_is_not_extended_by_heartbeats() {
        let object_store = Arc::new(InMemory::new());
        let db = Db::builder("/test", object_store).build().await.unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));

        let basin: BasinName = "test-basin".parse().unwrap();
        backend
            .create_basin(
                basin.clone(),
                BasinConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();
        let stream: s2_common::types::stream::StreamName = "test-stream".parse().unwrap();
        backend
            .create_stream(
                basin.clone(),
                stream.clone(),
                OptionalStreamConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();

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

        let session = backend.read(basin, stream, start, end).await.unwrap();
        let mut session = Box::pin(session);
        let probe_step = Duration::from_millis(1);
        let first = session
            .as_mut()
            .next()
            .await
            .expect("session should enter follow mode")
            .expect("session should not error");
        assert!(matches!(first, StoredReadSessionOutput::Heartbeat(_)));

        let started = Instant::now();
        let second = match poll_next_after_advance(&mut session, wait).await {
            Poll::Ready(Some(output)) => output,
            Poll::Ready(None) => panic!("session closed before emitting a follow heartbeat"),
            Poll::Pending => panic!("expected a follow heartbeat before the wait budget expired"),
        };
        assert!(matches!(second, StoredReadSessionOutput::Heartbeat(_)));

        tokio::task::yield_now().await;
        let closed_at = loop {
            match futures::poll!(session.as_mut().next()) {
                Poll::Ready(Some(Ok(StoredReadSessionOutput::Heartbeat(_)))) => {}
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
        let object_store = Arc::new(InMemory::new());
        let db = Db::builder("/test", object_store).build().await.unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));

        let basin: BasinName = "test-basin".parse().unwrap();
        backend
            .create_basin(
                basin.clone(),
                BasinConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();
        let stream: s2_common::types::stream::StreamName = "test-stream".parse().unwrap();
        backend
            .create_stream(
                basin.clone(),
                stream.clone(),
                OptionalStreamConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();

        let initial_input = stored_append_input(
            Record::try_from_parts(vec![], bytes::Bytes::from("initial")).unwrap(),
        );
        backend
            .append(basin.clone(), stream.clone(), initial_input)
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
            .read(basin.clone(), stream.clone(), start, end)
            .await
            .unwrap();
        let mut session = Box::pin(session);

        let first = session
            .as_mut()
            .next()
            .await
            .expect("session should yield the initial batch")
            .expect("session should not error");
        let StoredReadSessionOutput::Batch(batch) = first else {
            panic!("expected initial batch");
        };
        let initial_record = batch
            .records
            .first()
            .expect("batch should contain one record");
        let StoredRecord::Plaintext(Record::Envelope(initial_envelope)) = initial_record.inner()
        else {
            panic!("expected plaintext envelope record");
        };
        assert_eq!(initial_envelope.body().as_ref(), b"initial");

        let second = session
            .as_mut()
            .next()
            .await
            .expect("session should enter follow mode")
            .expect("session should not error");
        assert!(matches!(second, StoredReadSessionOutput::Heartbeat(_)));

        tokio::time::advance(Duration::from_millis(20)).await;
        tokio::task::yield_now().await;

        let follow_input = stored_append_input(
            Record::try_from_parts(vec![], bytes::Bytes::from("follow-1")).unwrap(),
        );
        backend.append(basin, stream, follow_input).await.unwrap();

        let follow = session
            .as_mut()
            .next()
            .await
            .expect("session should deliver the live batch")
            .expect("session should not error");
        let reset_at = Instant::now();
        let StoredReadSessionOutput::Batch(batch) = follow else {
            panic!("expected live batch after append");
        };
        let follow_record = batch
            .records
            .first()
            .expect("batch should contain one record");
        let StoredRecord::Plaintext(Record::Envelope(follow_envelope)) = follow_record.inner()
        else {
            panic!("expected plaintext envelope record");
        };
        assert_eq!(follow_envelope.body().as_ref(), b"follow-1");

        tokio::time::advance(wait - probe_step).await;
        tokio::task::yield_now().await;

        loop {
            match futures::poll!(session.as_mut().next()) {
                Poll::Ready(Some(Ok(StoredReadSessionOutput::Heartbeat(_)))) => {}
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
                Poll::Ready(Some(Ok(StoredReadSessionOutput::Heartbeat(_)))) => {}
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
        let object_store = Arc::new(InMemory::new());
        let db = Db::builder("/test", object_store).build().await.unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));

        let basin: BasinName = "test-basin".parse().unwrap();
        backend
            .create_basin(
                basin.clone(),
                BasinConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();
        let stream: s2_common::types::stream::StreamName = "test-stream".parse().unwrap();
        backend
            .create_stream(
                basin.clone(),
                stream.clone(),
                OptionalStreamConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();

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
            .read(basin.clone(), stream.clone(), start, end)
            .await
            .unwrap();
        let mut session = Box::pin(session);

        let first = session
            .as_mut()
            .next()
            .await
            .expect("session should enter follow mode")
            .expect("session should not error");
        assert!(matches!(first, StoredReadSessionOutput::Heartbeat(_)));

        let stream_id = StreamId::new(&basin, &stream);
        let mut delete_batch = WriteBatch::new();
        let lagged_appends = FOLLOWER_MAX_LAG + 25;

        for i in 0..lagged_appends {
            let input = stored_append_input(
                Record::try_from_parts(vec![], bytes::Bytes::from(format!("lagged-{i}"))).unwrap(),
            );
            let ack = backend
                .append(basin.clone(), stream.clone(), input)
                .await
                .unwrap();
            delete_batch.delete(kv::stream_record_data::ser_key(stream_id, ack.start));
        }

        static WRITE_OPTS: WriteOptions = WriteOptions {
            await_durable: true,
        };
        backend
            .db
            .write_with_options(delete_batch, &WRITE_OPTS)
            .await
            .unwrap();

        tokio::time::advance(wait + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let next = session.as_mut().next().await;
        assert!(
            next.is_none(),
            "session should close immediately once the original wait budget has elapsed"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn unbounded_follow_survives_streamer_dormancy() {
        let object_store = Arc::new(InMemory::new());
        let db = Db::builder("/test", object_store).build().await.unwrap();
        let backend = Backend::new(db, ByteSize::mib(10));

        let basin: BasinName = "test-basin".parse().unwrap();
        backend
            .create_basin(
                basin.clone(),
                BasinConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();
        let stream: s2_common::types::stream::StreamName = "test-stream".parse().unwrap();
        backend
            .create_stream(
                basin.clone(),
                stream.clone(),
                OptionalStreamConfig::default(),
                CreateMode::CreateOnly(None),
            )
            .await
            .unwrap();

        let initial_input = stored_append_input(
            Record::try_from_parts(vec![], bytes::Bytes::from("initial")).unwrap(),
        );
        backend
            .append(basin.clone(), stream.clone(), initial_input)
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
            .read(basin.clone(), stream.clone(), start, end)
            .await
            .unwrap();
        let mut session = Box::pin(session);

        let first = session
            .as_mut()
            .next()
            .await
            .expect("session should yield initial batch")
            .expect("session should not error");
        assert!(matches!(first, StoredReadSessionOutput::Batch(_)));

        let second = session
            .as_mut()
            .next()
            .await
            .expect("session should enter follow mode")
            .expect("session should not error");
        assert!(matches!(second, StoredReadSessionOutput::Heartbeat(_)));

        tokio::time::advance(DORMANT_TIMEOUT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let follow_input = stored_append_input(
            Record::try_from_parts(vec![], bytes::Bytes::from("follow-1")).unwrap(),
        );
        backend.append(basin, stream, follow_input).await.unwrap();

        let next = session
            .as_mut()
            .next()
            .await
            .expect("session should stay open after dormancy")
            .expect("session should not error after dormancy");
        let StoredReadSessionOutput::Batch(batch) = next else {
            panic!("expected new batch after append");
        };
        assert_eq!(batch.records.len(), 1);
        let record = batch.records.first().expect("batch should have one record");
        let StoredRecord::Plaintext(Record::Envelope(envelope)) = record.inner() else {
            panic!("expected envelope record");
        };
        assert_eq!(envelope.body().as_ref(), b"follow-1");
    }
}
