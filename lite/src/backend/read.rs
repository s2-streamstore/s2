use std::time::Duration;

use futures::Stream;
use s2_common::{
    caps,
    read_extent::{EvaluatedReadLimit, ReadLimit, ReadUntil},
    record::{Metered, MeteredSize as _, SeqNum, SequencedRecord, StreamPosition, Timestamp},
    types::{
        basin::BasinName,
        stream::{ReadBatch, ReadEnd, ReadPosition, ReadSessionOutput, ReadStart, StreamName},
    },
};
use slatedb::config::{DurabilityLevel, ScanOptions};
use tokio::sync::broadcast;

use super::Backend;
use crate::backend::{
    error::{
        CheckTailError, ReadError, StorageError, StreamerMissingInActionError, UnwrittenError,
    },
    kv,
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
    ) -> Result<impl Stream<Item = Result<ReadSessionOutput, ReadError>> + 'static, ReadError> {
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
                            yield state.on_batch(ReadBatch {
                                records: std::mem::replace(&mut records, new_records_buf),
                                tail: None,
                            });
                        }

                        records.push(record);
                    }

                    if !records.is_empty() {
                        yield state.on_batch(ReadBatch {
                            records,
                            tail: None,
                        });
                    }
                } else {
                    assert_eq!(state.start_seq_num, state.tail.seq_num);
                    if !end.may_follow() {
                        break;
                    }
                    match client.follow(state.start_seq_num).await? {
                        Ok(mut follow_rx) => {
                            yield ReadSessionOutput::Heartbeat(state.tail);
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
                                                    yield state.on_batch(ReadBatch {
                                                        records: records.drain(..allowed_count).collect(),
                                                        tail: Some(tail),
                                                    });
                                                }
                                                if allowed_count < count {
                                                    break 'session;
                                                }
                                            }
                                            Err(broadcast::error::RecvError::Lagged(_)) => {
                                                // Catch up using DB
                                                continue 'session;
                                            }
                                            Err(broadcast::error::RecvError::Closed) => {
                                                break;
                                            }
                                        }
                                    }
                                    _ = new_heartbeat_sleep() => {
                                        yield ReadSessionOutput::Heartbeat(state.tail);
                                    }
                                    _ = wait_sleep(end.wait) => {
                                        break 'session;
                                    }
                                }
                            }
                            Err(StreamerMissingInActionError)?;
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
    tail: StreamPosition,
}

impl ReadSessionState {
    fn on_batch(&mut self, batch: ReadBatch) -> ReadSessionOutput {
        if let Some(tail) = batch.tail {
            self.tail = tail;
        }
        let last_record = batch.records.last().expect("non-empty");
        let EvaluatedReadLimit::Remaining(limit) = self.limit else {
            panic!("batch after exhausted limit");
        };
        let count = batch.records.len();
        let bytes = batch.records.metered_size();
        assert!(limit.allow(count, bytes));
        assert!(self.until.allow(last_record.position.timestamp));
        self.start_seq_num = last_record.position.seq_num + 1;
        self.limit = limit.remaining(count, bytes);
        ReadSessionOutput::Batch(batch)
    }
}

fn count_allowed_records(
    limit: ReadLimit,
    until: ReadUntil,
    records: &[Metered<SequencedRecord>],
) -> usize {
    let mut acc_size = 0;
    let mut acc_count = 0;
    for record in records {
        if limit.deny(acc_count + 1, acc_size + record.metered_size())
            || until.deny(record.position.timestamp)
        {
            break;
        }
        acc_count += 1;
        acc_size += record.metered_size();
    }
    acc_count
}

fn new_heartbeat_sleep() -> tokio::time::Sleep {
    tokio::time::sleep(Duration::from_millis(rand::random_range(5_000..15_000)))
}

async fn wait_sleep(wait: Option<Duration>) {
    match wait {
        Some(wait) => tokio::time::sleep(wait).await,
        None => {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytesize::ByteSize;
    use slatedb::{Db, object_store::memory::InMemory};

    use super::*;

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
}
