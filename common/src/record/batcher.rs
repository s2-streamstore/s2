use std::iter::FusedIterator;

use bytes::Bytes;

use super::InternalRecordError;
use crate::{
    caps,
    read_extent::{EvaluatedReadLimit, ReadLimit, ReadUntil},
    record::{MeteredRecord, MeteredSequencedRecords, MeteredSize, SeqNum, Timestamp},
};

#[derive(Debug)]
pub struct RecordBatch {
    pub records: MeteredSequencedRecords,
    pub is_terminal: bool,
}

pub struct RecordBatcher<I, E>
where
    I: Iterator<Item = Result<(SeqNum, Timestamp, Bytes), E>>,
    E: Into<InternalRecordError>,
{
    record_iterator: I,
    buffered_records: MeteredSequencedRecords,
    buffered_error: Option<InternalRecordError>,
    read_limit: EvaluatedReadLimit,
    until: ReadUntil,
    is_terminated: bool,
}

fn make_records(read_limit: &EvaluatedReadLimit) -> MeteredSequencedRecords {
    match read_limit {
        EvaluatedReadLimit::Remaining(limit) => MeteredSequencedRecords::with_capacity(
            limit.count().map_or(caps::RECORD_BATCH_MAX.count, |n| {
                n.min(caps::RECORD_BATCH_MAX.count)
            }),
        ),
        EvaluatedReadLimit::Exhausted => MeteredSequencedRecords::default(),
    }
}

impl<I, E> RecordBatcher<I, E>
where
    I: Iterator<Item = Result<(SeqNum, Timestamp, Bytes), E>>,
    E: std::fmt::Debug + Into<InternalRecordError>,
{
    pub fn new(record_iterator: I, read_limit: ReadLimit, until: ReadUntil) -> Self {
        let read_limit = read_limit.remaining(0, 0);
        Self {
            record_iterator,
            buffered_records: make_records(&read_limit),
            buffered_error: None,
            read_limit,
            until,
            is_terminated: false,
        }
    }

    fn iter_next(&mut self) -> Option<Result<RecordBatch, InternalRecordError>> {
        let EvaluatedReadLimit::Remaining(remaining_limit) = self.read_limit else {
            return None;
        };

        let mut stashed_record = None;
        while self.buffered_error.is_none() {
            match self.record_iterator.next() {
                Some(Ok((seq_num, timestamp, data))) => {
                    let record = match MeteredRecord::try_from(data) {
                        Ok(record) => record.sequenced(seq_num, timestamp),
                        Err(err) => {
                            self.buffered_error = Some(err);
                            break;
                        }
                    };

                    if remaining_limit.deny(
                        self.buffered_records.len() + 1,
                        self.buffered_records.metered_size() + record.metered_size(),
                    ) || self.until.deny(timestamp)
                    {
                        self.read_limit = EvaluatedReadLimit::Exhausted;
                        break;
                    }

                    if self.buffered_records.len() == caps::RECORD_BATCH_MAX.count
                        || self.buffered_records.metered_size() + record.metered_size()
                            > caps::RECORD_BATCH_MAX.bytes
                    {
                        // It would would violate the per-batch limits.
                        stashed_record = Some(record);
                        break;
                    }

                    self.buffered_records.push(record);
                }
                Some(Err(err)) => {
                    self.buffered_error = Some(err.into());
                    break;
                }
                None => {
                    break;
                }
            }
        }
        if !self.buffered_records.is_empty() {
            self.read_limit = match self.read_limit {
                EvaluatedReadLimit::Remaining(read_limit) => read_limit.remaining(
                    self.buffered_records.len(),
                    self.buffered_records.metered_size(),
                ),
                EvaluatedReadLimit::Exhausted => EvaluatedReadLimit::Exhausted,
            };
            let is_terminal = self.read_limit == EvaluatedReadLimit::Exhausted;
            let records = std::mem::replace(
                &mut self.buffered_records,
                if is_terminal || self.buffered_error.is_some() {
                    MeteredSequencedRecords::default()
                } else {
                    let mut buf = make_records(&self.read_limit);
                    if let Some(record) = stashed_record.take() {
                        buf.push(record);
                    }
                    buf
                },
            );
            return Some(Ok(RecordBatch {
                records,
                is_terminal,
            }));
        }
        if let Some(err) = self.buffered_error.take() {
            return Some(Err(err));
        }
        None
    }
}

impl<I, E> Iterator for RecordBatcher<I, E>
where
    I: Iterator<Item = Result<(SeqNum, Timestamp, Bytes), E>>,
    E: std::fmt::Debug + Into<InternalRecordError>,
{
    type Item = Result<RecordBatch, InternalRecordError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_terminated {
            return None;
        }
        let item = self.iter_next();
        self.is_terminated = matches!(&item, None | Some(Err(_)));
        item
    }
}

impl<I, E> FusedIterator for RecordBatcher<I, E>
where
    I: Iterator<Item = Result<(SeqNum, Timestamp, Bytes), E>>,
    E: std::fmt::Debug + Into<InternalRecordError>,
{
}

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use rstest::rstest;

    use super::*;
    use crate::{
        caps,
        read_extent::{CountOrBytes, ReadLimit, ReadUntil},
        record::{Encodable, EnvelopeRecord, Header, InternalRecordError, MeteredSize, Record},
    };

    fn create_test_record(size: usize) -> Bytes {
        let body = Bytes::from(vec![b'x'; size]);
        let record = Record::Envelope(
            EnvelopeRecord::try_from_parts(
                vec![Header {
                    name: Bytes::from("test"),
                    value: Bytes::from("value"),
                }],
                body,
            )
            .unwrap(),
        );
        MeteredRecord::from(record).to_bytes()
    }

    fn uniform_records(
        count: usize,
        record_body_size: usize,
        starting_seq_num: SeqNum,
        timestamp_step: u64,
    ) -> impl Iterator<Item = Result<(SeqNum, Timestamp, Bytes), InternalRecordError>> {
        (0..count).map(move |i| {
            let seq_num = starting_seq_num + i as u64;
            let timestamp = seq_num * timestamp_step;
            let data = create_test_record(record_body_size);
            Ok((seq_num, timestamp, data))
        })
    }

    #[rstest]
    #[case(ReadLimit::Bytes(300_000), ReadUntil::Unbounded, 29, 290551, true)]
    #[case(ReadLimit::Count(50), ReadUntil::Unbounded, 50, 500950, true)]
    #[case(ReadLimit::CountOrBytes(CountOrBytes{ count: 50, bytes: 300_000}), ReadUntil::Unbounded, 29, 290551, true)]
    #[case(ReadLimit::Unbounded, ReadUntil::Unbounded, 1000, 10019000, false)]
    #[case(ReadLimit::Unbounded, ReadUntil::Timestamp(Timestamp::MAX), 1000, 10019000, false)]
    #[case(ReadLimit::Unbounded, ReadUntil::Timestamp(200000), 100, 1001900, true)]
    #[case(ReadLimit::Bytes(10019), ReadUntil::Unbounded, 1, 10019, true)]
    #[case(ReadLimit::Bytes(10019), ReadUntil::Timestamp(10000), 0, 0, false)]
    #[case(ReadLimit::Bytes(9999), ReadUntil::Unbounded, 0, 0, false)]
    #[case(ReadLimit::Bytes(0), ReadUntil::Unbounded, 0, 0, false)]
    #[case(ReadLimit::Bytes(10000), ReadUntil::Unbounded, 0, 0, false)]
    fn record_batcher(
        #[case] read_limit: ReadLimit,
        #[case] until: ReadUntil,
        #[case] expected_records: usize,
        #[case] expected_metered_bytes: usize,
        #[case] expected_is_terminal: bool,
    ) {
        let (acc_bytes, acc_count, is_terminal) =
            RecordBatcher::new(uniform_records(1000, 10_000, 100, 1000), read_limit, until).fold(
                (0usize, 0usize, false),
                |(acc_bytes, acc_count, is_terminal), batch| {
                    let batch = batch.expect("batch");
                    assert!(batch.records.len() <= caps::RECORD_BATCH_MAX.count);
                    assert!(batch.records.metered_size() <= caps::RECORD_BATCH_MAX.bytes);
                    (
                        acc_bytes + batch.records.metered_size(),
                        acc_count + batch.records.len(),
                        is_terminal || batch.is_terminal,
                    )
                },
            );

        assert_eq!(acc_bytes, expected_metered_bytes);
        assert_eq!(acc_count, expected_records);
        assert_eq!(is_terminal, expected_is_terminal);
    }

    #[test]
    fn record_batcher_single_batch() {
        let mut batcher = RecordBatcher::new(
            uniform_records(100, 10, 100, 1000),
            ReadLimit::CountOrBytes(CountOrBytes {
                count: 100,
                bytes: 1024 * 1024,
            }),
            ReadUntil::Unbounded,
        );

        let batch_1 = batcher.next().unwrap().unwrap();
        assert!(batch_1.is_terminal);
        assert!(batch_1.records.metered_size() <= 1024 * 1024);
        assert!(batch_1.records.len() <= 1000);

        let batch_2 = batcher.next();
        assert!(batch_2.is_none());
    }

    #[test]
    fn record_batcher_until_max_vs_none() {
        let create_records = || {
            uniform_records(100, 10, 100, 1000).map(|result| {
                result.map(|(seq_num, _timestamp, data)| {
                    let timestamp = if seq_num < 150 {
                        seq_num * 1000
                    } else {
                        Timestamp::MAX
                    };
                    (seq_num, timestamp, data)
                })
            })
        };

        let read_limit = ReadLimit::CountOrBytes(CountOrBytes {
            count: 100,
            bytes: 1024 * 1024,
        });

        let (count_none, last_seq_none, terminal_none) =
            RecordBatcher::new(create_records(), read_limit, ReadUntil::Unbounded).fold(
                (0usize, None, false),
                |(acc_count, _last_seq, is_terminal), batch| {
                    let batch = batch.expect("batch");
                    let last_seq = batch.records.last().map(|r| r.seq_num);
                    (
                        acc_count + batch.records.len(),
                        last_seq.or(_last_seq),
                        is_terminal || batch.is_terminal,
                    )
                },
            );

        let (count_max, last_seq_max, terminal_max) = RecordBatcher::new(
            create_records(),
            read_limit,
            ReadUntil::Timestamp(Timestamp::MAX),
        )
        .fold(
            (0usize, None, false),
            |(acc_count, _last_seq, is_terminal), batch| {
                let batch = batch.expect("batch");
                let last_seq = batch.records.last().map(|r| r.seq_num);
                (
                    acc_count + batch.records.len(),
                    last_seq.or(_last_seq),
                    is_terminal || batch.is_terminal,
                )
            },
        );

        assert_eq!(count_none, 100);
        assert_eq!(last_seq_none, Some(199));
        assert!(terminal_none);

        assert_eq!(count_max, 50);
        assert_eq!(last_seq_max, Some(149));
        assert!(terminal_max);
    }

    #[test]
    fn record_batcher_error_handling() {
        let records = vec![
            Ok((100, 100000, create_test_record(100))),
            Ok((101, 101000, create_test_record(100))),
            Err(InternalRecordError::Truncated("test error")),
        ];

        let mut batcher = RecordBatcher::new(
            records.into_iter(),
            ReadLimit::Unbounded,
            ReadUntil::Unbounded,
        );

        let batch_1 = batcher.next().unwrap().unwrap();
        assert_eq!(batch_1.records.len(), 2);

        let batch_2 = batcher.next();
        assert!(batch_2.is_some());
        assert!(batch_2.unwrap().is_err());

        let batch_3 = batcher.next();
        assert!(batch_3.is_none());
    }

    #[test]
    fn record_batcher_respects_batch_limits() {
        let mut batcher = RecordBatcher::new(
            uniform_records(2000, 10_000, 100, 1000),
            ReadLimit::Unbounded,
            ReadUntil::Unbounded,
        );

        let batch = batcher.next().unwrap().unwrap();
        assert!(batch.records.len() <= caps::RECORD_BATCH_MAX.count);
        assert!(batch.records.metered_size() <= caps::RECORD_BATCH_MAX.bytes);
    }

    #[test]
    fn record_batcher_empty_iterator() {
        let empty: Vec<Result<(SeqNum, Timestamp, Bytes), InternalRecordError>> = vec![];
        let mut batcher =
            RecordBatcher::new(empty.into_iter(), ReadLimit::Unbounded, ReadUntil::Unbounded);

        let batch = batcher.next();
        assert!(batch.is_none());
    }

    #[test]
    fn record_batcher_fused_iterator() {
        let records: Vec<Result<(SeqNum, Timestamp, Bytes), InternalRecordError>> =
            vec![Ok((100, 100000, create_test_record(100)))];

        let mut batcher = RecordBatcher::new(
            records.into_iter(),
            ReadLimit::Count(1),
            ReadUntil::Unbounded,
        );

        let _batch_1 = batcher.next().unwrap();
        let batch_2 = batcher.next();
        assert!(batch_2.is_none());

        let batch_3 = batcher.next();
        assert!(batch_3.is_none());
    }

    #[test]
    fn record_batcher_count_limit() {
        let mut batcher = RecordBatcher::new(
            uniform_records(100, 10, 100, 1000),
            ReadLimit::Count(5),
            ReadUntil::Unbounded,
        );

        let mut total_count = 0;
        while let Some(Ok(batch)) = batcher.next() {
            total_count += batch.records.len();
        }

        assert_eq!(total_count, 5);
    }

    #[test]
    fn record_batcher_bytes_limit() {
        let record_size = 10_019;
        let byte_limit = record_size * 2;
        let mut batcher = RecordBatcher::new(
            uniform_records(100, 10_000, 100, 1000),
            ReadLimit::Bytes(byte_limit),
            ReadUntil::Unbounded,
        );

        let mut total_bytes = 0;
        while let Some(Ok(batch)) = batcher.next() {
            total_bytes += batch.records.metered_size();
        }

        assert_eq!(total_bytes, byte_limit);
    }
}
