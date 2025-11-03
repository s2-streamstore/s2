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
mod tests {
    use super::*;
    use crate::{
        caps,
        read_extent::{ReadLimit, ReadUntil},
        record::{CommandRecord, Encodable, MeteredRecord, MeteredSize, Record},
    };
    use bytes::Bytes;

    type BatchItem = (SeqNum, Timestamp, Bytes);

    #[derive(Clone)]
    struct TestRecord {
        seq_num: SeqNum,
        timestamp: Timestamp,
        record: Record,
        bytes: Bytes,
        metered_size: usize,
    }

    impl TestRecord {
        fn trim(seq_num: SeqNum, timestamp: Timestamp) -> Self {
            let record = Record::Command(CommandRecord::Trim(seq_num));
            let metered: MeteredRecord = record.clone().into();
            Self {
                seq_num,
                timestamp,
                record,
                bytes: metered.to_bytes(),
                metered_size: metered.metered_size(),
            }
        }

        fn into_item(self) -> (SeqNum, Timestamp, Bytes) {
            (self.seq_num, self.timestamp, self.bytes)
        }
    }

    fn to_ok(record: TestRecord) -> Result<BatchItem, InternalRecordError> {
        Ok(record.into_item())
    }

    fn assert_batch(batch: &RecordBatch, expected: &[TestRecord], is_terminal: bool) {
        assert_eq!(batch.is_terminal, is_terminal);
        assert_eq!(batch.records.len(), expected.len());
        let expected_size: usize = expected.iter().map(|r| r.metered_size).sum();
        assert_eq!(batch.records.metered_size(), expected_size);
        for (actual, expected) in batch.records.iter().zip(expected.iter()) {
            assert_eq!(actual.seq_num, expected.seq_num);
            assert_eq!(actual.timestamp, expected.timestamp);
            assert_eq!(actual.record, expected.record);
        }
    }

    #[test]
    fn collects_records_until_iterator_ends() {
        let expected = vec![
            TestRecord::trim(1, 10),
            TestRecord::trim(2, 11),
            TestRecord::trim(3, 12),
        ];
        let iterator = expected.clone().into_iter().map(to_ok);
        let mut batcher = RecordBatcher::new(iterator, ReadLimit::Unbounded, ReadUntil::Unbounded);

        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert_batch(&batch, &expected, false);
        assert!(batcher.next().is_none());
    }

    #[test]
    fn stops_at_count_read_limit() {
        let expected = vec![
            TestRecord::trim(1, 10),
            TestRecord::trim(2, 11),
            TestRecord::trim(3, 12),
        ];
        let iterator = expected.clone().into_iter().map(to_ok);
        let mut batcher = RecordBatcher::new(iterator, ReadLimit::Count(2), ReadUntil::Unbounded);

        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert_batch(&batch, &expected[..2], true);
        assert!(batcher.next().is_none());
    }

    #[test]
    fn stops_at_byte_read_limit() {
        let expected = vec![TestRecord::trim(1, 10), TestRecord::trim(2, 11)];
        let first_size = expected[0].metered_size;
        let iterator = expected.clone().into_iter().map(to_ok);
        let mut batcher =
            RecordBatcher::new(iterator, ReadLimit::Bytes(first_size), ReadUntil::Unbounded);

        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert_batch(&batch, &expected[..1], true);
        assert!(batcher.next().is_none());
    }

    #[test]
    fn stops_at_timestamp_limit() {
        let expected = vec![
            TestRecord::trim(1, 10),
            TestRecord::trim(2, 19),
            TestRecord::trim(3, 20),
        ];
        let iterator = expected.clone().into_iter().map(to_ok);
        let mut batcher =
            RecordBatcher::new(iterator, ReadLimit::Unbounded, ReadUntil::Timestamp(20));

        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert_batch(&batch, &expected[..2], true);
        assert!(batcher.next().is_none());
    }

    #[test]
    fn splits_batches_when_caps_are_hit() {
        let mut records = Vec::with_capacity(caps::RECORD_BATCH_MAX.count + 1);
        for index in 0..=(caps::RECORD_BATCH_MAX.count as SeqNum) {
            records.push(TestRecord::trim(index, index + 10));
        }
        let iterator = records.clone().into_iter().map(to_ok);
        let mut batcher = RecordBatcher::new(iterator, ReadLimit::Unbounded, ReadUntil::Unbounded);

        let first_batch = batcher
            .next()
            .expect("first batch expected")
            .expect("first batch ok");
        assert_batch(
            &first_batch,
            &records[..caps::RECORD_BATCH_MAX.count],
            false,
        );

        let second_batch = batcher
            .next()
            .expect("second batch expected")
            .expect("second batch ok");
        assert_batch(
            &second_batch,
            &records[caps::RECORD_BATCH_MAX.count..],
            false,
        );
        assert!(batcher.next().is_none());
    }

    #[test]
    fn surfaces_decode_errors_after_draining_buffer() {
        let records = vec![TestRecord::trim(1, 10), TestRecord::trim(2, 11)];
        let invalid_data = (3, 12, Bytes::new());

        let iterator = records
            .clone()
            .into_iter()
            .map(to_ok)
            .chain(std::iter::once(Ok(invalid_data)));
        let mut batcher = RecordBatcher::new(iterator, ReadLimit::Unbounded, ReadUntil::Unbounded);

        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert_batch(&batch, &records, false);

        let error = batcher
            .next()
            .expect("error expected")
            .expect_err("expected decode error");
        assert!(matches!(error, InternalRecordError::Truncated("MagicByte")));
        assert!(batcher.next().is_none());
    }

    #[test]
    fn surfaces_iterator_errors_immediately() {
        let iterator = std::iter::once::<Result<(SeqNum, Timestamp, Bytes), InternalRecordError>>(
            Err(InternalRecordError::InvalidValue("test", "boom")),
        );
        let mut batcher = RecordBatcher::new(iterator, ReadLimit::Unbounded, ReadUntil::Unbounded);

        let error = batcher
            .next()
            .expect("error expected")
            .expect_err("expected iterator error");
        assert!(matches!(
            error,
            InternalRecordError::InvalidValue("test", "boom")
        ));
        assert!(batcher.next().is_none());
    }
}
