use std::iter::FusedIterator;

use crate::{
    caps,
    read_extent::{EvaluatedReadLimit, ReadLimit, ReadUntil},
    record::{Metered, MeteredSize, Sequenced, StoredRecord},
};

pub struct RecordBatch<T = StoredRecord>
where
    T: MeteredSize,
{
    pub records: Metered<Vec<Sequenced<T>>>,
    pub is_terminal: bool,
}

impl<T> std::fmt::Debug for RecordBatch<T>
where
    T: MeteredSize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordBatch")
            .field("num_records", &self.records.len())
            .field("metered_size", &self.records.metered_size())
            .field("is_terminal", &self.is_terminal)
            .finish()
    }
}

pub struct RecordBatcher<I, E, T>
where
    T: MeteredSize,
    I: Iterator<Item = Result<Metered<Sequenced<T>>, E>>,
{
    record_iterator: I,
    buffered_records: Metered<Vec<Sequenced<T>>>,
    buffered_error: Option<E>,
    read_limit: EvaluatedReadLimit,
    until: ReadUntil,
    is_terminated: bool,
}

fn make_records<T>(read_limit: &EvaluatedReadLimit) -> Metered<Vec<Sequenced<T>>>
where
    T: MeteredSize,
{
    match read_limit {
        EvaluatedReadLimit::Remaining(limit) => {
            Metered::with_capacity(limit.count().map_or(caps::RECORD_BATCH_MAX.count, |n| {
                n.min(caps::RECORD_BATCH_MAX.count)
            }))
        }
        EvaluatedReadLimit::Exhausted => Metered::default(),
    }
}

impl<I, E, T> RecordBatcher<I, E, T>
where
    T: MeteredSize,
    I: Iterator<Item = Result<Metered<Sequenced<T>>, E>>,
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

    fn iter_next(&mut self) -> Option<Result<RecordBatch<T>, E>> {
        let EvaluatedReadLimit::Remaining(remaining_limit) = self.read_limit else {
            return None;
        };

        let mut stashed_record = None;
        while self.buffered_error.is_none() {
            match self.record_iterator.next() {
                Some(Ok(record)) => {
                    if remaining_limit.deny(
                        self.buffered_records.len() + 1,
                        self.buffered_records.metered_size() + record.metered_size(),
                    ) || self.until.deny(record.position.timestamp)
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
                    self.buffered_error = Some(err);
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
                    Metered::default()
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

impl<I, E, T> Iterator for RecordBatcher<I, E, T>
where
    T: MeteredSize,
    I: Iterator<Item = Result<Metered<Sequenced<T>>, E>>,
{
    type Item = Result<RecordBatch<T>, E>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_terminated {
            return None;
        }
        let item = self.iter_next();
        self.is_terminated = matches!(&item, None | Some(Err(_)));
        item
    }
}

impl<I, E, T> FusedIterator for RecordBatcher<I, E, T>
where
    T: MeteredSize,
    I: Iterator<Item = Result<Metered<Sequenced<T>>, E>>,
{
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{
        caps,
        read_extent::{ReadLimit, ReadUntil},
        record::{
            CommandRecord, Encodable, EnvelopeRecord, Metered, MeteredExt, MeteredSize, Record,
            RecordDecodeError, SeqNum, Sequenced, SequencedRecord, StoredRecord,
            StoredRecordIterator, StoredSequencedBytes, StoredSequencedRecord, StreamPosition,
            Timestamp,
        },
    };

    fn test_logical_record(seq_num: SeqNum, timestamp: Timestamp) -> SequencedRecord {
        Record::Command(CommandRecord::Trim(seq_num))
            .metered()
            .sequenced(StreamPosition { seq_num, timestamp })
            .into_inner()
    }

    fn test_record(seq_num: SeqNum, timestamp: Timestamp) -> StoredSequencedRecord {
        Metered::from(StoredRecord::from(Record::Command(CommandRecord::Trim(
            seq_num,
        ))))
        .sequenced(StreamPosition { seq_num, timestamp })
        .into_inner()
    }

    fn test_large_record(
        seq_num: SeqNum,
        timestamp: Timestamp,
        body_len: usize,
    ) -> StoredSequencedRecord {
        Metered::from(StoredRecord::from(Record::Envelope(
            EnvelopeRecord::try_from_parts(vec![], Bytes::from(vec![0; body_len])).unwrap(),
        )))
        .sequenced(StreamPosition { seq_num, timestamp })
        .into_inner()
    }

    fn to_iter(
        records: Vec<StoredSequencedRecord>,
    ) -> impl Iterator<Item = Result<Metered<StoredSequencedRecord>, RecordDecodeError>> {
        records.into_iter().map(Metered::from).map(Ok)
    }

    fn to_logical_iter(
        records: Vec<SequencedRecord>,
    ) -> impl Iterator<Item = Result<Metered<SequencedRecord>, RecordDecodeError>> {
        records.into_iter().map(Metered::from).map(Ok)
    }

    fn to_stored_bytes_iter(
        records: Vec<StoredSequencedRecord>,
    ) -> impl Iterator<Item = Result<StoredSequencedBytes, RecordDecodeError>> {
        records
            .into_iter()
            .map(|record| {
                let (position, record) = record.into_parts();
                Sequenced::new(position, (&record).metered().to_bytes())
            })
            .map(Ok)
    }

    fn assert_batch(batch: &RecordBatch, expected: &[StoredSequencedRecord], is_terminal: bool) {
        assert_eq!(batch.is_terminal, is_terminal);
        assert_eq!(batch.records.len(), expected.len());
        let expected_size: usize = expected.iter().map(|r| r.metered_size()).sum();
        assert_eq!(batch.records.metered_size(), expected_size);
        for (actual, expected) in batch.records.iter().zip(expected.iter()) {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn collects_records_until_iterator_ends() {
        let expected = vec![test_record(1, 10), test_record(2, 11), test_record(3, 12)];
        let mut batcher = RecordBatcher::new(
            to_iter(expected.clone()),
            ReadLimit::Unbounded,
            ReadUntil::Unbounded,
        );
        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert_batch(&batch, &expected, false);
        assert!(batcher.next().is_none());
    }

    #[test]
    fn generic_batcher_collects_logical_records() {
        let expected = vec![
            test_logical_record(1, 10),
            test_logical_record(2, 11),
            test_logical_record(3, 12),
        ];
        let mut batcher = RecordBatcher::new(
            to_logical_iter(expected.clone()),
            ReadLimit::Unbounded,
            ReadUntil::Unbounded,
        );

        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert!(!batch.is_terminal);
        assert_eq!(batch.records.len(), expected.len());
        let expected_size: usize = expected.iter().map(|r| r.metered_size()).sum();
        assert_eq!(batch.records.metered_size(), expected_size);
        for (actual, expected) in batch.records.iter().zip(expected.iter()) {
            assert_eq!(actual, expected);
        }
        assert!(batcher.next().is_none());
    }

    #[test]
    fn stops_at_count_read_limit() {
        let expected = vec![test_record(1, 10), test_record(2, 11), test_record(3, 12)];
        let mut batcher = RecordBatcher::new(
            to_iter(expected.clone()),
            ReadLimit::Count(2),
            ReadUntil::Unbounded,
        );

        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert_batch(&batch, &expected[..2], true);
        assert!(batcher.next().is_none());
    }

    #[test]
    fn stops_at_byte_read_limit() {
        let expected = vec![test_record(1, 10), test_record(2, 11)];
        let first_size = expected[0].metered_size();
        let mut batcher = RecordBatcher::new(
            to_iter(expected.clone()),
            ReadLimit::Bytes(first_size),
            ReadUntil::Unbounded,
        );

        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert_batch(&batch, &expected[..1], true);
        assert!(batcher.next().is_none());
    }

    #[test]
    fn stops_at_timestamp_limit() {
        let expected = vec![test_record(1, 10), test_record(2, 19), test_record(3, 20)];
        let mut batcher = RecordBatcher::new(
            to_iter(expected.clone()),
            ReadLimit::Unbounded,
            ReadUntil::Timestamp(20),
        );

        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert_batch(&batch, &expected[..2], true);
        assert!(batcher.next().is_none());
    }

    #[test]
    fn splits_batches_when_caps_are_hit() {
        let mut records = Vec::with_capacity(caps::RECORD_BATCH_MAX.count + 1);
        for index in 0..=(caps::RECORD_BATCH_MAX.count as SeqNum) {
            records.push(test_record(index, index + 10));
        }
        let mut batcher = RecordBatcher::new(
            to_iter(records.clone()),
            ReadLimit::Unbounded,
            ReadUntil::Unbounded,
        );

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
    fn splits_batches_when_byte_cap_is_hit() {
        let records = vec![
            test_large_record(1, 10, caps::RECORD_BATCH_MAX.bytes / 2 + 1),
            test_large_record(2, 11, caps::RECORD_BATCH_MAX.bytes / 2 + 1),
        ];
        assert!(records[0].metered_size() <= caps::RECORD_BATCH_MAX.bytes);
        assert!(records[1].metered_size() <= caps::RECORD_BATCH_MAX.bytes);
        assert!(
            records[0].metered_size() + records[1].metered_size() > caps::RECORD_BATCH_MAX.bytes
        );

        let mut batcher = RecordBatcher::new(
            to_iter(records.clone()),
            ReadLimit::Unbounded,
            ReadUntil::Unbounded,
        );

        let first_batch = batcher
            .next()
            .expect("first batch expected")
            .expect("first batch ok");
        assert_batch(&first_batch, &records[..1], false);

        let second_batch = batcher
            .next()
            .expect("second batch expected")
            .expect("second batch ok");
        assert_batch(&second_batch, &records[1..], false);
        assert!(batcher.next().is_none());
    }

    #[test]
    fn surfaces_decode_errors_after_draining_buffer() {
        let records = vec![test_record(1, 10), test_record(2, 11)];
        let invalid_data = Sequenced::new(
            StreamPosition {
                seq_num: 3,
                timestamp: 12,
            },
            Bytes::new(),
        );

        let mut batcher = RecordBatcher::new(
            StoredRecordIterator::new(
                to_stored_bytes_iter(records.clone()).chain(std::iter::once(Ok(invalid_data))),
            ),
            ReadLimit::Unbounded,
            ReadUntil::Unbounded,
        );

        let batch = batcher.next().expect("batch expected").expect("ok batch");
        assert_batch(&batch, &records, false);

        let error = batcher
            .next()
            .expect("error expected")
            .expect_err("expected decode error");
        assert!(matches!(error, RecordDecodeError::Truncated("MagicByte")));
        assert!(batcher.next().is_none());
    }

    #[test]
    fn surfaces_iterator_errors_immediately() {
        let iterator = StoredRecordIterator::new(std::iter::once::<
            Result<StoredSequencedBytes, RecordDecodeError>,
        >(Err(RecordDecodeError::InvalidValue(
            "test", "boom",
        ))));
        let mut batcher = RecordBatcher::new(iterator, ReadLimit::Unbounded, ReadUntil::Unbounded);

        let error = batcher
            .next()
            .expect("error expected")
            .expect_err("expected iterator error");
        assert!(matches!(
            error,
            RecordDecodeError::InvalidValue("test", "boom")
        ));
        assert!(batcher.next().is_none());
    }
}
