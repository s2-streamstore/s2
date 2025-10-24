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
    // TODO new set of tests without the internal dep
}
