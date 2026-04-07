use std::iter::FusedIterator;

use super::{
    Metered, RecordDecodeError, StoredRecord, StoredSequencedBytes, StoredSequencedRecord,
};

pub struct StoredRecordIterator<I> {
    inner: I,
}

impl<I> StoredRecordIterator<I> {
    pub fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I, E> Iterator for StoredRecordIterator<I>
where
    I: Iterator<Item = Result<StoredSequencedBytes, E>>,
    E: std::fmt::Debug + Into<RecordDecodeError>,
{
    type Item = Result<Metered<StoredSequencedRecord>, RecordDecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|result| {
            let (position, bytes) = result.map_err(Into::into)?.into_parts();
            let record: Metered<StoredRecord> = bytes.try_into()?;
            Ok(record.sequenced(position))
        })
    }
}

impl<I, E> FusedIterator for StoredRecordIterator<I>
where
    I: FusedIterator<Item = Result<StoredSequencedBytes, E>>,
    E: std::fmt::Debug + Into<RecordDecodeError>,
{
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, Bytes, BytesMut};

    use super::*;
    use crate::record::{
        Encodable, EncryptedRecord, EnvelopeRecord, Metered, MeteredExt, MeteredSize, Record,
        SeqNum, Sequenced, StoredRecord, StoredSequencedBytes, StoredSequencedRecord,
        StreamPosition, Timestamp,
    };

    fn test_stored_plaintext_record(
        seq_num: SeqNum,
        timestamp: Timestamp,
        body: &'static [u8],
    ) -> Metered<StoredSequencedRecord> {
        StoredRecord::Plaintext(Record::Envelope(
            EnvelopeRecord::try_from_parts(vec![], Bytes::from_static(body)).unwrap(),
        ))
        .metered()
        .sequenced(StreamPosition { seq_num, timestamp })
    }

    fn test_stored_encrypted_record(
        seq_num: SeqNum,
        timestamp: Timestamp,
    ) -> Metered<StoredSequencedRecord> {
        let metered_size = Record::Envelope(
            EnvelopeRecord::try_from_parts(vec![], Bytes::from_static(b"secret payload")).unwrap(),
        )
        .metered_size();

        let mut encoded = BytesMut::with_capacity(1 + 12 + 10 + 16);
        encoded.put_u8(0x02);
        encoded.put_bytes(0xAB, 12);
        encoded.put_slice(b"ciphertext");
        encoded.put_bytes(0xCD, 16);
        let record = EncryptedRecord::try_from(encoded.freeze()).unwrap();

        StoredRecord::Encrypted {
            metered_size,
            record,
        }
        .metered()
        .sequenced(StreamPosition { seq_num, timestamp })
    }

    fn to_stored_bytes_iter(
        records: Vec<Metered<StoredSequencedRecord>>,
    ) -> impl Iterator<Item = Result<StoredSequencedBytes, RecordDecodeError>> {
        records
            .into_iter()
            .map(|record| {
                let (position, record) = record.into_parts();
                Sequenced::new(position, record.as_ref().to_bytes())
            })
            .map(Ok)
    }

    #[test]
    fn stored_iterator_decodes_plaintext_records() {
        let expected = vec![
            test_stored_plaintext_record(1, 10, b"p0"),
            test_stored_plaintext_record(2, 11, b"p1"),
        ];
        let actual = StoredRecordIterator::new(to_stored_bytes_iter(expected.clone()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn stored_iterator_preserves_encrypted_records() {
        let expected = vec![test_stored_encrypted_record(1, 10)];

        let actual = StoredRecordIterator::new(to_stored_bytes_iter(expected.clone()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn stored_iterator_surfaces_decode_errors() {
        let invalid_data = Sequenced::new(
            StreamPosition {
                seq_num: 1,
                timestamp: 10,
            },
            Bytes::new(),
        );
        let mut iter = StoredRecordIterator::new(std::iter::once::<
            Result<StoredSequencedBytes, RecordDecodeError>,
        >(Ok(invalid_data)));

        let error = iter
            .next()
            .expect("error expected")
            .expect_err("expected error");
        assert!(matches!(error, RecordDecodeError::Truncated("MagicByte")));
        assert!(iter.next().is_none());
    }

    #[test]
    fn stored_iterator_preserves_source_errors() {
        let mut iter = StoredRecordIterator::new(std::iter::once::<
            Result<StoredSequencedBytes, RecordDecodeError>,
        >(Err(RecordDecodeError::InvalidValue(
            "test", "boom",
        ))));

        let error = iter
            .next()
            .expect("error expected")
            .expect_err("expected error");
        assert!(matches!(
            error,
            RecordDecodeError::InvalidValue("test", "boom")
        ));
    }
}
