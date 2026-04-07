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
    use bytes::Bytes;

    use super::*;
    use crate::{
        encryption::EncryptionConfig,
        record::{
            Encodable, EnvelopeRecord, Header, Metered, MeteredExt, Record, SeqNum, Sequenced,
            SequencedRecord, StoredSequencedBytes, StoredSequencedRecord, StreamPosition,
            Timestamp, to_stored_records,
        },
    };

    const TEST_KEY: [u8; 32] = [0x42; 32];

    fn test_record(
        seq_num: SeqNum,
        timestamp: Timestamp,
        body: &'static [u8],
    ) -> Metered<SequencedRecord> {
        Record::Envelope(EnvelopeRecord::try_from_parts(vec![], Bytes::from_static(body)).unwrap())
            .metered()
            .sequenced(StreamPosition { seq_num, timestamp })
    }

    fn test_record_with_headers(
        seq_num: SeqNum,
        timestamp: Timestamp,
        headers: Vec<Header>,
        body: &'static [u8],
    ) -> Metered<SequencedRecord> {
        Record::Envelope(EnvelopeRecord::try_from_parts(headers, Bytes::from_static(body)).unwrap())
            .metered()
            .sequenced(StreamPosition { seq_num, timestamp })
    }

    fn make_stored_records(
        records: Vec<Metered<SequencedRecord>>,
        encryption: EncryptionConfig,
        aad: impl AsRef<[u8]>,
    ) -> Vec<Metered<StoredSequencedRecord>> {
        to_stored_records(records, &encryption, aad.as_ref())
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
        let expected = make_stored_records(
            vec![test_record(1, 10, b"p0"), test_record(2, 11, b"p1")],
            EncryptionConfig::Plain,
            [],
        );
        let actual = StoredRecordIterator::new(to_stored_bytes_iter(expected.clone()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn stored_iterator_preserves_encrypted_records() {
        let aad = [0xA5; 32];
        let encryption = EncryptionConfig::aegis256(TEST_KEY);
        let expected = make_stored_records(
            vec![test_record_with_headers(
                1,
                10,
                vec![Header {
                    name: Bytes::from_static(b"x-test"),
                    value: Bytes::from_static(b"hello"),
                }],
                b"secret payload",
            )],
            encryption,
            aad,
        );

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
