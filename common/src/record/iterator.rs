use std::iter::FusedIterator;

use bytes::Bytes;

use super::{
    InternalRecordError, Metered, RecordEncryptionError, SequencedRecord, StoredRecord,
    StoredSequencedBytes, decode_stored_record,
};
use crate::encryption::EncryptionConfig;

#[derive(Debug, thiserror::Error)]
pub enum RecordIteratorError<E> {
    #[error("source iterator error")]
    Source(E),
    #[error(transparent)]
    Decode(#[from] InternalRecordError),
    #[error(transparent)]
    Encryption(#[from] RecordEncryptionError),
}

pub struct DecodedRecordIterator<I> {
    inner: I,
    encryption: EncryptionConfig,
    aad: Bytes,
}

impl<I> DecodedRecordIterator<I> {
    pub fn new(inner: I, encryption: EncryptionConfig, aad: Bytes) -> Self {
        Self {
            inner,
            encryption,
            aad,
        }
    }
}

impl<I, E> Iterator for DecodedRecordIterator<I>
where
    I: Iterator<Item = Result<StoredSequencedBytes, E>>,
{
    type Item = Result<Metered<SequencedRecord>, RecordIteratorError<E>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|result| {
            let stored = result.map_err(RecordIteratorError::Source)?;
            let position = stored.position;
            let bytes = stored.record;
            let record: Metered<StoredRecord> = bytes.try_into()?;
            let record = decode_stored_record(record, &self.encryption, self.aad.as_ref())?;
            Ok(record.sequenced(position))
        })
    }
}

impl<I, E> FusedIterator for DecodedRecordIterator<I> where
    I: FusedIterator<Item = Result<StoredSequencedBytes, E>>
{
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{
        encryption::EncryptionConfig,
        record::{
            Encodable, EnvelopeRecord, Header, Metered, Record, SeqNum, Sequenced, SequencedRecord,
            StoredSequencedBytes, StreamPosition, Timestamp, to_stored_records,
        },
    };

    const TEST_KEY: [u8; 32] = [0x42; 32];

    fn test_record(
        seq_num: SeqNum,
        timestamp: Timestamp,
        body: &'static [u8],
    ) -> Metered<SequencedRecord> {
        Metered::from(Record::Envelope(
            EnvelopeRecord::try_from_parts(vec![], Bytes::from_static(body)).unwrap(),
        ))
        .sequenced(StreamPosition { seq_num, timestamp })
    }

    fn test_record_with_headers(
        seq_num: SeqNum,
        timestamp: Timestamp,
        headers: Vec<Header>,
        body: &'static [u8],
    ) -> Metered<SequencedRecord> {
        Metered::from(Record::Envelope(
            EnvelopeRecord::try_from_parts(headers, Bytes::from_static(body)).unwrap(),
        ))
        .sequenced(StreamPosition { seq_num, timestamp })
    }

    fn to_stored_bytes_iter(
        records: Vec<Metered<SequencedRecord>>,
        encryption: EncryptionConfig,
        aad: impl AsRef<[u8]>,
    ) -> impl Iterator<Item = Result<StoredSequencedBytes, InternalRecordError>> {
        to_stored_records(records, &encryption, aad.as_ref())
            .unwrap()
            .into_iter()
            .map(|record| {
                let (position, record) = record.into_parts();
                Sequenced {
                    position,
                    record: record.as_ref().to_bytes(),
                }
            })
            .map(Ok)
    }

    #[test]
    fn decodes_plaintext_records() {
        let expected = vec![test_record(1, 10, b"p0"), test_record(2, 11, b"p1")];
        let actual = DecodedRecordIterator::new(
            to_stored_bytes_iter(expected.clone(), EncryptionConfig::Plain, []),
            EncryptionConfig::Plain,
            Bytes::new(),
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn decrypts_encrypted_records() {
        let aad = [0xA5; 32];
        let encryption = EncryptionConfig::aegis256(TEST_KEY);
        let expected = vec![test_record_with_headers(
            1,
            10,
            vec![Header {
                name: Bytes::from_static(b"x-test"),
                value: Bytes::from_static(b"hello"),
            }],
            b"secret payload",
        )];

        let actual = DecodedRecordIterator::new(
            to_stored_bytes_iter(expected.clone(), encryption.clone(), aad),
            encryption,
            Bytes::copy_from_slice(&aad),
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_encrypted_records_without_decryption() {
        let aad = [0xA5; 32];
        let expected = vec![test_record(1, 10, b"secret payload")];
        let mut iter = DecodedRecordIterator::new(
            to_stored_bytes_iter(expected, EncryptionConfig::aegis256(TEST_KEY), aad),
            EncryptionConfig::Plain,
            Bytes::copy_from_slice(&aad),
        );

        let error = iter
            .next()
            .expect("record expected")
            .expect_err("expected error");
        assert!(matches!(
            error,
            RecordIteratorError::Encryption(RecordEncryptionError::UnexpectedEncryptedRecord)
        ));
    }

    #[test]
    fn surfaces_decode_errors() {
        let invalid_data = Sequenced {
            position: StreamPosition {
                seq_num: 1,
                timestamp: 10,
            },
            record: Bytes::new(),
        };
        let mut iter = DecodedRecordIterator::new(
            std::iter::once::<Result<StoredSequencedBytes, InternalRecordError>>(Ok(invalid_data)),
            EncryptionConfig::Plain,
            Bytes::new(),
        );

        let error = iter
            .next()
            .expect("error expected")
            .expect_err("expected error");
        assert!(matches!(
            error,
            RecordIteratorError::Decode(InternalRecordError::Truncated("MagicByte"))
        ));
        assert!(iter.next().is_none());
    }

    #[test]
    fn preserves_source_errors() {
        let mut iter = DecodedRecordIterator::new(
            std::iter::once::<Result<StoredSequencedBytes, InternalRecordError>>(Err(
                InternalRecordError::InvalidValue("test", "boom"),
            )),
            EncryptionConfig::Plain,
            Bytes::new(),
        );

        let error = iter
            .next()
            .expect("error expected")
            .expect_err("expected error");
        assert!(matches!(
            error,
            RecordIteratorError::Source(InternalRecordError::InvalidValue("test", "boom"))
        ));
    }
}
