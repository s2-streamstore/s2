//! Record protection composes logical records with encrypted storage framing.
//!
//! Plaintext records are stored as `StoredRecord::Plaintext(Record)` and use
//! the same command/envelope framing as the logical record layer.
//!
//! Encrypted envelope records are stored as `StoredRecord::Encrypted`. Their
//! outer record type is `RecordType::EncryptedEnvelope`, and the encoded body is
//! an [`EncryptedRecord`](super::EncryptedRecord) containing encrypted bytes for
//! the byte-for-byte plaintext [`EnvelopeRecord`](super::EnvelopeRecord)
//! encoding.
//!
//! The stored `metered_size` remains the logical plaintext metered size rather
//! than the ciphertext size, so protection does not change append/read
//! metering, limits, or accounting.

use super::{
    Encodable as _, EnvelopeRecord, Metered, MeteredSize, Record, SequencedRecord, StoredReadBatch,
    StoredRecord, StoredSequencedRecord,
};
use crate::{
    encryption::{self, EncryptionConfig, EncryptionError},
    types::{self},
};

pub fn to_stored_records(
    records: Vec<Metered<SequencedRecord>>,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<Vec<Metered<StoredSequencedRecord>>, EncryptionError> {
    records
        .into_iter()
        .map(|record| {
            let (position, record) = record.into_parts();
            let metered_size = record.metered_size();
            let stored = match (record.into_inner(), encryption) {
                (record @ Record::Command(_), _) => StoredRecord::Plaintext(record),
                (record @ Record::Envelope(_), EncryptionConfig::None) => {
                    StoredRecord::Plaintext(record)
                }
                (Record::Envelope(envelope), encryption) => {
                    let plaintext = envelope.to_bytes();
                    let encrypted = encryption::encrypt_payload(&plaintext, encryption, aad)?;
                    StoredRecord::encrypted(encrypted, metered_size)
                }
            };
            Ok(Metered::from(stored).sequenced(position))
        })
        .collect()
}

pub fn decrypt_read_batch(
    batch: StoredReadBatch,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<types::stream::ReadBatch, EncryptionError> {
    let records: Vec<super::SequencedRecord> = batch
        .records
        .into_inner()
        .into_iter()
        .map(|sr| match sr.record {
            StoredRecord::Plaintext(record) => Ok(super::Sequenced {
                position: sr.position,
                record,
            }),
            StoredRecord::Encrypted {
                record: encrypted, ..
            } => {
                let plaintext = encryption::decrypt_payload(&encrypted, encryption, aad)?;
                let envelope = EnvelopeRecord::try_from(plaintext)
                    .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))?;
                Ok(super::Sequenced {
                    position: sr.position,
                    record: Record::Envelope(envelope),
                })
            }
        })
        .collect::<Result<_, EncryptionError>>()?;

    Ok(types::stream::ReadBatch {
        records: Metered::from(records),
        tail: batch.tail,
    })
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{
        encryption::EncryptionConfig,
        record::{EnvelopeRecord, Header, StoredReadBatch, StreamPosition},
    };

    fn aegis256_encryption() -> EncryptionConfig {
        "aegis-256; QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
            .parse::<EncryptionConfig>()
            .unwrap()
    }

    fn aad() -> [u8; 32] {
        [0xA5; 32]
    }

    fn make_plaintext_envelope(headers: Vec<Header>, body: Bytes) -> Record {
        Record::Envelope(EnvelopeRecord::try_from_parts(headers, body).unwrap())
    }

    fn make_encrypted_stored_record(
        encryption: &EncryptionConfig,
        headers: Vec<Header>,
        body: Bytes,
        aad: &[u8],
    ) -> StoredRecord {
        let metered_size = make_plaintext_envelope(headers.clone(), body.clone()).metered_size();
        let plaintext = EnvelopeRecord::try_from_parts(headers, body)
            .unwrap()
            .to_bytes();
        let encrypted = encryption::encrypt_payload(&plaintext, encryption, aad).unwrap();
        StoredRecord::encrypted(encrypted, metered_size)
    }

    fn make_stored_read_batch(records: Vec<StoredRecord>) -> StoredReadBatch {
        let records = records
            .into_iter()
            .enumerate()
            .map(|(i, record)| {
                Metered::from(record)
                    .sequenced(StreamPosition {
                        seq_num: i as u64 + 1,
                        timestamp: i as u64 + 10,
                    })
                    .into_inner()
            })
            .collect::<Vec<_>>();
        StoredReadBatch {
            records: Metered::from(records),
            tail: None,
        }
    }

    fn make_sequenced_records(records: Vec<Record>) -> Vec<Metered<SequencedRecord>> {
        records
            .into_iter()
            .enumerate()
            .map(|(i, record)| {
                Metered::from(record).sequenced(StreamPosition {
                    seq_num: i as u64 + 1,
                    timestamp: i as u64 + 10,
                })
            })
            .collect::<Vec<_>>()
    }

    #[test]
    fn to_stored_records_marks_encrypted_envelopes() {
        let aad = aad();
        let input = make_sequenced_records(vec![make_plaintext_envelope(
            vec![Header {
                name: Bytes::from_static(b"x-test"),
                value: Bytes::from_static(b"hello"),
            }],
            Bytes::from_static(b"secret payload"),
        )]);

        let encrypted = to_stored_records(input, &aegis256_encryption(), &aad).unwrap();
        let (_, record) = encrypted.into_iter().next().unwrap().into_parts();
        let record = record.into_inner();

        let StoredRecord::Encrypted {
            record: envelope, ..
        } = record
        else {
            panic!("expected encrypted envelope record");
        };
        assert_ne!(envelope.to_bytes().as_ref(), b"secret payload");
    }

    #[test]
    fn decrypt_read_batch_preserves_plaintext_and_decrypts_encrypted_records() {
        let aad = aad();
        let batch = make_stored_read_batch(vec![
            StoredRecord::Plaintext(Record::Envelope(
                EnvelopeRecord::try_from_parts(vec![], Bytes::from_static(b"legacy-plaintext"))
                    .unwrap(),
            )),
            make_encrypted_stored_record(
                &aegis256_encryption(),
                vec![Header {
                    name: Bytes::from_static(b"x-test"),
                    value: Bytes::from_static(b"hello"),
                }],
                Bytes::from_static(b"secret payload"),
                &aad,
            ),
        ]);

        let decrypted = decrypt_read_batch(batch, &aegis256_encryption(), &aad).unwrap();
        let records = decrypted.records.into_inner();

        let Record::Envelope(first) = &records[0].record else {
            panic!("expected envelope record");
        };
        assert_eq!(first.body().as_ref(), b"legacy-plaintext");

        let Record::Envelope(second) = &records[1].record else {
            panic!("expected envelope record");
        };
        assert_eq!(second.headers().len(), 1);
        assert_eq!(second.headers()[0].name.as_ref(), b"x-test");
        assert_eq!(second.headers()[0].value.as_ref(), b"hello");
        assert_eq!(second.body().as_ref(), b"secret payload");
    }

    #[test]
    fn decrypt_read_batch_none_rejects_encrypted_records() {
        let aad = aad();
        let batch = make_stored_read_batch(vec![make_encrypted_stored_record(
            &aegis256_encryption(),
            vec![],
            Bytes::from_static(b"secret payload"),
            &aad,
        )]);

        let result = decrypt_read_batch(batch, &EncryptionConfig::None, &aad);

        assert!(matches!(
            result,
            Err(EncryptionError::UnexpectedEncryptedRecord)
        ));
    }
}
