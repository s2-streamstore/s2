//! Encrypted record storage, wire format, and raw cryptography.
//!
//! ```text
//! [suite_id: 1 byte] [nonce] [ciphertext] [tag]
//! ```
//!
//! | suite_id | Suite          | Nonce  | Tag  |
//! |----------|----------------|--------|------|
//! | 0x01     | AEGIS-256 v1   | 32 B   | 16 B |
//! | 0x02     | AES-256-GCM v1 | 12 B   | 16 B |
//!
//! The leading suite byte identifies the full ciphertext framing, not just the
//! algorithm. This leaves room for future layout changes without a separate
//! version byte.
//!
//! AAD is caller-supplied associated data.
//!
//! Plaintext records are stored as `StoredRecord::Plaintext(Record)` and use
//! the same command/envelope framing as the logical record layer.
//!
//! Encrypted envelope records are stored as `StoredRecord::Encrypted`. Their
//! outer record type is `RecordType::EncryptedEnvelope`, and the encoded body is
//! an [`EncryptedRecord`] containing encrypted bytes for the byte-for-byte
//! plaintext [`EnvelopeRecord`](super::EnvelopeRecord) encoding.
//!
//! The stored `metered_size` remains the logical plaintext metered size rather
//! than the ciphertext size, so protection does not change append/read
//! metering, limits, or accounting.

use aegis::aegis256::Aegis256;
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, AeadInPlace, Payload},
};
use bytes::{BufMut, Bytes, BytesMut};
use rand::random;

use super::{
    Encodable, EnvelopeRecord, Metered, MeteredSize, Record, Sequenced, SequencedRecord,
    StoredReadBatch, StoredRecord, StoredSequencedRecord,
};
use crate::{
    deep_size::DeepSize,
    encryption::{EncryptionAlgorithm, EncryptionConfig, EncryptionError},
    types::{self},
};

const SUITE_ID_LEN: usize = 1;

const SUITE_ID_AEGIS256_V1: u8 = 0x01;
const SUITE_ID_AES256GCM_V1: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EncryptedRecordError {
    #[error("truncated ciphertext")]
    Truncated,
    #[error("invalid ciphertext suite id: {0:#04x}")]
    InvalidSuiteId(u8),
    #[error("invalid ciphertext layout")]
    InvalidLayout,
}

#[derive(PartialEq, Eq, Clone)]
pub struct EncryptedRecord {
    encoded: Bytes,
    algorithm: EncryptionAlgorithm,
}

impl EncryptedRecord {
    #[cfg(test)]
    pub(crate) fn try_from_parts(
        algorithm: EncryptionAlgorithm,
        nonce: impl AsRef<[u8]>,
        ciphertext: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
    ) -> Result<Self, EncryptedRecordError> {
        let nonce = nonce.as_ref();
        let ciphertext = ciphertext.as_ref();
        let tag = tag.as_ref();

        let expected_nonce_len = algorithm.nonce_len();
        let expected_tag_len = algorithm.tag_len();
        if nonce.len() != expected_nonce_len || tag.len() != expected_tag_len {
            return Err(EncryptedRecordError::InvalidLayout);
        }

        let mut bytes =
            BytesMut::with_capacity(SUITE_ID_LEN + nonce.len() + ciphertext.len() + tag.len());
        bytes.put_u8(algorithm.suite_id());
        bytes.put_slice(nonce);
        bytes.put_slice(ciphertext);
        bytes.put_slice(tag);

        Ok(Self {
            encoded: bytes.freeze(),
            algorithm,
        })
    }

    pub(crate) fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    pub(crate) fn nonce(&self) -> &[u8] {
        let start = SUITE_ID_LEN;
        let end = start + self.algorithm.nonce_len();
        &self.encoded[start..end]
    }

    pub(crate) fn ciphertext(&self) -> &[u8] {
        let start = SUITE_ID_LEN + self.algorithm.nonce_len();
        let end = self.encoded.len() - self.algorithm.tag_len();
        &self.encoded[start..end]
    }

    pub(crate) fn ciphertext_and_tag(&self) -> &[u8] {
        let start = SUITE_ID_LEN + self.algorithm.nonce_len();
        &self.encoded[start..]
    }

    pub(crate) fn tag(&self) -> &[u8] {
        let start = self.encoded.len() - self.algorithm.tag_len();
        let end = self.encoded.len();
        &self.encoded[start..end]
    }
}

impl EncryptionAlgorithm {
    const fn try_from_suite_id(suite_id: u8) -> Result<Self, EncryptedRecordError> {
        match suite_id {
            SUITE_ID_AEGIS256_V1 => Ok(Self::Aegis256),
            SUITE_ID_AES256GCM_V1 => Ok(Self::Aes256Gcm),
            _ => Err(EncryptedRecordError::InvalidSuiteId(suite_id)),
        }
    }

    const fn suite_id(self) -> u8 {
        match self {
            Self::Aegis256 => SUITE_ID_AEGIS256_V1,
            Self::Aes256Gcm => SUITE_ID_AES256GCM_V1,
        }
    }

    const fn nonce_len(self) -> usize {
        match self {
            Self::Aegis256 => 32,
            Self::Aes256Gcm => 12,
        }
    }

    const fn tag_len(self) -> usize {
        match self {
            Self::Aegis256 => 16,
            Self::Aes256Gcm => 16,
        }
    }

    fn put_random_nonce(self, buf: &mut impl BufMut) {
        match self {
            Self::Aegis256 => buf.put_slice(&random::<[u8; 32]>()),
            Self::Aes256Gcm => buf.put_slice(&random::<[u8; 12]>()),
        }
    }
}

impl std::fmt::Debug for EncryptedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedRecord")
            .field("suite_id", &self.encoded[0])
            .field("algorithm", &self.algorithm)
            .field("nonce.len", &self.nonce().len())
            .field("ciphertext.len", &self.ciphertext().len())
            .field("tag.len", &self.tag().len())
            .finish()
    }
}

impl DeepSize for EncryptedRecord {
    fn deep_size(&self) -> usize {
        self.encoded.len()
    }
}

impl Encodable for EncryptedRecord {
    fn encoded_size(&self) -> usize {
        self.encoded.len()
    }

    fn encode_into(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.encoded.as_ref());
    }
}

impl TryFrom<Bytes> for EncryptedRecord {
    type Error = EncryptedRecordError;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.len() < SUITE_ID_LEN {
            return Err(EncryptedRecordError::Truncated);
        }

        let algorithm = EncryptionAlgorithm::try_from_suite_id(bytes[0])?;
        let nonce_len = algorithm.nonce_len();
        let tag_len = algorithm.tag_len();
        if bytes.len() < SUITE_ID_LEN + nonce_len + tag_len {
            return Err(EncryptedRecordError::Truncated);
        }

        Ok(Self {
            encoded: bytes,
            algorithm,
        })
    }
}

pub(crate) fn encrypt_payload(
    plaintext: &(impl Encodable + ?Sized),
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<EncryptedRecord, EncryptionError> {
    match encryption {
        EncryptionConfig::None => Err(EncryptionError::EncodingFailed(
            "cannot encrypt with 'alg=none'".to_owned(),
        )),
        EncryptionConfig::Aegis256(key) => encrypt_payload_with_algorithm(
            plaintext,
            EncryptionAlgorithm::Aegis256,
            key.secret(),
            aad,
        ),
        EncryptionConfig::Aes256Gcm(key) => encrypt_payload_with_algorithm(
            plaintext,
            EncryptionAlgorithm::Aes256Gcm,
            key.secret(),
            aad,
        ),
    }
}

pub(crate) fn decrypt_payload(
    record: &EncryptedRecord,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<Bytes, EncryptionError> {
    match (encryption, record.algorithm()) {
        (EncryptionConfig::None, _) => Err(EncryptionError::UnexpectedEncryptedRecord),
        (EncryptionConfig::Aegis256(key), EncryptionAlgorithm::Aegis256) => {
            let nonce: &[u8; 32] = record.nonce().try_into().unwrap();
            let tag: &[u8; 16] = record.tag().try_into().unwrap();

            let plaintext = Aegis256::<16>::new(key.secret(), nonce)
                .decrypt(record.ciphertext(), tag, aad)
                .map_err(|_| EncryptionError::DecryptionFailed)?;
            Ok(Bytes::from(plaintext))
        }
        (EncryptionConfig::Aes256Gcm(key), EncryptionAlgorithm::Aes256Gcm) => {
            let cipher = Aes256Gcm::new_from_slice(key.secret()).map_err(|_| {
                EncryptionError::EncodingFailed("invalid AES key length".to_owned())
            })?;
            let nonce_generic = aes_gcm::Nonce::from_slice(record.nonce());
            let plaintext = cipher
                .decrypt(
                    nonce_generic,
                    Payload {
                        msg: record.ciphertext_and_tag(),
                        aad,
                    },
                )
                .map_err(|_| EncryptionError::DecryptionFailed)?;
            Ok(Bytes::from(plaintext))
        }
        (EncryptionConfig::Aegis256(_), actual) => Err(EncryptionError::AlgorithmMismatch {
            expected: EncryptionAlgorithm::Aegis256,
            actual,
        }),
        (EncryptionConfig::Aes256Gcm(_), actual) => Err(EncryptionError::AlgorithmMismatch {
            expected: EncryptionAlgorithm::Aes256Gcm,
            actual,
        }),
    }
}

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
                    let encrypted = encrypt_payload(&envelope, encryption, aad)?;
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
    let records: Result<Vec<_>, _> = batch
        .records
        .into_inner()
        .into_iter()
        .map(|sr| -> Result<_, EncryptionError> {
            match sr.record {
                StoredRecord::Plaintext(record) => Ok(Sequenced {
                    position: sr.position,
                    record,
                }),
                StoredRecord::Encrypted {
                    record: encrypted, ..
                } => {
                    let plaintext = decrypt_payload(&encrypted, encryption, aad)?;
                    let envelope = EnvelopeRecord::try_from(plaintext)
                        .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))?;
                    Ok(Sequenced {
                        position: sr.position,
                        record: Record::Envelope(envelope),
                    })
                }
            }
        })
        .collect();
    let records = records?;

    Ok(types::stream::ReadBatch {
        records: Metered::from(records),
        tail: batch.tail,
    })
}

fn encrypt_payload_with_algorithm(
    plaintext: &(impl Encodable + ?Sized),
    alg: EncryptionAlgorithm,
    key: &[u8; 32],
    aad: &[u8],
) -> Result<EncryptedRecord, EncryptionError> {
    let payload_start = SUITE_ID_LEN + alg.nonce_len();
    let mut bytes =
        BytesMut::with_capacity(payload_start + plaintext.encoded_size() + alg.tag_len());
    bytes.put_u8(alg.suite_id());
    alg.put_random_nonce(&mut bytes);
    plaintext.encode_into(&mut bytes);

    let (prefix, payload) = bytes.split_at_mut(payload_start);
    let nonce = &prefix[SUITE_ID_LEN..];

    match alg {
        EncryptionAlgorithm::Aegis256 => {
            let nonce: &[u8; 32] = nonce.try_into().unwrap();
            let tag = Aegis256::<16>::new(key, nonce).encrypt_in_place(payload, aad);
            bytes.put_slice(tag.as_ref());
        }
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
                EncryptionError::EncodingFailed("invalid AES key length".to_owned())
            })?;
            let nonce_generic = aes_gcm::Nonce::from_slice(nonce);
            let tag = cipher
                .encrypt_in_place_detached(nonce_generic, aad, payload)
                .map_err(|_| {
                    EncryptionError::EncodingFailed("AES-256-GCM encryption failed".to_owned())
                })?;
            bytes.put_slice(tag.as_ref());
        }
    }

    EncryptedRecord::try_from(bytes.freeze())
        .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::record::{Header, StreamPosition};

    fn aegis256_encryption() -> EncryptionConfig {
        EncryptionConfig::aegis256([0x42u8; 32])
    }

    fn aes256gcm_encryption() -> EncryptionConfig {
        EncryptionConfig::aes256_gcm([0x42u8; 32])
    }

    fn other_aegis256_encryption() -> EncryptionConfig {
        EncryptionConfig::aegis256([0x99u8; 32])
    }

    fn other_aes256gcm_encryption() -> EncryptionConfig {
        EncryptionConfig::aes256_gcm([0x99u8; 32])
    }

    fn aad() -> [u8; 32] {
        [0xA5; 32]
    }

    fn make_envelope(headers: Vec<Header>, body: Bytes) -> EnvelopeRecord {
        EnvelopeRecord::try_from_parts(headers, body).unwrap()
    }

    fn make_plaintext_envelope(headers: Vec<Header>, body: Bytes) -> Record {
        Record::Envelope(make_envelope(headers, body))
    }

    fn make_encrypted_stored_record(
        encryption: &EncryptionConfig,
        headers: Vec<Header>,
        body: Bytes,
        aad: &[u8],
    ) -> StoredRecord {
        let metered_size = make_plaintext_envelope(headers.clone(), body.clone()).metered_size();
        let plaintext = make_envelope(headers, body);
        let encrypted = encrypt_payload(&plaintext, encryption, aad).unwrap();
        StoredRecord::encrypted(encrypted, metered_size)
    }

    fn make_stored_read_batch(records: Vec<StoredRecord>) -> StoredReadBatch {
        let records: Vec<_> = records
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
            .collect();
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
            .collect()
    }

    fn roundtrip(alg: EncryptionAlgorithm) {
        let headers = vec![Header {
            name: Bytes::from_static(b"x-test"),
            value: Bytes::from_static(b"hello"),
        }];
        let body = Bytes::from_static(b"secret payload");

        let aad = aad();
        let plaintext = make_envelope(headers.clone(), body.clone());
        let encryption = match alg {
            EncryptionAlgorithm::Aegis256 => aegis256_encryption(),
            EncryptionAlgorithm::Aes256Gcm => aes256gcm_encryption(),
        };
        let ciphertext = encrypt_payload(&plaintext, &encryption, &aad).unwrap();
        let decrypted = decrypt_payload(&ciphertext, &encryption, &aad).unwrap();
        let (out_headers, out_body) = EnvelopeRecord::try_from(decrypted).unwrap().into_parts();

        assert_eq!(out_headers, headers);
        assert_eq!(out_body, body);
    }

    #[test]
    fn roundtrip_aegis256() {
        roundtrip(EncryptionAlgorithm::Aegis256);
    }

    #[test]
    fn roundtrip_aes256gcm() {
        roundtrip(EncryptionAlgorithm::Aes256Gcm);
    }

    #[test]
    fn wrong_key_fails_aegis256() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let encryption = aegis256_encryption();
        let ciphertext = encrypt_payload(&plaintext, &encryption, &aad).unwrap();
        let result = decrypt_payload(&ciphertext, &other_aegis256_encryption(), &aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn wrong_key_fails_aes256gcm() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let encryption = aes256gcm_encryption();
        let ciphertext = encrypt_payload(&plaintext, &encryption, &aad).unwrap();
        let result = decrypt_payload(&ciphertext, &other_aes256gcm_encryption(), &aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn truncated_ciphertext_fails_no_panic() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let encryption = aegis256_encryption();
        let ciphertext = encrypt_payload(&plaintext, &encryption, &aad).unwrap();
        let truncated = ciphertext.to_bytes().slice(..4);
        let result = EncryptedRecord::try_from(truncated);
        assert!(matches!(result, Err(EncryptedRecordError::Truncated)));
    }

    #[test]
    fn invalid_suite_id_fails() {
        let body = Bytes::from_static(b"\xFFsome opaque bytes");
        let result = EncryptedRecord::try_from(body);
        assert!(matches!(
            result,
            Err(EncryptedRecordError::InvalidSuiteId(0xFF))
        ));
    }

    #[test]
    fn empty_body_fails() {
        let result = EncryptedRecord::try_from(Bytes::new());
        assert!(matches!(result, Err(EncryptedRecordError::Truncated)));
    }

    #[test]
    fn suite_id_byte_present() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let ciphertext = encrypt_payload(&plaintext, &aegis256_encryption(), &aad).unwrap();
        let encoded = ciphertext.to_bytes();
        assert_eq!(ciphertext.algorithm(), EncryptionAlgorithm::Aegis256);
        assert_eq!(encoded[0], 0x01);
    }

    #[test]
    fn suite_id_flip_detected() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let mut ciphertext = encrypt_payload(&plaintext, &aegis256_encryption(), &aad)
            .unwrap()
            .to_bytes()
            .to_vec();
        assert_eq!(ciphertext[0], 0x01);
        ciphertext[0] = 0x02;
        let ciphertext = EncryptedRecord::try_from(Bytes::from(ciphertext)).unwrap();
        let result = decrypt_payload(&ciphertext, &aegis256_encryption(), &aad);
        assert!(matches!(
            result,
            Err(EncryptionError::AlgorithmMismatch {
                expected: EncryptionAlgorithm::Aegis256,
                actual: EncryptionAlgorithm::Aes256Gcm,
            })
        ));
    }

    #[test]
    fn invalid_suite_flip_detected() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let mut ciphertext = encrypt_payload(&plaintext, &aegis256_encryption(), &aad)
            .unwrap()
            .to_bytes()
            .to_vec();
        ciphertext[0] = 0xFF;
        let result = EncryptedRecord::try_from(Bytes::from(ciphertext));
        assert!(matches!(
            result,
            Err(EncryptedRecordError::InvalidSuiteId(0xFF))
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let aad = aad();
        let other_aad = [0x5A; 32];
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let ciphertext = encrypt_payload(&plaintext, &aegis256_encryption(), &aad).unwrap();
        let result = decrypt_payload(&ciphertext, &aegis256_encryption(), &other_aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn roundtrip_aes256gcm_record() {
        let record = EncryptedRecord::try_from_parts(
            EncryptionAlgorithm::Aes256Gcm,
            Bytes::from_static(b"0123456789ab"),
            Bytes::from_static(b"ciphertext"),
            Bytes::from_static(b"0123456789abcdef"),
        )
        .unwrap();

        let bytes = record.to_bytes();
        let decoded = EncryptedRecord::try_from(bytes).unwrap();

        assert_eq!(decoded, record);
        assert_eq!(decoded.encoded[0], SUITE_ID_AES256GCM_V1);
        assert_eq!(decoded.nonce(), b"0123456789ab");
        assert_eq!(decoded.ciphertext(), b"ciphertext");
        assert_eq!(decoded.ciphertext_and_tag(), b"ciphertext0123456789abcdef");
        assert_eq!(decoded.tag(), b"0123456789abcdef");
    }

    #[test]
    fn rejects_invalid_suite_id() {
        let err = EncryptedRecord::try_from(Bytes::from_static(b"\xFFpayload")).unwrap_err();
        assert_eq!(err, EncryptedRecordError::InvalidSuiteId(0xFF));
    }

    #[test]
    fn rejects_truncated_layout() {
        let err = EncryptedRecord::try_from(Bytes::from_static(b"\x01tiny")).unwrap_err();
        assert_eq!(err, EncryptedRecordError::Truncated);
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
