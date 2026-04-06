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
use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInPlace};
use bytes::{BufMut, Bytes, BytesMut};
use rand::random;

use super::{
    Encodable, EnvelopeRecord, Metered, MeteredSize, Record, SequencedRecord, StoredRecord,
    StoredSequencedRecord,
};
use crate::{
    deep_size::DeepSize,
    encryption::{EncryptionAlgorithm, EncryptionConfig},
    record::Sequenced,
    types::stream::{
        AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts, ReadBatch, StoredReadBatch,
    },
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Encryption failed")]
pub struct RecordEncryptionError;

#[derive(Debug, Clone, thiserror::Error)]
pub enum RecordDecryptionError {
    #[error("Ciphertext algorithm mismatch: expected {expected}, actual {actual}")]
    AlgorithmMismatch {
        expected: EncryptionAlgorithm,
        actual: EncryptionAlgorithm,
    },
    #[error("Encrypted record encountered without decryption")]
    UnexpectedEncryptedRecord,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid decrypted record: {0}")]
    InvalidDecryptedRecord(String),
}

#[derive(PartialEq, Eq, Clone)]
pub struct EncryptedRecord {
    encoded: Bytes,
    algorithm: EncryptionAlgorithm,
}

impl EncryptedRecord {
    fn new(encoded: Bytes, algorithm: EncryptionAlgorithm) -> Self {
        debug_assert!(!encoded.is_empty());
        debug_assert_eq!(encoded[0], algorithm.suite_id());
        debug_assert!(encoded.len() >= SUITE_ID_LEN + algorithm.nonce_len() + algorithm.tag_len());
        Self { encoded, algorithm }
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

    #[cfg(test)]
    pub(crate) fn ciphertext_and_tag(&self) -> &[u8] {
        let start = SUITE_ID_LEN + self.algorithm.nonce_len();
        &self.encoded[start..]
    }

    pub(crate) fn tag(&self) -> &[u8] {
        let start = self.encoded.len() - self.algorithm.tag_len();
        let end = self.encoded.len();
        &self.encoded[start..end]
    }

    fn into_mut_encoded(self) -> BytesMut {
        self.encoded
            .try_into_mut()
            .unwrap_or_else(|encoded| BytesMut::from(encoded.as_ref()))
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

    fn try_from(encoded: Bytes) -> Result<Self, Self::Error> {
        if encoded.len() < SUITE_ID_LEN {
            return Err(EncryptedRecordError::Truncated);
        }

        let algorithm = EncryptionAlgorithm::try_from_suite_id(encoded[0])?;
        let nonce_len = algorithm.nonce_len();
        let tag_len = algorithm.tag_len();
        if encoded.len() < SUITE_ID_LEN + nonce_len + tag_len {
            return Err(EncryptedRecordError::Truncated);
        }

        Ok(Self::new(encoded, algorithm))
    }
}

fn payload_end(
    encoded_len: usize,
    payload_start: usize,
    tag_len: usize,
) -> Result<usize, RecordDecryptionError> {
    let payload_end = encoded_len
        .checked_sub(tag_len)
        .ok_or(RecordDecryptionError::DecryptionFailed)?;
    if payload_start > payload_end {
        return Err(RecordDecryptionError::DecryptionFailed);
    }
    Ok(payload_end)
}

pub(crate) fn decrypt_payload(
    record: EncryptedRecord,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<Bytes, RecordDecryptionError> {
    let algorithm = record.algorithm();
    match (encryption, algorithm) {
        (EncryptionConfig::Plain, _) => Err(RecordDecryptionError::UnexpectedEncryptedRecord),
        (EncryptionConfig::Aegis256(key), EncryptionAlgorithm::Aegis256) => {
            let payload_start = SUITE_ID_LEN + algorithm.nonce_len();
            let tag_len = algorithm.tag_len();
            let mut encoded = record.into_mut_encoded();
            let payload_end = payload_end(encoded.len(), payload_start, tag_len)?;
            let plaintext_len = payload_end - payload_start;
            let nonce: [u8; 32] = encoded
                .get(SUITE_ID_LEN..payload_start)
                .ok_or(RecordDecryptionError::DecryptionFailed)?
                .try_into()
                .map_err(|_| RecordDecryptionError::DecryptionFailed)?;
            let tag: [u8; 16] = encoded
                .get(payload_end..)
                .ok_or(RecordDecryptionError::DecryptionFailed)?
                .try_into()
                .map_err(|_| RecordDecryptionError::DecryptionFailed)?;
            let ciphertext = encoded
                .get_mut(payload_start..payload_end)
                .ok_or(RecordDecryptionError::DecryptionFailed)?;

            Aegis256::<16>::new(key.secret(), &nonce)
                .decrypt_in_place(ciphertext, &tag, aad)
                .map_err(|_| RecordDecryptionError::DecryptionFailed)?;
            let _ = encoded.split_to(payload_start);
            encoded.truncate(plaintext_len);
            Ok(encoded.freeze())
        }
        (EncryptionConfig::Aes256Gcm(key), EncryptionAlgorithm::Aes256Gcm) => {
            let payload_start = SUITE_ID_LEN + algorithm.nonce_len();
            let tag_len = algorithm.tag_len();
            let mut encoded = record.into_mut_encoded();
            let payload_end = payload_end(encoded.len(), payload_start, tag_len)?;
            let plaintext_len = payload_end - payload_start;
            let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key.secret()));
            let nonce = aes_gcm::Nonce::clone_from_slice(
                encoded
                    .get(SUITE_ID_LEN..payload_start)
                    .ok_or(RecordDecryptionError::DecryptionFailed)?,
            );
            let tag = aes_gcm::Tag::clone_from_slice(
                encoded
                    .get(payload_end..)
                    .ok_or(RecordDecryptionError::DecryptionFailed)?,
            );
            let ciphertext = encoded
                .get_mut(payload_start..payload_end)
                .ok_or(RecordDecryptionError::DecryptionFailed)?;
            cipher
                .decrypt_in_place_detached(&nonce, aad, ciphertext, &tag)
                .map_err(|_| RecordDecryptionError::DecryptionFailed)?;
            let _ = encoded.split_to(payload_start);
            encoded.truncate(plaintext_len);
            Ok(encoded.freeze())
        }
        (EncryptionConfig::Aegis256(_), actual) => Err(RecordDecryptionError::AlgorithmMismatch {
            expected: EncryptionAlgorithm::Aegis256,
            actual,
        }),
        (EncryptionConfig::Aes256Gcm(_), actual) => Err(RecordDecryptionError::AlgorithmMismatch {
            expected: EncryptionAlgorithm::Aes256Gcm,
            actual,
        }),
    }
}

pub fn decode_stored_record(
    record: StoredRecord,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<Metered<Record>, RecordDecryptionError> {
    match record {
        StoredRecord::Plaintext(record) => Ok(record.into()),
        StoredRecord::Encrypted {
            metered_size,
            record: encrypted,
        } => {
            let plaintext = decrypt_payload(encrypted, encryption, aad)?;
            let envelope = EnvelopeRecord::try_from(plaintext)
                .map_err(|e| RecordDecryptionError::InvalidDecryptedRecord(e.to_string()))?;
            let record = Record::Envelope(envelope);
            let actual_metered_size = record.metered_size();
            if metered_size != actual_metered_size {
                return Err(RecordDecryptionError::InvalidDecryptedRecord(format!(
                    "metered size mismatch: stored {metered_size}, actual {actual_metered_size}"
                )));
            }
            Ok(Metered {
                size: metered_size,
                inner: record,
            })
        }
    }
}

pub fn decode_stored_sequenced_record(
    Sequenced { position, record }: StoredSequencedRecord,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<Metered<SequencedRecord>, RecordDecryptionError> {
    Ok(decode_stored_record(record, encryption, aad)?.sequenced(position))
}

pub fn to_stored_records(
    records: Vec<Metered<SequencedRecord>>,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<Vec<Metered<StoredSequencedRecord>>, RecordEncryptionError> {
    records
        .into_iter()
        .map(|record| {
            let (position, record) = record.into_parts();
            let metered_size = record.metered_size();
            let stored = match (record.into_inner(), encryption) {
                (record @ Record::Command(_), _) => StoredRecord::Plaintext(record),
                (record @ Record::Envelope(_), EncryptionConfig::Plain) => {
                    StoredRecord::Plaintext(record)
                }
                (Record::Envelope(envelope), EncryptionConfig::Aegis256(key)) => {
                    let encrypted = encrypt_payload_with_algorithm(
                        &envelope,
                        EncryptionAlgorithm::Aegis256,
                        key.secret(),
                        aad,
                    )?;
                    StoredRecord::encrypted(encrypted, metered_size)
                }
                (Record::Envelope(envelope), EncryptionConfig::Aes256Gcm(key)) => {
                    let encrypted = encrypt_payload_with_algorithm(
                        &envelope,
                        EncryptionAlgorithm::Aes256Gcm,
                        key.secret(),
                        aad,
                    )?;
                    StoredRecord::encrypted(encrypted, metered_size)
                }
            };
            Ok(Metered::from(stored).sequenced(position))
        })
        .collect()
}

fn encrypt_append_record(
    record: AppendRecord,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<AppendRecord, RecordEncryptionError> {
    let AppendRecordParts { timestamp, record } = record.into();
    let metered_size = record.metered_size();
    let record = match (record.into_inner(), encryption) {
        (record @ StoredRecord::Encrypted { .. }, _) => record,
        (record @ StoredRecord::Plaintext(Record::Command(_)), _) => record,
        (record @ StoredRecord::Plaintext(Record::Envelope(_)), EncryptionConfig::Plain) => record,
        (StoredRecord::Plaintext(Record::Envelope(envelope)), EncryptionConfig::Aegis256(key)) => {
            let encrypted = encrypt_payload_with_algorithm(
                &envelope,
                EncryptionAlgorithm::Aegis256,
                key.secret(),
                aad,
            )?;
            StoredRecord::encrypted(encrypted, metered_size)
        }
        (StoredRecord::Plaintext(Record::Envelope(envelope)), EncryptionConfig::Aes256Gcm(key)) => {
            let encrypted = encrypt_payload_with_algorithm(
                &envelope,
                EncryptionAlgorithm::Aes256Gcm,
                key.secret(),
                aad,
            )?;
            StoredRecord::encrypted(encrypted, metered_size)
        }
    };

    AppendRecord::try_from(AppendRecordParts {
        timestamp,
        record: Metered {
            size: metered_size,
            inner: record,
        },
    })
    .map_err(|_| RecordEncryptionError)
}

pub fn encrypt_append_input(
    input: AppendInput,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<AppendInput, RecordEncryptionError> {
    let records = input
        .records
        .into_iter()
        .map(|record| encrypt_append_record(record, encryption, aad))
        .collect::<Result<Vec<_>, _>>()?;
    let records = AppendRecordBatch::try_from(records).map_err(|_| RecordEncryptionError)?;

    Ok(AppendInput {
        records,
        match_seq_num: input.match_seq_num,
        fencing_token: input.fencing_token,
    })
}

pub fn decrypt_read_batch(
    batch: StoredReadBatch,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<ReadBatch, RecordDecryptionError> {
    let records: Result<Metered<Vec<SequencedRecord>>, _> = batch
        .records
        .into_inner()
        .into_iter()
        .map(|record| decode_stored_sequenced_record(record, encryption, aad))
        .collect();
    let records = records?;

    Ok(ReadBatch {
        records,
        tail: batch.tail,
    })
}

fn encrypt_payload_with_algorithm(
    plaintext: &(impl Encodable + ?Sized),
    alg: EncryptionAlgorithm,
    key: &[u8; 32],
    aad: &[u8],
) -> Result<EncryptedRecord, RecordEncryptionError> {
    let payload_start = SUITE_ID_LEN + alg.nonce_len();
    let mut encoded =
        BytesMut::with_capacity(payload_start + plaintext.encoded_size() + alg.tag_len());
    encoded.put_u8(alg.suite_id());
    alg.put_random_nonce(&mut encoded);
    plaintext.encode_into(&mut encoded);

    let (prefix, payload) = encoded.split_at_mut(payload_start);
    let nonce = &prefix[SUITE_ID_LEN..];

    match alg {
        EncryptionAlgorithm::Aegis256 => {
            let nonce: [u8; 32] = nonce.try_into().map_err(|_| RecordEncryptionError)?;
            let tag = Aegis256::<16>::new(key, &nonce).encrypt_in_place(payload, aad);
            encoded.put_slice(tag.as_ref());
        }
        EncryptionAlgorithm::Aes256Gcm => {
            let nonce = aes_gcm::Nonce::from_slice(nonce);
            let tag = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key))
                .encrypt_in_place_detached(nonce, aad, payload)
                .map_err(|_| RecordEncryptionError)?;
            encoded.put_slice(tag.as_ref());
        }
    }

    Ok(EncryptedRecord::new(encoded.freeze(), alg))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::record::{Header, StreamPosition};

    const TEST_KEY: [u8; 32] = [0x42; 32];
    const OTHER_TEST_KEY: [u8; 32] = [0x99; 32];

    fn test_encryption(alg: EncryptionAlgorithm) -> EncryptionConfig {
        match alg {
            EncryptionAlgorithm::Aegis256 => EncryptionConfig::aegis256(TEST_KEY),
            EncryptionAlgorithm::Aes256Gcm => EncryptionConfig::aes256_gcm(TEST_KEY),
        }
    }

    fn other_test_encryption(alg: EncryptionAlgorithm) -> EncryptionConfig {
        match alg {
            EncryptionAlgorithm::Aegis256 => EncryptionConfig::aegis256(OTHER_TEST_KEY),
            EncryptionAlgorithm::Aes256Gcm => EncryptionConfig::aes256_gcm(OTHER_TEST_KEY),
        }
    }

    fn encrypt_test_payload(
        plaintext: &(impl Encodable + ?Sized),
        alg: EncryptionAlgorithm,
        aad: &[u8],
    ) -> EncryptedRecord {
        encrypt_payload_with_algorithm(plaintext, alg, &TEST_KEY, aad).unwrap()
    }

    fn make_encrypted_record(
        algorithm: EncryptionAlgorithm,
        nonce: impl AsRef<[u8]>,
        ciphertext: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
    ) -> EncryptedRecord {
        let nonce = nonce.as_ref();
        let ciphertext = ciphertext.as_ref();
        let tag = tag.as_ref();

        assert_eq!(nonce.len(), algorithm.nonce_len());
        assert_eq!(tag.len(), algorithm.tag_len());

        let mut encoded =
            BytesMut::with_capacity(SUITE_ID_LEN + nonce.len() + ciphertext.len() + tag.len());
        encoded.put_u8(algorithm.suite_id());
        encoded.put_slice(nonce);
        encoded.put_slice(ciphertext);
        encoded.put_slice(tag);

        EncryptedRecord::new(encoded.freeze(), algorithm)
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
        let encrypted = match encryption {
            EncryptionConfig::Plain => {
                unreachable!("plain encryption should not produce ciphertext")
            }
            EncryptionConfig::Aegis256(key) => encrypt_payload_with_algorithm(
                &plaintext,
                EncryptionAlgorithm::Aegis256,
                key.secret(),
                aad,
            )
            .unwrap(),
            EncryptionConfig::Aes256Gcm(key) => encrypt_payload_with_algorithm(
                &plaintext,
                EncryptionAlgorithm::Aes256Gcm,
                key.secret(),
                aad,
            )
            .unwrap(),
        };
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
                Metered::<Record>::from(record).sequenced(StreamPosition {
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
        let encryption = test_encryption(alg);
        let ciphertext = encrypt_test_payload(&plaintext, alg, &aad);
        let decrypted = decrypt_payload(ciphertext, &encryption, &aad).unwrap();
        let (out_headers, out_body) = EnvelopeRecord::try_from(decrypted).unwrap().into_parts();

        assert_eq!(out_headers, headers);
        assert_eq!(out_body, body);
    }

    fn roundtrip_shared_ciphertext_buffer(alg: EncryptionAlgorithm) {
        let headers = vec![Header {
            name: Bytes::from_static(b"x-test"),
            value: Bytes::from_static(b"hello"),
        }];
        let body = Bytes::from_static(b"secret payload");

        let aad = aad();
        let plaintext = make_envelope(headers.clone(), body.clone());
        let encryption = test_encryption(alg);
        let ciphertext = encrypt_test_payload(&plaintext, alg, &aad);
        let shared = ciphertext.encoded.clone();
        let ciphertext = EncryptedRecord::try_from(shared.clone()).unwrap();
        let decrypted = decrypt_payload(ciphertext, &encryption, &aad).unwrap();
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
    fn roundtrip_aegis256_with_shared_ciphertext_buffer() {
        roundtrip_shared_ciphertext_buffer(EncryptionAlgorithm::Aegis256);
    }

    #[test]
    fn roundtrip_aes256gcm_with_shared_ciphertext_buffer() {
        roundtrip_shared_ciphertext_buffer(EncryptionAlgorithm::Aes256Gcm);
    }

    #[test]
    fn wrong_key_fails_aegis256() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let ciphertext = encrypt_test_payload(&plaintext, EncryptionAlgorithm::Aegis256, &aad);
        let result = decrypt_payload(
            ciphertext,
            &other_test_encryption(EncryptionAlgorithm::Aegis256),
            &aad,
        );
        assert!(matches!(
            result,
            Err(RecordDecryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_key_fails_aes256gcm() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let ciphertext = encrypt_test_payload(&plaintext, EncryptionAlgorithm::Aes256Gcm, &aad);
        let result = decrypt_payload(
            ciphertext,
            &other_test_encryption(EncryptionAlgorithm::Aes256Gcm),
            &aad,
        );
        assert!(matches!(
            result,
            Err(RecordDecryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn truncated_ciphertext_fails_no_panic() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let ciphertext = encrypt_test_payload(&plaintext, EncryptionAlgorithm::Aegis256, &aad);
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
        let ciphertext = encrypt_test_payload(&plaintext, EncryptionAlgorithm::Aegis256, &aad);
        let encoded = ciphertext.to_bytes();
        assert_eq!(ciphertext.algorithm(), EncryptionAlgorithm::Aegis256);
        assert_eq!(encoded[0], 0x01);
    }

    #[test]
    fn suite_id_flip_detected() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let mut ciphertext = encrypt_test_payload(&plaintext, EncryptionAlgorithm::Aegis256, &aad)
            .to_bytes()
            .to_vec();
        assert_eq!(ciphertext[0], 0x01);
        ciphertext[0] = 0x02;
        let ciphertext = EncryptedRecord::try_from(Bytes::from(ciphertext)).unwrap();
        let result = decrypt_payload(
            ciphertext,
            &test_encryption(EncryptionAlgorithm::Aegis256),
            &aad,
        );
        assert!(matches!(
            result,
            Err(RecordDecryptionError::AlgorithmMismatch {
                expected: EncryptionAlgorithm::Aegis256,
                actual: EncryptionAlgorithm::Aes256Gcm,
            })
        ));
    }

    #[test]
    fn invalid_suite_flip_detected() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let mut ciphertext = encrypt_test_payload(&plaintext, EncryptionAlgorithm::Aegis256, &aad)
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
        let ciphertext = encrypt_test_payload(&plaintext, EncryptionAlgorithm::Aegis256, &aad);
        let result = decrypt_payload(
            ciphertext,
            &test_encryption(EncryptionAlgorithm::Aegis256),
            &other_aad,
        );
        assert!(matches!(
            result,
            Err(RecordDecryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn malformed_encrypted_record_layout_returns_error_instead_of_panicking() {
        let aad = aad();
        let record = EncryptedRecord {
            encoded: Bytes::from_static(b"\x01short"),
            algorithm: EncryptionAlgorithm::Aegis256,
        };

        let result = decrypt_payload(
            record,
            &test_encryption(EncryptionAlgorithm::Aegis256),
            &aad,
        );

        assert!(matches!(
            result,
            Err(RecordDecryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn roundtrip_aes256gcm_record() {
        let record = make_encrypted_record(
            EncryptionAlgorithm::Aes256Gcm,
            Bytes::from_static(b"0123456789ab"),
            Bytes::from_static(b"ciphertext"),
            Bytes::from_static(b"0123456789abcdef"),
        );

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

        let encrypted =
            to_stored_records(input, &test_encryption(EncryptionAlgorithm::Aegis256), &aad)
                .unwrap();
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
                &test_encryption(EncryptionAlgorithm::Aegis256),
                vec![Header {
                    name: Bytes::from_static(b"x-test"),
                    value: Bytes::from_static(b"hello"),
                }],
                Bytes::from_static(b"secret payload"),
                &aad,
            ),
        ]);

        let decrypted =
            decrypt_read_batch(batch, &test_encryption(EncryptionAlgorithm::Aegis256), &aad)
                .unwrap();
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
    fn decrypt_read_batch_plain_rejects_encrypted_records() {
        let aad = aad();
        let batch = make_stored_read_batch(vec![make_encrypted_stored_record(
            &test_encryption(EncryptionAlgorithm::Aegis256),
            vec![],
            Bytes::from_static(b"secret payload"),
            &aad,
        )]);

        let result = decrypt_read_batch(batch, &EncryptionConfig::Plain, &aad);

        assert!(matches!(
            result,
            Err(RecordDecryptionError::UnexpectedEncryptedRecord)
        ));
    }

    #[test]
    fn decode_stored_record_rejects_encrypted_metered_size_mismatch() {
        let aad = aad();
        let stored = make_encrypted_stored_record(
            &test_encryption(EncryptionAlgorithm::Aegis256),
            vec![Header {
                name: Bytes::from_static(b"x-test"),
                value: Bytes::from_static(b"hello"),
            }],
            Bytes::from_static(b"secret payload"),
            &aad,
        );
        let StoredRecord::Encrypted {
            metered_size,
            record,
        } = stored
        else {
            panic!("expected encrypted stored record");
        };

        let result = decode_stored_record(
            StoredRecord::encrypted(record, metered_size + 1),
            &test_encryption(EncryptionAlgorithm::Aegis256),
            &aad,
        );

        assert!(matches!(
            result,
            Err(RecordDecryptionError::InvalidDecryptedRecord(message))
                if message == format!(
                    "metered size mismatch: stored {}, actual {}",
                    metered_size + 1,
                    metered_size
                )
        ));
    }
}
