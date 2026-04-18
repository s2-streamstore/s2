//! Encrypted record storage, wire format, and raw cryptography.
//!
//! ```text
//! [format_id: 1 byte] [nonce] [ciphertext] [tag]
//! ```
//!
//! | format_id | Format         | Nonce  | Tag  |
//! |-----------|----------------|--------|------|
//! | 0x01      | AEGIS-256 v1   | 32 B   | 16 B |
//! | 0x02      | AES-256-GCM v1 | 12 B   | 16 B |
//!
//! The leading format byte identifies the full encrypted record framing,
//! including the framing version and encryption algorithm. This leaves room for
//! future layout changes without a separate version byte.
//!
//! AAD is caller-supplied associated data and is not stored in the encoded
//! record.
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
//! than the encoded encrypted record size, so protection does not change
//! append/read metering, limits, or accounting.

use aegis::aegis256::Aegis256;
use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInPlace};
use bytes::{BufMut, Bytes, BytesMut};
use rand::random;

use super::{Encodable, Metered, MeteredSize, Record, RecordDecodeError, StoredRecord};
use crate::{
    deep_size::DeepSize,
    encryption::{EncryptionAlgorithm, EncryptionSpec},
    record::MeteredExt as _,
};

const FORMAT_ID_LEN: usize = 1;

const FORMAT_ID_AEGIS256_V1: u8 = 0x01;
const FORMAT_ID_AES256GCM_V1: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncryptedRecordFormat {
    Aegis256V1,
    Aes256GcmV1,
}

impl EncryptedRecordFormat {
    const fn try_from_format_id(format_id: u8) -> Result<Self, RecordDecodeError> {
        match format_id {
            FORMAT_ID_AEGIS256_V1 => Ok(Self::Aegis256V1),
            FORMAT_ID_AES256GCM_V1 => Ok(Self::Aes256GcmV1),
            _ => Err(RecordDecodeError::InvalidValue(
                "EncryptedRecord",
                "invalid encrypted record format id",
            )),
        }
    }

    const fn format_id(self) -> u8 {
        match self {
            Self::Aegis256V1 => FORMAT_ID_AEGIS256_V1,
            Self::Aes256GcmV1 => FORMAT_ID_AES256GCM_V1,
        }
    }

    const fn algorithm(self) -> EncryptionAlgorithm {
        match self {
            Self::Aegis256V1 => EncryptionAlgorithm::Aegis256,
            Self::Aes256GcmV1 => EncryptionAlgorithm::Aes256Gcm,
        }
    }

    const fn nonce_len(self) -> usize {
        match self {
            Self::Aegis256V1 => 32,
            Self::Aes256GcmV1 => 12,
        }
    }

    const fn tag_len(self) -> usize {
        match self {
            Self::Aegis256V1 => 16,
            Self::Aes256GcmV1 => 16,
        }
    }

    fn put_random_nonce(self, buf: &mut impl BufMut) {
        match self {
            Self::Aegis256V1 => buf.put_slice(&random::<[u8; 32]>()),
            Self::Aes256GcmV1 => buf.put_slice(&random::<[u8; 12]>()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordDecryptionError {
    #[error("record encryption algorithm mismatch")]
    AlgorithmMismatch {
        expected: Option<EncryptionAlgorithm>,
        actual: Option<EncryptionAlgorithm>,
    },
    #[error("record decryption failed")]
    AuthenticationFailed,
    #[error("malformed encrypted record")]
    MalformedEncryptedRecord,
    #[error("decrypted record metered size mismatch: stored {stored}, actual {actual}")]
    MeteredSizeMismatch { stored: usize, actual: usize },
    #[error("malformed decrypted record: {0}")]
    MalformedDecryptedRecord(#[from] RecordDecodeError),
}

#[derive(PartialEq, Eq, Clone)]
pub struct EncryptedRecord {
    encoded: Bytes,
    format: EncryptedRecordFormat,
}

impl EncryptedRecord {
    fn new(encoded: Bytes, format: EncryptedRecordFormat) -> Self {
        debug_assert!(!encoded.is_empty());
        debug_assert_eq!(encoded[0], format.format_id());
        debug_assert!(encoded.len() >= FORMAT_ID_LEN + format.nonce_len() + format.tag_len());
        Self { encoded, format }
    }

    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.format.algorithm()
    }

    pub(crate) fn nonce(&self) -> &[u8] {
        let start = FORMAT_ID_LEN;
        let end = start + self.format.nonce_len();
        &self.encoded[start..end]
    }

    pub(crate) fn ciphertext(&self) -> &[u8] {
        let start = FORMAT_ID_LEN + self.format.nonce_len();
        let end = self.encoded.len() - self.format.tag_len();
        &self.encoded[start..end]
    }

    pub(crate) fn tag(&self) -> &[u8] {
        let start = self.encoded.len() - self.format.tag_len();
        let end = self.encoded.len();
        &self.encoded[start..end]
    }

    fn into_mut_encoded(self) -> BytesMut {
        self.encoded
            .try_into_mut()
            .unwrap_or_else(|encoded| BytesMut::from(encoded.as_ref()))
    }
}

impl std::fmt::Debug for EncryptedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedRecord")
            .field("format_id", &self.encoded[0])
            .field("format", &self.format)
            .field("algorithm", &self.format.algorithm())
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

pub fn encrypt_record(
    record: Metered<Record>,
    encryption: &EncryptionSpec,
    aad: &[u8],
) -> Metered<StoredRecord> {
    let metered_size = record.metered_size();
    let record = match (record.into_inner(), encryption) {
        (record @ Record::Command(_), _) => StoredRecord::Plaintext(record),
        (record @ Record::Envelope(_), EncryptionSpec::Plain) => StoredRecord::Plaintext(record),
        (Record::Envelope(envelope), EncryptionSpec::Aegis256(key)) => {
            let format = EncryptedRecordFormat::Aegis256V1;
            let (mut encoded, payload_start) = prep_encryption_buffer(&envelope, format);
            let (prefix, payload) = encoded.split_at_mut(payload_start);
            let nonce: &[u8; 32] = prefix[FORMAT_ID_LEN..]
                .try_into()
                .expect("AEGIS-256 nonce must be 32 bytes");
            let tag =
                Aegis256::<16>::new(key.expose_secret(), nonce).encrypt_in_place(payload, aad);
            encoded.put_slice(tag.as_ref());

            let encrypted = EncryptedRecord::new(encoded.freeze(), format);
            StoredRecord::encrypted(encrypted, metered_size)
        }
        (Record::Envelope(envelope), EncryptionSpec::Aes256Gcm(key)) => {
            let format = EncryptedRecordFormat::Aes256GcmV1;
            let (mut encoded, payload_start) = prep_encryption_buffer(&envelope, format);
            let (prefix, payload) = encoded.split_at_mut(payload_start);
            let nonce = aes_gcm::Nonce::from_slice(&prefix[FORMAT_ID_LEN..]);
            let tag = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key.expose_secret()))
                .encrypt_in_place_detached(nonce, aad, payload)
                .expect("AES-256-GCM encryption should not fail on size validation");
            encoded.put_slice(tag.as_ref());

            let encrypted = EncryptedRecord::new(encoded.freeze(), format);
            StoredRecord::encrypted(encrypted, metered_size)
        }
    };
    Metered::with_size(metered_size, record)
}

fn prep_encryption_buffer(
    envelope: &super::EnvelopeRecord,
    format: EncryptedRecordFormat,
) -> (BytesMut, usize) {
    let payload_start = FORMAT_ID_LEN + format.nonce_len();
    let mut encoded =
        BytesMut::with_capacity(payload_start + envelope.encoded_size() + format.tag_len());
    encoded.put_u8(format.format_id());
    format.put_random_nonce(&mut encoded);
    envelope.encode_into(&mut encoded);
    (encoded, payload_start)
}

impl TryFrom<Bytes> for EncryptedRecord {
    type Error = RecordDecodeError;

    fn try_from(encoded: Bytes) -> Result<Self, Self::Error> {
        if encoded.len() < FORMAT_ID_LEN {
            return Err(RecordDecodeError::Truncated("EncryptedRecordFormatId"));
        }

        let format = EncryptedRecordFormat::try_from_format_id(encoded[0])?;
        let nonce_len = format.nonce_len();
        let tag_len = format.tag_len();
        if encoded.len() < FORMAT_ID_LEN + nonce_len + tag_len {
            return Err(RecordDecodeError::Truncated("EncryptedRecordFrame"));
        }

        Ok(Self::new(encoded, format))
    }
}

pub fn decrypt_stored_record(
    record: StoredRecord,
    encryption: &EncryptionSpec,
    aad: &[u8],
) -> Result<Metered<Record>, RecordDecryptionError> {
    match record {
        StoredRecord::Plaintext(record @ Record::Command(_)) => Ok(record.metered()),
        StoredRecord::Plaintext(record @ Record::Envelope(_)) => match encryption {
            EncryptionSpec::Plain => Ok(record.metered()),
            EncryptionSpec::Aegis256(_) => Err(RecordDecryptionError::AlgorithmMismatch {
                expected: Some(EncryptionAlgorithm::Aegis256),
                actual: None,
            }),
            EncryptionSpec::Aes256Gcm(_) => Err(RecordDecryptionError::AlgorithmMismatch {
                expected: Some(EncryptionAlgorithm::Aes256Gcm),
                actual: None,
            }),
        },
        StoredRecord::Encrypted {
            metered_size,
            record: encrypted,
        } => {
            let plaintext = decrypt_payload(encrypted, encryption, aad)?;
            let record = Record::Envelope(plaintext.try_into()?);
            let actual_metered_size = record.metered_size();
            if metered_size != actual_metered_size {
                return Err(RecordDecryptionError::MeteredSizeMismatch {
                    stored: metered_size,
                    actual: actual_metered_size,
                });
            }
            Ok(Metered::with_size(metered_size, record))
        }
    }
}

fn decrypt_payload(
    record: EncryptedRecord,
    encryption: &EncryptionSpec,
    aad: &[u8],
) -> Result<Bytes, RecordDecryptionError> {
    let format = record.format;
    let (mut encoded, payload_start, payload_end) = decryption_layout(record, format)?;
    let plaintext_len = payload_end - payload_start;

    match (format, encryption) {
        (EncryptedRecordFormat::Aegis256V1, EncryptionSpec::Aegis256(key)) => {
            let (prefix, payload_and_tag) = encoded.split_at_mut(payload_start);
            let nonce: &[u8; 32] = prefix
                .get(FORMAT_ID_LEN..)
                .ok_or(RecordDecryptionError::MalformedEncryptedRecord)?
                .try_into()
                .map_err(|_| RecordDecryptionError::MalformedEncryptedRecord)?;
            let (ciphertext, tag) = payload_and_tag.split_at_mut(plaintext_len);
            let tag: &[u8; 16] = tag
                .as_ref()
                .try_into()
                .map_err(|_| RecordDecryptionError::MalformedEncryptedRecord)?;
            Aegis256::<16>::new(key.expose_secret(), nonce)
                .decrypt_in_place(ciphertext, tag, aad)
                .map_err(|_| RecordDecryptionError::AuthenticationFailed)?;
            Ok(decryption_finish(encoded, payload_start, plaintext_len))
        }
        (EncryptedRecordFormat::Aegis256V1, EncryptionSpec::Plain) => {
            Err(RecordDecryptionError::AlgorithmMismatch {
                expected: None,
                actual: Some(EncryptionAlgorithm::Aegis256),
            })
        }
        (EncryptedRecordFormat::Aegis256V1, EncryptionSpec::Aes256Gcm(_)) => {
            Err(RecordDecryptionError::AlgorithmMismatch {
                expected: Some(EncryptionAlgorithm::Aes256Gcm),
                actual: Some(EncryptionAlgorithm::Aegis256),
            })
        }
        (EncryptedRecordFormat::Aes256GcmV1, EncryptionSpec::Aes256Gcm(key)) => {
            let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key.expose_secret()));
            let (prefix, payload_and_tag) = encoded.split_at_mut(payload_start);
            let nonce: &[u8; 12] = prefix
                .get(FORMAT_ID_LEN..)
                .ok_or(RecordDecryptionError::MalformedEncryptedRecord)?
                .try_into()
                .map_err(|_| RecordDecryptionError::MalformedEncryptedRecord)?;
            let nonce = aes_gcm::Nonce::from_slice(nonce);
            let (ciphertext, tag) = payload_and_tag.split_at_mut(plaintext_len);
            let tag: &[u8; 16] = tag
                .as_ref()
                .try_into()
                .map_err(|_| RecordDecryptionError::MalformedEncryptedRecord)?;
            let tag = aes_gcm::Tag::from_slice(tag);
            cipher
                .decrypt_in_place_detached(nonce, aad, ciphertext, tag)
                .map_err(|_| RecordDecryptionError::AuthenticationFailed)?;
            Ok(decryption_finish(encoded, payload_start, plaintext_len))
        }
        (EncryptedRecordFormat::Aes256GcmV1, EncryptionSpec::Plain) => {
            Err(RecordDecryptionError::AlgorithmMismatch {
                expected: None,
                actual: Some(EncryptionAlgorithm::Aes256Gcm),
            })
        }
        (EncryptedRecordFormat::Aes256GcmV1, EncryptionSpec::Aegis256(_)) => {
            Err(RecordDecryptionError::AlgorithmMismatch {
                expected: Some(EncryptionAlgorithm::Aegis256),
                actual: Some(EncryptionAlgorithm::Aes256Gcm),
            })
        }
    }
}

fn decryption_layout(
    record: EncryptedRecord,
    format: EncryptedRecordFormat,
) -> Result<(BytesMut, usize, usize), RecordDecryptionError> {
    let payload_start = FORMAT_ID_LEN + format.nonce_len();
    let payload_end = record
        .encoded
        .len()
        .checked_sub(format.tag_len())
        .ok_or(RecordDecryptionError::MalformedEncryptedRecord)?;
    if payload_start > payload_end {
        return Err(RecordDecryptionError::MalformedEncryptedRecord);
    }
    Ok((record.into_mut_encoded(), payload_start, payload_end))
}

fn decryption_finish(mut encoded: BytesMut, payload_start: usize, plaintext_len: usize) -> Bytes {
    let _ = encoded.split_to(payload_start);
    encoded.truncate(plaintext_len);
    encoded.freeze()
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rstest::rstest;

    use super::*;
    use crate::record::{CommandRecord, EnvelopeRecord, Header, MeteredExt};

    const TEST_KEY: [u8; 32] = [0x42; 32];
    const OTHER_TEST_KEY: [u8; 32] = [0x99; 32];

    fn test_encryption(alg: EncryptionAlgorithm) -> EncryptionSpec {
        match alg {
            EncryptionAlgorithm::Aegis256 => EncryptionSpec::aegis256(TEST_KEY),
            EncryptionAlgorithm::Aes256Gcm => EncryptionSpec::aes256_gcm(TEST_KEY),
        }
    }

    fn other_test_encryption(alg: EncryptionAlgorithm) -> EncryptionSpec {
        match alg {
            EncryptionAlgorithm::Aegis256 => EncryptionSpec::aegis256(OTHER_TEST_KEY),
            EncryptionAlgorithm::Aes256Gcm => EncryptionSpec::aes256_gcm(OTHER_TEST_KEY),
        }
    }

    fn encrypt_test_record(
        plaintext: EnvelopeRecord,
        alg: EncryptionAlgorithm,
        aad: &[u8],
    ) -> EncryptedRecord {
        let stored = encrypt_record(
            Record::Envelope(plaintext).metered(),
            &test_encryption(alg),
            aad,
        )
        .into_inner();
        let StoredRecord::Encrypted { record, .. } = stored else {
            panic!("expected encrypted envelope record");
        };
        record
    }

    fn make_encrypted_record(
        format: EncryptedRecordFormat,
        nonce: impl AsRef<[u8]>,
        ciphertext: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
    ) -> EncryptedRecord {
        let nonce = nonce.as_ref();
        let ciphertext = ciphertext.as_ref();
        let tag = tag.as_ref();

        assert_eq!(nonce.len(), format.nonce_len());
        assert_eq!(tag.len(), format.tag_len());

        let mut encoded =
            BytesMut::with_capacity(FORMAT_ID_LEN + nonce.len() + ciphertext.len() + tag.len());
        encoded.put_u8(format.format_id());
        encoded.put_slice(nonce);
        encoded.put_slice(ciphertext);
        encoded.put_slice(tag);

        EncryptedRecord::new(encoded.freeze(), format)
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
        encryption: &EncryptionSpec,
        headers: Vec<Header>,
        body: Bytes,
        aad: &[u8],
    ) -> StoredRecord {
        let stored = encrypt_record(
            make_plaintext_envelope(headers, body).metered(),
            encryption,
            aad,
        )
        .into_inner();
        let StoredRecord::Encrypted { .. } = &stored else {
            panic!("plain encryption should not produce an encrypted record");
        };
        stored
    }

    #[rstest]
    #[case::aegis_unique(EncryptionAlgorithm::Aegis256, false)]
    #[case::aegis_shared(EncryptionAlgorithm::Aegis256, true)]
    #[case::aes_unique(EncryptionAlgorithm::Aes256Gcm, false)]
    #[case::aes_shared(EncryptionAlgorithm::Aes256Gcm, true)]
    fn encrypted_payload_roundtrips(
        #[case] algorithm: EncryptionAlgorithm,
        #[case] shared_encoded_record_buffer: bool,
    ) {
        let headers = vec![Header {
            name: Bytes::from_static(b"x-test"),
            value: Bytes::from_static(b"hello"),
        }];
        let body = Bytes::from_static(b"secret payload");

        let aad = aad();
        let plaintext = make_envelope(headers.clone(), body.clone());
        let encryption = test_encryption(algorithm);
        let encrypted_record = encrypt_test_record(plaintext, algorithm, &aad);
        let encrypted_record = if shared_encoded_record_buffer {
            let shared = encrypted_record.encoded.clone();
            EncryptedRecord::try_from(shared).unwrap()
        } else {
            encrypted_record
        };
        let decrypted = decrypt_payload(encrypted_record, &encryption, &aad).unwrap();
        let (out_headers, out_body) = EnvelopeRecord::try_from(decrypted).unwrap().into_parts();

        assert_eq!(out_headers, headers);
        assert_eq!(out_body, body);
    }

    #[rstest]
    #[case(EncryptionAlgorithm::Aegis256)]
    #[case(EncryptionAlgorithm::Aes256Gcm)]
    fn wrong_key_fails(#[case] algorithm: EncryptionAlgorithm) {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let encrypted_record = encrypt_test_record(plaintext, algorithm, &aad);
        let result = decrypt_payload(encrypted_record, &other_test_encryption(algorithm), &aad);
        assert!(matches!(
            result,
            Err(RecordDecryptionError::AuthenticationFailed)
        ));
    }

    #[test]
    fn empty_body_fails() {
        let result = EncryptedRecord::try_from(Bytes::new());
        assert!(matches!(
            result,
            Err(RecordDecodeError::Truncated("EncryptedRecordFormatId"))
        ));
    }

    #[test]
    fn format_id_byte_present() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let encrypted_record = encrypt_test_record(plaintext, EncryptionAlgorithm::Aegis256, &aad);
        let encoded = encrypted_record.to_bytes();
        assert_eq!(encrypted_record.format, EncryptedRecordFormat::Aegis256V1);
        assert_eq!(encrypted_record.algorithm(), EncryptionAlgorithm::Aegis256);
        assert_eq!(encoded[0], 0x01);
    }

    #[test]
    fn format_id_flip_detected() {
        let aad = aad();
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let mut encoded_record =
            encrypt_test_record(plaintext, EncryptionAlgorithm::Aegis256, &aad)
                .to_bytes()
                .to_vec();
        assert_eq!(encoded_record[0], 0x01);
        encoded_record[0] = 0x02;
        let encrypted_record = EncryptedRecord::try_from(Bytes::from(encoded_record)).unwrap();
        let result = decrypt_payload(
            encrypted_record,
            &test_encryption(EncryptionAlgorithm::Aegis256),
            &aad,
        );
        assert!(matches!(
            result,
            Err(RecordDecryptionError::AlgorithmMismatch {
                expected: Some(EncryptionAlgorithm::Aegis256),
                actual: Some(EncryptionAlgorithm::Aes256Gcm),
            })
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let aad = aad();
        let other_aad = [0x5A; 32];
        let plaintext = make_envelope(vec![], Bytes::from_static(b"data"));
        let encrypted_record = encrypt_test_record(plaintext, EncryptionAlgorithm::Aegis256, &aad);
        let result = decrypt_payload(
            encrypted_record,
            &test_encryption(EncryptionAlgorithm::Aegis256),
            &other_aad,
        );
        assert!(matches!(
            result,
            Err(RecordDecryptionError::AuthenticationFailed)
        ));
    }

    #[test]
    fn malformed_encrypted_record_layout_returns_error_instead_of_panicking() {
        let aad = aad();
        let record = EncryptedRecord {
            encoded: Bytes::from_static(b"\x01short"),
            format: EncryptedRecordFormat::Aegis256V1,
        };

        let result = decrypt_payload(
            record,
            &test_encryption(EncryptionAlgorithm::Aegis256),
            &aad,
        );

        assert!(matches!(
            result,
            Err(RecordDecryptionError::MalformedEncryptedRecord)
        ));
    }

    #[test]
    fn encrypted_record_roundtrips_aes256gcm() {
        let record = make_encrypted_record(
            EncryptedRecordFormat::Aes256GcmV1,
            Bytes::from_static(b"0123456789ab"),
            Bytes::from_static(b"ciphertext"),
            Bytes::from_static(b"0123456789abcdef"),
        );

        let bytes = record.to_bytes();
        let decoded = EncryptedRecord::try_from(bytes).unwrap();

        assert_eq!(decoded, record);
        assert_eq!(decoded.format, EncryptedRecordFormat::Aes256GcmV1);
        assert_eq!(decoded.encoded[0], FORMAT_ID_AES256GCM_V1);
        assert_eq!(decoded.nonce(), b"0123456789ab");
        assert_eq!(decoded.ciphertext(), b"ciphertext");
        assert_eq!(decoded.tag(), b"0123456789abcdef");
    }

    #[test]
    fn rejects_invalid_format_id() {
        let err = EncryptedRecord::try_from(Bytes::from_static(b"\xFFpayload")).unwrap_err();
        assert_eq!(
            err,
            RecordDecodeError::InvalidValue(
                "EncryptedRecord",
                "invalid encrypted record format id"
            )
        );
    }

    #[test]
    fn rejects_truncated_layout() {
        let err = EncryptedRecord::try_from(Bytes::from_static(b"\x01tiny")).unwrap_err();
        assert_eq!(err, RecordDecodeError::Truncated("EncryptedRecordFrame"));
    }

    #[test]
    fn encrypt_record_encrypts_envelope_records() {
        let aad = aad();
        let encryption = test_encryption(EncryptionAlgorithm::Aegis256);
        let headers = vec![Header {
            name: Bytes::from_static(b"x-test"),
            value: Bytes::from_static(b"hello"),
        }];
        let body = Bytes::from_static(b"secret payload");
        let record = make_plaintext_envelope(headers.clone(), body.clone()).metered();

        let stored = encrypt_record(record, &encryption, &aad).into_inner();
        let StoredRecord::Encrypted {
            record: envelope, ..
        } = &stored
        else {
            panic!("expected encrypted envelope record");
        };
        assert_eq!(envelope.format, EncryptedRecordFormat::Aegis256V1);
        assert_eq!(envelope.algorithm(), EncryptionAlgorithm::Aegis256);

        let decrypted = decrypt_stored_record(stored, &encryption, &aad).unwrap();
        let Record::Envelope(record) = decrypted.into_inner() else {
            panic!("expected envelope record");
        };
        assert_eq!(record.headers(), headers.as_slice());
        assert_eq!(record.body().as_ref(), body.as_ref());
    }

    #[test]
    fn decrypt_stored_record_preserves_plaintext_command_records() {
        let token: crate::record::FencingToken = "fence-test".parse().unwrap();
        let record = StoredRecord::Plaintext(Record::Command(CommandRecord::Fence(token.clone())));

        let decrypted = decrypt_stored_record(
            record,
            &test_encryption(EncryptionAlgorithm::Aegis256),
            &aad(),
        )
        .unwrap();

        let Record::Command(record) = decrypted.into_inner() else {
            panic!("expected command record");
        };
        assert_eq!(record, CommandRecord::Fence(token));
    }

    #[test]
    fn decrypt_stored_record_decrypts_encrypted_records() {
        let aad = aad();
        let record = make_encrypted_stored_record(
            &test_encryption(EncryptionAlgorithm::Aegis256),
            vec![Header {
                name: Bytes::from_static(b"x-test"),
                value: Bytes::from_static(b"hello"),
            }],
            Bytes::from_static(b"secret payload"),
            &aad,
        );

        let decrypted = decrypt_stored_record(
            record,
            &test_encryption(EncryptionAlgorithm::Aegis256),
            &aad,
        )
        .unwrap();

        let Record::Envelope(record) = decrypted.into_inner() else {
            panic!("expected envelope record");
        };
        assert_eq!(record.headers().len(), 1);
        assert_eq!(record.headers()[0].name.as_ref(), b"x-test");
        assert_eq!(record.headers()[0].value.as_ref(), b"hello");
        assert_eq!(record.body().as_ref(), b"secret payload");
    }

    #[test]
    fn decrypt_stored_record_plain_rejects_encrypted_records() {
        let aad = aad();
        let record = make_encrypted_stored_record(
            &test_encryption(EncryptionAlgorithm::Aegis256),
            vec![],
            Bytes::from_static(b"secret payload"),
            &aad,
        );

        let result = decrypt_stored_record(record, &EncryptionSpec::Plain, &aad);

        assert!(matches!(
            result,
            Err(RecordDecryptionError::AlgorithmMismatch {
                expected: None,
                actual: Some(EncryptionAlgorithm::Aegis256),
            })
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

        let result = decrypt_stored_record(
            StoredRecord::encrypted(record, metered_size + 1),
            &test_encryption(EncryptionAlgorithm::Aegis256),
            &aad,
        );

        assert!(matches!(
            result,
            Err(RecordDecryptionError::MeteredSizeMismatch {
                stored,
                actual
            }) if stored == metered_size + 1 && actual == metered_size
        ));
    }
}
