//! Encrypted record wire format.
//!
//! ```text
//! [suite_id: 1 byte] [nonce] [ciphertext] [tag]
//! ```
//!
//! | suite_id | Suite          | Nonce  | Tag  |
//! |----------|----------------|--------|------|
//! | 0x01     | AEGIS-256 v1   | 32 B   | 32 B |
//! | 0x02     | AES-256-GCM v1 | 12 B   | 16 B |
//!
//! The leading suite byte identifies the full ciphertext framing, not just the
//! algorithm. This leaves room for future layout changes without a separate
//! version byte.

use bytes::{BufMut, Bytes, BytesMut};

use super::Encodable;
use crate::{deep_size::DeepSize, types::config::EncryptionAlgorithm};

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
    bytes: Bytes,
    algorithm: EncryptionAlgorithm,
}

impl EncryptedRecord {
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
        bytes.put_u8(suite_id(algorithm));
        bytes.put_slice(nonce);
        bytes.put_slice(ciphertext);
        bytes.put_slice(tag);

        Ok(Self {
            bytes: bytes.freeze(),
            algorithm,
        })
    }

    pub(crate) fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    pub(crate) fn nonce(&self) -> &[u8] {
        &self.bytes[self.nonce_range()]
    }

    pub(crate) fn ciphertext(&self) -> &[u8] {
        &self.bytes[self.ciphertext_range()]
    }

    pub(crate) fn ciphertext_and_tag(&self) -> &[u8] {
        &self.bytes[self.ciphertext_range().start..]
    }

    pub(crate) fn tag(&self) -> &[u8] {
        &self.bytes[self.tag_range()]
    }

    fn nonce_range(&self) -> std::ops::Range<usize> {
        let start = SUITE_ID_LEN;
        let end = start + self.algorithm.nonce_len();
        start..end
    }

    fn ciphertext_range(&self) -> std::ops::Range<usize> {
        let start = self.nonce_range().end;
        let end = self.tag_range().start;
        start..end
    }

    fn tag_range(&self) -> std::ops::Range<usize> {
        let tag_len = self.algorithm.tag_len();
        let start = self.bytes.len() - tag_len;
        let end = self.bytes.len();
        start..end
    }
}

impl EncryptionAlgorithm {
    const fn nonce_len(self) -> usize {
        match self {
            Self::Aegis256 => 32,
            Self::Aes256Gcm => 12,
        }
    }

    const fn tag_len(self) -> usize {
        match self {
            Self::Aegis256 => 32,
            Self::Aes256Gcm => 16,
        }
    }
}

impl std::fmt::Debug for EncryptedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedRecord")
            .field("suite_id", &self.bytes[0])
            .field("algorithm", &self.algorithm)
            .field("nonce.len", &self.nonce().len())
            .field("ciphertext.len", &self.ciphertext().len())
            .field("tag.len", &self.tag().len())
            .finish()
    }
}

impl DeepSize for EncryptedRecord {
    fn deep_size(&self) -> usize {
        self.bytes.len()
    }
}

impl Encodable for EncryptedRecord {
    fn encoded_size(&self) -> usize {
        self.bytes.len()
    }

    fn encode_into(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.bytes.as_ref());
    }
}

impl TryFrom<Bytes> for EncryptedRecord {
    type Error = EncryptedRecordError;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.len() < SUITE_ID_LEN {
            return Err(EncryptedRecordError::Truncated);
        }

        let algorithm = parse_suite_id(bytes[0])?;
        let nonce_len = algorithm.nonce_len();
        let tag_len = algorithm.tag_len();
        if bytes.len() < SUITE_ID_LEN + nonce_len + tag_len {
            return Err(EncryptedRecordError::Truncated);
        }

        Ok(Self { bytes, algorithm })
    }
}

fn parse_suite_id(suite_id: u8) -> Result<EncryptionAlgorithm, EncryptedRecordError> {
    match suite_id {
        SUITE_ID_AEGIS256_V1 => Ok(EncryptionAlgorithm::Aegis256),
        SUITE_ID_AES256GCM_V1 => Ok(EncryptionAlgorithm::Aes256Gcm),
        _ => Err(EncryptedRecordError::InvalidSuiteId(suite_id)),
    }
}

fn suite_id(algorithm: EncryptionAlgorithm) -> u8 {
    match algorithm {
        EncryptionAlgorithm::Aegis256 => SUITE_ID_AEGIS256_V1,
        EncryptionAlgorithm::Aes256Gcm => SUITE_ID_AES256GCM_V1,
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

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
        assert_eq!(decoded.bytes[0], SUITE_ID_AES256GCM_V1);
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
}
