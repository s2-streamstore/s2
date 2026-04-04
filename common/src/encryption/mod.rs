//! Encryption configuration, key parsing, and raw crypto over [`crate::record::EncryptedRecord`].
//!
//! AAD is caller-supplied associated data.

mod config;
mod crypto;

use std::sync::Arc;

pub use config::{EncryptionConfig, S2_ENCRYPTION_HEADER};
pub(crate) use crypto::{decrypt_payload, encrypt_payload};
use secrecy::{ExposeSecret, SecretBox};

pub use crate::types::config::EncryptionAlgorithm;

type EncryptionKey<const N: usize> = Arc<SecretBox<[u8; N]>>;

#[cfg(test)]
fn make_key<const N: usize>(bytes: [u8; N]) -> EncryptionKey<N> {
    Arc::new(SecretBox::new(Box::new(bytes)))
}

#[derive(Debug, Clone)]
pub struct Aegis256Key(EncryptionKey<32>);

impl Aegis256Key {
    pub fn new(key: [u8; 32]) -> Self {
        Self(Arc::new(SecretBox::new(Box::new(key))))
    }

    pub fn from_base64(key_b64: &str) -> Result<Self, EncryptionError> {
        parse_encryption_key::<32>(key_b64).map(Self)
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        self.0.as_ref().expose_secret()
    }
}

#[derive(Debug, Clone)]
pub struct Aes256GcmKey(EncryptionKey<32>);

impl Aes256GcmKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(Arc::new(SecretBox::new(Box::new(key))))
    }

    pub fn from_base64(key_b64: &str) -> Result<Self, EncryptionError> {
        parse_encryption_key::<32>(key_b64).map(Self)
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        self.0.as_ref().expose_secret()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum EncryptionError {
    #[error("Malformed S2-Encryption header: {0}")]
    MalformedHeader(String),
    #[error("Ciphertext algorithm mismatch: expected {expected}, actual {actual}")]
    AlgorithmMismatch {
        expected: EncryptionAlgorithm,
        actual: EncryptionAlgorithm,
    },
    #[error("Encrypted record encountered without decryption")]
    UnexpectedEncryptedRecord,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Record encoding error: {0}")]
    EncodingFailed(String),
}

fn parse_encryption_key<const N: usize>(
    key_b64: &str,
) -> Result<EncryptionKey<N>, EncryptionError> {
    use base64ct::{Base64, Encoding};
    use secrecy::zeroize::Zeroize;

    let mut key = Box::new([0u8; N]);
    let decoded = match Base64::decode(key_b64, key.as_mut()) {
        Ok(decoded) => decoded,
        Err(e) => {
            key.as_mut().zeroize();
            return Err(EncryptionError::MalformedHeader(format!(
                "key is not valid base64: {e}"
            )));
        }
    };

    if decoded.len() != N {
        let len = decoded.len();
        key.as_mut().zeroize();
        return Err(EncryptionError::MalformedHeader(format!(
            "key must be exactly {N} bytes, got {len} bytes"
        )));
    }

    Ok(Arc::new(SecretBox::new(key)))
}
