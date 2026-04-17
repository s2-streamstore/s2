//! Encryption algorithm, key material parsing, and request header handling.

use core::str::FromStr;
use std::sync::Arc;

use base64ct::Encoding;
use http::{HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretBox};
use strum::{Display, EnumString};

use crate::http::ParseableHeader;

pub static S2_ENCRYPTION_KEY_HEADER: HeaderName = HeaderName::from_static("s2-encryption-key");

type SecretKey = Arc<SecretBox<[u8; 32]>>;
type SecretKeyMaterial = Arc<SecretBox<[u8]>>;

/// Encryption algorithm.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    Display,
    EnumString,
)]
#[strum(ascii_case_insensitive)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum EncryptionAlgorithm {
    /// AEGIS-256
    #[strum(serialize = "aegis-256")]
    #[serde(rename = "aegis-256")]
    #[cfg_attr(feature = "clap", value(name = "aegis-256"))]
    Aegis256,
    /// AES-256-GCM
    #[strum(serialize = "aes-256-gcm")]
    #[serde(rename = "aes-256-gcm")]
    #[cfg_attr(feature = "clap", value(name = "aes-256-gcm"))]
    Aes256Gcm,
}

/// Customer-supplied encryption key material for append/read operations.
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    bytes: SecretKeyMaterial,
}

impl EncryptionKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self::from_bytes(Box::new(key))
    }

    pub fn from_base64(key_b64: &str) -> Result<Self, EncryptionKeyError> {
        parse_encryption_key_material(key_b64).map(|bytes| Self { bytes })
    }

    pub fn from_bytes(bytes: Box<[u8]>) -> Self {
        Self {
            bytes: Arc::new(SecretBox::new(bytes)),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref().expose_secret()
    }

    pub fn to_header_value(&self) -> HeaderValue {
        let mut value = header_value_for_key_material(self.bytes());
        value.set_sensitive(true);
        value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncryptionKeyError {
    #[error("invalid encryption key: key is not valid base64")]
    InvalidBase64,
    #[error("invalid encryption key: key material must not be empty")]
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncryptionResolutionError {
    #[error("missing encryption key for stream encryption algorithm '{algorithm}'")]
    MissingKey { algorithm: EncryptionAlgorithm },
    #[error(
        "invalid encryption key length for stream encryption algorithm '{algorithm}': expected {expected} bytes, got {actual} bytes"
    )]
    InvalidKeyLength {
        algorithm: EncryptionAlgorithm,
        expected: usize,
        actual: usize,
    },
}

/// Resolved stream encryption after combining stream metadata with the request key.
#[derive(Clone, Default)]
pub struct EncryptionSpec {
    algorithm: Option<EncryptionAlgorithm>,
    key: Option<SecretKey>,
}

impl std::fmt::Debug for EncryptionSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionSpec")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl EncryptionSpec {
    pub fn plain() -> Self {
        Self::default()
    }

    pub fn resolve(
        algorithm: Option<EncryptionAlgorithm>,
        key: Option<EncryptionKey>,
    ) -> Result<Self, EncryptionResolutionError> {
        match (algorithm, key) {
            (None, _) => Ok(Self::plain()),
            (Some(EncryptionAlgorithm::Aegis256), Some(key)) => Ok(Self::with_secret_key(
                EncryptionAlgorithm::Aegis256,
                resolve_secret_key(EncryptionAlgorithm::Aegis256, key)?,
            )),
            (Some(EncryptionAlgorithm::Aes256Gcm), Some(key)) => Ok(Self::with_secret_key(
                EncryptionAlgorithm::Aes256Gcm,
                resolve_secret_key(EncryptionAlgorithm::Aes256Gcm, key)?,
            )),
            (Some(algorithm), None) => Err(EncryptionResolutionError::MissingKey { algorithm }),
        }
    }

    pub fn aegis256(key: [u8; 32]) -> Self {
        Self::with_secret_key(EncryptionAlgorithm::Aegis256, secret_key(key))
    }

    pub fn aes256_gcm(key: [u8; 32]) -> Self {
        Self::with_secret_key(EncryptionAlgorithm::Aes256Gcm, secret_key(key))
    }

    pub fn algorithm(&self) -> Option<EncryptionAlgorithm> {
        self.algorithm
    }

    pub fn is_plain(&self) -> bool {
        self.algorithm.is_none()
    }

    fn with_secret_key(algorithm: EncryptionAlgorithm, key: SecretKey) -> Self {
        Self {
            algorithm: Some(algorithm),
            key: Some(key),
        }
    }

    pub(crate) fn secret_key(&self) -> Option<&[u8; 32]> {
        self.key.as_ref().map(|key| key.as_ref().expose_secret())
    }

    pub(crate) fn secret_key_for_algorithm(
        &self,
        algorithm: EncryptionAlgorithm,
    ) -> Option<&[u8; 32]> {
        (self.algorithm == Some(algorithm))
            .then(|| self.secret_key())
            .flatten()
    }
}

impl FromStr for EncryptionKey {
    type Err = EncryptionKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base64(s.trim())
    }
}

impl ParseableHeader for EncryptionKey {
    fn name() -> &'static HeaderName {
        &S2_ENCRYPTION_KEY_HEADER
    }
}

fn parse_encryption_key_material(key_b64: &str) -> Result<SecretKeyMaterial, EncryptionKeyError> {
    use base64ct::{Base64, Encoding};
    use secrecy::zeroize::Zeroize;

    let mut key = match Base64::decode_vec(key_b64) {
        Ok(decoded) => decoded,
        Err(_) => {
            return Err(EncryptionKeyError::InvalidBase64);
        }
    };

    if key.is_empty() {
        key.zeroize();
        return Err(EncryptionKeyError::Empty);
    }

    Ok(Arc::new(SecretBox::new(key.into_boxed_slice())))
}

fn resolve_secret_key(
    algorithm: EncryptionAlgorithm,
    key: EncryptionKey,
) -> Result<SecretKey, EncryptionResolutionError> {
    // Parse the request header as opaque bytes and validate the current
    // algorithm-specific raw key requirement only at resolution time.
    let bytes = key.bytes();
    if bytes.len() != 32 {
        return Err(EncryptionResolutionError::InvalidKeyLength {
            algorithm,
            expected: 32,
            actual: bytes.len(),
        });
    }

    let mut secret = Box::new([0u8; 32]);
    secret.copy_from_slice(bytes);
    Ok(Arc::new(SecretBox::new(secret)))
}

fn header_value_for_key_material(key: &[u8]) -> HeaderValue {
    let mut value = vec![0u8; base64ct::Base64::encoded_len(key)];
    base64ct::Base64::encode(key, &mut value).expect("base64 output length should match buffer");
    HeaderValue::from_bytes(&value).expect("encryption key header value should be ASCII")
}

fn secret_key(key: [u8; 32]) -> SecretKey {
    Arc::new(SecretBox::new(Box::new(key)))
}

#[cfg(test)]
mod tests {
    use http::header::HeaderValue;
    use rstest::rstest;

    use super::*;

    const KEY_B64: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    const KEY_BYTES: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    #[test]
    fn parse_key_header_roundtrips() {
        let key = KEY_B64.parse::<EncryptionKey>().unwrap();
        assert_eq!(key.bytes(), KEY_BYTES);
    }

    #[test]
    fn key_header_value_is_sensitive() {
        let value = EncryptionKey::new([7; 32]).to_header_value();
        assert!(value.is_sensitive());
        assert_ne!(value, HeaderValue::from_static("plain"));
    }

    #[test]
    fn key_header_value_roundtrips() {
        let value = EncryptionKey::new(KEY_BYTES).to_header_value();
        assert_eq!(value.to_str().unwrap(), KEY_B64);
        assert!(value.is_sensitive());

        let parsed = value.to_str().unwrap().parse::<EncryptionKey>().unwrap();
        assert_eq!(parsed.bytes(), KEY_BYTES);
    }

    #[rstest]
    #[case("", EncryptionKeyError::Empty)]
    #[case("not-valid-base64!!!", EncryptionKeyError::InvalidBase64)]
    fn parse_key_header_invalid_cases(#[case] header: &str, #[case] expected: EncryptionKeyError) {
        let result = header.parse::<EncryptionKey>();
        match result {
            Err(actual) => assert_eq!(actual, expected),
            Ok(_) => panic!("expected invalid key for {header:?}"),
        }
    }

    #[rstest]
    #[case(EncryptionAlgorithm::Aegis256, "\"aegis-256\"")]
    #[case(EncryptionAlgorithm::Aes256Gcm, "\"aes-256-gcm\"")]
    fn algorithm_serde_roundtrip(#[case] algorithm: EncryptionAlgorithm, #[case] expected: &str) {
        let serialized = serde_json::to_string(&algorithm).unwrap();
        assert_eq!(serialized, expected);
        let deserialized: EncryptionAlgorithm = serde_json::from_str(expected).unwrap();
        assert_eq!(deserialized, algorithm);
    }

    #[test]
    fn resolve_plain_ignores_key() {
        let encryption =
            EncryptionSpec::resolve(None, Some(EncryptionKey::new(KEY_BYTES))).unwrap();
        assert!(encryption.is_plain());
    }

    #[test]
    fn resolve_encrypted_requires_key() {
        let err = EncryptionSpec::resolve(Some(EncryptionAlgorithm::Aegis256), None).unwrap_err();
        assert_eq!(
            err,
            EncryptionResolutionError::MissingKey {
                algorithm: EncryptionAlgorithm::Aegis256,
            }
        );
    }

    #[test]
    fn resolve_encrypted_validates_key_length_per_algorithm() {
        let err = EncryptionSpec::resolve(
            Some(EncryptionAlgorithm::Aegis256),
            Some(EncryptionKey::from_bytes(vec![0x42; 4].into_boxed_slice())),
        )
        .unwrap_err();
        assert_eq!(
            err,
            EncryptionResolutionError::InvalidKeyLength {
                algorithm: EncryptionAlgorithm::Aegis256,
                expected: 32,
                actual: 4,
            }
        );
    }
}
