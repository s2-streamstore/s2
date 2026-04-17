//! Encryption algorithm, key parsing, and key-only header handling.

use core::str::FromStr;
use std::sync::Arc;

use base64ct::Encoding;
use http::{HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretBox};
use strum::{Display, EnumString};

use crate::http::ParseableHeader;

pub static S2_ENCRYPTION_KEY_HEADER: HeaderName = HeaderName::from_static("s2-encryption-key");

type SecretKey = Arc<SecretBox<[u8; 32]>>;

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

/// Encryption mode, including plaintext.
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
    enumset::EnumSetType,
)]
#[strum(ascii_case_insensitive)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[enumset(no_super_impls)]
pub enum EncryptionMode {
    #[strum(serialize = "plain")]
    #[serde(rename = "plain")]
    Plain,
    #[strum(serialize = "aegis-256")]
    #[serde(rename = "aegis-256")]
    #[cfg_attr(feature = "clap", value(name = "aegis-256"))]
    Aegis256,
    #[strum(serialize = "aes-256-gcm")]
    #[serde(rename = "aes-256-gcm")]
    #[cfg_attr(feature = "clap", value(name = "aes-256-gcm"))]
    Aes256Gcm,
}

impl From<EncryptionAlgorithm> for EncryptionMode {
    fn from(value: EncryptionAlgorithm) -> Self {
        match value {
            EncryptionAlgorithm::Aegis256 => Self::Aegis256,
            EncryptionAlgorithm::Aes256Gcm => Self::Aes256Gcm,
        }
    }
}

/// Customer-supplied encryption key shared by all supported algorithms.
#[derive(Debug, Clone)]
pub struct EncryptionKey(SecretKey);

impl EncryptionKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(Arc::new(SecretBox::new(Box::new(key))))
    }

    pub fn from_base64(key_b64: &str) -> Result<Self, EncryptionKeyError> {
        parse_encryption_key(key_b64).map(Self)
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        self.0.as_ref().expose_secret()
    }

    pub fn to_header_value(&self) -> HeaderValue {
        let mut value = header_value_for_key(self.secret());
        value.set_sensitive(true);
        value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncryptionKeyError {
    #[error("invalid encryption key: key is not valid base64")]
    InvalidBase64,
    #[error("invalid encryption key: key must be exactly {expected} bytes, got {actual} bytes")]
    InvalidLength { expected: usize, actual: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncryptionResolutionError {
    #[error("missing encryption key for stream encryption algorithm '{algorithm}'")]
    MissingKey { algorithm: EncryptionAlgorithm },
}

/// Resolved stream encryption after combining stream metadata with the request key.
#[derive(Debug, Clone, Default)]
pub enum Encryption {
    #[default]
    Plain,
    Aegis256(EncryptionKey),
    Aes256Gcm(EncryptionKey),
}

impl Encryption {
    pub fn resolve(
        algorithm: Option<EncryptionAlgorithm>,
        key: Option<EncryptionKey>,
    ) -> Result<Self, EncryptionResolutionError> {
        match (algorithm, key) {
            (None, _) => Ok(Self::Plain),
            (Some(EncryptionAlgorithm::Aegis256), Some(key)) => Ok(Self::Aegis256(key)),
            (Some(EncryptionAlgorithm::Aes256Gcm), Some(key)) => Ok(Self::Aes256Gcm(key)),
            (Some(algorithm), None) => Err(EncryptionResolutionError::MissingKey { algorithm }),
        }
    }

    pub fn aegis256(key: [u8; 32]) -> Self {
        Self::Aegis256(EncryptionKey::new(key))
    }

    pub fn aes256_gcm(key: [u8; 32]) -> Self {
        Self::Aes256Gcm(EncryptionKey::new(key))
    }

    pub fn mode(&self) -> EncryptionMode {
        match self {
            Self::Plain => EncryptionMode::Plain,
            Self::Aegis256(_) => EncryptionMode::Aegis256,
            Self::Aes256Gcm(_) => EncryptionMode::Aes256Gcm,
        }
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

fn parse_encryption_key(key_b64: &str) -> Result<SecretKey, EncryptionKeyError> {
    use base64ct::{Base64, Encoding};
    use secrecy::zeroize::Zeroize;

    let mut key = Box::new([0u8; 32]);
    let decoded = match Base64::decode(key_b64, key.as_mut()) {
        Ok(decoded) => decoded,
        Err(_) => {
            key.as_mut().zeroize();
            return Err(EncryptionKeyError::InvalidBase64);
        }
    };

    if decoded.len() != 32 {
        let len = decoded.len();
        key.as_mut().zeroize();
        return Err(EncryptionKeyError::InvalidLength {
            expected: 32,
            actual: len,
        });
    }

    Ok(Arc::new(SecretBox::new(key)))
}

fn header_value_for_key(key: &[u8; 32]) -> HeaderValue {
    let mut value = vec![0u8; base64ct::Base64::encoded_len(key)];
    base64ct::Base64::encode(key, &mut value).expect("base64 output length should match buffer");
    HeaderValue::from_bytes(&value).expect("encryption key header value should be ASCII")
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
        assert_eq!(key.secret(), &KEY_BYTES);
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
        assert_eq!(parsed.secret(), &KEY_BYTES);
    }

    #[rstest]
    #[case("", EncryptionKeyError::InvalidLength {
        expected: 32,
        actual: 0
    })]
    #[case("3q2+7w==", EncryptionKeyError::InvalidLength {
        expected: 32,
        actual: 4
    })]
    #[case("not-valid-base64!!!", EncryptionKeyError::InvalidBase64)]
    fn parse_key_header_invalid_cases(#[case] header: &str, #[case] expected: EncryptionKeyError) {
        let result = header.parse::<EncryptionKey>();
        match result {
            Err(actual) => assert_eq!(actual, expected),
            Ok(_) => panic!("expected invalid key for {header:?}"),
        }
    }

    #[rstest]
    #[case(EncryptionMode::Plain, "\"plain\"")]
    #[case(EncryptionMode::Aegis256, "\"aegis-256\"")]
    #[case(EncryptionMode::Aes256Gcm, "\"aes-256-gcm\"")]
    fn mode_serde_roundtrip(#[case] mode: EncryptionMode, #[case] expected: &str) {
        let serialized = serde_json::to_string(&mode).unwrap();
        assert_eq!(serialized, expected);
        let deserialized: EncryptionMode = serde_json::from_str(expected).unwrap();
        assert_eq!(deserialized, mode);
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
        let encryption = Encryption::resolve(None, Some(EncryptionKey::new(KEY_BYTES))).unwrap();
        assert!(matches!(encryption, Encryption::Plain));
    }

    #[test]
    fn resolve_encrypted_requires_key() {
        let err = Encryption::resolve(Some(EncryptionAlgorithm::Aegis256), None).unwrap_err();
        assert_eq!(
            err,
            EncryptionResolutionError::MissingKey {
                algorithm: EncryptionAlgorithm::Aegis256,
            }
        );
    }
}
