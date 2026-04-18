//! Encryption algorithm, key material parsing, and request header handling.

use core::str::FromStr;
use std::sync::Arc;

use base64ct::{Base64, Decoder, Encoding};
use http::{HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretBox, SecretString, zeroize::Zeroize};
use strum::{Display, EnumString};

use crate::http::ParseableHeader;

pub static S2_ENCRYPTION_KEY_HEADER: HeaderName = HeaderName::from_static("s2-encryption-key");

// 32 bytes in Base 64
const MAX_ENCRYPTION_KEY_HEADER_VALUE_LEN: usize = 44;

type EncodedKeyMaterial = Arc<SecretString>;
type DecodedKeyMaterial<const N: usize> = Arc<SecretBox<[u8; N]>>;

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
pub struct EncryptionKey(EncodedKeyMaterial);

impl EncryptionKey {
    pub fn new<const N: usize>(key: [u8; N]) -> Self {
        Self(Arc::new(Base64::encode_string(&key).into()))
    }

    pub(crate) fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    pub fn to_header_value(&self) -> HeaderValue {
        let mut value = HeaderValue::from_bytes(self.expose_secret().as_bytes())
            .expect("encryption key header value should be ASCII");
        value.set_sensitive(true);
        value
    }
}

/// Decoded fixed-size customer-supplied encryption key material.
#[derive(Debug, Clone)]
pub struct DecodedEncryptionKey<const N: usize>(DecodedKeyMaterial<N>);

impl<const N: usize> DecodedEncryptionKey<N> {
    pub fn new(key: [u8; N]) -> Self {
        Self(Arc::new(SecretBox::new(Box::new(key))))
    }

    pub(crate) fn expose_secret(&self) -> &[u8; N] {
        self.0.expose_secret()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid encryption key: key material length {0} is out of range")]
pub struct EncryptionKeyLengthError(usize);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncryptionSpecResolutionError {
    #[error("missing encryption key for stream cipher '{cipher}'")]
    MissingKey { cipher: EncryptionAlgorithm },
    #[error("invalid encryption key for stream cipher '{cipher}': invalid base64")]
    InvalidBase64 { cipher: EncryptionAlgorithm },
    #[error("invalid encryption key length for stream cipher '{cipher}': {length}")]
    InvalidKeyLength {
        cipher: EncryptionAlgorithm,
        length: usize,
    },
}

/// Resolved encryption spec after combining stream metadata with the customer-supplied encryption key, if any.
#[rustfmt::skip]
#[derive(Debug, Clone, Default)]
pub enum EncryptionSpec {
    #[default]
    Plain,
    Aegis256(DecodedEncryptionKey<32>),
    Aes256Gcm(DecodedEncryptionKey<32>),
}

impl EncryptionSpec {
    pub fn resolve(
        cipher: Option<EncryptionAlgorithm>,
        key: Option<EncryptionKey>,
    ) -> Result<Self, EncryptionSpecResolutionError> {
        match (cipher, key) {
            (None, _) => Ok(Self::Plain),
            (Some(cipher @ EncryptionAlgorithm::Aegis256), Some(key)) => {
                Ok(Self::Aegis256(resolve_key(cipher, key)?))
            }
            (Some(cipher @ EncryptionAlgorithm::Aes256Gcm), Some(key)) => {
                Ok(Self::Aes256Gcm(resolve_key(cipher, key)?))
            }
            (Some(cipher), None) => Err(EncryptionSpecResolutionError::MissingKey { cipher }),
        }
    }

    pub fn aegis256(key: [u8; 32]) -> Self {
        Self::Aegis256(DecodedEncryptionKey::new(key))
    }

    pub fn aes256_gcm(key: [u8; 32]) -> Self {
        Self::Aes256Gcm(DecodedEncryptionKey::new(key))
    }
}

impl FromStr for EncryptionKey {
    type Err = EncryptionKeyLengthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if (1..=MAX_ENCRYPTION_KEY_HEADER_VALUE_LEN).contains(&trimmed.len()) {
            Ok(Self(Arc::new(trimmed.to_owned().into())))
        } else {
            Err(EncryptionKeyLengthError(trimmed.len()))
        }
    }
}

impl ParseableHeader for EncryptionKey {
    fn name() -> &'static HeaderName {
        &S2_ENCRYPTION_KEY_HEADER
    }
}

fn resolve_key<const N: usize>(
    cipher: EncryptionAlgorithm,
    key: EncryptionKey,
) -> Result<DecodedEncryptionKey<N>, EncryptionSpecResolutionError> {
    let mut decoder = Decoder::<Base64>::new(key.expose_secret().as_bytes())
        .map_err(|_| EncryptionSpecResolutionError::InvalidBase64 { cipher })?;
    let mut key_material = Box::new([0u8; N]);
    match decoder.decode(key_material.as_mut()) {
        Ok(_) if decoder.is_finished() => {
            Ok(DecodedEncryptionKey(Arc::new(SecretBox::new(key_material))))
        }
        Ok(_) => {
            let length = N
                .checked_add(decoder.remaining_len())
                .expect("decoded key length should fit usize");
            key_material.as_mut().zeroize();
            Err(EncryptionSpecResolutionError::InvalidKeyLength { cipher, length })
        }
        Err(base64ct::Error::InvalidEncoding) => {
            key_material.as_mut().zeroize();
            Err(EncryptionSpecResolutionError::InvalidBase64 { cipher })
        }
        Err(base64ct::Error::InvalidLength) => {
            let length = decoder.remaining_len();
            key_material.as_mut().zeroize();
            Err(EncryptionSpecResolutionError::InvalidKeyLength { cipher, length })
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const KEY_B64: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    const KEY_BYTES: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    fn resolve_encrypted(
        cipher: EncryptionAlgorithm,
        key: EncryptionKey,
    ) -> Result<EncryptionSpec, EncryptionSpecResolutionError> {
        EncryptionSpec::resolve(Some(cipher), Some(key))
    }

    #[test]
    fn key_header_value_roundtrips_and_is_sensitive() {
        let value = EncryptionKey::new(KEY_BYTES).to_header_value();
        assert_eq!(value.to_str().unwrap(), KEY_B64);
        assert!(value.is_sensitive());

        let parsed = value.to_str().unwrap().parse::<EncryptionKey>().unwrap();
        assert_eq!(parsed.to_header_value().to_str().unwrap(), KEY_B64);
    }

    #[test]
    fn encryption_key_parsing_trims_and_enforces_bounds() {
        let parsed = format!("  {KEY_B64}\n").parse::<EncryptionKey>().unwrap();
        assert_eq!(parsed.to_header_value().to_str().unwrap(), KEY_B64);

        assert_eq!(
            "   ".parse::<EncryptionKey>().unwrap_err(),
            EncryptionKeyLengthError(0)
        );

        let too_long = "A".repeat(MAX_ENCRYPTION_KEY_HEADER_VALUE_LEN + 1);
        assert_eq!(
            too_long.parse::<EncryptionKey>().unwrap_err(),
            EncryptionKeyLengthError(MAX_ENCRYPTION_KEY_HEADER_VALUE_LEN + 1)
        );
    }

    #[test]
    fn resolve_plain_ignores_supplied_key() {
        let encryption = EncryptionSpec::resolve(None, Some("!!!!".parse().unwrap())).unwrap();
        assert!(matches!(encryption, EncryptionSpec::Plain));
    }

    #[rstest]
    #[case(EncryptionAlgorithm::Aegis256)]
    #[case(EncryptionAlgorithm::Aes256Gcm)]
    fn resolve_encrypted_requires_key(#[case] cipher: EncryptionAlgorithm) {
        let err = EncryptionSpec::resolve(Some(cipher), None).unwrap_err();
        assert_eq!(err, EncryptionSpecResolutionError::MissingKey { cipher });
    }

    #[rstest]
    #[case(EncryptionAlgorithm::Aegis256)]
    #[case(EncryptionAlgorithm::Aes256Gcm)]
    fn resolve_encrypted_decodes_key_for_each_algorithm(#[case] cipher: EncryptionAlgorithm) {
        let encryption = resolve_encrypted(cipher, EncryptionKey::new(KEY_BYTES)).unwrap();

        match (cipher, encryption) {
            (EncryptionAlgorithm::Aegis256, EncryptionSpec::Aegis256(key)) => {
                assert_eq!(key.expose_secret(), &KEY_BYTES);
            }
            (EncryptionAlgorithm::Aes256Gcm, EncryptionSpec::Aes256Gcm(key)) => {
                assert_eq!(key.expose_secret(), &KEY_BYTES);
            }
            _ => panic!("resolved encryption spec did not match requested algorithm"),
        }
    }

    #[rstest]
    #[case(EncryptionAlgorithm::Aegis256)]
    #[case(EncryptionAlgorithm::Aes256Gcm)]
    fn resolve_encrypted_rejects_invalid_base64(#[case] cipher: EncryptionAlgorithm) {
        let err = resolve_encrypted(cipher, "!!!!".parse().unwrap()).unwrap_err();
        assert_eq!(err, EncryptionSpecResolutionError::InvalidBase64 { cipher });
    }

    #[test]
    fn resolve_encrypted_rejects_non_32_byte_keys() {
        let cipher = EncryptionAlgorithm::Aegis256;

        let short_err = resolve_encrypted(cipher, EncryptionKey::new([0x42; 4])).unwrap_err();
        assert_eq!(
            short_err,
            EncryptionSpecResolutionError::InvalidKeyLength { cipher, length: 4 }
        );

        let long_err = resolve_encrypted(cipher, EncryptionKey::new([0x42; 33])).unwrap_err();
        assert_eq!(
            long_err,
            EncryptionSpecResolutionError::InvalidKeyLength { cipher, length: 33 }
        );
    }
}
