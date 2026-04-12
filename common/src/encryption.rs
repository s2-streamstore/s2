//! Encryption spec parsing, header parsing, and key parsing.

use core::str::FromStr;
use std::sync::Arc;

use base64ct::Encoding;
use http::{HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretBox, zeroize::Zeroizing};
use strum::{Display, EnumString};

use crate::http::ParseableHeader;

pub static S2_ENCRYPTION_HEADER: HeaderName = HeaderName::from_static("s2-encryption");

type EncryptionKey<const N: usize> = Arc<SecretBox<[u8; N]>>;

/// Encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumString)]
#[strum(ascii_case_insensitive)]
pub enum EncryptionAlgorithm {
    /// AEGIS-256
    #[strum(serialize = "aegis-256")]
    Aegis256,
    /// AES-256-GCM
    #[strum(serialize = "aes-256-gcm")]
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
#[serde(rename_all = "kebab-case")]
pub enum EncryptionMode {
    #[strum(serialize = "plain")]
    Plain,
    #[strum(serialize = "aegis-256")]
    Aegis256,
    #[strum(serialize = "aes-256-gcm")]
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

#[derive(Debug, Clone)]
pub struct Aegis256Key(EncryptionKey<32>);

impl Aegis256Key {
    pub fn new(key: [u8; 32]) -> Self {
        Self(Arc::new(SecretBox::new(Box::new(key))))
    }

    pub fn from_base64(key_b64: &str) -> Result<Self, EncryptionSpecError> {
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

    pub fn from_base64(key_b64: &str) -> Result<Self, EncryptionSpecError> {
        parse_encryption_key::<32>(key_b64).map(Self)
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        self.0.as_ref().expose_secret()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncryptionSpecError {
    #[error("Invalid encryption spec: expected '<mode>; <key>' or 'plain'")]
    InvalidSyntax,
    #[error("Invalid encryption spec: missing encryption mode")]
    MissingMode,
    #[error(
        "Invalid encryption spec: unknown encryption mode {mode:?}; expected 'plain', 'aegis-256', or 'aes-256-gcm'"
    )]
    UnknownMode { mode: String },
    #[error("Invalid encryption spec: key is not allowed when mode is 'plain'")]
    UnexpectedKeyForPlain,
    #[error("Invalid encryption spec: missing key for '{mode}'")]
    MissingKey { mode: EncryptionMode },
    #[error("Invalid encryption spec: key is not valid base64")]
    InvalidKeyBase64,
    #[error("Invalid encryption spec: key must be exactly {expected} bytes, got {actual} bytes")]
    InvalidKeyLength { expected: usize, actual: usize },
}

#[derive(Debug, Clone, Default)]
pub enum EncryptionSpec {
    #[default]
    Plain,
    Aegis256(Aegis256Key),
    Aes256Gcm(Aes256GcmKey),
}

impl EncryptionSpec {
    pub fn aegis256(key: [u8; 32]) -> Self {
        Self::Aegis256(Aegis256Key::new(key))
    }

    pub fn aes256_gcm(key: [u8; 32]) -> Self {
        Self::Aes256Gcm(Aes256GcmKey::new(key))
    }

    pub fn mode(&self) -> EncryptionMode {
        match self {
            Self::Plain => EncryptionMode::Plain,
            Self::Aegis256(_) => EncryptionMode::Aegis256,
            Self::Aes256Gcm(_) => EncryptionMode::Aes256Gcm,
        }
    }

    pub fn to_header_value(&self) -> HeaderValue {
        let mut value = match self {
            Self::Plain => HeaderValue::from_static("plain"),
            Self::Aegis256(key) => {
                header_value_for_key(EncryptionAlgorithm::Aegis256, key.secret())
            }
            Self::Aes256Gcm(key) => {
                header_value_for_key(EncryptionAlgorithm::Aes256Gcm, key.secret())
            }
        };
        value.set_sensitive(true);
        value
    }
}

impl FromStr for EncryptionSpec {
    type Err = EncryptionSpecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let mut parts = s.splitn(3, ';');
        let mode_str = parts.next().unwrap_or_default().trim();
        let key_b64 = parts.next().map(str::trim);
        if parts.next().is_some() {
            return Err(EncryptionSpecError::InvalidSyntax);
        }

        if mode_str.is_empty() {
            return Err(EncryptionSpecError::MissingMode);
        }

        let key_b64 = key_b64.filter(|key| !key.is_empty());
        match (parse_mode(mode_str)?, key_b64) {
            (EncryptionMode::Plain, None) => Ok(Self::Plain),
            (EncryptionMode::Plain, Some(_)) => Err(EncryptionSpecError::UnexpectedKeyForPlain),
            (EncryptionMode::Aegis256, Some(key_b64)) => {
                Ok(Self::Aegis256(Aegis256Key::from_base64(key_b64)?))
            }
            (EncryptionMode::Aegis256, None) => Err(EncryptionSpecError::MissingKey {
                mode: EncryptionMode::Aegis256,
            }),
            (EncryptionMode::Aes256Gcm, Some(key_b64)) => {
                Ok(Self::Aes256Gcm(Aes256GcmKey::from_base64(key_b64)?))
            }
            (EncryptionMode::Aes256Gcm, None) => Err(EncryptionSpecError::MissingKey {
                mode: EncryptionMode::Aes256Gcm,
            }),
        }
    }
}

impl ParseableHeader for EncryptionSpec {
    fn name() -> &'static HeaderName {
        &S2_ENCRYPTION_HEADER
    }
}

fn parse_encryption_key<const N: usize>(
    key_b64: &str,
) -> Result<EncryptionKey<N>, EncryptionSpecError> {
    use base64ct::{Base64, Encoding};
    use secrecy::zeroize::Zeroize;

    let mut key = Box::new([0u8; N]);
    let decoded = match Base64::decode(key_b64, key.as_mut()) {
        Ok(decoded) => decoded,
        Err(_) => {
            key.as_mut().zeroize();
            return Err(EncryptionSpecError::InvalidKeyBase64);
        }
    };

    if decoded.len() != N {
        let len = decoded.len();
        key.as_mut().zeroize();
        return Err(EncryptionSpecError::InvalidKeyLength {
            expected: N,
            actual: len,
        });
    }

    Ok(Arc::new(SecretBox::new(key)))
}

fn header_value_for_key(algorithm: EncryptionAlgorithm, key: &[u8; 32]) -> HeaderValue {
    let algorithm = algorithm.to_string();
    let encoded_len = base64ct::Base64::encoded_len(key);
    let mut value = Zeroizing::new(vec![0u8; algorithm.len() + 2 + encoded_len]);
    value[..algorithm.len()].copy_from_slice(algorithm.as_bytes());
    value[algorithm.len()..algorithm.len() + 2].copy_from_slice(b"; ");
    base64ct::Base64::encode(key, &mut value[algorithm.len() + 2..])
        .expect("base64 output length should match buffer");

    HeaderValue::from_bytes(&value).expect("encryption header value should be ASCII")
}

fn parse_mode(mode_str: &str) -> Result<EncryptionMode, EncryptionSpecError> {
    mode_str
        .parse::<EncryptionMode>()
        .map_err(|_| EncryptionSpecError::UnknownMode {
            mode: mode_str.to_owned(),
        })
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

    fn assert_encrypted_spec(
        spec: EncryptionSpec,
        algorithm: EncryptionAlgorithm,
        expected: &[u8; 32],
    ) {
        match (algorithm, spec) {
            (EncryptionAlgorithm::Aegis256, EncryptionSpec::Aegis256(key)) => {
                assert_eq!(key.secret(), expected)
            }
            (EncryptionAlgorithm::Aes256Gcm, EncryptionSpec::Aes256Gcm(key)) => {
                assert_eq!(key.secret(), expected)
            }
            (_, EncryptionSpec::Plain) => panic!("expected encrypted spec"),
            (expected_algorithm, actual_spec) => {
                panic!("expected {expected_algorithm:?}, got {actual_spec:?}")
            }
        }
    }

    fn assert_invalid_parse(header: &str, expected: EncryptionSpecError) {
        let result = header.parse::<EncryptionSpec>();
        match result {
            Err(actual) => assert_eq!(actual, expected),
            Ok(actual) => panic!("expected invalid spec for {header:?}, got {actual:?}"),
        }
    }

    #[rstest]
    #[case("aegis-256", EncryptionAlgorithm::Aegis256)]
    #[case("aes-256-gcm", EncryptionAlgorithm::Aes256Gcm)]
    #[case("AEGIS-256", EncryptionAlgorithm::Aegis256)]
    #[case("AES-256-GCM", EncryptionAlgorithm::Aes256Gcm)]
    fn parse_header_valid_encrypted(
        #[case] algorithm: &str,
        #[case] expected: EncryptionAlgorithm,
    ) {
        let spec = format!("{algorithm}; {KEY_B64}")
            .parse::<EncryptionSpec>()
            .unwrap();
        assert_encrypted_spec(spec, expected, &KEY_BYTES);
    }

    #[test]
    fn parse_header_aes_with_whitespace() {
        let spec = format!(" aes-256-gcm ; {KEY_B64} ")
            .parse::<EncryptionSpec>()
            .unwrap();
        assert_encrypted_spec(spec, EncryptionAlgorithm::Aes256Gcm, &KEY_BYTES);
    }

    #[rstest]
    #[case("plain")]
    #[case("PLAIN")]
    #[case("plain; ")]
    fn parse_header_plain_variants(#[case] header: &str) {
        let spec = header.parse::<EncryptionSpec>().unwrap();
        assert!(matches!(spec, EncryptionSpec::Plain));
    }

    #[test]
    fn spec_mode_matches_variant() {
        assert_eq!(EncryptionSpec::Plain.mode(), EncryptionMode::Plain);
        assert_eq!(
            EncryptionSpec::aegis256(KEY_BYTES).mode(),
            EncryptionMode::Aegis256
        );
        assert_eq!(
            EncryptionSpec::aes256_gcm(KEY_BYTES).mode(),
            EncryptionMode::Aes256Gcm
        );
    }

    #[rstest]
    #[case("", EncryptionSpecError::MissingMode)]
    #[case(
        "aegis-256",
        EncryptionSpecError::MissingKey {
            mode: EncryptionMode::Aegis256
        }
    )]
    #[case(
        "aegis-256; AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=; extra",
        EncryptionSpecError::InvalidSyntax
    )]
    #[case(
        "aegis-256; 3q2+7w==",
        EncryptionSpecError::InvalidKeyLength {
            expected: 32,
            actual: 4
        }
    )]
    #[case(
        "aegis-256; not-valid-base64!!!",
        EncryptionSpecError::InvalidKeyBase64
    )]
    #[case(
        "bogus; AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
        EncryptionSpecError::UnknownMode {
            mode: "bogus".to_owned()
        }
    )]
    #[case(
        "plain; AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
        EncryptionSpecError::UnexpectedKeyForPlain
    )]
    fn parse_header_invalid_cases(#[case] header: &str, #[case] expected: EncryptionSpecError) {
        assert_invalid_parse(header, expected);
    }

    #[test]
    fn header_value_is_sensitive() {
        let value = EncryptionSpec::aegis256([7; 32]).to_header_value();
        assert!(value.is_sensitive());
        assert_ne!(value, HeaderValue::from_static("plain"));
    }

    #[test]
    fn plain_header_value_roundtrips() {
        let value = EncryptionSpec::Plain.to_header_value();
        assert_eq!(value.to_str().unwrap(), "plain");
        assert!(value.is_sensitive());

        let parsed = value.to_str().unwrap().parse::<EncryptionSpec>().unwrap();
        assert!(matches!(parsed, EncryptionSpec::Plain));
    }

    #[rstest]
    #[case(EncryptionAlgorithm::Aegis256)]
    #[case(EncryptionAlgorithm::Aes256Gcm)]
    fn encrypted_header_value_roundtrips(#[case] algorithm: EncryptionAlgorithm) {
        let value = match algorithm {
            EncryptionAlgorithm::Aegis256 => EncryptionSpec::aegis256(KEY_BYTES),
            EncryptionAlgorithm::Aes256Gcm => EncryptionSpec::aes256_gcm(KEY_BYTES),
        }
        .to_header_value();
        assert_eq!(value.to_str().unwrap(), format!("{algorithm}; {KEY_B64}"));
        assert!(value.is_sensitive());

        let parsed = value.to_str().unwrap().parse::<EncryptionSpec>().unwrap();
        assert_encrypted_spec(parsed, algorithm, &KEY_BYTES);
    }
}
