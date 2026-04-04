use core::str::FromStr;

use base64ct::Encoding;
use http::{HeaderName, HeaderValue};

use super::{Aegis256Key, Aes256GcmKey, EncryptionAlgorithm, EncryptionError};
use crate::http::ParseableHeader;

pub static S2_ENCRYPTION_HEADER: HeaderName = HeaderName::from_static("s2-encryption");

#[derive(Debug, Clone, Default)]
pub enum EncryptionConfig {
    #[default]
    None,
    Aegis256(Aegis256Key),
    Aes256Gcm(Aes256GcmKey),
}

impl EncryptionConfig {
    pub fn aegis256(key: [u8; 32]) -> Self {
        Self::Aegis256(Aegis256Key::new(key))
    }

    pub fn aes256_gcm(key: [u8; 32]) -> Self {
        Self::Aes256Gcm(Aes256GcmKey::new(key))
    }

    pub fn to_header_value(&self) -> HeaderValue {
        let value = match self {
            Self::None => "none".to_owned(),
            Self::Aegis256(key) => format!(
                "{}; {}",
                EncryptionAlgorithm::Aegis256,
                base64ct::Base64::encode_string(key.secret())
            ),
            Self::Aes256Gcm(key) => format!(
                "{}; {}",
                EncryptionAlgorithm::Aes256Gcm,
                base64ct::Base64::encode_string(key.secret())
            ),
        };
        let mut value =
            HeaderValue::try_from(value).expect("encryption header value should be ASCII");
        value.set_sensitive(true);
        value
    }
}

impl FromStr for EncryptionConfig {
    type Err = EncryptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let mut parts = s.splitn(3, ';');
        let alg_str = parts.next().unwrap_or_default().trim();
        let key_b64 = parts.next().map(str::trim);
        if parts.next().is_some() {
            return Err(EncryptionError::MalformedHeader(
                "expected '<alg>; <key>' or 'none'".to_owned(),
            ));
        }

        if alg_str.is_empty() {
            return Err(EncryptionError::MalformedHeader(
                "missing algorithm".to_owned(),
            ));
        }

        let key_b64 = key_b64.filter(|key| !key.is_empty());
        match (parse_algorithm(alg_str)?, key_b64) {
            (None, None) => Ok(Self::None),
            (None, Some(_)) => Err(EncryptionError::MalformedHeader(
                "key is not allowed when algorithm is 'none'".to_owned(),
            )),
            (Some(EncryptionAlgorithm::Aegis256), Some(key_b64)) => {
                Ok(Self::Aegis256(Aegis256Key::from_base64(key_b64)?))
            }
            (Some(EncryptionAlgorithm::Aegis256), None) => Err(EncryptionError::MalformedHeader(
                "missing key for 'aegis-256'".to_owned(),
            )),
            (Some(EncryptionAlgorithm::Aes256Gcm), Some(key_b64)) => {
                Ok(Self::Aes256Gcm(Aes256GcmKey::from_base64(key_b64)?))
            }
            (Some(EncryptionAlgorithm::Aes256Gcm), None) => Err(EncryptionError::MalformedHeader(
                "missing key for 'aes-256-gcm'".to_owned(),
            )),
        }
    }
}

impl ParseableHeader for EncryptionConfig {
    fn name() -> &'static HeaderName {
        &S2_ENCRYPTION_HEADER
    }
}

fn parse_algorithm(alg_str: &str) -> Result<Option<EncryptionAlgorithm>, EncryptionError> {
    if alg_str == "none" {
        Ok(None)
    } else {
        alg_str
            .parse::<EncryptionAlgorithm>()
            .map(Some)
            .map_err(|_| {
                EncryptionError::MalformedHeader(format!(
                    "unknown algorithm {alg_str:?}; expected 'none', 'aegis-256', or 'aes-256-gcm'"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use http::header::HeaderValue;

    use super::*;

    const KEY_B64: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

    #[test]
    fn parse_header_valid_aegis() {
        let config = format!("aegis-256; {KEY_B64}")
            .parse::<EncryptionConfig>()
            .unwrap();
        assert!(matches!(config, EncryptionConfig::Aegis256(_)));
    }

    #[test]
    fn parse_header_valid_aes() {
        let config = format!("aes-256-gcm; {KEY_B64}")
            .parse::<EncryptionConfig>()
            .unwrap();
        assert!(matches!(config, EncryptionConfig::Aes256Gcm(_)));
    }

    #[test]
    fn parse_header_valid_with_whitespace() {
        let config = format!(" aes-256-gcm ; {KEY_B64} ")
            .parse::<EncryptionConfig>()
            .unwrap();
        assert!(matches!(config, EncryptionConfig::Aes256Gcm(_)));
    }

    #[test]
    fn parse_header_none_without_key() {
        let config = "none".parse::<EncryptionConfig>().unwrap();
        assert!(matches!(config, EncryptionConfig::None));
    }

    #[test]
    fn parse_header_none_with_empty_key_slot() {
        let config = "none; ".parse::<EncryptionConfig>().unwrap();
        assert!(matches!(config, EncryptionConfig::None));
    }

    #[test]
    fn parse_header_absent() {
        assert!("".parse::<EncryptionConfig>().is_err());
    }

    #[test]
    fn parse_header_malformed_no_semicolon() {
        let result = "aegis-256".parse::<EncryptionConfig>();
        assert!(matches!(result, Err(EncryptionError::MalformedHeader(_))));
    }

    #[test]
    fn parse_header_wrong_key_length() {
        let result = "aegis-256; 3q2+7w==".parse::<EncryptionConfig>();
        assert!(matches!(result, Err(EncryptionError::MalformedHeader(_))));
    }

    #[test]
    fn parse_header_invalid_base64() {
        let result = "aegis-256; not-valid-base64!!!".parse::<EncryptionConfig>();
        assert!(matches!(result, Err(EncryptionError::MalformedHeader(_))));
    }

    #[test]
    fn parse_header_unknown_algorithm_fails() {
        let result = KEY_B64.parse::<EncryptionConfig>();
        assert!(matches!(result, Err(EncryptionError::MalformedHeader(_))));
    }

    #[test]
    fn parse_header_none_with_key_fails() {
        let result = format!("none; {KEY_B64}").parse::<EncryptionConfig>();
        assert!(matches!(result, Err(EncryptionError::MalformedHeader(_))));
    }

    #[test]
    fn header_value_is_sensitive() {
        let value = EncryptionConfig::aegis256([7; 32]).to_header_value();
        assert!(value.is_sensitive());
        assert_ne!(value, HeaderValue::from_static("none"));
    }
}
