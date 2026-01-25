use std::fmt;

use p256::{
    EncodedPoint, PublicKey, SecretKey,
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::sec1::FromEncodedPoint,
};

/// P-256 private key for signing
#[derive(Clone)]
pub struct RootKey {
    inner: SigningKey,
}

impl RootKey {
    /// Parse from base58-encoded 32-byte scalar
    pub fn from_base58(s: &str) -> Result<Self, KeyError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| KeyError::Base58Decode(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let secret =
            SecretKey::from_slice(&bytes).map_err(|e| KeyError::InvalidKey(e.to_string()))?;
        Ok(Self {
            inner: SigningKey::from(secret),
        })
    }

    /// Get the signing key for Biscuit/ECDSA operations
    pub fn signing_key(&self) -> &SigningKey {
        &self.inner
    }

    /// Derive the public key
    pub fn public_key(&self) -> RootPublicKey {
        RootPublicKey {
            inner: *self.inner.verifying_key(),
        }
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootKey").finish_non_exhaustive()
    }
}

/// P-256 public key (compressed, base58)
#[derive(Clone, PartialEq, Eq)]
pub struct RootPublicKey {
    inner: VerifyingKey,
}

impl RootPublicKey {
    /// Parse from base58-encoded compressed point (33 bytes)
    pub fn from_base58(s: &str) -> Result<Self, KeyError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| KeyError::Base58Decode(e.to_string()))?;
        if bytes.len() != 33 {
            return Err(KeyError::InvalidLength {
                expected: 33,
                got: bytes.len(),
            });
        }
        let point =
            EncodedPoint::from_bytes(&bytes).map_err(|e| KeyError::InvalidKey(e.to_string()))?;
        let public = PublicKey::from_encoded_point(&point)
            .into_option()
            .ok_or_else(|| KeyError::InvalidKey("invalid point".into()))?;
        Ok(Self {
            inner: VerifyingKey::from(public),
        })
    }

    /// Encode as base58 compressed point
    pub fn to_base58(&self) -> String {
        let point = self.inner.to_encoded_point(true); // compressed
        bs58::encode(point.as_bytes()).into_string()
    }

    /// Get the verifying key for signature verification
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.inner
    }

    /// Create from a VerifyingKey directly
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self { inner: *key }
    }
}

impl fmt::Debug for RootPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RootPublicKey")
            .field(&self.to_base58())
            .finish()
    }
}

impl fmt::Display for RootPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Client public key (same format as RootPublicKey but semantically different)
pub type ClientPublicKey = RootPublicKey;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("base58 decode error: {0}")]
    Base58Decode(String),
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("invalid key: {0}")]
    InvalidKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_key_roundtrip() {
        use p256::elliptic_curve::rand_core::OsRng;

        let secret = SecretKey::random(&mut OsRng);
        let bytes = secret.to_bytes();
        let base58 = bs58::encode(&bytes).into_string();

        let root_key = RootKey::from_base58(&base58).expect("should parse");
        let public_key = root_key.public_key();

        let pub_base58 = public_key.to_base58();
        let parsed = RootPublicKey::from_base58(&pub_base58).expect("should parse");
        assert_eq!(public_key, parsed);
    }

    #[test]
    fn test_root_key_invalid_length() {
        let short = bs58::encode(&[0u8; 16]).into_string();
        let err = RootKey::from_base58(&short).unwrap_err();
        assert!(matches!(
            err,
            KeyError::InvalidLength {
                expected: 32,
                got: 16
            }
        ));
    }

    #[test]
    fn test_public_key_invalid_length() {
        let short = bs58::encode(&[0u8; 32]).into_string();
        let err = RootPublicKey::from_base58(&short).unwrap_err();
        assert!(matches!(err, KeyError::InvalidLength { expected: 33, .. }));
    }

    #[test]
    fn test_base58_decode_error() {
        let err = RootKey::from_base58("invalid!@#$").unwrap_err();
        assert!(matches!(err, KeyError::Base58Decode(_)));
    }
}
