//! Server-side record encryption for HIPAA/BAA compliance.
//!
//! The `S2-Encryption` header carries the algorithm and key for each request.
//! The server encrypts on append and decrypts on read; the key never persists
//! beyond the request lifetime.
//!
//! ## Wire format (body of stored EnvelopeRecord)
//!
//! ```text
//! [alg_id: 1 byte] [nonce] [ciphertext] [tag]
//! ```
//!
//! | alg_id | Algorithm   | Nonce  | Tag  |
//! |--------|-------------|--------|------|
//! | 0x01   | AEGIS-256   | 32 B   | 32 B |
//! | 0x02   | AES-256-GCM | 12 B   | 16 B |

use aegis::aegis256::Aegis256;
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use bytes::{BufMut, Bytes, BytesMut};
use http::HeaderMap;
use rand::random;
use secrecy::{CloneableSecret, ExposeSecret, SecretBox};

use crate::record::{Encodable as _, EnvelopeRecord, Header};
pub use crate::types::config::EncryptionAlgorithm;

pub const S2_ENCRYPTION_HEADER: &str = "s2-encryption";

const ALG_ID_AEGIS256: u8 = 0x01;
const ALG_ID_AES256GCM: u8 = 0x02;

const NONCE_BYTES_AEGIS256: usize = 32;
const TAG_BYTES_AEGIS256: usize = 32;

const NONCE_BYTES_AES256GCM: usize = 12;
const TAG_BYTES_AES256GCM: usize = 16;

/// Newtype for a 32-byte encryption key that allows cloning and zeroizes on drop.
#[derive(Clone)]
pub struct KeyBytes(pub [u8; 32]);

impl secrecy::zeroize::Zeroize for KeyBytes {
    fn zeroize(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

impl CloneableSecret for KeyBytes {}

/// A cloneable, debug-redacted wrapper around a 32-byte key.
pub type EncryptionKey = SecretBox<KeyBytes>;

fn make_key(bytes: [u8; 32]) -> EncryptionKey {
    SecretBox::new(Box::new(KeyBytes(bytes)))
}

/// Parsed `S2-Encryption` header directive.
#[derive(Clone, Debug)]
pub enum EncryptionDirective {
    /// Client provides the key; server encrypts/decrypts.
    Key {
        alg: EncryptionAlgorithm,
        key: EncryptionKey,
    },
    /// Client handles encryption itself; server passes bytes through.
    Attest,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum EncryptionError {
    #[error("Malformed S2-Encryption header: {0}")]
    MalformedHeader(String),
    #[error("Algorithm mismatch: stream requires {expected:?}, got {got:?}")]
    AlgorithmMismatch {
        expected: EncryptionAlgorithm,
        got: EncryptionAlgorithm,
    },
    #[error("Encryption required: stream has encryption={0:?} but no key was provided")]
    EncryptionRequired(EncryptionAlgorithm),
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Record encoding error: {0}")]
    EncodingFailed(String),
}

/// Parse the `S2-Encryption` header value.
///
/// Returns:
/// - `Ok(None)` if the header is absent.
/// - `Ok(Some(directive))` on a valid header.
/// - `Err` if the header is present but malformed.
pub fn parse_s2_encryption_header(
    headers: &HeaderMap,
) -> Result<Option<EncryptionDirective>, EncryptionError> {
    let value = match headers.get(S2_ENCRYPTION_HEADER) {
        Some(v) => v,
        None => return Ok(None),
    };

    let s = value
        .to_str()
        .map_err(|_| EncryptionError::MalformedHeader("header is not valid UTF-8".to_owned()))?;

    // "attest" → client-side encryption, server passes through.
    if s.trim() == "attest" {
        return Ok(Some(EncryptionDirective::Attest));
    }

    // "alg=<name>; key=<64 hex chars>"
    let (alg_part, key_part) = s.split_once(';').ok_or_else(|| {
        EncryptionError::MalformedHeader(format!("expected 'alg=...; key=...', got {s:?}"))
    })?;

    let alg_str = alg_part
        .trim()
        .strip_prefix("alg=")
        .ok_or_else(|| {
            EncryptionError::MalformedHeader(format!("expected 'alg=...', got {alg_part:?}"))
        })?
        .trim();

    let key_hex = key_part
        .trim()
        .strip_prefix("key=")
        .ok_or_else(|| {
            EncryptionError::MalformedHeader(format!("expected 'key=...', got {key_part:?}"))
        })?
        .trim();

    let alg = match alg_str {
        "aegis-256" => EncryptionAlgorithm::Aegis256,
        "aes-256-gcm" => EncryptionAlgorithm::Aes256Gcm,
        other => {
            return Err(EncryptionError::MalformedHeader(format!(
                "unknown algorithm {other:?}; expected 'aegis-256' or 'aes-256-gcm'"
            )));
        }
    };

    if key_hex.len() != 64 {
        return Err(EncryptionError::MalformedHeader(format!(
            "key must be 64 hex characters (32 bytes), got {} characters",
            key_hex.len()
        )));
    }

    let key_bytes: Vec<u8> = hex::decode(key_hex)
        .map_err(|e| EncryptionError::MalformedHeader(format!("key is not valid hex: {e}")))?;

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| EncryptionError::MalformedHeader("key must be exactly 32 bytes".to_owned()))?;

    Ok(Some(EncryptionDirective::Key {
        alg,
        key: make_key(key_array),
    }))
}

/// Validate the directive against the stream's configured encryption algorithm.
///
/// Returns:
/// - `Ok(None)` if the stream has no encryption configured (pass-through).
/// - `Ok(Some(directive))` if encryption should proceed.
/// - `Err(EncryptionRequired)` if the stream requires encryption but none was provided.
/// - `Err(AlgorithmMismatch)` if the algorithms differ.
pub fn check_encryption_directive<'a>(
    stream_alg: Option<EncryptionAlgorithm>,
    directive: Option<&'a EncryptionDirective>,
) -> Result<Option<&'a EncryptionDirective>, EncryptionError> {
    let Some(required_alg) = stream_alg else {
        // Stream has no encryption: ignore any directive.
        return Ok(None);
    };

    match directive {
        None => Err(EncryptionError::EncryptionRequired(required_alg)),
        Some(EncryptionDirective::Attest) => Ok(directive),
        Some(EncryptionDirective::Key { alg, .. }) => {
            if *alg != required_alg {
                return Err(EncryptionError::AlgorithmMismatch {
                    expected: required_alg,
                    got: *alg,
                });
            }
            Ok(directive)
        }
    }
}

/// Encode headers + body as `EnvelopeRecord` bytes (the plaintext input to encryption).
pub fn encode_record_plaintext(
    headers: Vec<Header>,
    body: Bytes,
) -> Result<Bytes, EncryptionError> {
    EnvelopeRecord::try_from_parts(headers, body)
        .map(|r| r.to_bytes())
        .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))
}

/// Decode `EnvelopeRecord` bytes back to `(headers, body)` after decryption.
pub fn decode_record_plaintext(bytes: Bytes) -> Result<(Vec<Header>, Bytes), EncryptionError> {
    EnvelopeRecord::try_from(bytes)
        .map(|r| r.into_parts())
        .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))
}

/// Encrypt a record.
///
/// Output layout: `[alg_id][random_nonce][ciphertext][tag]` as contiguous `Bytes`.
pub fn encrypt_record(
    plaintext: &[u8],
    alg: EncryptionAlgorithm,
    key: &EncryptionKey,
    aad: &[u8],
) -> Result<Bytes, EncryptionError> {
    match alg {
        EncryptionAlgorithm::Aegis256 => {
            let nonce: [u8; NONCE_BYTES_AEGIS256] = random();
            let (ciphertext, tag) =
                Aegis256::<TAG_BYTES_AEGIS256>::new(&key.expose_secret().0, &nonce)
                    .encrypt(plaintext, aad);

            let mut out = BytesMut::with_capacity(
                1 + NONCE_BYTES_AEGIS256 + ciphertext.len() + TAG_BYTES_AEGIS256,
            );
            out.put_u8(ALG_ID_AEGIS256);
            out.put_slice(&nonce);
            out.put_slice(&ciphertext);
            out.put_slice(&tag);
            Ok(out.freeze())
        }
        EncryptionAlgorithm::Aes256Gcm => {
            let nonce: [u8; NONCE_BYTES_AES256GCM] = random();
            let cipher = Aes256Gcm::new_from_slice(&key.expose_secret().0).map_err(|_| {
                EncryptionError::EncodingFailed("invalid AES key length".to_owned())
            })?;
            let nonce_generic = aes_gcm::Nonce::from_slice(&nonce);
            // aes-gcm appends the 16-byte tag to the ciphertext automatically.
            let ciphertext_with_tag = cipher
                .encrypt(
                    nonce_generic,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| EncryptionError::DecryptionFailed)?;

            let mut out =
                BytesMut::with_capacity(1 + NONCE_BYTES_AES256GCM + ciphertext_with_tag.len());
            out.put_u8(ALG_ID_AES256GCM);
            out.put_slice(&nonce);
            out.put_slice(&ciphertext_with_tag);
            Ok(out.freeze())
        }
        EncryptionAlgorithm::None => Err(EncryptionError::EncodingFailed(
            "cannot encrypt with None algorithm".to_owned(),
        )),
    }
}

/// Decrypt a record body.
///
/// Returns:
/// - `Ok(Some(plaintext))` on success.
/// - `Ok(None)` if the first byte is not a known `alg_id` (unencrypted pass-through).
/// - `Err` on auth tag failure, truncation, or other error.
pub fn decrypt_record(
    body: &[u8],
    key: &EncryptionKey,
    aad: &[u8],
) -> Result<Option<Bytes>, EncryptionError> {
    let alg_id = match body.first() {
        Some(&b) => b,
        None => return Ok(None),
    };

    match alg_id {
        ALG_ID_AEGIS256 => {
            // Layout after alg_id: [nonce:32][ciphertext:n][tag:32]
            let rest = &body[1..];
            if rest.len() < NONCE_BYTES_AEGIS256 + TAG_BYTES_AEGIS256 {
                return Err(EncryptionError::DecryptionFailed);
            }
            let nonce: &[u8; NONCE_BYTES_AEGIS256] =
                rest[..NONCE_BYTES_AEGIS256].try_into().unwrap();
            let after_nonce = &rest[NONCE_BYTES_AEGIS256..];
            if after_nonce.len() < TAG_BYTES_AEGIS256 {
                return Err(EncryptionError::DecryptionFailed);
            }
            let tag_offset = after_nonce.len() - TAG_BYTES_AEGIS256;
            let ciphertext = &after_nonce[..tag_offset];
            let tag: &[u8; TAG_BYTES_AEGIS256] = after_nonce[tag_offset..].try_into().unwrap();

            let plaintext = Aegis256::<TAG_BYTES_AEGIS256>::new(&key.expose_secret().0, nonce)
                .decrypt(ciphertext, tag, aad)
                .map_err(|_| EncryptionError::DecryptionFailed)?;
            Ok(Some(Bytes::from(plaintext)))
        }
        ALG_ID_AES256GCM => {
            // Layout after alg_id: [nonce:12][ciphertext+tag:n+16]
            let rest = &body[1..];
            if rest.len() < NONCE_BYTES_AES256GCM + TAG_BYTES_AES256GCM {
                return Err(EncryptionError::DecryptionFailed);
            }
            let (nonce_bytes, ciphertext_with_tag) = rest.split_at(NONCE_BYTES_AES256GCM);
            let cipher = Aes256Gcm::new_from_slice(&key.expose_secret().0).map_err(|_| {
                EncryptionError::EncodingFailed("invalid AES key length".to_owned())
            })?;
            let nonce_generic = aes_gcm::Nonce::from_slice(nonce_bytes);
            let plaintext = cipher
                .decrypt(
                    nonce_generic,
                    Payload {
                        msg: ciphertext_with_tag,
                        aad,
                    },
                )
                .map_err(|_| EncryptionError::DecryptionFailed)?;
            Ok(Some(Bytes::from(plaintext)))
        }
        // Unknown first byte: not encrypted by S2, pass through.
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key_fn() -> EncryptionKey {
        make_key([0x42u8; 32])
    }

    fn make_wrong_key_fn() -> EncryptionKey {
        make_key([0x99u8; 32])
    }

    const AAD: &[u8] = b"test-basin/test-stream";

    fn roundtrip(alg: EncryptionAlgorithm) {
        let headers = vec![Header {
            name: Bytes::from_static(b"x-test"),
            value: Bytes::from_static(b"hello"),
        }];
        let body = Bytes::from_static(b"secret payload");

        let plaintext = encode_record_plaintext(headers.clone(), body.clone()).unwrap();
        let key = make_key_fn();
        let ciphertext = encrypt_record(&plaintext, alg, &key, AAD).unwrap();
        let decrypted = decrypt_record(&ciphertext, &key, AAD).unwrap().unwrap();
        let (out_headers, out_body) = decode_record_plaintext(decrypted).unwrap();

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
    fn wrong_key_fails_aegis256() {
        let plaintext = encode_record_plaintext(vec![], Bytes::from_static(b"data")).unwrap();
        let key = make_key_fn();
        let ciphertext =
            encrypt_record(&plaintext, EncryptionAlgorithm::Aegis256, &key, AAD).unwrap();
        let result = decrypt_record(&ciphertext, &make_wrong_key_fn(), AAD);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn wrong_key_fails_aes256gcm() {
        let plaintext = encode_record_plaintext(vec![], Bytes::from_static(b"data")).unwrap();
        let key = make_key_fn();
        let ciphertext =
            encrypt_record(&plaintext, EncryptionAlgorithm::Aes256Gcm, &key, AAD).unwrap();
        let result = decrypt_record(&ciphertext, &make_wrong_key_fn(), AAD);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn truncated_ciphertext_fails_no_panic() {
        let plaintext = encode_record_plaintext(vec![], Bytes::from_static(b"data")).unwrap();
        let key = make_key_fn();
        let ciphertext =
            encrypt_record(&plaintext, EncryptionAlgorithm::Aegis256, &key, AAD).unwrap();
        // Truncate to 3 bytes — too short to contain nonce+tag.
        let truncated = &ciphertext[..3];
        let result = decrypt_record(truncated, &key, AAD);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn unknown_first_byte_passthrough() {
        // First byte 0x00 is not a known alg_id.
        let body = b"\x00some opaque bytes";
        let key = make_key_fn();
        let result = decrypt_record(body, &key, AAD).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn empty_body_passthrough() {
        let key = make_key_fn();
        let result = decrypt_record(b"", &key, AAD).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_header_valid_aegis() {
        let mut headers = HeaderMap::new();
        headers.insert(
            S2_ENCRYPTION_HEADER,
            http::HeaderValue::from_static(
                "alg=aegis-256; key=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            ),
        );
        let directive = parse_s2_encryption_header(&headers).unwrap().unwrap();
        assert!(matches!(
            directive,
            EncryptionDirective::Key {
                alg: EncryptionAlgorithm::Aegis256,
                ..
            }
        ));
    }

    #[test]
    fn parse_header_valid_aes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            S2_ENCRYPTION_HEADER,
            http::HeaderValue::from_static(
                "alg=aes-256-gcm; key=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            ),
        );
        let directive = parse_s2_encryption_header(&headers).unwrap().unwrap();
        assert!(matches!(
            directive,
            EncryptionDirective::Key {
                alg: EncryptionAlgorithm::Aes256Gcm,
                ..
            }
        ));
    }

    #[test]
    fn parse_header_attest() {
        let mut headers = HeaderMap::new();
        headers.insert(
            S2_ENCRYPTION_HEADER,
            http::HeaderValue::from_static("attest"),
        );
        let directive = parse_s2_encryption_header(&headers).unwrap().unwrap();
        assert!(matches!(directive, EncryptionDirective::Attest));
    }

    #[test]
    fn parse_header_absent() {
        let headers = HeaderMap::new();
        let result = parse_s2_encryption_header(&headers).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_header_malformed_no_semicolon() {
        let mut headers = HeaderMap::new();
        headers.insert(
            S2_ENCRYPTION_HEADER,
            http::HeaderValue::from_static("alg=aegis-256"),
        );
        let result = parse_s2_encryption_header(&headers);
        assert!(matches!(result, Err(EncryptionError::MalformedHeader(_))));
    }

    #[test]
    fn parse_header_wrong_key_length() {
        let mut headers = HeaderMap::new();
        headers.insert(
            S2_ENCRYPTION_HEADER,
            http::HeaderValue::from_static("alg=aegis-256; key=deadbeef"),
        );
        let result = parse_s2_encryption_header(&headers);
        assert!(matches!(result, Err(EncryptionError::MalformedHeader(_))));
    }

    #[test]
    fn parse_header_invalid_hex() {
        let mut headers = HeaderMap::new();
        headers.insert(
            S2_ENCRYPTION_HEADER,
            http::HeaderValue::from_static(
                "alg=aegis-256; key=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            ),
        );
        let result = parse_s2_encryption_header(&headers);
        assert!(matches!(result, Err(EncryptionError::MalformedHeader(_))));
    }

    #[test]
    fn check_directive_alg_mismatch() {
        let key = make_key_fn();
        let directive = EncryptionDirective::Key {
            alg: EncryptionAlgorithm::Aes256Gcm,
            key,
        };
        let result =
            check_encryption_directive(Some(EncryptionAlgorithm::Aegis256), Some(&directive));
        assert!(matches!(
            result,
            Err(EncryptionError::AlgorithmMismatch { .. })
        ));
    }

    #[test]
    fn check_directive_required_but_absent() {
        let result = check_encryption_directive(Some(EncryptionAlgorithm::Aegis256), None);
        assert!(matches!(
            result,
            Err(EncryptionError::EncryptionRequired(_))
        ));
    }

    #[test]
    fn check_directive_no_stream_encryption() {
        let key = make_key_fn();
        let directive = EncryptionDirective::Key {
            alg: EncryptionAlgorithm::Aegis256,
            key,
        };
        let result = check_encryption_directive(None, Some(&directive));
        assert!(result.unwrap().is_none());
    }
}
