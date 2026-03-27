//! # Record encryption format
//!
//! AAD = stream_id bytes
//!
//! ```text
//! [version: 1 byte] [alg_id: 1 byte] [nonce] [ciphertext] [tag]
//! ```
//!
//! | alg_id | Algorithm   | Nonce  | Tag  |
//! |--------|-------------|--------|------|
//! | 0x01   | AEGIS-256   | 32 B   | 32 B |
//! | 0x02   | AES-256-GCM | 12 B   | 16 B |

use core::str::FromStr;

use aegis::aegis256::Aegis256;
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use bytes::{BufMut, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue};
use rand::random;
use secrecy::{CloneableSecret, ExposeSecret, SecretBox};

pub use crate::types::config::EncryptionAlgorithm;
use crate::{
    bash::Bash,
    record::{self, Encodable as _, EnvelopeRecord, Header, Metered, Record},
    types::{
        self,
        stream::{AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts},
    },
};

pub const S2_ENCRYPTION_HEADER: &str = "s2-encryption";

const CIPHERTEXT_V1: u8 = 0x01;

const ALG_ID_AEGIS256: u8 = 0x01;
const ALG_ID_AES256GCM: u8 = 0x02;

const NONCE_BYTES_AEGIS256: usize = 32;
const TAG_BYTES_AEGIS256: usize = 32;

const NONCE_BYTES_AES256GCM: usize = 12;
const TAG_BYTES_AES256GCM: usize = 16;

#[derive(Clone)]
pub struct KeyBytes(pub [u8; 32]);

impl secrecy::zeroize::Zeroize for KeyBytes {
    fn zeroize(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

impl CloneableSecret for KeyBytes {}

pub type EncryptionKey = SecretBox<KeyBytes>;

fn make_key(bytes: [u8; 32]) -> EncryptionKey {
    SecretBox::new(Box::new(KeyBytes(bytes)))
}

/// Parsed `s2-encryption` request directive.
#[derive(Clone, Debug)]
pub enum EncryptionDirective {
    /// Encrypt and decrypt record bodies with the provided AEAD algorithm and key.
    Key {
        /// AEAD algorithm to use.
        alg: EncryptionAlgorithm,
        /// 32-byte symmetric key.
        key: EncryptionKey,
    },
    /// Use attestation-based encryption mode instead of a caller-supplied key.
    Attest,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum EncryptionError {
    #[error("Malformed S2-Encryption header: {0}")]
    MalformedHeader(String),
    #[error("Unsupported ciphertext version: {0:#04x}")]
    UnsupportedVersion(u8),
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Record encoding error: {0}")]
    EncodingFailed(String),
}

impl TryFrom<&HeaderValue> for EncryptionDirective {
    type Error = EncryptionError;

    fn try_from(value: &HeaderValue) -> Result<Self, Self::Error> {
        value
            .to_str()
            .map_err(|_| EncryptionError::MalformedHeader("header is not valid UTF-8".to_owned()))?
            .parse()
    }
}

impl FromStr for EncryptionDirective {
    type Err = EncryptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s == "attest" {
            return Ok(Self::Attest);
        }

        let mut alg_str = None;
        let mut key_hex = None;
        for part in s.split(';') {
            let (name, value) = part.split_once('=').ok_or_else(|| {
                EncryptionError::MalformedHeader("expected 'alg=...; key=...'".to_owned())
            })?;
            let name = name.trim();
            let value = value.trim();
            match name {
                "alg" => {
                    if alg_str.replace(value).is_some() {
                        return Err(EncryptionError::MalformedHeader(
                            "duplicate 'alg=' parameter".to_owned(),
                        ));
                    }
                }
                "key" => {
                    if key_hex.replace(value).is_some() {
                        return Err(EncryptionError::MalformedHeader(
                            "duplicate 'key=' parameter".to_owned(),
                        ));
                    }
                }
                _ => {
                    return Err(EncryptionError::MalformedHeader(format!(
                        "unknown parameter {name:?}; expected 'alg' or 'key'"
                    )));
                }
            }
        }

        let alg_str = alg_str.ok_or_else(|| {
            EncryptionError::MalformedHeader("missing 'alg=' parameter".to_owned())
        })?;
        let key_hex = key_hex.ok_or_else(|| {
            EncryptionError::MalformedHeader("missing 'key=' parameter".to_owned())
        })?;
        let alg: EncryptionAlgorithm = alg_str.parse().map_err(|_| {
            EncryptionError::MalformedHeader(format!(
                "unknown algorithm {alg_str:?}; expected 'aegis-256' or 'aes-256-gcm'"
            ))
        })?;
        let key = parse_encryption_key(key_hex)?;
        Ok(Self::Key { alg, key })
    }
}

pub fn parse_s2_encryption_header(
    headers: &HeaderMap,
) -> Result<Option<EncryptionDirective>, EncryptionError> {
    headers
        .get(S2_ENCRYPTION_HEADER)
        .map(EncryptionDirective::try_from)
        .transpose()
}

fn parse_encryption_key(key_hex: &str) -> Result<EncryptionKey, EncryptionError> {
    if key_hex.len() != 64 {
        return Err(EncryptionError::MalformedHeader(format!(
            "key must be 64 hex characters (32 bytes), got {} characters",
            key_hex.len()
        )));
    }

    let mut key_bytes: Vec<u8> = hex::decode(key_hex)
        .map_err(|e| EncryptionError::MalformedHeader(format!("key is not valid hex: {e}")))?;

    let key_array: [u8; 32] = match key_bytes.as_slice().try_into() {
        Ok(arr) => {
            secrecy::zeroize::Zeroize::zeroize(&mut key_bytes);
            arr
        }
        Err(_) => {
            secrecy::zeroize::Zeroize::zeroize(&mut key_bytes);
            return Err(EncryptionError::MalformedHeader(
                "key must be exactly 32 bytes".to_owned(),
            ));
        }
    };
    Ok(make_key(key_array))
}

pub fn encode_record_plaintext(
    headers: Vec<Header>,
    body: Bytes,
) -> Result<Bytes, EncryptionError> {
    EnvelopeRecord::try_from_parts(headers, body)
        .map(|r| r.to_bytes())
        .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))
}

pub fn decode_record_plaintext(bytes: Bytes) -> Result<(Vec<Header>, Bytes), EncryptionError> {
    EnvelopeRecord::try_from(bytes)
        .map(|r| r.into_parts())
        .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))
}

pub fn stream_id_aad(
    basin: &(impl AsRef<[u8]> + ?Sized),
    stream: &(impl AsRef<[u8]> + ?Sized),
) -> [u8; 32] {
    *Bash::delimited(&[basin.as_ref(), stream.as_ref()], 0).as_bytes()
}

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
                2 + NONCE_BYTES_AEGIS256 + ciphertext.len() + TAG_BYTES_AEGIS256,
            );
            out.put_u8(CIPHERTEXT_V1);
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
            let ciphertext_with_tag = cipher
                .encrypt(
                    nonce_generic,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| {
                    EncryptionError::EncodingFailed("AES-256-GCM encryption failed".to_owned())
                })?;

            let mut out =
                BytesMut::with_capacity(2 + NONCE_BYTES_AES256GCM + ciphertext_with_tag.len());
            out.put_u8(CIPHERTEXT_V1);
            out.put_u8(ALG_ID_AES256GCM);
            out.put_slice(&nonce);
            out.put_slice(&ciphertext_with_tag);
            Ok(out.freeze())
        }
    }
}

pub fn decrypt_record(
    body: &[u8],
    key: &EncryptionKey,
    aad: &[u8],
) -> Result<Bytes, EncryptionError> {
    let (&version, after_version) = body
        .split_first()
        .ok_or(EncryptionError::DecryptionFailed)?;

    match version {
        CIPHERTEXT_V1 => decrypt_record_v1(after_version, key, aad),
        v => Err(EncryptionError::UnsupportedVersion(v)),
    }
}

fn decrypt_record_v1(
    body: &[u8],
    key: &EncryptionKey,
    aad: &[u8],
) -> Result<Bytes, EncryptionError> {
    let (&alg_id, rest) = body
        .split_first()
        .ok_or(EncryptionError::DecryptionFailed)?;

    match alg_id {
        ALG_ID_AEGIS256 => {
            if rest.len() < NONCE_BYTES_AEGIS256 + TAG_BYTES_AEGIS256 {
                return Err(EncryptionError::DecryptionFailed);
            }
            let nonce: &[u8; NONCE_BYTES_AEGIS256] =
                rest[..NONCE_BYTES_AEGIS256].try_into().unwrap();
            let after_nonce = &rest[NONCE_BYTES_AEGIS256..];
            let tag_offset = after_nonce.len() - TAG_BYTES_AEGIS256;
            let ciphertext = &after_nonce[..tag_offset];
            let tag: &[u8; TAG_BYTES_AEGIS256] = after_nonce[tag_offset..].try_into().unwrap();

            let plaintext = Aegis256::<TAG_BYTES_AEGIS256>::new(&key.expose_secret().0, nonce)
                .decrypt(ciphertext, tag, aad)
                .map_err(|_| EncryptionError::DecryptionFailed)?;
            Ok(Bytes::from(plaintext))
        }
        ALG_ID_AES256GCM => {
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
            Ok(Bytes::from(plaintext))
        }
        _ => Err(EncryptionError::DecryptionFailed),
    }
}

pub fn encrypt_append_input(
    input: AppendInput,
    alg: EncryptionAlgorithm,
    key: &EncryptionKey,
    aad: &[u8],
) -> Result<AppendInput, EncryptionError> {
    let encrypted_records: Vec<AppendRecord> = input
        .records
        .into_iter()
        .map(|record| {
            let AppendRecordParts {
                timestamp,
                record: metered_record,
            } = record.into();
            let inner_record = metered_record.into_inner();
            let encrypted = match &inner_record {
                Record::Envelope(env) => {
                    let plaintext =
                        encode_record_plaintext(env.headers().to_vec(), env.body().clone())?;
                    let enc_body = encrypt_record(&plaintext, alg, key, aad)?;
                    Record::try_from_parts(vec![], enc_body)
                        .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))?
                }
                Record::Command(_) => inner_record,
            };
            AppendRecordParts {
                timestamp,
                record: Metered::from(encrypted),
            }
            .try_into()
            .map_err(|e: &str| EncryptionError::EncodingFailed(e.to_owned()))
        })
        .collect::<Result<_, EncryptionError>>()?;

    let records: AppendRecordBatch = encrypted_records
        .try_into()
        .map_err(|e: &str| EncryptionError::EncodingFailed(e.to_owned()))?;

    Ok(AppendInput {
        records,
        match_seq_num: input.match_seq_num,
        fencing_token: input.fencing_token,
    })
}

pub fn decrypt_read_batch(
    batch: types::stream::ReadBatch,
    directive: Option<&EncryptionDirective>,
    aad: &[u8],
) -> Result<types::stream::ReadBatch, EncryptionError> {
    let Some(EncryptionDirective::Key { key, .. }) = directive else {
        return Ok(batch);
    };
    let records: Vec<record::SequencedRecord> = batch
        .records
        .into_inner()
        .into_iter()
        .map(|sr| {
            let record::Record::Envelope(ref env) = sr.record else {
                return Ok(sr);
            };
            let plaintext = decrypt_record(env.body(), key, aad)?;
            let (headers, body) = decode_record_plaintext(plaintext)?;
            let record = record::Record::try_from_parts(headers, body)
                .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))?;
            Ok(record::SequencedRecord {
                position: sr.position,
                record,
            })
        })
        .collect::<Result<_, EncryptionError>>()?;
    Ok(types::stream::ReadBatch {
        records: record::Metered::from(records),
        tail: batch.tail,
    })
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

    fn test_aad() -> [u8; 32] {
        stream_id_aad("test-basin", "test-stream")
    }

    fn roundtrip(alg: EncryptionAlgorithm) {
        let headers = vec![Header {
            name: Bytes::from_static(b"x-test"),
            value: Bytes::from_static(b"hello"),
        }];
        let body = Bytes::from_static(b"secret payload");

        let aad = test_aad();
        let plaintext = encode_record_plaintext(headers.clone(), body.clone()).unwrap();
        let key = make_key_fn();
        let ciphertext = encrypt_record(&plaintext, alg, &key, &aad).unwrap();
        let decrypted = decrypt_record(&ciphertext, &key, &aad).unwrap();
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
        let aad = test_aad();
        let plaintext = encode_record_plaintext(vec![], Bytes::from_static(b"data")).unwrap();
        let key = make_key_fn();
        let ciphertext =
            encrypt_record(&plaintext, EncryptionAlgorithm::Aegis256, &key, &aad).unwrap();
        let result = decrypt_record(&ciphertext, &make_wrong_key_fn(), &aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn wrong_key_fails_aes256gcm() {
        let aad = test_aad();
        let plaintext = encode_record_plaintext(vec![], Bytes::from_static(b"data")).unwrap();
        let key = make_key_fn();
        let ciphertext =
            encrypt_record(&plaintext, EncryptionAlgorithm::Aes256Gcm, &key, &aad).unwrap();
        let result = decrypt_record(&ciphertext, &make_wrong_key_fn(), &aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn truncated_ciphertext_fails_no_panic() {
        let aad = test_aad();
        let plaintext = encode_record_plaintext(vec![], Bytes::from_static(b"data")).unwrap();
        let key = make_key_fn();
        let ciphertext =
            encrypt_record(&plaintext, EncryptionAlgorithm::Aegis256, &key, &aad).unwrap();
        let truncated = &ciphertext[..4];
        let result = decrypt_record(truncated, &key, &aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn unsupported_version_fails() {
        let aad = test_aad();
        let key = make_key_fn();
        let body = b"\xFFsome opaque bytes";
        let result = decrypt_record(body, &key, &aad);
        assert!(matches!(
            result,
            Err(EncryptionError::UnsupportedVersion(0xFF))
        ));
    }

    #[test]
    fn empty_body_fails() {
        let aad = test_aad();
        let key = make_key_fn();
        let result = decrypt_record(b"", &key, &aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn version_byte_present() {
        let aad = test_aad();
        let plaintext = encode_record_plaintext(vec![], Bytes::from_static(b"data")).unwrap();
        let key = make_key_fn();
        let ciphertext =
            encrypt_record(&plaintext, EncryptionAlgorithm::Aegis256, &key, &aad).unwrap();
        assert_eq!(ciphertext[0], CIPHERTEXT_V1);
        assert_eq!(ciphertext[1], ALG_ID_AEGIS256);
    }

    #[test]
    fn alg_id_flip_detected() {
        let aad = test_aad();
        let plaintext = encode_record_plaintext(vec![], Bytes::from_static(b"data")).unwrap();
        let key = make_key_fn();
        let mut ciphertext = encrypt_record(&plaintext, EncryptionAlgorithm::Aegis256, &key, &aad)
            .unwrap()
            .to_vec();
        assert_eq!(ciphertext[0], CIPHERTEXT_V1);
        assert_eq!(ciphertext[1], ALG_ID_AEGIS256);
        ciphertext[1] = ALG_ID_AES256GCM;
        let result = decrypt_record(&ciphertext, &key, &aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn version_flip_detected() {
        let aad = test_aad();
        let plaintext = encode_record_plaintext(vec![], Bytes::from_static(b"data")).unwrap();
        let key = make_key_fn();
        let mut ciphertext = encrypt_record(&plaintext, EncryptionAlgorithm::Aegis256, &key, &aad)
            .unwrap()
            .to_vec();
        ciphertext[0] = 0x02;
        let result = decrypt_record(&ciphertext, &key, &aad);
        assert!(matches!(
            result,
            Err(EncryptionError::UnsupportedVersion(0x02))
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let aad = test_aad();
        let other_aad = stream_id_aad("other-basin", "other-stream");
        let plaintext = encode_record_plaintext(vec![], Bytes::from_static(b"data")).unwrap();
        let key = make_key_fn();
        let ciphertext =
            encrypt_record(&plaintext, EncryptionAlgorithm::Aegis256, &key, &aad).unwrap();
        let result = decrypt_record(&ciphertext, &key, &other_aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
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
    fn parse_header_valid_reordered_params() {
        let mut headers = HeaderMap::new();
        headers.insert(
            S2_ENCRYPTION_HEADER,
            http::HeaderValue::from_static(
                "key=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20; alg=aes-256-gcm",
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
}
