use aegis::aegis256::Aegis256;
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use bytes::Bytes;
use rand::random;

use super::{EncryptionAlgorithm, EncryptionConfig, EncryptionError};
use crate::record::EncryptedRecord;

fn encrypt_payload_with_algorithm(
    plaintext: &[u8],
    alg: EncryptionAlgorithm,
    key: &[u8; 32],
    aad: &[u8],
) -> Result<EncryptedRecord, EncryptionError> {
    match alg {
        EncryptionAlgorithm::Aegis256 => {
            let nonce: [u8; 32] = random();
            let (ciphertext, tag) = Aegis256::<32>::new(key, &nonce).encrypt(plaintext, aad);

            EncryptedRecord::try_from_parts(EncryptionAlgorithm::Aegis256, nonce, ciphertext, tag)
                .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))
        }
        EncryptionAlgorithm::Aes256Gcm => {
            let nonce: [u8; 12] = random();
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
                EncryptionError::EncodingFailed("invalid AES key length".to_owned())
            })?;
            let nonce_generic = aes_gcm::Nonce::from_slice(&nonce);
            let mut ciphertext_with_tag = cipher
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
            let tag_offset = ciphertext_with_tag.len().checked_sub(16).ok_or(
                EncryptionError::EncodingFailed(
                    "AES-256-GCM encryption produced a short tag".to_owned(),
                ),
            )?;
            let tag = ciphertext_with_tag.split_off(tag_offset);

            EncryptedRecord::try_from_parts(
                EncryptionAlgorithm::Aes256Gcm,
                nonce,
                ciphertext_with_tag,
                tag,
            )
            .map_err(|e| EncryptionError::EncodingFailed(e.to_string()))
        }
    }
}

pub(crate) fn encrypt_payload(
    plaintext: &[u8],
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<EncryptedRecord, EncryptionError> {
    match encryption {
        EncryptionConfig::None => Err(EncryptionError::EncodingFailed(
            "cannot encrypt with 'alg=none'".to_owned(),
        )),
        EncryptionConfig::Aegis256(key) => encrypt_payload_with_algorithm(
            plaintext,
            EncryptionAlgorithm::Aegis256,
            key.secret(),
            aad,
        ),
        EncryptionConfig::Aes256Gcm(key) => encrypt_payload_with_algorithm(
            plaintext,
            EncryptionAlgorithm::Aes256Gcm,
            key.secret(),
            aad,
        ),
    }
}

pub(crate) fn decrypt_payload(
    record: &EncryptedRecord,
    encryption: &EncryptionConfig,
    aad: &[u8],
) -> Result<Bytes, EncryptionError> {
    match (encryption, record.algorithm()) {
        (EncryptionConfig::None, _) => Err(EncryptionError::UnexpectedEncryptedRecord),
        (EncryptionConfig::Aegis256(key), EncryptionAlgorithm::Aegis256) => {
            let nonce: &[u8; 32] = record.nonce().try_into().unwrap();
            let tag: &[u8; 32] = record.tag().try_into().unwrap();

            let plaintext = Aegis256::<32>::new(key.secret(), nonce)
                .decrypt(record.ciphertext(), tag, aad)
                .map_err(|_| EncryptionError::DecryptionFailed)?;
            Ok(Bytes::from(plaintext))
        }
        (EncryptionConfig::Aes256Gcm(key), EncryptionAlgorithm::Aes256Gcm) => {
            let cipher = Aes256Gcm::new_from_slice(key.secret()).map_err(|_| {
                EncryptionError::EncodingFailed("invalid AES key length".to_owned())
            })?;
            let nonce_generic = aes_gcm::Nonce::from_slice(record.nonce());
            let plaintext = cipher
                .decrypt(
                    nonce_generic,
                    Payload {
                        msg: record.ciphertext_and_tag(),
                        aad,
                    },
                )
                .map_err(|_| EncryptionError::DecryptionFailed)?;
            Ok(Bytes::from(plaintext))
        }
        (EncryptionConfig::Aegis256(_), actual) => Err(EncryptionError::AlgorithmMismatch {
            expected: EncryptionAlgorithm::Aegis256,
            actual,
        }),
        (EncryptionConfig::Aes256Gcm(_), actual) => Err(EncryptionError::AlgorithmMismatch {
            expected: EncryptionAlgorithm::Aes256Gcm,
            actual,
        }),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{
        super::{Aegis256Key, Aes256GcmKey, make_key},
        *,
    };
    use crate::record::{
        Encodable as _, EncryptedRecord, EncryptedRecordError, EnvelopeRecord, Header,
    };

    fn aegis256_encryption() -> EncryptionConfig {
        EncryptionConfig::Aegis256(Aegis256Key(make_key([0x42u8; 32])))
    }

    fn aes256gcm_encryption() -> EncryptionConfig {
        EncryptionConfig::Aes256Gcm(Aes256GcmKey(make_key([0x42u8; 32])))
    }

    fn other_aegis256_encryption() -> EncryptionConfig {
        EncryptionConfig::Aegis256(Aegis256Key(make_key([0x99u8; 32])))
    }

    fn other_aes256gcm_encryption() -> EncryptionConfig {
        EncryptionConfig::Aes256Gcm(Aes256GcmKey(make_key([0x99u8; 32])))
    }

    fn aad() -> [u8; 32] {
        [0xA5; 32]
    }

    fn encode_payload(headers: Vec<Header>, body: Bytes) -> Bytes {
        EnvelopeRecord::try_from_parts(headers, body)
            .unwrap()
            .to_bytes()
    }

    fn decode_payload(bytes: Bytes) -> (Vec<Header>, Bytes) {
        EnvelopeRecord::try_from(bytes).unwrap().into_parts()
    }

    fn roundtrip(alg: EncryptionAlgorithm) {
        let headers = vec![Header {
            name: Bytes::from_static(b"x-test"),
            value: Bytes::from_static(b"hello"),
        }];
        let body = Bytes::from_static(b"secret payload");

        let aad = aad();
        let plaintext = encode_payload(headers.clone(), body.clone());
        let encryption = match alg {
            EncryptionAlgorithm::Aegis256 => aegis256_encryption(),
            EncryptionAlgorithm::Aes256Gcm => aes256gcm_encryption(),
        };
        let ciphertext = encrypt_payload(&plaintext, &encryption, &aad).unwrap();
        let decrypted = decrypt_payload(&ciphertext, &encryption, &aad).unwrap();
        let (out_headers, out_body) = decode_payload(decrypted);

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
        let aad = aad();
        let plaintext = encode_payload(vec![], Bytes::from_static(b"data"));
        let encryption = aegis256_encryption();
        let ciphertext = encrypt_payload(&plaintext, &encryption, &aad).unwrap();
        let result = decrypt_payload(&ciphertext, &other_aegis256_encryption(), &aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn wrong_key_fails_aes256gcm() {
        let aad = aad();
        let plaintext = encode_payload(vec![], Bytes::from_static(b"data"));
        let encryption = aes256gcm_encryption();
        let ciphertext = encrypt_payload(&plaintext, &encryption, &aad).unwrap();
        let result = decrypt_payload(&ciphertext, &other_aes256gcm_encryption(), &aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn truncated_ciphertext_fails_no_panic() {
        let aad = aad();
        let plaintext = encode_payload(vec![], Bytes::from_static(b"data"));
        let encryption = aegis256_encryption();
        let ciphertext = encrypt_payload(&plaintext, &encryption, &aad).unwrap();
        let truncated = ciphertext.to_bytes().slice(..4);
        let result = EncryptedRecord::try_from(truncated);
        assert!(matches!(result, Err(EncryptedRecordError::Truncated)));
    }

    #[test]
    fn invalid_suite_id_fails() {
        let body = Bytes::from_static(b"\xFFsome opaque bytes");
        let result = EncryptedRecord::try_from(body);
        assert!(matches!(
            result,
            Err(EncryptedRecordError::InvalidSuiteId(0xFF))
        ));
    }

    #[test]
    fn empty_body_fails() {
        let result = EncryptedRecord::try_from(Bytes::new());
        assert!(matches!(result, Err(EncryptedRecordError::Truncated)));
    }

    #[test]
    fn suite_id_byte_present() {
        let aad = aad();
        let plaintext = encode_payload(vec![], Bytes::from_static(b"data"));
        let ciphertext = encrypt_payload(&plaintext, &aegis256_encryption(), &aad).unwrap();
        let encoded = ciphertext.to_bytes();
        assert_eq!(ciphertext.algorithm(), EncryptionAlgorithm::Aegis256);
        assert_eq!(encoded[0], 0x01);
    }

    #[test]
    fn suite_id_flip_detected() {
        let aad = aad();
        let plaintext = encode_payload(vec![], Bytes::from_static(b"data"));
        let mut ciphertext = encrypt_payload(&plaintext, &aegis256_encryption(), &aad)
            .unwrap()
            .to_bytes()
            .to_vec();
        assert_eq!(ciphertext[0], 0x01);
        ciphertext[0] = 0x02;
        let ciphertext = EncryptedRecord::try_from(Bytes::from(ciphertext)).unwrap();
        let result = decrypt_payload(&ciphertext, &aegis256_encryption(), &aad);
        assert!(matches!(
            result,
            Err(EncryptionError::AlgorithmMismatch {
                expected: EncryptionAlgorithm::Aegis256,
                actual: EncryptionAlgorithm::Aes256Gcm,
            })
        ));
    }

    #[test]
    fn invalid_suite_flip_detected() {
        let aad = aad();
        let plaintext = encode_payload(vec![], Bytes::from_static(b"data"));
        let mut ciphertext = encrypt_payload(&plaintext, &aegis256_encryption(), &aad)
            .unwrap()
            .to_bytes()
            .to_vec();
        ciphertext[0] = 0xFF;
        let result = EncryptedRecord::try_from(Bytes::from(ciphertext));
        assert!(matches!(
            result,
            Err(EncryptedRecordError::InvalidSuiteId(0xFF))
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let aad = aad();
        let other_aad = [0x5A; 32];
        let plaintext = encode_payload(vec![], Bytes::from_static(b"data"));
        let ciphertext = encrypt_payload(&plaintext, &aegis256_encryption(), &aad).unwrap();
        let result = decrypt_payload(&ciphertext, &aegis256_encryption(), &other_aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }
}
