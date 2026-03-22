use bytes::Bytes;
use futures::StreamExt;
use s2_common::{
    encryption::{
        EncryptionAlgorithm, EncryptionDirective, EncryptionKey, KeyBytes, decrypt_read_batch,
        stream_aad,
    },
    read_extent::{ReadLimit, ReadUntil},
    record::Record,
    types::{
        config::OptionalStreamConfig,
        stream::{AppendInput, ReadEnd, ReadFrom, ReadSessionOutput, ReadStart},
    },
};
use s2_lite::backend::AppendEncryption;
use secrecy::SecretBox;

use super::common::*;

fn test_key() -> EncryptionKey {
    SecretBox::new(Box::new(KeyBytes([0x42u8; 32])))
}

fn test_key_2() -> EncryptionKey {
    SecretBox::new(Box::new(KeyBytes([0x99u8; 32])))
}

fn make_append_encryption(
    alg: EncryptionAlgorithm,
    key: EncryptionKey,
    basin: &s2_common::types::basin::BasinName,
    stream: &s2_common::types::stream::StreamName,
) -> AppendEncryption {
    AppendEncryption {
        directive: EncryptionDirective::Key { alg, key },
        aad: stream_aad(basin, stream).into_bytes(),
    }
}

#[tokio::test]
async fn test_encrypt_append_and_decrypt_read_aegis256() {
    let (backend, basin, stream) =
        setup_backend_with_stream("enc-aegis", "stream", OptionalStreamConfig::default()).await;

    let enc = make_append_encryption(EncryptionAlgorithm::Aegis256, test_key(), &basin, &stream);

    let input = AppendInput {
        records: create_test_record_batch(vec![
            Bytes::from_static(b"secret 1"),
            Bytes::from_static(b"secret 2"),
        ]),
        match_seq_num: None,
        fencing_token: None,
    };

    let ack = backend
        .append(basin.clone(), stream.clone(), input, Some(enc))
        .await
        .expect("encrypted append should succeed");
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 2);

    // Read back raw (encrypted) records.
    let session = backend
        .read(
            basin.clone(),
            stream.clone(),
            ReadStart {
                from: ReadFrom::SeqNum(0),
                clamp: false,
            },
            ReadEnd {
                limit: ReadLimit::Count(10),
                until: ReadUntil::Unbounded,
                wait: None,
            },
        )
        .await
        .expect("read session");

    let mut batches = Vec::new();
    tokio::pin!(session);
    while let Some(output) = session.next().await {
        match output.expect("read output") {
            ReadSessionOutput::Batch(batch) => batches.push(batch),
            ReadSessionOutput::Heartbeat(_) => {}
        }
    }
    assert!(!batches.is_empty());

    // Raw records should NOT match plaintext (they're encrypted).
    let Record::Envelope(ref env) = batches[0].records[0].record else {
        panic!("expected envelope record");
    };
    assert_ne!(env.body().as_ref(), b"secret 1");

    // Decrypt and verify plaintext matches.
    let directive = EncryptionDirective::Key {
        alg: EncryptionAlgorithm::Aegis256,
        key: test_key(),
    };
    let aad = stream_aad(&basin, &stream).into_bytes();
    for batch in batches {
        let decrypted =
            decrypt_read_batch(batch, Some(&directive), &aad).expect("decryption should succeed");
        for sr in decrypted.records.iter() {
            let Record::Envelope(ref env) = sr.record else {
                panic!("expected envelope record");
            };
            let text = std::str::from_utf8(env.body()).expect("valid utf8");
            assert!(
                text == "secret 1" || text == "secret 2",
                "unexpected body: {text}"
            );
        }
    }
}

#[tokio::test]
async fn test_encrypt_append_and_decrypt_read_aes256gcm() {
    let (backend, basin, stream) =
        setup_backend_with_stream("enc-aes", "stream", OptionalStreamConfig::default()).await;

    let enc = make_append_encryption(EncryptionAlgorithm::Aes256Gcm, test_key(), &basin, &stream);

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"aes payload")]),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin.clone(), stream.clone(), input, Some(enc))
        .await
        .expect("encrypted append should succeed");

    let session = backend
        .read(
            basin.clone(),
            stream.clone(),
            ReadStart {
                from: ReadFrom::SeqNum(0),
                clamp: false,
            },
            ReadEnd {
                limit: ReadLimit::Count(10),
                until: ReadUntil::Unbounded,
                wait: None,
            },
        )
        .await
        .expect("read session");

    let directive = EncryptionDirective::Key {
        alg: EncryptionAlgorithm::Aes256Gcm,
        key: test_key(),
    };
    let aad = stream_aad(&basin, &stream).into_bytes();

    tokio::pin!(session);
    while let Some(output) = session.next().await {
        match output.expect("read output") {
            ReadSessionOutput::Batch(batch) => {
                let decrypted = decrypt_read_batch(batch, Some(&directive), &aad)
                    .expect("decryption should succeed");
                for sr in decrypted.records.iter() {
                    let Record::Envelope(ref env) = sr.record else {
                        panic!("expected envelope record");
                    };
                    assert_eq!(env.body().as_ref(), b"aes payload");
                }
            }
            ReadSessionOutput::Heartbeat(_) => {}
        }
    }
}

#[tokio::test]
async fn test_wrong_key_fails_decryption() {
    let (backend, basin, stream) =
        setup_backend_with_stream("enc-wrongkey", "stream", OptionalStreamConfig::default()).await;

    let enc = make_append_encryption(EncryptionAlgorithm::Aegis256, test_key(), &basin, &stream);

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"secret")]),
        match_seq_num: None,
        fencing_token: None,
    };

    backend
        .append(basin.clone(), stream.clone(), input, Some(enc))
        .await
        .expect("append should succeed");

    let session = backend
        .read(
            basin.clone(),
            stream.clone(),
            ReadStart {
                from: ReadFrom::SeqNum(0),
                clamp: false,
            },
            ReadEnd {
                limit: ReadLimit::Count(10),
                until: ReadUntil::Unbounded,
                wait: None,
            },
        )
        .await
        .expect("read session");

    let wrong_directive = EncryptionDirective::Key {
        alg: EncryptionAlgorithm::Aegis256,
        key: test_key_2(),
    };
    let aad = stream_aad(&basin, &stream).into_bytes();

    tokio::pin!(session);
    while let Some(output) = session.next().await {
        match output.expect("read output") {
            ReadSessionOutput::Batch(batch) => {
                let result = decrypt_read_batch(batch, Some(&wrong_directive), &aad);
                assert!(result.is_err(), "decryption with wrong key should fail");
            }
            ReadSessionOutput::Heartbeat(_) => {}
        }
    }
}

#[tokio::test]
async fn test_mixed_encrypted_and_plaintext_append() {
    let (backend, basin, stream) =
        setup_backend_with_stream("enc-mixed", "stream", OptionalStreamConfig::default()).await;

    // First append: plaintext.
    let input1 = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"plaintext")]),
        match_seq_num: None,
        fencing_token: None,
    };
    backend
        .append(basin.clone(), stream.clone(), input1, None)
        .await
        .expect("plaintext append");

    // Second append: encrypted.
    let enc = make_append_encryption(EncryptionAlgorithm::Aegis256, test_key(), &basin, &stream);
    let input2 = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"encrypted")]),
        match_seq_num: None,
        fencing_token: None,
    };
    backend
        .append(basin.clone(), stream.clone(), input2, Some(enc))
        .await
        .expect("encrypted append");

    // Read all records.
    let session = backend
        .read(
            basin.clone(),
            stream.clone(),
            ReadStart {
                from: ReadFrom::SeqNum(0),
                clamp: false,
            },
            ReadEnd {
                limit: ReadLimit::Count(10),
                until: ReadUntil::Unbounded,
                wait: None,
            },
        )
        .await
        .expect("read session");

    let mut records = Vec::new();
    tokio::pin!(session);
    while let Some(output) = session.next().await {
        match output.expect("read output") {
            ReadSessionOutput::Batch(batch) => {
                for sr in batch.records.into_inner() {
                    records.push(sr);
                }
            }
            ReadSessionOutput::Heartbeat(_) => {}
        }
    }

    assert_eq!(records.len(), 2);
    // Record 0: plaintext, body should be readable directly.
    let Record::Envelope(ref env0) = records[0].record else {
        panic!("expected envelope record");
    };
    assert_eq!(env0.body().as_ref(), b"plaintext");
    // Record 1: encrypted, body should NOT be plaintext.
    let Record::Envelope(ref env1) = records[1].record else {
        panic!("expected envelope record");
    };
    assert_ne!(env1.body().as_ref(), b"encrypted");
}
