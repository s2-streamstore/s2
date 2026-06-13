use bytes::Bytes;
use s2_common::record::{EnvelopeRecord, Header, MeteredExt as _, Record};

use super::{StoredRecord, encode_stored_record};

const MAX_METERED_SIZE: usize = 0xFF_FFFF;
const MAX_STORED_ENVELOPE_RECORD_LEN: usize = MAX_METERED_SIZE - 2;
const MAX_EMPTY_ENVELOPE_BODY_LEN: usize = MAX_METERED_SIZE - 8;
const EMPTY_ENVELOPE_METERED_OVERHEAD: usize = MAX_METERED_SIZE - MAX_EMPTY_ENVELOPE_BODY_LEN;

/// Build a stored plaintext envelope record with no headers and `body_len` body bytes.
///
/// The fixture is produced through the stored-record encoder, so callers get a valid storage
/// frame.
///
/// # Panics
///
/// Panics if the resulting record's metered size cannot fit in the stored-record metered-size
/// prefix.
pub fn stored_envelope_record_with_body_len(body_len: usize) -> Bytes {
    assert!(
        body_len <= MAX_EMPTY_ENVELOPE_BODY_LEN,
        "stored envelope record body length must be <= {MAX_EMPTY_ENVELOPE_BODY_LEN}"
    );

    encode_stored_envelope_record(vec![], body_len)
}

/// Build a stored plaintext envelope record with no headers and the exact logical
/// `metered_size`.
///
/// The fixture is produced through the stored-record encoder, so callers get a valid storage
/// frame.
///
/// # Panics
///
/// Panics if `metered_size` is outside the representable range for an empty envelope record.
pub fn stored_envelope_record_with_metered_size(metered_size: usize) -> Bytes {
    assert!(
        (EMPTY_ENVELOPE_METERED_OVERHEAD..=MAX_METERED_SIZE).contains(&metered_size),
        "stored envelope record metered size must be in {EMPTY_ENVELOPE_METERED_OVERHEAD}..={MAX_METERED_SIZE}"
    );

    stored_envelope_record_with_body_len(metered_size - EMPTY_ENVELOPE_METERED_OVERHEAD)
}

/// Build a stored plaintext envelope record whose encoded length is exactly `encoded_len`.
///
/// The fixture is produced through the stored-record encoder, so callers get a valid storage frame
/// with a controlled encoded size.
///
/// # Panics
///
/// Panics if `encoded_len` is outside the representable range for this fixture.
pub fn stored_envelope_record_with_encoded_len(encoded_len: usize) -> Bytes {
    // Empty envelopes cover the smallest lengths and the exact points where the metered-size
    // prefix widens. A single one-byte header fills the adjacent gaps.
    let (headers, body_len) = match encoded_len {
        3..=6 => (vec![], encoded_len - 3),
        7..=251 => (single_header(), encoded_len - 7),
        252 => (vec![], encoded_len - 4),
        253..=65_532 => (single_header(), encoded_len - 8),
        65_533 => (vec![], encoded_len - 5),
        65_534..=MAX_STORED_ENVELOPE_RECORD_LEN => (single_header(), encoded_len - 9),
        _ => panic!(
            "stored envelope record encoded length must be in 3..={MAX_STORED_ENVELOPE_RECORD_LEN}"
        ),
    };

    let encoded = encode_stored_envelope_record(headers, body_len);
    assert_eq!(encoded.len(), encoded_len);

    encoded
}

fn encode_stored_envelope_record(headers: Vec<Header>, body_len: usize) -> Bytes {
    let envelope =
        EnvelopeRecord::try_from_parts(headers, Bytes::from(vec![0u8; body_len])).unwrap();
    let stored = StoredRecord::from(Record::Envelope(envelope)).metered();
    encode_stored_record(stored.as_ref())
}

fn single_header() -> Vec<Header> {
    vec![Header {
        name: Bytes::from_static(b"x"),
        value: Bytes::new(),
    }]
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rstest::rstest;
    use s2_common::record::{Metered, MeteredSize as _, Record};

    use super::{
        EMPTY_ENVELOPE_METERED_OVERHEAD, MAX_EMPTY_ENVELOPE_BODY_LEN, MAX_METERED_SIZE,
        MAX_STORED_ENVELOPE_RECORD_LEN, stored_envelope_record_with_body_len,
        stored_envelope_record_with_encoded_len, stored_envelope_record_with_metered_size,
    };
    use crate::record::{StoredRecord, decode_stored_record, encode_stored_record};

    #[rstest]
    #[case(3)]
    #[case(4)]
    #[case(6)]
    #[case(7)]
    #[case(8)]
    #[case(250)]
    #[case(251)]
    #[case(252)]
    #[case(253)]
    #[case(254)]
    #[case(32_768)]
    #[case(65_532)]
    #[case(65_533)]
    #[case(65_534)]
    #[case(65_535)]
    #[case(MAX_STORED_ENVELOPE_RECORD_LEN - 1)]
    #[case(MAX_STORED_ENVELOPE_RECORD_LEN)]
    fn exact_encoded_len_fixture_is_valid_at_boundaries(#[case] encoded_len: usize) {
        let encoded = stored_envelope_record_with_encoded_len(encoded_len);
        assert_valid_stored_envelope(encoded, encoded_len);
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(247)]
    #[case(248)]
    #[case(65_527)]
    #[case(65_528)]
    #[case(MAX_EMPTY_ENVELOPE_BODY_LEN)]
    fn body_len_fixture_is_valid(#[case] body_len: usize) {
        let encoded = stored_envelope_record_with_body_len(body_len);

        let decoded = assert_valid_stored_envelope(encoded.clone(), encoded.len());
        let StoredRecord::Plaintext(Record::Envelope(envelope)) = decoded.into_inner() else {
            panic!("expected plaintext envelope record");
        };
        assert_eq!(envelope.headers(), []);
        assert_eq!(envelope.body().len(), body_len);
    }

    #[rstest]
    #[case(EMPTY_ENVELOPE_METERED_OVERHEAD)]
    #[case(EMPTY_ENVELOPE_METERED_OVERHEAD + 1)]
    #[case(255)]
    #[case(256)]
    #[case(65_535)]
    #[case(65_536)]
    #[case(MAX_METERED_SIZE)]
    fn metered_size_fixture_is_valid(#[case] metered_size: usize) {
        let encoded = stored_envelope_record_with_metered_size(metered_size);

        let decoded = assert_valid_stored_envelope(encoded.clone(), encoded.len());
        assert_eq!(decoded.metered_size(), metered_size);
        let StoredRecord::Plaintext(Record::Envelope(envelope)) = decoded.into_inner() else {
            panic!("expected plaintext envelope record");
        };
        assert_eq!(envelope.headers(), []);
    }

    #[test]
    #[should_panic(expected = "stored envelope record encoded length must be in")]
    fn exact_encoded_len_rejects_too_small_len() {
        stored_envelope_record_with_encoded_len(2);
    }

    #[test]
    #[should_panic(expected = "stored envelope record encoded length must be in")]
    fn exact_encoded_len_rejects_too_large_len() {
        stored_envelope_record_with_encoded_len(MAX_STORED_ENVELOPE_RECORD_LEN + 1);
    }

    #[test]
    #[should_panic(expected = "stored envelope record body length must be <=")]
    fn body_len_rejects_too_large_body() {
        stored_envelope_record_with_body_len(MAX_EMPTY_ENVELOPE_BODY_LEN + 1);
    }

    #[test]
    #[should_panic(expected = "stored envelope record metered size must be in")]
    fn metered_size_rejects_too_small_size() {
        stored_envelope_record_with_metered_size(EMPTY_ENVELOPE_METERED_OVERHEAD - 1);
    }

    #[test]
    #[should_panic(expected = "stored envelope record metered size must be in")]
    fn metered_size_rejects_too_large_size() {
        stored_envelope_record_with_metered_size(MAX_METERED_SIZE + 1);
    }

    fn assert_valid_stored_envelope(encoded: Bytes, expected_len: usize) -> Metered<StoredRecord> {
        assert_eq!(encoded.len(), expected_len);

        let decoded = decode_stored_record(encoded.clone()).unwrap();
        let decoded_record = decoded.clone().into_inner();
        assert!(matches!(
            decoded_record,
            StoredRecord::Plaintext(Record::Envelope(_))
        ));
        assert_eq!(decoded.metered_size(), decoded_record.metered_size());
        assert_eq!(encode_stored_record(decoded.as_ref()), encoded);

        decoded
    }
}
