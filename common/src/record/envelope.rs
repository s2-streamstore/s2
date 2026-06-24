use bytes::Bytes;

use super::{Header, MeteredSize, RecordPartsError};

const MAX_HEADER_COUNT: usize = 0xFF_FFFF;
const MAX_HEADER_NAME_OR_VALUE_LEN: usize = u32::MAX as usize;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum HeaderValidationError {
    #[error("too many")]
    TooMany,
    #[error("too long")]
    TooLong,
    #[error("empty name")]
    NameEmpty,
}

#[derive(PartialEq, Eq, Clone)]
pub struct EnvelopeRecord {
    headers: Vec<Header>,
    body: Bytes,
    header_sizing: HeaderSizing,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
struct HeaderSizing(u64);

impl HeaderSizing {
    const TOTAL_BYTES_MASK: u64 = (1 << 60) - 1;
    const NAME_LENGTH_WIDTH_SHIFT: u32 = 62;
    const VALUE_LENGTH_WIDTH_SHIFT: u32 = 60;

    fn new(total_bytes: usize, name_length_width: u8, value_length_width: u8) -> Self {
        debug_assert!(total_bytes as u64 <= Self::TOTAL_BYTES_MASK);
        debug_assert!((1..=4).contains(&name_length_width));
        debug_assert!((1..=4).contains(&value_length_width));

        Self(
            total_bytes as u64
                | (u64::from(name_length_width - 1) << Self::NAME_LENGTH_WIDTH_SHIFT)
                | (u64::from(value_length_width - 1) << Self::VALUE_LENGTH_WIDTH_SHIFT),
        )
    }

    fn total_bytes(self) -> usize {
        (self.0 & Self::TOTAL_BYTES_MASK) as usize
    }

    fn name_length_width_bytes(self) -> usize {
        (((self.0 >> Self::NAME_LENGTH_WIDTH_SHIFT) & 0b11) + 1) as usize
    }

    fn value_length_width_bytes(self) -> usize {
        (((self.0 >> Self::VALUE_LENGTH_WIDTH_SHIFT) & 0b11) + 1) as usize
    }
}

impl std::fmt::Debug for EnvelopeRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeRecord")
            .field("headers.len", &self.headers.len())
            .field("body.len", &self.body.len())
            .finish()
    }
}

impl MeteredSize for EnvelopeRecord {
    fn metered_size(&self) -> usize {
        8 + (2 * self.headers.len()) + self.header_sizing.total_bytes() + self.body.len()
    }
}

impl EnvelopeRecord {
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Total bytes across all header names and values.
    pub fn headers_total_bytes(&self) -> usize {
        self.header_sizing.total_bytes()
    }

    #[doc(hidden)]
    pub fn header_name_length_width_bytes(&self) -> usize {
        self.header_sizing.name_length_width_bytes()
    }

    #[doc(hidden)]
    pub fn header_value_length_width_bytes(&self) -> usize {
        self.header_sizing.value_length_width_bytes()
    }

    pub fn into_parts(self) -> (Vec<Header>, Bytes) {
        (self.headers, self.body)
    }

    pub fn try_from_parts(headers: Vec<Header>, body: Bytes) -> Result<Self, RecordPartsError> {
        let header_sizing = validate_headers(&headers)?;
        Ok(Self {
            headers,
            body,
            header_sizing,
        })
    }
}

fn validate_headers(headers: &[Header]) -> Result<HeaderSizing, HeaderValidationError> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(HeaderValidationError::TooMany);
    }

    let mut total_bytes = 0usize;
    let mut name_length_width_bytes = 1u8;
    let mut value_length_width_bytes = 1u8;

    for Header { name, value } in headers {
        if name.is_empty() {
            return Err(HeaderValidationError::NameEmpty);
        }
        if name.len() > MAX_HEADER_NAME_OR_VALUE_LEN || value.len() > MAX_HEADER_NAME_OR_VALUE_LEN {
            return Err(HeaderValidationError::TooLong);
        }

        total_bytes = total_bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(HeaderValidationError::TooLong)?;
        if total_bytes as u64 > HeaderSizing::TOTAL_BYTES_MASK {
            return Err(HeaderValidationError::TooLong);
        }

        name_length_width_bytes = name_length_width_bytes.max(length_width_bytes(name.len())?);
        value_length_width_bytes = value_length_width_bytes.max(length_width_bytes(value.len())?);
    }

    Ok(HeaderSizing::new(
        total_bytes,
        name_length_width_bytes,
        value_length_width_bytes,
    ))
}

fn length_width_bytes(len: usize) -> Result<u8, HeaderValidationError> {
    if len == 0 {
        return Ok(1);
    }

    let width = 8 - len.leading_zeros() / 8;
    if width <= 4 {
        Ok(width as u8)
    } else {
        Err(HeaderValidationError::TooLong)
    }
}

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use proptest::prelude::*;

    use super::{
        EnvelopeRecord, Header, HeaderSizing, HeaderValidationError, MeteredSize, RecordPartsError,
        length_width_bytes,
    };

    fn assert_parts_preserved(headers: Vec<Header>, body: Bytes) {
        let record = EnvelopeRecord::try_from_parts(headers.clone(), body.clone()).unwrap();
        assert_eq!(record.headers(), headers);
        assert_eq!(record.body(), &body);
    }

    #[test]
    fn preserves_headers() {
        assert_parts_preserved(
            vec![
                Header {
                    name: Bytes::from("key_1"),
                    value: Bytes::from("val_1"),
                },
                Header {
                    name: Bytes::from("key_2"),
                    value: Bytes::from("val_2"),
                },
                Header {
                    name: Bytes::from("key_3"),
                    value: Bytes::from("val_3"),
                },
                Header {
                    name: Bytes::from("key_4"),
                    value: Bytes::from("val_4"),
                },
            ],
            Bytes::from("hello"),
        );
    }

    #[test]
    fn preserves_no_headers() {
        assert_parts_preserved(vec![], Bytes::from("hello"));
    }

    #[test]
    fn rejects_empty_header_name() {
        assert_eq!(
            EnvelopeRecord::try_from_parts(
                vec![Header {
                    name: Bytes::new(),
                    value: Bytes::from_static(b"value"),
                }],
                Bytes::from_static(b"body"),
            ),
            Err(RecordPartsError::Header(HeaderValidationError::NameEmpty))
        );
    }

    #[test]
    fn preserves_duplicate_keys() {
        // Duplicate keys preserved in original order.
        assert_parts_preserved(
            vec![
                Header {
                    name: Bytes::from("b"),
                    value: Bytes::from("val_1"),
                },
                Header {
                    name: Bytes::from("b"),
                    value: Bytes::from("val_2"),
                },
                Header {
                    name: Bytes::from("a"),
                    value: Bytes::from("val_3"),
                },
            ],
            Bytes::from("hello"),
        );
    }

    #[test]
    fn metered_size_uses_cached_header_bytes() {
        let record = EnvelopeRecord::try_from_parts(
            vec![
                Header {
                    name: Bytes::from("alpha"),
                    value: Bytes::from("1"),
                },
                Header {
                    name: Bytes::from("beta"),
                    value: Bytes::from("two"),
                },
            ],
            Bytes::from("body"),
        )
        .unwrap();

        assert_eq!(
            record.metered_size(),
            8 + (2 * record.headers().len())
                + ("alpha".len() + "1".len() + "beta".len() + "two".len())
                + "body".len()
        );
    }

    #[test]
    fn header_sizing_is_cached_from_validated_headers() {
        let long_name = Bytes::from(vec![b'n'; 256]);
        let long_value = Bytes::from(vec![b'v'; 65_536]);
        let record = EnvelopeRecord::try_from_parts(
            vec![
                Header {
                    name: Bytes::from_static(b"a"),
                    value: Bytes::from_static(b"value"),
                },
                Header {
                    name: long_name.clone(),
                    value: long_value.clone(),
                },
            ],
            Bytes::from_static(b"body"),
        )
        .unwrap();

        assert_eq!(
            record.headers_total_bytes(),
            "a".len() + "value".len() + long_name.len() + long_value.len()
        );
        assert_eq!(record.header_name_length_width_bytes(), 2);
        assert_eq!(record.header_value_length_width_bytes(), 3);
    }

    proptest! {
        #[test]
        fn header_sizing_pack_roundtrips(
            total_bytes in 0usize..=HeaderSizing::TOTAL_BYTES_MASK as usize,
            name_length_width in 1u8..=4,
            value_length_width in 1u8..=4,
        ) {
            let summary = HeaderSizing::new(
                total_bytes,
                name_length_width,
                value_length_width,
            );

            prop_assert_eq!(summary.total_bytes(), total_bytes);
            prop_assert_eq!(
                summary.name_length_width_bytes(),
                name_length_width as usize,
            );
            prop_assert_eq!(
                summary.value_length_width_bytes(),
                value_length_width as usize,
            );
        }
    }

    #[test]
    fn length_width_bytes_covers_encoding_boundaries() {
        assert_eq!(length_width_bytes(0), Ok(1));
        assert_eq!(length_width_bytes(1), Ok(1));
        assert_eq!(length_width_bytes(0xff), Ok(1));
        assert_eq!(length_width_bytes(0x100), Ok(2));
        assert_eq!(length_width_bytes(0xffff), Ok(2));
        assert_eq!(length_width_bytes(0x1_0000), Ok(3));
        assert_eq!(length_width_bytes(0xff_ffff), Ok(3));
        assert_eq!(length_width_bytes(0x100_0000), Ok(4));
        assert_eq!(length_width_bytes(u32::MAX as usize), Ok(4));

        if let Some(too_long) = (u32::MAX as usize).checked_add(1) {
            assert_eq!(
                length_width_bytes(too_long),
                Err(HeaderValidationError::TooLong)
            );
        }
    }
}
