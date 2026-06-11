use bytes::Bytes;

use super::{Header, MeteredSize, RecordPartsError};
use crate::deep_size::DeepSize;

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
    headers_total_bytes: usize,
}

impl std::fmt::Debug for EnvelopeRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeRecord")
            .field("headers.len", &self.headers.len())
            .field("body.len", &self.body.len())
            .finish()
    }
}

impl DeepSize for EnvelopeRecord {
    fn deep_size(&self) -> usize {
        self.headers.deep_size() + self.body.deep_size()
    }
}

impl MeteredSize for EnvelopeRecord {
    fn metered_size(&self) -> usize {
        8 + (2 * self.headers.len()) + self.headers_total_bytes + self.body.len()
    }
}

impl EnvelopeRecord {
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    pub fn into_parts(self) -> (Vec<Header>, Bytes) {
        (self.headers, self.body)
    }

    pub fn try_from_parts(headers: Vec<Header>, body: Bytes) -> Result<Self, RecordPartsError> {
        let headers_total_bytes = validate_headers(&headers)?;
        Ok(Self {
            headers,
            body,
            headers_total_bytes,
        })
    }
}

fn validate_headers(headers: &[Header]) -> Result<usize, HeaderValidationError> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(HeaderValidationError::TooMany);
    }

    headers
        .iter()
        .try_fold(0usize, |total, Header { name, value }| {
            if name.is_empty() {
                return Err(HeaderValidationError::NameEmpty);
            }
            if name.len() > MAX_HEADER_NAME_OR_VALUE_LEN
                || value.len() > MAX_HEADER_NAME_OR_VALUE_LEN
            {
                return Err(HeaderValidationError::TooLong);
            }
            Ok(total + name.len() + value.len())
        })
}

#[cfg(test)]
mod test {
    use bytes::Bytes;

    use super::{EnvelopeRecord, Header, HeaderValidationError, MeteredSize, RecordPartsError};

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
}
