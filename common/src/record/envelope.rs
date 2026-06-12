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
    header_summary: HeaderSummary,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
struct HeaderSummary {
    total_bytes: usize,
    max_name_bytes: u32,
    max_value_bytes: u32,
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
        8 + (2 * self.headers.len()) + self.header_summary.total_bytes + self.body.len()
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
        self.header_summary.total_bytes
    }

    /// Length of the longest header name.
    pub fn max_header_name_bytes(&self) -> usize {
        self.header_summary.max_name_bytes as usize
    }

    /// Length of the longest header value.
    pub fn max_header_value_bytes(&self) -> usize {
        self.header_summary.max_value_bytes as usize
    }

    pub fn into_parts(self) -> (Vec<Header>, Bytes) {
        (self.headers, self.body)
    }

    pub fn try_from_parts(headers: Vec<Header>, body: Bytes) -> Result<Self, RecordPartsError> {
        let header_summary = validate_headers(&headers)?;
        Ok(Self {
            headers,
            body,
            header_summary,
        })
    }
}

fn validate_headers(headers: &[Header]) -> Result<HeaderSummary, HeaderValidationError> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(HeaderValidationError::TooMany);
    }

    headers.iter().try_fold(
        HeaderSummary::default(),
        |summary, Header { name, value }| {
            if name.is_empty() {
                return Err(HeaderValidationError::NameEmpty);
            }
            if name.len() > MAX_HEADER_NAME_OR_VALUE_LEN
                || value.len() > MAX_HEADER_NAME_OR_VALUE_LEN
            {
                return Err(HeaderValidationError::TooLong);
            }
            Ok(HeaderSummary {
                total_bytes: summary.total_bytes + name.len() + value.len(),
                max_name_bytes: summary.max_name_bytes.max(name.len() as u32),
                max_value_bytes: summary.max_value_bytes.max(value.len() as u32),
            })
        },
    )
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

    #[test]
    fn header_summary_is_cached_from_validated_headers() {
        let record = EnvelopeRecord::try_from_parts(
            vec![
                Header {
                    name: Bytes::from_static(b"a"),
                    value: Bytes::from_static(b"value"),
                },
                Header {
                    name: Bytes::from_static(b"long-name"),
                    value: Bytes::from_static(b"x"),
                },
            ],
            Bytes::from_static(b"body"),
        )
        .unwrap();

        assert_eq!(
            record.headers_total_bytes(),
            "a".len() + "value".len() + "long-name".len() + "x".len()
        );
        assert_eq!(record.max_header_name_bytes(), "long-name".len());
        assert_eq!(record.max_header_value_bytes(), "value".len());
    }
}
