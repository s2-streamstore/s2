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
    header_metrics: EnvelopeHeaderMetrics,
}

/// Cached metrics for validated envelope headers.
///
/// These values describe the logical header collection. Storage codecs may use
/// them to derive wire framing, but the metrics themselves are not a wire format.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct EnvelopeHeaderMetrics {
    total_bytes: usize,
    max_name_bytes: usize,
    max_value_bytes: usize,
}

impl EnvelopeHeaderMetrics {
    /// Total bytes across all header names and values.
    pub fn total_bytes(self) -> usize {
        self.total_bytes
    }

    /// Length of the longest header name.
    pub fn max_name_bytes(self) -> usize {
        self.max_name_bytes
    }

    /// Length of the longest header value.
    pub fn max_value_bytes(self) -> usize {
        self.max_value_bytes
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

impl DeepSize for EnvelopeRecord {
    fn deep_size(&self) -> usize {
        self.headers.deep_size() + self.body.deep_size()
    }
}

impl MeteredSize for EnvelopeRecord {
    fn metered_size(&self) -> usize {
        8 + (2 * self.headers.len()) + self.header_metrics.total_bytes + self.body.len()
    }
}

impl EnvelopeRecord {
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Cached metrics for the validated header collection.
    pub fn header_metrics(&self) -> EnvelopeHeaderMetrics {
        self.header_metrics
    }

    pub fn into_parts(self) -> (Vec<Header>, Bytes) {
        (self.headers, self.body)
    }

    pub fn try_from_parts(headers: Vec<Header>, body: Bytes) -> Result<Self, RecordPartsError> {
        let header_metrics = validate_headers(&headers)?;
        Ok(Self {
            headers,
            body,
            header_metrics,
        })
    }
}

fn validate_headers(headers: &[Header]) -> Result<EnvelopeHeaderMetrics, HeaderValidationError> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(HeaderValidationError::TooMany);
    }

    headers.iter().try_fold(
        EnvelopeHeaderMetrics::default(),
        |metrics, Header { name, value }| {
            if name.is_empty() {
                return Err(HeaderValidationError::NameEmpty);
            }
            if name.len() > MAX_HEADER_NAME_OR_VALUE_LEN
                || value.len() > MAX_HEADER_NAME_OR_VALUE_LEN
            {
                return Err(HeaderValidationError::TooLong);
            }
            Ok(EnvelopeHeaderMetrics {
                total_bytes: metrics.total_bytes + name.len() + value.len(),
                max_name_bytes: metrics.max_name_bytes.max(name.len()),
                max_value_bytes: metrics.max_value_bytes.max(value.len()),
            })
        },
    )
}

#[cfg(test)]
mod test {
    use bytes::Bytes;

    use super::{
        EnvelopeHeaderMetrics, EnvelopeRecord, Header, HeaderValidationError, MeteredSize,
        RecordPartsError,
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
    fn header_metrics_are_cached_from_validated_headers() {
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
            record.header_metrics(),
            EnvelopeHeaderMetrics {
                total_bytes: "a".len() + "value".len() + "long-name".len() + "x".len(),
                max_name_bytes: "long-name".len(),
                max_value_bytes: "value".len(),
            }
        );
    }
}
