use std::num::NonZeroU8;

use bytes::{Buf, BufMut, Bytes};

use super::{Encodable, Header, InternalRecordError, PublicRecordError};
use crate::deep_size::DeepSize;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum HeaderValidationError {
    #[error("Too many")]
    TooMany,
    #[error("Too long")]
    TooLong,
    #[error("Empty name")]
    NameEmpty,
}

#[derive(PartialEq, Clone)]
pub struct EnvelopeRecord {
    headers: Vec<Header>,
    body: Bytes,
    encoding_info: EncodingInfo,
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

    pub fn try_from_parts(headers: Vec<Header>, body: Bytes) -> Result<Self, PublicRecordError> {
        let encoding_info = headers.as_slice().try_into()?;
        Ok(Self {
            headers,
            body,
            encoding_info,
        })
    }
}

impl Encodable for EnvelopeRecord {
    fn encoded_size(&self) -> usize {
        1 + self.encoding_info.flag.num_headers_length_bytes as usize
            + self.headers.len()
                * (self.encoding_info.flag.name_length_bytes.get() as usize
                    + self.encoding_info.flag.value_length_bytes.get() as usize)
            + self.encoding_info.headers_total_bytes
            + self.body.len()
    }

    fn encode_into(&self, buf: &mut impl BufMut) {
        // Write prefix: flag and number of headers.
        buf.put_u8(self.encoding_info.flag.into());
        buf.put_uint(
            self.headers.len() as u64,
            self.encoding_info.flag.num_headers_length_bytes as usize,
        );
        // Write headers.
        for Header { name, value } in &self.headers {
            buf.put_uint(
                name.len() as u64,
                self.encoding_info.flag.name_length_bytes.get() as usize,
            );
            buf.put_slice(name);
            buf.put_uint(
                value.len() as u64,
                self.encoding_info.flag.value_length_bytes.get() as usize,
            );
            buf.put_slice(value);
        }
        buf.put_slice(&self.body);
    }
}

impl TryFrom<Bytes> for EnvelopeRecord {
    type Error = InternalRecordError;

    fn try_from(mut buf: Bytes) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(InternalRecordError::InvalidValue("HeaderFlag", "missing"));
        }

        let flag: HeaderFlag = buf
            .get_u8()
            .try_into()
            .map_err(|info| InternalRecordError::InvalidValue("HeaderFlag", info))?;
        if flag.num_headers_length_bytes == 0 {
            return Ok(Self {
                encoding_info: EMPTY_HEADERS_ENCODING_INFO,
                headers: vec![],
                body: buf,
            });
        }

        let num_headers = buf
            .try_get_uint(flag.num_headers_length_bytes as usize)
            .map_err(|_| InternalRecordError::Truncated("NumHeaders"))?;

        let mut headers_total_bytes = 0;
        let mut headers: Vec<Header> = Vec::with_capacity(num_headers as usize);
        for _ in 0..num_headers {
            let name_len = buf
                .try_get_uint(flag.name_length_bytes.get() as usize)
                .map_err(|_| InternalRecordError::Truncated("HeaderNameLen"))?
                as usize;
            if buf.remaining() < name_len {
                return Err(InternalRecordError::Truncated("HeaderName"));
            }
            let name = buf.split_to(name_len);

            let value_len = buf
                .try_get_uint(flag.value_length_bytes.get() as usize)
                .map_err(|_| InternalRecordError::Truncated("HeaderValueLen"))?
                as usize;
            if buf.remaining() < value_len {
                return Err(InternalRecordError::Truncated("HeaderValue"));
            }
            let value = buf.split_to(value_len);

            headers_total_bytes += name.len() + value.len();
            headers.push(Header { name, value })
        }

        Ok(Self {
            encoding_info: EncodingInfo {
                headers_total_bytes,
                flag,
            },
            headers,
            body: buf,
        })
    }
}

const EMPTY_HEADER_FLAG: HeaderFlag = HeaderFlag {
    num_headers_length_bytes: 0,
    name_length_bytes: NonZeroU8::new(1).unwrap(),
    value_length_bytes: NonZeroU8::new(1).unwrap(),
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct HeaderFlag {
    num_headers_length_bytes: u8,
    name_length_bytes: NonZeroU8,
    value_length_bytes: NonZeroU8,
}

impl From<HeaderFlag> for u8 {
    fn from(value: HeaderFlag) -> Self {
        (value.num_headers_length_bytes << 4)
            | ((value.name_length_bytes.get() - 1) << 2)
            | (value.value_length_bytes.get() - 1)
    }
}

impl TryFrom<u8> for HeaderFlag {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (value & (0b11u8 << 6)) != 0u8 {
            return Err("reserved bit set");
        }
        Ok(Self {
            num_headers_length_bytes: (0b110000 & value) >> 4,
            name_length_bytes: NonZeroU8::new(((0b1100 & value) >> 2) + 1).unwrap(),
            value_length_bytes: NonZeroU8::new((0b11 & value) + 1).unwrap(),
        })
    }
}

const EMPTY_HEADERS_ENCODING_INFO: EncodingInfo = EncodingInfo {
    headers_total_bytes: 0,
    flag: EMPTY_HEADER_FLAG,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct EncodingInfo {
    headers_total_bytes: usize,
    flag: HeaderFlag,
}

impl TryFrom<&[Header]> for EncodingInfo {
    type Error = HeaderValidationError;

    fn try_from(headers: &[Header]) -> Result<Self, Self::Error> {
        // Given number of KV pairs, determine how many bytes are required for storing
        // the length number.
        fn size_bytes_headers_len(elems: u64) -> Result<u8, HeaderValidationError> {
            let size = 8 - elems.leading_zeros() / 8;
            if size > 3 {
                Err(HeaderValidationError::TooMany)
            } else {
                Ok(size as u8)
            }
        }

        // Given max length of a name (key) or value, determine how many bytes are required for
        // storing this number.
        fn size_bytes_name_value_len(elems: u64) -> Result<NonZeroU8, HeaderValidationError> {
            if elems == 0 {
                return Ok(NonZeroU8::new(1u8).unwrap());
            }
            let size = 8 - (elems.leading_zeros() / 8);
            if size > 4 {
                Err(HeaderValidationError::TooLong)
            } else {
                Ok(NonZeroU8::new(size as u8).unwrap())
            }
        }

        if headers.is_empty() {
            return Ok(EMPTY_HEADERS_ENCODING_INFO);
        }

        let (headers_total_bytes, name_max, value_max) = headers.iter().try_fold(
            (0usize, 0usize, 0usize),
            |(size_bytes_acc, name_max, value_max), Header { name, value }| {
                if name.is_empty() {
                    return Err(HeaderValidationError::NameEmpty);
                }
                let name_len = name.len();
                let value_len = value.len();
                Ok((
                    size_bytes_acc + name_len + value_len,
                    name_max.max(name_len),
                    value_max.max(value_len),
                ))
            },
        )?;

        let num_headers_length_bytes = size_bytes_headers_len(headers.len() as u64)?;
        let name_length_bytes = size_bytes_name_value_len(name_max as u64)?;
        let value_length_bytes = size_bytes_name_value_len(value_max as u64)?;

        Ok(Self {
            headers_total_bytes,
            flag: HeaderFlag {
                num_headers_length_bytes,
                name_length_bytes,
                value_length_bytes,
            },
        })
    }
}

#[cfg(test)]
mod test {
    use std::num::NonZeroU8;

    use bytes::Bytes;

    use super::{Encodable as _, EnvelopeRecord, Header, HeaderFlag, InternalRecordError};

    fn roundtrip_parts(headers: Vec<Header>, body: Bytes) {
        let encoded: Bytes = EnvelopeRecord::try_from_parts(headers.clone(), body.clone())
            .unwrap()
            .to_bytes();
        let decoded = EnvelopeRecord::try_from(encoded).unwrap();
        assert_eq!(decoded.headers(), headers);
        assert_eq!(decoded.body(), &body);
    }

    #[test]
    fn framed_with_headers() {
        roundtrip_parts(
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
    fn framed_no_headers() {
        roundtrip_parts(vec![], Bytes::from("hello"));
    }

    #[test]
    fn framed_duplicate_keys() {
        // Duplicate keys preserved in original order.
        roundtrip_parts(
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
    fn flag_ex1() {
        assert_eq!(
            Ok(HeaderFlag {
                num_headers_length_bytes: 2,
                name_length_bytes: NonZeroU8::new(1).unwrap(),
                value_length_bytes: NonZeroU8::new(1).unwrap(),
            }),
            0b00100000.try_into()
        );

        let u8_repr: u8 = HeaderFlag {
            num_headers_length_bytes: 2,
            name_length_bytes: NonZeroU8::new(1).unwrap(),
            value_length_bytes: NonZeroU8::new(1).unwrap(),
        }
        .into();
        assert_eq!(u8_repr, 0b00100000);
    }

    #[test]
    fn flag_ex2() {
        assert_eq!(
            Ok(HeaderFlag {
                num_headers_length_bytes: 1,
                name_length_bytes: NonZeroU8::new(1).unwrap(),
                value_length_bytes: NonZeroU8::new(1).unwrap(),
            }),
            0b00010000.try_into()
        );

        let u8_repr: u8 = HeaderFlag {
            num_headers_length_bytes: 1,
            name_length_bytes: NonZeroU8::new(1).unwrap(),
            value_length_bytes: NonZeroU8::new(1).unwrap(),
        }
        .into();
        assert_eq!(u8_repr, 0b00010000);
    }

    #[test]
    fn empty_envelope_size() {
        assert_eq!(
            1,
            EnvelopeRecord::try_from_parts(vec![], Bytes::new())
                .unwrap()
                .to_bytes()
                .len()
        );
    }

    #[test]
    fn truncated_returns_error() {
        let record = EnvelopeRecord::try_from_parts(
            vec![Header {
                name: Bytes::from("key"),
                value: Bytes::from("value"),
            }],
            Bytes::new(),
        )
        .unwrap();
        let encoded = record.to_bytes();

        // Truncation anywhere before the end should error
        // (with empty body, there's no trailing data that can be truncated safely).
        for len in 1..encoded.len() {
            let truncated = encoded.slice(..len);
            assert!(
                matches!(
                    EnvelopeRecord::try_from(truncated),
                    Err(InternalRecordError::Truncated(_))
                ),
                "expected Truncated error for len {len}"
            );
        }
    }
}
