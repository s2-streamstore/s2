use s2_common::types::{basin::BasinName, stream::StreamName};

const FIELD_SEPARATOR: u8 = 0x00;

/// Unique identifier for a stream scoped by its basin.
///
/// The identifier is the Blake3 hash of the string representations of the
/// basin and stream names with a separator byte to avoid collisions when
/// concatenating variable length fields.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StreamId(blake3::Hash);

impl StreamId {
    pub fn new(basin: &BasinName, stream: &StreamName) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(basin.as_ref().as_bytes());
        hasher.update(&[FIELD_SEPARATOR]);
        hasher.update(stream.as_ref().as_bytes());

        Self(hasher.finalize())
    }

    /// Access the raw 32-byte hash.
    pub fn as_hash(&self) -> blake3::Hash {
        self.0
    }

    /// Borrow the identifier as raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Consume the identifier and return the raw bytes.
    pub fn into_bytes(self) -> [u8; 32] {
        *self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::StreamId;
    use s2_common::types::{basin::BasinName, stream::StreamName};
    use std::str::FromStr;

    #[test]
    fn deterministic_for_same_inputs() {
        let basin = BasinName::from_str("basin-alpha").unwrap();
        let stream = StreamName::from_str("stream-main").unwrap();

        let first = StreamId::new(&basin, &stream);
        let second = StreamId::new(&basin, &stream);

        assert_eq!(first, second);
    }

    #[test]
    fn distinct_for_different_inputs() {
        let basin = BasinName::from_str("basin-alpha").unwrap();
        let stream_a = StreamName::from_str("stream-main").unwrap();
        let stream_b = StreamName::from_str("stream-aux").unwrap();

        let id_a = StreamId::new(&basin, &stream_a);
        let id_b = StreamId::new(&basin, &stream_b);

        assert_ne!(id_a, id_b);
    }
}
