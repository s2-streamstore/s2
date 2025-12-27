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
}

impl AsRef<[u8]> for StreamId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<[u8; 32]> for StreamId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(blake3::Hash::from_bytes(bytes))
    }
}

impl From<StreamId> for [u8; 32] {
    fn from(id: StreamId) -> Self {
        *id.0.as_bytes()
    }
}

impl From<blake3::Hash> for StreamId {
    fn from(hash: blake3::Hash) -> Self {
        Self(hash)
    }
}

impl From<StreamId> for blake3::Hash {
    fn from(id: StreamId) -> Self {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use s2_common::types::{basin::BasinName, stream::StreamName};

    use super::StreamId;

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
