use s2_common::{
    bash::Bash,
    types::{basin::BasinName, stream::StreamName},
};

/// Unique identifier for a stream scoped by its basin.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(Bash);

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StreamId({})", self.0)
    }
}

impl StreamId {
    pub const LEN: usize = 32;

    pub fn new(basin: &BasinName, stream: &StreamName) -> Self {
        Self(Bash::new(&[basin.as_bytes(), stream.as_bytes()]))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        self.0.as_bytes()
    }
}

impl From<[u8; StreamId::LEN]> for StreamId {
    fn from(bytes: [u8; StreamId::LEN]) -> Self {
        Self(bytes.into())
    }
}

impl From<StreamId> for [u8; StreamId::LEN] {
    fn from(id: StreamId) -> Self {
        id.0.into()
    }
}
