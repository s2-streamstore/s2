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
    const SEPARATOR: u8 = 0;

    pub fn new(basin: &BasinName, stream: &StreamName) -> Self {
        Self(Bash::delimited(
            &[basin.as_bytes(), stream.as_bytes()],
            Self::SEPARATOR,
        ))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        self.0.as_bytes()
    }

    pub fn aad(basin: &BasinName, stream: &StreamName) -> [u8; Self::LEN] {
        *Self::new(basin, stream).as_bytes()
    }
}

pub fn aad(basin: &BasinName, stream: &StreamName) -> [u8; StreamId::LEN] {
    StreamId::aad(basin, stream)
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
