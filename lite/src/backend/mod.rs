use s2_common::record::StreamPosition;

use self::kv::timestamp::TimestampSecs;

pub mod error;

mod basins;
pub mod bgtasks;
mod core;
mod durability_notifier;
mod read;
mod store;
mod streamer;
mod streams;

mod append;
mod kv;

pub use core::Backend;

pub use crate::stream_id::StreamId;

pub const FOLLOWER_MAX_LAG: usize = 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PersistedStreamTail {
    pub tail: StreamPosition,
    pub write_timestamp: TimestampSecs,
}

impl Default for PersistedStreamTail {
    fn default() -> Self {
        Self {
            tail: StreamPosition::MIN,
            write_timestamp: TimestampSecs::from_secs(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreatedOrReconfigured<T> {
    Created(T),
    Reconfigured(T),
}

impl<T> CreatedOrReconfigured<T> {
    pub fn is_created(&self) -> bool {
        matches!(self, Self::Created(_))
    }

    pub fn into_inner(self) -> T {
        match self {
            Self::Created(v) | Self::Reconfigured(v) => v,
        }
    }
}
