use s2_common::encryption::EncryptionSpec;

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

pub struct StreamHandle {
    db: slatedb::Db,
    client: streamer::GuardedStreamerClient,
    encryption: EncryptionSpec,
}

pub const FOLLOWER_MAX_LAG: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsureResult<T> {
    Created(T),
    Updated(T),
}

impl<T> EnsureResult<T> {
    pub fn into_inner(self) -> T {
        match self {
            Self::Created(v) | Self::Updated(v) => v,
        }
    }
}
