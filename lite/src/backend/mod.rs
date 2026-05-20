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
