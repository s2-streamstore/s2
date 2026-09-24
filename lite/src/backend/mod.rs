use s2_common::{
    config::{OptionalStreamConfig, StreamConfig},
    encryption::EncryptionSpec,
};

pub mod error;

mod basins;
pub mod bgtasks;
mod core;
mod durability_notifier;
mod read;
mod store;
mod streamer;
mod streams;

#[cfg(test)]
mod test_util;

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

fn resolve_stream_config(
    config: OptionalStreamConfig,
    basin_defaults: OptionalStreamConfig,
) -> StreamConfig {
    let mut config = config.merge(basin_defaults);
    config.storage_class.get_or_insert_with(|| "express".into());
    config
}
