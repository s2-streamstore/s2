use s2_common::{ValidationError, config::StorageClass, encryption::EncryptionSpec};

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

fn validate_storage_class(storage_class: Option<StorageClass>) -> Result<(), ValidationError> {
    if storage_class == Some(StorageClass::Native) {
        return Err(ValidationError(
            "native storage class is not supported by S2 Lite".to_owned(),
        ));
    }
    Ok(())
}
