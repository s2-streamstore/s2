pub mod error;

use s2_common::types::{basin::BasinName, stream::StreamName};

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
pub(crate) mod stream_id;

pub use core::Backend;

#[inline]
pub fn aad(basin: &BasinName, stream: &StreamName) -> [u8; stream_id::StreamId::LEN] {
    *stream_id::StreamId::new(basin, stream).as_bytes()
}

pub const FOLLOWER_MAX_LAG: usize = 25;

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
