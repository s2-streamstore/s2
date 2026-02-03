pub mod error;

mod basins;
pub mod bgtasks;
mod core;
mod read;
mod store;
mod streamer;
mod streams;

mod append;
mod kv;
mod stream_id;

pub use core::Backend;

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
