pub const MIN_BASIN_NAME_LEN: usize = 8;
pub const MAX_BASIN_NAME_LEN: usize = 48;

pub const MAX_STREAM_NAME_LEN: usize = 512;

pub const MAX_TOKEN_ID_LEN: usize = 96;

/// All record batches in the system are limited to 1000 records.
/// Batches are limited to a collective size of 1 MiB, which is also the maximum size of a single
/// record.
pub const RECORD_BATCH_MAX: crate::read_extent::CountOrBytes = crate::read_extent::CountOrBytes {
    count: 1000,
    bytes: 1024 * 1024,
};
