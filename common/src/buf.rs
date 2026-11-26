/// Maximum zstd decoder window log (2^24 = 16 MiB).
///
/// Covers standard streaming zstd encoders (e.g. 8 MiB default `windowLog=23`) while bounding
/// decoder memory well below libzstd's 128 MiB default.
pub const ZSTD_MAX_WINDOW_LOG: u32 = 24;

/// Trim unused trailing capacity from `buf` when it exceeds `max(buf.len() / 8, min_slack)` bytes.
pub fn shrink_if_excess_slack(buf: &mut Vec<u8>, min_slack: usize) {
    let max_slack = (buf.len() / 8).max(min_slack);
    if buf.capacity().saturating_sub(buf.len()) > max_slack {
        buf.shrink_to_fit();
    }
}

/// Upper bound on compressed output size for `raw_len` bytes of incompressible input.
///
/// Matches a branchless upper bound on libzstd's `ZSTD_COMPRESSBOUND` (and covers gzip's framing
/// and stored-block overhead) so incompressible payloads do not overflow and reallocate mid-write.
#[must_use]
pub const fn compressed_capacity_bound(raw_len: usize) -> usize {
    raw_len.saturating_add(raw_len >> 8).saturating_add(64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shrink_if_excess_slack_reduces_only_when_above_threshold() {
        let mut oversized = Vec::with_capacity(64 * 1024);
        oversized.extend_from_slice(&[0xAB; 512]);
        assert!(oversized.capacity() >= 64 * 1024);
        shrink_if_excess_slack(&mut oversized, 4096);
        assert!(
            oversized.capacity() < 4096,
            "expected capacity to shrink, got {}",
            oversized.capacity()
        );

        let mut within_floor = Vec::with_capacity(4096);
        within_floor.extend_from_slice(&[0xCD; 2048]);
        let before = within_floor.capacity();
        shrink_if_excess_slack(&mut within_floor, 4096);
        assert_eq!(within_floor.capacity(), before);

        // Slack above min_slack (4096) but within len / 8 (8192) is preserved.
        let mut within_ratio = Vec::with_capacity(64 * 1024 + 6000);
        within_ratio.resize(64 * 1024, 0xEF);
        let before = within_ratio.capacity();
        shrink_if_excess_slack(&mut within_ratio, 4096);
        assert_eq!(within_ratio.capacity(), before);
    }

    #[test]
    fn compressed_capacity_bound_covers_overhead_and_saturates() {
        assert_eq!(compressed_capacity_bound(0), 64);
        assert_eq!(compressed_capacity_bound(1024), 1024 + 4 + 64);
        assert_eq!(compressed_capacity_bound(usize::MAX), usize::MAX);
    }
}
