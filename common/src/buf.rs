/// Trim unused trailing capacity from `buf` when it exceeds `max_slack` bytes.
pub fn shrink_if_excess_slack(buf: &mut Vec<u8>, max_slack: usize) {
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

        let mut within_budget = Vec::with_capacity(4096);
        within_budget.extend_from_slice(&[0xCD; 2048]);
        let before = within_budget.capacity();
        shrink_if_excess_slack(&mut within_budget, 4096);
        assert_eq!(within_budget.capacity(), before);
    }

    #[test]
    fn compressed_capacity_bound_covers_overhead_and_saturates() {
        assert_eq!(compressed_capacity_bound(0), 64);
        assert_eq!(compressed_capacity_bound(1024), 1024 + 4 + 64);
        assert_eq!(compressed_capacity_bound(usize::MAX), usize::MAX);
    }
}
