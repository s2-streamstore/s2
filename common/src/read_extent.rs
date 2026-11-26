use crate::record::Timestamp;

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Copy)]
pub struct CountOrBytes {
    pub count: u64,
    pub bytes: u64,
}

impl CountOrBytes {
    pub const ZERO: CountOrBytes = CountOrBytes { count: 0, bytes: 0 };

    pub const MAX: CountOrBytes = CountOrBytes {
        count: u64::MAX,
        bytes: u64::MAX,
    };
}

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ReadLimit {
    #[default]
    Unbounded,
    Count(u64),
    Bytes(u64),
    CountOrBytes(CountOrBytes),
}

#[derive(PartialEq, Eq, Debug)]
pub enum EvaluatedReadLimit {
    Remaining(ReadLimit),
    Exhausted,
}

impl ReadLimit {
    pub fn is_unbounded(&self) -> bool {
        matches!(self, ReadLimit::Unbounded)
    }

    pub fn is_bounded(&self) -> bool {
        !matches!(self, ReadLimit::Unbounded)
    }

    pub fn from_count_and_bytes(count: Option<u64>, bytes: Option<u64>) -> Self {
        match (count, bytes) {
            (None, None) => Self::Unbounded,
            (Some(0), _) | (_, Some(0)) => Self::Count(0),
            (Some(count), None) => Self::Count(count),
            (None, Some(bytes)) => Self::Bytes(bytes),
            (Some(count), Some(bytes)) => Self::CountOrBytes(CountOrBytes { count, bytes }),
        }
    }

    pub fn count(&self) -> Option<u64> {
        match self {
            ReadLimit::Unbounded => None,
            ReadLimit::Count(count) => Some(*count),
            ReadLimit::Bytes(_) => None,
            ReadLimit::CountOrBytes(CountOrBytes { count, .. }) => Some(*count),
        }
    }

    pub fn bytes(&self) -> Option<u64> {
        match self {
            ReadLimit::Unbounded => None,
            ReadLimit::Count(_) => None,
            ReadLimit::Bytes(bytes) => Some(*bytes),
            ReadLimit::CountOrBytes(CountOrBytes { bytes, .. }) => Some(*bytes),
        }
    }

    /// Clamp each dimension of this limit to `max`, filling any unbounded dimension with the
    /// corresponding bound from `max`.
    pub fn into_allowance(self, max: impl Into<CountOrBytes>) -> CountOrBytes {
        let max = max.into();
        match self {
            ReadLimit::Unbounded => max,
            ReadLimit::Count(count) => CountOrBytes {
                count: count.min(max.count),
                bytes: max.bytes,
            },
            ReadLimit::Bytes(bytes) => CountOrBytes {
                count: max.count,
                bytes: bytes.min(max.bytes),
            },
            ReadLimit::CountOrBytes(CountOrBytes { count, bytes }) => CountOrBytes {
                count: count.min(max.count),
                bytes: bytes.min(max.bytes),
            },
        }
    }

    pub fn allow(&self, additional_count: u64, additional_bytes: u64) -> bool {
        match self {
            ReadLimit::Unbounded => true,
            ReadLimit::Count(count) => additional_count <= *count,
            ReadLimit::Bytes(bytes) => additional_bytes <= *bytes,
            ReadLimit::CountOrBytes(CountOrBytes { count, bytes }) => {
                additional_count <= *count && additional_bytes <= *bytes
            }
        }
    }

    pub fn deny(&self, additional_count: u64, additional_bytes: u64) -> bool {
        match self {
            ReadLimit::Unbounded => false,
            ReadLimit::Count(count) => additional_count > *count,
            ReadLimit::Bytes(bytes) => additional_bytes > *bytes,
            ReadLimit::CountOrBytes(CountOrBytes { count, bytes }) => {
                additional_count > *count || additional_bytes > *bytes
            }
        }
    }

    /// Given the amount of records already consumed, generate a new `ReadLimit` representing
    /// the remaining limit, or none if the limit has been met.
    pub fn remaining(&self, consumed_count: u64, consumed_bytes: u64) -> EvaluatedReadLimit {
        let remaining = match self {
            ReadLimit::Unbounded => Some(ReadLimit::Unbounded),
            ReadLimit::Count(count) => {
                (consumed_count < *count).then(|| ReadLimit::Count(count - consumed_count))
            }
            ReadLimit::Bytes(bytes) => {
                (consumed_bytes < *bytes).then(|| ReadLimit::Bytes(bytes - consumed_bytes))
            }
            ReadLimit::CountOrBytes(CountOrBytes { count, bytes }) => {
                (consumed_count < *count && consumed_bytes < *bytes).then(|| {
                    ReadLimit::CountOrBytes(CountOrBytes {
                        count: count - consumed_count,
                        bytes: bytes - consumed_bytes,
                    })
                })
            }
        };

        match remaining {
            Some(limit) => EvaluatedReadLimit::Remaining(limit),
            None => EvaluatedReadLimit::Exhausted,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ReadUntil {
    #[default]
    Unbounded,
    Timestamp(Timestamp),
}

impl From<Option<Timestamp>> for ReadUntil {
    fn from(timestamp: Option<Timestamp>) -> Self {
        match timestamp {
            Some(ts) => ReadUntil::Timestamp(ts),
            None => ReadUntil::Unbounded,
        }
    }
}

impl ReadUntil {
    pub fn is_unbounded(&self) -> bool {
        matches!(self, ReadUntil::Unbounded)
    }

    pub fn is_timestamp(&self) -> bool {
        matches!(self, ReadUntil::Timestamp(_))
    }

    pub fn allow(&self, timestamp: Timestamp) -> bool {
        match self {
            ReadUntil::Unbounded => true,
            ReadUntil::Timestamp(t) => timestamp < *t,
        }
    }

    pub fn deny(&self, timestamp: Timestamp) -> bool {
        match self {
            ReadUntil::Unbounded => false,
            ReadUntil::Timestamp(t) => timestamp >= *t,
        }
    }
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::{CountOrBytes, EvaluatedReadLimit, ReadLimit};

    #[rstest]
    #[case(
        ReadLimit::Count(100),
        10,
        100000,
        EvaluatedReadLimit::Remaining(ReadLimit::Count(90))
    )]
    #[case(ReadLimit::Count(100), 100, 100000, EvaluatedReadLimit::Exhausted)]
    #[case(
        ReadLimit::Bytes(100),
        1000,
        99,
        EvaluatedReadLimit::Remaining(ReadLimit::Bytes(1))
    )]
    #[case(ReadLimit::CountOrBytes(CountOrBytes{count: 50, bytes: 50}), 40, 45, EvaluatedReadLimit::Remaining(ReadLimit::CountOrBytes(CountOrBytes{count: 10, bytes: 5})))]
    #[case(ReadLimit::CountOrBytes(CountOrBytes{count: 50, bytes: 50}), 51, 45, EvaluatedReadLimit::Exhausted)]
    #[case(
        ReadLimit::CountOrBytes(CountOrBytes {
            count: u64::from(u32::MAX) + 10,
            bytes: u64::MAX,
        }),
        10,
        100,
        EvaluatedReadLimit::Remaining(ReadLimit::CountOrBytes(CountOrBytes {
            count: u64::from(u32::MAX),
            bytes: u64::MAX - 100,
        }))
    )]
    fn remaining(
        #[case] old_limit: ReadLimit,
        #[case] consumed_count: u64,
        #[case] consumed_bytes: u64,
        #[case] remaining_limit: EvaluatedReadLimit,
    ) {
        assert_eq!(
            old_limit.remaining(consumed_count, consumed_bytes),
            remaining_limit
        )
    }

    #[rstest]
    #[case::unbounded(
        ReadLimit::Unbounded,
        CountOrBytes {
            count: crate::caps::RECORD_BATCH_MAX.count as u64,
            bytes: crate::caps::RECORD_BATCH_MAX.bytes as u64,
        }
    )]
    #[case::count_below_cap(
        ReadLimit::Count(500),
        CountOrBytes {
            count: 500,
            bytes: crate::caps::RECORD_BATCH_MAX.bytes as u64,
        }
    )]
    #[case::count_above_cap(
        ReadLimit::Count(u64::MAX),
        CountOrBytes {
            count: crate::caps::RECORD_BATCH_MAX.count as u64,
            bytes: crate::caps::RECORD_BATCH_MAX.bytes as u64,
        }
    )]
    #[case::bytes_below_cap(
        ReadLimit::Bytes(1024),
        CountOrBytes {
            count: crate::caps::RECORD_BATCH_MAX.count as u64,
            bytes: 1024,
        }
    )]
    #[case::bytes_above_cap(
        ReadLimit::Bytes(u64::MAX),
        CountOrBytes {
            count: crate::caps::RECORD_BATCH_MAX.count as u64,
            bytes: crate::caps::RECORD_BATCH_MAX.bytes as u64,
        }
    )]
    #[case::both_mixed(
        ReadLimit::from_count_and_bytes(Some(500), Some(u64::MAX)),
        CountOrBytes {
            count: 500,
            bytes: crate::caps::RECORD_BATCH_MAX.bytes as u64,
        }
    )]
    fn into_allowance_with_batch_limits(#[case] limit: ReadLimit, #[case] expected: CountOrBytes) {
        assert_eq!(
            limit.into_allowance(crate::caps::RECORD_BATCH_MAX),
            expected
        );
    }
}
