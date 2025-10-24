use crate::record::Timestamp;

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Copy)]
pub struct CountOrBytes {
    pub count: usize,
    pub bytes: usize,
}

impl CountOrBytes {
    pub const ZERO: CountOrBytes = CountOrBytes { count: 0, bytes: 0 };

    pub const MAX: CountOrBytes = CountOrBytes {
        count: usize::MAX,
        bytes: usize::MAX,
    };
}

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ReadLimit {
    #[default]
    Unbounded,
    Count(usize),
    Bytes(usize),
    CountOrBytes(CountOrBytes),
}

#[derive(PartialEq, Debug)]
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

    pub fn from_count_and_bytes(count: Option<usize>, bytes: Option<usize>) -> Self {
        match (count, bytes) {
            (None, None) => Self::Unbounded,
            (Some(0), _) | (_, Some(0)) => Self::Count(0),
            (Some(count), None) => Self::Count(count),
            (None, Some(bytes)) => Self::Bytes(bytes),
            (Some(count), Some(bytes)) => Self::CountOrBytes(CountOrBytes { count, bytes }),
        }
    }

    pub fn count(&self) -> Option<usize> {
        match self {
            ReadLimit::Unbounded => None,
            ReadLimit::Count(count) => Some(*count),
            ReadLimit::Bytes(_) => None,
            ReadLimit::CountOrBytes(CountOrBytes { count, .. }) => Some(*count),
        }
    }

    pub fn bytes(&self) -> Option<usize> {
        match self {
            ReadLimit::Unbounded => None,
            ReadLimit::Count(_) => None,
            ReadLimit::Bytes(bytes) => Some(*bytes),
            ReadLimit::CountOrBytes(CountOrBytes { bytes, .. }) => Some(*bytes),
        }
    }

    pub fn into_allowance(self, max: CountOrBytes) -> CountOrBytes {
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

    pub fn allow(&self, additional_count: usize, additional_bytes: usize) -> bool {
        match self {
            ReadLimit::Unbounded => true,
            ReadLimit::Count(count) => additional_count <= *count,
            ReadLimit::Bytes(bytes) => additional_bytes <= *bytes,
            ReadLimit::CountOrBytes(CountOrBytes { count, bytes }) => {
                additional_count <= *count && additional_bytes <= *bytes
            }
        }
    }

    pub fn deny(&self, additional_count: usize, additional_bytes: usize) -> bool {
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
    pub fn remaining(&self, consumed_count: usize, consumed_bytes: usize) -> EvaluatedReadLimit {
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

impl From<ReadUntil> for Option<Timestamp> {
    fn from(until: ReadUntil) -> Self {
        match until {
            ReadUntil::Unbounded => None,
            ReadUntil::Timestamp(ts) => Some(ts),
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
    fn remaining(
        #[case] old_limit: ReadLimit,
        #[case] consumed_count: usize,
        #[case] consumed_bytes: usize,
        #[case] remaining_limit: EvaluatedReadLimit,
    ) {
        assert_eq!(
            old_limit.remaining(consumed_count, consumed_bytes),
            remaining_limit
        )
    }
}
