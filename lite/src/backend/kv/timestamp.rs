use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TimestampSecs(u32);

impl TimestampSecs {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u32::MAX);

    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now())
    }

    pub fn after(dur: Duration) -> Self {
        match SystemTime::now().checked_add(dur) {
            Some(deadline) => Self::from_system_time(deadline),
            None => Self(u32::MAX),
        }
    }

    pub fn from_secs(secs: u32) -> Self {
        Self(secs)
    }

    pub fn from_millis(millis: i64) -> Self {
        if millis <= 0 {
            return Self::ZERO;
        }
        let secs = (millis as u64) / 1000;
        if secs >= u64::from(Self::MAX.0) {
            Self::MAX
        } else {
            Self(secs as u32)
        }
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn checked_sub_duration(self, dur: Duration) -> Option<Self> {
        u64::from(self.0)
            .checked_sub(dur.as_secs())
            .map(|secs| Self(secs as u32))
    }

    fn from_system_time(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                let secs = duration.as_secs();
                if secs >= u64::from(Self::MAX.0) {
                    Self::MAX
                } else {
                    Self(secs as u32)
                }
            }
            Err(_) => Self::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TimestampSecs;

    #[test]
    fn from_millis_converts_to_seconds() {
        assert_eq!(TimestampSecs::from_millis(-1), TimestampSecs::ZERO);
        assert_eq!(TimestampSecs::from_millis(0), TimestampSecs::ZERO);
        assert_eq!(
            TimestampSecs::from_millis(1_999),
            TimestampSecs::from_secs(1)
        );
        assert_eq!(TimestampSecs::from_millis(i64::MAX), TimestampSecs::MAX);
    }

    #[test]
    fn checked_sub_duration_subtracts_seconds() {
        assert_eq!(
            TimestampSecs::from_secs(10).checked_sub_duration(std::time::Duration::from_secs(3)),
            Some(TimestampSecs::from_secs(7))
        );
        assert_eq!(
            TimestampSecs::from_secs(3).checked_sub_duration(std::time::Duration::from_secs(10)),
            None
        );
    }
}
