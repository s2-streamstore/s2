use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TimestampSecs(u32);

impl TimestampSecs {
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
            return Self(0);
        }
        let secs = (millis as u64) / 1000;
        if secs >= u64::from(u32::MAX) {
            Self(u32::MAX)
        } else {
            Self(secs as u32)
        }
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }

    fn from_system_time(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                let secs = duration.as_secs();
                if secs >= u64::from(u32::MAX) {
                    Self(u32::MAX)
                } else {
                    Self(secs as u32)
                }
            }
            Err(_) => Self(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TimestampSecs;

    #[test]
    fn from_millis_converts_to_seconds() {
        assert_eq!(TimestampSecs::from_millis(-1), TimestampSecs::from_secs(0));
        assert_eq!(TimestampSecs::from_millis(0), TimestampSecs::from_secs(0));
        assert_eq!(
            TimestampSecs::from_millis(1_999),
            TimestampSecs::from_secs(1)
        );
        assert_eq!(
            TimestampSecs::from_millis(i64::MAX),
            TimestampSecs::from_secs(u32::MAX)
        );
    }
}
