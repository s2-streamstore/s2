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
