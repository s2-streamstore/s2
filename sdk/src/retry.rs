use std::time::Duration;

use rand::{RngExt, rng};

#[derive(Debug, Clone, Copy)]
pub struct RetryBackoffBuilder {
    pub min_base_delay: Duration,
    pub max_base_delay: Duration,
    pub max_retries: u32,
}

impl Default for RetryBackoffBuilder {
    fn default() -> Self {
        Self {
            min_base_delay: Duration::from_millis(100),
            max_base_delay: Duration::from_secs(1),
            max_retries: 3,
        }
    }
}

impl RetryBackoffBuilder {
    pub fn with_min_base_delay(self, min_base_delay: Duration) -> Self {
        Self {
            min_base_delay,
            ..self
        }
    }

    pub fn with_max_base_delay(self, max_base_delay: Duration) -> Self {
        Self {
            max_base_delay,
            ..self
        }
    }

    pub fn with_max_retries(self, max_retries: u32) -> Self {
        Self {
            max_retries,
            ..self
        }
    }

    pub fn build(self) -> RetryBackoff {
        RetryBackoff {
            min_base_delay: self.min_base_delay,
            max_base_delay: self.max_base_delay,
            max_retries: self.max_retries,
            cur_retry: 0,
        }
    }
}

pub struct RetryBackoff {
    min_base_delay: Duration,
    max_base_delay: Duration,
    max_retries: u32,
    cur_retry: u32,
}

impl RetryBackoff {
    pub fn remaining(&self) -> u32 {
        self.max_retries.saturating_sub(self.cur_retry)
    }

    pub fn is_exhausted(&self) -> bool {
        self.cur_retry >= self.max_retries
    }

    pub fn reset(&mut self) {
        self.cur_retry = 0;
    }

    pub fn used(&self) -> u32 {
        self.cur_retry
    }
}

impl Iterator for RetryBackoff {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur_retry == self.max_retries {
            return None;
        }
        let base_delay = (self
            .min_base_delay
            .saturating_mul(2u32.saturating_pow(self.cur_retry)))
        .min(self.max_base_delay);
        let jitter =
            Duration::try_from_secs_f64(base_delay.as_secs_f64() * rng().random_range(0.0..=1.0))
                .unwrap_or(Duration::MAX);
        let delay = base_delay + jitter;
        self.cur_retry += 1;
        Some(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoffs() {
        let backoffs: Vec<_> = RetryBackoffBuilder::default()
            .with_max_retries(6)
            .build()
            .collect();

        assert_eq!(backoffs.len(), 6);
        assert!(backoffs[0] >= Duration::from_millis(100));
        assert!(backoffs[0] <= Duration::from_millis(200));

        assert!(backoffs[1] >= Duration::from_millis(200));
        assert!(backoffs[1] <= Duration::from_millis(400));

        assert!(backoffs[2] >= Duration::from_millis(400));
        assert!(backoffs[2] <= Duration::from_millis(800));

        assert!(backoffs[3] >= Duration::from_millis(800));
        assert!(backoffs[3] <= Duration::from_millis(1600));

        assert!(backoffs[4] >= Duration::from_millis(1000));
        assert!(backoffs[4] <= Duration::from_millis(2000));

        assert!(backoffs[5] >= Duration::from_millis(1000));
        assert!(backoffs[5] <= Duration::from_millis(2000));
    }

    #[test]
    fn backoff_with_reset() {
        let mut backoff = RetryBackoffBuilder::default().with_max_retries(3).build();

        assert_eq!(backoff.used(), 0);
        assert_eq!(backoff.remaining(), 3);
        assert!(!backoff.is_exhausted());

        assert!(backoff.next().is_some());
        assert_eq!(backoff.used(), 1);
        assert_eq!(backoff.remaining(), 2);
        assert!(!backoff.is_exhausted());

        backoff.reset();

        assert_eq!(backoff.used(), 0);
        assert_eq!(backoff.remaining(), 3);
        assert!(!backoff.is_exhausted());

        assert!(backoff.next().is_some());
        assert_eq!(backoff.used(), 1);
        assert_eq!(backoff.remaining(), 2);

        assert!(backoff.next().is_some());
        assert_eq!(backoff.used(), 2);
        assert_eq!(backoff.remaining(), 1);

        assert!(backoff.next().is_some());
        assert_eq!(backoff.used(), 3);
        assert_eq!(backoff.remaining(), 0);
        assert!(backoff.is_exhausted());

        assert!(backoff.next().is_none());
    }
}
