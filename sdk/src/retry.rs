use std::time::Duration;

use rand::{RngExt, rng};

use crate::types::RetryConfig;

pub(crate) struct RetryBackoff {
    min_base_delay: Duration,
    max_base_delay: Duration,
    max_retries: u32,
    cur_retry: u32,
}

impl RetryBackoff {
    pub(crate) fn from_config(config: &RetryConfig) -> Self {
        Self {
            min_base_delay: config.min_base_delay,
            max_base_delay: config.max_base_delay,
            max_retries: config.max_retries(),
            cur_retry: 0,
        }
    }

    /// Compute the base delay for `retry_index` (`T3`: `min(min_base_delay * 2^n,
    /// max_base_delay)`).
    fn base_delay_for(&self, retry_index: u32) -> Duration {
        if self.min_base_delay.is_zero() || self.min_base_delay >= self.max_base_delay {
            return self.min_base_delay.min(self.max_base_delay);
        }
        let mut delay = self.min_base_delay;
        for _ in 0..retry_index {
            delay = delay.saturating_mul(2);
            if delay >= self.max_base_delay {
                return self.max_base_delay;
            }
        }
        delay
    }

    /// Return the next exponential-backoff delay ignoring `max_retries` (`T3`, `T5b`).
    pub(crate) fn next_unbounded(&mut self) -> Duration {
        let base_delay = self.base_delay_for(self.cur_retry);
        self.cur_retry = self.cur_retry.saturating_add(1);
        jittered_delay(base_delay)
    }

    pub(crate) fn remaining(&self) -> u32 {
        self.max_retries.saturating_sub(self.cur_retry)
    }

    pub(crate) fn is_exhausted(&self) -> bool {
        self.cur_retry >= self.max_retries
    }

    pub(crate) fn reset(&mut self) {
        self.cur_retry = 0;
    }

    /// 1-based attempt number for the current try (1 on initial try, 2 on first retry, etc.).
    pub(crate) fn attempt_number(&self) -> u32 {
        self.cur_retry.saturating_add(1)
    }
}

impl Iterator for RetryBackoff {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_exhausted() {
            return None;
        }
        Some(self.next_unbounded())
    }
}

fn jittered_delay(base_delay: Duration) -> Duration {
    let jitter =
        Duration::try_from_secs_f64(base_delay.as_secs_f64() * rng().random_range(0.0..=1.0))
            .unwrap_or(Duration::MAX);
    base_delay.saturating_add(jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case::budgeted_cap_1s(7, Duration::from_secs(1), true)]
    #[case::unbounded_zero_budget(1, Duration::from_secs(1), false)]
    #[case::unbounded_cap_7s(2, Duration::from_secs(7), false)]
    fn backoff_ramps_and_caps_with_jitter(
        #[case] max_attempts: u32,
        #[case] max_base_delay: Duration,
        #[case] budgeted: bool,
    ) {
        let min = Duration::from_millis(100);
        let config = RetryConfig::new()
            .with_max_attempts(max_attempts)
            .with_min_base_delay(min)
            .with_max_base_delay(max_base_delay);
        let mut backoff = RetryBackoff::from_config(&config);

        if budgeted {
            assert_eq!(backoff.attempt_number(), 1);
            assert_eq!(backoff.remaining(), max_attempts - 1);
            assert!(backoff.next().is_some());
            assert_eq!(backoff.attempt_number(), 2);
            backoff.reset();
            assert_eq!(backoff.attempt_number(), 1);
            assert_eq!(backoff.remaining(), max_attempts - 1);

            let delays: Vec<_> = backoff.by_ref().collect();
            assert_eq!(delays.len(), (max_attempts - 1) as usize);
            assert!(backoff.is_exhausted());
            for (i, d) in delays.into_iter().enumerate() {
                let expected = min.saturating_mul(2u32.pow(i as u32)).min(max_base_delay);
                assert!(d >= expected && d <= expected * 2, "step {i}: {d:?}");
            }
        } else {
            // Exhaust budgeted retries first (if any), then verify unbounded ramp + cap.
            for i in 0..8u32 {
                let expected = min.saturating_mul(2u32.pow(i)).min(max_base_delay);
                let d = backoff.next().unwrap_or_else(|| backoff.next_unbounded());
                assert!(d >= expected && d <= expected * 2, "step {i}: {d:?}");
            }
            assert!(backoff.is_exhausted());
            assert_eq!(backoff.attempt_number(), 9);

            backoff.reset();
            let after_reset = backoff.next_unbounded();
            assert!(after_reset >= min && after_reset <= min * 2);
        }
    }

    #[test]
    fn base_delay_reaches_max_past_32_retries() {
        let config = RetryConfig::new()
            .with_min_base_delay(Duration::from_nanos(10))
            .with_max_base_delay(Duration::from_secs(60));
        let backoff = RetryBackoff::from_config(&config);
        // 10ns * 2^32 = ~42.95s < 60s; retry 33 must double past 2^32 and hit 60s cap.
        assert_eq!(backoff.base_delay_for(33), Duration::from_secs(60));
        assert_eq!(backoff.base_delay_for(u32::MAX), Duration::from_secs(60));
    }
}
