use std::time::Duration;

use rand::{RngExt, rng};

use crate::frame_signal::FrameSignal;

pub(crate) trait AppendRetryError: Sized {
    /// Whether the failure represented by this error guarantees that no mutation occurred.
    fn has_no_side_effects(&self) -> bool;

    /// Mark the whole append as indefinite, retaining this final attempt's definite error.
    /// The caller must establish that an earlier attempt may have taken effect.
    fn into_indefinite_failure(self) -> Self;

    /// Wrap a definite final error if an earlier attempt may have taken effect.
    /// Already indefinite errors are returned unchanged.
    fn with_prior_uncertainty(self, prior_uncertainty: bool) -> Self {
        if prior_uncertainty && self.has_no_side_effects() {
            self.into_indefinite_failure()
        } else {
            self
        }
    }

    /// Whether this attempt may have taken effect, accounting for unsent request data.
    /// Without a frame signal, assume the request may have been sent.
    fn attempt_may_have_side_effects(&self, frame_signal: Option<&FrameSignal>) -> bool {
        !self.has_no_side_effects() && frame_signal.is_none_or(|s| s.is_signalled())
    }
}

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
    /// Compute the base delay for `cur_retry` (`T3`: `min(min_base_delay * 2^n, max_base_delay)`).
    fn base_delay_for(&self, retry_index: u32) -> Duration {
        self.min_base_delay
            .saturating_mul(2u32.saturating_pow(retry_index))
            .min(self.max_base_delay)
    }

    /// Return the next exponential-backoff delay ignoring `max_retries` (`T3`, `T5b`).
    pub fn next_or_max(&mut self) -> Duration {
        let base_delay = self.base_delay_for(self.cur_retry);
        self.cur_retry = self.cur_retry.saturating_add(1);
        jittered_delay(base_delay)
    }

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
        if self.cur_retry >= self.max_retries {
            return None;
        }
        let base_delay = self.base_delay_for(self.cur_retry);
        self.cur_retry += 1;
        Some(jittered_delay(base_delay))
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
    fn next_or_max_ramps_exponentially_even_with_zero_max_retries() {
        let mut backoff = RetryBackoffBuilder::default()
            .with_min_base_delay(Duration::from_millis(100))
            .with_max_base_delay(Duration::from_millis(1000))
            .with_max_retries(0)
            .build();

        let d0 = backoff.next_or_max();
        assert!(d0 >= Duration::from_millis(100) && d0 <= Duration::from_millis(200));
        let d1 = backoff.next_or_max();
        assert!(d1 >= Duration::from_millis(200) && d1 <= Duration::from_millis(400));
        let d2 = backoff.next_or_max();
        assert!(d2 >= Duration::from_millis(400) && d2 <= Duration::from_millis(800));
        let d3 = backoff.next_or_max();
        assert!(d3 >= Duration::from_millis(800) && d3 <= Duration::from_millis(1600));
        let d4 = backoff.next_or_max();
        assert!(d4 >= Duration::from_millis(1000) && d4 <= Duration::from_millis(2000));
        assert_eq!(backoff.used(), 5);

        backoff.reset();
        let after_reset = backoff.next_or_max();
        assert!(
            after_reset >= Duration::from_millis(100) && after_reset <= Duration::from_millis(200)
        );
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

    #[test]
    fn next_or_max_continues_with_capped_jitter() {
        let delay = Duration::from_secs(7);
        let mut backoff = RetryBackoffBuilder::default()
            .with_min_base_delay(Duration::from_millis(100))
            .with_max_base_delay(delay)
            .with_max_retries(1)
            .build();
        // Retry 0: 100ms..=200ms (consumes the 1 budgeted retry).
        let d0 = backoff.next().unwrap();
        assert!(d0 >= Duration::from_millis(100) && d0 <= Duration::from_millis(200));
        assert!(backoff.next().is_none());

        // Retries 1..=6 ramp exponentially: 200ms, 400ms, 800ms, 1.6s, 3.2s, 6.4s.
        for retry in 1u32..=6 {
            let expected = Duration::from_millis(100) * 2u32.pow(retry);
            let next = backoff.next_or_max();
            assert!(next >= expected && next <= expected * 2);
        }

        // Subsequent retries cap at max_base_delay (7s..=14s).
        for _ in 0..10 {
            let next = backoff.next_or_max();
            assert!(next >= delay);
            assert!(next <= delay * 2);
        }
        assert!(backoff.is_exhausted());
    }
}
