//! Token buckets keyed by a string, one bucket per key (spec 9.3).
//!
//! A bucket holds at most `per_minute` tokens and gains `per_minute` of them
//! per minute, so a caller that has been quiet may spend a whole minute's
//! worth at once and is then held to the steady rate. Fractional tokens are
//! kept, which is what makes half a minute worth half a minute's refill.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Bucket {
    tokens: f64,
    /// When the bucket was last refilled, which is also when it was last
    /// used: [`RateLimiter::prune`] reads it as the idle time.
    last: Instant,
}

pub struct RateLimiter {
    /// Both the capacity and the refill per minute. 0 means unlimited, and
    /// then no bucket is ever created.
    per_minute: u32,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// `per_minute` of 0 means unlimited.
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one token for `key` if one is available.
    pub fn allow(&self, key: &str) -> bool {
        self.allow_at(key, Instant::now())
    }

    /// [`RateLimiter::allow`] with the clock supplied, so a test can state
    /// the passage of time as arithmetic rather than wait for it.
    pub fn allow_at(&self, key: &str, now: Instant) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        let capacity = f64::from(self.per_minute);
        let mut buckets = self.buckets.lock().expect("rate limiter mutex");
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });
        let minutes = now.saturating_duration_since(bucket.last).as_secs_f64() / 60.0;
        bucket.tokens = (bucket.tokens + minutes * capacity).min(capacity);
        // `Instant::now()` never goes backwards, but `allow_at` takes any
        // instant a caller cares to name. Keeping the later of the two stops
        // a stale one from making the next call look like a long wait.
        bucket.last = bucket.last.max(now);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drops every bucket that has been idle for `idle` or longer, so that a
    /// key seen once does not occupy memory for the life of the process. A
    /// dropped bucket comes back full, which is right: a key idle that long
    /// would have refilled to capacity anyway.
    pub fn prune(&self, idle: Duration) {
        let now = Instant::now();
        self.buckets
            .lock()
            .expect("rate limiter mutex")
            .retain(|_, bucket| now.saturating_duration_since(bucket.last) < idle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn bucket_empties_and_refills() {
        let l = RateLimiter::new(2);
        let t0 = Instant::now();
        assert!(l.allow_at("u", t0));
        assert!(l.allow_at("u", t0));
        assert!(!l.allow_at("u", t0));
        assert!(l.allow_at("other", t0));
        assert!(l.allow_at("u", t0 + Duration::from_secs(30))); // half a minute refills one
        assert!(!l.allow_at("u", t0 + Duration::from_secs(30)));
    }

    #[test]
    fn zero_is_unlimited_and_prune_forgets_idle_keys() {
        let l = RateLimiter::new(0);
        for _ in 0..1000 {
            assert!(l.allow("u"));
        }
        let l = RateLimiter::new(1);
        assert!(l.allow("u"));
        l.prune(Duration::ZERO);
        assert!(l.allow("u")); // forgotten, so a fresh bucket
    }

    /// A bucket refills to its capacity and no further, so a long silence
    /// does not buy a burst larger than one minute's worth.
    #[test]
    fn refill_stops_at_capacity() {
        let l = RateLimiter::new(2);
        let t0 = Instant::now();
        assert!(l.allow_at("u", t0));
        let hour_later = t0 + Duration::from_secs(3600);
        assert!(l.allow_at("u", hour_later));
        assert!(l.allow_at("u", hour_later));
        assert!(!l.allow_at("u", hour_later));
    }

    /// A bucket still in use is kept, however long the process has run.
    #[test]
    fn prune_keeps_a_bucket_that_is_still_in_use() {
        let l = RateLimiter::new(1);
        assert!(l.allow("u"));
        l.prune(Duration::from_secs(600));
        assert!(!l.allow("u")); // the emptied bucket is still there
    }
}
