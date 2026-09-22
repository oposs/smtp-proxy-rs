//! Token buckets keyed by a string, one bucket per key (spec 9.3).
//!
//! A bucket holds at most `per_minute` tokens and gains `per_minute` of them
//! per minute, so a caller that has been quiet may spend a whole minute's
//! worth at once and is then held to the steady rate. Fractional tokens are
//! kept, which is what makes half a minute worth half a minute's refill.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The most distinct keys the map will hold. A key is the username claimed
/// at AUTH, which nothing has verified by the time the bucket is created, so
/// the map grows on unauthenticated input: without a ceiling a client that
/// reconnects under a new name each time adds entries for as long as the ten
/// minutes between sweeps allow.
///
/// Deliberately on the low side. Exceeding it costs only the idlest bucket,
/// which the next sweep was about to drop in any case, so a deployment that
/// somehow has more than this many distinct senders inside one prune window
/// loses nothing that matters -- being under is cheap, being over is not.
const MAX_BUCKETS: usize = 10_000;

struct Bucket {
    tokens: f64,
    /// When the bucket was last refilled, which is also when it was last
    /// used: [`RateLimiter::prune`] reads it as the idle time.
    last: Instant,
}

/// Drops the least recently used bucket, to make room for one more.
///
/// Linear in the size of the map, and it runs with the one mutex held that
/// every session's MAIL FROM also needs. Documented rather than fixed,
/// because the numbers bound it: `MAX_BUCKETS` caps the map at 10,000
/// entries, the scan happens only on an insert of a key a *full* map does
/// not already hold, and a `min_by_key` over ten thousand `Instant`s is tens
/// of microseconds. Do not read that as "no real workload reaches it" -- the
/// key is an unverified AUTH username, so filling the map is simply
/// something a client can decide to do. What the workload does bound is the
/// rate: the same client is held to `--max_messages_per_minute` and
/// `--max_connections_per_ip`, which leaves a worst case of a few
/// milliseconds of aggregate contention per second.
///
/// That trade stops holding if `MAX_BUCKETS` is ever raised past about
/// 100,000, or if a profile shows one scan costing more than a millisecond.
/// The answer then is a smaller `MAX_BUCKETS`, not a sampled LRU: sampling
/// changes which bucket is evicted, which is the behaviour
/// `the_map_is_capped_and_gives_up_its_idlest_bucket` exists to pin down.
///
/// Evicting rather than refusing is the point: a limiter that turned new
/// keys away once full would let anyone able to fill the map lock out every
/// legitimate user arriving afterwards, trading a bounded memory problem for
/// an unbounded availability one. An evicted user gets a fresh bucket, which
/// is exactly what [`RateLimiter::prune`] would have given them anyway.
fn evict_idlest(buckets: &mut HashMap<String, Bucket>) {
    let idlest = buckets
        .iter()
        .min_by_key(|(_, bucket)| bucket.last)
        .map(|(key, _)| key.clone());
    if let Some(key) = idlest {
        buckets.remove(&key);
    }
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
        // The length test comes first so that the normal path -- a map that
        // is nowhere near full -- pays nothing for the second lookup.
        if buckets.len() >= MAX_BUCKETS && !buckets.contains_key(key) {
            evict_idlest(&mut buckets);
        }
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

    /// How many buckets are held. Exposed so that the ceiling, and the fact
    /// that a refused login leaves nothing behind at all, can be asserted
    /// directly rather than only through their visible effects.
    pub fn bucket_count(&self) -> usize {
        self.buckets.lock().expect("rate limiter mutex").len()
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

    /// The map is bounded even between sweeps, and the bucket it gives up to
    /// stay bounded is the least recently used one.
    ///
    /// A key is an unverified AUTH username, so a client that reconnects
    /// under a new name each time drives the inserts; without the ceiling
    /// the map would grow for the whole ten minutes until the next sweep.
    #[test]
    fn the_map_is_capped_and_gives_up_its_idlest_bucket() {
        let l = RateLimiter::new(1);
        let t0 = Instant::now();
        // One key, then exactly enough newer ones to fill the map and ask
        // for one more place than there is.
        assert!(l.allow_at("quiet", t0));
        let busy = t0 + Duration::from_secs(1);
        for i in 0..MAX_BUCKETS {
            l.allow_at(&format!("k{i}"), busy);
        }
        assert_eq!(
            l.bucket_count(),
            MAX_BUCKETS,
            "the map grew past its ceiling"
        );
        // "quiet" was the idlest, so it is the one that went. It comes back
        // as a fresh full bucket; had it survived it would be empty, having
        // spent its only token above.
        assert!(
            l.allow_at("quiet", t0),
            "the idlest bucket was not the one evicted"
        );
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
