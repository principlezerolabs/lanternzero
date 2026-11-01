//! Request rate limits (spec §3.5) and push back-off (spec §5.3).
//!
//! OHTTP hides client IPs, so limits are per account and per device. Relays
//! limit per IP.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Entries kept before stale windows are pruned.
const PRUNE_AT: usize = 100_000;
/// Longest `Retry-After` honored from a push gateway.
const MAX_BACKOFF: Duration = Duration::from_secs(24 * 3600);

/// A fixed one-minute window counter per key: an account id or a device
/// id.
#[derive(Debug)]
pub struct RateLimiter<K = String> {
    per_minute: u32,
    windows: Mutex<HashMap<K, (u64, u32)>>,
}

impl<K: Hash + Eq> RateLimiter<K> {
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one request for `key`. On `Err`, the caller should answer 429
    /// with `Retry-After` set to the returned seconds.
    pub fn check<Q>(&self, key: &Q, now: SystemTime) -> Result<(), u64>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        let secs = crate::clock::unix_secs(now);
        let minute = secs / 60;
        let mut w = self.windows.lock().expect("limiter lock");
        if w.len() >= PRUNE_AT {
            w.retain(|_, (m, _)| *m == minute);
        }
        let entry = w.entry(key.to_owned()).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        if entry.1 >= self.per_minute {
            return Err(60 - secs % 60);
        }
        entry.1 += 1;
        Ok(())
    }
}

/// Devices a push gateway asked us to leave alone until a given time.
#[derive(Debug, Default)]
pub struct PushBackoff(Mutex<HashMap<String, SystemTime>>);

impl PushBackoff {
    pub fn is_paused(&self, device_id: &str, now: SystemTime) -> bool {
        let mut m = self.0.lock().expect("backoff lock");
        match m.get(device_id) {
            Some(until) if *until > now => true,
            Some(_) => {
                m.remove(device_id);
                false
            }
            None => false,
        }
    }

    /// Records a `429`. `retry_after` is the header value, if any; without
    /// one, the device skips one wake slot.
    pub fn pause(
        &self,
        device_id: &str,
        retry_after: Option<&str>,
        now: SystemTime,
        default: Duration,
    ) {
        let wait = retry_after
            .and_then(|v| parse_retry_after(v, now))
            .unwrap_or(default)
            .min(MAX_BACKOFF);
        self.0
            .lock()
            .expect("backoff lock")
            .insert(device_id.to_owned(), now + wait);
    }
}

/// `Retry-After` as delay-seconds or an HTTP-date (RFC 9110 §10.2.3).
pub fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(at.duration_since(now).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn limits_per_key_per_minute() {
        let l = RateLimiter::new(2);
        let t = UNIX_EPOCH + Duration::from_secs(600);
        assert_eq!(l.check("a", t), Ok(()));
        assert_eq!(l.check("a", t), Ok(()));
        assert_eq!(l.check("a", t + Duration::from_secs(15)), Err(45));
        assert_eq!(l.check("b", t), Ok(()));
        assert_eq!(l.check("a", t + Duration::from_secs(60)), Ok(()));
    }

    #[test]
    fn honors_retry_after_forms() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(
            parse_retry_after("120", now),
            Some(Duration::from_secs(120))
        );
        let later = httpdate::fmt_http_date(now + Duration::from_secs(300));
        assert_eq!(
            parse_retry_after(&later, now),
            Some(Duration::from_secs(300))
        );
        assert_eq!(parse_retry_after("soon", now), None);

        let b = PushBackoff::default();
        b.pause("d", Some("3600"), now, Duration::from_secs(1800));
        assert!(b.is_paused("d", now + Duration::from_secs(3599)));
        assert!(!b.is_paused("d", now + Duration::from_secs(3601)));
        b.pause("e", None, now, Duration::from_secs(1800));
        assert!(b.is_paused("e", now + Duration::from_secs(1799)));
        b.pause("f", Some("99999999"), now, Duration::from_secs(1800));
        assert!(!b.is_paused("f", now + MAX_BACKOFF + Duration::from_secs(1)));
    }
}
