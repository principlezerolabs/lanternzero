//! The server's clock, and Unix time in whole seconds.
//!
//! The scanner, limiters, and push scheduler take a [`SystemTime`]; the
//! store and key files keep Unix seconds, as they write them to disk.
//! [`unix_secs`] converts at that boundary.
//!
//! Everything that runs inside a server reads the time from its
//! [`Clock`] (`AppState::clock`), never from `SystemTime::now()`, so tests
//! can move it forward and check that leases and events expire through the
//! real API and background loops (invariants 2 and 3). Commands that run
//! without a server (`init`, `doctor`, key rotation) use [`unix_now`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch; 0 for a time before it.
pub fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// The current Unix time in seconds, from the system clock.
pub fn unix_now() -> u64 {
    unix_secs(SystemTime::now())
}

/// The system clock, plus however far tests have moved it forward.
///
/// The server itself never moves it, so in production it is the system
/// clock. It only moves forward, so time never runs backwards for the
/// code reading it.
#[derive(Debug, Default)]
pub struct Clock {
    ahead_ms: AtomicU64,
}

impl Clock {
    pub fn now(&self) -> SystemTime {
        SystemTime::now() + Duration::from_millis(self.ahead_ms.load(Ordering::Relaxed))
    }

    /// [`Clock::now`] in Unix seconds.
    pub fn unix_now(&self) -> u64 {
        unix_secs(self.now())
    }

    /// Moves the clock forward by `by`. For tests only.
    pub fn advance(&self, by: Duration) {
        let ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.ahead_ms.fetch_add(ms, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_and_clamps_before_the_epoch() {
        assert_eq!(unix_secs(UNIX_EPOCH + Duration::from_millis(5_999)), 5);
        assert_eq!(unix_secs(UNIX_EPOCH - Duration::from_secs(1)), 0);
        assert!(unix_now() > 1_700_000_000);
    }

    #[test]
    fn a_clock_follows_the_system_until_moved_forward() {
        let c = Clock::default();
        assert!(c.unix_now().abs_diff(unix_now()) <= 1);
        c.advance(Duration::from_secs(86_400));
        c.advance(Duration::from_secs(3_600));
        assert!(c.unix_now().abs_diff(unix_now() + 90_000) <= 1);
    }
}
