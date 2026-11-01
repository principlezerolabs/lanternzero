//! Unix time, in whole seconds.
//!
//! The scanner, limiters, and push scheduler take a [`SystemTime`]; the
//! store and key files keep Unix seconds, as they write them to disk.
//! These convert at that boundary.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch; 0 for a time before it.
pub fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// The current Unix time in seconds.
pub fn unix_now() -> u64 {
    unix_secs(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn converts_and_clamps_before_the_epoch() {
        assert_eq!(unix_secs(UNIX_EPOCH + Duration::from_millis(5_999)), 5);
        assert_eq!(unix_secs(UNIX_EPOCH - Duration::from_secs(1)), 0);
        assert!(unix_now() > 1_700_000_000);
    }
}
