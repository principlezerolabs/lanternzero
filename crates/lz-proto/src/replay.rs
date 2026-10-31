//! Per-device replay window for `seq` (spec §3.4): the 64 most recent values
//! up to and including the highest accepted one, as in IPsec and DTLS.

/// Values tracked, ending at the highest accepted `seq`.
pub const WINDOW: u64 = 64;

/// The `seq` a wallet sends next: the current time in milliseconds, or one
/// more than the last value sent if the clock hasn't moved past it.
///
/// Time-based values keep increasing even if the app's storage is wiped or
/// restored from an old backup, so a device never gets stuck below its own
/// window (spec §3.4).
pub fn next_seq(last_sent: Option<u64>, now_unix_ms: u64) -> u64 {
    match last_sent {
        Some(last) if last >= now_unix_ms => last.saturating_add(1),
        _ => now_unix_ms,
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayError {
    #[error("seq {0} was already used")]
    Duplicate(u64),
    #[error("seq {0} is too old")]
    TooOld(u64),
}

/// Replay state for one device. Holds no key material, so servers may store
/// it on disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeqWindow {
    /// Highest accepted `seq`, if any.
    pub highest: Option<u64>,
    /// Bit `i` set means `highest - i` was accepted.
    pub seen: u64,
}

impl SeqWindow {
    /// Accepts `seq` if it is new and inside the window, and records it.
    pub fn accept(&mut self, seq: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            self.highest = Some(seq);
            self.seen = 1;
            return Ok(());
        };
        if seq > highest {
            let shift = seq - highest;
            self.seen = if shift >= WINDOW {
                0
            } else {
                self.seen << shift
            };
            self.seen |= 1;
            self.highest = Some(seq);
            return Ok(());
        }
        let behind = highest - seq;
        if behind >= WINDOW {
            return Err(ReplayError::TooOld(seq));
        }
        let bit = 1u64 << behind;
        if self.seen & bit != 0 {
            return Err(ReplayError::Duplicate(seq));
        }
        self.seen |= bit;
        Ok(())
    }

    /// The `min_seq` to report with a `stale-seq` error (spec §3.4): a value
    /// this window will always accept.
    pub fn min_seq(&self) -> u64 {
        self.highest.map_or(0, |h| h.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_increasing_and_out_of_order_inside_window() {
        let mut w = SeqWindow::default();
        for s in [5, 7, 6, 100, 99, 37] {
            assert_eq!(w.accept(s), Ok(()), "seq {s}");
        }
    }

    #[test]
    fn rejects_duplicates_and_old_values() {
        let mut w = SeqWindow::default();
        w.accept(10).unwrap();
        assert_eq!(w.accept(10), Err(ReplayError::Duplicate(10)));
        w.accept(200).unwrap();
        assert_eq!(w.accept(136), Err(ReplayError::TooOld(136)));
        assert_eq!(w.accept(137), Ok(()));
        assert_eq!(w.accept(137), Err(ReplayError::Duplicate(137)));
    }

    #[test]
    fn min_seq_is_always_accepted() {
        let mut w = SeqWindow::default();
        assert_eq!(w.min_seq(), 0);
        w.accept(1_700_000_000_000).unwrap();
        let m = w.min_seq();
        assert_eq!(w.accept(m), Ok(()));
    }

    #[test]
    fn next_seq_follows_the_clock_and_never_repeats() {
        assert_eq!(next_seq(None, 1_000), 1_000);
        assert_eq!(next_seq(Some(500), 1_000), 1_000);
        assert_eq!(next_seq(Some(1_000), 1_000), 1_001);
        assert_eq!(next_seq(Some(5_000), 1_000), 5_001);
        assert_eq!(next_seq(Some(u64::MAX), 1), u64::MAX);
    }

    /// The attack spec §3.4 exists for: a relay replays an old `wake` that
    /// carried a key, after the user opted out.
    #[test]
    fn replayed_lease_after_opt_out_is_rejected() {
        let mut w = SeqWindow::default();
        w.accept(41).unwrap(); // wake with a key
        w.accept(42).unwrap(); // wake with lease: null
        assert!(w.accept(41).is_err());
    }
}
