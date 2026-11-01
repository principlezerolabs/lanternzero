//! Per-device and per-server-key rate limits (spec §5.3).
//!
//! Binding stops other servers from pushing to a device, but not the
//! device's own server from pushing too often. Background wakes and
//! visible payment alerts get separate hourly budgets per device; a server
//! key also has an overall per-minute budget.

use std::collections::HashMap;
use std::sync::Mutex;

/// A fixed-window counter: at most `limit` hits per `window_secs` per key.
#[derive(Debug)]
pub struct Window {
    limit: u32,
    window_secs: u64,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// The window the map was last pruned in.
    pruned: u64,
    /// Per key: its window and its count in that window.
    counts: HashMap<[u8; 32], (u64, u32)>,
}

impl Window {
    pub fn new(limit: u32, window_secs: u64) -> Self {
        Self {
            limit,
            window_secs,
            state: Mutex::new(State::default()),
        }
    }

    /// Counts a hit for `key` at `now_unix`. On `Err`, the seconds until the
    /// window resets, for `Retry-After`.
    pub fn hit(&self, key: [u8; 32], now_unix: u64) -> Result<(), u64> {
        let slot = now_unix / self.window_secs;
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Once per window, drop keys not seen in it: memory stays bounded by
        // the keys active in one window, and no hit pays for a full scan.
        if st.pruned != slot {
            st.counts.retain(|_, (s, _)| *s == slot);
            st.pruned = slot;
        }
        let e = st.counts.entry(key).or_insert((slot, 0));
        if e.0 != slot {
            *e = (slot, 0);
        }
        if e.1 >= self.limit {
            return Err(self.window_secs - now_unix % self.window_secs);
        }
        e.1 += 1;
        Ok(())
    }
}

/// The gateway's limits, from config.
#[derive(Debug)]
pub struct Limits {
    pub background: Window,
    pub alert: Window,
    pub per_server: Window,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_per_key_and_resets_each_window() {
        let w = Window::new(2, 3600);
        let t = 7200;
        assert_eq!(w.hit([1; 32], t), Ok(()));
        assert_eq!(w.hit([1; 32], t + 1), Ok(()));
        assert_eq!(w.hit([1; 32], t + 600), Err(3000));
        assert_eq!(w.hit([2; 32], t), Ok(()));
        assert_eq!(w.hit([1; 32], t + 3600), Ok(()));
    }

    #[test]
    fn forgets_keys_from_past_windows() {
        let w = Window::new(1, 60);
        for i in 0..100u8 {
            w.hit([i; 32], 600).unwrap();
        }
        w.hit([200; 32], 660).unwrap();
        assert_eq!(w.state.lock().unwrap().counts.len(), 1);
    }
}
