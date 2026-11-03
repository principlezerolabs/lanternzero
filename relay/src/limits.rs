//! Per-client rate limits, held in memory only (relay/DESIGN.md, "Rules").
//!
//! A client is an IPv4 address or an IPv6 /64, since one host usually holds
//! a whole /64. The tables hold client addresses, so they live only in
//! memory: a restart forgets them, and nothing logs them.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// A client address reduced to what limits are counted on.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientKey([u8; 16]);

impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientKey(<redacted>)")
    }
}

impl ClientKey {
    pub fn of(ip: IpAddr) -> Self {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match ip {
            IpAddr::V4(v4) => Self(v4.to_ipv6_mapped().octets()),
            IpAddr::V6(v6) => {
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&v6.octets()[..8]);
                Self(b)
            }
        }
    }
}

/// A fixed-window counter: at most `limit` hits per `window_secs` per key.
/// The same shape as the gateway's (`gateway/src/limits.rs`).
#[derive(Debug)]
pub struct Window {
    limit: u32,
    window_secs: u64,
    state: Mutex<WindowState>,
}

#[derive(Debug, Default)]
struct WindowState {
    pruned: u64,
    counts: HashMap<ClientKey, (u64, u32)>,
}

impl Window {
    pub fn new(limit: u32, window_secs: u64) -> Self {
        Self {
            limit,
            window_secs,
            state: Mutex::new(WindowState::default()),
        }
    }

    /// Counts a hit at `now_secs`. On `Err`, the seconds until the window
    /// resets, for `Retry-After`.
    pub fn hit(&self, key: ClientKey, now_secs: u64) -> Result<(), u64> {
        let slot = now_secs / self.window_secs;
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Once per window, drop keys not seen in it, so memory stays bounded
        // by the clients active in one window.
        if st.pruned != slot {
            st.counts.retain(|_, (s, _)| *s == slot);
            st.pruned = slot;
        }
        let e = st.counts.entry(key).or_insert((slot, 0));
        if e.0 != slot {
            *e = (slot, 0);
        }
        if e.1 >= self.limit {
            return Err(self.window_secs - now_secs % self.window_secs);
        }
        e.1 += 1;
        Ok(())
    }
}

/// Requests in flight per client. A slot is held by an [`InFlightGuard`]
/// and freed when it drops, so a client with all its slots in held
/// long-polls can't open more.
#[derive(Debug, Clone)]
pub struct InFlight {
    limit: u32,
    counts: Arc<Mutex<HashMap<ClientKey, u32>>>,
}

#[derive(Debug)]
pub struct InFlightGuard {
    key: ClientKey,
    counts: Arc<Mutex<HashMap<ClientKey, u32>>>,
}

impl InFlight {
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            counts: Arc::default(),
        }
    }

    pub fn acquire(&self, key: ClientKey) -> Option<InFlightGuard> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let n = counts.entry(key).or_insert(0);
        // `limit` is at least 1 (config check), so a refused client
        // already has an entry: nothing is left behind.
        if *n >= self.limit {
            return None;
        }
        *n += 1;
        Some(InFlightGuard {
            key,
            counts: self.counts.clone(),
        })
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.counts.lock().unwrap().len()
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = counts.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> ClientKey {
        ClientKey::of(s.parse().unwrap())
    }

    #[test]
    fn ipv6_counts_per_64_and_mapped_ipv4_as_ipv4() {
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff::9"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("::ffff:192.0.2.1"), key("192.0.2.1"));
        assert_ne!(key("192.0.2.1"), key("192.0.2.2"));
    }

    #[test]
    fn debug_hides_the_address() {
        assert_eq!(format!("{:?}", key("192.0.2.1")), "ClientKey(<redacted>)");
    }

    #[test]
    fn counts_per_client_and_resets_each_window() {
        let w = Window::new(2, 60);
        let t = 600;
        assert_eq!(w.hit(key("192.0.2.1"), t), Ok(()));
        assert_eq!(w.hit(key("192.0.2.1"), t + 1), Ok(()));
        assert_eq!(w.hit(key("192.0.2.1"), t + 20), Err(40));
        assert_eq!(w.hit(key("192.0.2.2"), t), Ok(()));
        assert_eq!(w.hit(key("192.0.2.1"), t + 60), Ok(()));
        // Old windows are forgotten.
        assert_eq!(w.state.lock().unwrap().counts.len(), 1);
    }

    #[test]
    fn in_flight_slots_free_on_drop() {
        let f = InFlight::new(2);
        let a = f.acquire(key("192.0.2.1")).unwrap();
        let b = f.acquire(key("192.0.2.1")).unwrap();
        assert!(f.acquire(key("192.0.2.1")).is_none());
        assert!(f.acquire(key("192.0.2.2")).is_some());
        drop(a);
        let c = f.acquire(key("192.0.2.1")).unwrap();
        drop((b, c));
        assert_eq!(f.tracked(), 0, "idle clients are forgotten");
    }
}
