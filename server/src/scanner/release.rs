//! The server-wide long-poll release (spec §4.3), at most once every
//! [`MIN_RELEASE_GAP`].
//!
//! Every release returns every waiting poll on the server, so without a
//! limit anyone with a scanning account could send themselves a stream of
//! small payments and make every foreground wallet send a request for each.
//! The first trigger after a quiet spell releases at once; triggers within
//! the gap after a release join one release when the gap ends. Releases
//! stay server-wide, so the limit reveals nothing (invariant 4).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

/// The least time between two releases (spec §4.3).
pub const MIN_RELEASE_GAP: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
struct Gate {
    last: Option<Instant>,
    /// A delayed release is already scheduled.
    pending: bool,
}

#[derive(Debug)]
pub(super) struct Release {
    tx: watch::Sender<u64>,
    gate: Mutex<Gate>,
}

impl Release {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            tx: watch::channel(0).0,
            gate: Mutex::new(Gate::default()),
        })
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<u64> {
        self.tx.subscribe()
    }

    /// Asks for a release: now, or when [`MIN_RELEASE_GAP`] has passed
    /// since the last one.
    pub(super) fn trigger(self: &Arc<Self>) {
        let now = Instant::now();
        let mut gate = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if gate.pending {
            return;
        }
        let due = gate.last.map_or(now, |t| t + MIN_RELEASE_GAP);
        // Outside a runtime (synchronous tests) nothing can wait: release now.
        let runtime = tokio::runtime::Handle::try_current();
        match runtime {
            Ok(handle) if due > now => {
                gate.pending = true;
                let this = self.clone();
                handle.spawn(async move {
                    tokio::time::sleep_until(due).await;
                    this.fire();
                });
            }
            _ => {
                drop(gate);
                self.fire();
            }
        }
    }

    fn fire(&self) {
        {
            let mut gate = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            gate.last = Some(Instant::now());
            gate.pending = false;
        }
        self.tx.send_modify(|g| *g = g.wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn triggers_within_the_gap_join_one_later_release() {
        let r = Release::new();
        let mut rx = r.subscribe();
        r.trigger();
        assert!(rx.has_changed().unwrap(), "the first goes at once");
        rx.borrow_and_update();

        r.trigger();
        r.trigger();
        r.trigger();
        assert!(!rx.has_changed().unwrap(), "held for the gap");
        tokio::time::sleep(MIN_RELEASE_GAP - Duration::from_millis(100)).await;
        assert!(!rx.has_changed().unwrap());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(*rx.borrow_and_update(), 2, "one release for all three");
    }
}
