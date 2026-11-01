//! Idle expiry and the issuer's deletion log (spec §4.6,
//! `server/ISSUER.md`).

use super::*;

impl Store {
    /// Records today as the account's last-active day, if idle expiry is
    /// on. Written to disk with the next periodic flush, so at most once a
    /// day per account.
    pub(super) fn touch(&self, account: AccountId, now_unix: u64) {
        if !self.track_activity.load(Ordering::Relaxed) {
            return;
        }
        let today = day(now_unix);
        let mut st = self.state.lock().expect("store lock");
        let old = st.last_active_day.insert(hex(&account), today);
        drop(st);
        if old != Some(today) {
            *self.dirty.lock().expect("dirty lock") = true;
        }
    }

    /// Accounts deleted after deletion `after`, oldest first, at most
    /// `limit`, and the cursor to pass next. Kept for
    /// [`ISSUER_RETENTION_SECS`].
    pub fn deletions(&self, after: u64, limit: usize) -> (Vec<AccountId>, u64) {
        let st = self.state.lock().expect("store lock");
        let page: Vec<&Deletion> = st
            .deletions
            .iter()
            .filter(|d| d.seq > after)
            .take(limit)
            .collect();
        let next = page.last().map_or(after, |d| d.seq);
        let ids = page
            .iter()
            .filter_map(|d| unhex::<16>(&d.account))
            .collect();
        (ids, next)
    }

    /// The daily housekeeping for idle expiry and the issuer. Returns the
    /// accounts idle for more than `idle_days` (0: none) with no scanning
    /// time left; the caller deletes them.
    ///
    /// Also forgets scanning end times that have passed, activity days of
    /// accounts that no longer exist, and issuer records past
    /// [`ISSUER_RETENTION_SECS`]. Accounts without an activity day (new, or
    /// from before idle expiry was turned on) get today.
    pub fn sweep(&self, idle_days: u32, now_unix: u64) -> Vec<AccountId> {
        let live: std::collections::HashSet<String> = {
            let accounts = self.accounts.lock().expect("accounts lock");
            accounts
                .iter()
                .filter(|e| e.valid_at(now_unix))
                .map(|e| hex(&e.account))
                .collect()
        };
        let today = day(now_unix);
        let cutoff = now_unix.saturating_sub(ISSUER_RETENTION_SECS);
        let mut st = self.state.lock().expect("store lock");
        st.scan_until
            .retain(|a, u| *u > now_unix && live.contains(a));
        st.webhooks.retain(|a, _| live.contains(a));
        st.grants.retain(|_, g| g.at > cutoff);
        st.deletions.retain(|d| d.at > cutoff);
        let mut idle = Vec::new();
        if self.track_activity.load(Ordering::Relaxed) && idle_days > 0 {
            // Days the server was down don't count (spec §4.6).
            let missed = st
                .last_sweep_day
                .map_or(0, |last| today.saturating_sub(last).saturating_sub(1));
            st.last_sweep_day = Some(today);
            st.last_active_day.retain(|a, _| live.contains(a));
            for a in &live {
                let d = st.last_active_day.entry(a.clone()).or_insert(today);
                *d = d.saturating_add(missed).min(today);
            }
            for (a, &d) in &st.last_active_day {
                let has_time = st.scan_until.contains_key(a);
                if today.saturating_sub(d) > idle_days && !has_time {
                    idle.extend(unhex::<16>(a));
                }
            }
        }
        drop(st);
        self.flush_now();
        idle
    }
}
