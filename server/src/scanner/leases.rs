//! Viewing-key leases: set, renew, end, and expire (spec §4.2,
//! invariants 1 and 2).

use super::*;

impl Scanner {
    /// Starts or renews a lease. Same keys: the expiry and alert mode are
    /// updated. New keys (or no lease before): returns the backfill to run.
    pub fn set_lease(
        &self,
        account: AccountId,
        keys: ScanKeys,
        req: &LeaseRequest,
        duration: Duration,
        tip: u64,
        now: SystemTime,
    ) -> Option<Backfill> {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        let expires_at = now + duration;
        let from = req
            .from_height
            .max(tip.saturating_sub(MAX_BACKFILL_BLOCKS))
            .max(1);
        let can_backfill = tip > 0 && from <= tip;
        if let Some(lease) = inner.leases.get_mut(&account)
            && lease.expires_at > now
            && lease.keys.same_keys(&keys)
        {
            lease.expires_at = expires_at;
            lease.alert_mode = req.alert_mode;
            if !(lease.needs_backfill && can_backfill) {
                return None;
            }
            lease.needs_backfill = false;
            return Some(Backfill {
                account,
                keys: lease.keys.clone(),
                generation: lease.generation,
                from,
                to: tip,
            });
        }
        inner.next_generation += 1;
        let generation = inner.next_generation;
        let keys = Arc::new(keys);
        inner.leases.insert(
            account,
            Lease {
                keys: keys.clone(),
                expires_at,
                alert_mode: req.alert_mode,
                generation,
                needs_backfill: !can_backfill,
            },
        );
        can_backfill.then_some(Backfill {
            account,
            keys,
            generation,
            from,
            to: tip,
        })
    }

    /// Opt-out (`lease: null`): drops the lease, its keys, and the account's
    /// events and hints at once.
    pub fn end_lease(&self, account: AccountId, now: SystemTime) {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        inner.leases.remove(&account);
        inner.events.remove(&account);
        inner.unfinalized.retain(|(a, _)| *a != account);
    }

    pub fn lease_status(&self, account: AccountId, now: SystemTime) -> LeaseStatus {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        match inner.leases.get(&account).filter(|l| l.expires_at > now) {
            Some(l) => LeaseStatus {
                active: true,
                expires_at: Some(rfc3339(l.expires_at)),
            },
            None => LeaseStatus {
                active: false,
                expires_at: None,
            },
        }
    }

    /// Whether the account has an active (unexpired) lease.
    pub fn has_lease(&self, account: AccountId, now: SystemTime) -> bool {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        inner.leases.contains_key(&account)
    }

    /// Generation of an active lease, for a backfill that must stop if the
    /// lease is replaced.
    pub(super) fn lease_generation(&self, account: AccountId) -> Option<u64> {
        self.lock().leases.get(&account).map(|l| l.generation)
    }

    /// The keys of every active lease.
    pub fn active_keys(&self, now: SystemTime) -> Vec<(AccountId, Arc<ScanKeys>)> {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        inner
            .leases
            .iter()
            .map(|(a, l)| (*a, l.keys.clone()))
            .collect()
    }

    pub(super) fn is_current(&self, account: AccountId, generation: u64, now: SystemTime) -> bool {
        self.lock()
            .leases
            .get(&account)
            .is_some_and(|l| l.generation == generation && l.expires_at > now)
    }

    pub fn alert_mode(&self, account: AccountId, now: SystemTime) -> Option<AlertMode> {
        let mut inner = self.lock();
        drop_expired_leases(&mut inner, now);
        inner.leases.get(&account).map(|l| l.alert_mode)
    }
}
