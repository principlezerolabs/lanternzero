//! Scanning time the issuer grants (spec §4.2, §4.6).

use super::*;

impl Store {
    /// The account's scanning end time (Unix seconds), if it is in the
    /// future.
    pub fn scan_until(&self, account: AccountId, now_unix: u64) -> Option<u64> {
        let st = self.state.lock().expect("store lock");
        st.scan_until
            .get(&hex(&account))
            .copied()
            .filter(|&u| u > now_unix)
    }

    /// Seconds of scanning time the account has left.
    pub fn scan_secs_left(&self, account: AccountId, now_unix: u64) -> u64 {
        self.scan_until(account, now_unix)
            .map_or(0, |u| u - now_unix)
    }

    /// Adds `secs` of scanning time, after whatever is left, or from now.
    /// A `key` already applied to this account adds nothing and returns the
    /// current end time, so the issuer may retry. Written to disk before it
    /// returns.
    pub fn add_scan_time(
        &self,
        account: AccountId,
        secs: u64,
        key: &str,
        now_unix: u64,
    ) -> Result<u64, GrantError> {
        if !self.has_account_at(account, now_unix) {
            return Err(GrantError::UnknownAccount);
        }
        let id = hex(&account);
        let key_hash = TokenHash::of_text(key).to_hex();
        let mut st = self.state.lock().expect("store lock");
        if let Some(g) = st.grants.get(&key_hash) {
            if g.account != id {
                return Err(GrantError::KeyReused);
            }
            return Ok(st.scan_until.get(&id).copied().unwrap_or(now_unix));
        }
        let old = st.scan_until.get(&id).copied();
        let until = old
            .filter(|&u| u > now_unix)
            .unwrap_or(now_unix)
            .saturating_add(secs);
        st.scan_until.insert(id.clone(), until);
        st.grants.insert(
            key_hash.clone(),
            Grant {
                account: id.clone(),
                at: now_unix,
            },
        );
        drop(st);
        if let Err(e) = self.flush_strict() {
            // Undo, so a retry with the same key applies it.
            let mut st = self.state.lock().expect("store lock");
            st.grants.remove(&key_hash);
            match old {
                Some(u) => st.scan_until.insert(id, u),
                None => st.scan_until.remove(&id),
            };
            return Err(e.into());
        }
        Ok(until)
    }
}
