//! `accounts.txt` and the accounts in it: token hashes, rotation, and
//! deletion (spec §2.2, §4.6).

use super::*;

const ACCOUNTS_LOCK: &str = "accounts.lock";

/// One token hash of an account (a line of `accounts.txt`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) hash: [u8; 32],
    pub(super) account: AccountId,
    /// Set on a token that rotation replaced: accepted until then.
    pub(super) until: Option<u64>,
}

impl std::fmt::Debug for Entry {
    // Not even token hashes are printed (CONTRIBUTING.md).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("hash", &"<redacted>")
            .field("until", &self.until)
            .finish_non_exhaustive()
    }
}

impl Entry {
    pub(super) fn valid_at(&self, now_unix: u64) -> bool {
        self.until.is_none_or(|u| u > now_unix)
    }

    fn line(&self) -> String {
        match self.until {
            Some(u) => format!("{} {} {u}", hex(&self.hash), hex(&self.account)),
            None => format!("{} {}", hex(&self.hash), hex(&self.account)),
        }
    }
}

impl Store {
    /// Appends a new account to `accounts.txt`. Used by `new-account`.
    pub fn add_account_to_file(dir: &Path, hash: &TokenHash) -> std::io::Result<AccountId> {
        use std::io::Write;
        let mut id = [0u8; 16];
        rand::fill(&mut id);
        let _lock = lock_accounts(dir)?;
        let mut f = crate::files::private_file()
            .create(true)
            .append(true)
            .open(dir.join(ACCOUNTS_FILE))?;
        writeln!(f, "{} {}", hash.to_hex(), hex(&id))?;
        f.sync_all()?;
        Ok(id)
    }

    /// The account for a token hash, if any. Compares every stored hash in
    /// constant time (spec §2.2).
    pub fn authenticate(&self, hash: &TokenHash) -> Option<AccountId> {
        self.authenticate_at(hash, unix_now())
    }

    /// [`authenticate`](Self::authenticate) at `now_unix`. The first use of
    /// a token that rotation added retires the token it replaced
    /// (spec §4.6).
    pub fn authenticate_at(&self, hash: &TokenHash, now_unix: u64) -> Option<AccountId> {
        let mut accounts = self.accounts.lock().expect("accounts lock");
        let mut found = None;
        for e in accounts.iter() {
            if TokenHash(e.hash).ct_eq(hash) && e.valid_at(now_unix) {
                found = Some(*e);
            }
        }
        let found = found?;
        self.touch(found.account, now_unix);
        // Only the token rotation replaced (marked with a deadline) goes.
        let replaced = |e: &Entry| e.account == found.account && e.until.is_some();
        let retire = found.until.is_none() && accounts.iter().any(replaced);
        if retire {
            let result = self.rewrite_accounts(
                &mut accounts,
                now_unix,
                &mut |e| (!replaced(e)).then_some(*e),
                None,
            );
            if let Err(e) = result {
                // Both tokens keep working; the next use tries again.
                tracing::error!(error = %e, "cannot retire a rotated token");
            }
        }
        Some(found.account)
    }

    /// The account for a token hash, current or still in its rotation
    /// grace, without the side effects of
    /// [`authenticate_at`](Self::authenticate_at): for the issuer, so it
    /// neither retires a token nor counts as the account's activity.
    pub fn resolve_at(&self, hash: &TokenHash, now_unix: u64) -> Option<AccountId> {
        let accounts = self.accounts.lock().expect("accounts lock");
        let mut found = None;
        for e in accounts.iter() {
            if TokenHash(e.hash).ct_eq(hash) && e.valid_at(now_unix) {
                found = Some(e.account);
            }
        }
        found
    }

    /// Creates an account for a token hash the issuer received from the
    /// user's device (spec §2.3). It is live at once.
    pub fn create_account(
        &self,
        hash: &TokenHash,
        now_unix: u64,
    ) -> Result<AccountId, CreateError> {
        let mut accounts = self.accounts.lock().expect("accounts lock");
        // Lines `new-account` appended aren't in memory yet.
        let on_disk = read_accounts(&self.dir)?;
        if accounts
            .iter()
            .chain(on_disk.iter())
            .any(|e| TokenHash(e.hash).ct_eq(hash))
        {
            return Err(CreateError::Taken);
        }
        let mut account = [0u8; 16];
        rand::fill(&mut account);
        let added = Entry {
            hash: hash.0,
            account,
            until: None,
        };
        self.rewrite_accounts(&mut accounts, now_unix, &mut |e| Some(*e), Some(added))?;
        drop(accounts);
        self.touch(account, now_unix);
        Ok(account)
    }

    /// Replaces the token `presented` (spec §4.6). `presented` keeps
    /// working until `new` is first used, or for
    /// [`ROTATION_GRACE_SECS`]; any earlier, unused replacement is dropped.
    pub fn rotate_token(
        &self,
        account: AccountId,
        presented: &TokenHash,
        new: &TokenHash,
        now_unix: u64,
    ) -> Result<(), RotateError> {
        let mut accounts = self.accounts.lock().expect("accounts lock");
        if let Some(e) = accounts.iter().find(|e| TokenHash(e.hash).ct_eq(new)) {
            // The same request again, after a lost response.
            let retry = e.account == account && e.until.is_none() && e.hash != presented.0;
            return if retry {
                Ok(())
            } else {
                Err(RotateError::InUse)
            };
        }
        let deadline = now_unix + ROTATION_GRACE_SECS;
        let added = Entry {
            hash: new.0,
            account,
            until: None,
        };
        self.rewrite_accounts(
            &mut accounts,
            now_unix,
            &mut |e| {
                if e.account != account {
                    Some(*e)
                } else if e.hash == presented.0 {
                    Some(Entry {
                        until: Some(e.until.map_or(deadline, |u| u.min(deadline))),
                        ..*e
                    })
                } else {
                    None
                }
            },
            Some(added),
        )?;
        Ok(())
    }

    /// Whether the account still exists.
    pub fn has_account(&self, account: AccountId) -> bool {
        self.has_account_at(account, unix_now())
    }

    pub fn has_account_at(&self, account: AccountId, now: u64) -> bool {
        self.accounts
            .lock()
            .expect("accounts lock")
            .iter()
            .any(|e| e.account == account && e.valid_at(now))
    }

    /// Deletes the account's token hashes, devices, replay window, scanning
    /// end time, and activity day (spec §4.6). With the issuer on, its id
    /// is kept in the deletion log. The scanner's lease and events are the
    /// caller's to drop.
    pub fn delete_account(&self, account: AccountId) -> std::io::Result<()> {
        {
            let mut accounts = self.accounts.lock().expect("accounts lock");
            self.rewrite_accounts(
                &mut accounts,
                unix_now(),
                &mut |e| (e.account != account).then_some(*e),
                None,
            )?;
        }
        {
            let mut st = self.state.lock().expect("store lock");
            let id = hex(&account);
            st.devices.retain(|_, d| d.account != account);
            st.account_seq.remove(&id);
            st.scan_until.remove(&id);
            st.last_active_day.remove(&id);
            st.grants.retain(|_, g| g.account != id);
            st.webhooks.remove(&id);
            if self.log_deletions.load(Ordering::Relaxed) {
                let seq = st.next_deletion + 1;
                st.next_deletion = seq;
                st.deletions.push(Deletion {
                    seq,
                    account: id,
                    at: unix_now(),
                });
            }
        }
        self.flush_now();
        Ok(())
    }

    /// Applies `keep` to every entry of `accounts.txt` (as it is on disk
    /// now) and to `memory`, drops expired tokens, appends `add`, and writes
    /// the file atomically under the lock. `memory` changes only if the
    /// write succeeds.
    pub(super) fn rewrite_accounts(
        &self,
        memory: &mut Vec<Entry>,
        now_unix: u64,
        keep: &mut dyn FnMut(&Entry) -> Option<Entry>,
        add: Option<Entry>,
    ) -> std::io::Result<()> {
        let _lock = lock_accounts(&self.dir)?;
        let on_disk = match std::fs::read_to_string(self.dir.join(ACCOUNTS_FILE)) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        // Line by line, so the operator's comments survive.
        let mut text = String::new();
        for (n, line) in on_disk.lines().enumerate() {
            match parse_line(line).map_err(|()| bad_line(n))? {
                None => text.push_str(line),
                Some(e) => match keep(&e).filter(|e| e.valid_at(now_unix)) {
                    Some(kept) => text.push_str(&kept.line()),
                    None => continue,
                },
            }
            text.push('\n');
        }
        if let Some(e) = add {
            text.push_str(&e.line());
            text.push('\n');
        }
        crate::files::write_private_atomic(&self.dir, ACCOUNTS_FILE, text.as_bytes())?;
        let mut next: Vec<Entry> = memory.iter().filter_map(&mut *keep).chain(add).collect();
        next.retain(|e| e.valid_at(now_unix));
        *memory = next;
        Ok(())
    }
}

/// Parses one line: `None` for blank lines and comments.
fn parse_line(line: &str) -> Result<Option<Entry>, ()> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let (Some(h), Some(a), until, None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(());
    };
    let (Some(hash), Some(account)) = (unhex::<32>(h), unhex::<16>(a)) else {
        return Err(());
    };
    let until = match until {
        Some(u) => Some(u.parse().map_err(|_| ())?),
        None => None,
    };
    Ok(Some(Entry {
        hash,
        account,
        until,
    }))
}

fn bad_line(n: usize) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "{ACCOUNTS_FILE} line {}: expected `<sha256-hex> <account-id-hex> [<valid-until-unix>]`",
            n + 1
        ),
    )
}

/// Every entry in `accounts.txt`, expired or not.
pub(super) fn read_accounts(dir: &Path) -> std::io::Result<Vec<Entry>> {
    let text = match std::fs::read_to_string(dir.join(ACCOUNTS_FILE)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if let Some(e) = parse_line(line).map_err(|()| bad_line(n))? {
            out.push(e);
        }
    }
    Ok(out)
}

/// Serializes writers of `accounts.txt` across processes (the server and
/// `new-account`). Released when the returned file is dropped.
fn lock_accounts(dir: &Path) -> std::io::Result<std::fs::File> {
    let f = crate::files::private_file()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(ACCOUNTS_LOCK))?;
    f.lock()?;
    Ok(f)
}
