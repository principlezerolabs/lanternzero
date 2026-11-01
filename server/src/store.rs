//! Accounts, devices, and replay windows.
//!
//! Nothing here comes from a viewing key, so it may be written to disk
//! (spec §3.4, §4.1). Viewing keys and key-derived data never enter this
//! module (invariants 1 and 3).
//!
//! Accounts come from `accounts.txt` in the data directory: one
//! `<token-sha256-hex> <account-id-hex> [<valid-until-unix>]` per line. The
//! third field marks a token replaced by rotation, still accepted until then
//! (spec §4.6). Devices and replay windows are kept in `state.json`.
//!
//! The server rewrites `accounts.txt` on rotation and deletion, and
//! `new-account` appends to it, both under a lock on `accounts.lock`. The
//! server re-reads the file before each rewrite, so accounts added while it
//! runs are kept (they load at the next start).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lz_proto::api::DeviceRegistration;
use lz_proto::replay::{ReplayError, SeqWindow};
use lz_proto::token::TokenHash;
use serde::{Deserialize, Serialize};

pub const ACCOUNTS_FILE: &str = "accounts.txt";
const ACCOUNTS_LOCK: &str = "accounts.lock";
const STATE_FILE: &str = "state.json";
/// How long a rotated-out token keeps working if the new one isn't used
/// (spec §4.6).
pub const ROTATION_GRACE_SECS: u64 = 24 * 3600;

pub type AccountId = [u8; 16];

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub account: AccountId,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub seq: SeqWindow,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("account", &self.account)
            .field("endpoint", &"<redacted>")
            .field("p256dh", &"<redacted>")
            .field("auth", &"<redacted>")
            .field("seq", &self.seq)
            .finish()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    devices: HashMap<String, Device>,
    account_seq: HashMap<String, SeqWindow>,
}

/// One token hash of an account (a line of `accounts.txt`).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Entry {
    hash: [u8; 32],
    account: AccountId,
    /// Set on a token that rotation replaced: accepted until then.
    until: Option<u64>,
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
    fn valid_at(&self, now_unix: u64) -> bool {
        self.until.is_none_or(|u| u > now_unix)
    }

    fn line(&self) -> String {
        match self.until {
            Some(u) => format!("{} {} {u}", hex(&self.hash), hex(&self.account)),
            None => format!("{} {}", hex(&self.hash), hex(&self.account)),
        }
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

#[derive(Debug, thiserror::Error)]
pub enum RotateError {
    /// The new hash is already a token's (this account's or another's).
    #[error("token hash already in use")]
    InUse,
    #[error("cannot write {ACCOUNTS_FILE}: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("unknown device")]
    UnknownDevice,
    #[error("too many devices on this account")]
    TooManyDevices,
    #[error("stale seq")]
    StaleSeq { min_seq: u64 },
}

#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    /// Token hashes and their accounts. Changes are written to
    /// `accounts.txt` before they take effect here.
    accounts: Mutex<Vec<Entry>>,
    state: Mutex<State>,
    dirty: Mutex<bool>,
    /// Held while writing `state.json`, so two writers can't interleave on
    /// the temp file.
    flush_lock: Mutex<()>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn check_private_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "data directory file is readable by group or others",
                ));
            }
        }
    }
    Ok(())
}

impl Store {
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        check_private_file(&dir.join(ACCOUNTS_FILE))?;
        check_private_file(&dir.join(STATE_FILE))?;
        let now = now_unix();
        let on_disk = read_accounts(dir)?;
        let expired = on_disk.iter().any(|e| !e.valid_at(now));
        let accounts: Vec<Entry> = on_disk.into_iter().filter(|e| e.valid_at(now)).collect();
        let state = match std::fs::read(dir.join(STATE_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e),
        };
        let store = Self {
            dir: dir.to_owned(),
            accounts: Mutex::new(accounts),
            state: Mutex::new(state),
            dirty: Mutex::new(false),
            flush_lock: Mutex::new(()),
        };
        // Rotated-out tokens past their 24 hours: no reason to keep even
        // their hashes.
        if expired {
            let mut accounts = store.accounts.lock().expect("accounts lock");
            store.rewrite_accounts(&mut accounts, now, &mut |e| Some(*e), None)?;
        }
        Ok(store)
    }

    /// Appends a new account to `accounts.txt`. Used by `new-account`.
    pub fn add_account_to_file(dir: &Path, hash: &TokenHash) -> std::io::Result<AccountId> {
        use std::io::Write;
        let mut id = [0u8; 16];
        rand::fill(&mut id);
        let _lock = lock_accounts(dir)?;
        let mut f = crate::keys::private_file()
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
        self.authenticate_at(hash, now_unix())
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
        let now = now_unix();
        self.accounts
            .lock()
            .expect("accounts lock")
            .iter()
            .any(|e| e.account == account && e.valid_at(now))
    }

    /// Deletes the account's token hashes, devices, and replay window
    /// (spec §4.6). The scanner's lease and events are the caller's to drop.
    pub fn delete_account(&self, account: AccountId) -> std::io::Result<()> {
        {
            let mut accounts = self.accounts.lock().expect("accounts lock");
            self.rewrite_accounts(
                &mut accounts,
                now_unix(),
                &mut |e| (e.account != account).then_some(*e),
                None,
            )?;
        }
        {
            let mut st = self.state.lock().expect("store lock");
            st.devices.retain(|_, d| d.account != account);
            st.account_seq.remove(&hex(&account));
        }
        self.flush_now();
        Ok(())
    }

    /// Applies `keep` to every entry of `accounts.txt` (as it is on disk
    /// now) and to `memory`, drops expired tokens, appends `add`, and writes
    /// the file atomically under the lock. `memory` changes only if the
    /// write succeeds.
    fn rewrite_accounts(
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
        crate::keys::write_private_atomic(&self.dir, ACCOUNTS_FILE, text.as_bytes())?;
        let mut next: Vec<Entry> = memory.iter().filter_map(&mut *keep).chain(add).collect();
        next.retain(|e| e.valid_at(now_unix));
        *memory = next;
        Ok(())
    }

    pub fn register_device(
        &self,
        account: AccountId,
        reg: &DeviceRegistration,
        max_devices: usize,
    ) -> Result<String, StoreError> {
        let mut st = self.state.lock().expect("store lock");
        // Re-registering the same endpoint replaces the old record (spec §4.1).
        st.devices
            .retain(|_, d| !(d.account == account && d.endpoint == reg.endpoint));
        let count = st.devices.values().filter(|d| d.account == account).count();
        if count >= max_devices {
            return Err(StoreError::TooManyDevices);
        }
        let mut seq = SeqWindow::default();
        seq.accept(reg.seq).expect("a fresh window accepts any seq");
        let mut raw = [0u8; 16];
        rand::fill(&mut raw);
        let id = URL_SAFE_NO_PAD.encode(raw);
        st.devices.insert(
            id.clone(),
            Device {
                account,
                endpoint: reg.endpoint.clone(),
                p256dh: reg.keys.p256dh.clone(),
                auth: reg.keys.auth.clone(),
                seq,
            },
        );
        drop(st);
        self.flush_now();
        Ok(id)
    }

    /// Checks `seq` against a device's window. The device must belong to the
    /// account.
    pub fn accept_device_seq(
        &self,
        account: AccountId,
        device_id: &str,
        seq: u64,
    ) -> Result<(), StoreError> {
        let mut st = self.state.lock().expect("store lock");
        let dev = st
            .devices
            .get_mut(device_id)
            .filter(|d| d.account == account)
            .ok_or(StoreError::UnknownDevice)?;
        accept(&mut dev.seq, seq)?;
        *self.dirty.lock().expect("dirty lock") = true;
        Ok(())
    }

    /// Checks `seq` for requests that name no device (spec §3.4).
    pub fn accept_account_seq(&self, account: AccountId, seq: u64) -> Result<(), StoreError> {
        let mut st = self.state.lock().expect("store lock");
        accept(st.account_seq.entry(hex(&account)).or_default(), seq)?;
        *self.dirty.lock().expect("dirty lock") = true;
        Ok(())
    }

    pub fn delete_device(&self, account: AccountId, device_id: &str) -> Result<(), StoreError> {
        let mut st = self.state.lock().expect("store lock");
        match st.devices.get(device_id) {
            Some(d) if d.account == account => {
                st.devices.remove(device_id);
            }
            _ => return Err(StoreError::UnknownDevice),
        }
        drop(st);
        self.flush_now();
        Ok(())
    }

    /// Removes a device whose push subscription is gone (`404`/`410`).
    pub fn remove_device(&self, device_id: &str) {
        let removed = self
            .state
            .lock()
            .expect("store lock")
            .devices
            .remove(device_id)
            .is_some();
        if removed {
            self.flush_now();
        }
    }

    /// All devices, for the wake-up scheduler.
    pub fn devices(&self) -> Vec<(String, Device)> {
        let st = self.state.lock().expect("store lock");
        st.devices
            .iter()
            .map(|(id, d)| (id.clone(), d.clone()))
            .collect()
    }

    /// Writes state if a replay window changed since the last write. Losing
    /// a few seconds of `seq` state is safe: the 60 s `Date` check still
    /// bounds replays (spec §3.4).
    pub fn flush_if_dirty(&self) {
        let dirty = std::mem::take(&mut *self.dirty.lock().expect("dirty lock"));
        if dirty {
            self.flush_now();
        }
    }

    fn flush_now(&self) {
        let _writing = self.flush_lock.lock().expect("flush lock");
        let bytes = {
            let st = self.state.lock().expect("store lock");
            serde_json::to_vec(&*st).expect("state serializes")
        };
        let tmp = self.dir.join(format!("{STATE_FILE}.tmp"));
        let result = crate::keys::private_file()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(&bytes)?;
                f.sync_all()
            })
            .and_then(|()| std::fs::rename(&tmp, self.dir.join(STATE_FILE)));
        if let Err(e) = result {
            tracing::error!(error = %e, "failed to write state");
            *self.dirty.lock().expect("dirty lock") = true;
        }
    }
}

fn accept(window: &mut SeqWindow, seq: u64) -> Result<(), StoreError> {
    window.accept(seq).map_err(|e| match e {
        ReplayError::Duplicate(_) | ReplayError::TooOld(_) => StoreError::StaleSeq {
            min_seq: window.min_seq(),
        },
    })
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
fn read_accounts(dir: &Path) -> std::io::Result<Vec<Entry>> {
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
    let f = crate::keys::private_file()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(ACCOUNTS_LOCK))?;
    f.lock()?;
    Ok(f)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lz_proto::api::PushKeys;
    use lz_proto::token::AccountToken;

    fn tmp() -> PathBuf {
        let mut raw = [0u8; 8];
        rand::fill(&mut raw);
        let d = std::env::temp_dir().join(format!("lz-store-{}", hex(&raw)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn reg(endpoint: &str, seq: u64) -> DeviceRegistration {
        DeviceRegistration {
            seq,
            endpoint: endpoint.into(),
            keys: PushKeys {
                p256dh: "p".into(),
                auth: "a".into(),
            },
        }
    }

    #[test]
    fn accounts_devices_and_persistence() {
        let dir = tmp();
        let token = AccountToken::from_bytes([3; 32]);
        let id = Store::add_account_to_file(&dir, &token.hash()).unwrap();
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.authenticate(&token.hash()), Some(id));
        assert_eq!(
            s.authenticate(&AccountToken::from_bytes([4; 32]).hash()),
            None
        );

        let d = s
            .register_device(id, &reg("https://g.example/1", 10), 2)
            .unwrap();
        // Same endpoint replaces; a third distinct endpoint exceeds the cap.
        let d2 = s
            .register_device(id, &reg("https://g.example/1", 11), 2)
            .unwrap();
        assert_ne!(d, d2);
        s.register_device(id, &reg("https://g.example/2", 12), 2)
            .unwrap();
        assert_eq!(
            s.register_device(id, &reg("https://g.example/3", 13), 2),
            Err(StoreError::TooManyDevices)
        );

        assert_eq!(s.accept_device_seq(id, &d2, 12), Ok(()));
        assert_eq!(
            s.accept_device_seq(id, &d2, 12),
            Err(StoreError::StaleSeq { min_seq: 13 })
        );
        assert_eq!(
            s.accept_device_seq(id, &d, 20),
            Err(StoreError::UnknownDevice)
        );
        assert_eq!(
            s.accept_device_seq([9; 16], &d2, 20),
            Err(StoreError::UnknownDevice)
        );
        s.flush_if_dirty();

        // Replay state survives a restart.
        let s = Store::open(&dir).unwrap();
        assert_eq!(
            s.accept_device_seq(id, &d2, 12),
            Err(StoreError::StaleSeq { min_seq: 13 })
        );
        assert_eq!(s.devices().len(), 2);
        s.delete_device(id, &d2).unwrap();
        assert_eq!(s.devices().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_loose_data_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp();
        std::fs::write(dir.join(STATE_FILE), "{}").unwrap();
        std::fs::set_permissions(dir.join(STATE_FILE), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(Store::open(&dir).is_err());
    }

    #[test]
    fn device_debug_redacts_secrets() {
        let d = Device {
            account: [1; 16],
            endpoint: "https://push.example/secret".into(),
            p256dh: "pk".into(),
            auth: "au".into(),
            seq: SeqWindow::default(),
        };
        let dbg = format!("{d:?}");
        assert!(!dbg.contains("secret"));
        assert!(!dbg.contains("pk"));
        assert!(dbg.contains("redacted"));
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp();
        let token = AccountToken::from_bytes([5; 32]);
        let id = Store::add_account_to_file(&dir, &token.hash()).unwrap();
        let s = Store::open(&dir).unwrap();
        s.register_device(id, &reg("https://g.example/1", 1), 10)
            .unwrap();
        for f in [ACCOUNTS_FILE, STATE_FILE] {
            let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{f}");
        }
    }

    #[test]
    fn authenticate_uses_constant_time_compare() {
        let dir = tmp();
        let t1 = AccountToken::from_bytes([1; 32]);
        let t2 = AccountToken::from_bytes([2; 32]);
        let id1 = Store::add_account_to_file(&dir, &t1.hash()).unwrap();
        let id2 = Store::add_account_to_file(&dir, &t2.hash()).unwrap();
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.authenticate(&t1.hash()), Some(id1));
        assert_eq!(s.authenticate(&t2.hash()), Some(id2));
        assert_eq!(
            s.authenticate(&AccountToken::from_bytes([3; 32]).hash()),
            None
        );
    }

    #[test]
    fn rotation_keeps_the_old_token_until_the_new_one_is_used() {
        let dir = tmp();
        let old = AccountToken::from_bytes([1; 32]).hash();
        let new = AccountToken::from_bytes([2; 32]).hash();
        let other = AccountToken::from_bytes([3; 32]).hash();
        let id = Store::add_account_to_file(&dir, &old).unwrap();
        let other_id = Store::add_account_to_file(&dir, &other).unwrap();
        let s = Store::open(&dir).unwrap();
        let t = 1_800_000_000;

        // A hash already in use, the account's own or another's, is refused.
        assert!(matches!(
            s.rotate_token(id, &old, &old, t),
            Err(RotateError::InUse)
        ));
        assert!(matches!(
            s.rotate_token(id, &old, &other, t),
            Err(RotateError::InUse)
        ));

        s.rotate_token(id, &old, &new, t).unwrap();
        // A retry after a lost response succeeds.
        s.rotate_token(id, &old, &new, t + 5).unwrap();
        assert_eq!(s.authenticate_at(&old, t + 10), Some(id));
        // Both survive a restart, with the old one's deadline.
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.authenticate_at(&old, t + 10), Some(id));
        assert_eq!(s.authenticate_at(&new, t + 10), Some(id));
        // That first use of the new token retired the old one, on disk too.
        assert_eq!(s.authenticate_at(&old, t + 11), None);
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.authenticate_at(&old, t + 11), None);
        assert_eq!(s.authenticate_at(&new, t + 11), Some(id));
        assert_eq!(s.authenticate_at(&other, t + 11), Some(other_id));
    }

    #[test]
    fn an_unused_new_token_is_replaced_and_the_grace_period_ends() {
        let dir = tmp();
        let old = AccountToken::from_bytes([1; 32]).hash();
        let first = AccountToken::from_bytes([2; 32]).hash();
        let second = AccountToken::from_bytes([3; 32]).hash();
        let id = Store::add_account_to_file(&dir, &old).unwrap();
        let s = Store::open(&dir).unwrap();
        let t = 1_800_000_000;
        s.rotate_token(id, &old, &first, t).unwrap();
        // Rotating again before `first` is used replaces it, and the old
        // token's deadline doesn't move.
        s.rotate_token(id, &old, &second, t + 3600).unwrap();
        assert_eq!(s.authenticate_at(&first, t + 3601), None);
        assert_eq!(
            s.authenticate_at(&old, t + ROTATION_GRACE_SECS - 1),
            Some(id)
        );
        assert_eq!(s.authenticate_at(&old, t + ROTATION_GRACE_SECS), None);
        assert_eq!(
            s.authenticate_at(&second, t + ROTATION_GRACE_SECS),
            Some(id)
        );
    }

    #[test]
    fn rewrites_keep_comments_and_accounts_added_meanwhile() {
        let dir = tmp();
        let old = AccountToken::from_bytes([1; 32]).hash();
        let new = AccountToken::from_bytes([2; 32]).hash();
        let id = Store::add_account_to_file(&dir, &old).unwrap();
        let text = std::fs::read_to_string(dir.join(ACCOUNTS_FILE)).unwrap();
        std::fs::write(dir.join(ACCOUNTS_FILE), format!("# alice\n{text}")).unwrap();
        let s = Store::open(&dir).unwrap();
        // `new-account` runs while the server is up.
        let late = AccountToken::from_bytes([9; 32]).hash();
        let late_id = Store::add_account_to_file(&dir, &late).unwrap();

        s.rotate_token(id, &old, &new, 1_800_000_000).unwrap();
        let text = std::fs::read_to_string(dir.join(ACCOUNTS_FILE)).unwrap();
        assert!(text.starts_with("# alice\n"), "{text}");
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.authenticate(&late), Some(late_id));
        assert_eq!(s.authenticate(&new), Some(id));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(ACCOUNTS_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn deleting_an_account_drops_its_tokens_devices_and_seq() {
        let dir = tmp();
        let a = AccountToken::from_bytes([1; 32]).hash();
        let a_new = AccountToken::from_bytes([2; 32]).hash();
        let b = AccountToken::from_bytes([3; 32]).hash();
        let ida = Store::add_account_to_file(&dir, &a).unwrap();
        let idb = Store::add_account_to_file(&dir, &b).unwrap();
        let s = Store::open(&dir).unwrap();
        s.rotate_token(ida, &a, &a_new, 1_800_000_000).unwrap();
        s.register_device(ida, &reg("https://g.example/a", 1), 10)
            .unwrap();
        let db = s
            .register_device(idb, &reg("https://g.example/b", 1), 10)
            .unwrap();
        s.accept_account_seq(ida, 5).unwrap();

        s.delete_account(ida).unwrap();
        assert!(!s.has_account(ida));
        assert_eq!(s.authenticate(&a), None);
        assert_eq!(s.authenticate(&a_new), None);
        assert_eq!(s.devices().len(), 1);
        assert_eq!(s.devices()[0].0, db);
        // A fresh window: the old seq state is gone.
        s.accept_account_seq(ida, 1).unwrap();

        let s = Store::open(&dir).unwrap();
        assert_eq!(s.authenticate(&a), None);
        assert_eq!(s.authenticate(&a_new), None);
        assert_eq!(s.authenticate(&b), Some(idb));
        assert_eq!(s.devices().len(), 1);
        let text = std::fs::read_to_string(dir.join(ACCOUNTS_FILE)).unwrap();
        assert!(!text.contains(&hex(&ida)), "the account id is gone");
    }

    #[test]
    fn using_a_token_never_revokes_another_unrotated_one() {
        // An operator gave one account two tokens by hand.
        let dir = tmp();
        let a = AccountToken::from_bytes([1; 32]).hash();
        let b = AccountToken::from_bytes([2; 32]).hash();
        let id = Store::add_account_to_file(&dir, &a).unwrap();
        let text = std::fs::read_to_string(dir.join(ACCOUNTS_FILE)).unwrap();
        std::fs::write(
            dir.join(ACCOUNTS_FILE),
            format!("{text}{} {}\n", b.to_hex(), hex(&id)),
        )
        .unwrap();
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.authenticate(&a), Some(id));
        assert_eq!(s.authenticate(&b), Some(id));
        assert_eq!(s.authenticate(&a), Some(id));
    }

    #[test]
    fn expired_tokens_leave_the_file_at_start() {
        let dir = tmp();
        let live = AccountToken::from_bytes([1; 32]).hash();
        let id = Store::add_account_to_file(&dir, &live).unwrap();
        let dead = AccountToken::from_bytes([2; 32]).hash();
        let mut text = std::fs::read_to_string(dir.join(ACCOUNTS_FILE)).unwrap();
        text.push_str(&format!("{} {} 1000\n", dead.to_hex(), hex(&id)));
        std::fs::write(dir.join(ACCOUNTS_FILE), text).unwrap();
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.authenticate(&dead), None);
        let text = std::fs::read_to_string(dir.join(ACCOUNTS_FILE)).unwrap();
        assert!(!text.contains(&dead.to_hex()), "{text}");
        assert_eq!(s.authenticate(&live), Some(id));
    }

    #[test]
    fn rejects_malformed_accounts_file() {
        let dir = tmp();
        std::fs::write(dir.join(ACCOUNTS_FILE), "nothex 00\n").unwrap();
        assert!(Store::open(&dir).is_err());
    }
}
