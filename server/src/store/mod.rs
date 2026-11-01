//! Accounts, devices, and replay windows.
//!
//! Nothing here comes from a viewing key, so it may be written to disk
//! (spec §3.4, §4.1). Viewing keys and key-derived data never enter this
//! module (invariants 1 and 3).
//!
//! Accounts come from `accounts.txt` in the data directory: one
//! `<token-sha256-hex> <account-id-hex> [<valid-until-unix>]` per line. The
//! third field marks a token replaced by rotation, still accepted until then
//! (spec §4.6). Devices and replay windows are kept in `state.json`, and so
//! are the account data the issuer interface and idle expiry need (spec
//! §4.6, `server/ISSUER.md`): scanning end times, the UTC day of each
//! account's last request (only while idle expiry is on), `add_scan_time`
//! idempotency keys (hashed), and recently deleted account ids.
//!
//! The server rewrites `accounts.txt` on rotation, deletion, and issuer
//! `create`, and `new-account` appends to it, all under a lock on
//! `accounts.lock`. The server re-reads the file before each rewrite, so
//! accounts `new-account` adds while it runs are kept (they load at the
//! next start); accounts the issuer creates are live at once.
//!
//! Layout: `accounts` (`accounts.txt`, tokens), `devices` (devices and
//! replay windows), `scan_time` (issuer grants), and `activity` (idle
//! expiry and the deletion log), all methods on the one [`Store`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lz_proto::api::DeviceRegistration;
use lz_proto::hex::{decode as unhex, encode as hex};
use lz_proto::replay::{ReplayError, SeqWindow};
use lz_proto::token::TokenHash;
use serde::{Deserialize, Serialize};

use crate::clock::unix_now;

mod accounts;
mod activity;
mod devices;
mod scan_time;
mod webhooks;

use accounts::{Entry, read_accounts};
pub use devices::Device;
pub use webhooks::Webhook;

pub const ACCOUNTS_FILE: &str = "accounts.txt";
const STATE_FILE: &str = "state.json";
/// Locked by the one process that owns `state.json` while it runs.
const INSTANCE_LOCK: &str = "server.lock";
/// How long a rotated-out token keeps working if the new one isn't used
/// (spec §4.6).
pub const ROTATION_GRACE_SECS: u64 = 24 * 3600;
/// How long `add_scan_time` keys and deleted account ids are kept
/// (`server/ISSUER.md`, spec §4.6).
pub const ISSUER_RETENTION_SECS: u64 = 30 * 86_400;
/// Longest issuer idempotency key, in bytes.
pub const MAX_GRANT_KEY_LEN: usize = 128;
/// Most scanning time one `add_scan_time` may add: about 10 years.
pub const MAX_GRANT_SECS: u64 = 3_650 * 86_400;
const DAY_SECS: u64 = 86_400;

pub type AccountId = [u8; 16];

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    devices: HashMap<String, Device>,
    account_seq: HashMap<String, SeqWindow>,
    /// Scanning end time, Unix seconds, by account id hex (spec §4.6).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    scan_until: HashMap<String, u64>,
    /// The UTC day (days since 1970-01-01) of each account's last
    /// authenticated request. Kept only while idle expiry is on, and never
    /// anything finer (spec §4.6).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    last_active_day: HashMap<String, u32>,
    /// The day of the last idle sweep. Days after it on which no sweep ran
    /// (the server was down) don't count against anyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_sweep_day: Option<u32>,
    /// `add_scan_time` calls already applied, by hex SHA-256 of the
    /// issuer's key.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    grants: HashMap<String, Grant>,
    /// Recently deleted accounts, oldest first, for the issuer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deletions: Vec<Deletion>,
    /// The `seq` of the next deletion: never reused, so cursors stay valid.
    #[serde(default)]
    next_deletion: u64,
    /// Each account's webhook, by account id hex (spec §4.5).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    webhooks: HashMap<String, WebhookRecord>,
}

/// A webhook's URL and signing secret (`whsec_…`), as stored. `Debug`
/// hides both, and the secret is zeroed on drop.
#[derive(Clone, Serialize, Deserialize)]
struct WebhookRecord {
    url: String,
    secret: String,
}

impl std::fmt::Debug for WebhookRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebhookRecord(<redacted>)")
    }
}

impl Drop for WebhookRecord {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Grant {
    account: String,
    at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Deletion {
    seq: u64,
    account: String,
    at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RotateError {
    /// The new hash is already a token's (this account's or another's).
    #[error("token hash already in use")]
    InUse,
    #[error("cannot write {ACCOUNTS_FILE}: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    /// Some account already has this token hash.
    #[error("token hash already in use")]
    Taken,
    #[error("cannot write {ACCOUNTS_FILE}: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    #[error("unknown account")]
    UnknownAccount,
    /// The key was already used for another account.
    #[error("idempotency key already used for another account")]
    KeyReused,
    #[error("cannot write state: {0}")]
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
    /// Record each account's last-active day (idle expiry is on).
    track_activity: AtomicBool,
    /// Keep deleted account ids for the issuer.
    log_deletions: AtomicBool,
    /// The exclusive lock on [`INSTANCE_LOCK`], released on drop.
    _instance: std::fs::File,
}

/// Takes [`INSTANCE_LOCK`] without waiting.
fn lock_instance(dir: &Path) -> std::io::Result<std::fs::File> {
    let f = crate::files::private_file()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(INSTANCE_LOCK))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "another lz-server process is using this data directory; stop it first",
        )),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
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
    /// Opens the store, taking the data directory for this process alone.
    ///
    /// Each process keeps `state.json` in memory and writes it whole, so a
    /// second process on the same directory (a second server, or
    /// `rotate-vapid` while the server runs) would overwrite the other's
    /// changes. It gets `WouldBlock` instead.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        let instance = lock_instance(dir)?;
        check_private_file(&dir.join(ACCOUNTS_FILE))?;
        check_private_file(&dir.join(STATE_FILE))?;
        let now = unix_now();
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
            track_activity: AtomicBool::new(false),
            log_deletions: AtomicBool::new(false),
            _instance: instance,
        };
        // Rotated-out tokens past their 24 hours: no reason to keep even
        // their hashes.
        if expired {
            let mut accounts = store.accounts.lock().expect("accounts lock");
            store.rewrite_accounts(&mut accounts, now, &mut |e| Some(*e), None)?;
        }
        Ok(store)
    }

    /// Turns on what idle expiry and the issuer need (spec §4.6). Turning
    /// either off forgets what it kept: activity days, or deleted ids.
    pub fn configure(&self, track_activity: bool, log_deletions: bool) {
        self.track_activity.store(track_activity, Ordering::Relaxed);
        self.log_deletions.store(log_deletions, Ordering::Relaxed);
        let mut st = self.state.lock().expect("store lock");
        let mut changed = false;
        if !track_activity && (!st.last_active_day.is_empty() || st.last_sweep_day.is_some()) {
            st.last_active_day.clear();
            st.last_sweep_day = None;
            changed = true;
        }
        if !log_deletions && !st.deletions.is_empty() {
            st.deletions.clear();
            changed = true;
        }
        drop(st);
        if changed {
            self.flush_now();
        }
    }

    /// Writes state if a replay window changed since the last write. Losing
    /// a few seconds of `seq` state is safe: the 60 s `Date` check still
    /// bounds replays (spec §3.4).
    /// Blocks on file I/O: async code uses [`crate::AppState::flush_store`].
    pub fn flush_if_dirty(&self) {
        let dirty = std::mem::take(&mut *self.dirty.lock().expect("dirty lock"));
        if dirty {
            self.flush_now();
        }
    }

    fn flush_now(&self) {
        if let Err(e) = self.flush_strict() {
            tracing::error!(error = %e, "failed to write state");
            *self.dirty.lock().expect("dirty lock") = true;
        }
    }

    /// Writes `state.json` now, reporting failure.
    fn flush_strict(&self) -> std::io::Result<()> {
        let _writing = self.flush_lock.lock().expect("flush lock");
        let bytes = {
            let st = self.state.lock().expect("store lock");
            serde_json::to_vec(&*st).expect("state serializes")
        };
        // Also syncs the directory, so the rename survives a crash.
        crate::files::write_private_atomic(&self.dir, STATE_FILE, &bytes)
    }
}

/// The UTC day of a Unix time: days since 1970-01-01.
fn day(unix: u64) -> u32 {
    u32::try_from(unix / DAY_SECS).unwrap_or(u32::MAX)
}

/// An account id as the issuer interface writes it: lowercase hex.
pub fn account_hex(account: &AccountId) -> String {
    hex(account)
}

/// Parses [`account_hex`].
pub fn parse_account(s: &str) -> Option<AccountId> {
    unhex::<16>(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lz_proto::api::PushKeys;
    use lz_proto::token::AccountToken;

    fn tmp() -> crate::files::TestDir {
        crate::files::TestDir::new("store")
    }

    fn reg(endpoint: &str, seq: u64) -> DeviceRegistration {
        DeviceRegistration {
            seq,
            endpoint: endpoint.into(),
            keys: PushKeys {
                p256dh: "p".into(),
                auth: "a".into(),
            },
            vapid_public_key: None,
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
        drop(s); // A restart: the lock goes with the process.
        let s = Store::open(&dir).unwrap();
        assert_eq!(
            s.accept_device_seq(id, &d2, 12),
            Err(StoreError::StaleSeq { min_seq: 13 })
        );
        assert_eq!(s.devices().len(), 2);
        s.delete_device(id, &d2).unwrap();
        assert_eq!(s.devices().len(), 1);
    }

    #[test]
    fn one_process_owns_the_data_directory() {
        let dir = tmp();
        let first = Store::open(&dir).unwrap();
        let second = Store::open(&dir).unwrap_err();
        assert_eq!(second.kind(), std::io::ErrorKind::WouldBlock);
        drop(first);
        Store::open(&dir).unwrap();
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
            vapid: None,
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
        drop(s); // A restart: the lock goes with the process.
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.authenticate_at(&old, t + 10), Some(id));
        assert_eq!(s.authenticate_at(&new, t + 10), Some(id));
        // That first use of the new token retired the old one, on disk too.
        assert_eq!(s.authenticate_at(&old, t + 11), None);
        drop(s);
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
        drop(s); // A restart: the lock goes with the process.
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

        drop(s); // A restart: the lock goes with the process.
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

    const T0: u64 = 1_800_000_000;

    fn new_hash() -> TokenHash {
        AccountToken::generate().unwrap().hash()
    }

    fn state_json(dir: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(dir.join(STATE_FILE)).unwrap()).unwrap()
    }

    #[test]
    fn issuer_accounts_are_live_and_resolve_has_no_side_effects() {
        let dir = tmp();
        let store = Store::open(&dir).unwrap();
        store.configure(true, true);
        let old = new_hash();
        let a = store.create_account(&old, T0).unwrap();
        assert!(matches!(
            store.create_account(&old, T0),
            Err(CreateError::Taken)
        ));
        assert_eq!(store.authenticate_at(&old, T0), Some(a));
        assert_eq!(store.resolve_at(&new_hash(), T0), None);

        // Resolving the new token doesn't retire the old one.
        let new = new_hash();
        store.rotate_token(a, &old, &new, T0).unwrap();
        assert_eq!(store.resolve_at(&new, T0), Some(a));
        assert_eq!(store.resolve_at(&old, T0), Some(a));
        assert_eq!(store.authenticate_at(&new, T0), Some(a));
        assert_eq!(store.resolve_at(&old, T0), None);

        // On disk too.
        drop(store); // A restart: the lock goes with the process.
        let again = Store::open(&dir).unwrap();
        assert_eq!(again.resolve_at(&new, T0), Some(a));
    }

    #[test]
    fn scan_time_stacks_is_idempotent_and_survives_a_restart() {
        let dir = tmp();
        let store = Store::open(&dir).unwrap();
        let a = store.create_account(&new_hash(), T0).unwrap();
        let b = store.create_account(&new_hash(), T0).unwrap();
        assert_eq!(store.scan_until(a, T0), None);
        assert_eq!(store.add_scan_time(a, 100, "k1", T0).unwrap(), T0 + 100);
        assert_eq!(store.add_scan_time(a, 100, "k1", T0 + 5).unwrap(), T0 + 100);
        assert_eq!(store.add_scan_time(a, 50, "k2", T0 + 10).unwrap(), T0 + 150);
        assert!(matches!(
            store.add_scan_time(b, 50, "k2", T0),
            Err(GrantError::KeyReused)
        ));
        assert!(matches!(
            store.add_scan_time([9; 16], 50, "k3", T0),
            Err(GrantError::UnknownAccount)
        ));
        assert_eq!(store.scan_secs_left(a, T0 + 140), 10);
        // After it runs out, new time starts from now.
        assert_eq!(
            store.add_scan_time(a, 10, "k3", T0 + 1000).unwrap(),
            T0 + 1010
        );

        // Written before returning; the key isn't stored in the clear.
        drop(store); // A restart: the lock goes with the process.
        let again = Store::open(&dir).unwrap();
        assert_eq!(again.scan_until(a, T0 + 1000), Some(T0 + 1010));
        assert_eq!(
            again.add_scan_time(a, 10, "k3", T0 + 1000).unwrap(),
            T0 + 1010
        );
        let text = std::fs::read_to_string(dir.join(STATE_FILE)).unwrap();
        assert!(!text.contains("k3\""));
    }

    /// Spec §4.6: only the UTC day is kept, and nothing at all when idle
    /// expiry is off.
    #[test]
    fn activity_is_kept_as_a_day_only_while_idle_expiry_is_on() {
        let dir = tmp();
        let store = Store::open(&dir).unwrap();
        let h = new_hash();
        let a = store.create_account(&h, T0).unwrap();
        store.authenticate_at(&h, T0 + 1234);
        store.flush_now();
        assert!(state_json(&dir).get("last_active_day").is_none());

        store.configure(true, false);
        store.authenticate_at(&h, T0 + 1234);
        store.flush_if_dirty();
        let days = &state_json(&dir)["last_active_day"];
        assert_eq!(days[hex(&a)], (T0 + 1234) / 86_400);
        // A second request the same day changes nothing to write.
        store.authenticate_at(&h, T0 + 2000);
        assert!(!*store.dirty.lock().unwrap());

        drop(store); // A restart: the lock goes with the process.
        let again = Store::open(&dir).unwrap();
        again.configure(false, false);
        assert!(state_json(&dir).get("last_active_day").is_none());
    }

    #[test]
    fn idle_sweep_skips_downtime_and_accounts_with_scanning_time() {
        let dir = tmp();
        let store = Store::open(&dir).unwrap();
        store.configure(true, false);
        let idle = store.create_account(&new_hash(), T0).unwrap();
        let paid = store.create_account(&new_hash(), T0).unwrap();
        store.add_scan_time(paid, 100 * 86_400, "p", T0).unwrap();
        let day = |d: u64| T0 + d * 86_400;
        // The server sweeps hourly, so a day with no sweep is a day it was
        // down.
        for d in 0..=5 {
            assert!(store.sweep(10, day(d)).is_empty(), "day {d}");
        }
        // Down from day 6 to day 29: those 24 days don't count, so the idle
        // account's 11th counted day is day 35.
        for d in 30..=34 {
            assert!(store.sweep(10, day(d)).is_empty(), "day {d}");
        }
        assert_eq!(store.sweep(10, day(35)), vec![idle]);
        store.delete_account(idle).unwrap();
        // Once its scanning time is over, the paid account goes too.
        for d in 36..=99 {
            assert!(store.sweep(10, day(d)).is_empty(), "day {d}");
        }
        assert_eq!(store.sweep(10, day(100)), vec![paid]);
    }

    #[test]
    fn deletions_are_logged_only_for_an_issuer_and_kept_30_days() {
        let dir = tmp();
        let store = Store::open(&dir).unwrap();
        let a = store.create_account(&new_hash(), T0).unwrap();
        store.add_scan_time(a, 100, "k", T0).unwrap();
        store.delete_account(a).unwrap();
        assert_eq!(store.deletions(0, 10), (vec![], 0));
        assert!(state_json(&dir).get("scan_until").is_none());
        assert!(state_json(&dir).get("grants").is_none());

        store.configure(false, true);
        let b = store.create_account(&new_hash(), T0).unwrap();
        let c = store.create_account(&new_hash(), T0).unwrap();
        store.delete_account(b).unwrap();
        store.delete_account(c).unwrap();
        assert_eq!(store.deletions(0, 1), (vec![b], 1));
        assert_eq!(store.deletions(1, 10), (vec![c], 2));
        assert_eq!(store.deletions(2, 10), (vec![], 2));
        store.sweep(0, unix_now() + ISSUER_RETENTION_SECS + 1);
        assert_eq!(store.deletions(0, 10), (vec![], 0));
        // Cursors are never reused.
        let d = store.create_account(&new_hash(), T0).unwrap();
        store.delete_account(d).unwrap();
        assert_eq!(store.deletions(2, 10), (vec![d], 3));
    }
}
