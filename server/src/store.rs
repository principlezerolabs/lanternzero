//! Accounts, devices, and replay windows.
//!
//! Nothing here comes from a viewing key, so it may be written to disk
//! (spec §3.4, §4.1). Viewing keys and key-derived data never enter this
//! module (invariants 1 and 3).
//!
//! Accounts come from `accounts.txt` in the data directory: one
//! `<token-sha256-hex> <account-id-hex>` per line. Devices and replay windows
//! are kept in `state.json`.

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
const STATE_FILE: &str = "state.json";

pub type AccountId = [u8; 16];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub account: AccountId,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub seq: SeqWindow,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    devices: HashMap<String, Device>,
    account_seq: HashMap<String, SeqWindow>,
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
    /// SHA-256(token) -> account id.
    accounts: HashMap<[u8; 32], AccountId>,
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

impl Store {
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        let mut accounts = HashMap::new();
        match std::fs::read_to_string(dir.join(ACCOUNTS_FILE)) {
            Ok(text) => {
                for (n, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let mut parts = line.split_whitespace();
                    let (Some(h), Some(a), None) = (parts.next(), parts.next(), parts.next())
                    else {
                        return Err(bad_line(n));
                    };
                    let (Some(h), Some(a)) = (unhex::<32>(h), unhex::<16>(a)) else {
                        return Err(bad_line(n));
                    };
                    accounts.insert(h, a);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let state = match std::fs::read(dir.join(STATE_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            dir: dir.to_owned(),
            accounts,
            state: Mutex::new(state),
            dirty: Mutex::new(false),
            flush_lock: Mutex::new(()),
        })
    }

    /// Appends a new account to `accounts.txt`. Used by `new-account`.
    pub fn add_account_to_file(dir: &Path, hash: &TokenHash) -> std::io::Result<AccountId> {
        use std::io::Write;
        let mut id = [0u8; 16];
        rand::fill(&mut id);
        let mut f = crate::keys::private_file()
            .create(true)
            .append(true)
            .open(dir.join(ACCOUNTS_FILE))?;
        writeln!(f, "{} {}", hash.to_hex(), hex(&id))?;
        f.sync_all()?;
        Ok(id)
    }

    /// The account for a token hash, if any.
    pub fn authenticate(&self, hash: &TokenHash) -> Option<AccountId> {
        self.accounts.get(&hash.0).copied()
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
            "{ACCOUNTS_FILE} line {}: expected `<sha256-hex> <account-id-hex>`",
            n + 1
        ),
    )
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
    fn rejects_malformed_accounts_file() {
        let dir = tmp();
        std::fs::write(dir.join(ACCOUNTS_FILE), "nothex 00\n").unwrap();
        assert!(Store::open(&dir).is_err());
    }
}
