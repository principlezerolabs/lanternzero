//! Revoked subscriptions, in `data_dir/revoked` (spec §4.1).
//!
//! When the user removes a server, the wallet revokes its subscription so
//! that server can't keep waking the device or showing it alerts. A
//! stateless gateway can't forget an endpoint it never stored, so it keeps
//! a list instead. Each entry is the subscription's revocation hash (a
//! hash of a random secret only the wallet holds) and its expiry: nothing
//! about the device, the server, or the endpoint. Entries go once their
//! subscription has expired, so the list holds at most one lifetime's
//! revocations.
//!
//! File format: append-only records of hash (32 bytes) and expiry (u64 big
//! endian), compacted at each start.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

pub const REVOKED_FILE: &str = "revoked";
const RECORD: usize = 32 + 8;
/// Most revocations held at once (40 MB on disk). Subscribing is open, so
/// someone could subscribe and revoke in a loop; past this, revocations get
/// `503` until old entries expire. Deployments should rate-limit by client
/// address in front of the gateway.
pub const MAX_REVOKED: usize = 1_000_000;
const HASH_CONTEXT: &[u8] = b"lz-gateway revoke v1";

/// The hash sealed into an endpoint for a wallet's revocation secret.
pub fn secret_hash(secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HASH_CONTEXT);
    h.update(secret);
    h.finalize().into()
}

#[derive(Debug, thiserror::Error)]
pub enum RevokeError {
    #[error("revocation list is full")]
    Full,
    #[error("revocation list: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct Revoked {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    entries: HashMap<[u8; 32], u64>,
    file: File,
}

impl Revoked {
    /// Loads the list, drops expired entries, and rewrites the file.
    pub fn open(dir: &Path, now_unix: u64) -> std::io::Result<Self> {
        crate::keys::create_private_dir(dir)?;
        let path = dir.join(REVOKED_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        // A crash mid-append leaves a partial last record: ignore it.
        let entries: HashMap<[u8; 32], u64> = bytes
            .chunks_exact(RECORD)
            .filter_map(|r| {
                let hash: [u8; 32] = r[..32].try_into().ok()?;
                let expires = u64::from_be_bytes(r[32..].try_into().ok()?);
                (expires >= now_unix).then_some((hash, expires))
            })
            .collect();
        let mut out = Vec::with_capacity(entries.len() * RECORD);
        for (hash, expires) in &entries {
            out.extend_from_slice(hash);
            out.extend_from_slice(&expires.to_be_bytes());
        }
        crate::keys::write_atomic(dir, REVOKED_FILE, &out)?;
        let file = std::fs::OpenOptions::new().append(true).open(&path)?;
        Ok(Self {
            inner: Mutex::new(Inner { entries, file }),
        })
    }

    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.lock().entries.contains_key(hash)
    }

    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Records a revocation, durably, before returning. Blocking: call it
    /// off the async runtime.
    pub fn revoke(&self, hash: [u8; 32], expires: u64, now_unix: u64) -> Result<(), RevokeError> {
        let mut inner = self.lock();
        if inner.entries.contains_key(&hash) {
            return Ok(());
        }
        if inner.entries.len() >= MAX_REVOKED {
            inner.entries.retain(|_, e| *e >= now_unix);
            if inner.entries.len() >= MAX_REVOKED {
                return Err(RevokeError::Full);
            }
        }
        let mut record = [0u8; RECORD];
        record[..32].copy_from_slice(&hash);
        record[32..].copy_from_slice(&expires.to_be_bytes());
        inner.file.write_all(&record)?;
        inner.file.sync_data()?;
        inner.entries.insert(hash, expires);
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn survives_restarts_and_forgets_expired_entries() {
        let mut raw = [0u8; 8];
        rand::fill(&mut raw);
        let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let d = std::env::temp_dir().join(format!("lz-gw-revoked-{name}"));
        let t = 1_800_000_000;
        let r = Revoked::open(&d, t).unwrap();
        r.revoke([1; 32], t + 100, t).unwrap();
        r.revoke([2; 32], t + 10_000, t).unwrap();
        r.revoke([2; 32], t + 10_000, t).unwrap();
        drop(r);
        // A torn last write is ignored.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(d.join(REVOKED_FILE))
            .unwrap();
        f.write_all(&[9; 7]).unwrap();
        drop(f);

        let r = Revoked::open(&d, t + 50).unwrap();
        assert!(r.contains(&[1; 32]) && r.contains(&[2; 32]));
        assert_eq!(r.len(), 2);
        drop(r);
        let r = Revoked::open(&d, t + 200).unwrap();
        assert!(!r.contains(&[1; 32]) && r.contains(&[2; 32]));
        assert_eq!(std::fs::metadata(d.join(REVOKED_FILE)).unwrap().len(), 40);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
