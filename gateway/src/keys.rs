//! The endpoint-sealing keys, in `data_dir/endpoint-keys`.
//!
//! One current key seals new endpoints. A routine rotation retires it: it
//! still opens the endpoints it sealed until all of them have expired,
//! then it is dropped. A rotation after a suspected leak drops every old
//! key at once, which invalidates every endpoint (pushes get `404`, servers
//! drop the devices, and wallets register again).
//!
//! File format: records of key id (1 byte), retirement time (u64 big
//! endian, 0 for the current key), and the 32-byte key.

use std::io::Write as _;
use std::path::Path;

use zeroize::Zeroizing;

pub const KEYS_FILE: &str = "endpoint-keys";
const RECORD: usize = 1 + 8 + 32;
/// The longest endpoint lifetime a gateway may configure.
pub const MAX_LIFETIME_DAYS: u64 = 365;
/// How long a retired key keeps opening endpoints. Endpoints it sealed
/// expire within this, whatever lifetime was configured when it sealed
/// them.
pub const RETAIN_SECS: u64 = MAX_LIFETIME_DAYS * 86_400;

pub struct SealingKey {
    pub id: u8,
    /// Unix seconds when a rotation retired it; `None` for the current key.
    pub retired: Option<u64>,
    pub key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealingKey")
            .field("id", &self.id)
            .field("retired", &self.retired)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("endpoint keys: {0}")]
    Io(#[from] std::io::Error),
    #[error("endpoint key file is corrupt")]
    Corrupt,
    #[error("no free key id: 256 keys retained")]
    NoFreeId,
}

/// The current key and the retired keys still in use.
#[derive(Debug)]
pub struct KeyRing {
    keys: Vec<SealingKey>,
}

impl KeyRing {
    /// A ring of one current key; for tests and tools.
    pub fn single(id: u8, key: [u8; 32]) -> Self {
        Self {
            keys: vec![SealingKey {
                id,
                retired: None,
                key: Zeroizing::new(key),
            }],
        }
    }

    /// Reads the keys, creating a first key (mode 0600, in a 0700
    /// directory) on first start. Retired keys whose endpoints have all
    /// expired are left out.
    pub fn load_or_create(dir: &Path, now_unix: u64) -> Result<Self, KeyError> {
        create_private_dir(dir)?;
        let path = dir.join(KEYS_FILE);
        let mut ring = match std::fs::read(&path) {
            Ok(bytes) => Self::parse(&Zeroizing::new(bytes))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let ring = Self::single(0, random_key());
                ring.write(dir)?;
                ring
            }
            Err(e) => return Err(e.into()),
        };
        ring.prune(now_unix);
        Ok(ring)
    }

    /// Retires the current key and makes a new one; returns its id. With
    /// `drop_old`, every old key is dropped, invalidating every endpoint.
    /// The running gateway uses the new key from its next start.
    pub fn rotate(dir: &Path, now_unix: u64, drop_old: bool) -> Result<u8, KeyError> {
        let mut ring = Self::load_or_create(dir, now_unix)?;
        let last = ring.current().id;
        for k in &mut ring.keys {
            k.retired.get_or_insert(now_unix);
        }
        if drop_old {
            ring.keys.clear();
        }
        // The next free id after the last one, so a dropped key's id isn't
        // reused soon.
        let id = (1..=255u8)
            .map(|step| last.wrapping_add(step))
            .find(|id| ring.get(*id).is_none())
            .ok_or(KeyError::NoFreeId)?;
        ring.keys.push(SealingKey {
            id,
            retired: None,
            key: Zeroizing::new(random_key()),
        });
        ring.write(dir)?;
        Ok(id)
    }

    pub fn current(&self) -> &SealingKey {
        self.keys
            .iter()
            .find(|k| k.retired.is_none())
            .expect("a key ring always has a current key")
    }

    pub fn get(&self, id: u8) -> Option<&SealingKey> {
        self.keys.iter().find(|k| k.id == id)
    }

    pub fn keys(&self) -> &[SealingKey] {
        &self.keys
    }

    fn prune(&mut self, now_unix: u64) {
        self.keys.retain(|k| {
            k.retired
                .is_none_or(|r| r.saturating_add(RETAIN_SECS) > now_unix)
        });
    }

    fn parse(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.is_empty() || !bytes.len().is_multiple_of(RECORD) {
            return Err(KeyError::Corrupt);
        }
        let mut keys: Vec<SealingKey> = Vec::new();
        for r in bytes.chunks_exact(RECORD) {
            let id = r[0];
            let retired = u64::from_be_bytes(r[1..9].try_into().map_err(|_| KeyError::Corrupt)?);
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&r[9..]);
            if keys.iter().any(|k| k.id == id) {
                return Err(KeyError::Corrupt);
            }
            keys.push(SealingKey {
                id,
                retired: (retired != 0).then_some(retired),
                key,
            });
        }
        if keys.iter().filter(|k| k.retired.is_none()).count() != 1 {
            return Err(KeyError::Corrupt);
        }
        Ok(Self { keys })
    }

    /// Replaces the file atomically: a crash leaves the old or new set.
    fn write(&self, dir: &Path) -> Result<(), KeyError> {
        let mut out = Zeroizing::new(Vec::with_capacity(self.keys.len() * RECORD));
        for k in &self.keys {
            out.push(k.id);
            out.extend_from_slice(&k.retired.unwrap_or(0).to_be_bytes());
            out.extend_from_slice(&k.key[..]);
        }
        write_atomic(dir, KEYS_FILE, &out)?;
        Ok(())
    }
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    key
}

/// Creates `dir` (mode 0700) if needed.
pub(crate) fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Writes `bytes` to `dir/name` through a temporary file (mode 0600) and a
/// rename, syncing both.
pub(crate) fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, dir.join(name))?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> std::path::PathBuf {
        let mut raw = [0u8; 8];
        rand::fill(&mut raw);
        let name = crate::hex(&raw);
        std::env::temp_dir().join(format!("lz-gw-keys-{name}"))
    }

    #[test]
    fn rotation_keeps_old_keys_until_their_endpoints_expire() {
        let d = dir();
        let t = 1_800_000_000;
        let first = KeyRing::load_or_create(&d, t).unwrap();
        let first_id = first.current().id;
        assert_eq!(
            KeyRing::load_or_create(&d, t).unwrap().current().key,
            first.current().key
        );

        let second = KeyRing::rotate(&d, t + 10, false).unwrap();
        assert_ne!(second, first_id);
        let ring = KeyRing::load_or_create(&d, t + 20).unwrap();
        assert_eq!(ring.current().id, second);
        assert_eq!(ring.get(first_id).unwrap().retired, Some(t + 10));
        assert_eq!(ring.get(first_id).unwrap().key, first.current().key);

        // Once every endpoint the old key sealed has expired, it's gone.
        let later = KeyRing::load_or_create(&d, t + 10 + RETAIN_SECS).unwrap();
        assert!(later.get(first_id).is_none());
        assert_eq!(later.current().id, second);

        // After a leak, every old key goes at once.
        let third = KeyRing::rotate(&d, t + 30, true).unwrap();
        let ring = KeyRing::load_or_create(&d, t + 40).unwrap();
        assert_eq!(ring.keys().len(), 1);
        assert_eq!(ring.current().id, third);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rejects_corrupt_files_and_redacts_keys() {
        assert!(KeyRing::parse(&[]).is_err());
        assert!(KeyRing::parse(&[0; RECORD - 1]).is_err());
        // Two current keys.
        assert!(KeyRing::parse(&[[0; RECORD], [0; RECORD]].concat()).is_err());
        let ring = KeyRing::single(3, [0xC7; 32]);
        assert!(!format!("{ring:?}").contains("199"));
    }
}
