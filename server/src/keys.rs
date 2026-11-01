//! The server's own long-term keys: the OHTTP key configuration, the VAPID
//! signing key, and the event-id secret. These are server secrets, not user data, so they live
//! in `data_dir` with owner-only permissions.

use std::io::Write;
use std::path::Path;

use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyConfig, SymmetricSuite};
use zeroize::Zeroizing;

use crate::webpush::Vapid;

const OHTTP_IKM_FILE: &str = "ohttp-ikm";
const VAPID_KEY_FILE: &str = "vapid-key";
/// Retired VAPID keys some devices are still bound to, one file each,
/// named by the public key (spec §5.3).
pub const VAPID_RETIRED_DIR: &str = "vapid-retired";
const EVENT_ID_SECRET_FILE: &str = "event-id-secret";
/// Key id of the current OHTTP key configuration.
const OHTTP_KEY_ID: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key file {0}: {1}")]
    Io(String, std::io::Error),
    #[error("key file {0} is corrupt")]
    Corrupt(String),
    #[error("OHTTP: {0}")]
    Ohttp(#[from] ohttp::Error),
}

/// Creates `dir` (and parents) readable only by the owner.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Open options for files only the owner may read (mode 0600 on Unix).
pub fn private_file() -> std::fs::OpenOptions {
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts
}

/// Replaces `dir/name` with `bytes` (mode 0600) through a temporary file
/// and a rename, so a crash leaves the old or the new contents.
pub fn write_private_atomic(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = private_file()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, dir.join(name))?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Reads a 32-byte secret from `name`, creating it from the OS RNG if absent.
/// `valid` rejects random values that aren't usable keys, so a new one is
/// drawn (for P-256, about one value in 2^32 is out of range).
fn load_or_create_secret(
    dir: &Path,
    name: &str,
    valid: fn(&[u8; 32]) -> bool,
) -> Result<[u8; 32], KeyError> {
    let path = dir.join(name);
    let label = path.display().to_string();
    match std::fs::read(&path) {
        Ok(bytes) => bytes.try_into().map_err(|_| KeyError::Corrupt(label)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut secret = [0u8; 32];
            loop {
                rand::fill(&mut secret);
                if valid(&secret) {
                    break;
                }
            }
            let mut f = private_file()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| KeyError::Io(label.clone(), e))?;
            f.write_all(&secret)
                .and_then(|()| f.sync_all())
                .map_err(|e| KeyError::Io(label, e))?;
            Ok(secret)
        }
        Err(e) => Err(KeyError::Io(label, e)),
    }
}

/// The OHTTP key configuration, derived from a stored seed so it stays the
/// same across restarts (spec §3.2: serve one configuration to everyone).
pub fn ohttp_key_config(dir: &Path) -> Result<KeyConfig, KeyError> {
    let ikm = Zeroizing::new(load_or_create_secret(dir, OHTTP_IKM_FILE, |_| true)?);
    Ok(KeyConfig::derive(
        OHTTP_KEY_ID,
        Kem::X25519Sha256,
        vec![
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ],
        &ikm[..],
    )?)
}

/// The VAPID (RFC 8292) signing key for push requests.
pub fn vapid_key(dir: &Path) -> Result<Vapid, KeyError> {
    let raw = Zeroizing::new(load_or_create_secret(dir, VAPID_KEY_FILE, valid_vapid)?);
    Vapid::from_secret(&raw).map_err(|_| KeyError::Corrupt(VAPID_KEY_FILE.into()))
}

fn valid_vapid(s: &[u8; 32]) -> bool {
    Vapid::from_secret(s).is_ok()
}

/// The current VAPID key, which `info` publishes and new devices are bound
/// to, and retired keys still bound to some devices (spec §5.3).
pub struct VapidKeys {
    current: Vapid,
    retired: Vec<Vapid>,
}

impl std::fmt::Debug for VapidKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VapidKeys")
            .field("current", &self.current.public_b64)
            .field("retired", &self.retired.len())
            .finish()
    }
}

impl VapidKeys {
    pub fn current(&self) -> &Vapid {
        &self.current
    }

    /// The key with this public key (base64url), current or retired.
    pub fn get(&self, public_b64: &str) -> Option<&Vapid> {
        std::iter::once(&self.current)
            .chain(&self.retired)
            .find(|v| v.public_b64 == public_b64)
    }

    /// Public keys of the retired keys.
    pub fn retired(&self) -> impl Iterator<Item = &str> {
        self.retired.iter().map(|v| v.public_b64.as_str())
    }
}

/// Loads the current VAPID key (creating it on first start) and the
/// retired ones.
pub fn vapid_keys(dir: &Path) -> Result<VapidKeys, KeyError> {
    let current = vapid_key(dir)?;
    let mut retired: Vec<Vapid> = Vec::new();
    for (path, raw) in retired_vapid_files(dir)? {
        let key = Vapid::from_secret(&raw).map_err(|_| KeyError::Corrupt(path))?;
        // A crash mid-rotation can leave the current key in both places.
        if key.public_b64 != current.public_b64
            && !retired.iter().any(|r| r.public_b64 == key.public_b64)
        {
            retired.push(key);
        }
    }
    Ok(VapidKeys { current, retired })
}

/// A retired key file's path and its secret.
type RetiredFile = (String, Zeroizing<[u8; 32]>);

/// Each retired key file and its secret.
fn retired_vapid_files(dir: &Path) -> Result<Vec<RetiredFile>, KeyError> {
    let rdir = dir.join(VAPID_RETIRED_DIR);
    let label = rdir.display().to_string();
    let entries = match std::fs::read_dir(&rdir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(KeyError::Io(label, e)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| KeyError::Io(label.clone(), e))?.path();
        let name = path.display().to_string();
        if path.extension().is_some_and(|x| x == "tmp") {
            continue;
        }
        let bytes =
            Zeroizing::new(std::fs::read(&path).map_err(|e| KeyError::Io(name.clone(), e))?);
        let raw: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::Corrupt(name.clone()))?;
        out.push((name, Zeroizing::new(raw)));
    }
    Ok(out)
}

/// Retires the current VAPID key and makes a new one (spec §5.3); returns
/// the new public key. The retired key keeps signing for the devices bound
/// to it until none is left. With `drop_old`, for a suspected leak, every
/// retired key is deleted instead, and at the next start the server drops
/// the devices bound to them. Pin devices to their key before calling
/// ([`crate::store::Store::pin_vapid`]).
pub fn rotate_vapid(dir: &Path, drop_old: bool) -> Result<String, KeyError> {
    create_private_dir(dir).map_err(|e| KeyError::Io(dir.display().to_string(), e))?;
    let old = Zeroizing::new(load_or_create_secret(dir, VAPID_KEY_FILE, valid_vapid)?);
    let rdir = dir.join(VAPID_RETIRED_DIR);
    let rlabel = rdir.display().to_string();
    create_private_dir(&rdir).map_err(|e| KeyError::Io(rlabel.clone(), e))?;
    if drop_old {
        for (path, _) in retired_vapid_files(dir)? {
            std::fs::remove_file(&path).map_err(|e| KeyError::Io(path, e))?;
        }
    } else {
        let public = Vapid::from_secret(&old)
            .map_err(|_| KeyError::Corrupt(VAPID_KEY_FILE.into()))?
            .public_b64;
        // Written before the current key is replaced, so a crash can't
        // lose it.
        write_private_atomic(&rdir, &public, &old[..]).map_err(|e| KeyError::Io(rlabel, e))?;
    }
    let mut new = Zeroizing::new([0u8; 32]);
    loop {
        rand::fill(&mut new[..]);
        if valid_vapid(&new) {
            break;
        }
    }
    write_private_atomic(dir, VAPID_KEY_FILE, &new[..])
        .map_err(|e| KeyError::Io(VAPID_KEY_FILE.into(), e))?;
    Ok(Vapid::from_secret(&new)
        .map_err(|_| KeyError::Corrupt(VAPID_KEY_FILE.into()))?
        .public_b64)
}

/// Deletes retired keys that `in_use` says no device is bound to; returns
/// how many.
pub fn prune_vapid(dir: &Path, in_use: &dyn Fn(&str) -> bool) -> Result<usize, KeyError> {
    let mut pruned = 0;
    for (path, raw) in retired_vapid_files(dir)? {
        let key = Vapid::from_secret(&raw).map_err(|_| KeyError::Corrupt(path.clone()))?;
        if !in_use(&key.public_b64) {
            std::fs::remove_file(&path).map_err(|e| KeyError::Io(path, e))?;
            pruned += 1;
        }
    }
    Ok(pruned)
}

/// The secret for deterministic event ids (spec §4.4). Kept for the server's
/// lifetime so a re-detected payment keeps its id across restarts.
pub fn event_id_secret(dir: &Path) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    Ok(Zeroizing::new(load_or_create_secret(
        dir,
        EVENT_ID_SECRET_FILE,
        |_| true,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let mut raw = [0u8; 8];
        rand::fill(&mut raw);
        let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let d = std::env::temp_dir().join(format!("lz-keys-{name}"));
        create_private_dir(&d).unwrap();
        d
    }

    #[test]
    fn rotation_retires_the_old_key_and_pruning_removes_it() {
        let dir = tmp();
        let k1 = vapid_keys(&dir).unwrap().current().public_b64.clone();
        let k2 = rotate_vapid(&dir, false).unwrap();
        let keys = vapid_keys(&dir).unwrap();
        assert_eq!(keys.current().public_b64, k2);
        assert!(keys.get(&k1).is_some() && keys.get(&k2).is_some());
        assert!(keys.get("not-a-key").is_none());

        // Still in use: kept. Then not: deleted.
        assert_eq!(prune_vapid(&dir, &|k| k == k1).unwrap(), 0);
        assert_eq!(prune_vapid(&dir, &|_| false).unwrap(), 1);
        assert!(vapid_keys(&dir).unwrap().get(&k1).is_none());

        // A leak: old keys go at once.
        rotate_vapid(&dir, false).unwrap();
        let k4 = rotate_vapid(&dir, true).unwrap();
        let keys = vapid_keys(&dir).unwrap();
        assert_eq!(keys.current().public_b64, k4);
        assert_eq!(keys.retired().count(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.join(VAPID_KEY_FILE)), 0o600);
            assert_eq!(mode(&dir.join(VAPID_RETIRED_DIR)), 0o700);
        }
    }

    #[test]
    fn a_crash_mid_rotation_and_corrupt_files() {
        let dir = tmp();
        // The current key was copied to the retired directory, then the
        // crash: the same key in both places loads once.
        let current = vapid_keys(&dir).unwrap().current().public_b64.clone();
        let raw = std::fs::read(dir.join(VAPID_KEY_FILE)).unwrap();
        create_private_dir(&dir.join(VAPID_RETIRED_DIR)).unwrap();
        write_private_atomic(&dir.join(VAPID_RETIRED_DIR), &current, &raw).unwrap();
        let keys = vapid_keys(&dir).unwrap();
        assert_eq!(keys.retired().count(), 0);
        assert_eq!(keys.current().public_b64, current);

        std::fs::write(dir.join(VAPID_RETIRED_DIR).join("junk"), b"short").unwrap();
        assert!(matches!(vapid_keys(&dir), Err(KeyError::Corrupt(_))));
        let dbg = format!(
            "{:?}",
            VapidKeys {
                current: Vapid::from_secret(&[7; 32]).unwrap(),
                retired: vec![],
            }
        );
        assert!(!dbg.contains("[7"), "{dbg}");
    }
}
