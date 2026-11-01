//! OHTTP key configurations and their rotation (spec §3.2).
//!
//! The gateway serves one current configuration. After `rotate-ohttp`, the
//! previous one is still accepted for [`OVERLAP_SECS`], so wallets that
//! cached it keep working, and is then deleted from memory and disk:
//! anyone who recorded requests sent to it and later got its private key
//! could read them (tokens and viewing keys included).
//!
//! On disk, in `data_dir`, each key is one record (mode 0600): the current
//! one in [`CURRENT_FILE`], retired ones in [`RETIRED_DIR`], one file per
//! key id. Servers from before rev 3.13 kept a bare seed in `ohttp-ikm`;
//! it is migrated as key id 1, which it always was.

use std::path::Path;
use std::sync::RwLock;

use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyConfig, SymmetricSuite};
use zeroize::Zeroizing;

use crate::keys::{KeyError, create_private_dir, write_private_atomic};

pub const CURRENT_FILE: &str = "ohttp-key";
pub const RETIRED_DIR: &str = "ohttp-retired";
/// The bare seed servers kept before rev 3.13 (key id 1).
const LEGACY_SEED_FILE: &str = "ohttp-ikm";
const LEGACY_KEY_ID: u8 = 1;
/// How long a retired configuration is still accepted (spec §3.2).
pub const OVERLAP_SECS: u64 = 7 * 86_400;
/// Rotate at least this often (spec §3.2); `doctor` warns past it.
pub const MAX_AGE_SECS: u64 = 90 * 86_400;

/// Key id, created at, retired at (0 for the current key), seed.
const RECORD_LEN: usize = 1 + 8 + 8 + 32;

/// One OHTTP key: its id, when it was made and retired, and the seed its
/// key configuration is derived from. `Debug` hides the seed.
pub struct OhttpKey {
    pub id: u8,
    pub created_at: u64,
    pub retired_at: Option<u64>,
    seed: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for OhttpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OhttpKey")
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("retired_at", &self.retired_at)
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl OhttpKey {
    fn generate(id: u8, now: u64) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::fill(&mut seed[..]);
        Self {
            id,
            created_at: now,
            retired_at: None,
            seed,
        }
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(RECORD_LEN));
        out.push(self.id);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.retired_at.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.seed[..]);
        out
    }

    fn decode(bytes: &[u8], label: &str) -> Result<Self, KeyError> {
        let corrupt = || KeyError::Corrupt(label.to_owned());
        if bytes.len() != RECORD_LEN {
            return Err(corrupt());
        }
        let u64_at = |i: usize| -> Result<u64, KeyError> {
            Ok(u64::from_be_bytes(
                bytes[i..i + 8].try_into().map_err(|_| corrupt())?,
            ))
        };
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes[17..]);
        let retired_at = u64_at(9)?;
        Ok(Self {
            id: bytes[0],
            created_at: u64_at(1)?,
            retired_at: (retired_at != 0).then_some(retired_at),
            seed,
        })
    }

    /// The key configuration, derived from the seed.
    pub fn config(&self) -> Result<KeyConfig, KeyError> {
        Ok(KeyConfig::derive(
            self.id,
            Kem::X25519Sha256,
            vec![
                SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
                SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
            ],
            &self.seed[..],
        )?)
    }

    /// For a retired key, the end of its overlap.
    pub fn accepted_until(&self) -> Option<u64> {
        self.retired_at.map(|t| t.saturating_add(OVERLAP_SECS))
    }
}

/// The current key and the retired ones still on disk.
#[derive(Debug)]
pub struct OhttpKeys {
    pub current: OhttpKey,
    pub retired: Vec<OhttpKey>,
}

fn io(label: &str) -> impl FnOnce(std::io::Error) -> KeyError + '_ {
    move |e| KeyError::Io(label.to_owned(), e)
}

/// Reads the current key without creating or migrating anything (for
/// `doctor`). A pre-rev-3.13 seed reads as key id 1, made at its file's
/// modification time.
pub fn read_current(dir: &Path) -> Result<Option<OhttpKey>, KeyError> {
    let path = dir.join(CURRENT_FILE);
    let label = path.display().to_string();
    match std::fs::read(&path) {
        Ok(bytes) => return OhttpKey::decode(&Zeroizing::new(bytes), &label).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(KeyError::Io(label, e)),
    }
    let legacy = dir.join(LEGACY_SEED_FILE);
    let label = legacy.display().to_string();
    let bytes = match std::fs::read(&legacy) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(KeyError::Io(label, e)),
    };
    let mut seed = Zeroizing::new([0u8; 32]);
    if bytes.len() != 32 {
        return Err(KeyError::Corrupt(label));
    }
    seed.copy_from_slice(&bytes);
    let created_at = std::fs::metadata(&legacy)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    Ok(Some(OhttpKey {
        id: LEGACY_KEY_ID,
        created_at,
        retired_at: None,
        seed,
    }))
}

/// Each retired key on disk, with its file's path.
fn retired_files(dir: &Path) -> Result<Vec<(std::path::PathBuf, OhttpKey)>, KeyError> {
    let rdir = dir.join(RETIRED_DIR);
    let label = rdir.display().to_string();
    let entries = match std::fs::read_dir(&rdir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(KeyError::Io(label, e)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.map_err(io(&label))?.path();
        if path.extension().is_some_and(|x| x == "tmp") {
            continue;
        }
        let name = path.display().to_string();
        let bytes = Zeroizing::new(std::fs::read(&path).map_err(io(&name))?);
        let key = OhttpKey::decode(&bytes, &name)?;
        if key.retired_at.is_none() {
            return Err(KeyError::Corrupt(name));
        }
        out.push((path, key));
    }
    Ok(out)
}

/// Loads the keys, creating the first one or migrating a pre-rev-3.13
/// seed. Retired keys past their overlap are left out (and deleted by
/// [`prune`]).
pub fn load(dir: &Path, now: u64) -> Result<OhttpKeys, KeyError> {
    create_private_dir(dir).map_err(io(&dir.display().to_string()))?;
    let current = match read_current(dir)? {
        Some(k) => k,
        None => OhttpKey::generate(LEGACY_KEY_ID, now),
    };
    if !dir.join(CURRENT_FILE).exists() {
        write_private_atomic(dir, CURRENT_FILE, &current.encode()).map_err(io(CURRENT_FILE))?;
    }
    remove_legacy(dir)?;
    let mut retired: Vec<OhttpKey> = Vec::new();
    for (_, key) in retired_files(dir)? {
        // A crash mid-rotation can leave the current key in both places.
        let live = key.accepted_until().is_some_and(|t| now < t);
        if live && key.id != current.id && !retired.iter().any(|r| r.id == key.id) {
            retired.push(key);
        }
    }
    Ok(OhttpKeys { current, retired })
}

fn remove_legacy(dir: &Path) -> Result<(), KeyError> {
    match std::fs::remove_file(dir.join(LEGACY_SEED_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(KeyError::Io(LEGACY_SEED_FILE.into(), e))
        }
        _ => Ok(()),
    }
}

/// Retires the current key and makes a new one (spec §3.2); returns the
/// new key id. The old key is accepted for [`OVERLAP_SECS`] from `now`.
/// With `drop_old`, for a suspected leak, the old key and every retired
/// one are deleted instead. Takes effect at the server's next start.
pub fn rotate(dir: &Path, now: u64, drop_old: bool) -> Result<u8, KeyError> {
    let keys = load(dir, now)?;
    let rdir = dir.join(RETIRED_DIR);
    let rlabel = rdir.display().to_string();
    create_private_dir(&rdir).map_err(io(&rlabel))?;
    let mut in_use = vec![keys.current.id];
    if drop_old {
        for (path, _) in retired_files(dir)? {
            std::fs::remove_file(&path).map_err(io(&path.display().to_string()))?;
        }
    } else {
        in_use.extend(keys.retired.iter().map(|k| k.id));
        let mut old = keys.current;
        old.retired_at = Some(now.max(1));
        // Written before the current key is replaced, so a crash can't
        // lose it.
        write_private_atomic(&rdir, &old.id.to_string(), &old.encode()).map_err(io(&rlabel))?;
    }
    // The next id after the current one that nothing still accepted uses.
    let start = in_use[0];
    let id = (1..=255u16)
        .map(|i| ((u16::from(start) + i - 1) % 255 + 1) as u8)
        .find(|id| !in_use.contains(id))
        .ok_or_else(|| KeyError::Corrupt(rlabel.clone()))?;
    // A file left for an id no longer accepted would be read as live again.
    let stale = rdir.join(id.to_string());
    if stale.exists() {
        std::fs::remove_file(&stale).map_err(io(&rlabel))?;
    }
    let new = OhttpKey::generate(id, now);
    write_private_atomic(dir, CURRENT_FILE, &new.encode()).map_err(io(CURRENT_FILE))?;
    Ok(id)
}

/// Deletes retired keys past their overlap; returns how many.
pub fn prune(dir: &Path, now: u64) -> Result<usize, KeyError> {
    let mut pruned = 0;
    for (path, key) in retired_files(dir)? {
        if key.accepted_until().is_none_or(|t| now >= t) {
            match std::fs::remove_file(&path) {
                Ok(()) => pruned += 1,
                // Another server on the same data directory got there first.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(KeyError::Io(path.display().to_string(), e)),
            }
        }
    }
    Ok(pruned)
}

/// What became of an encapsulated request.
pub enum Decapsulated {
    Ok(Zeroizing<Vec<u8>>, ohttp::ServerResponse),
    /// Its key id is not one the server accepts: answer with the
    /// `ohttp-key` problem (spec §3.2).
    UnknownKey,
    /// Malformed, or it didn't decrypt.
    Invalid,
}

impl std::fmt::Debug for Decapsulated {
    // Never the plaintext: it holds the bearer token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ok(..) => "Decapsulated::Ok(<redacted>)",
            Self::UnknownKey => "Decapsulated::UnknownKey",
            Self::Invalid => "Decapsulated::Invalid",
        })
    }
}

struct Retired {
    id: u8,
    until: u64,
    server: ohttp::Server,
}

/// One set of keys, swapped whole when [`Gateway::reload`] finds a change.
struct Keys {
    current_id: u8,
    current_created_at: u64,
    current: ohttp::Server,
    retired: Vec<Retired>,
    encoded: Vec<u8>,
    sha256_hex: String,
}

impl Keys {
    fn build(keys: &OhttpKeys) -> Result<Self, KeyError> {
        use sha2::{Digest, Sha256};
        let config = keys.current.config()?;
        let encoded = KeyConfig::encode_list(&[&config])?;
        let sha256_hex = Sha256::digest(&encoded)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut retired = Vec::new();
        for k in &keys.retired {
            if let Some(until) = k.accepted_until() {
                retired.push(Retired {
                    id: k.id,
                    until,
                    server: ohttp::Server::new(k.config()?)?,
                });
            }
        }
        Ok(Self {
            current_id: keys.current.id,
            current_created_at: keys.current.created_at,
            current: ohttp::Server::new(config)?,
            retired,
            encoded,
            sha256_hex,
        })
    }

    /// Whether `keys` on disk differ from these.
    fn differs(&self, keys: &OhttpKeys) -> bool {
        let mut on_disk: Vec<u8> = keys.retired.iter().map(|k| k.id).collect();
        let mut here: Vec<u8> = self.retired.iter().map(|r| r.id).collect();
        on_disk.sort_unstable();
        here.sort_unstable();
        self.current_id != keys.current.id
            || self.current_created_at != keys.current.created_at
            || on_disk != here
    }
}

/// The gateway's keys at run time: the current one, and retired ones until
/// their overlap ends. [`reload`](Self::reload) picks up a rotation done on
/// disk (`rotate-ohttp`) without a restart.
pub struct Gateway {
    keys: RwLock<Keys>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("current_id", &self.current_id())
            .field("retired", &self.retired_count())
            .finish_non_exhaustive()
    }
}

impl Gateway {
    pub fn new(keys: &OhttpKeys) -> Result<Self, KeyError> {
        Ok(Self {
            keys: RwLock::new(Keys::build(keys)?),
        })
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Keys> {
        self.keys.read().unwrap_or_else(|p| p.into_inner())
    }

    /// The current configuration as served (`application/ohttp-keys`).
    pub fn encoded(&self) -> Vec<u8> {
        self.read().encoded.clone()
    }

    /// Hex SHA-256 of [`encoded`](Self::encoded), published in `info`.
    pub fn sha256_hex(&self) -> String {
        self.read().sha256_hex.clone()
    }

    pub fn current_id(&self) -> u8 {
        self.read().current_id
    }

    /// How many retired keys are still accepted.
    pub fn retired_count(&self) -> usize {
        self.read().retired.len()
    }

    /// Decrypts with the key the request names (its first byte, RFC 9458
    /// §4.3), if that key is accepted at `now`.
    pub fn decapsulate(&self, request: &[u8], now: u64) -> Decapsulated {
        let Some(&id) = request.first() else {
            return Decapsulated::Invalid;
        };
        let keys = self.read();
        let opened = if id == keys.current_id {
            keys.current.decapsulate(request)
        } else {
            match keys.retired.iter().find(|r| r.id == id && now < r.until) {
                Some(r) => r.server.decapsulate(request),
                None => return Decapsulated::UnknownKey,
            }
        };
        match opened {
            Ok((plain, ctx)) => Decapsulated::Ok(Zeroizing::new(plain), ctx),
            Err(_) => Decapsulated::Invalid,
        }
    }

    /// Drops retired keys past their overlap from memory; returns how many.
    pub fn drop_expired(&self, now: u64) -> usize {
        let mut keys = self.keys.write().unwrap_or_else(|p| p.into_inner());
        let before = keys.retired.len();
        keys.retired.retain(|r| now < r.until);
        before - keys.retired.len()
    }

    /// Re-reads the keys from `dir` and switches to them if they changed,
    /// for example after `rotate-ohttp`; returns the new current key id if
    /// it switched. Several servers on one data directory thus serve the
    /// same configuration (spec §3.2).
    pub fn reload(&self, dir: &Path, now: u64) -> Result<Option<u8>, KeyError> {
        let on_disk = load(dir, now)?;
        if !self.read().differs(&on_disk) {
            return Ok(None);
        }
        let fresh = Keys::build(&on_disk)?;
        let id = fresh.current_id;
        *self.keys.write().unwrap_or_else(|p| p.into_inner()) = fresh;
        Ok(Some(id))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000;

    fn tmp() -> std::path::PathBuf {
        let mut raw = [0u8; 8];
        rand::fill(&mut raw);
        let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let d = std::env::temp_dir().join(format!("lz-ohttp-{name}"));
        create_private_dir(&d).unwrap();
        d
    }

    /// A request encapsulated to `config`, as a wallet sends it.
    fn request_to(encoded: &[u8]) -> Vec<u8> {
        let client = ohttp::ClientRequest::from_encoded_config_list(encoded).unwrap();
        client.encapsulate(b"hello").unwrap().0
    }

    #[test]
    fn first_load_creates_key_id_1_and_is_stable() {
        let dir = tmp();
        let a = load(&dir, T0).unwrap();
        assert_eq!(a.current.id, 1);
        assert_eq!(a.current.created_at, T0);
        let b = load(&dir, T0 + 10).unwrap();
        assert_eq!(
            Gateway::new(&a).unwrap().encoded(),
            Gateway::new(&b).unwrap().encoded()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(CURRENT_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn migrates_a_legacy_seed_unchanged() {
        let dir = tmp();
        std::fs::write(dir.join(LEGACY_SEED_FILE), [9u8; 32]).unwrap();
        let before = read_current(&dir).unwrap().unwrap();
        let expect = KeyConfig::encode_list(&[&before.config().unwrap()]).unwrap();
        let keys = load(&dir, T0).unwrap();
        assert_eq!(keys.current.id, 1);
        assert_eq!(Gateway::new(&keys).unwrap().encoded(), expect);
        assert!(!dir.join(LEGACY_SEED_FILE).exists());
        assert!(dir.join(CURRENT_FILE).exists());
    }

    #[test]
    fn rotation_overlap_and_expiry() {
        let dir = tmp();
        let old = Gateway::new(&load(&dir, T0).unwrap()).unwrap();
        let old_request = request_to(&old.encoded());

        assert_eq!(rotate(&dir, T0, false).unwrap(), 2);
        let keys = load(&dir, T0 + 1).unwrap();
        assert_eq!(keys.current.id, 2);
        let gw = Gateway::new(&keys).unwrap();
        assert_ne!(gw.encoded(), old.encoded(), "only the new config is served");
        assert_eq!(gw.retired_count(), 1);

        // Within the overlap, both keys work.
        assert!(matches!(
            gw.decapsulate(&request_to(&gw.encoded()), T0 + 1),
            Decapsulated::Ok(..)
        ));
        let Decapsulated::Ok(plain, _) = gw.decapsulate(&old_request, T0 + OVERLAP_SECS - 1) else {
            panic!("the old key must still work");
        };
        assert_eq!(&plain[..], b"hello");

        // After it, the old key id is unknown, and the key goes.
        let end = T0 + OVERLAP_SECS;
        assert!(matches!(
            gw.decapsulate(&old_request, end),
            Decapsulated::UnknownKey
        ));
        assert_eq!(gw.drop_expired(end), 1);
        assert_eq!(gw.retired_count(), 0);
        assert_eq!(prune(&dir, end - 1).unwrap(), 0);
        assert_eq!(prune(&dir, end).unwrap(), 1);
        assert!(load(&dir, end).unwrap().retired.is_empty());

        // Garbage and tampering are not "unknown key".
        assert!(matches!(gw.decapsulate(&[], end), Decapsulated::Invalid));
        let mut bad = request_to(&gw.encoded());
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(matches!(gw.decapsulate(&bad, end), Decapsulated::Invalid));
    }

    #[test]
    fn a_running_gateway_picks_up_a_rotation() {
        let dir = tmp();
        let gw = Gateway::new(&load(&dir, T0).unwrap()).unwrap();
        let old = gw.encoded();
        let old_hash = gw.sha256_hex();
        assert_eq!(gw.reload(&dir, T0 + 1).unwrap(), None, "nothing changed");

        rotate(&dir, T0 + 2, false).unwrap();
        assert_eq!(gw.reload(&dir, T0 + 3).unwrap(), Some(2));
        assert_ne!(gw.encoded(), old);
        assert_ne!(gw.sha256_hex(), old_hash);
        assert!(matches!(
            gw.decapsulate(&request_to(&old), T0 + 4),
            Decapsulated::Ok(..)
        ));
        assert!(matches!(
            gw.decapsulate(&request_to(&gw.encoded()), T0 + 4),
            Decapsulated::Ok(..)
        ));

        // Past the overlap, a reload forgets the old key.
        let end = T0 + 2 + OVERLAP_SECS;
        assert_eq!(gw.reload(&dir, end).unwrap(), Some(2));
        assert_eq!(gw.retired_count(), 0);
        assert!(matches!(
            gw.decapsulate(&request_to(&old), end),
            Decapsulated::UnknownKey
        ));

        // --drop-old: gone at the next reload.
        rotate(&dir, end, false).unwrap();
        gw.reload(&dir, end).unwrap();
        assert_eq!(gw.retired_count(), 1);
        rotate(&dir, end, true).unwrap();
        gw.reload(&dir, end).unwrap();
        assert_eq!(gw.retired_count(), 0);
    }

    #[test]
    fn drop_old_and_key_ids() {
        let dir = tmp();
        load(&dir, T0).unwrap();
        assert_eq!(rotate(&dir, T0, false).unwrap(), 2);
        assert_eq!(rotate(&dir, T0 + 1, false).unwrap(), 3);
        assert_eq!(load(&dir, T0 + 2).unwrap().retired.len(), 2);
        // A leak: nothing old is accepted, and the new id avoids only the
        // key it replaces.
        assert_eq!(rotate(&dir, T0 + 2, true).unwrap(), 4);
        let keys = load(&dir, T0 + 3).unwrap();
        assert!(keys.retired.is_empty());
        assert_eq!(std::fs::read_dir(dir.join(RETIRED_DIR)).unwrap().count(), 0);

        // Ids wrap from 255 to 1.
        let mut k = OhttpKey::generate(255, T0);
        k.retired_at = None;
        write_private_atomic(&dir, CURRENT_FILE, &k.encode()).unwrap();
        assert_eq!(rotate(&dir, T0 + 4, false).unwrap(), 1);
    }

    #[test]
    fn a_crash_mid_rotation_and_corrupt_files() {
        let dir = tmp();
        let current = load(&dir, T0).unwrap().current;
        // The current key was copied to the retired directory, then the
        // crash: it loads once, as current.
        let mut copy = OhttpKey::decode(&current.encode(), "x").unwrap();
        copy.retired_at = Some(T0);
        create_private_dir(&dir.join(RETIRED_DIR)).unwrap();
        write_private_atomic(&dir.join(RETIRED_DIR), "1", &copy.encode()).unwrap();
        let keys = load(&dir, T0 + 1).unwrap();
        assert!(keys.retired.is_empty());
        assert_eq!(keys.current.id, 1);

        std::fs::write(dir.join(RETIRED_DIR).join("junk"), b"short").unwrap();
        assert!(matches!(load(&dir, T0), Err(KeyError::Corrupt(_))));

        let dbg = format!("{:?}", OhttpKey::generate(7, T0));
        assert!(
            dbg.contains("<redacted>") && !dbg.contains("seed: ["),
            "{dbg}"
        );
    }
}
