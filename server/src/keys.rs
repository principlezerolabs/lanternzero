//! The server's own long-term keys: the OHTTP key configuration and the
//! VAPID signing key. These are server secrets, not user data, so they live
//! in `data_dir` with owner-only permissions.

use std::io::Write;
use std::path::Path;

use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyConfig, SymmetricSuite};
use zeroize::Zeroizing;

use crate::webpush::Vapid;

const OHTTP_IKM_FILE: &str = "ohttp-ikm";
const VAPID_KEY_FILE: &str = "vapid-key";
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
    let raw = Zeroizing::new(load_or_create_secret(dir, VAPID_KEY_FILE, |s| {
        Vapid::from_secret(s).is_ok()
    })?);
    Vapid::from_secret(&raw).map_err(|_| KeyError::Corrupt(VAPID_KEY_FILE.into()))
}
