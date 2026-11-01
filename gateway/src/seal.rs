//! Sealed endpoints: the gateway stores no device tokens or subscriptions
//! (spec §4.1).
//!
//! The `<opaque>` part of each push endpoint is the device's platform
//! token, the server key it is bound to (spec §5.3), its expiry, and the
//! hash of its revocation secret, encrypted and authenticated with one of
//! the gateway's sealing keys (XChaCha20-Poly1305, [`crate::keys`]).
//! Servers never see the raw device token, and nobody can forge or alter
//! an endpoint without that key.
//!
//! `opaque = base64url(key id || nonce || ciphertext)`. The key id is in
//! the clear so the right key can be picked, and is bound in as AAD.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::keys::{KeyRing, RETAIN_SECS};

/// Format version of the sealed plaintext.
const VERSION: u8 = 2;
/// Binds the ciphertext to its purpose; the key id follows it.
const AAD: &[u8] = b"lz-gateway endpoint v2";
const NONCE_LEN: usize = 24;
/// Longest platform token accepted. APNs tokens are 32 bytes today, FCM
/// tokens about 160 characters.
pub const MAX_TOKEN_LEN: usize = 512;
/// An uncompressed P-256 public key.
pub const KEY_LEN: usize = 65;
/// Longest `<opaque>` accepted (the longest token seals to about 900).
const MAX_OPAQUE: usize = 1024;

/// Where the gateway forwards pushes for a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Apns,
    Fcm,
}

impl Platform {
    pub(crate) fn code(self) -> u8 {
        match self {
            Platform::Apns => 1,
            Platform::Fcm => 2,
        }
    }

    fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(Platform::Apns),
            2 => Some(Platform::Fcm),
            _ => None,
        }
    }
}

/// What an endpoint carries, once opened.
#[derive(Clone, PartialEq, Eq)]
pub struct Subscription {
    pub platform: Platform,
    /// The server key pushes must be signed with (uncompressed P-256).
    pub server_key: [u8; KEY_LEN],
    /// APNs: the raw device token. FCM: the registration token's bytes.
    pub token: Zeroizing<Vec<u8>>,
    /// Unix seconds when the subscription was created.
    pub created: u64,
    /// Unix seconds after which pushes get `410`.
    pub expires: u64,
    /// [`crate::revoke::secret_hash`] of the wallet's revocation secret.
    pub revoke_hash: [u8; 32],
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("platform", &self.platform)
            .field("token", &"<redacted>")
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

/// Seals endpoints with the current key and opens them with any key in
/// the ring.
pub struct Sealer {
    current: u8,
    ciphers: Vec<(u8, XChaCha20Poly1305)>,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sealer(<redacted>)")
    }
}

fn aad(key_id: u8) -> [u8; AAD.len() + 1] {
    let mut a = [0u8; AAD.len() + 1];
    a[..AAD.len()].copy_from_slice(AAD);
    a[AAD.len()] = key_id;
    a
}

impl Sealer {
    pub fn new(ring: &KeyRing) -> Self {
        Self {
            current: ring.current().id,
            ciphers: ring
                .keys()
                .iter()
                .map(|k| {
                    let cipher =
                        XChaCha20Poly1305::new_from_slice(&k.key[..]).expect("32-byte key");
                    (k.id, cipher)
                })
                .collect(),
        }
    }

    fn cipher(&self, id: u8) -> Option<&XChaCha20Poly1305> {
        self.ciphers.iter().find(|(i, _)| *i == id).map(|(_, c)| c)
    }

    /// The base64url `<opaque>` for `sub`.
    pub fn seal(&self, sub: &Subscription) -> String {
        let mut plain = Zeroizing::new(Vec::with_capacity(
            1 + 1 + KEY_LEN + 8 + 8 + 32 + 2 + sub.token.len(),
        ));
        plain.push(VERSION);
        plain.push(sub.platform.code());
        plain.extend_from_slice(&sub.server_key);
        plain.extend_from_slice(&sub.created.to_be_bytes());
        plain.extend_from_slice(&sub.expires.to_be_bytes());
        plain.extend_from_slice(&sub.revoke_hash);
        plain.extend_from_slice(&(sub.token.len() as u16).to_be_bytes());
        plain.extend_from_slice(&sub.token);
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce);
        let cipher = self
            .cipher(self.current)
            .expect("the current key is in the ring");
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &aad(self.current),
                },
            )
            .expect("encryption of a bounded message");
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(self.current);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        URL_SAFE_NO_PAD.encode(out)
    }

    /// Opens an `<opaque>`; `None` if no key in the ring sealed it, it was
    /// altered, or it doesn't parse. Expiry is the caller's to check.
    pub fn open(&self, opaque: &str) -> Option<Subscription> {
        if opaque.len() > MAX_OPAQUE {
            return None;
        }
        let raw = URL_SAFE_NO_PAD.decode(opaque).ok()?;
        let (&key_id, raw) = raw.split_first()?;
        if raw.len() <= NONCE_LEN {
            return None;
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
        let plain = Zeroizing::new(
            self.cipher(key_id)?
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: ct,
                        aad: &aad(key_id),
                    },
                )
                .ok()?,
        );
        let (&version, rest) = plain.split_first()?;
        if version != VERSION {
            return None;
        }
        let (&code, rest) = rest.split_first()?;
        let platform = Platform::from_code(code)?;
        let (server_key, rest) = rest.split_at_checked(KEY_LEN)?;
        let (created, rest) = rest.split_at_checked(8)?;
        let (expires, rest) = rest.split_at_checked(8)?;
        let (revoke_hash, rest) = rest.split_at_checked(32)?;
        let (len, token) = rest.split_at_checked(2)?;
        let created = u64::from_be_bytes(created.try_into().ok()?);
        let expires = u64::from_be_bytes(expires.try_into().ok()?);
        let len = u16::from_be_bytes(len.try_into().ok()?) as usize;
        // A retired key is kept only as long as the longest lifetime.
        if token.len() != len
            || token.is_empty()
            || len > MAX_TOKEN_LEN
            || expires < created
            || expires - created > RETAIN_SECS
        {
            return None;
        }
        Some(Subscription {
            platform,
            server_key: server_key.try_into().ok()?,
            token: Zeroizing::new(token.to_vec()),
            created,
            expires,
            revoke_hash: revoke_hash.try_into().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub() -> Subscription {
        Subscription {
            platform: Platform::Apns,
            server_key: [4; KEY_LEN],
            token: Zeroizing::new(vec![0xAB; 32]),
            created: 1_800_000_000,
            expires: 1_800_000_000 + 90 * 86_400,
            revoke_hash: [9; 32],
        }
    }

    #[test]
    fn round_trips_and_hides_the_token() {
        let s = Sealer::new(&KeyRing::single(0, [7; 32]));
        let opaque = s.seal(&sub());
        assert_eq!(s.open(&opaque), Some(sub()));
        // Fresh nonce each time: the same subscription seals differently.
        assert_ne!(opaque, s.seal(&sub()));
        let raw = URL_SAFE_NO_PAD.decode(&opaque).unwrap();
        assert!(!raw.windows(32).any(|w| w == [0xAB; 32]), "token visible");
        assert!(!format!("{:?}", sub()).contains("171"), "token in Debug");
        let longest = Subscription {
            token: Zeroizing::new(vec![1; MAX_TOKEN_LEN]),
            ..sub()
        };
        assert!(s.open(&s.seal(&longest)).is_some());
    }

    #[test]
    fn rejects_other_keys_tampering_and_garbage() {
        let s = Sealer::new(&KeyRing::single(0, [7; 32]));
        let opaque = s.seal(&sub());
        assert!(
            Sealer::new(&KeyRing::single(0, [8; 32]))
                .open(&opaque)
                .is_none()
        );
        let mut raw = URL_SAFE_NO_PAD.decode(&opaque).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(s.open(&URL_SAFE_NO_PAD.encode(&raw)).is_none());
        // The key id is authenticated too.
        let same_key_other_id = Sealer::new(&KeyRing::single(1, [7; 32]));
        let mut raw = URL_SAFE_NO_PAD.decode(&opaque).unwrap();
        raw[0] = 1;
        assert!(
            same_key_other_id
                .open(&URL_SAFE_NO_PAD.encode(&raw))
                .is_none()
        );
        assert!(s.open("").is_none());
        assert!(s.open("not base64 !!").is_none());
        assert!(s.open(&"A".repeat(5000)).is_none());
        // A lifetime longer than any key is kept for.
        let too_long = Subscription {
            expires: sub().created + RETAIN_SECS + 1,
            ..sub()
        };
        assert!(s.open(&s.seal(&too_long)).is_none());
    }
}
