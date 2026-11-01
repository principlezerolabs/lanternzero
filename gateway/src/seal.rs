//! Sealed endpoints: the gateway stores nothing (CLAUDE.md, spec §4.1).
//!
//! The `<opaque>` part of each push endpoint is the device's platform
//! token and the server key it is bound to (spec §5.3), encrypted and
//! authenticated with the gateway's own key (XChaCha20-Poly1305). Servers
//! never see the raw device token, and nobody can forge or alter an
//! endpoint without that key.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Format version of the sealed plaintext.
const VERSION: u8 = 1;
/// Binds the ciphertext to its purpose.
const AAD: &[u8] = b"lz-gateway endpoint v1";
const NONCE_LEN: usize = 24;
/// Longest platform token accepted. APNs tokens are 32 bytes today, FCM
/// tokens about 160 characters.
pub const MAX_TOKEN_LEN: usize = 512;
/// An uncompressed P-256 public key.
pub const KEY_LEN: usize = 65;

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
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("platform", &self.platform)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Seals and opens endpoints with the gateway's key.
pub struct Sealer {
    cipher: XChaCha20Poly1305,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sealer(<redacted>)")
    }
}

impl Sealer {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new_from_slice(key).expect("32-byte key"),
        }
    }

    /// The base64url `<opaque>` for `sub`.
    pub fn seal(&self, sub: &Subscription) -> String {
        let mut plain = Zeroizing::new(Vec::with_capacity(
            1 + 1 + KEY_LEN + 8 + 2 + sub.token.len(),
        ));
        plain.push(VERSION);
        plain.push(sub.platform.code());
        plain.extend_from_slice(&sub.server_key);
        plain.extend_from_slice(&sub.created.to_be_bytes());
        plain.extend_from_slice(&(sub.token.len() as u16).to_be_bytes());
        plain.extend_from_slice(&sub.token);
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce);
        let ct = self
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: AAD,
                },
            )
            .expect("encryption of a bounded message");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        URL_SAFE_NO_PAD.encode(out)
    }

    /// Opens an `<opaque>`; `None` if it wasn't sealed by this gateway's
    /// key, was altered, or doesn't parse.
    pub fn open(&self, opaque: &str) -> Option<Subscription> {
        if opaque.len() > 2048 {
            return None;
        }
        let raw = URL_SAFE_NO_PAD.decode(opaque).ok()?;
        if raw.len() <= NONCE_LEN {
            return None;
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
        let plain = Zeroizing::new(
            self.cipher
                .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: AAD })
                .ok()?,
        );
        let (&version, rest) = plain.split_first()?;
        if version != VERSION {
            return None;
        }
        let (&code, rest) = rest.split_first()?;
        let platform = Platform::from_code(code)?;
        let server_key: [u8; KEY_LEN] = rest.get(..KEY_LEN)?.try_into().ok()?;
        let rest = &rest[KEY_LEN..];
        let created = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
        let len = u16::from_be_bytes(rest.get(8..10)?.try_into().ok()?) as usize;
        let token = rest.get(10..10 + len)?;
        if rest.len() != 10 + len || token.is_empty() || len > MAX_TOKEN_LEN {
            return None;
        }
        Some(Subscription {
            platform,
            server_key,
            token: Zeroizing::new(token.to_vec()),
            created,
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
        }
    }

    #[test]
    fn round_trips_and_hides_the_token() {
        let s = Sealer::new(&[7; 32]);
        let opaque = s.seal(&sub());
        assert_eq!(s.open(&opaque), Some(sub()));
        // Fresh nonce each time: the same subscription seals differently.
        assert_ne!(opaque, s.seal(&sub()));
        let raw = URL_SAFE_NO_PAD.decode(&opaque).unwrap();
        assert!(!raw.windows(32).any(|w| w == [0xAB; 32]), "token visible");
        assert!(!format!("{:?}", sub()).contains("171"), "token in Debug");
    }

    #[test]
    fn rejects_other_keys_tampering_and_garbage() {
        let s = Sealer::new(&[7; 32]);
        let opaque = s.seal(&sub());
        assert!(Sealer::new(&[8; 32]).open(&opaque).is_none());
        let mut raw = URL_SAFE_NO_PAD.decode(&opaque).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(s.open(&URL_SAFE_NO_PAD.encode(&raw)).is_none());
        assert!(s.open("").is_none());
        assert!(s.open("not base64 !!").is_none());
        assert!(s.open(&"A".repeat(5000)).is_none());
    }
}
