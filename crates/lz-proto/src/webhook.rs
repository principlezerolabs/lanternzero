//! Webhook ids, secrets, and signatures (spec §4.5, Standard Webhooks).
//!
//! The server signs each delivery with the account's secret; a merchant's
//! receiver verifies it with [`verify`].

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::api::EventStatus;

/// Prefix of a signing secret's text form.
pub const SECRET_PREFIX: &str = "whsec_";
/// Bytes in a signing secret (Standard Webhooks allows 24 to 64).
pub const SECRET_LEN: usize = 32;

/// `webhook-id` for an event in a given state (spec §4.5):
/// `id "." base64url(SHA-256(status || 0x00 || height || 0x00 ||
/// confirmations)[0..9])`. The same state always gives the same id, even
/// after a restart has reset the event's `rev`; any change gives a new one.
pub fn webhook_id(
    event_id: &str,
    status: EventStatus,
    height: Option<u64>,
    confirmations: u32,
) -> String {
    let status = match status {
        EventStatus::Mempool => "mempool",
        EventStatus::Mined => "mined",
        EventStatus::Reorged => "reorged",
        EventStatus::Unknown => "unknown",
    };
    let mut h = Sha256::new();
    h.update(status.as_bytes());
    h.update([0]);
    if let Some(height) = height {
        h.update(height.to_string().as_bytes());
    }
    h.update([0]);
    h.update(confirmations.to_string().as_bytes());
    let digest = h.finalize();
    format!("{event_id}.{}", URL_SAFE_NO_PAD.encode(&digest[..9]))
}

/// A webhook signing secret. `Debug` hides it, and it is zeroed on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningSecret(Zeroizing<[u8; SECRET_LEN]>);

impl std::fmt::Debug for SigningSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningSecret(<redacted>)")
    }
}

impl SigningSecret {
    /// A fresh secret from the OS RNG. The server makes it; clients never
    /// choose one (spec §4.5).
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut raw = Zeroizing::new([0u8; SECRET_LEN]);
        getrandom::fill(&mut raw[..])?;
        Ok(Self(raw))
    }

    pub fn from_bytes(raw: [u8; SECRET_LEN]) -> Self {
        Self(Zeroizing::new(raw))
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    /// `whsec_` plus standard base64, as `PUT /v0/webhook` returns it.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::from(SECRET_PREFIX));
        STANDARD.encode_string(&self.0[..], &mut out);
        out
    }

    /// Parses [`encode`](Self::encode)'s form.
    pub fn parse(text: &str) -> Option<Self> {
        let b64 = text.strip_prefix(SECRET_PREFIX)?;
        let mut bytes = Zeroizing::new(STANDARD.decode(b64).ok()?);
        let raw: [u8; SECRET_LEN] = bytes.as_slice().try_into().ok()?;
        bytes.zeroize();
        Some(Self::from_bytes(raw))
    }
}

fn mac(secret: &SigningSecret, id: &str, timestamp: u64, body: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac
}

/// The `webhook-signature` header: `v1,` and the standard-base64
/// HMAC-SHA256 of `id.timestamp.body`.
pub fn sign(secret: &SigningSecret, id: &str, timestamp: u64, body: &[u8]) -> String {
    let tag = mac(secret, id, timestamp, body).finalize().into_bytes();
    format!("v1,{}", STANDARD.encode(tag))
}

/// Checks a delivery as a receiver would: one of the space-separated
/// signatures in `signature_header` is a valid `v1` signature, compared in
/// constant time. Receivers should also check that `timestamp` is recent.
pub fn verify(
    secret: &SigningSecret,
    id: &str,
    timestamp: u64,
    body: &[u8],
    signature_header: &str,
) -> bool {
    signature_header.split(' ').any(|sig| {
        sig.strip_prefix("v1,")
            .and_then(|b64| STANDARD.decode(b64).ok())
            .is_some_and(|tag| mac(secret, id, timestamp, body).verify_slice(&tag).is_ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_follow_the_state_not_the_revision() {
        let a = webhook_id("abc", EventStatus::Mempool, None, 0);
        assert_eq!(a, webhook_id("abc", EventStatus::Mempool, None, 0));
        assert!(a.starts_with("abc.") && a.len() == "abc.".len() + 12, "{a}");
        let mined = webhook_id("abc", EventStatus::Mined, Some(100), 1);
        assert_ne!(a, mined);
        assert_ne!(mined, webhook_id("abc", EventStatus::Mined, Some(100), 2));
        assert_ne!(mined, webhook_id("abc", EventStatus::Mined, Some(10), 1));
        assert_ne!(mined, webhook_id("abx", EventStatus::Mined, Some(100), 1));
    }

    #[test]
    fn secrets_round_trip_and_stay_hidden() {
        let s = SigningSecret::from_bytes([7; SECRET_LEN]);
        let text = s.encode();
        assert!(text.starts_with("whsec_"));
        assert_eq!(SigningSecret::parse(&text), Some(s.clone()));
        assert_eq!(SigningSecret::parse("whsec_AAAA"), None);
        assert_eq!(SigningSecret::parse(&text[1..]), None);
        assert_eq!(format!("{s:?}"), "SigningSecret(<redacted>)");
    }

    #[test]
    fn signatures_verify_only_for_the_same_message_and_secret() {
        let s = SigningSecret::from_bytes([1; SECRET_LEN]);
        let sig = sign(&s, "id.x", 1_800_000_000, b"{}");
        assert!(sig.starts_with("v1,"));
        assert!(verify(&s, "id.x", 1_800_000_000, b"{}", &sig));
        assert!(verify(
            &s,
            "id.x",
            1_800_000_000,
            b"{}",
            &format!("v1,AAAA {sig}")
        ));
        assert!(!verify(&s, "id.x", 1_800_000_001, b"{}", &sig));
        assert!(!verify(&s, "id.x", 1_800_000_000, b"{ }", &sig));
        let other = SigningSecret::from_bytes([2; SECRET_LEN]);
        assert!(!verify(&other, "id.x", 1_800_000_000, b"{}", &sig));
        assert!(!verify(&s, "id.x", 1_800_000_000, b"{}", "v1a,abc"));
    }
}
