//! Webhook ids, secrets, and signatures (spec §4.5, Standard Webhooks).
//!
//! The server signs each delivery with the account's secret. A merchant's
//! receiver hands each request to [`receive`], whatever HTTP framework it
//! uses:
//!
//! ```
//! use lz_proto::webhook::{SigningSecret, receive, sign};
//!
//! // The secret `PUT /v0/webhook` returned once, kept in the merchant's
//! // secret store.
//! let secret = SigningSecret::parse(&SigningSecret::from_bytes([7; 32]).encode()).unwrap();
//! # let body = br#"{"id":"ev1","rev":1,"kind":"received","status":"mined","height":3600000,
//! #   "confirmations":10,"txid":"ab","pool":"ironwood","amount":150000000,
//! #   "memo":"b3JkZXIgNDIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
//! # let now = 1_800_000_000;
//! # let id = "ev1.AAAAAAAAAAAA";
//! # let timestamp = now.to_string();
//! # let signature = sign(&secret, id, now, body);
//! // From the request: the three `webhook-*` headers and the raw body.
//! match receive(&secret, id, &timestamp, &signature, body, now) {
//!     Ok(delivery) => {
//!         // Deduplicate on `webhook-id` (keep ids for 7 days), then act
//!         // on the state. Credit an order only once `confirmations`
//!         // reaches the finality depth `info` reports.
//!         assert_eq!(delivery.amount, 150_000_000);
//!         assert_eq!(delivery.memo_text().as_deref(), Some("order 42"));
//!         // Answer 2xx. Answer 410 only to delete the webhook for good.
//!     }
//!     // Answer 401 (or 400); the server retries, and nothing is credited.
//!     Err(_) => {}
//! }
//! ```

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::api::{EventStatus, WebhookDelivery};

/// Most a delivery's `webhook-timestamp` may differ from the receiver's
/// clock (Standard Webhooks' 5 minutes), against replays of old ones.
pub const TIMESTAMP_TOLERANCE_SECS: u64 = 300;

/// Why [`receive`] refused a delivery.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiveError {
    /// No valid signature with this secret: not from the server, altered,
    /// or signed with a secret a later `PUT /v0/webhook` replaced.
    #[error("bad webhook signature")]
    BadSignature,
    /// Signed, but the timestamp is further than
    /// [`TIMESTAMP_TOLERANCE_SECS`] from now: a replay, or a clock off.
    #[error("webhook timestamp outside the tolerance")]
    Stale,
    /// Signed and current, but not a delivery body this version knows.
    #[error("malformed webhook body")]
    Malformed,
}

/// Checks one delivery as a receiver gets it: the `webhook-id`,
/// `webhook-timestamp`, and `webhook-signature` headers and the raw body,
/// at `now_unix_secs`. Checks the signature first, then the timestamp,
/// then parses the body. Deduplicating on `webhook-id` is the caller's.
pub fn receive(
    secret: &SigningSecret,
    id: &str,
    timestamp: &str,
    signature: &str,
    body: &[u8],
    now_unix_secs: u64,
) -> Result<WebhookDelivery, ReceiveError> {
    let ts: u64 = timestamp.parse().map_err(|_| ReceiveError::BadSignature)?;
    if !verify(secret, id, ts, body, signature) {
        return Err(ReceiveError::BadSignature);
    }
    if ts.abs_diff(now_unix_secs) > TIMESTAMP_TOLERANCE_SECS {
        return Err(ReceiveError::Stale);
    }
    serde_json::from_slice(body).map_err(|_| ReceiveError::Malformed)
}

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
        let bytes = Zeroizing::new(STANDARD.decode(b64).ok()?);
        let raw: [u8; SECRET_LEN] = bytes.as_slice().try_into().ok()?;
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

    #[test]
    fn receivers_check_signature_then_time_then_body() {
        let s = SigningSecret::from_bytes([3; SECRET_LEN]);
        let now = 1_800_000_000;
        let body = br#"{"id":"e","rev":1,"kind":"received","status":"mempool","height":null,"confirmations":0,"txid":"ab","pool":"sapling","amount":1,"memo":null}"#;
        let sig = sign(&s, "e.x", now, body);
        let ts = now.to_string();
        let d = receive(&s, "e.x", &ts, &sig, body, now + 10).unwrap();
        assert_eq!(d.amount, 1);
        assert_eq!(d.memo_text(), None);
        let other = SigningSecret::from_bytes([4; SECRET_LEN]);
        assert_eq!(
            receive(&other, "e.x", &ts, &sig, body, now).unwrap_err(),
            ReceiveError::BadSignature
        );
        assert_eq!(
            receive(&s, "e.y", &ts, &sig, body, now).unwrap_err(),
            ReceiveError::BadSignature,
            "the id is signed"
        );
        assert_eq!(
            receive(&s, "e.x", "soon", &sig, body, now).unwrap_err(),
            ReceiveError::BadSignature
        );
        assert_eq!(
            receive(
                &s,
                "e.x",
                &ts,
                &sig,
                body,
                now + TIMESTAMP_TOLERANCE_SECS + 1
            )
            .unwrap_err(),
            ReceiveError::Stale
        );
        let junk = b"{}";
        let junk_sig = sign(&s, "e.x", now, junk);
        assert_eq!(
            receive(&s, "e.x", &ts, &junk_sig, junk, now).unwrap_err(),
            ReceiveError::Malformed
        );
    }

    #[test]
    fn memos_read_as_zip_302() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let delivery = |memo: Option<[u8; 512]>| WebhookDelivery {
            event: crate::api::Event {
                id: "e".into(),
                rev: 1,
                kind: crate::api::EventKind::Received,
                status: EventStatus::Mined,
                height: Some(1),
                confirmations: 1,
                compact_tx: None,
            },
            txid: "ab".into(),
            pool: crate::event_id::Pool::Sapling,
            amount: 1,
            memo: memo.map(|m| URL_SAFE_NO_PAD.encode(m)),
        };
        let mut text = [0u8; 512];
        text[..6].copy_from_slice("héllo".as_bytes());
        assert_eq!(delivery(Some(text)).memo_text().as_deref(), Some("héllo"));
        let mut empty = [0u8; 512];
        empty[0] = 0xF6;
        assert_eq!(delivery(Some(empty)).memo_text(), None);
        assert_eq!(delivery(Some(empty)).memo_bytes().unwrap()[0], 0xF6);
        let mut bad = [0u8; 512];
        bad[0] = 0xC3; // a lone UTF-8 lead byte
        assert_eq!(delivery(Some(bad)).memo_text(), None);
        assert_eq!(delivery(None).memo_bytes(), None);
        assert_eq!(delivery(Some([0; 512])).memo_text().as_deref(), Some(""));
    }
}
