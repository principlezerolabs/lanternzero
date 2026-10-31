//! JSON bodies for the v0 API (spec §4, §5). Unknown fields are ignored on
//! input, as the spec requires. Enums a wallet receives also accept unknown
//! values (as `Unknown`), so a newer server can't break an older wallet.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::event_id::Pool;
use crate::lease::{LeaseRequest, Network};

/// RFC 8291 receiver keys of a Web Push subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushKeys {
    /// Receiver public key (P-256), base64url.
    pub p256dh: String,
    /// Auth secret, 16 bytes, base64url.
    pub auth: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistrationError {
    #[error("endpoint must be an https URL of at most 1024 bytes, with no user name or password")]
    Endpoint,
    #[error("p256dh must be a 65-byte uncompressed P-256 point")]
    P256dh,
    #[error("auth must be 16 bytes")]
    Auth,
}

/// Longest push endpoint URL a server accepts.
pub const MAX_ENDPOINT_LEN: usize = 1024;

impl DeviceRegistration {
    /// Shape checks a server runs before storing a subscription. Servers must
    /// also apply the SSRF rules in spec §4.1 when they connect.
    pub fn validate(&self) -> Result<(), RegistrationError> {
        let ok_endpoint = self.endpoint.len() <= MAX_ENDPOINT_LEN
            && ::url::Url::parse(&self.endpoint).is_ok_and(|u| {
                u.scheme() == "https"
                    && u.host_str().is_some()
                    && u.username().is_empty()
                    && u.password().is_none()
            });
        if !ok_endpoint {
            return Err(RegistrationError::Endpoint);
        }
        let p = URL_SAFE_NO_PAD
            .decode(&self.keys.p256dh)
            .map_err(|_| RegistrationError::P256dh)?;
        if p.len() != 65 || p[0] != 0x04 {
            return Err(RegistrationError::P256dh);
        }
        let a = URL_SAFE_NO_PAD
            .decode(&self.keys.auth)
            .map_err(|_| RegistrationError::Auth)?;
        if a.len() != 16 {
            return Err(RegistrationError::Auth);
        }
        Ok(())
    }
}

/// `POST /v0/devices` (spec §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistration {
    pub seq: u64,
    /// RFC 8030 push resource on the wallet vendor's gateway.
    pub endpoint: String,
    pub keys: PushKeys,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistered {
    pub device_id: String,
}

/// A body that carries only `seq` (deletes, rotation without other fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqOnly {
    pub seq: u64,
}

/// `POST /v0/wake` (spec §4.2). `lease: None` ends any lease (opt-out) and
/// is what default-mode wallets always send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeRequest {
    pub device_id: String,
    pub seq: u64,
    pub ack: Vec<String>,
    pub lease: Option<LeaseRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseStatus {
    pub active: bool,
    /// RFC 3339, UTC. Absent when no lease is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// A half-open height range `[start, end)` holding the user's notes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hint {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeResponse {
    pub tip: u64,
    pub lease: LeaseStatus,
    pub hints: Vec<Hint>,
    pub events: Vec<Event>,
    pub cursor: String,
    pub next: Option<String>,
}

/// `POST /v0/events` (spec §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsRequest {
    pub device_id: String,
    pub seq: u64,
    pub cursor: String,
    pub wait: u32,
    pub ack: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsResponse {
    pub cursor: String,
    pub events: Vec<Event>,
    pub next: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Received,
    Spent,
    /// A kind added by a later version.
    #[serde(other, skip_serializing)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStatus {
    Mempool,
    Mined,
    Reorged,
    /// A status added by a later version.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// A matched transaction (spec §4.3). Derived from a key, so it lives in
/// server memory only (invariant 3).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub rev: u32,
    pub kind: EventKind,
    pub status: EventStatus,
    pub height: Option<u64>,
    pub confirmations: u32,
    /// `CompactTx` protobuf bytes, base64url. Omitted in push payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compact_tx: Option<String>,
}

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event")
            .field("id", &self.id)
            .field("rev", &self.rev)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("height", &self.height)
            .field("confirmations", &self.confirmations)
            .field(
                "compact_tx",
                &self.compact_tx.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Webhook delivery body (spec §4.5): the event plus merchant fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDelivery {
    #[serde(flatten)]
    pub event: Event,
    pub txid: String,
    pub pool: Pool,
    pub amount: u64,
    pub memo: Option<String>,
}

/// `PUT /v0/webhook`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub seq: u64,
    pub url: String,
}

/// Returned once by `PUT /v0/webhook`. `Debug` hides the secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookSecret {
    pub secret: String,
}

impl std::fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebhookSecret(<redacted>)")
    }
}

/// `POST /v0/token/rotate` (spec §4.6). Carries only the new token's hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRotate {
    pub seq: u64,
    /// Hex `SHA-256` of the new token's text form.
    pub new_token_hash: String,
}

/// `POST /v0/info` response (spec §4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    pub versions: Vec<String>,
    pub network: Network,
    pub wake_interval_secs: u32,
    pub long_poll_wait_secs: [u32; 2],
    pub finality_depth: u32,
    pub vapid_public_key: String,
    pub ohttp_key_config_sha256: String,
    /// Reserved for enclave attestation; always `null` in v0.
    pub attestation: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PingType {
    Wake,
    Payment,
    /// A type added by a later version; wallets ignore the ping.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// A push ping's plaintext before padding and RFC 8291 encryption (spec §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    pub v: u32,
    pub t: PingType,
    /// Empty except for `private` alerts (up to 4) and payment pushes (1).
    pub events: Vec<Event>,
}

/// Most events a scheduled ping carries under `private` alerts.
pub const MAX_PING_EVENTS: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{AlertMode, MAX_DURATION_SECS, ViewingKey};
    use crate::padding::{PING_SIZE, REQUEST_SIZE, pad_ping_json};

    fn event() -> Event {
        Event {
            id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            rev: 1,
            kind: EventKind::Received,
            status: EventStatus::Mempool,
            height: None,
            confirmations: 0,
            compact_tx: None,
        }
    }

    #[test]
    fn event_debug_redacts_compact_tx() {
        let mut e = event();
        e.compact_tx = Some("secretpayload".into());
        let dbg = format!("{e:?}");
        assert!(!dbg.contains("secretpayload"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn default_wake_matches_spec_shape() {
        let w = WakeRequest {
            device_id: "d".into(),
            seq: 42,
            ack: vec![],
            lease: None,
        };
        assert_eq!(
            serde_json::to_string(&w).unwrap(),
            r#"{"device_id":"d","seq":42,"ack":[],"lease":null}"#
        );
    }

    #[test]
    fn ignores_unknown_fields() {
        let r: EventsResponse =
            serde_json::from_str(r#"{"cursor":"c","events":[],"next":null,"future_field":1}"#)
                .unwrap();
        assert_eq!(r.cursor, "c");
    }

    /// Spec §3.3 and §8: a lease with four long full viewing keys and a full
    /// ack list must fit in a 4096-byte request, leaving room for the Binary
    /// HTTP framing and headers (budgeted at 1 KiB).
    #[test]
    fn largest_wake_fits_request_size() {
        let key = format!("uview1{}", "q".repeat(600));
        let w = WakeRequest {
            device_id: "x".repeat(32),
            seq: u64::MAX,
            ack: vec!["A".repeat(22); 4],
            lease: Some(LeaseRequest {
                keys: (0..4).map(|_| ViewingKey::new(key.clone())).collect(),
                from_height: u64::MAX,
                duration_secs: MAX_DURATION_SECS,
                spend_alerts: true,
                alert_mode: AlertMode::Private,
            }),
        };
        let len = serde_json::to_vec(&w).unwrap().len();
        assert!(len + 1024 <= REQUEST_SIZE, "wake body is {len} bytes");
    }

    /// Spec §5.1: a scheduled ping with the most `private` events still fits
    /// the fixed ping size.
    #[test]
    fn fullest_ping_fits_ping_size() {
        let mut e = event();
        e.status = EventStatus::Mined;
        e.height = Some(u64::MAX);
        e.confirmations = u32::MAX;
        e.rev = u32::MAX;
        let p = Ping {
            v: 0,
            t: PingType::Wake,
            events: vec![e; MAX_PING_EVENTS],
        };
        let padded = pad_ping_json(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(padded.len(), PING_SIZE);
    }

    #[test]
    fn unknown_enum_values_do_not_break_parsing() {
        let e: Event = serde_json::from_str(
            r#"{"id":"x","rev":1,"kind":"refunded","status":"finalized","height":1,"confirmations":9}"#,
        )
        .unwrap();
        assert_eq!(e.kind, EventKind::Unknown);
        assert_eq!(e.status, EventStatus::Unknown);
        let p: Ping = serde_json::from_str(r#"{"v":0,"t":"later","events":[]}"#).unwrap();
        assert_eq!(p.t, PingType::Unknown);
    }

    fn registration(endpoint: &str, p256dh: Vec<u8>, auth: Vec<u8>) -> DeviceRegistration {
        DeviceRegistration {
            seq: 1,
            endpoint: endpoint.into(),
            keys: PushKeys {
                p256dh: URL_SAFE_NO_PAD.encode(p256dh),
                auth: URL_SAFE_NO_PAD.encode(auth),
            },
        }
    }

    #[test]
    fn validates_registration_shape() {
        let mut point = vec![0x04];
        point.extend([1u8; 64]);
        let good = "https://push.example.app/wp/abc";
        assert_eq!(
            registration(good, point.clone(), vec![2; 16]).validate(),
            Ok(())
        );
        for bad in [
            "http://push.example.app/wp",
            "https://u:p@push.example.app/",
            "not a url",
        ] {
            assert_eq!(
                registration(bad, point.clone(), vec![2; 16]).validate(),
                Err(RegistrationError::Endpoint)
            );
        }
        let long = format!("https://x.org/{}", "a".repeat(MAX_ENDPOINT_LEN));
        assert_eq!(
            registration(&long, point.clone(), vec![2; 16]).validate(),
            Err(RegistrationError::Endpoint)
        );
        assert_eq!(
            registration(good, vec![0x04; 33], vec![2; 16]).validate(),
            Err(RegistrationError::P256dh)
        );
        assert_eq!(
            registration(good, point, vec![2; 15]).validate(),
            Err(RegistrationError::Auth)
        );
    }

    #[test]
    fn webhook_secret_debug_is_redacted() {
        let s = WebhookSecret {
            secret: "whsec_topsecret".into(),
        };
        assert!(!format!("{s:?}").contains("topsecret"));
    }
}
