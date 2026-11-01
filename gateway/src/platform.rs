//! Forwarding to APNs and FCM (spec §5.4).
//!
//! The ciphertext from the server goes to the device unchanged, base64url
//! in the `lz` field. Apple and Google see only that opaque string, the
//! timing, and, for payment alerts, a generic visible title (invariant 5).

use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde_json::json;

/// Apple accepts a provider token for up to an hour, and asks that it be
/// refreshed no more often than every 20 minutes.
const APNS_TOKEN_REFRESH: Duration = Duration::from_secs(40 * 60);
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// The two kinds of push in spec §5.3, told apart by `Urgency`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Scheduled wake: a silent background push.
    Background,
    /// Instant payment alert (`Urgency: high`): a visible notification the
    /// app's extension decrypts.
    Alert,
}

/// One push to forward.
#[derive(Debug)]
pub struct Push<'a> {
    pub kind: Kind,
    /// The RFC 8291 ciphertext, as received.
    pub body: &'a [u8],
    pub ttl_secs: u64,
    /// RFC 8030 `Topic`, used as the collapse key.
    pub topic: Option<&'a str>,
}

/// What the platform said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Delivered,
    /// The token is no longer valid: the server should drop the device.
    Gone,
    /// Slow down; seconds to wait, if the platform said.
    RateLimited(Option<u64>),
    Failed,
}

/// APNs over HTTP/2 with token-based (JWT) authentication.
pub struct Apns {
    http: reqwest::Client,
    base_url: String,
    topic: String,
    team_id: String,
    key_id: String,
    key: SigningKey,
    alert_title: String,
    token: Mutex<Option<(std::time::Instant, String)>>,
}

impl std::fmt::Debug for Apns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Apns")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("cannot read key file {0}: {1}")]
    Read(String, std::io::Error),
    #[error("invalid APNs key (expected a PKCS#8 .p8 file)")]
    ApnsKey,
    #[error("FCM credentials: {0}")]
    Fcm(String),
}

impl Apns {
    pub fn new(
        http: reqwest::Client,
        config: &crate::config::ApnsConfig,
        alert_title: String,
    ) -> Result<Self, PlatformError> {
        let pem = std::fs::read_to_string(&config.key_path)
            .map_err(|e| PlatformError::Read(config.key_path.display().to_string(), e))?;
        let key = SigningKey::from_pkcs8_pem(&pem).map_err(|_| PlatformError::ApnsKey)?;
        Ok(Self {
            http,
            base_url: config.base_url(),
            topic: config.topic.clone(),
            team_id: config.team_id.clone(),
            key_id: config.key_id.clone(),
            key,
            alert_title,
            token: Mutex::new(None),
        })
    }

    fn provider_token(&self, now_unix: u64) -> String {
        let mut cached = self.token.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, t)) = cached.as_ref()
            && at.elapsed() < APNS_TOKEN_REFRESH
        {
            return t.clone();
        }
        let header = json!({ "alg": "ES256", "kid": self.key_id });
        let claims = json!({ "iss": self.team_id, "iat": now_unix });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig: Signature = self.key.sign(input.as_bytes());
        let t = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        *cached = Some((std::time::Instant::now(), t.clone()));
        t
    }

    pub async fn send(&self, device_token: &[u8], push: &Push<'_>, now_unix: u64) -> Delivery {
        let hex: String = device_token.iter().map(|b| format!("{b:02x}")).collect();
        let lz = URL_SAFE_NO_PAD.encode(push.body);
        let (push_type, priority, payload) = match push.kind {
            Kind::Background => (
                "background",
                "5",
                json!({ "aps": { "content-available": 1 }, "lz": lz }),
            ),
            Kind::Alert => (
                "alert",
                "10",
                json!({
                    "aps": { "alert": { "title": self.alert_title }, "mutable-content": 1 },
                    "lz": lz,
                }),
            ),
        };
        let expiration = if push.ttl_secs == 0 {
            0
        } else {
            now_unix + push.ttl_secs
        };
        let mut req = self
            .http
            .post(format!("{}/3/device/{hex}", self.base_url))
            .header(
                "authorization",
                format!("bearer {}", self.provider_token(now_unix)),
            )
            .header("apns-topic", &self.topic)
            .header("apns-push-type", push_type)
            .header("apns-priority", priority)
            .header("apns-expiration", expiration.to_string())
            .header("content-type", "application/json")
            .body(payload.to_string());
        if let Some(t) = push.topic {
            req = req.header("apns-collapse-id", t);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    timeout = e.is_timeout(),
                    connect = e.is_connect(),
                    "APNs request failed"
                );
                return Delivery::Failed;
            }
        };
        let status = resp.status().as_u16();
        let retry = retry_after(&resp);
        let reason = resp
            .bytes()
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["reason"].as_str().map(str::to_owned))
            .unwrap_or_default();
        match (status, reason.as_str()) {
            (200, _) => Delivery::Delivered,
            (410, _) | (400, "BadDeviceToken" | "DeviceTokenNotForTopic") => Delivery::Gone,
            (429, _) => Delivery::RateLimited(retry),
            (403, "ExpiredProviderToken" | "InvalidProviderToken") => {
                *self.token.lock().unwrap_or_else(|e| e.into_inner()) = None;
                tracing::warn!(reason, "APNs rejected the provider token");
                Delivery::Failed
            }
            _ => {
                tracing::warn!(status, reason, "APNs error");
                Delivery::Failed
            }
        }
    }
}

/// Where FCM access tokens come from.
pub enum FcmAuth {
    ServiceAccount(Box<gcp_auth::CustomServiceAccount>),
    /// A fixed bearer token, for tests and local development only.
    Static(String),
}

impl std::fmt::Debug for FcmAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FcmAuth::ServiceAccount(_) => "FcmAuth::ServiceAccount",
            FcmAuth::Static(_) => "FcmAuth::Static(<redacted>)",
        })
    }
}

/// FCM HTTP v1.
pub struct Fcm {
    http: reqwest::Client,
    base_url: String,
    project_id: String,
    auth: FcmAuth,
}

impl std::fmt::Debug for Fcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fcm")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl Fcm {
    pub fn new(
        http: reqwest::Client,
        config: &crate::config::FcmConfig,
    ) -> Result<Self, PlatformError> {
        let auth = match (&config.credentials_path, &config.static_access_token) {
            (Some(path), _) => FcmAuth::ServiceAccount(Box::new(
                gcp_auth::CustomServiceAccount::from_file(path)
                    .map_err(|e| PlatformError::Fcm(e.to_string()))?,
            )),
            (None, Some(t)) => FcmAuth::Static(t.clone()),
            (None, None) => {
                return Err(PlatformError::Fcm(
                    "set credentials_path to a service-account key".into(),
                ));
            }
        };
        Ok(Self {
            http,
            base_url: config.base_url.clone(),
            project_id: config.project_id.clone(),
            auth,
        })
    }

    async fn access_token(&self) -> Option<String> {
        use gcp_auth::TokenProvider;
        match &self.auth {
            FcmAuth::Static(t) => Some(t.clone()),
            FcmAuth::ServiceAccount(sa) => match sa.token(&[FCM_SCOPE]).await {
                Ok(t) => Some(t.as_str().to_owned()),
                Err(_) => {
                    tracing::warn!("cannot get an FCM access token");
                    None
                }
            },
        }
    }

    pub async fn send(&self, registration_token: &[u8], push: &Push<'_>) -> Delivery {
        let Ok(token) = std::str::from_utf8(registration_token) else {
            return Delivery::Gone;
        };
        let Some(access) = self.access_token().await else {
            return Delivery::Failed;
        };
        let mut android = json!({
            "priority": if push.kind == Kind::Alert { "high" } else { "normal" },
            "ttl": format!("{}s", push.ttl_secs),
        });
        if let Some(t) = push.topic {
            android["collapse_key"] = json!(t);
        }
        let body = json!({ "message": {
            "token": token,
            "data": { "lz": URL_SAFE_NO_PAD.encode(push.body) },
            "android": android,
        }});
        let resp = match self
            .http
            .post(format!(
                "{}/v1/projects/{}/messages:send",
                self.base_url, self.project_id
            ))
            .bearer_auth(access)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    timeout = e.is_timeout(),
                    connect = e.is_connect(),
                    "FCM request failed"
                );
                return Delivery::Failed;
            }
        };
        match resp.status().as_u16() {
            200 => Delivery::Delivered,
            // UNREGISTERED: the app was uninstalled or the token rotated.
            404 => Delivery::Gone,
            429 | 503 => Delivery::RateLimited(retry_after(&resp)),
            status => {
                tracing::warn!(status, "FCM error");
                Delivery::Failed
            }
        }
    }
}

fn retry_after(resp: &reqwest::Response) -> Option<u64> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}
