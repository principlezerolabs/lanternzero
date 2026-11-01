//! Lantern Zero reference push gateway (spec §4.1, §5.3, §5.4).
//!
//! A wallet vendor runs this with its APNs and FCM credentials. Lantern
//! Zero servers push to it with standard Web Push (RFC 8030, VAPID
//! RFC 8292, RFC 8291 payloads); it forwards to Apple and Google.
//!
//! - **No device records.** The device token, the bound server key, and
//!   the expiry are sealed into each endpoint URL ([`seal`]). The gateway
//!   stores only its sealing keys ([`keys`]) and a list of revoked
//!   subscriptions that holds nothing about devices ([`revoke`]).
//! - **Bound.** Each subscription accepts pushes signed by one server key
//!   ([`vapid`]); there is no admission list.
//! - **Rate-limited** per device, with background and alert budgets apart,
//!   and per server key ([`limits`]).
//! - **Blind.** Payloads are forwarded as received: encrypted to the
//!   device. Nothing logs device tokens, endpoints, or payloads.
//!
//! Wallet API (vendor-internal, not part of the Lantern Zero spec):
//! - `POST /v0/subscriptions` with
//!   `{"platform": "apns" | "fcm", "token": "...", "server_key": "<base64url>"}`
//!   returns `201 {"endpoint": "https://<origin>/wp/<opaque>",
//!   "expires": <unix seconds>, "revoke_secret": "<base64url>"}`.
//! - `DELETE /v0/subscriptions/<opaque>` with
//!   `Authorization: Bearer <revoke_secret>` revokes it: `204`.

pub mod config;
pub mod keys;
pub mod limits;
pub mod platform;
pub mod revoke;
pub mod seal;
pub mod vapid;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::keys::KeyRing;
use crate::limits::{Limits, Window};
use crate::platform::{Apns, Delivery, Fcm, Kind, Push};
use crate::revoke::{RevokeError, Revoked};
use crate::seal::{MAX_TOKEN_LEN, Platform, Sealer, Subscription};

/// Largest push body accepted (RFC 8030 §7.2: at least 4096 bytes). The
/// protocol's 1024-byte pings are about 1.1 KB once encrypted.
pub const MAX_PUSH_BODY: usize = 4096;
/// Longest `TTL` honored: 28 days, as FCM allows.
const MAX_TTL_SECS: u64 = 28 * 86_400;
/// `Retry-After` when Apple or Google throttle us without saying how long.
const PLATFORM_RETRY_SECS: u64 = 60;

pub struct AppState {
    pub config: config::Config,
    pub sealer: Sealer,
    pub revoked: Arc<Revoked>,
    pub limits: Limits,
    pub apns: Option<Apns>,
    pub fcm: Option<Fcm>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("data_dir: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Keys(#[from] keys::KeyError),
    #[error(transparent)]
    Platform(#[from] platform::PlatformError),
    #[error("HTTP client: {0}")]
    Http(#[from] reqwest::Error),
}

impl AppState {
    pub fn new(config: config::Config) -> Result<Arc<Self>, StartError> {
        let now = now_unix();
        let ring = KeyRing::load_or_create(&config.data_dir, now)?;
        let revoked = Arc::new(Revoked::open(&config.data_dir, now)?);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        let apns = match &config.apns {
            Some(c) => Some(Apns::new(http.clone(), c, config.alert_title.clone())?),
            None => None,
        };
        let fcm = match &config.fcm {
            Some(c) => Some(Fcm::new(http.clone(), c)?),
            None => None,
        };
        let l = &config.limits;
        let limits = Limits {
            background: Window::new(l.background_per_hour, 3600),
            alert: Window::new(l.alerts_per_hour, 3600),
            per_server: Window::new(l.per_server_per_minute, 60),
        };
        Ok(Arc::new(Self {
            sealer: Sealer::new(&ring),
            revoked,
            limits,
            apns,
            fcm,
            config,
        }))
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v0/subscriptions", post(subscribe))
        .route("/v0/subscriptions/{opaque}", delete(revoke))
        .route("/wp/{opaque}", post(push))
        .layer(DefaultBodyLimit::max(MAX_PUSH_BODY * 2))
        .with_state(state)
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The current Unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, message).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscribeRequest {
    platform: String,
    /// A device identifier, not a secret, but never logged.
    token: String,
    server_key: String,
}

/// Creates a subscription bound to `server_key` (spec §4.1).
async fn subscribe(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<SubscribeRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, "malformed request");
    };
    let platform = match req.platform.as_str() {
        "apns" if state.apns.is_some() => Platform::Apns,
        "fcm" if state.fcm.is_some() => Platform::Fcm,
        "apns" | "fcm" => return error(StatusCode::BAD_REQUEST, "platform not configured"),
        _ => return error(StatusCode::BAD_REQUEST, "unknown platform"),
    };
    let token = match platform {
        // APNs device tokens are hex.
        Platform::Apns => {
            let t = req.token.trim();
            if t.len() % 2 != 0 || t.len() < 32 || t.len() > 2 * MAX_TOKEN_LEN {
                return error(StatusCode::BAD_REQUEST, "invalid token");
            }
            let bytes: Option<Vec<u8>> = (0..t.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(t.get(i..i + 2)?, 16).ok())
                .collect();
            match bytes {
                Some(b) => b,
                None => return error(StatusCode::BAD_REQUEST, "invalid token"),
            }
        }
        Platform::Fcm => {
            let t = req.token.trim();
            if t.is_empty() || t.len() > MAX_TOKEN_LEN || !t.is_ascii() {
                return error(StatusCode::BAD_REQUEST, "invalid token");
            }
            t.as_bytes().to_vec()
        }
    };
    let Some(server_key) = vapid::parse_server_key(&req.server_key) else {
        return error(StatusCode::BAD_REQUEST, "invalid server_key");
    };
    let now = now_unix();
    let expires = now + state.config.endpoint_lifetime_days * 86_400;
    // Only the wallet gets the secret; the endpoint carries its hash, so
    // the server, which holds the endpoint, can't revoke (spec §4.1).
    let mut secret = Zeroizing::new([0u8; 32]);
    rand::fill(&mut secret[..]);
    let opaque = state.sealer.seal(&Subscription {
        platform,
        server_key,
        token: Zeroizing::new(token),
        created: now,
        expires,
        revoke_hash: revoke::secret_hash(&secret),
    });
    let endpoint = format!("{}/wp/{opaque}", state.config.public_origin);
    let body = serde_json::json!({
        "endpoint": endpoint,
        "expires": expires,
        "revoke_secret": URL_SAFE_NO_PAD.encode(&secret[..]),
    })
    .to_string();
    (
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// Revokes a subscription (spec §4.1): later pushes to it get `410`.
async fn revoke(
    State(state): State<Arc<AppState>>,
    UrlPath(opaque): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    let now = now_unix();
    let Some(sub) = state.sealer.open(&opaque) else {
        return error(StatusCode::NOT_FOUND, "no such subscription");
    };
    let raw = Zeroizing::new(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .and_then(|b64| URL_SAFE_NO_PAD.decode(b64.trim()).ok())
            .unwrap_or_default(),
    );
    let Ok(secret) = <&[u8; 32]>::try_from(raw.as_slice()) else {
        return error(StatusCode::UNAUTHORIZED, "revocation secret required");
    };
    if !bool::from(revoke::secret_hash(secret).ct_eq(&sub.revoke_hash)) {
        return error(StatusCode::FORBIDDEN, "wrong revocation secret");
    }
    if now > sub.expires {
        // Already dead; nothing to keep.
        return StatusCode::NO_CONTENT.into_response();
    }
    let revoked = state.revoked.clone();
    let result =
        tokio::task::spawn_blocking(move || revoked.revoke(sub.revoke_hash, sub.expires, now))
            .await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(RevokeError::Full)) => {
            tracing::warn!("revocation list is full");
            error(StatusCode::SERVICE_UNAVAILABLE, "try again later")
        }
        Ok(Err(RevokeError::Io(e))) => {
            tracing::error!(error = %e, "cannot record a revocation");
            error(StatusCode::INTERNAL_SERVER_ERROR, "cannot revoke now")
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "cannot revoke now"),
    }
}

/// Receives a Web Push message (RFC 8030 §5) and forwards it.
async fn push(
    State(state): State<Arc<AppState>>,
    UrlPath(opaque): UrlPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_unix();
    let Some(sub) = state.sealer.open(&opaque) else {
        return error(StatusCode::NOT_FOUND, "no such subscription");
    };
    let header_str = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    // Spec §5.3: only the server this subscription is bound to.
    let Some(auth) = header_str("authorization") else {
        return error(StatusCode::UNAUTHORIZED, "VAPID authorization required");
    };
    match vapid::verify(auth, &sub.server_key, &state.config.public_origin, now) {
        Ok(()) => {}
        Err(vapid::VapidError::WrongKey) => {
            return error(
                StatusCode::FORBIDDEN,
                "not the key this subscription is bound to",
            );
        }
        Err(vapid::VapidError::Invalid) => {
            return error(StatusCode::UNAUTHORIZED, "invalid VAPID authorization");
        }
    }
    // Checked after VAPID, so only the bound server learns of it. Either
    // way the server drops the device (spec §5.3).
    if now > sub.expires {
        return error(StatusCode::GONE, "subscription expired");
    }
    if state.revoked.contains(&sub.revoke_hash) {
        return error(StatusCode::GONE, "subscription revoked");
    }

    if body.len() > MAX_PUSH_BODY {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "push message too large");
    }
    // Invariant 5: only RFC 8291 ciphertext travels on.
    if !header_str("content-encoding").is_some_and(|v| v.trim().eq_ignore_ascii_case("aes128gcm"))
        || body.is_empty()
    {
        return error(
            StatusCode::BAD_REQUEST,
            "payload must be aes128gcm (RFC 8291)",
        );
    }
    let Some(ttl) = header_str("ttl").and_then(|v| v.trim().parse::<u64>().ok()) else {
        return error(StatusCode::BAD_REQUEST, "TTL header required");
    };
    let kind = match header_str("urgency").map(str::trim) {
        None | Some("very-low" | "low" | "normal") => Kind::Background,
        Some("high") => Kind::Alert,
        Some(_) => return error(StatusCode::BAD_REQUEST, "invalid Urgency"),
    };
    let topic = header_str("topic").map(str::trim);
    if let Some(t) = topic
        && (t.is_empty()
            || t.len() > 32
            || !t
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    {
        return error(StatusCode::BAD_REQUEST, "invalid Topic");
    }

    // Budgets are per device and server: binding means only the wallet,
    // which knows the token, can create subscriptions, and a wallet using
    // two servers must not have one server's wakes eat the other's.
    let server_id: [u8; 32] = Sha256::digest(sub.server_key).into();
    let device_id: [u8; 32] = {
        let mut h = Sha256::new();
        h.update([sub.platform.code()]);
        h.update(server_id);
        h.update(&sub.token[..]);
        h.finalize().into()
    };
    let limited = state
        .limits
        .per_server
        .hit(server_id, now)
        .and_then(|()| match kind {
            Kind::Background => state.limits.background.hit(device_id, now),
            Kind::Alert => state.limits.alert.hit(device_id, now),
        });
    if let Err(retry) = limited {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry.to_string())],
            "rate limited",
        )
            .into_response();
    }

    let p = Push {
        kind,
        body: &body,
        ttl_secs: ttl.min(MAX_TTL_SECS),
        topic,
    };
    let delivery = match (sub.platform, &state.apns, &state.fcm) {
        (Platform::Apns, Some(apns), _) => apns.send(&sub.token, &p, now).await,
        (Platform::Fcm, _, Some(fcm)) => fcm.send(&sub.token, &p).await,
        // The platform was configured when this endpoint was made, but
        // isn't any more: the endpoint can never work again.
        _ => Delivery::Gone,
    };
    match delivery {
        Delivery::Delivered => {
            let mut id = [0u8; 12];
            rand::fill(&mut id);
            let hex = hex(&id);
            (
                StatusCode::CREATED,
                [(
                    header::LOCATION,
                    format!("{}/m/{hex}", state.config.public_origin),
                )],
            )
                .into_response()
        }
        Delivery::Gone => error(StatusCode::GONE, "subscription expired"),
        // Spec §5.3: the server waits at least `Retry-After`, so always send
        // one; APNs usually gives none.
        Delivery::RateLimited(retry) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                header::RETRY_AFTER,
                retry.unwrap_or(PLATFORM_RETRY_SECS).to_string(),
            )],
            "platform rate limited",
        )
            .into_response(),
        Delivery::Failed => error(StatusCode::BAD_GATEWAY, "delivery failed"),
    }
}

/// Crates whose debug logs include URLs (and so device tokens) or headers.
/// Capped at `warn` whatever `RUST_LOG` says.
const NOISY_DEPENDENCIES: &[&str] = &[
    "hyper",
    "hyper_util",
    "h2",
    "reqwest",
    "rustls",
    "tower_http",
    "gcp_auth",
];

pub fn log_filter(default: &str) -> tracing_subscriber::EnvFilter {
    let mut filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    for dep in NOISY_DEPENDENCIES {
        filter = filter.add_directive(format!("{dep}=warn").parse().expect("valid directive"));
    }
    filter
}
