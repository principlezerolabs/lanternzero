//! Lantern Zero reference push gateway (spec §4.1, §5.3, §5.4).
//!
//! A wallet vendor runs this with its APNs and FCM credentials. Lantern
//! Zero servers push to it with standard Web Push (RFC 8030, VAPID
//! RFC 8292, RFC 8291 payloads); it forwards to Apple and Google.
//!
//! - **Stateless.** The device token and the bound server key are sealed
//!   into each endpoint URL ([`seal`]). The gateway stores only its own
//!   sealing key.
//! - **Bound.** Each subscription accepts pushes signed by one server key
//!   ([`vapid`]); there is no admission list.
//! - **Rate-limited** per device, with background and alert budgets apart,
//!   and per server key ([`limits`]).
//! - **Blind.** Payloads are forwarded as received: encrypted to the
//!   device. Nothing logs device tokens, endpoints, or payloads.
//!
//! Wallet API (vendor-internal, not part of the Lantern Zero spec):
//! `POST /v0/subscriptions` with
//! `{"platform": "apns" | "fcm", "token": "...", "server_key": "<base64url>"}`
//! returns `201 {"endpoint": "https://<origin>/wp/<opaque>"}`.

pub mod config;
pub mod limits;
pub mod platform;
pub mod seal;
pub mod vapid;

use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::limits::{Limits, Window};
use crate::platform::{Apns, Delivery, Fcm, Kind, Push};
use crate::seal::{MAX_TOKEN_LEN, Platform, Sealer, Subscription};

/// Largest push body accepted (RFC 8030 §7.2: at least 4096 bytes). The
/// protocol's 1024-byte pings are about 1.1 KB once encrypted.
pub const MAX_PUSH_BODY: usize = 4096;
/// Longest `TTL` honored: 28 days, as FCM allows.
const MAX_TTL_SECS: u64 = 28 * 86_400;
const KEY_FILE: &str = "endpoint-key";
/// `Retry-After` when Apple or Google throttle us without saying how long.
const PLATFORM_RETRY_SECS: u64 = 60;

pub struct AppState {
    pub config: config::Config,
    pub sealer: Sealer,
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
    #[error("endpoint key file is corrupt")]
    CorruptKey,
    #[error(transparent)]
    Platform(#[from] platform::PlatformError),
    #[error("HTTP client: {0}")]
    Http(#[from] reqwest::Error),
}

impl AppState {
    pub fn new(config: config::Config) -> Result<Arc<Self>, StartError> {
        let key = load_or_create_key(&config.data_dir)?;
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
            sealer: Sealer::new(&key),
            limits,
            apns,
            fcm,
            config,
        }))
    }
}

/// Reads the sealing key, creating it (mode 0600, in a 0700 directory) on
/// first start. Losing it invalidates every endpoint.
fn load_or_create_key(dir: &Path) -> Result<Zeroizing<[u8; 32]>, StartError> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)?;
    let path = dir.join(KEY_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes.try_into().map_err(|_| StartError::CorruptKey)?;
            Ok(Zeroizing::new(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut key = Zeroizing::new([0u8; 32]);
            rand::fill(&mut key[..]);
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&path)?;
            f.write_all(&key[..])?;
            f.sync_all()?;
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v0/subscriptions", post(subscribe))
        .route("/wp/{opaque}", post(push))
        .layer(DefaultBodyLimit::max(MAX_PUSH_BODY * 2))
        .with_state(state)
}

fn now_unix() -> u64 {
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
    let opaque = state.sealer.seal(&Subscription {
        platform,
        server_key,
        token: Zeroizing::new(token),
        created: now_unix(),
    });
    let endpoint = format!("{}/wp/{opaque}", state.config.public_origin);
    (
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "endpoint": endpoint }).to_string(),
    )
        .into_response()
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
            let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
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
