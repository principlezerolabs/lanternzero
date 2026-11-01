//! The `/v0/` API (spec §4). Mounted behind the OHTTP gateway.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use lz_proto::api::{
    DeviceRegistered, DeviceRegistration, EventsRequest, EventsResponse, Info, SeqOnly,
    TokenRotate, WakeRequest, WakeResponse,
};
use lz_proto::lease::clamp_duration;
use lz_proto::padding::RESPONSE_SIZE;
use lz_proto::token::TokenHash;
use rand::RngExt;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroize;

use crate::AppState;
use crate::config::ScanningPolicy;
use crate::scanner::{FINALITY_DEPTH, Page};
use crate::ssrf;
use crate::store::{AccountId, RotateError, StoreError};
use crate::viewkey::ScanKeys;

/// Largest clock difference accepted in an inner request's `Date` (spec §3.4).
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);
/// Most JSON in one response body: the fixed response size less room for
/// the Binary HTTP status and headers.
const MAX_JSON: usize = RESPONSE_SIZE - 160;
/// Most hint ranges in one `wake` response.
const MAX_HINTS: usize = 32;
/// Long-poll hold, clamped to this range (spec §4.3).
const LONG_POLL_SECS: std::ops::RangeInclusive<u32> = 25..=30;
/// Each released long-poll waits a random delay below this (spec §4.3).
const RELEASE_JITTER: Duration = Duration::from_secs(2);

/// Builds the API router. Paths are relative to the configured base path.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v0/info", post(info))
        .route("/v0/devices", post(register_device))
        .route("/v0/devices/{device_id}", delete(delete_device))
        .route("/v0/wake", post(wake))
        .route("/v0/events", post(events))
        .route("/v0/token/rotate", post(rotate_token))
        .route("/v0/account", delete(delete_account))
        .layer(middleware::from_fn(require_date))
        .with_state(state)
}

/// An RFC 9457 problem response (spec §3.6).
#[derive(Debug)]
pub struct Problem {
    status: StatusCode,
    slug: &'static str,
    title: &'static str,
    min_seq: Option<u64>,
    retry_after: Option<u64>,
}

impl Problem {
    pub fn new(status: StatusCode, slug: &'static str, title: &'static str) -> Self {
        Self {
            status,
            slug,
            title,
            min_seq: None,
            retry_after: None,
        }
    }
    fn rate_limited(retry_after: u64) -> Self {
        Self {
            retry_after: Some(retry_after),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate-limited",
                "too many requests",
            )
        }
    }
    pub(crate) fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
        )
    }
    pub(crate) fn bad_request(title: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad-request", title)
    }
    fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or unknown account token",
        )
    }
}

#[derive(Serialize)]
struct ProblemBody {
    #[serde(rename = "type")]
    kind: String,
    title: &'static str,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_seq: Option<u64>,
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let body = ProblemBody {
            kind: format!("https://lanternzero.com/problems/{}", self.slug),
            title: self.title,
            status: self.status.as_u16(),
            min_seq: self.min_seq,
        };
        let mut resp = (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            serde_json::to_vec(&body).expect("problem serializes"),
        )
            .into_response();
        if let Some(secs) = self.retry_after {
            resp.headers_mut().insert(header::RETRY_AFTER, secs.into());
        }
        resp
    }
}

impl From<StoreError> for Problem {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::UnknownDevice => Self::new(
                StatusCode::NOT_FOUND,
                "unknown-device",
                "unknown device; register again",
            ),
            StoreError::TooManyDevices => Self::new(
                StatusCode::CONFLICT,
                "too-many-devices",
                "this account has the maximum number of devices",
            ),
            StoreError::StaleSeq { min_seq } => Self {
                min_seq: Some(min_seq),
                ..Self::new(
                    StatusCode::CONFLICT,
                    "stale-seq",
                    "seq was already used or is too old",
                )
            },
        }
    }
}

/// Rejects requests without a current `Date` header (spec §3.4).
async fn require_date(req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(header::DATE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok())
        .is_some_and(|date| {
            let now = SystemTime::now();
            let skew = now
                .duration_since(date)
                .or_else(|_| date.duration_since(now))
                .unwrap_or(Duration::MAX);
            skew <= MAX_CLOCK_SKEW
        });
    if !ok {
        return Problem::new(
            StatusCode::BAD_REQUEST,
            "bad-date",
            "Date header missing or more than 60 s off",
        )
        .into_response();
    }
    next.run(req).await
}

/// Resolves the bearer token to an account and applies the per-account rate
/// limit. Hashes the header text without keeping it; never logs either
/// (invariant 6). The auth scheme is case-insensitive (RFC 9110 §11.1).
fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<AccountId, Problem> {
    authenticate_hash(state, headers).map(|(account, _)| account)
}

/// [`authenticate`], also returning the presented token's hash.
fn authenticate_hash(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(AccountId, TokenHash), Problem> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(Problem::unauthorized)?;
    let (scheme, text) = value.split_once(' ').ok_or_else(Problem::unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Problem::unauthorized());
    }
    let hash = TokenHash::of_text(text.trim());
    let account = state
        .store
        .authenticate(&hash)
        .ok_or_else(Problem::unauthorized)?;
    let key: String = account.iter().map(|b| format!("{b:02x}")).collect();
    state
        .account_limiter
        .check(&key, SystemTime::now())
        .map_err(Problem::rate_limited)?;
    Ok((account, hash))
}

/// Applies the per-device rate limit.
fn limit_device(state: &AppState, device_id: &str) -> Result<(), Problem> {
    state
        .device_limiter
        .check(device_id, SystemTime::now())
        .map_err(Problem::rate_limited)
}

fn parse<T: DeserializeOwned>(body: &Bytes) -> Result<T, Problem> {
    serde_json::from_slice(body).map_err(|_| Problem::bad_request("malformed JSON body"))
}

/// Parses JSON and zeroes a uniquely owned body buffer (viewing keys in
/// `wake` requests).
fn parse_zero<T: DeserializeOwned>(body: Bytes) -> Result<T, Problem> {
    match body.try_into_mut() {
        Ok(mut unique) => {
            let out = serde_json::from_slice(&unique).map_err(|_| {
                unique.zeroize();
                Problem::bad_request("malformed JSON body")
            })?;
            unique.zeroize();
            Ok(out)
        }
        Err(body) => parse(&body),
    }
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(value).expect("response serializes"),
    )
        .into_response()
}

async fn info(State(state): State<Arc<AppState>>) -> Response {
    json(
        StatusCode::OK,
        &Info {
            versions: vec![lz_proto::VERSION.to_owned()],
            network: state.config.network,
            wake_interval_secs: crate::push::WAKE_INTERVAL.as_secs() as u32,
            long_poll_wait_secs: [25, 30],
            finality_depth: FINALITY_DEPTH,
            vapid_public_key: state.vapid.current().public_b64.clone(),
            ohttp_key_config_sha256: state.ohttp_keys_sha256.clone(),
            idle_account_days: Some(state.config.accounts.idle_account_days).filter(|&d| d > 0),
            attestation: None,
        },
    )
}

async fn register_device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Problem> {
    let account = authenticate(&state, &headers)?;
    let mut reg: DeviceRegistration = parse(&body)?;
    // Registration names no device, so it uses the account's window
    // (spec §3.4).
    state.store.accept_account_seq(account, reg.seq)?;
    // The key the subscription is bound to (spec §4.1): named; or, when
    // the same endpoint is registered again, the key it already had (a
    // subscription's key never changes); or the current one.
    let vapid = match reg.vapid_public_key.take() {
        None => state
            .store
            .endpoint_vapid(account, &reg.endpoint)
            .filter(|k| state.vapid.get(k).is_some())
            .unwrap_or_else(|| state.vapid.current().public_b64.clone()),
        Some(k) if state.vapid.get(&k).is_some() => k,
        Some(_) => {
            return Err(Problem::new(
                StatusCode::BAD_REQUEST,
                "unknown-vapid-key",
                "this server doesn't hold that VAPID key; read info again",
            ));
        }
    };
    reg.vapid_public_key = Some(vapid);
    reg.validate()
        .map_err(|_| Problem::bad_request("invalid push subscription"))?;
    let push = &state.config.push;
    ssrf::check_url(
        &reg.endpoint,
        push.allow_private_targets,
        &push.gateway_allowlist,
    )
    .map_err(|_| Problem::bad_request("push endpoint not allowed"))?;
    let device_id = state
        .store
        .register_device(account, &reg, push.max_devices_per_account)?;
    Ok(json(StatusCode::CREATED, &DeviceRegistered { device_id }))
}

async fn delete_device(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Problem> {
    let account = authenticate(&state, &headers)?;
    limit_device(&state, &device_id)?;
    let SeqOnly { seq } = parse(&body)?;
    state.store.accept_device_seq(account, &device_id, seq)?;
    state.store.delete_device(account, &device_id)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn wake(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Problem> {
    let account = authenticate(&state, &headers)?;
    let req: WakeRequest = parse_zero(body)?;
    limit_device(&state, &req.device_id)?;
    state
        .store
        .accept_device_seq(account, &req.device_id, req.seq)?;
    state.scanner.ack(account, &req.ack);
    let now = SystemTime::now();
    match &req.lease {
        None => state.scanner.end_lease(account),
        Some(lease) => {
            lease
                .validate(state.config.network)
                .map_err(|_| Problem::bad_request("invalid lease"))?;
            // `req` (and the keys in it) is dropped, and zeroed, on every
            // return below.
            if state.chain_source.is_none() {
                return Err(Problem::new(
                    StatusCode::NOT_IMPLEMENTED,
                    "scanning-unavailable",
                    "this server does not offer scanning",
                ));
            }
            if lease.spend_alerts {
                return Err(Problem::new(
                    StatusCode::NOT_IMPLEMENTED,
                    "spend-alerts-unavailable",
                    "this server does not offer spend alerts",
                ));
            }
            // Scanning time (spec §4.2, §4.6).
            let secs_left = match state.config.accounts.scanning {
                ScanningPolicy::All => None,
                ScanningPolicy::Entitled => {
                    let left = state.store.scan_secs_left(account, unix_secs(now));
                    if left == 0 {
                        state.scanner.end_lease(account);
                        return Err(Problem::new(
                            StatusCode::FORBIDDEN,
                            "scanning-not-included",
                            "scanning is not part of this account",
                        ));
                    }
                    Some(left)
                }
            };
            let keys = ScanKeys::decode(&lease.keys, state.config.network)
                .map_err(|_| Problem::bad_request("invalid lease"))?;
            let duration = Duration::from_secs(clamp_duration(lease.duration_secs, secs_left));
            let tip = state.chain.tip();
            if let Some(bf) = state
                .scanner
                .set_lease(account, keys, lease, duration, tip, now)
            {
                tokio::spawn(crate::scanner::backfill(state.clone(), bf));
            }
            // The account was deleted while this request was in flight: a
            // lease must not outlive it (spec §4.6).
            if !state.store.has_account(account) {
                state.scanner.end_lease(account);
                return Err(Problem::unauthorized());
            }
        }
    }
    drop(req);

    let mut hints = state.scanner.hints(account);
    hints.truncate(MAX_HINTS);
    let mut resp = WakeResponse {
        tip: state.chain.tip(),
        lease: state.scanner.lease_status(account, now),
        hints,
        events: vec![],
        cursor: u64::MAX.to_string(),
        next: Some(u64::MAX.to_string()),
    };
    let Page {
        events,
        cursor,
        more,
    } = state
        .scanner
        .page(account, None, MAX_JSON.saturating_sub(json_len(&resp)));
    resp.events = events;
    resp.cursor = cursor.to_string();
    resp.next = more.then(|| cursor.to_string());
    Ok(json(StatusCode::OK, &resp))
}

/// `POST /v0/events`: the long-poll (spec §4.3). Holds every poll until the
/// server-wide release or the wait runs out, even when events are already
/// pending: an early return would show the relay this account scans
/// (invariant 4). `wait: 0` returns at once; wallets use it only to fetch a
/// `next` page.
async fn events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Problem> {
    let account = authenticate(&state, &headers)?;
    let req: EventsRequest = parse(&body)?;
    limit_device(&state, &req.device_id)?;
    state
        .store
        .accept_device_seq(account, &req.device_id, req.seq)?;
    state.scanner.ack(account, &req.ack);
    let after: u64 = req
        .cursor
        .parse()
        .map_err(|_| Problem::bad_request("invalid cursor"))?;
    let mut release = state.scanner.subscribe_release();
    if req.wait > 0 {
        let wait = Duration::from_secs(
            req.wait
                .clamp(*LONG_POLL_SECS.start(), *LONG_POLL_SECS.end())
                .into(),
        );
        tokio::select! {
            changed = release.changed() => {
                if changed.is_ok() {
                    let jitter = rand::rng().random_range(Duration::ZERO..RELEASE_JITTER);
                    tokio::time::sleep(jitter).await;
                }
            }
            () = tokio::time::sleep(wait) => {}
        }
    }
    let mut resp = EventsResponse {
        cursor: u64::MAX.to_string(),
        events: vec![],
        next: Some(u64::MAX.to_string()),
    };
    let page = state.scanner.page(
        account,
        Some(after),
        MAX_JSON.saturating_sub(json_len(&resp)),
    );
    resp.events = page.events;
    resp.cursor = page.cursor.to_string();
    resp.next = page.more.then(|| page.cursor.to_string());
    Ok(json(StatusCode::OK, &resp))
}

/// `POST /v0/token/rotate` (spec §4.6). The presented token keeps working
/// until the new one is first used, or for 24 hours.
async fn rotate_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Problem> {
    let (account, presented) = authenticate_hash(&state, &headers)?;
    let req: TokenRotate = parse(&body)?;
    state.store.accept_account_seq(account, req.seq)?;
    let new = TokenHash::from_hex(&req.new_token_hash)
        .ok_or_else(|| Problem::bad_request("invalid new_token_hash"))?;
    let now = unix_secs(SystemTime::now());
    match state.store.rotate_token(account, &presented, &new, now) {
        Ok(()) => Ok(StatusCode::NO_CONTENT.into_response()),
        // Says nothing about whose token it is.
        Err(RotateError::InUse) => Err(Problem::bad_request("new_token_hash cannot be used")),
        Err(RotateError::Io(e)) => {
            tracing::error!(error = %e, "cannot rotate a token");
            Err(Problem::internal())
        }
    }
}

/// `DELETE /v0/account` (spec §4.6): drops the token hashes, devices,
/// lease, events, and hints at once.
async fn delete_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Problem> {
    let account = authenticate(&state, &headers)?;
    let SeqOnly { seq } = parse(&body)?;
    state.store.accept_account_seq(account, seq)?;
    if let Err(e) = state.delete_account(account) {
        tracing::error!(error = %e, "cannot delete an account");
        return Err(Problem::internal());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn json_len<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |v| v.len())
}
