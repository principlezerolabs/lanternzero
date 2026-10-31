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
    DeviceRegistered, DeviceRegistration, Info, LeaseStatus, SeqOnly, WakeRequest, WakeResponse,
};
use lz_proto::token::TokenHash;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::AppState;
use crate::ssrf;
use crate::store::{AccountId, StoreError};

/// Largest clock difference accepted in an inner request's `Date` (spec §3.4).
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// Builds the API router. Paths are relative to the configured base path.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v0/info", post(info))
        .route("/v0/devices", post(register_device))
        .route("/v0/devices/{device_id}", delete(delete_device))
        .route("/v0/wake", post(wake))
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
    fn bad_request(title: &'static str) -> Self {
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
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(Problem::unauthorized)?;
    let (scheme, text) = value.split_once(' ').ok_or_else(Problem::unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Problem::unauthorized());
    }
    let account = state
        .store
        .authenticate(&TokenHash::of_text(text.trim()))
        .ok_or_else(Problem::unauthorized)?;
    let key: String = account.iter().map(|b| format!("{b:02x}")).collect();
    state
        .account_limiter
        .check(&key, SystemTime::now())
        .map_err(Problem::rate_limited)?;
    Ok(account)
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
            finality_depth: 10,
            vapid_public_key: state.vapid.public_b64.clone(),
            ohttp_key_config_sha256: state.ohttp_keys_sha256.clone(),
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
    let reg: DeviceRegistration = parse(&body)?;
    // Registration names no device, so it uses the account's window
    // (spec §3.4).
    state.store.accept_account_seq(account, reg.seq)?;
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
    let req: WakeRequest = parse(&body)?;
    limit_device(&state, &req.device_id)?;
    state
        .store
        .accept_device_seq(account, &req.device_id, req.seq)?;
    if let Some(lease) = &req.lease {
        lease
            .validate(state.config.network)
            .map_err(|_| Problem::bad_request("invalid lease"))?;
        // The scanner doesn't exist yet. `req` (and the keys in it) is
        // dropped, and zeroed, on return.
        return Err(Problem::new(
            StatusCode::NOT_IMPLEMENTED,
            "scanning-unavailable",
            "this server does not offer scanning yet",
        ));
    }
    Ok(json(
        StatusCode::OK,
        &WakeResponse {
            tip: state.chain.tip(),
            lease: LeaseStatus {
                active: false,
                expires_at: None,
            },
            hints: vec![],
            events: vec![],
            cursor: "0".to_owned(),
            next: None,
        },
    ))
}
