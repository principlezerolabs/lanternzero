//! `lz-relay`: a small OHTTP relay (RFC 9458) for Lantern Zero gateways,
//! for third parties to run. Design and rules: `relay/DESIGN.md`.
//!
//! - `POST /<gateway origin>` forwards an encapsulated request to the
//!   gateway's `/.well-known/ohttp-gateway`.
//! - `GET /<gateway origin>` returns the gateway's key configuration,
//!   fetched from the relay's own address and cached (spec §3.2).
//! - `OPTIONS` answers CORS preflights; `GET /health` answers 200.
//!
//! It forwards only to gateways that declare one of its purposes, forwards
//! only `Content-Type`, and logs nothing about clients: no addresses, no
//! per-request lines, and no gateway origins.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod config;
pub mod gateways;
pub mod limits;
pub mod origin;
pub mod ssrf;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use http::header::{self, HeaderValue};
use http::{HeaderMap, Method, StatusCode};
use lz_proto::padding::{REQUEST_SIZE, RESPONSE_SIZE};

use crate::config::Config;
use crate::gateways::{Admission, Gateways};
use crate::limits::{ClientKey, InFlight, Window};
use crate::origin::{Origin, Scheme};

/// Largest encapsulated request: the fixed inner size plus room for the
/// HPKE header and tag (the gateway's own cap, `server/src/gateway.rs`).
pub const MAX_REQUEST: usize = REQUEST_SIZE + 1024;
/// Largest encapsulated response, likewise.
pub const MAX_RESPONSE: usize = RESPONSE_SIZE + 1024;

const OHTTP_REQUEST: &str = "message/ohttp-req";
const OHTTP_RESPONSE: &str = "message/ohttp-res";

/// The relay's time limits. Fixed in production ([`Timing::default`]);
/// tests shorten them.
#[derive(Debug, Clone)]
pub struct Timing {
    /// For the gateway to start its response. Spec §1.1 requires at least
    /// 35 seconds, because long-polls are held for up to 30.
    pub first_byte: Duration,
    /// For the whole forwarded exchange.
    pub total: Duration,
    /// For the client to send its request body, so a slow client can't
    /// hold a slot.
    pub body_read: Duration,
    /// For opt-in checks and key-configuration fetches.
    pub probe_timeout: Duration,
    /// How long a gateway's opt-in is remembered.
    pub opted_in: Duration,
    /// How long a gateway that doesn't opt in is remembered.
    pub opted_out: Duration,
    /// How long a gateway that couldn't be asked is remembered.
    pub unreachable: Duration,
    /// Longest a key configuration is cached (less if the gateway says so).
    pub key_max_age: Duration,
    /// Shortest time between refetches caused by `ohttp-key` answers.
    pub key_refetch_after: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            first_byte: Duration::from_secs(40),
            total: Duration::from_secs(60),
            body_read: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(10),
            opted_in: Duration::from_secs(24 * 3600),
            opted_out: Duration::from_secs(3600),
            unreachable: Duration::from_secs(60),
            key_max_age: Duration::from_secs(3600),
            key_refetch_after: Duration::from_secs(60),
        }
    }
}

/// Monotonic time that tests can move forward.
#[derive(Debug, Clone)]
pub struct Clock {
    start: Instant,
    offset: Arc<Mutex<Duration>>,
}

impl Default for Clock {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            offset: Arc::default(),
        }
    }
}

impl Clock {
    pub fn now(&self) -> Instant {
        Instant::now() + *self.offset.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Seconds since the relay started, for rate-limit windows.
    pub fn secs(&self) -> u64 {
        self.now().saturating_duration_since(self.start).as_secs()
    }

    /// Moves the clock forward (tests).
    pub fn advance(&self, by: Duration) {
        *self.offset.lock().unwrap_or_else(|e| e.into_inner()) += by;
    }
}

/// Totals since they were last logged: across all gateways, never per
/// gateway or per client.
#[derive(Debug, Default)]
pub struct Totals {
    pub forwarded: AtomicU64,
    pub key_configs: AtomicU64,
    pub refused: AtomicU64,
    pub limited: AtomicU64,
    pub failed: AtomicU64,
}

impl Totals {
    fn add(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Takes the totals, starting the next period at zero.
    pub fn take(&self) -> [u64; 5] {
        [
            &self.forwarded,
            &self.key_configs,
            &self.refused,
            &self.limited,
            &self.failed,
        ]
        .map(|c| c.swap(0, Ordering::Relaxed))
    }
}

#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub timing: Timing,
    pub clock: Clock,
    pub http: reqwest::Client,
    pub gateways: Gateways,
    pub totals: Totals,
    per_minute: Window,
    in_flight: InFlight,
}

impl AppState {
    pub fn new(config: Config) -> Result<Arc<Self>, reqwest::Error> {
        Self::with_timing(config, Timing::default())
    }

    pub fn with_timing(config: Config, timing: Timing) -> Result<Arc<Self>, reqwest::Error> {
        let allow_private = config.allow_private_targets;
        let http = reqwest::Client::builder()
            .dns_resolver(ssrf::SafeResolver { allow_private })
            // A redirect would send the client's request somewhere the
            // opt-in check never looked.
            .redirect(reqwest::redirect::Policy::none())
            // A proxy from the environment would connect for us, around
            // the resolver's address check.
            .no_proxy()
            .https_only(!allow_private)
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        Ok(Arc::new(Self {
            per_minute: Window::new(config.limits.per_minute, 60),
            in_flight: InFlight::new(config.limits.concurrent),
            config,
            timing,
            clock: Clock::default(),
            http,
            gateways: Gateways::default(),
            totals: Totals::default(),
        }))
    }

    /// The client's address, for rate limits only: the peer, or the last
    /// `X-Forwarded-For` entry when the peer is a trusted proxy.
    fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.config.trusted_proxies.contains(&peer) {
            return peer;
        }
        headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .next_back()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(peer)
    }

    /// The checks that need no network: lists, port, literal addresses.
    fn allowed_target(&self, origin: &Origin) -> bool {
        let g = &self.config.gateways;
        let host = origin.host();
        if g.deny.iter().any(|h| h == host) {
            return false;
        }
        if !g.allow.is_empty() && !g.allow.iter().any(|h| h == host) {
            return false;
        }
        if self.config.allow_private_targets {
            return true;
        }
        let port_ok = origin.scheme() == Scheme::Https
            && (origin.port() == 443 || g.ports.contains(&origin.port()));
        port_ok && origin.ip().is_none_or(ssrf::is_public)
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .fallback(relay)
        .with_state(state)
}

/// Serves the router with the peer address each handler needs.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

fn reply(status: StatusCode) -> Response {
    (status, cors()).into_response()
}

fn cors() -> [(header::HeaderName, HeaderValue); 1] {
    [(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    )]
}

fn preflight() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            (
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("*"),
            ),
            (
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, OPTIONS"),
            ),
            (
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("content-type"),
            ),
            (
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("86400"),
            ),
        ],
    )
        .into_response()
}

async fn relay(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let method = req.method().clone();
    if method == Method::OPTIONS {
        return preflight();
    }
    if method != Method::GET && method != Method::POST {
        return reply(StatusCode::METHOD_NOT_ALLOWED);
    }

    let key = ClientKey::of(s.client_ip(peer.ip(), req.headers()));
    if let Err(retry) = s.per_minute.hit(key, s.clock.secs()) {
        Totals::add(&s.totals.limited);
        let mut r = reply(StatusCode::TOO_MANY_REQUESTS);
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(retry));
        return r;
    }
    let Some(_slot) = s.in_flight.acquire(key) else {
        Totals::add(&s.totals.limited);
        return reply(StatusCode::TOO_MANY_REQUESTS);
    };

    if req.uri().query().is_some() {
        return refuse(&s, StatusCode::BAD_REQUEST);
    }
    let path = req.uri().path();
    let Ok(origin) = Origin::parse(
        path.strip_prefix('/').unwrap_or(path),
        s.config.allow_private_targets,
    ) else {
        return refuse(&s, StatusCode::BAD_REQUEST);
    };

    if method == Method::GET {
        if let Err(r) = admit(&s, &origin).await {
            return r;
        }
        return match s.gateways.key_config(&s, &origin).await {
            Some(bytes) => {
                Totals::add(&s.totals.key_configs);
                (
                    StatusCode::OK,
                    cors(),
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/ohttp-keys"),
                    )],
                    bytes,
                )
                    .into_response()
            }
            None => fail(&s, StatusCode::BAD_GATEWAY),
        };
    }

    // POST: the cheap checks first, before any outbound request.
    let is_ohttp = req
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(OHTTP_REQUEST.as_bytes()));
    if !is_ohttp {
        return refuse(&s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let declared_too_big = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > MAX_REQUEST);
    if declared_too_big {
        return refuse(&s, StatusCode::PAYLOAD_TOO_LARGE);
    }
    let body = tokio::time::timeout(
        s.timing.body_read,
        axum::body::to_bytes(req.into_body(), MAX_REQUEST),
    )
    .await;
    let body = match body {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => return refuse(&s, StatusCode::PAYLOAD_TOO_LARGE),
        Err(_) => return refuse(&s, StatusCode::REQUEST_TIMEOUT),
    };
    if let Err(r) = admit(&s, &origin).await {
        return r;
    }
    forward(&s, &origin, body).await
}

fn refuse(s: &AppState, status: StatusCode) -> Response {
    Totals::add(&s.totals.refused);
    reply(status)
}

fn fail(s: &AppState, status: StatusCode) -> Response {
    Totals::add(&s.totals.failed);
    reply(status)
}

async fn admit(s: &AppState, origin: &Origin) -> Result<(), Response> {
    if !s.allowed_target(origin) {
        return Err(refuse(s, StatusCode::FORBIDDEN));
    }
    match s.gateways.admission(s, origin).await {
        Admission::Allowed => Ok(()),
        Admission::Refused => Err(refuse(s, StatusCode::FORBIDDEN)),
        Admission::Unreachable => Err(fail(s, StatusCode::BAD_GATEWAY)),
    }
}

async fn forward(s: &AppState, origin: &Origin, body: Bytes) -> Response {
    let send = s
        .http
        .post(origin.gateway_url())
        .header(header::CONTENT_TYPE, OHTTP_REQUEST)
        .header(header::ACCEPT, OHTTP_RESPONSE)
        .timeout(s.timing.total)
        .body(body)
        .send();
    let resp = match tokio::time::timeout(s.timing.first_byte, send).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) if e.is_timeout() => return fail(s, StatusCode::GATEWAY_TIMEOUT),
        Ok(Err(_)) => return fail(s, StatusCode::BAD_GATEWAY),
        Err(_) => return fail(s, StatusCode::GATEWAY_TIMEOUT),
    };
    let status = resp.status();
    let content_type = resp.headers().get(header::CONTENT_TYPE).cloned();
    let Ok(body) = read_capped(resp, MAX_RESPONSE).await else {
        return fail(s, StatusCode::BAD_GATEWAY);
    };
    // The gateway can't encrypt this answer, so the relay can read it: the
    // client used a key the gateway no longer has.
    if status == StatusCode::BAD_REQUEST
        && content_type
            .as_ref()
            .is_some_and(|v| v.as_bytes().starts_with(b"application/problem+json"))
        && contains(&body, lz_proto::problem::OHTTP_KEY_TYPE.as_bytes())
    {
        s.gateways.key_rejected(s, origin);
    }
    Totals::add(&s.totals.forwarded);
    let mut r = (status, cors(), body).into_response();
    if let Some(ct) = content_type {
        r.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    r
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[derive(Debug)]
pub(crate) enum ReadError {
    TooLarge,
    Failed,
}

/// Reads a response body, refusing one larger than `cap` rather than
/// truncating it.
pub(crate) async fn read_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> Result<Bytes, ReadError> {
    if resp.content_length().is_some_and(|n| n > cap as u64) {
        return Err(ReadError::TooLarge);
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| ReadError::Failed)? {
        if out.len() + chunk.len() > cap {
            return Err(ReadError::TooLarge);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

/// Logs the totals every `every`, and nothing about any request.
pub async fn log_totals(state: Arc<AppState>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        let [forwarded, key_configs, refused, limited, failed] = state.totals.take();
        tracing::info!(forwarded, key_configs, refused, limited, failed, "totals");
    }
}

/// Turns off core dumps: the rate-limit tables hold client addresses.
/// Returns whether that worked.
#[cfg(unix)]
pub fn disable_core_dumps() -> bool {
    use rustix::process::{Resource, Rlimit, setrlimit};
    let off = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .is_ok();
    #[cfg(target_os = "linux")]
    let off = off
        && rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .is_ok();
    off
}

#[cfg(not(unix))]
pub fn disable_core_dumps() -> bool {
    false
}

/// Crates whose debug logs include URLs (so gateway origins) or headers.
/// Capped at `warn` whatever `RUST_LOG` says.
const NOISY_DEPENDENCIES: &[&str] = &[
    "hyper",
    "hyper_util",
    "h2",
    "reqwest",
    "rustls",
    "tower",
    "tower_http",
    "axum",
];

pub fn log_filter(default: &str) -> tracing_subscriber::EnvFilter {
    let mut filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    for dep in NOISY_DEPENDENCIES {
        if let Ok(d) = format!("{dep}=warn").parse() {
            filter = filter.add_directive(d);
        }
    }
    filter
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(extra: &str) -> Arc<AppState> {
        let config = Config::parse(&format!("listen = \"127.0.0.1:0\"\n{extra}")).unwrap();
        AppState::new(config).unwrap()
    }

    fn origin(s: &str) -> Origin {
        Origin::parse(s, false).unwrap()
    }

    #[test]
    fn production_timing_meets_the_spec() {
        let t = Timing::default();
        assert!(t.first_byte >= Duration::from_secs(35), "spec §1.1");
        assert!(t.total >= t.first_byte);
    }

    #[test]
    fn checks_targets_without_the_network() {
        let s = state("");
        assert!(s.allowed_target(&origin("lz.example.org")));
        assert!(!s.allowed_target(&origin("lz.example.org:8443")), "port");
        assert!(!s.allowed_target(&origin("127.0.0.1")));
        assert!(!s.allowed_target(&origin("[::1]")));
        assert!(!s.allowed_target(&origin("169.254.169.254")));
        assert!(
            !s.allowed_target(&origin("192.0.2.1")),
            "documentation range"
        );
        assert!(s.allowed_target(&origin("1.1.1.1")));

        let s = state("[gateways]\nports = [8443]\ndeny = [\"bad.example\"]");
        assert!(s.allowed_target(&origin("lz.example.org:8443")));
        assert!(!s.allowed_target(&origin("BAD.example")));

        let s = state("[gateways]\nallow = [\"lz.example.org\"]");
        assert!(s.allowed_target(&origin("lz.example.org")));
        assert!(!s.allowed_target(&origin("other.example.org")));
    }

    #[test]
    fn trusts_forwarded_for_only_from_listed_proxies() {
        let s = state("trusted_proxies = [\"10.0.0.2\"]");
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            "198.51.100.1, 203.0.113.7".parse().unwrap(),
        );
        assert_eq!(
            s.client_ip("10.0.0.2".parse().unwrap(), &h),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            s.client_ip("10.0.0.3".parse().unwrap(), &h),
            "10.0.0.3".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            s.client_ip("10.0.0.2".parse().unwrap(), &HeaderMap::new()),
            "10.0.0.2".parse::<IpAddr>().unwrap()
        );
    }
}
