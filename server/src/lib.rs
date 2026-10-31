//! Lantern Zero server (spec `spec/v0.md`).
//!
//! Layers, outside in:
//! - [`gateway`]: the OHTTP gateway at the origin root. It decapsulates
//!   requests, checks their fixed size, and hands the inner Binary HTTP
//!   request to the API router.
//! - [`api`]: the `/v0/` endpoints. Reachable only through the gateway,
//!   except on a self-hosted onion service with `direct_api`.
//! - [`push`]: the 30-minute wake-up scheduler.
//!
//! Nothing in this crate logs request bodies, headers, tokens, or push
//! endpoints (invariants 1 and 6).

pub mod api;
pub mod config;
pub mod gateway;
pub mod keys;
pub mod limits;
pub mod push;
pub mod ssrf;
pub mod store;
pub mod webpush;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

/// Shared server state.
pub struct AppState {
    pub config: config::Config,
    pub store: store::Store,
    pub ohttp: ohttp::Server,
    /// The key configuration list, as served (`application/ohttp-keys`).
    pub ohttp_keys: Vec<u8>,
    /// Hex SHA-256 of `ohttp_keys`, published in `info` (spec §3.2).
    pub ohttp_keys_sha256: String,
    pub vapid: webpush::Vapid,
    pub http: reqwest::Client,
    /// Best known chain tip. Set by the chain follower once it exists.
    pub tip: AtomicU64,
    pub account_limiter: limits::RateLimiter,
    pub device_limiter: limits::RateLimiter,
    pub push_backoff: limits::PushBackoff,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Keys(#[from] keys::KeyError),
    #[error("store: {0}")]
    Store(#[from] std::io::Error),
    #[error("OHTTP: {0}")]
    Ohttp(#[from] ohttp::Error),
    #[error("HTTP client: {0}")]
    Http(#[from] reqwest::Error),
}

impl AppState {
    pub fn new(config: config::Config) -> Result<Arc<Self>, StartError> {
        use sha2_shim::sha256_hex;

        keys::create_private_dir(&config.data_dir)?;
        let key_config = keys::ohttp_key_config(&config.data_dir)?;
        let ohttp_keys = ohttp::KeyConfig::encode_list(&[&key_config])?;
        let ohttp_keys_sha256 = sha256_hex(&ohttp_keys);
        let ohttp = ohttp::Server::new(key_config)?;
        let vapid = keys::vapid_key(&config.data_dir)?;
        let allow_private = config.push.allow_private_targets;
        let http = reqwest::Client::builder()
            .dns_resolver(ssrf::SafeResolver { allow_private })
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(!allow_private)
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        let store = store::Store::open(&config.data_dir)?;
        let account_limiter = limits::RateLimiter::new(config.limits.account_per_minute);
        let device_limiter = limits::RateLimiter::new(config.limits.device_per_minute);
        Ok(Arc::new(Self {
            config,
            store,
            ohttp,
            ohttp_keys,
            ohttp_keys_sha256,
            vapid,
            http,
            tip: AtomicU64::new(0),
            account_limiter,
            device_limiter,
            push_backoff: limits::PushBackoff::default(),
        }))
    }
}

/// Crates whose debug and trace logs include hosts, URLs, or headers.
/// They are capped at `warn` whatever `RUST_LOG` says (invariants 1 and 6).
const NOISY_DEPENDENCIES: &[&str] = &[
    "hyper",
    "hyper_util",
    "h2",
    "reqwest",
    "rustls",
    "tower_http",
];

/// The log filter for the server: `RUST_LOG` (or `default`), with
/// [`NOISY_DEPENDENCIES`] always capped at `warn`.
pub fn log_filter(default: &str) -> tracing_subscriber::EnvFilter {
    let mut filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    for dep in NOISY_DEPENDENCIES {
        filter = filter.add_directive(format!("{dep}=warn").parse().expect("valid directive"));
    }
    filter
}

mod sha2_shim {
    use sha2::{Digest, Sha256};
    pub fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
