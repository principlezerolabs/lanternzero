//! Lantern Zero server (spec `spec/v0.md`).
//!
//! Layers, outside in:
//! - [`gateway`]: the OHTTP gateway at the origin root. It decapsulates
//!   requests, checks their fixed size, and hands the inner Binary HTTP
//!   request to the API router.
//! - [`api`]: the `/v0/` endpoints. Reachable only through the gateway,
//!   except on a self-hosted onion service with `direct_api`.
//! - [`push`]: the 30-minute wake-up scheduler.
//! - [`chain`]: the chain follower, which keeps `tip` current and announces
//!   blocks.
//! - [`issuer`]: the local issuer interface on a Unix socket in `data_dir`
//!   (`server/ISSUER.md`). Never reachable through the gateway.
//!
//! Nothing in this crate logs request bodies, headers, tokens, or push
//! endpoints (invariants 1 and 6).

pub mod api;
pub mod chain;
pub mod clock;
pub mod config;
pub mod doctor;
pub mod files;
pub mod gateway;
pub mod hardening;
pub mod init;
pub mod issuer;
pub mod keys;
pub mod limits;
pub mod mempool;
pub mod ohttp_keys;
pub mod push;
pub mod scanner;
pub mod set_chain;
pub mod ssrf;
pub mod store;
pub mod tasks;
pub mod viewkey;
pub mod webhook;
pub mod webpush;

use std::future::Future;
use std::sync::Arc;

use clock::unix_now;

/// Shared server state.
pub struct AppState {
    pub config: config::Config,
    pub store: store::Store,
    /// The current OHTTP key, and retired ones during their overlap.
    pub ohttp: ohttp_keys::Gateway,
    /// The current VAPID key and retired ones still bound to devices.
    pub vapid: keys::VapidKeys,
    pub http: reqwest::Client,
    /// Best known tip and block announcements, fed by [`chain::run`].
    pub chain: Arc<chain::Chain>,
    /// The chain source from `[chain]`, if configured. Also used for
    /// backfills.
    pub chain_source: Option<chain::Lightwalletd>,
    /// Leases, events, and hints. Memory only.
    pub scanner: scanner::Scanner,
    pub account_limiter: limits::RateLimiter<store::AccountId>,
    pub device_limiter: limits::RateLimiter,
    pub push_backoff: limits::PushBackoff,
    /// Instant payment pushes per account (spec §5.2).
    pub payment_push_limiter: limits::RateLimiter<store::AccountId>,
    /// The time, for everything the server does (see [`clock`]).
    pub clock: clock::Clock,
    /// Short-lived background work (backfills, payment pushes, webhook
    /// deliveries), so tests can wait for it with [`AppState::settle`].
    pub tasks: tasks::Tasks,
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
    #[error(transparent)]
    Chain(#[from] chain::ChainError),
}

impl AppState {
    pub fn new(config: config::Config) -> Result<Arc<Self>, StartError> {
        files::create_private_dir(&config.data_dir)?;
        let clock = clock::Clock::default();
        let now = clock.unix_now();
        let pruned = ohttp_keys::prune(&config.data_dir, now)?;
        if pruned > 0 {
            tracing::info!(pruned, "deleted OHTTP keys past their overlap");
        }
        let ohttp = ohttp_keys::Gateway::new(&ohttp_keys::load(&config.data_dir, now)?)?;
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
        store.configure(
            config.accounts.idle_account_days > 0,
            config.accounts.issuer_socket,
        );
        let vapid = load_vapid(&config.data_dir, &store)?;
        let scanner = scanner::Scanner::new(keys::event_id_secret(&config.data_dir)?);
        let chain_source = match &config.chain {
            Some(c) => Some(chain::Lightwalletd::new(&c.lightwalletd)?),
            None => None,
        };
        let account_limiter = limits::RateLimiter::new(config.limits.account_per_minute);
        let device_limiter = limits::RateLimiter::new(config.limits.device_per_minute);
        Ok(Arc::new(Self {
            config,
            store,
            ohttp,
            vapid,
            http,
            chain: Arc::default(),
            chain_source,
            scanner,
            account_limiter,
            device_limiter,
            push_backoff: limits::PushBackoff::default(),
            payment_push_limiter: limits::RateLimiter::new(scanner::PAYMENT_PUSHES_PER_MINUTE),
            clock,
            tasks: tasks::Tasks::default(),
        }))
    }
}

impl AppState {
    /// Runs short-lived background work on [`AppState::tasks`].
    pub fn spawn<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.tasks.spawn(task);
    }

    /// Waits until no background task started with [`AppState::spawn`] is
    /// running. For tests, which then check that something did not happen.
    pub async fn settle(&self) {
        self.tasks.settle().await;
    }

    /// Writes the store's state if it changed, on a blocking thread, so
    /// writing `state.json` doesn't hold up async tasks.
    pub async fn flush_store(self: &Arc<Self>) {
        let state = self.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || state.store.flush_if_dirty()).await {
            tracing::error!(error = %e, "state flush task failed");
        }
    }

    /// Deletes an account as `DELETE /v0/account` does (spec §4.6): its
    /// token hashes, devices, and replay window on disk, then its lease,
    /// events, and hints in memory. Used by the API, the idle sweep, and
    /// the issuer.
    pub fn delete_account(&self, account: store::AccountId) -> std::io::Result<()> {
        let now = self.clock.now();
        self.store
            .delete_account_at(account, clock::unix_secs(now))?;
        self.scanner.end_lease(account, now);
        Ok(())
    }

    /// One pass of account housekeeping: deletes idle accounts (spec §4.6)
    /// and forgets expired issuer records. Returns how many it deleted.
    pub fn sweep_accounts(&self, now_unix: u64) -> usize {
        let idle = self
            .store
            .sweep(self.config.accounts.idle_account_days, now_unix);
        let mut deleted = 0;
        for account in idle {
            match self.delete_account(account) {
                Ok(()) => deleted += 1,
                Err(e) => tracing::error!(error = %e, "cannot delete an idle account"),
            }
        }
        deleted
    }
}

/// Runs [`AppState::sweep_accounts`] at start and then every hour. The
/// store counts whole UTC days, so sweeping more often than daily deletes
/// nothing sooner.
pub async fn account_sweep_loop(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let deleted = state.sweep_accounts(state.clock.unix_now());
        if deleted > 0 {
            tracing::info!(deleted, "deleted idle accounts");
        }
    }
}

/// How often the server re-reads its OHTTP keys from disk.
pub const OHTTP_KEY_RELOAD: std::time::Duration = std::time::Duration::from_secs(300);

/// Every [`OHTTP_KEY_RELOAD`]: switches to a key `rotate-ohttp` made, and
/// forgets retired keys past their overlap, in memory and on disk (spec
/// §3.2), so neither waits for a restart.
pub async fn ohttp_key_sweep_loop(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(OHTTP_KEY_RELOAD);
    tick.tick().await; // AppState::new just loaded them.
    loop {
        tick.tick().await;
        let now = state.clock.unix_now();
        let dropped = state.ohttp.drop_expired(now);
        match ohttp_keys::prune(&state.config.data_dir, now) {
            Ok(pruned) if dropped + pruned > 0 => {
                tracing::info!(dropped, pruned, "retired OHTTP keys past their overlap");
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "cannot delete retired OHTTP keys"),
        }
        match state.ohttp.reload(&state.config.data_dir, now) {
            Ok(Some(key_id)) => tracing::info!(key_id, "serving the OHTTP key on disk"),
            Ok(None) => {}
            Err(e) => tracing::error!(error = %e, "cannot reload the OHTTP keys"),
        }
    }
}

/// `lz-server <config> rotate-ohttp [--drop-old]` (spec §3.2): a running
/// server serves the new key within [`OHTTP_KEY_RELOAD`], and the old one
/// is accepted for 7 days from now (not at all with `drop_old`). Returns
/// the new key id.
pub fn rotate_ohttp(dir: &std::path::Path, drop_old: bool) -> Result<u8, StartError> {
    Ok(ohttp_keys::rotate(dir, unix_now(), drop_old)?)
}

/// Loads the VAPID keys and reconciles them with the devices (spec §5.3):
/// records from before rotation are bound to the current key, devices bound
/// to a dropped key are removed (they can't be signed for), and retired
/// keys no device uses any more are deleted.
fn load_vapid(dir: &std::path::Path, store: &store::Store) -> Result<keys::VapidKeys, StartError> {
    let vapid = keys::vapid_keys(dir)?;
    store.pin_vapid(&vapid.current().public_b64);
    let dropped =
        store.retain_devices(|d| d.vapid.as_deref().is_some_and(|k| vapid.get(k).is_some()));
    if dropped > 0 {
        tracing::warn!(dropped, "removed devices bound to a dropped VAPID key");
    }
    let devices = store.devices();
    let pruned = keys::prune_vapid(dir, &|k| {
        devices.iter().any(|(_, d)| d.vapid.as_deref() == Some(k))
    })?;
    if pruned > 0 {
        tracing::info!(pruned, "deleted retired VAPID keys no device uses");
        return Ok(keys::vapid_keys(dir)?);
    }
    Ok(vapid)
}

/// `lz-server <config> rotate-vapid [--drop-old]`: binds existing devices
/// to the current key, then retires it (spec §5.3). The server must be
/// stopped: this takes the data directory's lock. Returns the new public
/// key.
pub fn rotate_vapid(dir: &std::path::Path, drop_old: bool) -> Result<String, StartError> {
    let store = store::Store::open(dir)?;
    store.pin_vapid(&keys::vapid_key(dir)?.public_b64);
    Ok(keys::rotate_vapid(dir, drop_old)?)
}

/// Crates whose debug and trace logs include hosts, URLs, or headers, or,
/// for `ohttp`, derived key material and request bytes. They are capped at
/// `warn` whatever `RUST_LOG` says (invariants 1 and 6).
const NOISY_DEPENDENCIES: &[&str] = &[
    "ohttp",
    "bhttp",
    "hyper",
    "hyper_util",
    "h2",
    "reqwest",
    "rustls",
    "tower_http",
    "tonic",
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
