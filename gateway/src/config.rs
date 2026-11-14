//! Gateway configuration, read from a TOML file.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on. TLS is terminated in front of the gateway.
    pub listen: SocketAddr,
    /// Proxies in front of the gateway whose `X-Forwarded-For` names the
    /// client. Used for the per-address limits on the wallet API only, and
    /// never logged.
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
    /// This gateway's public origin, for example `https://push.example.app`.
    /// Endpoints are built on it, and VAPID tokens must name it as `aud`.
    pub public_origin: String,
    /// Holds the endpoint-sealing keys (created on first start) and the
    /// revocation list.
    pub data_dir: PathBuf,
    /// How long a new subscription lasts. Wallets renew before it ends
    /// (spec §4.1); a revocation is kept this long. At most 365.
    #[serde(default = "default_lifetime")]
    pub endpoint_lifetime_days: u64,
    /// The visible title of payment alerts. Apple and Google relay it, so it
    /// must say nothing about the payment (spec §5.4).
    #[serde(default = "default_alert_title")]
    pub alert_title: String,
    pub apns: Option<ApnsConfig>,
    pub fcm: Option<FcmConfig>,
    #[serde(default)]
    pub limits: LimitsConfig,
}

fn default_lifetime() -> u64 {
    90
}

fn default_alert_title() -> String {
    "New activity".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsConfig {
    /// Apple Developer team id (the JWT `iss`).
    pub team_id: String,
    /// Key id of the APNs auth key (the JWT `kid`).
    pub key_id: String,
    /// The `.p8` auth key file. Keep it outside the repository.
    pub key_path: PathBuf,
    /// The app's bundle id (`apns-topic`).
    pub topic: String,
    /// Send `apns` subscriptions to the development APNs environment.
    #[serde(default)]
    pub sandbox: bool,
    /// Also accept `apns-sandbox` subscriptions, from development builds
    /// (Xcode), and send them to the development environment, so one
    /// gateway serves both kinds of build. The same auth key works in
    /// both. Leave it off for a gateway that only release builds use.
    #[serde(default)]
    pub allow_sandbox: bool,
    /// A separate key for `apns-sandbox`, such as an Apple key limited to
    /// this app and the development environment (Apple scopes a key to
    /// one app only if it covers one environment). Without it, the main
    /// key is used for both. Set both or neither.
    #[serde(default)]
    pub sandbox_key_id: Option<String>,
    #[serde(default)]
    pub sandbox_key_path: Option<PathBuf>,
    /// Overrides the APNs host, for tests.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Overrides the development APNs host for `apns-sandbox`, for tests.
    #[serde(default)]
    pub sandbox_base_url: Option<String>,
}

impl ApnsConfig {
    pub fn base_url(&self) -> String {
        match (&self.base_url, self.sandbox) {
            (Some(u), _) => u.trim_end_matches('/').to_owned(),
            (None, true) => "https://api.sandbox.push.apple.com".into(),
            (None, false) => "https://api.push.apple.com".into(),
        }
    }

    /// Where `apns-sandbox` subscriptions go, when allowed.
    pub fn sandbox_url(&self) -> Option<String> {
        self.allow_sandbox.then(|| match &self.sandbox_base_url {
            Some(u) => u.trim_end_matches('/').to_owned(),
            None => "https://api.sandbox.push.apple.com".into(),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FcmConfig {
    pub project_id: String,
    /// A Google service-account key file with the Firebase Messaging role.
    #[serde(default)]
    pub credentials_path: Option<PathBuf>,
    /// A fixed access token instead of a service account: tests only.
    #[serde(default)]
    pub static_access_token: Option<String>,
    #[serde(default = "default_fcm_base")]
    pub base_url: String,
}

fn default_fcm_base() -> String {
    "https://fcm.googleapis.com".into()
}

/// Spec §5.3: per-device budgets, background and alerts apart, plus an
/// overall per-server-key budget.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Background wakes per device per hour. Apple advises 2–3; the
    /// protocol's schedule uses 2.
    #[serde(default = "default_background")]
    pub background_per_hour: u32,
    /// Visible payment alerts per device per hour.
    #[serde(default = "default_alert")]
    pub alerts_per_hour: u32,
    /// All pushes signed by one server key, per minute.
    #[serde(default = "default_per_server")]
    pub per_server_per_minute: u32,
    /// Subscriptions created per client address (an IPv4 address or an
    /// IPv6 /64) per hour. A wallet subscribes once per server and renews
    /// every few months, but carrier NAT puts many phones on one IPv4
    /// address.
    #[serde(default = "default_per_address")]
    pub subscriptions_per_address_per_hour: u32,
    /// Revocations per client address per hour. They fill the revocation
    /// list, which holds at most 1,000,000.
    #[serde(default = "default_per_address")]
    pub revocations_per_address_per_hour: u32,
}

fn default_background() -> u32 {
    3
}
fn default_alert() -> u32 {
    20
}
fn default_per_server() -> u32 {
    100_000
}
fn default_per_address() -> u32 {
    60
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            background_per_hour: default_background(),
            alerts_per_hour: default_alert(),
            per_server_per_minute: default_per_server(),
            subscriptions_per_address_per_hour: default_per_address(),
            revocations_per_address_per_hour: default_per_address(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("public_origin must be an origin like https://push.example.app (no path)")]
    Origin,
    #[error("configure at least one of [apns] and [fcm]")]
    NoPlatform,
    #[error("endpoint_lifetime_days must be 1 to 365")]
    Lifetime,
    #[error("[limits] per-address limits must be at least 1")]
    Limits,
    #[error("[apns] sandbox_key_id and sandbox_key_path go together, with allow_sandbox")]
    SandboxKey,
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(&std::fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let uri: http::Uri = self
            .public_origin
            .parse()
            .map_err(|_| ConfigError::Origin)?;
        let origin_only = uri.scheme().is_some()
            && uri.host().is_some()
            && uri
                .path_and_query()
                .is_none_or(|p| p.as_str() == "/" || p.as_str().is_empty())
            && !self.public_origin.ends_with('/');
        if !origin_only {
            return Err(ConfigError::Origin);
        }
        if self.apns.is_none() && self.fcm.is_none() {
            return Err(ConfigError::NoPlatform);
        }
        if !(1..=crate::keys::MAX_LIFETIME_DAYS).contains(&self.endpoint_lifetime_days) {
            return Err(ConfigError::Lifetime);
        }
        if let Some(a) = &self.apns
            && (a.sandbox_key_id.is_some() != a.sandbox_key_path.is_some()
                || (a.sandbox_key_id.is_some() && !a.allow_sandbox))
        {
            return Err(ConfigError::SandboxKey);
        }
        if self.limits.subscriptions_per_address_per_hour == 0
            || self.limits.revocations_per_address_per_hour == 0
        {
            return Err(ConfigError::Limits);
        }
        Ok(())
    }
}
