//! Gateway configuration, read from a TOML file.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on. TLS is terminated in front of the gateway.
    pub listen: SocketAddr,
    /// This gateway's public origin, for example `https://push.example.app`.
    /// Endpoints are built on it, and VAPID tokens must name it as `aud`.
    pub public_origin: String,
    /// Holds the gateway's endpoint-sealing key, created on first start.
    pub data_dir: PathBuf,
    /// The visible title of payment alerts. Apple and Google relay it, so it
    /// must say nothing about the payment (spec §5.4).
    #[serde(default = "default_alert_title")]
    pub alert_title: String,
    pub apns: Option<ApnsConfig>,
    pub fcm: Option<FcmConfig>,
    #[serde(default)]
    pub limits: LimitsConfig,
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
    /// Use the development APNs environment.
    #[serde(default)]
    pub sandbox: bool,
    /// Overrides the APNs host, for tests.
    #[serde(default)]
    pub base_url: Option<String>,
}

impl ApnsConfig {
    pub fn base_url(&self) -> String {
        match (&self.base_url, self.sandbox) {
            (Some(u), _) => u.trim_end_matches('/').to_owned(),
            (None, true) => "https://api.sandbox.push.apple.com".into(),
            (None, false) => "https://api.push.apple.com".into(),
        }
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

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            background_per_hour: default_background(),
            alerts_per_hour: default_alert(),
            per_server_per_minute: default_per_server(),
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
        Ok(())
    }
}
