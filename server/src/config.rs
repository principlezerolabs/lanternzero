//! Server configuration, read from a TOML file.

use std::net::SocketAddr;
use std::path::PathBuf;

use lz_proto::lease::Network;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on, for example `0.0.0.0:8080`. TLS is terminated in
    /// front of the server.
    pub listen: SocketAddr,
    /// The host in this server's connection URLs, for example
    /// `lz.example.org`.
    pub public_host: String,
    /// Base path of the API, for example `""` or `"/lz"`. No trailing slash.
    #[serde(default)]
    pub base_path: String,
    pub network: Network,
    /// Holds the server's own keys and account list. Never user data from
    /// viewing keys (invariant 1).
    pub data_dir: PathBuf,
    /// VAPID `sub` claim: a `mailto:` or `https:` contact for push gateways.
    pub vapid_contact: String,
    /// Serve the API directly, without OHTTP. Only for a self-hosted server
    /// reached as a Tor onion service (spec §3.1).
    #[serde(default)]
    pub direct_api: bool,
    /// Where chain data comes from. Without it, `tip` stays 0 and nothing is
    /// scanned; only useful for testing push delivery.
    #[serde(default)]
    pub chain: Option<ChainConfig>,
    #[serde(default)]
    pub push: PushConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// The Zaino or lightwalletd server to follow.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    /// Its gRPC URL, for example `http://127.0.0.1:8137`. Use `https://` for
    /// anything outside the host or private network.
    pub lightwalletd: String,
    /// Seconds between tip checks, 1 to 60. Blocks come every 75 s, and every
    /// 25 s after NU7.
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,
}

fn default_poll_secs() -> u64 {
    5
}

/// Request rate limits (spec §3.5). A foreground wallet long-polls about
/// every 25 s, so the defaults leave plenty of headroom.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_account_per_minute")]
    pub account_per_minute: u32,
    #[serde(default = "default_device_per_minute")]
    pub device_per_minute: u32,
}

fn default_account_per_minute() -> u32 {
    120
}

fn default_device_per_minute() -> u32 {
    30
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            account_per_minute: default_account_per_minute(),
            device_per_minute: default_device_per_minute(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushConfig {
    /// Allow push endpoints on private, loopback, or link-local addresses.
    /// Only for self-hosting and tests (spec §4.1).
    #[serde(default)]
    pub allow_private_targets: bool,
    /// If not empty, accept only push endpoints on these hosts.
    #[serde(default)]
    pub gateway_allowlist: Vec<String>,
    #[serde(default = "default_max_devices")]
    pub max_devices_per_account: usize,
}

fn default_max_devices() -> usize {
    10
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            allow_private_targets: false,
            gateway_allowlist: Vec::new(),
            max_devices_per_account: default_max_devices(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("base_path must be empty or start with `/`, with no trailing `/`")]
    BasePath,
    #[error("direct_api is only allowed for .onion hosts")]
    DirectApi,
    #[error("chain.poll_secs must be between 1 and 60")]
    PollSecs,
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let bp = &self.base_path;
        if !bp.is_empty() && (!bp.starts_with('/') || bp.ends_with('/')) {
            return Err(ConfigError::BasePath);
        }
        if self.direct_api && !self.public_host.ends_with(".onion") {
            return Err(ConfigError::DirectApi);
        }
        if let Some(chain) = &self.chain
            && !(1..=60).contains(&chain.poll_secs)
        {
            return Err(ConfigError::PollSecs);
        }
        Ok(())
    }
}
