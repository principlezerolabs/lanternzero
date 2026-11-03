//! Relay configuration, read from a TOML file.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on. TLS is terminated in front of the relay.
    pub listen: SocketAddr,
    /// Proxies in front of the relay whose `X-Forwarded-For` names the
    /// client. It is used for rate limits only, and never logged or
    /// forwarded.
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
    /// Purposes a gateway must declare in `?allowed_purposes` before the
    /// relay forwards to it (RFC 9540; the opt-in payjoin-mailroom uses).
    #[serde(default = "default_purposes")]
    pub purposes: Vec<String>,
    #[serde(default)]
    pub gateways: GatewaysConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Tests only: also connect to private and loopback addresses, and to
    /// plain `http` gateways.
    #[serde(default)]
    pub allow_private_targets: bool,
}

fn default_purposes() -> Vec<String> {
    vec![lz_proto::OHTTP_PURPOSE.to_owned()]
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewaysConfig {
    /// If set, forward only to these hosts (which must also opt in).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Never forward to these hosts.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Ports besides 443 that gateways may use.
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Requests per minute from one client address (an IPv4 address or an
    /// IPv6 /64).
    #[serde(default = "default_per_minute")]
    pub per_minute: u32,
    /// Requests in flight at once from one client address. Long-polls are
    /// held for up to 30 seconds, so a wallet may have one or two open.
    #[serde(default = "default_concurrent")]
    pub concurrent: u32,
}

fn default_per_minute() -> u32 {
    60
}

fn default_concurrent() -> u32 {
    10
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            per_minute: default_per_minute(),
            concurrent: default_concurrent(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read the config file: {0}")]
    Read(#[from] std::io::Error),
    #[error("bad config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("bad config: {0}")]
    Invalid(&'static str),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut config: Config = toml::from_str(text)?;
        config.check()?;
        Ok(config)
    }

    /// Checks the values, and writes the host lists in the canonical form
    /// that gateway origins are compared in.
    pub fn check(&mut self) -> Result<(), ConfigError> {
        if self.purposes.is_empty() {
            return Err(ConfigError::Invalid("`purposes` must not be empty"));
        }
        if self
            .purposes
            .iter()
            .any(|p| p.is_empty() || p.len() > usize::from(u8::MAX))
        {
            return Err(ConfigError::Invalid(
                "each purpose must be 1 to 255 bytes long",
            ));
        }
        if self.limits.per_minute == 0 || self.limits.concurrent == 0 {
            return Err(ConfigError::Invalid("limits must be at least 1"));
        }
        for host in self
            .gateways
            .allow
            .iter_mut()
            .chain(self.gateways.deny.iter_mut())
        {
            let bracketed = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]")
            } else {
                host.clone()
            };
            let canonical = crate::origin::canonical_host(&bracketed).map_err(|_| {
                ConfigError::Invalid(
                    "a gateway host in `allow` or `deny` is not a host name or address",
                )
            })?;
            *host = canonical
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_gets_the_defaults() {
        let c = Config::parse(r#"listen = "0.0.0.0:8080""#).unwrap();
        assert_eq!(c.purposes, [lz_proto::OHTTP_PURPOSE]);
        assert_eq!(c.limits.per_minute, 60);
        assert_eq!(c.limits.concurrent, 10);
        assert!(!c.allow_private_targets);
        assert!(c.gateways.ports.is_empty());
    }

    #[test]
    fn rejects_bad_values() {
        for bad in [
            "listen = \"0.0.0.0:8080\"\npurposes = []",
            "listen = \"0.0.0.0:8080\"\npurposes = [\"\"]",
            "listen = \"0.0.0.0:8080\"\n[limits]\nper_minute = 0",
            "listen = \"0.0.0.0:8080\"\nunknown = 1",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn writes_hosts_in_canonical_form() {
        let c = Config::parse(
            "listen = \"0.0.0.0:8080\"\n[gateways]\nallow = [\"LZ.Example.org\", \"2001:DB8:0::1\", \"[::1]\"]\ndeny = [\"Bad.Example\", \"2130706433\"]",
        )
        .unwrap();
        assert_eq!(c.gateways.allow, ["lz.example.org", "2001:db8::1", "::1"]);
        assert_eq!(c.gateways.deny, ["bad.example", "127.0.0.1"]);
        assert!(
            Config::parse("listen = \"0.0.0.0:8080\"\n[gateways]\ndeny = [\"https://x/\"]")
                .is_err()
        );
    }
}
