//! Viewing-key leases (spec §4.2).
//!
//! A [`ViewingKey`] is held as text, zeroed on drop, and never shown in
//! `Debug` output (invariant 1). Full decoding (ZIP 316) is the scanner's job;
//! this module only checks which kind of key it is and for which network.
//!
//! Servers: serde copies strings while parsing. Parse request bodies from a
//! buffer you zero afterwards, so no key text lingers outside these types.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Shortest lease, in seconds (24 h).
pub const MIN_DURATION_SECS: u64 = 86_400;
/// Longest lease, in seconds (7 days). Also the recommended request.
pub const MAX_DURATION_SECS: u64 = 604_800;
/// Most keys one lease may carry (one per `use_qsk` variant, ZIP 326).
pub const MAX_KEYS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Main,
    Test,
    Regtest,
}

/// Whether a key can see only incoming payments, or spends too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// Unified Incoming Viewing Key (`uivk…`).
    Incoming,
    /// Unified Full Viewing Key (`uview…`). Only with spend alerts.
    Full,
}

/// A unified viewing key in its ZIP 316 text form.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct ViewingKey(String);

impl ViewingKey {
    pub fn new(text: String) -> Self {
        Self(text)
    }

    /// The text form, for handing to the scanner. Never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Kind and network from the Bech32m human-readable part. Bech32m text
    /// is all lowercase or all uppercase (QR codes often use uppercase);
    /// mixed case is invalid.
    pub fn classify(&self) -> Option<(KeyKind, Network)> {
        let s = self.0.as_str();
        let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
        let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
        if has_lower && has_upper {
            return None;
        }
        let hrp = s.rsplit_once('1')?.0;
        // ZIP 316 Revision 0 prefixes, then Revision 2.
        const HRPS: [(&str, KeyKind, Network); 12] = [
            ("uivk", KeyKind::Incoming, Network::Main),
            ("uivktest", KeyKind::Incoming, Network::Test),
            ("uivkregtest", KeyKind::Incoming, Network::Regtest),
            ("uview", KeyKind::Full, Network::Main),
            ("uviewtest", KeyKind::Full, Network::Test),
            ("uviewregtest", KeyKind::Full, Network::Regtest),
            ("uvi", KeyKind::Incoming, Network::Main),
            ("uvitest", KeyKind::Incoming, Network::Test),
            ("uviregtest", KeyKind::Incoming, Network::Regtest),
            ("uvf", KeyKind::Full, Network::Main),
            ("uvftest", KeyKind::Full, Network::Test),
            ("uvfregtest", KeyKind::Full, Network::Regtest),
        ];
        HRPS.iter()
            .find(|(h, _, _)| h.eq_ignore_ascii_case(hrp))
            .map(|&(_, kind, net)| (kind, net))
    }
}

impl std::fmt::Debug for ViewingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ViewingKey(<redacted>)")
    }
}

/// How a scanning lease delivers payment alerts (spec §5.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertMode {
    /// An extra push as soon as a lease matches. Apple/Google see the timing.
    #[default]
    Instant,
    /// Alerts ride inside the next scheduled ping.
    Private,
}

/// The `lease` object of a `wake` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub keys: Vec<ViewingKey>,
    pub from_height: u64,
    pub duration_secs: u64,
    pub spend_alerts: bool,
    #[serde(default)]
    pub alert_mode: AlertMode,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LeaseError {
    #[error("a lease needs 1 to 4 keys")]
    KeyCount,
    #[error("key {0} is not a unified viewing key")]
    UnknownKey(usize),
    #[error("key {0} is for a different network")]
    WrongNetwork(usize),
    #[error("key {0} repeats an earlier key")]
    DuplicateKey(usize),
    #[error(
        "full viewing keys are accepted only with spend alerts, and spend alerts need full viewing keys"
    )]
    KindMismatch,
}

impl LeaseRequest {
    /// Checks the rules in spec §4.2 that don't need key decoding.
    pub fn validate(&self, network: Network) -> Result<(), LeaseError> {
        if self.keys.is_empty() || self.keys.len() > MAX_KEYS {
            return Err(LeaseError::KeyCount);
        }
        let wanted = if self.spend_alerts {
            KeyKind::Full
        } else {
            KeyKind::Incoming
        };
        for (i, key) in self.keys.iter().enumerate() {
            let (kind, net) = key.classify().ok_or(LeaseError::UnknownKey(i))?;
            if net != network {
                return Err(LeaseError::WrongNetwork(i));
            }
            if kind != wanted {
                return Err(LeaseError::KindMismatch);
            }
            if self.keys[..i]
                .iter()
                .any(|k| k.0.eq_ignore_ascii_case(&key.0))
            {
                return Err(LeaseError::DuplicateKey(i));
            }
        }
        Ok(())
    }
}

/// Clamps a requested lease length to 24 h–7 days, then to the time left in
/// the account's paid period, if any. A result of 0 means the paid period is
/// over: grant no lease.
pub fn clamp_duration(requested_secs: u64, paid_secs_left: Option<u64>) -> u64 {
    let d = requested_secs.clamp(MIN_DURATION_SECS, MAX_DURATION_SECS);
    match paid_secs_left {
        Some(left) => d.min(left),
        None => d,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(keys: &[&str], spend_alerts: bool) -> LeaseRequest {
        LeaseRequest {
            keys: keys
                .iter()
                .map(|k| ViewingKey::new((*k).to_owned()))
                .collect(),
            from_height: 3_500_000,
            duration_secs: MAX_DURATION_SECS,
            spend_alerts,
            alert_mode: AlertMode::Instant,
        }
    }

    #[test]
    fn accepts_revision_2_prefixes() {
        assert_eq!(lease(&["uvi1abc"], false).validate(Network::Main), Ok(()));
        assert_eq!(
            lease(&["UVITEST1ABC"], false).validate(Network::Test),
            Ok(())
        );
        assert_eq!(lease(&["uvf1abc"], true).validate(Network::Main), Ok(()));
        assert_eq!(
            lease(&["uvf1abc"], false).validate(Network::Main),
            Err(LeaseError::KindMismatch)
        );
        assert_eq!(
            lease(&["uviregtest1abc"], false).validate(Network::Main),
            Err(LeaseError::WrongNetwork(0))
        );
    }

    #[test]
    fn validates_kind_count_and_network() {
        assert_eq!(lease(&["uivk1abc"], false).validate(Network::Main), Ok(()));
        assert_eq!(lease(&["uview1abc"], true).validate(Network::Main), Ok(()));
        assert_eq!(
            lease(&["uview1abc"], false).validate(Network::Main),
            Err(LeaseError::KindMismatch)
        );
        assert_eq!(
            lease(&["uivk1abc"], true).validate(Network::Main),
            Err(LeaseError::KindMismatch)
        );
        assert_eq!(
            lease(&["uivktest1abc"], false).validate(Network::Main),
            Err(LeaseError::WrongNetwork(0))
        );
        assert_eq!(
            lease(&["zxviews1abc"], false).validate(Network::Main),
            Err(LeaseError::UnknownKey(0))
        );
        assert_eq!(
            lease(&[], false).validate(Network::Main),
            Err(LeaseError::KeyCount)
        );
        assert_eq!(
            lease(&["uivk1a"; 5], false).validate(Network::Main),
            Err(LeaseError::KeyCount)
        );
        assert_eq!(
            lease(&["uivk1abc", "UIVK1ABC"], false).validate(Network::Main),
            Err(LeaseError::DuplicateKey(1))
        );
    }

    #[test]
    fn accepts_uppercase_but_not_mixed_case() {
        assert_eq!(lease(&["UIVK1ABC"], false).validate(Network::Main), Ok(()));
        assert_eq!(
            lease(&["Uivk1abc"], false).validate(Network::Main),
            Err(LeaseError::UnknownKey(0))
        );
    }

    #[test]
    fn clamps_duration() {
        assert_eq!(clamp_duration(60, None), MIN_DURATION_SECS);
        assert_eq!(clamp_duration(u64::MAX, None), MAX_DURATION_SECS);
        assert_eq!(clamp_duration(MAX_DURATION_SECS, Some(3_600)), 3_600);
    }

    /// Invariant 1: keys never appear in debug output, even nested.
    #[test]
    fn debug_output_is_redacted() {
        let l = lease(&["uivk1secretsecretsecret"], false);
        let dbg = format!("{l:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn alert_mode_defaults_to_instant() {
        let l: LeaseRequest = serde_json::from_str(
            r#"{"keys":["uivk1a"],"from_height":1,"duration_secs":86400,"spend_alerts":false}"#,
        )
        .unwrap();
        assert_eq!(l.alert_mode, AlertMode::Instant);
    }
}
