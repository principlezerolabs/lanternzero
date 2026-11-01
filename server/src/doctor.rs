//! `lz-server <config.toml> doctor`: checks an install (deploy/DESIGN.md).
//!
//! Prints pass, warn, or fail for each check. The output holds no tokens,
//! keys, URLs, host names, or file contents, so it is safe to paste into an
//! issue or hand to the self-hosting skill.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::hardening::{self, Lock, Swap, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub status: Status,
    pub name: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Check {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = match self.status {
            Status::Pass => "pass",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
        };
        write!(f, "{status}  {:<10}  {}", self.name, self.detail)
    }
}

fn check(status: Status, name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        status,
        name,
        detail: detail.into(),
    }
}

/// A tip older than this means the chain source is behind or stalled.
const STALE_TIP: Duration = Duration::from_secs(20 * 60);
/// Each call to the chain source.
const CHAIN_TIMEOUT: Duration = Duration::from_secs(15);

/// Runs every check.
pub async fn run(config: &Config) -> Vec<Check> {
    vec![
        data_dir(&config.data_dir),
        core_dumps(&hardening::inspect()),
        memory(&hardening::inspect(), config),
        ohttp_key(config, now_secs()),
        chain(config).await,
    ]
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The OHTTP key's age: rotate at least every 90 days (spec §3.2).
pub fn ohttp_key(config: &Config, now: u64) -> Check {
    const NAME: &str = "ohttp-key";
    if config.direct_api {
        return check(
            Status::Pass,
            NAME,
            "not used: wallets reach this server as an onion service",
        );
    }
    match crate::ohttp_keys::read_current(&config.data_dir) {
        Ok(None) => check(
            Status::Warn,
            NAME,
            "not created yet; the server creates it at first start",
        ),
        Err(_) => check(
            Status::Fail,
            NAME,
            "the OHTTP key file is unreadable or corrupt",
        ),
        Ok(Some(key)) => {
            let days = now.saturating_sub(key.created_at) / 86_400;
            if now.saturating_sub(key.created_at) > crate::ohttp_keys::MAX_AGE_SECS {
                check(
                    Status::Warn,
                    NAME,
                    format!(
                        "{days} days old: rotate it (rotate-ohttp, then restart) at least every 90 days"
                    ),
                )
            } else {
                check(Status::Pass, NAME, format!("{days} days old"))
            }
        }
    }
}

/// Owner-only permissions on the data directory and everything in it.
pub fn data_dir(dir: &Path) -> Check {
    const NAME: &str = "data-dir";
    if !dir.exists() {
        return check(
            Status::Warn,
            NAME,
            "not created yet; the server creates it at first start",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let loose =
            |p: &Path| std::fs::metadata(p).map_or(true, |m| m.permissions().mode() & 0o077 != 0);
        let mut bad: Vec<String> = Vec::new();
        if loose(dir) {
            bad.push("the directory itself".into());
        }
        let vapid = dir.join(crate::keys::VAPID_RETIRED_DIR);
        let ohttp = dir.join(crate::ohttp_keys::RETIRED_DIR);
        for (base, label) in [
            (dir, ""),
            (vapid.as_path(), "vapid-retired/"),
            (ohttp.as_path(), "ohttp-retired/"),
        ] {
            let Ok(entries) = std::fs::read_dir(base) else {
                continue;
            };
            for e in entries.flatten() {
                if loose(&e.path()) {
                    // Retired key files are named by their public key:
                    // don't print it.
                    let name = if label.is_empty() {
                        e.file_name().to_string_lossy().into_owned()
                    } else {
                        format!("{label}…")
                    };
                    bad.push(name);
                }
            }
        }
        if bad.is_empty() {
            check(Status::Pass, NAME, "owner-only permissions")
        } else {
            bad.sort();
            bad.dedup();
            check(
                Status::Fail,
                NAME,
                format!(
                    "readable by group or others: {} (chmod 700 the directory, 600 its files)",
                    bad.join(", ")
                ),
            )
        }
    }
    #[cfg(not(unix))]
    check(Status::Warn, NAME, "can't check permissions on this system")
}

pub fn core_dumps(report: &hardening::Report) -> Check {
    if report.core_dumps_off {
        check(
            Status::Pass,
            "core-dumps",
            "the server turns them off at start (RLIMIT_CORE 0, not dumpable)",
        )
    } else {
        check(
            Status::Fail,
            "core-dumps",
            "can't turn them off on this system (spec §6.2)",
        )
    }
}

/// Locked memory, or swap that can't hold it (spec §6.2).
pub fn memory(report: &hardening::Report, config: &Config) -> Check {
    const NAME: &str = "memory";
    let scanning = config.chain.is_some();
    let how = match (report.memory, report.swap) {
        (Lock::Locked, _) => "memory can be locked (RLIMIT_MEMLOCK unlimited)",
        (_, Swap::Off) => "no swap",
        (_, Swap::CgroupOff) => "swap is off for this container (memory.swap.max 0)",
        (_, Swap::Encrypted) => "swap is always encrypted on this system",
        (_, Swap::On | Swap::Unknown) => "",
    };
    match hardening::verdict(report, scanning, &config.hardening) {
        Verdict::Ok => check(Status::Pass, NAME, how),
        Verdict::Warn if !scanning => check(
            Status::Warn,
            NAME,
            "swap may hold memory, but without [chain] no viewing keys are held",
        ),
        Verdict::Warn => check(
            Status::Warn,
            NAME,
            "swap may hold memory; allowed by hardening.allow_swap, so it must be encrypted",
        ),
        Verdict::Refuse => check(
            Status::Fail,
            NAME,
            "swap may hold viewing keys, so the server won't start: set the memlock \
             limit to unlimited (LimitMEMLOCK=infinity, or ulimits memlock -1), turn \
             swap off for it, or encrypt swap and set hardening.allow_swap",
        ),
    }
}

/// The chain source: reachable, on the configured network, and current.
pub async fn chain(config: &Config) -> Check {
    const NAME: &str = "chain";
    let Some(c) = &config.chain else {
        return check(
            Status::Warn,
            NAME,
            "no [chain]: no scanning, and tip stays 0",
        );
    };
    // Errors from the chain client can include its URL: print none of them.
    let Ok(source) = crate::chain::Lightwalletd::new(&c.lightwalletd) else {
        return check(Status::Fail, NAME, "invalid [chain] lightwalletd URL");
    };
    let call = |f| tokio::time::timeout(CHAIN_TIMEOUT, f);
    match call(source.check_network(config.network)).await {
        Ok(Ok(())) => {}
        Ok(Err(crate::chain::ChainError::WrongNetwork { .. })) => {
            return check(
                Status::Fail,
                NAME,
                format!("the chain source isn't on {:?}", config.network),
            );
        }
        _ => return check(Status::Fail, NAME, "can't reach the chain source"),
    }
    let Ok(Ok(tip)) = tokio::time::timeout(CHAIN_TIMEOUT, source.latest_height()).await else {
        return check(Status::Fail, NAME, "the chain source didn't report a tip");
    };
    let Ok(Ok(blocks)) = tokio::time::timeout(CHAIN_TIMEOUT, source.blocks(tip, tip)).await else {
        return check(
            Status::Fail,
            NAME,
            "the chain source didn't serve its tip block",
        );
    };
    let Some(time) = blocks.first().map(|b| u64::from(b.time)) else {
        return check(
            Status::Fail,
            NAME,
            "the chain source didn't serve its tip block",
        );
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    tip_check(tip, time, now)
}

/// Judges the tip's age; a block from the future means this clock is
/// behind (requests are rejected beyond 60 s of skew, spec §3.4).
pub fn tip_check(tip: u64, block_time: u64, now: u64) -> Check {
    const NAME: &str = "chain";
    if block_time > now + 120 {
        return check(
            Status::Warn,
            NAME,
            format!(
                "tip {tip} is {} s in the future: check this machine's clock",
                block_time - now
            ),
        );
    }
    let age = now.saturating_sub(block_time);
    let detail = format!("network ok, tip {tip}, {} min old", age / 60);
    if age > STALE_TIP.as_secs() {
        check(
            Status::Warn,
            NAME,
            format!("{detail}: still syncing, or stalled"),
        )
    } else {
        check(Status::Pass, NAME, detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tip_age_and_clock() {
        let now = 1_800_000_000;
        assert_eq!(tip_check(5, now - 60, now).status, Status::Pass);
        assert_eq!(tip_check(5, now - 3600, now).status, Status::Warn);
        let ahead = tip_check(5, now + 600, now);
        assert_eq!(ahead.status, Status::Warn);
        assert!(ahead.detail.contains("clock"));
    }

    #[test]
    fn ohttp_key_age() {
        let mut raw = [0u8; 8];
        rand::fill(&mut raw);
        let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("lz-doctor-ohttp-{name}"));
        let mut config: Config = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\npublic_host = \"lz.example.org\"\n\
             network = \"main\"\ndata_dir = {:?}\nvapid_contact = \"mailto:a@b\"\n",
            dir.display().to_string()
        ))
        .unwrap();
        let t0 = 1_800_000_000;
        assert_eq!(ohttp_key(&config, t0).status, Status::Warn, "not created");
        crate::ohttp_keys::load(&dir, t0).unwrap();
        let fresh = ohttp_key(&config, t0 + 89 * 86_400);
        assert_eq!(fresh.status, Status::Pass);
        assert_eq!(fresh.detail, "89 days old");
        let old = ohttp_key(&config, t0 + 91 * 86_400);
        assert_eq!(old.status, Status::Warn);
        assert!(old.detail.contains("rotate-ohttp"));
        config.public_host = format!("{}.onion", "a".repeat(56));
        config.direct_api = true;
        assert_eq!(ohttp_key(&config, t0 + 91 * 86_400).status, Status::Pass);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn data_dir_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let mut raw = [0u8; 8];
        rand::fill(&mut raw);
        let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("lz-doctor-{name}"));
        assert_eq!(data_dir(&dir).status, Status::Warn);
        crate::keys::create_private_dir(&dir).unwrap();
        crate::keys::write_private_atomic(&dir, "accounts.txt", b"").unwrap();
        assert_eq!(data_dir(&dir).status, Status::Pass);

        let retired = dir.join(crate::keys::VAPID_RETIRED_DIR);
        crate::keys::create_private_dir(&retired).unwrap();
        std::fs::write(retired.join("BPublicKeyName"), [1; 32]).unwrap();
        std::fs::set_permissions(
            retired.join("BPublicKeyName"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        std::fs::set_permissions(
            dir.join("accounts.txt"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let c = data_dir(&dir);
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("accounts.txt"), "{}", c.detail);
        assert!(!c.detail.contains("BPublicKeyName"), "key names stay out");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
