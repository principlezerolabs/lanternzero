//! `lz-server <config.toml> doctor`: checks an install (deploy/DESIGN.md).
//!
//! Prints pass, warn, or fail for each check. The output holds no tokens,
//! keys, URLs, host names, or file contents, so it is safe to paste into an
//! issue or hand to the self-hosting skill.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::clock::unix_now;
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
        ohttp_key(config, unix_now()),
        chain(config).await,
        gateway(config).await,
        clock(TIME_SERVER).await,
    ]
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
    tip_check(tip, time, unix_now())
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

/// How long the gateway check waits.
const GATEWAY_TIMEOUT: Duration = Duration::from_secs(15);

/// Where the server answers wallets: as an onion service, the listen
/// address Tor forwards to; over OHTTP, the public gateway URL relays
/// forward to. Either must serve this server's current key configuration
/// at `/.well-known/ohttp-gateway`. The onion name itself would need a
/// Tor client, which the kit's Tor doesn't offer (no SOCKS port).
pub async fn gateway(config: &Config) -> Check {
    const NAME: &str = "gateway";
    let path = crate::gateway::GATEWAY_PATH;
    let url = if config.direct_api {
        format!("http://{}{path}", local_target(config.listen))
    } else {
        format!("https://{}{path}", config.public_host)
    };
    let expected = match crate::ohttp_keys::read_current(&config.data_dir) {
        Ok(Some(key)) => key.served().ok(),
        _ => None,
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(GATEWAY_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return check(Status::Fail, NAME, "couldn't set up an HTTP client");
    };
    // Errors and URLs name the host: print neither.
    let served = match client.get(&url).send().await {
        Ok(r) if r.status() == reqwest::StatusCode::OK => r.bytes().await.ok(),
        Ok(r) => {
            return check(
                Status::Fail,
                NAME,
                format!("the gateway answered {}", r.status().as_u16()),
            );
        }
        Err(_) => None,
    };
    gateway_check(config.direct_api, served.as_deref(), expected.as_deref())
}

/// Judges what the gateway served, given the configuration on disk.
pub fn gateway_check(onion: bool, served: Option<&[u8]>, expected: Option<&[u8]>) -> Check {
    const NAME: &str = "gateway";
    let Some(served) = served else {
        let detail = if onion {
            "nothing answers on the listen address: is the server running?"
        } else {
            "can't reach the public gateway over HTTPS: check DNS, TLS, and the \
             proxy in front of the server"
        };
        return check(Status::Fail, NAME, detail);
    };
    if let Some(expected) = expected
        && served != expected
    {
        return check(
            Status::Fail,
            NAME,
            "it serves another key configuration than this server's: another \
             server answers there, or a cache in front of it is stale",
        );
    }
    let detail = if onion {
        "answers on the listen address, where Tor forwards; the onion name \
         itself isn't checked"
    } else {
        "the public gateway answers with this server's key configuration"
    };
    check(Status::Pass, NAME, detail)
}

/// `listen` as an address to connect to: an unspecified address means
/// this machine.
fn local_target(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, listen.port())
}

/// The NTP server `doctor` asks for the time.
pub const TIME_SERVER: &str = "pool.ntp.org:123";
/// How long to wait for its answer.
const TIME_TIMEOUT: Duration = Duration::from_secs(5);
/// Seconds from 1900 (NTP's epoch) to 1970.
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// This machine's clock against an NTP server (one SNTP query, RFC 4330).
/// Requests more than 60 s off the server's clock are rejected (spec
/// §3.4); wallets correct for the server's clock, but webhook receivers
/// and push gateways check times too.
pub async fn clock(server: &str) -> Check {
    match tokio::time::timeout(TIME_TIMEOUT, sntp_offset(server)).await {
        Ok(Some(offset)) => clock_check(offset),
        _ => check(
            Status::Warn,
            "clock",
            "couldn't ask a time server (is UDP port 123 blocked?); clock not checked",
        ),
    }
}

/// Judges an offset in seconds (positive: this clock is behind).
pub fn clock_check(offset: f64) -> Check {
    const NAME: &str = "clock";
    let off = offset.abs();
    let way = if offset > 0.0 { "behind" } else { "ahead" };
    if off <= 5.0 {
        check(Status::Pass, NAME, format!("within {off:.1} s of NTP time"))
    } else if off <= 60.0 {
        check(
            Status::Warn,
            NAME,
            format!("{off:.0} s {way}: turn on time sync"),
        )
    } else {
        check(
            Status::Fail,
            NAME,
            format!("{off:.0} s {way}: past the 60 s replay window (spec §3.4); turn on time sync"),
        )
    }
}

/// One SNTP exchange; returns the offset in seconds.
async fn sntp_offset(server: &str) -> Option<f64> {
    let addr = tokio::net::lookup_host(server).await.ok()?.next()?;
    let bind: SocketAddr = if addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = tokio::net::UdpSocket::bind(bind).await.ok()?;
    socket.connect(addr).await.ok()?;
    // A random transmit timestamp: the reply must echo it as its
    // originate timestamp, so a forged or stray reply is ignored.
    let nonce: [u8; 8] = rand::random();
    let mut request = [0u8; 48];
    request[0] = 0x23; // LI 0, version 4, mode 3 (client)
    request[40..].copy_from_slice(&nonce);
    let sent = SystemTime::now();
    socket.send(&request).await.ok()?;
    let mut reply = [0u8; 128];
    let n = socket.recv(&mut reply).await.ok()?;
    let received = SystemTime::now();
    sntp_parse(&reply[..n], &nonce, unix_f64(sent)?, unix_f64(received)?)
}

fn unix_f64(t: SystemTime) -> Option<f64> {
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_secs_f64())
}

/// Reads an SNTP reply to a request sent at `sent` and received at
/// `received` (Unix seconds). `None` unless it is a synchronized server's
/// answer to `nonce`.
pub fn sntp_parse(reply: &[u8], nonce: &[u8; 8], sent: f64, received: f64) -> Option<f64> {
    if reply.len() < 48 {
        return None;
    }
    let leap = reply[0] >> 6;
    let mode = reply[0] & 0x07;
    let stratum = reply[1];
    if leap == 3 || mode != 4 || !(1..=15).contains(&stratum) || reply[24..32] != nonce[..] {
        return None;
    }
    let secs = u64::from(u32::from_be_bytes(reply[40..44].try_into().ok()?));
    let frac = f64::from(u32::from_be_bytes(reply[44..48].try_into().ok()?)) / 4_294_967_296.0;
    let server = secs.checked_sub(NTP_UNIX_OFFSET)? as f64 + frac;
    Some(server - (sent + received) / 2.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs the network: `cargo test -p lz-server -- --ignored clock_against`.
    #[tokio::test]
    #[ignore]
    async fn clock_against_the_ntp_pool() {
        let c = clock(TIME_SERVER).await;
        assert_eq!(c.status, Status::Pass, "{c}");
    }

    #[test]
    fn clock_offsets() {
        assert_eq!(clock_check(0.3).status, Status::Pass);
        let behind = clock_check(20.0);
        assert_eq!(behind.status, Status::Warn);
        assert!(behind.detail.contains("behind"), "{}", behind.detail);
        let ahead = clock_check(-90.0);
        assert_eq!(ahead.status, Status::Fail);
        assert!(ahead.detail.contains("ahead"), "{}", ahead.detail);
    }

    #[test]
    fn sntp_replies() {
        let nonce = [9u8; 8];
        let mut reply = [0u8; 48];
        reply[0] = 0x24; // LI 0, version 4, mode 4 (server)
        reply[1] = 2;
        reply[24..32].copy_from_slice(&nonce);
        // 1_800_000_010.5 in NTP time.
        let secs = (1_800_000_010u64 + NTP_UNIX_OFFSET) as u32;
        reply[40..44].copy_from_slice(&secs.to_be_bytes());
        reply[44..48].copy_from_slice(&(1u32 << 31).to_be_bytes());
        let offset = sntp_parse(&reply, &nonce, 1_800_000_000.0, 1_800_000_001.0).unwrap();
        assert!((offset - 10.0).abs() < 1e-3, "{offset}");

        assert_eq!(sntp_parse(&reply, &[0; 8], 0.0, 0.0), None, "wrong nonce");
        let mut unsynced = reply;
        unsynced[0] = 0xE4;
        assert_eq!(sntp_parse(&unsynced, &nonce, 0.0, 0.0), None);
        let mut kiss = reply;
        kiss[1] = 0;
        assert_eq!(sntp_parse(&kiss, &nonce, 0.0, 0.0), None, "kiss-o'-death");
        assert_eq!(sntp_parse(&reply[..40], &nonce, 0.0, 0.0), None);
    }

    #[test]
    fn gateway_answers() {
        let ok = gateway_check(true, Some(b"cfg"), Some(b"cfg"));
        assert_eq!(ok.status, Status::Pass);
        assert!(ok.detail.contains("onion name"));
        assert_eq!(
            gateway_check(false, Some(b"cfg"), None).status,
            Status::Pass
        );
        let other = gateway_check(false, Some(b"old"), Some(b"cfg"));
        assert_eq!(other.status, Status::Fail);
        assert!(other.detail.contains("stale"));
        assert_eq!(gateway_check(true, None, Some(b"cfg")).status, Status::Fail);
        assert_eq!(
            local_target("0.0.0.0:8080".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            local_target("172.30.77.10:8080".parse().unwrap()),
            "172.30.77.10:8080".parse().unwrap()
        );
    }

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
        // A data directory that doesn't exist yet.
        let tmp = crate::files::TestDir::new("doctor-ohttp");
        let dir = tmp.join("data");
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
    }

    #[cfg(unix)]
    #[test]
    fn data_dir_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = crate::files::TestDir::new("doctor");
        let dir = tmp.join("data");
        assert_eq!(data_dir(&dir).status, Status::Warn);
        crate::files::create_private_dir(&dir).unwrap();
        crate::files::write_private_atomic(&dir, "accounts.txt", b"").unwrap();
        assert_eq!(data_dir(&dir).status, Status::Pass);

        let retired = dir.join(crate::keys::VAPID_RETIRED_DIR);
        crate::files::create_private_dir(&retired).unwrap();
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
    }
}
