//! `lz-server <config.toml> init`: sets up a self-hosted server
//! (deploy/DESIGN.md).
//!
//! It writes `config.toml` (mode 0600, never over an existing one), creates
//! the data directory (0700) with the server's own keys, and creates the
//! first account. The caller prints that account's connection URL once.
//! For an onion service it reads the hostname Tor writes, waiting for Tor
//! to write it. Nothing secret goes into the config file, and no error
//! message names the onion address, a token, or a URL.

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use lz_proto::lease::Network;
use lz_proto::token::AccountToken;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::store::Store;

/// How the wallet reaches the server (spec §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// A Tor onion service; the API is served without OHTTP. The hostname
    /// is read from the file Tor writes into the hidden service directory.
    Onion { hostname_file: PathBuf },
    /// OHTTP behind TLS at `public_host` (a relay points at it).
    Ohttp {
        public_host: String,
        base_path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitOptions {
    pub network: Network,
    pub listen: SocketAddr,
    /// Defaults to `data` next to the config file.
    pub data_dir: Option<PathBuf>,
    pub transport: Transport,
    /// The Zaino or lightwalletd gRPC URL. `None` only with `--no-chain`.
    pub lightwalletd: Option<String>,
    pub vapid_contact: String,
    /// How long to wait for Tor to write the onion hostname.
    pub wait: Duration,
}

pub const USAGE: &str = "usage: lz-server <config.toml> init --network <main|test|regtest> \
    (--onion-hostname-file <path> | --public-host <host> [--base-path </path>]) \
    (--lightwalletd <url> | --no-chain) --vapid-contact <mailto:…|https:…> \
    [--listen <addr:port>] [--data-dir <path>] [--wait-secs <n>]";

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("{0}\n{USAGE}")]
    Usage(String),
    #[error(
        "a config file already exists there; init never overwrites one (use new-account for more accounts)"
    )]
    Exists,
    #[error("Tor hasn't written the onion hostname file yet; is the tor service running?")]
    NoOnionHostname,
    #[error("the onion hostname file doesn't hold a v3 onion address")]
    BadOnionHostname,
    #[error("paths must be valid UTF-8")]
    NonUtf8Path,
    #[error("the generated config is invalid: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("{0}: {1}")]
    Io(&'static str, std::io::Error),
    #[error("server keys: {0}")]
    Keys(#[from] crate::keys::KeyError),
    #[error("cannot generate an account token")]
    Token,
    #[error(
        "the config was written, but creating the first account failed ({0}); \
         run `lz-server <config.toml> new-account`"
    )]
    Account(Box<InitError>),
}

fn usage(msg: impl Into<String>) -> InitError {
    InitError::Usage(msg.into())
}

/// Options that take a value.
const VALUE_FLAGS: &[&str] = &[
    "--network",
    "--listen",
    "--wait-secs",
    "--data-dir",
    "--onion-hostname-file",
    "--public-host",
    "--base-path",
    "--lightwalletd",
    "--vapid-contact",
];

/// Parses the arguments after `init`.
pub fn parse_args(args: &[String]) -> Result<InitOptions, InitError> {
    let mut network = None;
    let mut listen = None;
    let mut data_dir = None;
    let mut onion_file = None;
    let mut public_host = None;
    let mut base_path = None;
    let mut lightwalletd = None;
    let mut no_chain = false;
    let mut vapid_contact = None;
    let mut wait_secs = 60u64;

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if flag == "--no-chain" {
            no_chain = true;
            continue;
        }
        // Don't echo unknown arguments: one could be a secret pasted in the
        // wrong place.
        if !VALUE_FLAGS.contains(&flag.as_str()) {
            return Err(usage("unknown option"));
        }
        let value = it
            .next()
            .ok_or_else(|| usage(format!("{flag} needs a value")))?;
        let slot = match flag.as_str() {
            "--network" => {
                network = Some(match value.as_str() {
                    "main" => Network::Main,
                    "test" => Network::Test,
                    "regtest" => Network::Regtest,
                    _ => return Err(usage("--network must be main, test, or regtest")),
                });
                continue;
            }
            "--listen" => {
                listen = Some(
                    value
                        .parse::<SocketAddr>()
                        .map_err(|_| usage("--listen must be an address and port"))?,
                );
                continue;
            }
            "--wait-secs" => {
                wait_secs = value
                    .parse()
                    .map_err(|_| usage("--wait-secs must be a number"))?;
                continue;
            }
            "--data-dir" => &mut data_dir,
            "--onion-hostname-file" => &mut onion_file,
            "--public-host" => &mut public_host,
            "--base-path" => &mut base_path,
            "--lightwalletd" => &mut lightwalletd,
            "--vapid-contact" => &mut vapid_contact,
            _ => return Err(usage("unknown option")),
        };
        if slot.replace(value.clone()).is_some() {
            return Err(usage(format!("{flag} given twice")));
        }
    }

    let network = network.ok_or_else(|| usage("--network is required"))?;
    let transport = match (onion_file, public_host) {
        (Some(f), None) => {
            if base_path.is_some() {
                return Err(usage("--base-path is only for --public-host"));
            }
            Transport::Onion {
                hostname_file: PathBuf::from(f),
            }
        }
        (None, Some(host)) => {
            if !is_plain_host(&host) {
                return Err(usage(
                    "--public-host must be a host name, optionally with :port (no scheme or path)",
                ));
            }
            Transport::Ohttp {
                public_host: host,
                base_path: base_path.unwrap_or_default(),
            }
        }
        _ => {
            return Err(usage(
                "give exactly one of --onion-hostname-file and --public-host",
            ));
        }
    };
    let lightwalletd = match (lightwalletd, no_chain) {
        (Some(url), false) => Some(url),
        (None, true) => None,
        _ => return Err(usage("give exactly one of --lightwalletd and --no-chain")),
    };
    let vapid_contact = vapid_contact.ok_or_else(|| usage("--vapid-contact is required"))?;
    if !(vapid_contact.starts_with("mailto:") || vapid_contact.starts_with("https:")) {
        return Err(usage(
            "--vapid-contact must be a mailto: or https: URL (RFC 8292)",
        ));
    }
    Ok(InitOptions {
        network,
        listen: listen.unwrap_or(SocketAddr::from(([127, 0, 0, 1], 8080))),
        data_dir: data_dir.map(PathBuf::from),
        transport,
        lightwalletd,
        vapid_contact,
        wait: Duration::from_secs(wait_secs),
    })
}

/// Whether `host` is only a host (name, IPv4, or bracketed IPv6) with an
/// optional port, so it can't change the connection URL's path or token.
pub fn is_plain_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with(['.', '-', ':'])
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
}

/// Whether `host` is a v3 onion address: 56 base32 characters, `.onion`.
pub fn is_v3_onion(host: &str) -> bool {
    host.strip_suffix(".onion").is_some_and(|name| {
        name.len() == 56
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    })
}

/// Reads the onion hostname Tor writes, polling until `wait` has passed.
pub fn read_onion_hostname(file: &Path, wait: Duration) -> Result<String, InitError> {
    let deadline = Instant::now() + wait;
    loop {
        match std::fs::read_to_string(file) {
            Ok(text) => {
                let host = text.trim();
                return if is_v3_onion(host) {
                    Ok(host.to_owned())
                } else {
                    Err(InitError::BadOnionHostname)
                };
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(InitError::NoOnionHostname);
            }
            Err(e) => return Err(InitError::Io("cannot read the onion hostname file", e)),
        }
    }
}

/// A TOML basic string, quoted and escaped.
fn quote(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

fn network_name(n: Network) -> &'static str {
    match n {
        Network::Main => "main",
        Network::Test => "test",
        Network::Regtest => "regtest",
    }
}

/// The config file's text. `public_host` is resolved already.
pub fn render_config(
    opts: &InitOptions,
    public_host: &str,
    data_dir: &Path,
) -> Result<String, InitError> {
    let data_dir = data_dir.to_str().ok_or(InitError::NonUtf8Path)?;
    let (base_path, transport) = match &opts.transport {
        Transport::Onion { .. } => (
            "",
            "# Reached as a Tor onion service, so the API is served without OHTTP\n\
             # (spec §3.1).\ndirect_api = true\n",
        ),
        Transport::Ohttp { base_path, .. } => (
            base_path.as_str(),
            "# Reached through OHTTP relays. Put TLS in front of `listen`, and point\n\
             # relays at https://<public_host>/.well-known/ohttp-gateway.\n",
        ),
    };
    let chain = match &opts.lightwalletd {
        Some(url) => format!(
            "\n# Zaino or lightwalletd gRPC. Use https:// for anything off this host\n\
             # or private network.\n[chain]\nlightwalletd = {}\npoll_secs = 5\n",
            quote(url)
        ),
        None => "\n# No [chain]: tip stays 0 and nothing is scanned (push testing only).\n".into(),
    };
    Ok(format!(
        "# Written by `lz-server init`. No secrets here: the server's keys and\n\
         # the account list live in data_dir. Reference: server/examples/config.toml.\n\
         listen = {listen}\n\
         public_host = {host}\n\
         base_path = {base}\n\
         network = {network}\n\
         data_dir = {data}\n\
         vapid_contact = {contact}\n\
         {transport}{chain}",
        listen = quote(&opts.listen.to_string()),
        host = quote(public_host),
        base = quote(base_path),
        network = quote(network_name(opts.network)),
        data = quote(data_dir),
        contact = quote(&opts.vapid_contact),
    ))
}

/// Creates an account and returns its connection URL, holding the token.
/// The server loads it at its next start.
pub fn new_account_url(config: &Config) -> Result<Zeroizing<String>, InitError> {
    crate::keys::create_private_dir(&config.data_dir)
        .map_err(|e| InitError::Io("cannot create data_dir", e))?;
    let token = AccountToken::generate().map_err(|_| InitError::Token)?;
    Store::add_account_to_file(&config.data_dir, &token.hash())
        .map_err(|e| InitError::Io("cannot write the account", e))?;
    let encoded = token.encode();
    Ok(Zeroizing::new(format!(
        "lanternzero://{}{}#{}",
        config.public_host,
        config.base_path,
        encoded.as_str()
    )))
}

/// Runs `init`: keys, then the config file, then the first account.
/// Returns the account's connection URL for the caller to print once.
pub fn run(config_path: &Path, opts: &InitOptions) -> Result<Zeroizing<String>, InitError> {
    if config_path.exists() {
        return Err(InitError::Exists);
    }
    let parent = match config_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let data_dir = opts.data_dir.clone().unwrap_or_else(|| parent.join("data"));
    let public_host = match &opts.transport {
        Transport::Onion { hostname_file } => read_onion_hostname(hostname_file, opts.wait)?,
        Transport::Ohttp { public_host, .. } => public_host.clone(),
    };
    let text = render_config(opts, &public_host, &data_dir)?;
    let config: Config = toml::from_str(&text).map_err(crate::config::ConfigError::from)?;
    config.validate()?;

    // The server's own keys (spec §3.2, §5.3), created now so the first
    // start doesn't race anything.
    crate::keys::create_private_dir(&data_dir)
        .map_err(|e| InitError::Io("cannot create data_dir", e))?;
    crate::ohttp_keys::load(&data_dir, crate::unix_now())?;
    crate::keys::vapid_keys(&data_dir)?;
    crate::keys::event_id_secret(&data_dir)?;

    crate::keys::create_private_dir(&parent)
        .map_err(|e| InitError::Io("cannot create the config directory", e))?;
    let mut f = crate::keys::private_file()
        .write(true)
        .create_new(true)
        .open(config_path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => InitError::Exists,
            _ => InitError::Io("cannot write the config file", e),
        })?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| InitError::Io("cannot write the config file", e))?;

    new_account_url(&config).map_err(|e| InitError::Account(Box::new(e)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    fn tmp() -> PathBuf {
        let mut raw = [0u8; 8];
        rand::fill(&mut raw);
        let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let d = std::env::temp_dir().join(format!("lz-init-{name}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn onion_opts(dir: &Path) -> InitOptions {
        std::fs::write(dir.join("hostname"), format!("{ONION}\n")).unwrap();
        parse_args(&args(&format!(
            "--network main --onion-hostname-file {} --lightwalletd http://zaino:8137 \
             --vapid-contact mailto:me@example.org --listen 0.0.0.0:8080",
            dir.join("hostname").display()
        )))
        .unwrap()
    }

    #[test]
    fn parses_onion_and_ohttp() {
        let o = parse_args(&args(
            "--network test --public-host lz.example.org --base-path /lz \
             --no-chain --vapid-contact https://example.org/contact",
        ))
        .unwrap();
        assert_eq!(o.network, Network::Test);
        assert_eq!(o.listen, SocketAddr::from(([127, 0, 0, 1], 8080)));
        assert_eq!(
            o.transport,
            Transport::Ohttp {
                public_host: "lz.example.org".into(),
                base_path: "/lz".into()
            }
        );
        assert_eq!(o.lightwalletd, None);
    }

    #[test]
    fn rejects_bad_arguments() {
        let bad = [
            "",
            "--network main --no-chain --vapid-contact mailto:a@b",
            "--network main --public-host h --onion-hostname-file f --no-chain --vapid-contact mailto:a@b",
            "--network main --public-host h --vapid-contact mailto:a@b",
            "--network main --public-host h --no-chain --lightwalletd x --vapid-contact mailto:a@b",
            "--network main --public-host h --no-chain --vapid-contact ops@example.org",
            "--network mainnet --public-host h --no-chain --vapid-contact mailto:a@b",
            "--network main --public-host h --public-host i --no-chain --vapid-contact mailto:a@b",
            "--network main --onion-hostname-file f --base-path /x --no-chain --vapid-contact mailto:a@b",
            "--network main --public-host h --no-chain --vapid-contact",
        ];
        for b in bad {
            assert!(
                matches!(parse_args(&args(b)), Err(InitError::Usage(_))),
                "{b}"
            );
        }
    }

    #[test]
    fn unknown_options_are_not_echoed() {
        let secret = "lanternzero://h#SECRET-LOOKING-VALUE";
        let e = parse_args(&[secret.to_owned()]).unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
    }

    #[test]
    fn checks_public_hosts() {
        for ok in [
            "lz.example.org",
            "lz.example.org:8443",
            "[2001:db8::1]:443",
            "10.0.0.2",
        ] {
            assert!(is_plain_host(ok), "{ok}");
        }
        for bad in [
            "",
            "https://lz.example.org",
            "lz.example.org/x",
            "h#token",
            "a b",
            "user@h",
            "-h",
        ] {
            assert!(!is_plain_host(bad), "{bad}");
        }
        let e = parse_args(&args(
            "--network main --public-host h/x --no-chain --vapid-contact mailto:a@b",
        ));
        assert!(matches!(e, Err(InitError::Usage(_))));
    }

    #[test]
    fn checks_onion_addresses() {
        assert!(is_v3_onion(ONION));
        assert!(!is_v3_onion("example.org"));
        assert!(!is_v3_onion("abc.onion"));
        assert!(!is_v3_onion(&ONION.to_uppercase()));
        assert!(!is_v3_onion(&ONION.replace('a', "1")));
    }

    #[test]
    fn waits_for_tor_then_gives_up() {
        let dir = tmp();
        let file = dir.join("hostname");
        let e = read_onion_hostname(&file, Duration::from_millis(600)).unwrap_err();
        assert!(matches!(e, InitError::NoOnionHostname));
        let writer = {
            let file = file.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                std::fs::write(file, format!("{ONION}\n")).unwrap();
            })
        };
        assert_eq!(
            read_onion_hostname(&file, Duration::from_secs(5)).unwrap(),
            ONION
        );
        writer.join().unwrap();
        std::fs::write(&file, "not-an-onion\n").unwrap();
        let e = read_onion_hostname(&file, Duration::ZERO).unwrap_err();
        assert!(matches!(e, InitError::BadOnionHostname));
        assert!(!e.to_string().contains("not-an-onion"));
    }

    #[test]
    fn rendered_config_loads_and_escapes() {
        let mut o = parse_args(&args(
            "--network regtest --public-host lz.example.org --lightwalletd http://x:1 \
             --vapid-contact mailto:a@b",
        ))
        .unwrap();
        o.vapid_contact = "mailto:\"quoted\"\n@b".into();
        let text = render_config(&o, "lz.example.org", Path::new("/d")).unwrap();
        let c: Config = toml::from_str(&text).unwrap();
        c.validate().unwrap();
        assert_eq!(c.vapid_contact, "mailto:\"quoted\"\n@b");
        assert!(!c.direct_api);
        assert_eq!(c.chain.unwrap().lightwalletd, "http://x:1");
    }

    #[test]
    fn init_writes_everything_and_never_overwrites() {
        let dir = tmp();
        let opts = onion_opts(&dir);
        let config_path = dir.join("conf").join("config.toml");
        let url = run(&config_path, &opts).unwrap();
        assert!(url.starts_with(&format!("lanternzero://{ONION}#")));

        let config = Config::load(&config_path).unwrap();
        assert!(config.direct_api);
        assert_eq!(config.public_host, ONION);
        assert_eq!(config.data_dir, dir.join("conf").join("data"));
        let text = std::fs::read_to_string(&config_path).unwrap();
        let token = url.split('#').nth(1).unwrap();
        assert!(!text.contains(token), "the token must not be in the config");

        // Keys and the account exist; the server can start on them.
        for f in [
            crate::ohttp_keys::CURRENT_FILE,
            "vapid-key",
            "event-id-secret",
            crate::store::ACCOUNTS_FILE,
        ] {
            assert!(config.data_dir.join(f).exists(), "{f}");
        }
        let store = Store::open(&config.data_dir).unwrap();
        let parsed = lz_proto::token::AccountToken::parse(token).unwrap();
        assert!(store.authenticate(&parsed.hash()).is_some());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&config_path), 0o600);
            assert_eq!(mode(&config.data_dir), 0o700);
            assert_eq!(mode(&dir.join("conf")), 0o700);
        }
        assert_eq!(
            crate::doctor::data_dir(&config.data_dir).status,
            crate::doctor::Status::Pass
        );

        // A second run refuses and creates no second account.
        let accounts =
            std::fs::read_to_string(config.data_dir.join(crate::store::ACCOUNTS_FILE)).unwrap();
        assert!(matches!(run(&config_path, &opts), Err(InitError::Exists)));
        assert_eq!(
            std::fs::read_to_string(config.data_dir.join(crate::store::ACCOUNTS_FILE)).unwrap(),
            accounts
        );
    }
}
