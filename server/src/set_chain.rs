//! `lz-server <config.toml> set-chain --lightwalletd <url> [--network <net>]
//! [--no-check]`: points an installed server at another chain source, or
//! another network, without starting over (deploy/DESIGN.md).
//!
//! It checks the new source the way `doctor` does before changing
//! anything, then rewrites only `network` and `[chain] lightwalletd` in the
//! config file, keeping its comments and layout. The result must parse to
//! the old config with just those values changed, or nothing is written.
//! The server uses it from its next start. Messages never print the URL:
//! it may carry credentials.

use std::path::Path;

use lz_proto::lease::Network;

use crate::config::{ChainConfig, Config};
use crate::doctor::{self, Check, Status};

pub const USAGE: &str = "usage: lz-server <config.toml> set-chain --lightwalletd <url> \
    [--network <main|test|regtest>] [--no-check]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetChainOptions {
    pub lightwalletd: String,
    pub network: Option<Network>,
    /// Check the new source before writing (on unless `--no-check`).
    pub check: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SetChainError {
    #[error("{0}\n{USAGE}")]
    Usage(String),
    #[error(
        "the new chain source failed its check: {0}; nothing was changed (--no-check skips the check)"
    )]
    CheckFailed(String),
    #[error("the config file's layout isn't one set-chain can edit safely; nothing was changed")]
    Layout,
    #[error("the new settings are invalid: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("{0}: {1}")]
    Io(&'static str, std::io::Error),
}

fn usage(msg: impl Into<String>) -> SetChainError {
    SetChainError::Usage(msg.into())
}

/// Parses the arguments after `set-chain`.
pub fn parse_args(args: &[String]) -> Result<SetChainOptions, SetChainError> {
    let mut lightwalletd = None;
    let mut network = None;
    let mut check = true;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--no-check" => check = false,
            "--lightwalletd" | "--network" => {
                let value = it
                    .next()
                    .ok_or_else(|| usage(format!("{flag} needs a value")))?;
                if flag == "--network" {
                    let n = match value.as_str() {
                        "main" => Network::Main,
                        "test" => Network::Test,
                        "regtest" => Network::Regtest,
                        _ => return Err(usage("--network must be main, test, or regtest")),
                    };
                    if network.replace(n).is_some() {
                        return Err(usage("--network given twice"));
                    }
                } else if lightwalletd.replace(value.clone()).is_some() {
                    return Err(usage("--lightwalletd given twice"));
                }
            }
            // Don't echo it: it could be a URL with credentials.
            _ => return Err(usage("unknown option")),
        }
    }
    let lightwalletd = lightwalletd.ok_or_else(|| usage("--lightwalletd is required"))?;
    if !(lightwalletd.starts_with("http://") || lightwalletd.starts_with("https://")) {
        return Err(usage("--lightwalletd must be an http:// or https:// URL"));
    }
    Ok(SetChainOptions {
        lightwalletd,
        network,
        check,
    })
}

fn network_name(n: Network) -> &'static str {
    match n {
        Network::Main => "main",
        Network::Test => "test",
        Network::Regtest => "regtest",
    }
}

/// The key a `key = value` line sets, if it is one.
fn line_key(line: &str) -> Option<&str> {
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with('[') {
        return None;
    }
    let (key, _) = t.split_once('=')?;
    Some(key.trim())
}

/// The table a `[name]` header line opens, if it is one.
fn table_header(line: &str) -> Option<&str> {
    let t = line.trim();
    let inner = t.strip_prefix('[')?;
    let end = inner.find(']')?;
    Some(inner[..end].trim_matches(|c| c == '[' || c == ' '))
}

/// Rewrites `network` (when given) and `[chain] lightwalletd` in `text`,
/// adding a `[chain]` table or key if missing. Everything else is kept.
pub fn rewrite(
    text: &str,
    lightwalletd: &str,
    network: Option<Network>,
) -> Result<String, SetChainError> {
    let quote = |s: &str| toml::Value::String(s.to_owned()).to_string();
    let url_line = format!("lightwalletd = {}", quote(lightwalletd));
    let mut out: Vec<String> = Vec::new();
    let mut table: Option<String> = None;
    let mut saw_network = false;
    let mut chain_header_at = None;
    let mut saw_url = false;
    for line in text.lines() {
        if let Some(name) = table_header(line) {
            table = Some(name.to_owned());
            if name == "chain" {
                chain_header_at = Some(out.len());
            }
            out.push(line.to_owned());
            continue;
        }
        match (table.as_deref(), line_key(line)) {
            (None, Some("network")) if network.is_some() => {
                saw_network = true;
                let n = network.map(network_name).unwrap_or_default();
                out.push(format!("network = {}", quote(n)));
            }
            (Some("chain"), Some("lightwalletd")) => {
                saw_url = true;
                out.push(url_line.clone());
            }
            _ => out.push(line.to_owned()),
        }
    }
    if network.is_some() && !saw_network {
        return Err(SetChainError::Layout);
    }
    match (chain_header_at, saw_url) {
        (_, true) => {}
        (Some(at), false) => out.insert(at + 1, url_line),
        (None, false) => {
            out.push(String::new());
            out.push("[chain]".into());
            out.push(url_line);
        }
    }
    let mut text = out.join("\n");
    text.push('\n');
    Ok(text)
}

/// What `set-chain` did: the new source's check, if it ran.
#[derive(Debug)]
pub struct Outcome {
    pub check: Option<Check>,
    pub network_changed: bool,
}

/// Checks the new source, then rewrites the config file in place (mode
/// 0600, through a temporary file and a rename).
pub async fn run(config_path: &Path, opts: &SetChainOptions) -> Result<Outcome, SetChainError> {
    let old = Config::load(config_path)?;
    let mut want = old.clone();
    want.network = opts.network.unwrap_or(old.network);
    let poll_secs = old.chain.as_ref().map_or(5, |c| c.poll_secs);
    want.chain = Some(ChainConfig {
        lightwalletd: opts.lightwalletd.clone(),
        poll_secs,
    });
    want.validate()?;

    let check = if opts.check {
        let c = doctor::chain(&want).await;
        if c.status == Status::Fail {
            return Err(SetChainError::CheckFailed(c.detail));
        }
        Some(c)
    } else {
        None
    };

    let text = std::fs::read_to_string(config_path)
        .map_err(|e| SetChainError::Io("cannot read the config file", e))?;
    let new_text = rewrite(&text, &opts.lightwalletd, opts.network)?;
    // The edit must change exactly what was asked. `Config`'s `Debug`
    // covers every field, and holds no secrets.
    let parsed: Config = toml::from_str(&new_text).map_err(|_| SetChainError::Layout)?;
    if format!("{parsed:?}") != format!("{want:?}") {
        return Err(SetChainError::Layout);
    }

    let parent = match config_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = config_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| usage("the config path must name a file"))?;
    crate::files::write_private_atomic(parent, name, new_text.as_bytes())
        .map_err(|e| SetChainError::Io("cannot write the config file", e))?;
    Ok(Outcome {
        check,
        network_changed: want.network != old.network,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    /// A config as `init` writes it.
    fn init_config(dir: &Path) -> String {
        let opts = crate::init::parse_args(&args(
            "--network main --public-host lz.example.org --lightwalletd http://zaino:8137 \
             --vapid-contact mailto:a@b",
        ))
        .unwrap();
        crate::init::render_config(&opts, "lz.example.org", &dir.join("data")).unwrap()
    }

    #[test]
    fn parses_options() {
        let o = parse_args(&args("--lightwalletd https://n:443 --network test")).unwrap();
        assert_eq!(o.network, Some(Network::Test));
        assert!(o.check);
        assert!(
            !parse_args(&args("--lightwalletd http://n --no-check"))
                .unwrap()
                .check
        );
        for bad in [
            "",
            "--network main",
            "--lightwalletd n:8137",
            "--lightwalletd http://a --lightwalletd http://b",
            "--lightwalletd http://a --network mainnet",
            "--lightwalletd",
        ] {
            assert!(
                matches!(parse_args(&args(bad)), Err(SetChainError::Usage(_))),
                "{bad}"
            );
        }
        let e = parse_args(&args("http://user:SECRET@host")).unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
    }

    #[test]
    fn rewrites_only_the_chain_lines_and_keeps_comments() {
        let dir = crate::files::TestDir::new("set-chain-rewrite");
        let text = init_config(&dir);
        let new = rewrite(
            &text,
            "http://host.docker.internal:9067",
            Some(Network::Test),
        )
        .unwrap();
        let c: Config = toml::from_str(&new).unwrap();
        assert_eq!(c.network, Network::Test);
        assert_eq!(
            c.chain.unwrap().lightwalletd,
            "http://host.docker.internal:9067"
        );
        // Every comment survives, and only two lines changed.
        let changed = text
            .lines()
            .zip(new.lines())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(changed, 2);
        assert_eq!(text.lines().count(), new.lines().count());
    }

    #[test]
    fn adds_a_missing_chain_table_or_key() {
        let base =
            "listen = \"127.0.0.1:1\"\nnetwork = \"main\"\n\n[push]\nmax_devices_per_account = 3\n";
        let new = rewrite(base, "http://n:1", None).unwrap();
        assert!(new.ends_with("[chain]\nlightwalletd = \"http://n:1\"\n"));
        assert!(new.contains("max_devices_per_account = 3"));

        let with_table = "network = \"main\"\n[chain]\npoll_secs = 7\n[push]\n";
        let new = rewrite(with_table, "http://n:1", None).unwrap();
        assert!(new.contains("[chain]\nlightwalletd = \"http://n:1\"\npoll_secs = 7\n"));
    }

    #[tokio::test]
    async fn writes_owner_only_and_refuses_what_it_cant_verify() {
        let dir = crate::files::TestDir::new("set-chain-run");
        let path = dir.join("config.toml");
        std::fs::write(&path, init_config(&dir)).unwrap();

        // An unreachable source fails the check, and nothing changes.
        let before = std::fs::read_to_string(&path).unwrap();
        let opts = parse_args(&args("--lightwalletd http://127.0.0.1:1")).unwrap();
        let e = run(&path, &opts).await.unwrap_err();
        assert!(matches!(e, SetChainError::CheckFailed(_)), "{e}");
        assert!(!e.to_string().contains("127.0.0.1"), "no URL in messages");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        // Without the check it writes, keeping 0600.
        let opts = parse_args(&args(
            "--lightwalletd http://127.0.0.1:1 --network test --no-check",
        ))
        .unwrap();
        let out = run(&path, &opts).await.unwrap();
        assert!(out.check.is_none() && out.network_changed);
        let c = Config::load(&path).unwrap();
        assert_eq!(c.network, Network::Test);
        assert_eq!(c.chain.unwrap().lightwalletd, "http://127.0.0.1:1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // A layout the line edit can't handle (a dotted key) is refused.
        let dotted = before.replace(
            "\n[chain]\nlightwalletd = \"http://zaino:8137\"\npoll_secs = 5\n",
            "\n",
        );
        let dotted = dotted.replacen(
            "network = \"main\"",
            "network = \"main\"\nchain.lightwalletd = \"http://zaino:8137\"",
            1,
        );
        assert!(
            toml::from_str::<Config>(&dotted).is_ok(),
            "still a valid config"
        );
        std::fs::write(&path, &dotted).unwrap();
        let opts = parse_args(&args("--lightwalletd http://n:2 --no-check")).unwrap();
        assert!(matches!(
            run(&path, &opts).await.unwrap_err(),
            SetChainError::Layout
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), dotted);
    }
}
