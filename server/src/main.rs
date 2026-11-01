//! `lz-server <config.toml>` runs the server.
//! `lz-server <config.toml> init …` writes the config, keys, and first
//! account for a self-hosted server (deploy/DESIGN.md; `init` with no
//! options prints its usage).
//! `lz-server <config.toml> new-account` creates an account and prints its
//! connection URL once (self-hosting; spec §2.3).
//! `lz-server <config.toml> rotate-vapid [--drop-old]` replaces the VAPID
//! key, used from the next start (spec §5.3). Stop the server first.
//! `lz-server <config.toml> rotate-ohttp [--drop-old]` replaces the OHTTP
//! key; a running server serves it within 5 minutes, and accepts the old
//! one for 7 days (spec §3.2).
//! `lz-server <config.toml> doctor` checks the install and prints pass,
//! warn, or fail for each check, with nothing secret in the output.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use lz_server::config::Config;
use lz_server::{AppState, chain, gateway, mempool, push, scanner};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(lz_server::log_filter("info"))
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    // `init` writes the config, so it runs before any config is loaded.
    if let [c, cmd, rest @ ..] = args.as_slice()
        && cmd == "init"
    {
        return init(&PathBuf::from(c), rest);
    }
    let (config_path, command, flag) = match args.as_slice() {
        [c] => (PathBuf::from(c), None, None),
        [c, cmd] => (PathBuf::from(c), Some(cmd.as_str()), None),
        [c, cmd, flag] => (PathBuf::from(c), Some(cmd.as_str()), Some(flag.as_str())),
        _ => {
            tracing::error!(
                "usage: lz-server <config.toml> [init … | new-account | rotate-vapid [--drop-old] | rotate-ohttp [--drop-old] | doctor]"
            );
            return ExitCode::FAILURE;
        }
    };
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "bad config");
            return ExitCode::FAILURE;
        }
    };

    match (command, flag) {
        (None, _) => serve(config).await,
        (Some("new-account"), None) => new_account(&config),
        (Some("doctor"), None) => doctor(&config).await,
        (Some("rotate-vapid"), None) => rotate_vapid(&config, false),
        (Some("rotate-vapid"), Some("--drop-old")) => rotate_vapid(&config, true),
        (Some("rotate-ohttp"), None) => rotate_ohttp(&config, false),
        (Some("rotate-ohttp"), Some("--drop-old")) => rotate_ohttp(&config, true),
        (Some(other), _) => {
            tracing::error!(command = other, "unknown command or option");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> ExitCode {
    // Before any key is loaded (spec §6.2).
    let report = lz_server::hardening::apply();
    let scanning = config.chain.is_some();
    match lz_server::hardening::verdict(&report, scanning, &config.hardening) {
        lz_server::hardening::Verdict::Ok => {
            tracing::info!(memory = ?report.memory, swap = ?report.swap, "memory hygiene ok");
        }
        lz_server::hardening::Verdict::Warn => {
            tracing::warn!(
                memory = ?report.memory,
                swap = ?report.swap,
                core_dumps_off = report.core_dumps_off,
                scanning,
                allow_swap = config.hardening.allow_swap,
                "swap may hold this process's memory; run `doctor` for how to fix it"
            );
        }
        lz_server::hardening::Verdict::Refuse => {
            tracing::error!(
                memory = ?report.memory,
                swap = ?report.swap,
                core_dumps_off = report.core_dumps_off,
                "refusing to start: viewing keys could reach swap or a core dump \
                 (spec §6.2); run `doctor` for how to fix it"
            );
            return ExitCode::FAILURE;
        }
    }
    let listen = config.listen;
    let state = match AppState::new(config) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            return ExitCode::FAILURE;
        }
    };
    tokio::spawn(push::run(state.clone()));
    match (&state.config.chain, &state.chain_source) {
        (Some(c), Some(source)) => {
            tokio::spawn(chain::run(
                state.chain.clone(),
                source.clone(),
                state.config.network,
                Duration::from_secs(c.poll_secs),
            ));
            tokio::spawn(scanner::run(state.clone()));
            tokio::spawn(mempool::run(state.clone()));
            tokio::spawn(lz_server::webhook::run(state.clone()));
        }
        _ => tracing::warn!("no [chain] configured: tip stays 0 and nothing is scanned"),
    }
    tokio::spawn(scanner::sweep_loop(state.clone()));
    tokio::spawn(lz_server::account_sweep_loop(state.clone()));
    tokio::spawn(lz_server::ohttp_key_sweep_loop(state.clone()));
    if state.config.accounts.issuer_socket {
        #[cfg(unix)]
        {
            let listener = match lz_server::issuer::bind(&state.config.data_dir) {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "cannot serve the issuer socket");
                    return ExitCode::FAILURE;
                }
            };
            let app = lz_server::issuer::router(state.clone());
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!(error = %e, "issuer socket stopped");
                }
            });
            tracing::info!("serving the issuer interface on data_dir/issuer.sock");
        }
        #[cfg(not(unix))]
        {
            tracing::error!("accounts.issuer_socket needs a Unix system");
            return ExitCode::FAILURE;
        }
    }
    let flusher = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            flusher.flush_store().await;
        }
    });

    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, %listen, "cannot listen");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(%listen, "serving");
    let app = gateway::router(state.clone());
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    state.store.flush_if_dirty();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "server error");
            ExitCode::FAILURE
        }
    }
}

/// Resolves on Ctrl-C, or on SIGTERM (`docker stop`, `systemctl stop`), so
/// replay state is flushed before exit.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = term => {}
    }
    tracing::info!("shutting down");
}

/// Prints each check; fails if any check failed.
#[allow(clippy::print_stdout)] // Deliberate: the report is the output.
async fn doctor(config: &Config) -> ExitCode {
    let checks = lz_server::doctor::run(config).await;
    for c in &checks {
        println!("{c}");
    }
    if checks
        .iter()
        .any(|c| c.status == lz_server::doctor::Status::Fail)
    {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Retires the OHTTP key (spec §3.2). A running server switches within
/// [`lz_server::OHTTP_KEY_RELOAD`]; no restart is needed.
fn rotate_ohttp(config: &Config, drop_old: bool) -> ExitCode {
    match lz_server::rotate_ohttp(&config.data_dir, drop_old) {
        Ok(key_id) => {
            tracing::info!(
                key_id,
                drop_old,
                "new OHTTP key; a running server serves it within 5 minutes"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "OHTTP key rotation failed");
            ExitCode::FAILURE
        }
    }
}

/// Retires the VAPID key (spec §5.3). Devices keep the key they were
/// registered under; wallets move to the new one when `info` shows it.
/// `--drop-old` is for a suspected leak: devices bound to old keys are
/// dropped at the next start and register again.
fn rotate_vapid(config: &Config, drop_old: bool) -> ExitCode {
    match lz_server::rotate_vapid(&config.data_dir, drop_old) {
        Ok(public) => {
            tracing::info!(
                vapid_public_key = %public,
                drop_old,
                "new VAPID key; start the server to use it"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "VAPID rotation failed");
            ExitCode::FAILURE
        }
    }
}

/// Generates a token on this machine, stores only its hash, and prints the
/// connection URL once. The running server picks it up on restart.
#[allow(clippy::print_stdout)] // Deliberate: the operator must see the URL once.
fn new_account(config: &Config) -> ExitCode {
    match lz_server::init::new_account_url(config) {
        Ok(url) => {
            println!("{}", url.as_str());
            println!("Restart the server to load the new account. This URL is shown only once.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "cannot create the account");
            ExitCode::FAILURE
        }
    }
}

/// Writes the config, data directory, and server keys, and prints the
/// first account's connection URL once (deploy/DESIGN.md).
#[allow(clippy::print_stdout)] // Deliberate: the operator must see the URL once.
fn init(config_path: &std::path::Path, args: &[String]) -> ExitCode {
    let opts = match lz_server::init::parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match lz_server::init::run(config_path, &opts) {
        Ok(url) => {
            println!("Your connection URL (paste it into your wallet; shown only once):");
            println!();
            println!("{}", url.as_str());
            println!();
            println!("Then start the server, and check it with `doctor`.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "init failed");
            ExitCode::FAILURE
        }
    }
}
