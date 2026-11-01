//! `lz-server <config.toml>` runs the server.
//! `lz-server <config.toml> new-account` creates an account and prints its
//! connection URL once (self-hosting; spec §2.3).
//! `lz-server <config.toml> rotate-vapid [--drop-old]` replaces the VAPID
//! key, used from the next start (spec §5.3).
//! `lz-server <config.toml> doctor` checks the install and prints pass,
//! warn, or fail for each check, with nothing secret in the output.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use lz_proto::token::AccountToken;
use lz_server::config::Config;
use lz_server::store::Store;
use lz_server::{AppState, chain, gateway, mempool, push, scanner};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(lz_server::log_filter("info"))
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let (config_path, command, flag) = match args.as_slice() {
        [c] => (PathBuf::from(c), None, None),
        [c, cmd] => (PathBuf::from(c), Some(cmd.as_str()), None),
        [c, cmd, flag] => (PathBuf::from(c), Some(cmd.as_str()), Some(flag.as_str())),
        _ => {
            tracing::error!(
                "usage: lz-server <config.toml> [new-account | rotate-vapid [--drop-old] | doctor]"
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
        }
        _ => tracing::warn!("no [chain] configured: tip stays 0 and nothing is scanned"),
    }
    tokio::spawn(scanner::sweep_loop(state.clone()));
    let flusher = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            flusher.store.flush_if_dirty();
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
                "new VAPID key; restart the server to use it"
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
    if let Err(e) = lz_server::keys::create_private_dir(&config.data_dir) {
        tracing::error!(error = %e, "cannot create data_dir");
        return ExitCode::FAILURE;
    }
    let token = match AccountToken::generate() {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "cannot generate token");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = Store::add_account_to_file(&config.data_dir, &token.hash()) {
        tracing::error!(error = %e, "cannot write account");
        return ExitCode::FAILURE;
    }
    println!(
        "lanternzero://{}{}#{}",
        config.public_host,
        config.base_path,
        token.encode().as_str()
    );
    println!("Restart the server to load the new account. This URL is shown only once.");
    ExitCode::SUCCESS
}
