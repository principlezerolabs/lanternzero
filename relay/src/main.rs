//! `lz-relay <config.toml>` runs the relay (relay/DESIGN.md).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use lz_relay::config::Config;
use lz_relay::{AppState, log_totals, serve};

/// How often the relay logs its totals.
const TOTALS_EVERY: Duration = Duration::from_secs(3600);

#[tokio::main]
async fn main() -> ExitCode {
    // Colors only on a terminal: under Docker, escape codes would land in
    // the log files.
    tracing_subscriber::fmt()
        .with_env_filter(lz_relay::log_filter("info"))
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path] = args.as_slice() else {
        tracing::error!("usage: lz-relay <config.toml>");
        return ExitCode::FAILURE;
    };
    let config = match Config::load(&PathBuf::from(path)) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "bad config");
            return ExitCode::FAILURE;
        }
    };
    if !lz_relay::disable_core_dumps() {
        tracing::warn!("could not turn off core dumps");
    }
    if config.allow_private_targets {
        tracing::warn!("allow_private_targets is set: for tests only");
    }
    let listen = config.listen;
    let state = match AppState::new(config) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, %listen, "cannot listen");
            return ExitCode::FAILURE;
        }
    };
    tokio::spawn(log_totals(state.clone(), TOTALS_EVERY));
    tracing::info!(%listen, "relaying");
    match serve(listener, state, shutdown_signal()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "server error");
            ExitCode::FAILURE
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
