//! `lz-gateway <config.toml>` runs the push gateway.
//!
//! `lz-gateway rotate-key <config.toml> [--drop-old]` makes a new
//! endpoint-sealing key, used from the gateway's next start. Old keys keep
//! opening their endpoints until those expire; `--drop-old`, for a
//! suspected leak, drops them now and so invalidates every endpoint.

use std::path::PathBuf;
use std::process::ExitCode;

use lz_gateway::config::Config;
use lz_gateway::{AppState, app};

#[tokio::main]
async fn main() -> ExitCode {
    // Colors only on a terminal: under Docker, escape codes would land in
    // the log files.
    tracing_subscriber::fmt()
        .with_env_filter(lz_gateway::log_filter("info"))
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (path, rotate) = match args.as_slice() {
        [path] => (*path, None),
        ["rotate-key", path] => (*path, Some(false)),
        ["rotate-key", path, "--drop-old"] => (*path, Some(true)),
        _ => {
            tracing::error!(
                "usage: lz-gateway <config.toml> | lz-gateway rotate-key <config.toml> [--drop-old]"
            );
            return ExitCode::FAILURE;
        }
    };
    let config = match Config::load(&PathBuf::from(path)) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "bad config");
            return ExitCode::FAILURE;
        }
    };
    if let Some(drop_old) = rotate {
        let now = lz_gateway::now_unix();
        return match lz_gateway::keys::KeyRing::rotate(&config.data_dir, now, drop_old) {
            Ok(id) => {
                tracing::info!(
                    key_id = id,
                    drop_old,
                    "new sealing key; restart the gateway to use it"
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                tracing::error!(error = %e, "rotation failed");
                ExitCode::FAILURE
            }
        };
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
    tracing::info!(%listen, "serving");
    match axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "server error");
            ExitCode::FAILURE
        }
    }
}

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
