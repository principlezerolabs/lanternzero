//! `lz-gateway <config.toml>` runs the push gateway.

use std::path::PathBuf;
use std::process::ExitCode;

use lz_gateway::config::Config;
use lz_gateway::{AppState, router};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(lz_gateway::log_filter("info"))
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path] = args.as_slice() else {
        tracing::error!("usage: lz-gateway <config.toml>");
        return ExitCode::FAILURE;
    };
    let config = match Config::load(&PathBuf::from(path)) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "bad config");
            return ExitCode::FAILURE;
        }
    };
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
    match axum::serve(listener, router(state))
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
