//! `vault-web` server: HTTPS for the browser client. Design: `web-app-security.md`.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;

use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use vault_core::storage::FileStore;
use vault_web::args::Args;
use vault_web::{App, AppConfig};

/// Entry point: hardens the process before anything else (even the async runtime),
/// refusing to start if core dumps can't be disabled; then parses flags, sets up
/// logging and TLS, and serves the app until the process is stopped.
///
/// ```text
/// $ vault-web --bind 127.0.0.1:8443
/// vault-web: serving https://localhost:8443
/// ```
fn main() -> ExitCode {
    if vault_core::crypto::harden_process().is_err() {
        eprintln!("vault-web: could not disable core dumps; refusing to start");
        return ExitCode::FAILURE;
    }
    let args = Args::parse();
    vault_web::logging::init(std::io::stderr);
    log_panics_without_message();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("vault-web: could not start the async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve(&args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("vault-web: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Replaces the default panic hook, which prints the panic message to stderr, with one
/// logging only where the panic happened.
///
/// Security: a panic message can carry request data (e.g. an `unwrap` printing a
/// value); the location identifies the bug without it. The request still gets a
/// generic 500 and its session ends (`middleware::catch_panic`).
///
/// ```ignore
/// log_panics_without_message();
/// ```
fn log_panics_without_message() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map_or_else(
            || "unknown".to_owned(),
            |l| format!("{}:{}", l.file(), l.line()),
        );
        tracing::error!(event = "panic", location = %location);
    }));
}

/// Prepares the vault directory and TLS from `args`, then serves the app on
/// `args.bind` until stopped. Errors are one-line messages for the operator.
///
/// Security: warns if bound to anything but a loopback address, since other machines
/// could then reach the server (the Host check still refuses foreign names).
///
/// ```ignore
/// serve(&Args::parse()).await?;
/// ```
async fn serve(args: &Args) -> Result<(), String> {
    let data_dir = dirs::data_dir().map(|dir| dir.join("secure-pass-manager"));
    let vault_dir = args
        .vault_dir(data_dir.as_deref())
        .ok_or("no platform data directory; pass --vault-dir")?;
    let cert_source = args
        .cert_source(data_dir.as_deref())
        .ok_or("no platform data directory; pass --tls-cert and --tls-key")?;

    FileStore::new(&vault_dir)
        .map_err(|_| format!("could not open the vault directory {}", vault_dir.display()))?;
    let tls = vault_web::tls::server_config(&cert_source).map_err(|err| err.to_string())?;

    if !args.bind.ip().is_loopback() {
        tracing::warn!(event = "bind_not_loopback");
    }
    let port = args.bind.port();
    let app = App::new(AppConfig::new(vault_dir, port));
    app.spawn_sweeper();

    let handle = Handle::new();
    let listening = handle.clone();
    tokio::spawn(async move {
        if listening.listening().await.is_some() {
            println!("vault-web: serving https://localhost:{port}");
        }
    });
    tokio::spawn(stop_on_signal(app.clone(), handle.clone()));
    let served = axum_server::bind_rustls(args.bind, RustlsConfig::from_config(Arc::new(tls)))
        .handle(handle)
        .serve(app.router().into_make_service())
        .await
        .map_err(|err| format!("could not serve on {}: {err}", args.bind));
    // Also covers a session opened while the server was stopping, and a serve error.
    lock_all_on_shutdown(&app).await;
    served
}

/// Waits for SIGINT or SIGTERM, locks every session, then stops the server at once
/// (open connections are dropped, so no request can use a session afterwards). A
/// second signal exits at once, in case locking waits on a stuck request.
///
/// Security: keys are wiped before the process exits, each lock recorded as a
/// termination signal in its vault's audit log. If the handlers can't be installed,
/// the signals keep their default action (exit without locking; keys die with the
/// process, never written to disk).
///
/// ```ignore
/// tokio::spawn(stop_on_signal(app.clone(), handle.clone()));
/// ```
async fn stop_on_signal(app: App, handle: Handle<std::net::SocketAddr>) {
    let (Ok(mut interrupt), Ok(mut terminate)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        tracing::warn!(event = "signal_handlers_unavailable");
        return;
    };
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
    }
    tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        tracing::warn!(event = "forced_exit");
        std::process::exit(1);
    });
    lock_all_on_shutdown(&app).await;
    handle.shutdown();
}

/// Locks every session of `app` on the blocking pool, refusing new ones from then on,
/// and logs how many were open.
///
/// ```ignore
/// lock_all_on_shutdown(&app).await;
/// ```
async fn lock_all_on_shutdown(app: &App) {
    let app = app.clone();
    if let Ok(locked) = tokio::task::spawn_blocking(move || app.lock_all()).await
        && locked > 0
    {
        tracing::info!(event = "sessions_locked_on_shutdown", count = locked);
    }
}
