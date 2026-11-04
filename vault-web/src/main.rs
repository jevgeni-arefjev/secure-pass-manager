//! `vault-web` server: HTTPS for the browser client. Design: `web-app-security.md`.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;

use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use tracing_subscriber::filter::LevelFilter;
use vault_core::storage::FileStore;
use vault_web::AppConfig;
use vault_web::args::Args;

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
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(LevelFilter::INFO)
        .with_target(false)
        .init();
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
    let app = vault_web::app(AppConfig::new(vault_dir, port));

    let handle = Handle::new();
    let listening = handle.clone();
    tokio::spawn(async move {
        if listening.listening().await.is_some() {
            println!("vault-web: serving https://localhost:{port}");
        }
    });
    axum_server::bind_rustls(args.bind, RustlsConfig::from_config(Arc::new(tls)))
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .map_err(|err| format!("could not serve on {}: {err}", args.bind))
}
