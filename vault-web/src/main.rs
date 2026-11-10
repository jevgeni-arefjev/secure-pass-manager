//! `vault-web` server: HTTPS for the browser client. Design: `web-app-security.md`.
#![forbid(unsafe_code)]

use std::io;
use std::process::ExitCode;
use std::sync::Arc;

use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use vault_core::storage::{FileStore, StorageError};
use vault_web::args::Args;
use vault_web::{App, AppConfig};

/// Entry point: installs the JSON diagnostics and the panic hook, then hardens the
/// process before anything else (even flag parsing and the async runtime), refusing
/// to start if core dumps can't be disabled; then sets up TLS and serves the app until
/// the process is stopped. A failure to start is one `startup_failed` JSON line
/// ([`StartupError`]); a bad flag is clap's usage message.
///
/// ```text
/// $ vault-web --bind 127.0.0.1:8443
/// vault-web: serving https://localhost:8443
/// ```
fn main() -> ExitCode {
    vault_web::logging::init(std::io::stderr);
    log_panics_without_message();
    if vault_core::crypto::harden_process().is_err() {
        return StartupError::new("core_dumps").report();
    }
    let args = Args::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => return StartupError::with_kind("async_runtime", err.kind()).report(),
    };
    match runtime.block_on(serve(&args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => err.report(),
    }
}

/// Why the server couldn't start: a fixed cause name and, for a file system failure,
/// its [`io::ErrorKind`].
///
/// Security: like every other diagnostic (ADR-0014), it carries no path and no OS or
/// library error text; the operator knows which paths and flags they passed.
struct StartupError {
    /// What failed, e.g. `vault_directory` or `tls_key_invalid`.
    cause: &'static str,
    /// The file system cause kind, if the failure was one.
    kind: Option<io::ErrorKind>,
}

impl StartupError {
    /// A failure with no file system cause kind.
    ///
    /// ```ignore
    /// return Err(StartupError::new("no_data_directory"));
    /// ```
    fn new(cause: &'static str) -> Self {
        Self { cause, kind: None }
    }

    /// A file system failure of kind `kind`.
    ///
    /// ```ignore
    /// StartupError::with_kind("bind", err.kind())
    /// ```
    fn with_kind(cause: &'static str, kind: io::ErrorKind) -> Self {
        Self {
            cause,
            kind: Some(kind),
        }
    }

    /// Logs the failure as one `startup_failed` JSON line and returns the failure exit
    /// code.
    ///
    /// ```ignore
    /// return StartupError::new("core_dumps").report();
    /// // {"timestamp":"…","level":"ERROR","event":"startup_failed","cause":"core_dumps"}
    /// ```
    fn report(self) -> ExitCode {
        tracing::error!(
            event = "startup_failed",
            cause = self.cause,
            kind = self.kind.map(tracing::field::debug),
        );
        ExitCode::FAILURE
    }
}

impl From<vault_web::tls::TlsError> for StartupError {
    /// The TLS step that failed, by its fixed cause name and kind.
    ///
    /// ```ignore
    /// let tls = vault_web::tls::server_config(&source)?;
    /// ```
    fn from(err: vault_web::tls::TlsError) -> Self {
        Self {
            cause: err.cause(),
            kind: err.kind(),
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
/// `args.bind` (a loopback address, checked by [`Args`]) until stopped.
///
/// ```ignore
/// serve(&Args::parse()).await?;
/// ```
async fn serve(args: &Args) -> Result<(), StartupError> {
    let data_dir = dirs::data_dir().map(|dir| dir.join("secure-pass-manager"));
    // Without a platform data directory, --vault-dir (and --tls-cert/--tls-key) say
    // where to keep things.
    let vault_dir = args
        .vault_dir(data_dir.as_deref())
        .ok_or(StartupError::new("no_data_directory_for_vaults"))?;
    let cert_source = args
        .cert_source(data_dir.as_deref())
        .ok_or(StartupError::new("no_data_directory_for_tls"))?;

    FileStore::new(&vault_dir).map_err(|err| match err {
        StorageError::Io(kind) => StartupError::with_kind("vault_directory", kind),
        _ => StartupError::new("vault_directory"),
    })?;
    let tls = vault_web::tls::server_config(&cert_source)?;

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
        .map_err(|err| StartupError::with_kind("bind", err.kind()));
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
