//! `vault-web`: the HTTPS server for the browser client (ICS0027). The library builds
//! the whole HTTP app from an [`AppConfig`]; the binary parses flags, hardens the
//! process, sets up TLS and logging, and serves it.
//!
//! Design and threat model: `web-app-security.md`.
#![forbid(unsafe_code)]

mod api;
pub mod args;
pub mod assets;
mod auth;
pub mod config;
mod json;
mod kdf_limiter;
mod middleware;
mod sessions;
pub mod tls;

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use axum::routing::get;

pub use assets::Assets;
pub use config::{AppConfig, CreateFormat, KdfLimits};
pub use middleware::CONTENT_SECURITY_POLICY;

use kdf_limiter::KdfLimiter;
use sessions::Sessions;

/// What every handler can reach: the config, the session registry and the KDF limiter.
/// Cloning is cheap; all clones share the same sessions.
#[derive(Clone)]
pub(crate) struct AppState {
    config: AppConfig,
    sessions: Arc<Sessions>,
    kdf: Arc<KdfLimiter>,
}

impl AppState {
    /// Fresh state for an app built from `config`: no sessions yet.
    ///
    /// ```ignore
    /// let state = AppState::new(config);
    /// ```
    fn new(config: AppConfig) -> Self {
        Self {
            sessions: Arc::new(Sessions::new(
                Arc::clone(&config.clock),
                config.session_lifetime,
            )),
            kdf: Arc::new(KdfLimiter::new(config.kdf_limits)),
            config,
        }
    }
}

impl FromRef<AppState> for Assets {
    /// Lets asset handlers take `State<Assets>` from the app state.
    ///
    /// ```ignore
    /// async fn index(State(assets): State<Assets>) -> Response { .. }
    /// ```
    fn from_ref(state: &AppState) -> Self {
        state.config.assets.clone()
    }
}

/// A response extension naming the session a response opened, as a short hash for the
/// request log (the request's own cookie names the old one, if any).
#[derive(Clone)]
pub(crate) struct SessionTag(String);

/// The HTTP app (client bundle and API) and the sessions it holds, built from a
/// config. The binary serves [`App::router`] over HTTPS, runs [`App::spawn_sweeper`]
/// and calls [`App::lock_all`] on SIGINT/SIGTERM; tests drive the router in-process
/// with `tower::ServiceExt::oneshot`.
///
/// Security: requests not addressed to `localhost:<port>` or `127.0.0.1:<port>` are
/// refused, state-changing requests must come from the server's own origin, and every
/// response carries the security headers and `Cache-Control: no-store`. Sessions live
/// in this app instance only, and end server-side: on lock, on the idle timeout, at
/// the absolute lifetime, on a panicking request and on shutdown.
///
/// ```
/// let app = vault_web::App::new(vault_web::AppConfig::new("/tmp/web-vaults", 8443));
/// let _router = app.router();
/// ```
#[derive(Clone)]
pub struct App {
    state: AppState,
}

impl App {
    /// A new app with no sessions yet.
    ///
    /// ```
    /// let app = vault_web::App::new(vault_web::AppConfig::new("/tmp/web-vaults", 8443));
    /// assert_eq!(app.session_count(), 0);
    /// ```
    pub fn new(config: AppConfig) -> Self {
        Self {
            state: AppState::new(config),
        }
    }

    /// The router serving every request; all clones share this app's sessions.
    ///
    /// ```
    /// # let app = vault_web::App::new(vault_web::AppConfig::new("/tmp/web-vaults", 8443));
    /// let service = app.router().into_make_service();
    /// # let _ = service;
    /// ```
    pub fn router(&self) -> Router {
        let config = self.state.config.clone();
        Router::new()
            .route("/", get(assets::index))
            .route("/{file}", get(assets::file))
            .nest("/api", api::router())
            .with_state(self.state.clone())
            .layer(axum::middleware::from_fn(middleware::origin_check))
            .layer(axum::middleware::from_fn_with_state(
                config,
                middleware::host_check,
            ))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&self.state.sessions),
                middleware::catch_panic,
            ))
            .layer(axum::middleware::from_fn(middleware::request_log))
            .layer(axum::middleware::from_fn(middleware::security_headers))
    }

    /// Ends every session past its idle timeout (auto-locked, as such in the audit log)
    /// or the absolute lifetime: removed and its keys wiped, so its cookie gets a 401.
    /// Returns how many ended.
    ///
    /// Blocks while a request holds a session's vault; from async code, use
    /// [`App::spawn_sweeper`] or `spawn_blocking`.
    ///
    /// ```
    /// # let app = vault_web::App::new(vault_web::AppConfig::new("/tmp/web-vaults", 8443));
    /// assert_eq!(app.sweep(), 0);
    /// ```
    pub fn sweep(&self) -> usize {
        let ended = self.state.sessions.sweep();
        if ended > 0 {
            tracing::info!(event = "sessions_expired", count = ended);
        }
        ended
    }

    /// Starts a task running [`App::sweep`] on the blocking pool every
    /// `config.sweep_interval`, until aborted or the runtime stops. Call it inside a
    /// Tokio runtime.
    ///
    /// ```ignore
    /// let sweeper = app.spawn_sweeper();
    /// ```
    pub fn spawn_sweeper(&self) -> tokio::task::JoinHandle<()> {
        let mut interval = tokio::time::interval(self.state.config.sweep_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let app = self.clone();
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                let app = app.clone();
                // A failed sweep (a panic) is retried on the next tick; lookups still
                // refuse expired sessions meanwhile.
                let _ = tokio::task::spawn_blocking(move || app.sweep()).await;
            }
        })
    }

    /// Removes every session and wipes its keys, recorded in each vault's audit log as
    /// a termination signal; every cookie then gets a 401. Returns how many were open.
    ///
    /// Blocks while a request holds a session's vault; from async code, use
    /// `spawn_blocking`.
    ///
    /// ```
    /// # let app = vault_web::App::new(vault_web::AppConfig::new("/tmp/web-vaults", 8443));
    /// assert_eq!(app.lock_all(), 0); // e.g. on SIGTERM
    /// ```
    pub fn lock_all(&self) -> usize {
        self.state.sessions.lock_all()
    }

    /// How many sessions the app holds, including expired ones not yet swept.
    ///
    /// ```
    /// # let app = vault_web::App::new(vault_web::AppConfig::new("/tmp/web-vaults", 8443));
    /// assert_eq!(app.session_count(), 0);
    /// ```
    pub fn session_count(&self) -> usize {
        self.state.sessions.len()
    }
}
