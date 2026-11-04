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

/// The whole HTTP app (client bundle and API) built from `config`, without TLS: the
/// binary serves it over HTTPS, tests drive it in-process with `tower::ServiceExt::oneshot`.
///
/// Security: requests not addressed to `localhost:<port>` or `127.0.0.1:<port>` are
/// refused, state-changing requests must come from the server's own origin, and every
/// response carries the security headers and `Cache-Control: no-store`. Sessions live
/// in this app instance only.
///
/// ```
/// let app = vault_web::app(vault_web::AppConfig::new("/tmp/web-vaults", 8443));
/// # let _ = app;
/// ```
pub fn app(config: AppConfig) -> Router {
    Router::new()
        .route("/", get(assets::index))
        .route("/{file}", get(assets::file))
        .nest("/api", api::router())
        .with_state(AppState::new(config.clone()))
        .layer(axum::middleware::from_fn(middleware::origin_check))
        .layer(axum::middleware::from_fn_with_state(
            config,
            middleware::host_check,
        ))
        .layer(axum::middleware::from_fn(middleware::request_log))
        .layer(axum::middleware::from_fn(middleware::security_headers))
}
