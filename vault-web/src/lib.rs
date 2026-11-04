//! `vault-web`: the HTTPS server for the browser client (ICS0027). The library builds
//! the whole HTTP app from an [`AppConfig`]; the binary parses flags, hardens the
//! process, sets up TLS and logging, and serves it.
//!
//! Design and threat model: `web-app-security.md`.
#![forbid(unsafe_code)]

mod api;
pub mod args;
pub mod assets;
pub mod config;
mod middleware;
pub mod tls;

use axum::Router;
use axum::extract::FromRef;
use axum::routing::get;

pub use assets::Assets;
pub use config::{AppConfig, CreateFormat, KdfLimits};
pub use middleware::CONTENT_SECURITY_POLICY;

impl FromRef<AppConfig> for Assets {
    /// Lets asset handlers take `State<Assets>` from the app config.
    ///
    /// ```ignore
    /// async fn index(State(assets): State<Assets>) -> Response { .. }
    /// ```
    fn from_ref(config: &AppConfig) -> Self {
        config.assets.clone()
    }
}

/// The whole HTTP app (client bundle and API) built from `config`, without TLS: the
/// binary serves it over HTTPS, tests drive it in-process with `tower::ServiceExt::oneshot`.
///
/// Security: requests not addressed to `localhost:<port>` or `127.0.0.1:<port>` are
/// refused, and every response carries the security headers and `Cache-Control: no-store`.
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
        .with_state(config.clone())
        .layer(axum::middleware::from_fn_with_state(
            config,
            middleware::host_check,
        ))
        .layer(axum::middleware::from_fn(middleware::request_log))
        .layer(axum::middleware::from_fn(middleware::security_headers))
}
