//! Middleware applied to every request: request logging, panic catching, the Host and
//! Origin checks and security headers on every response.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures_util::FutureExt;

use crate::api::ApiError;
use crate::auth::{is_state_changing, request_session_id};
use crate::sessions::Sessions;
use crate::{AppConfig, SessionTag, auth};

/// The Content Security Policy from `web-app-security.md`: same-origin code only, no
/// inline script or style, no framing, and Trusted Types for every DOM sink.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
    style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; \
    base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'";

/// Browser features the client never uses, all disabled.
const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), display-capture=(), \
    geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

/// Headers set on every response, overriding any a handler set.
///
/// HSTS is short on purpose: a long one on `localhost` would force HTTPS on every
/// other local dev server.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("content-security-policy", CONTENT_SECURITY_POLICY),
    ("strict-transport-security", "max-age=300"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    ("permissions-policy", PERMISSIONS_POLICY),
    ("cache-control", "no-store"),
];

/// Adds [`SECURITY_HEADERS`] to the response, whatever produced it (handler, 404,
/// refused request).
///
/// Security: `Cache-Control: no-store` everywhere keeps vault data out of the
/// browser's disk cache.
///
/// ```ignore
/// router.layer(axum::middleware::from_fn(security_headers))
/// ```
pub(crate) async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    response
}

/// Refuses (421) a request unless it names this server: its `Host` header and, if
/// present (HTTP/2, absolute-form), its URI authority must both be
/// `localhost:<port>` or `127.0.0.1:<port>`, and at least one must be there.
///
/// Security: blocks DNS rebinding, where a malicious site's domain resolves to the
/// local server and its scripts would otherwise reach the API same-origin.
///
/// ```ignore
/// router.layer(axum::middleware::from_fn_with_state(config, host_check))
/// ```
pub(crate) async fn host_check(
    State(config): State<AppConfig>,
    request: Request,
    next: Next,
) -> Response {
    let host_header = request
        .headers()
        .get(header::HOST)
        .map(|value| value.to_str().unwrap_or_default());
    let authority = request
        .uri()
        .authority()
        .map(|authority| authority.as_str());
    let named = [host_header, authority];
    let own = named.iter().any(Option::is_some)
        && named.iter().flatten().all(|host| config.is_own_host(host));
    if own {
        next.run(request).await
    } else {
        ApiError::UNKNOWN_HOST.into_response()
    }
}

/// Refuses (403) a state-changing request (anything but GET, HEAD, OPTIONS) unless its
/// `Origin` is `https://` plus the host it was sent to. Runs after [`host_check`], so
/// that host is one of the server's own.
///
/// Security: one of the two CSRF defences (with the per-session token). It covers
/// unlock and create too, which have no session yet, so another site can't log a
/// victim into an attacker's vault.
///
/// ```ignore
/// router.layer(axum::middleware::from_fn(origin_check))
/// ```
pub(crate) async fn origin_check(request: Request, next: Next) -> Response {
    if is_state_changing(request.method()) && !is_same_origin(&request) {
        return ApiError::CROSS_ORIGIN.into_response();
    }
    next.run(request).await
}

/// Whether `request`'s `Origin` is `https://<the host it was sent to>`, ignoring ASCII
/// case. `false` without an `Origin` header.
///
/// ```ignore
/// assert!(is_same_origin(&request)); // Host: localhost:8443, Origin: https://localhost:8443
/// ```
fn is_same_origin(request: &Request) -> bool {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str())
        });
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(|origin| origin.strip_prefix("https://"));
    match (host, origin) {
        (Some(host), Some(origin)) => origin.eq_ignore_ascii_case(host),
        _ => false,
    }
}

/// Catches a panic anywhere below it (handler, extractor or inner middleware) and
/// answers a generic 500 instead of dropping the connection. The session the request's
/// cookie named is removed and its keys wiped, and the response deletes the cookie.
///
/// Security: a request that panicked may have left its session's vault half-used, so
/// the session ends rather than staying open. No audit event is written (ADR-0014):
/// there is no reliable "locked" to record mid-panic. The response and the log carry no
/// panic message (it could hold request data); only an `event = "request_panicked"`
/// line, plus whatever the process panic hook prints.
///
/// ```ignore
/// router.layer(axum::middleware::from_fn_with_state(sessions, catch_panic))
/// ```
pub(crate) async fn catch_panic(
    State(sessions): State<Arc<Sessions>>,
    request: Request,
    next: Next,
) -> Response {
    let key = request_session_id(request.headers()).map(|id| id.key());
    match AssertUnwindSafe(next.run(request)).catch_unwind().await {
        Ok(response) => response,
        Err(_) => {
            tracing::error!(event = "request_panicked");
            let mut response = ApiError::INTERNAL.into_response();
            if let Some(key) = key {
                // On the blocking pool: wiping waits for any other request of this
                // session to release the vault (a mutex poisoned by the panic is
                // recovered).
                let _ = tokio::task::spawn_blocking(move || sessions.end_after_panic(key)).await;
                response.headers_mut().extend(auth::ended_session_headers());
            }
            response
        }
    }
}

/// Logs one structured line per request: method, route template (e.g. `/{file}`),
/// status, latency and a short hash of the session ID (the one a response opened, else
/// the request cookie's; `-` for none). Requests no route matched are logged as route
/// `unmatched`.
///
/// Security: never logs the concrete path, query, headers (cookies, Host), body or
/// session ID, which can hold vaultnames, titles or credentials.
///
/// ```ignore
/// router.layer(axum::middleware::from_fn(request_log))
/// ```
pub(crate) async fn request_log(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |path| path.as_str().to_owned());
    let request_session = request_session_id(request.headers()).map(|id| id.key().tag());
    let started = Instant::now();
    let response = next.run(request).await;
    let session = response
        .extensions()
        .get::<SessionTag>()
        .map(|tag| tag.0.clone())
        .or(request_session)
        .unwrap_or_else(|| "-".to_owned());
    tracing::info!(
        event = "request",
        method = %method,
        route = %route,
        status = response.status().as_u16(),
        latency_ms = started.elapsed().as_secs_f64() * 1000.0,
        session = %session,
    );
    response
}
