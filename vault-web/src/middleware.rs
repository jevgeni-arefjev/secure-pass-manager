//! Middleware applied to every request: request logging, the Host check and
//! security headers on every response.

use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::AppConfig;
use crate::api::ApiError;

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

/// Logs one structured line per request: method, route template (e.g. `/{file}`),
/// status and latency. Requests no route matched are logged as route `unmatched`.
///
/// Security: never logs the concrete path, query, headers (cookies, Host) or body,
/// which can hold vaultnames, titles or session IDs.
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
    let started = Instant::now();
    let response = next.run(request).await;
    tracing::info!(
        method = %method,
        route = %route,
        status = response.status().as_u16(),
        latency_ms = started.elapsed().as_secs_f64() * 1000.0,
        "request"
    );
    response
}
