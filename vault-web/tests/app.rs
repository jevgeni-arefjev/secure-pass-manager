//! Behaviour of the `vault-web` HTTP app, driven in-process through
//! `tower::ServiceExt::oneshot` on a temp vault directory and a manual clock: no TLS,
//! no sockets.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, Response, StatusCode, header};
use tempfile::TempDir;
use tower::ServiceExt;
use vault_core::session::Clock;
use vault_web::{AppConfig, Assets, CreateFormat};

const PORT: u16 = 8443;
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
    connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; \
    require-trusted-types-for 'script'";

/// A clock that only moves when told to (sleeping moves it too).
struct ManualClock {
    start: Instant,
    elapsed: Mutex<Duration>,
}

impl Clock for ManualClock {
    /// The start instant plus the time advanced so far.
    fn now(&self) -> Instant {
        self.start + *self.elapsed.lock().unwrap()
    }

    /// A fixed epoch plus the time advanced so far.
    fn unix_time(&self) -> u64 {
        1_800_000_000 + self.elapsed.lock().unwrap().as_secs()
    }

    /// Advances the clock instead of sleeping.
    fn sleep(&self, duration: Duration) {
        *self.elapsed.lock().unwrap() += duration;
    }
}

/// An app on a temp vault directory with a manual clock, the test vault format and
/// a small client bundle.
struct TestApp {
    _dir: TempDir,
    config: AppConfig,
}

impl TestApp {
    /// A test app serving a placeholder `index.html`, `app.js` and `app.css`.
    ///
    /// ```text
    /// let app = TestApp::new();
    /// ```
    fn new() -> Self {
        Self::with_assets(Assets::from_files([
            (
                "index.html",
                b"<!doctype html><title>vault</title>".to_vec(),
            ),
            ("app.js", b"console.log(1);".to_vec()),
            ("app.css", b"body{}".to_vec()),
        ]))
    }

    /// A test app serving `assets` as the client bundle.
    ///
    /// ```text
    /// let app = TestApp::with_assets(Assets::from_files::<_, &str, Vec<u8>>([]));
    /// ```
    fn with_assets(assets: Assets) -> Self {
        init_logging();
        let dir = tempfile::tempdir().unwrap();
        let mut config = AppConfig::new(dir.path().join("web-vaults"), PORT);
        config.clock = Arc::new(ManualClock {
            start: Instant::now(),
            elapsed: Mutex::new(Duration::ZERO),
        });
        config.create_format = CreateFormat::InsecureTest;
        config.assets = assets;
        Self { _dir: dir, config }
    }

    /// The HTTP app built from this config.
    ///
    /// ```text
    /// let response = app.router().oneshot(request).await?;
    /// ```
    fn router(&self) -> Router {
        vault_web::app(self.config.clone())
    }

    /// Sends one request through a fresh app.
    ///
    /// ```text
    /// let response = app.send(get("/")).await;
    /// ```
    async fn send(&self, request: Request<Body>) -> Response<Body> {
        self.router().oneshot(request).await.unwrap()
    }
}

/// A `GET path` request with the server's own `Host`.
///
/// ```text
/// let request = get("/app.js");
/// ```
fn get(path: &str) -> Request<Body> {
    get_with_host(path, &format!("localhost:{PORT}"))
}

/// A `GET path` request with `Host: host`.
///
/// ```text
/// let request = get_with_host("/", "evil.example:8443");
/// ```
fn get_with_host(path: &str, host: &str) -> Request<Body> {
    Request::get(path)
        .header(header::HOST, host)
        .body(Body::empty())
        .unwrap()
}

/// The response body as text.
///
/// ```text
/// assert!(body_text(response).await.contains("vault"));
/// ```
async fn body_text(response: Response<Body>) -> String {
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Asserts every security header from `web-app-security.md` is present with its exact value.
///
/// ```text
/// assert_security_headers(response.headers());
/// ```
fn assert_security_headers(headers: &HeaderMap) {
    let expect = [
        ("content-security-policy", CSP),
        ("strict-transport-security", "max-age=300"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("cache-control", "no-store"),
    ];
    for (name, value) in expect {
        assert_eq!(
            headers.get(name).and_then(|v| v.to_str().ok()),
            Some(value),
            "header {name}"
        );
    }
    let permissions = headers
        .get("permissions-policy")
        .and_then(|v| v.to_str().ok())
        .expect("permissions-policy");
    for feature in ["camera=()", "microphone=()", "geolocation=()"] {
        assert!(
            permissions.contains(feature),
            "permissions-policy {feature}"
        );
    }
}

#[tokio::test]
async fn html_page_carries_the_security_headers() {
    let app = TestApp::new();
    let response = app.send(get("/")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_security_headers(response.headers());
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert!(body_text(response).await.contains("<title>vault</title>"));
}

#[tokio::test]
async fn asset_carries_the_security_headers_and_its_content_type() {
    let app = TestApp::new();
    let response = app.send(get("/app.js")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_security_headers(response.headers());
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/javascript; charset=utf-8"
    );
    assert_eq!(body_text(response).await, "console.log(1);");
}

#[tokio::test]
async fn unknown_asset_is_404_with_the_security_headers() {
    let app = TestApp::new();
    let response = app.send(get("/missing.js")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_security_headers(response.headers());
}

#[tokio::test]
async fn unknown_api_route_is_a_json_404_with_the_security_headers() {
    let app = TestApp::new();
    let response = app.send(get("/api/nothing/here")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_security_headers(response.headers());
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(body_text(response).await, r#"{"error":"not found"}"#);
}

#[tokio::test]
async fn own_hosts_are_accepted() {
    let app = TestApp::new();
    for host in ["localhost:8443", "127.0.0.1:8443", "LocalHost:8443"] {
        let response = app.send(get_with_host("/", host)).await;
        assert_eq!(response.status(), StatusCode::OK, "host {host}");
    }
}

#[tokio::test]
async fn foreign_host_is_refused_with_the_security_headers() {
    let app = TestApp::new();
    for host in [
        "evil.example:8443",
        "localhost:9999",
        "localhost",
        "127.0.0.2:8443",
        "localhost.evil.example:8443",
        "[::1]:8443",
        "",
    ] {
        let response = app.send(get_with_host("/api/nothing", host)).await;
        assert_eq!(
            response.status(),
            StatusCode::MISDIRECTED_REQUEST,
            "host {host:?}"
        );
        assert_security_headers(response.headers());
        assert_eq!(body_text(response).await, r#"{"error":"unknown host"}"#);
    }
}

#[tokio::test]
async fn request_without_a_host_is_refused() {
    let app = TestApp::new();
    let request = Request::get("/").body(Body::empty()).unwrap();
    let response = app.send(request).await;
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn http2_authority_is_checked_when_there_is_no_host_header() {
    let app = TestApp::new();
    let own = Request::get("https://localhost:8443/")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.send(own).await.status(), StatusCode::OK);
    let foreign = Request::get("https://evil.example:8443/")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.send(foreign).await.status(),
        StatusCode::MISDIRECTED_REQUEST
    );
}

#[tokio::test]
async fn without_a_bundle_the_client_not_built_page_is_served() {
    let app = TestApp::with_assets(Assets::from_files::<_, &str, Vec<u8>>([]));
    let response = app.send(get("/")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_security_headers(response.headers());
    let page = body_text(response).await;
    assert!(page.contains("client not built"), "{page}");
    assert!(page.contains("npm run build"), "{page}");
    assert!(!page.contains("<script") && !page.contains("<style") && !page.contains("style="));

    let response = app.send(get("/app.js")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

thread_local! {
    /// Everything logged on this thread. Each `#[tokio::test]` runs the app on its own
    /// thread, so this holds exactly one test's logs.
    static LOGS: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// A `tracing` writer appending to this thread's [`LOGS`].
struct ThreadLogs;

impl std::io::Write for ThreadLogs {
    /// Appends `buf` to this thread's logs.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOGS.with(|logs| logs.borrow_mut().extend_from_slice(buf));
        Ok(buf.len())
    }

    /// Nothing to flush: writes go straight to memory.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs one global subscriber writing to [`ThreadLogs`], once per test binary.
/// A global one, because scoped subscribers race on `tracing`'s shared callsite
/// cache when tests run in parallel.
///
/// ```text
/// init_logging();
/// ```
fn init_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_writer(|| ThreadLogs)
            .with_ansi(false)
            .init();
    });
}

/// Sends `request` through `app` and returns what it logged.
///
/// ```text
/// let (response, logs) = send_logged(&app, get("/")).await;
/// ```
async fn send_logged(app: &TestApp, request: Request<Body>) -> (Response<Body>, String) {
    LOGS.with(|logs| logs.borrow_mut().clear());
    let response = app.send(request).await;
    let logs = LOGS.with(|logs| String::from_utf8(logs.take()).unwrap());
    (response, logs)
}

#[tokio::test]
async fn request_log_has_method_route_template_status_and_latency() {
    let app = TestApp::new();
    let (_, logs) = send_logged(&app, get("/app.js?token=hunter2")).await;
    assert!(logs.contains("method=GET"), "{logs}");
    assert!(logs.contains("route=/{file}"), "{logs}");
    assert!(logs.contains("status=200"), "{logs}");
    assert!(logs.contains("latency_ms="), "{logs}");
    assert!(
        !logs.contains("app.js") && !logs.contains("hunter2"),
        "{logs}"
    );
}

#[tokio::test]
async fn request_log_never_holds_the_concrete_path() {
    let app = TestApp::new();
    for path in [
        "/api/secrets/alice-github",
        "/alice-github",
        "/a/alice-github",
    ] {
        let (response, logs) = send_logged(&app, get(path)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(logs.contains("status=404"), "{logs}");
        assert!(!logs.contains("alice-github"), "{logs}");
    }
}

#[tokio::test]
async fn refused_host_is_logged_without_the_host() {
    let app = TestApp::new();
    let (_, logs) = send_logged(&app, get_with_host("/", "rebind.evil.example:8443")).await;
    assert!(logs.contains("status=421"), "{logs}");
    assert!(!logs.contains("evil"), "{logs}");
}
