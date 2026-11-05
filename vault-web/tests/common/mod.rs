//! Shared helpers for the `vault-web` HTTP app tests: a test app on a temp vault
//! directory with a manual clock, request builders and log capture.
#![allow(dead_code)] // each test binary uses a different subset

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, header};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use vault_core::audit::FileSink;
use vault_core::crypto::MasterPassword;
use vault_core::session::{Clock, Secret, Session, SessionConfig};
use vault_core::storage::FileStore;
use vault_web::{AppConfig, Assets, CreateFormat};

pub const PORT: u16 = 8443;
pub const HOST: &str = "localhost:8443";
pub const ORIGIN: &str = "https://localhost:8443";
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
    connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; \
    require-trusted-types-for 'script'";
/// A master password the core policy accepts.
pub const PASSWORD: &str = "correct horse battery";

/// A clock that only moves when told to (sleeping moves it too).
pub struct ManualClock {
    start: Instant,
    elapsed: Mutex<Duration>,
}

impl ManualClock {
    /// A clock at its start instant.
    ///
    /// ```text
    /// let clock = ManualClock::new();
    /// ```
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            elapsed: Mutex::new(Duration::ZERO),
        }
    }

    /// The time advanced so far.
    ///
    /// ```text
    /// assert!(clock.elapsed() >= Duration::from_secs(1));
    /// ```
    pub fn elapsed(&self) -> Duration {
        *self.elapsed.lock().unwrap()
    }
}

impl Clock for ManualClock {
    /// The start instant plus the time advanced so far.
    fn now(&self) -> Instant {
        self.start + self.elapsed()
    }

    /// A fixed epoch plus the time advanced so far.
    fn unix_time(&self) -> u64 {
        1_800_000_000 + self.elapsed().as_secs()
    }

    /// Advances the clock instead of sleeping.
    fn sleep(&self, duration: Duration) {
        *self.elapsed.lock().unwrap() += duration;
    }
}

/// An app on a temp vault directory with a manual clock, the test vault format and
/// a small client bundle. One app instance serves every request, so sessions persist.
pub struct TestApp {
    dir: TempDir,
    pub config: AppConfig,
    pub clock: Arc<ManualClock>,
    router: Router,
}

impl TestApp {
    /// A test app serving a placeholder `index.html`, `app.js` and `app.css`.
    ///
    /// ```text
    /// let app = TestApp::new();
    /// ```
    pub fn new() -> Self {
        Self::with_setup(|_| {})
    }

    /// A test app serving `assets` as the client bundle.
    ///
    /// ```text
    /// let app = TestApp::with_assets(Assets::from_files::<_, &str, Vec<u8>>([]));
    /// ```
    pub fn with_assets(assets: Assets) -> Self {
        Self::with_setup(|config| config.assets = assets)
    }

    /// A test app whose config `setup` adjusts after the test defaults are in place.
    ///
    /// ```text
    /// let app = TestApp::with_setup(|config| config.kdf_limits.queue = 0);
    /// ```
    pub fn with_setup(setup: impl FnOnce(&mut AppConfig)) -> Self {
        init_logging();
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new());
        let mut config = AppConfig::new(dir.path().join("web-vaults"), PORT);
        config.clock = clock.clone();
        config.create_format = CreateFormat::InsecureTest;
        config.assets = Assets::from_files([
            (
                "index.html",
                b"<!doctype html><title>vault</title>".to_vec(),
            ),
            ("app.js", b"console.log(1);".to_vec()),
            ("app.css", b"body{}".to_vec()),
        ]);
        setup(&mut config);
        let router = vault_web::app(config.clone());
        Self {
            dir,
            config,
            clock,
            router,
        }
    }

    /// Sends one request through the app.
    ///
    /// ```text
    /// let response = app.send(get("/")).await;
    /// ```
    pub async fn send(&self, request: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(request).await.unwrap()
    }

    /// The app's router, for tests that send requests concurrently.
    ///
    /// ```text
    /// tokio::spawn(app.router().oneshot(request));
    /// ```
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// The audit log of `vaultname`, as written by `vault-core::audit::FileSink`.
    ///
    /// ```text
    /// assert!(app.audit_log("alice").contains("unlock_failed"));
    /// ```
    pub fn audit_log(&self, vaultname: &str) -> String {
        std::fs::read_to_string(self.vault_home(vaultname).join("audit.log")).unwrap_or_default()
    }

    /// The vault home of `vaultname` inside the vault directory.
    ///
    /// ```text
    /// assert!(app.vault_home("alice").is_dir());
    /// ```
    pub fn vault_home(&self, vaultname: &str) -> PathBuf {
        self.dir.path().join("web-vaults").join(vaultname)
    }

    /// Creates vault `vaultname` with [`PASSWORD`] and returns its session.
    ///
    /// ```text
    /// let alice = app.create_vault("alice").await;
    /// ```
    pub async fn create_vault(&self, vaultname: &str) -> Unlocked {
        let body = json!({"vaultname": vaultname, "master_password": PASSWORD});
        let response = self.send(post_json("/api/vaults", &body)).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        Unlocked::from_response(response).await
    }

    /// Creates vault `vaultname` with [`PASSWORD`] holding `secrets`, written straight
    /// through `vault-core` (faster than one request per secret), and returns a web session
    /// unlocked on it.
    ///
    /// ```text
    /// let alice = app.vault_with("alice", [Secret::new("github")]).await;
    /// ```
    pub async fn vault_with(
        &self,
        vaultname: &str,
        secrets: impl IntoIterator<Item = Secret>,
    ) -> Unlocked {
        let vault_dir = self.dir.path().join("web-vaults");
        let store = FileStore::new(&vault_dir).unwrap();
        let config = SessionConfig::new(Arc::new(FileSink::new(&vault_dir)));
        let password = MasterPassword::new(PASSWORD.into());
        let mut session =
            Session::create_insecure_for_tests(store, vaultname, &password, config).unwrap();
        for secret in secrets {
            session.save(secret).unwrap();
        }
        session.lock();
        self.unlock(vaultname).await
    }

    /// Unlocks vault `vaultname` with [`PASSWORD`] and returns its session.
    ///
    /// ```text
    /// let alice = app.unlock("alice").await;
    /// ```
    pub async fn unlock(&self, vaultname: &str) -> Unlocked {
        let body = json!({"vaultname": vaultname, "master_password": PASSWORD});
        let response = self.send(post_json("/api/unlock", &body)).await;
        assert_eq!(response.status(), StatusCode::OK);
        Unlocked::from_response(response).await
    }
}

/// A browser's view of an unlocked session: its cookie and CSRF token.
#[derive(Clone, Debug)]
pub struct Unlocked {
    /// `__Host-session=<id>`, as the browser sends it back.
    pub cookie: String,
    /// The CSRF token from the response body.
    pub csrf: String,
}

impl Unlocked {
    /// Reads the cookie and CSRF token from a successful unlock or create response.
    ///
    /// ```text
    /// let alice = Unlocked::from_response(response).await;
    /// ```
    pub async fn from_response(response: Response<Body>) -> Self {
        let cookie = session_cookie(&response).expect("a session cookie");
        let body = body_json(response).await;
        Self {
            cookie,
            csrf: body["csrf_token"].as_str().expect("csrf_token").to_owned(),
        }
    }

    /// `request` with this session's cookie and CSRF token added.
    ///
    /// ```text
    /// let request = alice.authorize(api(Method::POST, "/api/lock"));
    /// ```
    pub fn authorize(&self, request: axum::http::request::Builder) -> axum::http::request::Builder {
        request
            .header(header::COOKIE, &self.cookie)
            .header("x-csrf-token", &self.csrf)
    }

    /// `POST /api/lock` for this session.
    ///
    /// ```text
    /// let response = app.send(alice.lock()).await;
    /// ```
    pub fn lock(&self) -> Request<Body> {
        self.authorize(api(Method::POST, "/api/lock"))
            .body(Body::empty())
            .unwrap()
    }

    /// A same-origin `POST path` with `body` as JSON, this session's cookie and CSRF
    /// token.
    ///
    /// ```text
    /// let response = app.send(alice.post_json("/api/secrets/GitHub/reveal", &json!({"field": "password"}))).await;
    /// ```
    pub fn post_json(&self, path: &str, body: &Value) -> Request<Body> {
        self.send_json(Method::POST, path, body)
    }

    /// A same-origin `PUT path` with `body` as JSON, this session's cookie and CSRF
    /// token.
    ///
    /// ```text
    /// let response = app.send(alice.put_json("/api/secrets/GitHub", &json!({"title": "GitHub"}))).await;
    /// ```
    pub fn put_json(&self, path: &str, body: &Value) -> Request<Body> {
        self.send_json(Method::PUT, path, body)
    }

    /// A same-origin `method path` with `body` as JSON, this session's cookie and CSRF
    /// token.
    ///
    /// ```text
    /// let request = alice.send_json(Method::PUT, "/api/secrets/GitHub", &body);
    /// ```
    pub fn send_json(&self, method: Method, path: &str, body: &Value) -> Request<Body> {
        self.authorize(api(method, path))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// A same-origin `DELETE path` with this session's cookie and CSRF token.
    ///
    /// ```text
    /// let response = app.send(alice.delete("/api/secrets/GitHub")).await;
    /// ```
    pub fn delete(&self, path: &str) -> Request<Body> {
        self.authorize(api(Method::DELETE, path))
            .body(Body::empty())
            .unwrap()
    }

    /// `GET path` with this session's cookie.
    ///
    /// ```text
    /// let response = app.send(alice.get("/api/secrets")).await;
    /// ```
    pub fn get(&self, path: &str) -> Request<Body> {
        api(Method::GET, path)
            .header(header::COOKIE, &self.cookie)
            .body(Body::empty())
            .unwrap()
    }

    /// `GET /api/session` with this session's cookie.
    ///
    /// ```text
    /// let response = app.send(alice.session()).await;
    /// ```
    pub fn session(&self) -> Request<Body> {
        api(Method::GET, "/api/session")
            .header(header::COOKIE, &self.cookie)
            .body(Body::empty())
            .unwrap()
    }
}

/// A request builder for `method path` with the server's own `Host` and `Origin`.
///
/// ```text
/// let request = api(Method::POST, "/api/lock").body(Body::empty())?;
/// ```
pub fn api(method: Method, path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
}

/// A same-origin `POST path` with `body` as JSON.
///
/// ```text
/// let request = post_json("/api/unlock", &json!({"vaultname": "alice"}));
/// ```
pub fn post_json(path: &str, body: &Value) -> Request<Body> {
    api(Method::POST, path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A `GET path` request with the server's own `Host`.
///
/// ```text
/// let request = get("/app.js");
/// ```
pub fn get(path: &str) -> Request<Body> {
    get_with_host(path, HOST)
}

/// A `GET path` request with `Host: host`.
///
/// ```text
/// let request = get_with_host("/", "evil.example:8443");
/// ```
pub fn get_with_host(path: &str, host: &str) -> Request<Body> {
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
pub async fn body_text(response: Response<Body>) -> String {
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The response body as JSON.
///
/// ```text
/// assert_eq!(body_json(response).await["error"], "not found");
/// ```
pub async fn body_json(response: Response<Body>) -> Value {
    serde_json::from_str(&body_text(response).await).unwrap()
}

/// The response's only `Set-Cookie` header, in full.
///
/// ```text
/// assert!(set_cookie(&response).unwrap().contains("HttpOnly"));
/// ```
pub fn set_cookie(response: &Response<Body>) -> Option<String> {
    let mut values = response.headers().get_all(header::SET_COOKIE).iter();
    let value = values.next()?.to_str().unwrap().to_owned();
    assert!(values.next().is_none(), "one Set-Cookie");
    Some(value)
}

/// The `name=value` pair of the response's `Set-Cookie`, as a browser sends it back.
///
/// ```text
/// let cookie = session_cookie(&response).unwrap(); // "__Host-session=..."
/// ```
pub fn session_cookie(response: &Response<Body>) -> Option<String> {
    let set = set_cookie(response)?;
    Some(set.split(';').next().unwrap().trim().to_owned())
}

/// Asserts every security header from `web-app-security.md` is present with its exact value.
///
/// ```text
/// assert_security_headers(response.headers());
/// ```
pub fn assert_security_headers(headers: &HeaderMap) {
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

thread_local! {
    /// Everything logged on this thread. Each `#[tokio::test]` runs the app on its own
    /// thread, so this holds exactly one test's logs (work moved to the blocking pool
    /// logs elsewhere).
    static LOGS: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// A `tracing` writer appending to this thread's [`LOGS`].
pub struct ThreadLogs;

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
pub fn init_logging() {
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
pub async fn send_logged(app: &TestApp, request: Request<Body>) -> (Response<Body>, String) {
    LOGS.with(|logs| logs.borrow_mut().clear());
    let response = app.send(request).await;
    let logs = LOGS.with(|logs| String::from_utf8(logs.take()).unwrap());
    (response, logs)
}
