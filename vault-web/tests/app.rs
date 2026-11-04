//! Behaviour of the `vault-web` HTTP app, driven in-process through
//! `tower::ServiceExt::oneshot` on a temp vault directory and a manual clock: no TLS,
//! no sockets.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;
use vault_web::Assets;

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
