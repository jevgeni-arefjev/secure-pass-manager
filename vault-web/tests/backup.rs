//! Downloading a backup over the HTTP API: the vault file exactly as stored, named
//! after the vaultname and revision, behind the CSRF token, audited, and refused (the
//! session locked) when another session has saved since unlock.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::*;
use serde_json::json;
use vault_core::session::Secret;

/// `POST /api/backup` from `session`.
///
/// ```text
/// let response = app.send(backup(&alice)).await;
/// ```
fn backup(session: &Unlocked) -> Request<Body> {
    session
        .authorize(api(Method::POST, "/api/backup"))
        .body(Body::empty())
        .unwrap()
}

/// The body of a response as bytes.
///
/// ```text
/// let bytes = body_bytes(response).await;
/// ```
async fn body_bytes(response: axum::http::Response<Body>) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn the_backup_is_the_stored_vault_file_as_an_attachment_named_by_revision() {
    let app = TestApp::new();
    let alice = app
        .vault_with("alice", [Secret::new("GitHub"), Secret::new("gitlab")])
        .await;

    let response = app.send(backup(&alice)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_security_headers(response.headers());
    let headers = response.headers().clone();
    assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"alice-r2.vault\""
    );
    assert_eq!(
        body_bytes(response).await,
        std::fs::read(app.vault_home("alice").join("secrets.vault")).unwrap()
    );
    assert!(
        app.audit_log("alice")
            .contains(r#""kind":"backup_created","revision":2"#),
        "{}",
        app.audit_log("alice")
    );
}

#[tokio::test]
async fn a_backup_needs_the_csrf_token() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let forged = Unlocked {
        cookie: alice.cookie.clone(),
        csrf: "0".repeat(64),
    };

    let response = app.send(backup(&forged)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!app.audit_log("alice").contains("backup_created"));
}

#[tokio::test]
async fn a_backup_after_another_session_saved_locks_this_session() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let other_tab = app.unlock("alice").await;
    let saved = app
        .send(other_tab.post_json("/api/secrets", &json!({"title": "GitHub"})))
        .await;
    assert_eq!(saved.status(), StatusCode::CREATED);

    let response = app.send(backup(&alice)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(response).await,
        json!({"error": "vault is locked"})
    );
    assert_eq!(
        app.send(alice.session()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(!app.audit_log("alice").contains("backup_created"));
}

#[tokio::test]
async fn a_backup_without_a_session_is_refused() {
    let app = TestApp::new();
    app.create_vault("alice").await;

    let response = app
        .send(
            api(Method::POST, "/api/backup")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
