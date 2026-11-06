//! Changing the master password over the HTTP API: the vault then unlocks only with the
//! new one, the rules are checked before any KDF runs, wrong current master passwords
//! are audited and the third in a row locks the session, and a change ends every other
//! web session on the vault and reissues this one.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use serde_json::json;
use tower::ServiceExt;

/// A new master password that passes the rules.
const NEW_PASSWORD: &str = "tr0ub4dor & 3 staples";

/// `POST /api/master-password` from `session`, changing `current` to `new`.
///
/// ```text
/// let response = app.send(change(&alice, PASSWORD, NEW_PASSWORD)).await;
/// ```
fn change(session: &Unlocked, current: &str, new: &str) -> Request<Body> {
    session.post_json(
        "/api/master-password",
        &json!({"current_master_password": current, "new_master_password": new}),
    )
}

/// `POST /api/unlock` for `vaultname` with `password`.
///
/// ```text
/// let response = app.send(unlock_with("alice", NEW_PASSWORD)).await;
/// ```
fn unlock_with(vaultname: &str, password: &str) -> Request<Body> {
    post_json("/api/unlock", &unlock_body(vaultname, password))
}

#[tokio::test]
async fn after_a_change_the_vault_unlocks_with_the_new_master_password_only() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;

    let response = app.send(change(&alice, PASSWORD, NEW_PASSWORD)).await;
    assert_eq!(response.status(), StatusCode::OK);

    let old = app.send(unlock_with("alice", PASSWORD)).await;
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
    let new = app.send(unlock_with("alice", NEW_PASSWORD)).await;
    assert_eq!(new.status(), StatusCode::OK);
    assert!(app.audit_log("alice").contains("master_password_changed"));
}

#[tokio::test]
async fn a_new_master_password_breaking_the_rules_is_refused_on_its_field() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;

    for (new, message) in [
        ("short", "master password must be at least 12 characters"),
        (
            "correct horse\tbattery",
            "master password must not contain control characters",
        ),
        ("password1234", "master password is too common"),
    ] {
        let body = expect(
            app.send(change(&alice, PASSWORD, new)).await,
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(
            body,
            json!({"error": message, "field": "new_master_password"}),
            "{new:?}"
        );
    }
    let unlocked = app.send(unlock_with("alice", PASSWORD)).await;
    assert_eq!(unlocked.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_wrong_current_master_password_is_refused_on_its_field_and_audited() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;

    let body = expect(
        app.send(change(&alice, "not the master password", NEW_PASSWORD))
            .await,
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(
        body,
        json!({"error": "wrong master password", "field": "current_master_password"})
    );
    assert!(
        app.audit_log("alice")
            .contains("master_password_change_failed")
    );

    // The session stays open, and the vault keeps its master password.
    assert_eq!(app.send(alice.session()).await.status(), StatusCode::OK);
    let unlocked = app.send(unlock_with("alice", PASSWORD)).await;
    assert_eq!(unlocked.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_third_wrong_current_master_password_in_a_row_locks_the_session() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;

    for _ in 0..2 {
        let response = app
            .send(change(&alice, "not the master password", NEW_PASSWORD))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let body = expect(
        app.send(change(&alice, "not the master password", NEW_PASSWORD))
            .await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(body, json!({"error": "vault is locked"}));
    assert_eq!(
        app.send(alice.session()).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_right_current_master_password_resets_the_count_of_wrong_ones() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;

    for _ in 0..2 {
        let response = app
            .send(change(&alice, "not the master password", NEW_PASSWORD))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let changed = app.send(change(&alice, PASSWORD, NEW_PASSWORD)).await;
    assert_eq!(changed.status(), StatusCode::OK);
    let alice = Unlocked::from_response(changed).await;

    let response = app
        .send(change(&alice, "not the master password", PASSWORD))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(app.send(alice.session()).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_change_reissues_this_session_and_its_old_cookie_and_token_stop_working() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;

    let response = app.send(change(&alice, PASSWORD, NEW_PASSWORD)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let renewed = Unlocked::from_response(response).await;
    assert_ne!(renewed.cookie, alice.cookie);
    assert_ne!(renewed.csrf, alice.csrf);

    assert_eq!(
        app.send(alice.session()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let body = expect(app.send(renewed.session()).await, StatusCode::OK).await;
    assert_eq!(body["vaultname"], "alice");
    assert_eq!(body["csrf_token"], renewed.csrf.as_str());
    assert_eq!(
        app.send(renewed.get("/api/secrets")).await.status(),
        StatusCode::OK
    );
    assert_eq!(app.session_count(), 1);
}

#[tokio::test]
async fn a_change_locks_every_other_web_session_on_the_vault_only() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let other_tab = app.unlock("alice").await;
    let bob = app.create_vault("bob").await;

    let response = app.send(change(&alice, PASSWORD, NEW_PASSWORD)).await;
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        app.send(other_tab.session()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(app.send(bob.session()).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_change_needs_the_csrf_token() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let forged = Unlocked {
        cookie: alice.cookie.clone(),
        csrf: "0".repeat(64),
    };

    let response = app.send(change(&forged, PASSWORD, NEW_PASSWORD)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let unlocked = app.send(unlock_with("alice", PASSWORD)).await;
    assert_eq!(unlocked.status(), StatusCode::OK);
}

#[tokio::test]
async fn master_passwords_never_reach_the_logs_or_the_response() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;

    let (response, logs) = send_logged(&app, change(&alice, PASSWORD, NEW_PASSWORD)).await;
    let text = body_text(response).await;
    for password in [PASSWORD, NEW_PASSWORD] {
        assert!(!logs.contains(password), "{logs}");
        assert!(!text.contains(password), "{text}");
        assert!(!app.audit_log("alice").contains(password));
    }
}

#[tokio::test]
async fn a_change_beyond_the_kdf_limit_is_turned_away_with_503_after_the_rules() {
    let (clock, mut entered, release) = GateClock::new();
    let app = TestApp::with_setup(|config| {
        config.clock = clock;
        config.kdf_limits.concurrency = 1;
        config.kdf_limits.queue = 0;
    });
    let alice = app.create_vault("alice").await;

    // A failed unlock holds the only slot while it sleeps out its failure delay.
    let holding = tokio::spawn(
        app.router()
            .oneshot(unlock_with("alice", "not the master password")),
    );
    entered.recv().await.unwrap();

    let body = expect(
        app.send(change(&alice, PASSWORD, NEW_PASSWORD)).await,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(body, json!({"error": "server busy, try again shortly"}));
    // A new master password breaking the rules gets its field error without a slot.
    let response = app.send(change(&alice, PASSWORD, "short")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    release.send(()).unwrap();
    holding.await.unwrap().unwrap();
    assert_eq!(app.send(alice.session()).await.status(), StatusCode::OK);
}
