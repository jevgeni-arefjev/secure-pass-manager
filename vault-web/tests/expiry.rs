//! When the server ends a session on its own: the sweeper (idle timeout and the 8 h
//! absolute lifetime), activity keeping a session open, locking every session on
//! shutdown, and a panicking request.

mod common;

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use common::*;
use serde_json::json;
use vault_core::session::Clock;

/// One minute.
const MINUTE: Duration = Duration::from_secs(60);

#[tokio::test]
async fn sweep_ends_an_idle_session_and_its_cookie_gets_401() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    app.clock.sleep(5 * MINUTE);

    app.sweep();

    assert_eq!(app.session_count(), 0);
    assert!(app.audit_log("alice").contains("\"auto_locked\""));
    let response = app.send(alice.get("/api/secrets")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn activity_within_the_idle_timeout_keeps_the_session_open() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    for _ in 0..3 {
        app.clock.sleep(4 * MINUTE);
        let response = app.send(alice.get("/api/secrets")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    app.clock.sleep(4 * MINUTE);

    app.sweep();

    assert_eq!(app.session_count(), 1);
    let response = app.send(alice.get("/api/secrets")).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn checking_the_session_is_not_activity() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    for _ in 0..2 {
        app.clock.sleep(3 * MINUTE);
        app.send(alice.session()).await;
    }

    app.sweep();

    assert_eq!(app.session_count(), 0);
}

#[tokio::test]
async fn sweep_ends_an_active_session_eight_hours_after_unlock() {
    let app = TestApp::new();
    let body =
        json!({"vaultname": "alice", "master_password": PASSWORD, "idle_timeout_minutes": 60});
    let alice = Unlocked::from_response(app.send(post_json("/api/vaults", &body)).await).await;
    for _ in 0..9 {
        app.clock.sleep(50 * MINUTE);
        let response = app.send(alice.get("/api/secrets")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    // 7 h 30 min in: still within the lifetime.
    app.sweep();
    assert_eq!(app.session_count(), 1);

    app.clock.sleep(30 * MINUTE);
    app.sweep();

    assert_eq!(app.session_count(), 0);
    assert!(app.audit_log("alice").contains("\"locked\""));
    let response = app.send(alice.get("/api/secrets")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sweep_keeps_live_sessions_and_ends_only_expired_ones() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    app.clock.sleep(3 * MINUTE);
    let bob = app.create_vault("bob").await;
    app.clock.sleep(2 * MINUTE);

    app.sweep();

    assert_eq!(app.session_count(), 1);
    let response = app.send(alice.get("/api/secrets")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app.send(bob.get("/api/secrets")).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_sweeper_task_sweeps_periodically() {
    let app = TestApp::with_setup(|config| config.sweep_interval = Duration::from_millis(10));
    let alice = app.create_vault("alice").await;
    let sweeper = app.spawn_sweeper();
    app.clock.sleep(5 * MINUTE);

    let deadline = Instant::now() + Duration::from_secs(5);
    while app.session_count() > 0 {
        assert!(Instant::now() < deadline, "sweeper never ran");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    sweeper.abort();
    assert!(app.audit_log("alice").contains("\"auto_locked\""));
    let response = app.send(alice.get("/api/secrets")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn lock_all_locks_every_session_as_terminated_by_signal() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let bob = app.create_vault("bob").await;

    app.lock_all();

    assert_eq!(app.session_count(), 0);
    for (vaultname, user) in [("alice", alice), ("bob", bob)] {
        assert!(
            app.audit_log(vaultname)
                .contains("\"terminated_by_signal\"")
        );
        let response = app.send(user.get("/api/secrets")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{vaultname}");
    }
}

#[tokio::test]
async fn a_panicking_request_is_a_generic_500_and_ends_its_session() {
    // Before the vault is touched (session lookup), and while it is held.
    for nth in [1, 2] {
        a_request_panicking_on_now_call(nth).await;
    }
}

/// Makes a request panic on the `nth` clock call and checks the response and that only
/// its session ended.
///
/// ```text
/// a_request_panicking_on_now_call(2).await;
/// ```
async fn a_request_panicking_on_now_call(nth: usize) {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let bob = app.create_vault("bob").await;
    app.clock.panic_on_now_call(nth);

    let (response, logs) = send_logged(&app, alice.get("/api/secrets")).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_security_headers(response.headers());
    assert!(set_cookie(&response).unwrap().contains("Max-Age=0"));
    assert_eq!(
        body_json(response).await,
        json!({"error": "internal error"})
    );
    assert!(logs.contains("status=500"), "{logs}");
    assert!(!logs.contains("on purpose"), "{logs}");
    assert_eq!(app.session_count(), 1);
    assert!(app.audit_log("alice").contains("\"locked\""));
    let response = app.send(alice.get("/api/secrets")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app.send(bob.get("/api/secrets")).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_panicking_request_without_a_session_is_a_generic_500() {
    let app = TestApp::new();
    app.clock.panic_on_now_call(1);

    let body = json!({"vaultname": "alice", "master_password": PASSWORD});
    let response = app.send(post_json("/api/unlock", &body)).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(set_cookie(&response).is_none());
    assert_eq!(
        body_json(response).await,
        json!({"error": "internal error"})
    );
}

#[tokio::test]
async fn a_vault_unlocked_after_lock_all_is_locked_at_once() {
    let app = TestApp::new();
    app.create_vault("alice").await;
    app.lock_all();

    // As an unlock still deriving its key when the server began stopping.
    let body = json!({"vaultname": "alice", "master_password": PASSWORD});
    let response = app.send(post_json("/api/unlock", &body)).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(set_cookie(&response).is_none());
    assert_eq!(app.session_count(), 0);
    let log = app.audit_log("alice");
    assert!(
        log.trim_end()
            .ends_with("\"kind\":\"terminated_by_signal\"}"),
        "{log}"
    );
}
