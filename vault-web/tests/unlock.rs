//! Creating, unlocking and locking a vault over the HTTP API, and the session machinery
//! around it: cookie, CSRF token, Origin check, KDF limiter and strict request parsing.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::*;
use serde_json::json;
use tower::ServiceExt;
use vault_core::session::Clock;

/// A session ID that looks real but was never issued, as an attacker would plant it.
const PLANTED: &str =
    "__Host-session=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#[tokio::test]
async fn created_vault_is_returned_unlocked() {
    let app = TestApp::new();
    let alice = app.create_vault("Alice").await;
    assert_eq!(alice.csrf.len(), 64);

    let response = app.send(alice.session()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["vaultname"], "alice");
    assert_eq!(body["idle_timeout_minutes"], 5);
    assert_eq!(body["csrf_token"], alice.csrf.as_str());
    assert!(app.vault_home("alice").is_dir());
    assert!(app.audit_log("alice").contains("vault_created"));
}

#[tokio::test]
async fn session_cookie_is_host_only_http_only_secure_strict_and_session_scoped() {
    let app = TestApp::new();
    let body = unlock_body("alice", PASSWORD);
    let response = app.send(post_json("/api/vaults", &body)).await;
    assert_security_headers(response.headers());
    let cookie = set_cookie(&response).unwrap();
    let mut parts = cookie.split("; ");
    let (name, value) = parts.next().unwrap().split_once('=').unwrap();
    assert_eq!(name, "__Host-session");
    assert_eq!(value.len(), 64);
    let mut attributes: Vec<_> = parts.collect();
    attributes.sort_unstable();
    assert_eq!(
        attributes,
        ["HttpOnly", "Path=/", "SameSite=Strict", "Secure"]
    );
}

#[tokio::test]
async fn idle_timeout_is_taken_from_the_request() {
    let app = TestApp::new();
    let body =
        json!({"vaultname": "alice", "master_password": PASSWORD, "idle_timeout_minutes": 60});
    let response = app.send(post_json("/api/vaults", &body)).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(body_json(response).await["idle_timeout_minutes"], 60);

    let body =
        json!({"vaultname": "alice", "master_password": PASSWORD, "idle_timeout_minutes": 1});
    let response = app.send(post_json("/api/unlock", &body)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["idle_timeout_minutes"], 1);
}

#[tokio::test]
async fn idle_timeout_outside_one_to_sixty_minutes_is_a_field_error() {
    let app = TestApp::new();
    for path in ["/api/vaults", "/api/unlock"] {
        for minutes in [0, 61, 100_000] {
            let body = json!({"vaultname": "alice", "master_password": PASSWORD, "idle_timeout_minutes": minutes});
            let response = app.send(post_json(path, &body)).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{path} {minutes}"
            );
            assert_eq!(
                body_json(response).await,
                json!({"error": "idle timeout must be 1-60 minutes", "field": "idle_timeout_minutes"})
            );
        }
    }
    assert!(!app.vault_home("alice").exists());
}

#[tokio::test]
async fn taken_vaultname_is_a_conflict() {
    let app = TestApp::new();
    app.create_vault("alice").await;
    let response = app
        .send(post_json(
            "/api/vaults",
            &unlock_body("ALICE", "another strong passphrase"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(set_cookie(&response).is_none());
    assert_eq!(
        body_json(response).await,
        json!({"error": "vaultname taken"})
    );
}

#[tokio::test]
async fn invalid_vaultname_is_a_field_error_and_touches_no_file() {
    let app = TestApp::new();
    for vaultname in [
        "",
        "../alice",
        "..",
        "alice/../../etc",
        "/etc/passwd",
        "a\\b",
        ".hidden",
        "-alice",
        "alice\u{0}",
        "con",
        "alicé",
        &"a".repeat(33),
    ] {
        let response = app
            .send(post_json("/api/vaults", &unlock_body(vaultname, PASSWORD)))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{vaultname:?}");
        let body = body_json(response).await;
        assert_eq!(body["field"], "vaultname", "{vaultname:?}");
        assert!(
            body["error"].as_str().unwrap().contains("vaultname"),
            "{body}"
        );
    }
    let vault_dir = app.config.vault_dir.clone();
    let entries = std::fs::read_dir(&vault_dir).map_or(0, Iterator::count);
    assert_eq!(entries, 0);
    assert!(!vault_dir.parent().unwrap().join("alice").exists());
}

#[tokio::test]
async fn weak_master_password_is_a_field_error() {
    let app = TestApp::new();
    for (password, message) in [
        ("short", "master password must be at least 12 characters"),
        ("password1234", "master password is too common"),
        ("aaaaaaaaaaaaaaaa", "master password is too common"),
        (
            &*"x1".repeat(513),
            "master password must be at most 1024 characters",
        ),
        (
            "correct horse\nbattery",
            "master password must not contain control characters",
        ),
    ] {
        let response = app
            .send(post_json("/api/vaults", &unlock_body("alice", password)))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{password}");
        assert_eq!(
            body_json(response).await,
            json!({"error": message, "field": "master_password"})
        );
    }
    assert!(!app.vault_home("alice").exists());
}

#[tokio::test]
async fn a_1024_character_master_password_is_accepted() {
    let app = TestApp::new();
    let password = "x1".repeat(512);
    let response = app
        .send(post_json("/api/vaults", &unlock_body("alice", &password)))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn a_vaultname_with_surrounding_spaces_opens_the_same_vault() {
    let app = TestApp::new();
    let response = app
        .send(post_json("/api/vaults", &unlock_body(" alice ", PASSWORD)))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(body_json(response).await["vaultname"], "alice");
    let response = app
        .send(post_json("/api/unlock", &unlock_body("  alice", PASSWORD)))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["vaultname"], "alice");
}

#[tokio::test]
async fn unlock_opens_an_existing_vault_with_a_new_session() {
    let app = TestApp::new();
    let created = app.create_vault("alice").await;
    let unlocked = app.unlock("alice").await;
    assert_ne!(unlocked.cookie, created.cookie);
    assert_ne!(unlocked.csrf, created.csrf);
    let response = app.send(unlocked.session()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["vaultname"], "alice");
    assert!(app.audit_log("alice").contains("\"unlocked\""));
}

#[tokio::test]
async fn every_unlock_failure_is_the_same_401_after_the_minimum_delay() {
    let app = TestApp::new();
    app.create_vault("alice").await;
    let mut bodies = Vec::new();
    for (vaultname, password) in [
        ("alice", "wrong master password"),
        ("bob", PASSWORD),
        ("../alice", PASSWORD),
        ("", ""),
        ("alice", &*"x".repeat(5000)),
        ("alice", "correct horse\nbattery\u{1b}[2J"),
    ] {
        let before = app.clock.elapsed();
        let response = app
            .send(post_json("/api/unlock", &unlock_body(vaultname, password)))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{vaultname:?}");
        assert!(set_cookie(&response).is_none());
        assert!(
            app.clock.elapsed() - before >= Duration::from_secs(1),
            "{vaultname:?} answered early"
        );
        bodies.push(body_text(response).await);
    }
    assert!(bodies.iter().all(|body| *body == bodies[0]), "{bodies:?}");
    assert_eq!(
        bodies[0],
        r#"{"error":"wrong vaultname or master password"}"#
    );
    assert!(!app.vault_home("bob").exists());
}

#[tokio::test]
async fn failed_unlocks_are_audited_and_never_lock_the_owner_out() {
    let app = TestApp::new();
    app.create_vault("alice").await;
    for _ in 0..10 {
        let response = app
            .send(post_json(
                "/api/unlock",
                &unlock_body("alice", "guessing wrong"),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(app.audit_log("alice").matches("unlock_failed").count(), 10);
    app.unlock("alice").await;
}

#[tokio::test]
async fn lock_ends_the_session_deletes_the_cookie_and_clears_site_data() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let response = app.send(alice.lock()).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_security_headers(response.headers());
    assert_eq!(
        response.headers()["clear-site-data"],
        "\"cache\", \"storage\""
    );
    let cookie = set_cookie(&response).unwrap();
    assert!(cookie.starts_with("__Host-session=;"), "{cookie}");
    assert!(cookie.contains("Max-Age=0"), "{cookie}");
    assert!(app.audit_log("alice").contains("\"locked\""));

    let response = app.send(alice.session()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app.send(alice.lock()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()["clear-site-data"],
        "\"cache\", \"storage\""
    );
}

#[tokio::test]
async fn session_check_without_a_live_session_is_401_and_deletes_the_cookie() {
    let app = TestApp::new();
    let no_cookie = api(Method::GET, "/api/session")
        .body(Body::empty())
        .unwrap();
    let response = app.send(no_cookie).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(response).await,
        json!({"error": "vault is locked"})
    );

    for cookie in [PLANTED, "__Host-session=../../etc", "__Host-session="] {
        let request = api(Method::GET, "/api/session")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.send(request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{cookie}");
        assert!(set_cookie(&response).unwrap().contains("Max-Age=0"));
        assert_eq!(
            response.headers()["clear-site-data"],
            "\"cache\", \"storage\""
        );
    }
}

#[tokio::test]
async fn idle_session_is_locked_on_its_next_check() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    app.clock.sleep(Duration::from_secs(4 * 60));
    assert_eq!(app.send(alice.session()).await.status(), StatusCode::OK);
    app.clock.sleep(Duration::from_secs(60));
    assert_eq!(
        app.send(alice.session()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(app.audit_log("alice").contains("auto_locked"));
}

#[tokio::test]
async fn a_cookie_from_before_unlock_is_not_accepted_after_it() {
    let app = TestApp::new();
    let before = app.create_vault("alice").await;

    let request = before
        .authorize(api(Method::POST, "/api/unlock"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(unlock_body("alice", PASSWORD).to_string()))
        .unwrap();
    let response = app.send(request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let after = Unlocked::from_response(response).await;
    assert_ne!(after.cookie, before.cookie);
    assert_eq!(
        app.send(before.session()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(app.send(after.session()).await.status(), StatusCode::OK);

    // A planted cookie is replaced too and never becomes a session.
    let request = api(Method::POST, "/api/unlock")
        .header(header::COOKIE, PLANTED)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(unlock_body("alice", PASSWORD).to_string()))
        .unwrap();
    let response = app.send(request).await;
    assert_ne!(session_cookie(&response).unwrap(), PLANTED);
    let planted = Unlocked {
        cookie: PLANTED.to_owned(),
        csrf: String::new(),
    };
    assert_eq!(
        app.send(planted.session()).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn state_changing_request_needs_this_sessions_csrf_token() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let bob = app.create_vault("bob").await;
    let without = api(Method::POST, "/api/lock")
        .header(header::COOKIE, &alice.cookie)
        .body(Body::empty())
        .unwrap();
    let mut wrong = alice.clone();
    wrong.csrf = "0".repeat(64);
    let mut others = alice.clone();
    others.csrf = bob.csrf.clone();
    let mut truncated = alice.clone();
    truncated.csrf.pop();

    for request in [without, wrong.lock(), others.lock(), truncated.lock()] {
        let response = app.send(request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(set_cookie(&response).is_none());
        assert_eq!(
            body_json(response).await,
            json!({"error": "missing or invalid CSRF token"})
        );
    }
    assert_eq!(app.send(alice.session()).await.status(), StatusCode::OK);
    assert_eq!(
        app.send(alice.lock()).await.status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn state_changing_request_needs_the_servers_own_origin() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    for origin in [
        None,
        Some("https://evil.example"),
        Some("http://localhost:8443"),
        Some("https://localhost:9999"),
        Some("https://localhost:8443.evil.example"),
        Some("null"),
    ] {
        let requests = [
            ("/api/vaults", Some(unlock_body("bob", PASSWORD))),
            ("/api/unlock", Some(unlock_body("alice", PASSWORD))),
            ("/api/lock", None),
        ];
        for (path, body) in requests {
            let mut request = alice
                .authorize(Request::post(path))
                .header(header::HOST, HOST)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(origin) = origin {
                request = request.header(header::ORIGIN, origin);
            }
            let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
            let response = app.send(request.body(body).unwrap()).await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{path} {origin:?}"
            );
            assert_eq!(
                body_json(response).await,
                json!({"error": "cross-origin request refused"})
            );
        }
    }
    assert!(!app.vault_home("bob").exists());
    assert_eq!(app.send(alice.session()).await.status(), StatusCode::OK);

    let same_origin_other_name = alice
        .authorize(Request::post("/api/lock"))
        .header(header::HOST, "127.0.0.1:8443")
        .header(header::ORIGIN, "https://127.0.0.1:8443")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.send(same_origin_other_name).await.status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn oversized_body_is_refused() {
    let app = TestApp::new();
    let padding = "x".repeat(64 * 1024);
    let body = json!({"vaultname": "alice", "master_password": padding});
    let response = app.send(post_json("/api/vaults", &body)).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        body_json(response).await,
        json!({"error": "request body too large"})
    );
    assert!(!app.vault_home("alice").exists());
}

#[tokio::test]
async fn malformed_bodies_are_refused_without_details() {
    let app = TestApp::new();
    let bodies = [
        json!({"vaultname": "alice", "master_password": PASSWORD, "admin": true}).to_string(),
        json!({"vaultname": "alice", "master_password": 1234}).to_string(),
        json!({"vaultname": "alice"}).to_string(),
        json!({"vaultname": "alice", "master_password": PASSWORD, "idle_timeout_minutes": -1})
            .to_string(),
        json!(["alice", PASSWORD]).to_string(),
        "{\"vaultname\": \"alice\", ".to_owned(),
        String::new(),
    ];
    for path in ["/api/vaults", "/api/unlock"] {
        for body in &bodies {
            let request = api(Method::POST, path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.clone()))
                .unwrap();
            let response = app.send(request).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path} {body}");
            assert_eq!(
                body_json(response).await,
                json!({"error": "invalid request body"})
            );
        }
    }
    assert!(!app.vault_home("alice").exists());
}

#[tokio::test]
async fn non_json_body_is_refused() {
    let app = TestApp::new();
    for content_type in [
        None,
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
    ] {
        let mut request = api(Method::POST, "/api/unlock");
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let body = Body::from(unlock_body("alice", PASSWORD).to_string());
        let response = app.send(request.body(body).unwrap()).await;
        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type:?}"
        );
    }
}

#[tokio::test]
async fn unlocks_beyond_the_kdf_limit_are_turned_away_with_503() {
    let (clock, mut entered, release) = GateClock::new();
    let app = TestApp::with_setup(|config| {
        config.clock = clock;
        config.kdf_limits.concurrency = 1;
        config.kdf_limits.queue = 0;
    });

    // A failed unlock holds the only slot while it sleeps out its failure delay.
    let holding = tokio::spawn(
        app.router()
            .oneshot(post_json("/api/unlock", &unlock_body("alice", PASSWORD))),
    );
    entered.recv().await.unwrap();

    for path in ["/api/unlock", "/api/vaults"] {
        let response = app
            .send(post_json(path, &unlock_body("alice", PASSWORD)))
            .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(
            body_json(response).await,
            json!({"error": "server busy, try again shortly"})
        );
    }

    // Invalid creates are refused by their cheap checks, without waiting for a slot.
    for (body, field) in [
        (unlock_body("../alice", PASSWORD), "vaultname"),
        (unlock_body("alice", "short"), "master_password"),
        (unlock_body("alice", &"x1".repeat(513)), "master_password"),
        (
            unlock_body("alice", "correct horse\tbattery"),
            "master_password",
        ),
        (
            json!({"vaultname": "alice", "master_password": PASSWORD, "idle_timeout_minutes": 0}),
            "idle_timeout_minutes",
        ),
    ] {
        let response = app.send(post_json("/api/vaults", &body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        assert_eq!(body_json(response).await["field"], field);
    }

    release.send(()).unwrap();
    let response = holding.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    app.create_vault("alice").await;
}

#[tokio::test]
async fn request_log_carries_a_session_hash_but_no_vaultname_password_cookie_or_body() {
    let app = TestApp::new();
    let body = unlock_body("zebracorn", PASSWORD);
    let (response, create_logs) = send_logged(&app, post_json("/api/vaults", &body)).await;
    let alice = Unlocked::from_response(response).await;
    let (_, failed_logs) = send_logged(
        &app,
        post_json("/api/unlock", &unlock_body("zebracorn", "hunter2hunter2")),
    )
    .await;
    let (_, session_logs) = send_logged(&app, alice.session()).await;
    let (_, lock_logs) = send_logged(&app, alice.lock()).await;

    let session_id = alice.cookie.split_once('=').unwrap().1;
    for logs in [&create_logs, &failed_logs, &session_logs, &lock_logs] {
        assert!(logs.contains("status="), "{logs}");
        for leak in [
            "zebracorn",
            PASSWORD,
            "hunter2",
            session_id,
            &alice.csrf,
            "__Host-session",
        ] {
            assert!(!logs.contains(leak), "{leak:?} in {logs}");
        }
    }
    let tag = |logs: &str| {
        let start = logs.find("session=").expect("session field") + "session=".len();
        logs[start..].split_whitespace().next().unwrap().to_owned()
    };
    assert_eq!(tag(&create_logs).len(), 8);
    assert_eq!(tag(&create_logs), tag(&session_logs));
    assert_eq!(tag(&session_logs), tag(&lock_logs));
    assert_eq!(tag(&failed_logs), "-");
}
