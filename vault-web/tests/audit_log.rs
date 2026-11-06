//! Reading the audit log over the HTTP API: the session's own vault only, newest first,
//! `limit` honoured and capped at 1000, unreadable lines marked, and never a field value.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use vault_core::session::{HiddenValue, Secret};

/// The JSON body of `GET path` from `session`, asserting its status.
///
/// ```text
/// let body = fetch(&app, &alice, "/api/audit-log", StatusCode::OK).await;
/// ```
async fn fetch(app: &TestApp, session: &Unlocked, path: &str, status: StatusCode) -> Value {
    let response = app.send(session.get(path)).await;
    assert_eq!(response.status(), status);
    assert_security_headers(response.headers());
    body_json(response).await
}

/// The `kind` of each event in an audit log response, in order.
///
/// ```text
/// assert_eq!(kinds(&body), ["unlocked", "locked"]);
/// ```
fn kinds(body: &Value) -> Vec<&str> {
    body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["kind"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn events_come_newest_first_with_their_time_and_title_or_revision() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [Secret::new("GitHub")]).await;
    let backup = app
        .send(
            alice
                .authorize(common::api(axum::http::Method::POST, "/api/backup"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(backup.status(), StatusCode::OK);

    let body = fetch(&app, &alice, "/api/audit-log", StatusCode::OK).await;
    assert_eq!(
        kinds(&body),
        [
            "backup_created",
            "unlocked",
            "locked",
            "secret_added",
            "vault_created"
        ]
    );
    let events = body["events"].as_array().unwrap();
    assert_eq!(events[0]["revision"], 1);
    assert_eq!(events[3]["title"], "GitHub");
    let time = events[0]["time"].as_str().unwrap();
    assert!(time.ends_with('Z') || time.ends_with("+00:00"), "{time}");
}

#[tokio::test]
async fn limit_picks_the_newest_events_and_defaults_to_20() {
    let app = TestApp::new();
    let secrets: Vec<_> = (0..25).map(|n| Secret::new(format!("s{n:02}"))).collect();
    let alice = app.vault_with("alice", secrets).await;

    let body = fetch(&app, &alice, "/api/audit-log", StatusCode::OK).await;
    assert_eq!(kinds(&body).len(), 20);
    let body = fetch(&app, &alice, "/api/audit-log?limit=2", StatusCode::OK).await;
    assert_eq!(kinds(&body), ["unlocked", "locked"]);
    let body = fetch(&app, &alice, "/api/audit-log?limit=1000", StatusCode::OK).await;
    assert_eq!(kinds(&body).len(), 28);
}

#[tokio::test]
async fn a_limit_over_1000_is_capped_at_1000() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;

    for query in ["limit=1001", "limit=99999999999999999999999"] {
        let body = fetch(
            &app,
            &alice,
            &format!("/api/audit-log?{query}"),
            StatusCode::OK,
        )
        .await;
        assert_eq!(kinds(&body), ["vault_created"], "{query}");
    }
}

#[tokio::test]
async fn a_limit_that_is_not_a_whole_number_of_at_least_1_is_refused_on_its_field() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;

    for query in [
        "limit=0",
        "limit=-1",
        "limit=many",
        "limit=",
        "limit=1.5",
        "other=1",
    ] {
        let body = fetch(
            &app,
            &alice,
            &format!("/api/audit-log?{query}"),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(
            body,
            json!({"error": "limit must be a whole number of at least 1", "field": "limit"}),
            "{query}"
        );
    }
}

#[tokio::test]
async fn an_unreadable_line_is_marked_and_the_rest_still_shown() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let log = app.vault_home("alice").join("audit.log");
    let mut text = std::fs::read_to_string(&log).unwrap();
    text.push_str("not json\n");
    std::fs::write(&log, text).unwrap();

    let body = fetch(&app, &alice, "/api/audit-log", StatusCode::OK).await;
    assert_eq!(body["events"][0], json!({"kind": "unreadable"}));
    assert_eq!(kinds(&body)[1..], ["vault_created"]);
}

#[tokio::test]
async fn the_log_never_holds_a_field_value() {
    let app = TestApp::new();
    let alice = app
        .vault_with(
            "alice",
            [Secret::new("GitHub")
                .with_username("alice-at-github")
                .with_password(HiddenValue::new("pa55-never-logged".into()))],
        )
        .await;
    let revealed = app
        .send(alice.post_json("/api/secrets/GitHub/reveal", &json!({"field": "password"})))
        .await;
    assert_eq!(revealed.status(), StatusCode::OK);

    let response = app.send(alice.get("/api/audit-log")).await;
    let text = body_text(response).await;
    assert!(text.contains("secret_revealed"), "{text}");
    assert!(!text.contains("pa55-never-logged"), "{text}");
    assert!(!text.contains("alice-at-github"), "{text}");
}

#[tokio::test]
async fn a_session_reads_only_its_own_vaults_log() {
    let app = TestApp::new();
    app.vault_with("bob", [Secret::new("bob-only")]).await;
    let alice = app.create_vault("alice").await;

    let response = app.send(alice.get("/api/audit-log?limit=1000")).await;
    let text = body_text(response).await;
    assert!(!text.contains("bob-only"), "{text}");
}

#[tokio::test]
async fn the_log_without_a_session_is_refused() {
    let app = TestApp::new();
    app.create_vault("alice").await;

    let response = app.send(get("/api/audit-log")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
