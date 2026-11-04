//! Listing and viewing secrets over the HTTP API: what the list and detail views
//! contain, what they never contain, titles in URLs, and per-vault access.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use vault_core::session::{Clock, CustomField, HiddenValue, Secret};

/// A hidden value that must never appear in a list or detail response.
const PASSWORD_VALUE: &str = "pa55-never-listed";
/// A hidden custom field value that must never appear in a list or detail response.
const RECOVERY_VALUE: &str = "recovery-never-listed";
/// Notes, shown in the detail view only.
const NOTES: &str = "security questions: none";
/// A plain custom field value, shown in the detail view only.
const REGION: &str = "eu-west-1";

/// A secret using every kind of field.
///
/// ```text
/// app.vault_with("alice", [github()]).await;
/// ```
fn github() -> Secret {
    Secret::new("GitHub")
        .with_username("alice")
        .with_password(HiddenValue::new(PASSWORD_VALUE.into()))
        .with_url("https://github.com")
        .with_notes(NOTES)
        .with_tag("work")
        .with_tag("code")
        .with_custom_field(CustomField::hidden(
            "recovery code",
            HiddenValue::new(RECOVERY_VALUE.into()),
        ))
        .with_custom_field(CustomField::plain("region", REGION))
}

#[tokio::test]
async fn list_shows_every_secret_without_hidden_values_notes_or_plain_custom_values() {
    let app = TestApp::new();
    let alice = app
        .vault_with("alice", [github(), Secret::new("bank")])
        .await;

    let response = app.send(alice.get("/api/secrets")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_security_headers(response.headers());
    let text = body_text(response).await;
    for never in [PASSWORD_VALUE, RECOVERY_VALUE, NOTES, REGION] {
        assert!(!text.contains(never), "list leaks {never:?}");
    }
    let mut body: serde_json::Value = serde_json::from_str(&text).unwrap();
    let secrets = body["secrets"].as_array_mut().unwrap();
    for secret in secrets.iter_mut() {
        let object = secret.as_object_mut().unwrap();
        assert!(object.remove("created_at").unwrap().as_u64().unwrap() > 0);
        assert!(object.remove("updated_at").unwrap().as_u64().unwrap() > 0);
    }
    assert_eq!(
        body,
        json!({"secrets": [
            {
                "title": "bank",
                "username": null,
                "url": null,
                "tags": [],
                "has_password": false,
                "has_notes": false,
                "custom_fields": [],
            },
            {
                "title": "GitHub",
                "username": "alice",
                "url": "https://github.com",
                "tags": ["work", "code"],
                "has_password": true,
                "has_notes": true,
                "custom_fields": [
                    {"name": "recovery code", "hidden": true},
                    {"name": "region", "hidden": false},
                ],
            },
        ]})
    );
}

/// The detail response for `title` from `session`, with the timestamps checked and
/// removed so the rest can be compared exactly.
///
/// ```text
/// let body = detail(&app, &alice, "GitHub").await;
/// ```
async fn detail(app: &TestApp, session: &Unlocked, path_title: &str) -> serde_json::Value {
    let path = format!("/api/secrets/{path_title}");
    let response = app.send(session.get(&path)).await;
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    assert_security_headers(response.headers());
    let text = body_text(response).await;
    for never in [PASSWORD_VALUE, RECOVERY_VALUE] {
        assert!(!text.contains(never), "detail leaks {never:?}");
    }
    let mut body: serde_json::Value = serde_json::from_str(&text).unwrap();
    let object = body.as_object_mut().unwrap();
    assert!(object.remove("created_at").unwrap().as_u64().unwrap() > 0);
    assert!(object.remove("updated_at").unwrap().as_u64().unwrap() > 0);
    body
}

#[tokio::test]
async fn detail_shows_non_hidden_fields_and_names_hidden_ones_only() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;

    assert_eq!(
        detail(&app, &alice, "GitHub").await,
        json!({
            "title": "GitHub",
            "username": "alice",
            "url": "https://github.com",
            "notes": NOTES,
            "tags": ["work", "code"],
            "has_password": true,
            "custom_fields": [
                {"name": "recovery code", "hidden": true},
                {"name": "region", "hidden": false, "value": REGION},
            ],
        })
    );
}

#[tokio::test]
async fn detail_of_a_secret_with_only_a_title_has_empty_fields() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [Secret::new("bank")]).await;

    assert_eq!(
        detail(&app, &alice, "bank").await,
        json!({
            "title": "bank",
            "username": null,
            "url": null,
            "notes": null,
            "tags": [],
            "has_password": false,
            "custom_fields": [],
        })
    );
}

/// `text` percent-encoded for one path segment: every byte but ASCII letters and digits
/// becomes `%XX` (dots included, which axum doesn't resolve as dot segments).
///
/// ```text
/// assert_eq!(encode("a b/.."), "a%20b%2F%2E%2E");
/// ```
fn encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[tokio::test]
async fn unusual_titles_round_trip_through_percent_encoding() {
    let titles = [
        "my bank / savings",
        "..",
        ".",
        "50% off?#&=+",
        "日本語 🔑",
        "<script>alert(1)</script>",
        "back\\slash 'quotes\"",
    ];
    let app = TestApp::new();
    let alice = app
        .vault_with("alice", titles.iter().map(|title| Secret::new(*title)))
        .await;

    for title in titles {
        let body = detail(&app, &alice, &encode(title)).await;
        assert_eq!(body["title"], title);
    }
}

#[tokio::test]
async fn dot_titles_are_found_by_the_paths_the_client_sends() {
    // Browsers resolve `.`, `..` and `%2E%2E` as dot segments, so the client appends an
    // encoded space (`web/src/secrets.ts`); lookup ignores surrounding spaces.
    let app = TestApp::new();
    let alice = app
        .vault_with("alice", [Secret::new("."), Secret::new("..")])
        .await;

    assert_eq!(detail(&app, &alice, ".%20").await["title"], ".");
    assert_eq!(detail(&app, &alice, "..%20").await["title"], "..");
}

#[tokio::test]
async fn detail_matches_titles_ignoring_case() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;

    assert_eq!(detail(&app, &alice, "gITHUB").await["title"], "GitHub");
}

#[tokio::test]
async fn unknown_title_is_404_without_echoing_it() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;

    for path in [
        "/api/secrets/gitlab",
        "/api/secrets/%FF%FE", // not UTF-8
        "/api/secrets/GitHub/extra",
    ] {
        let response = app.send(alice.get(path)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_security_headers(response.headers());
        let text = body_text(response).await;
        assert!(
            !text.contains("gitlab") && !text.contains("GitHub"),
            "{text}"
        );
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(body["error"].is_string(), "{path}");
    }
    // The session is still there.
    assert_eq!(app.send(alice.session()).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_session_reads_only_the_vault_it_unlocked() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;
    let bob = app.vault_with("bob", [Secret::new("bob's bank")]).await;

    let body = body_json(app.send(bob.get("/api/secrets")).await).await;
    let titles: Vec<_> = body["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|secret| secret["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["bob's bank"]);
    let response = app.send(bob.get("/api/secrets/GitHub")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // A vaultname in the query is ignored: the vault comes from the session alone.
    let response = app
        .send(bob.get("/api/secrets/GitHub?vaultname=alice"))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    assert_eq!(detail(&app, &alice, "GitHub").await["title"], "GitHub");
}

#[tokio::test]
async fn reading_secrets_without_a_live_session_is_401_and_ends_it_in_the_browser() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;
    let no_cookie = || {
        api(Method::GET, "/api/secrets")
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.send(no_cookie()).await.status(),
        StatusCode::UNAUTHORIZED
    );

    app.clock.sleep(Duration::from_secs(5 * 60));
    for path in ["/api/secrets", "/api/secrets/GitHub"] {
        let response = app.send(alice.get(path)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert!(set_cookie(&response).unwrap().contains("Max-Age=0"));
        assert_eq!(
            response.headers()["clear-site-data"],
            "\"cache\", \"storage\""
        );
        assert_eq!(
            body_json(response).await,
            json!({"error": "vault is locked"})
        );
    }
}

#[tokio::test]
async fn locked_session_reads_nothing() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;
    assert_eq!(
        app.send(alice.lock()).await.status(),
        StatusCode::NO_CONTENT
    );

    let response = app.send(alice.get("/api/secrets")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!body_text(response).await.contains("GitHub"));
}

#[tokio::test]
async fn reading_secrets_is_not_audited_as_a_reveal() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;
    app.send(alice.get("/api/secrets")).await;
    detail(&app, &alice, "GitHub").await;

    assert!(!app.audit_log("alice").contains("revealed"));
}

#[tokio::test]
async fn request_logs_carry_route_templates_but_no_title_or_field_value() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;

    let (_, list_logs) = send_logged(&app, alice.get("/api/secrets")).await;
    let (_, detail_logs) = send_logged(&app, alice.get("/api/secrets/GitHub")).await;
    let (_, missing_logs) = send_logged(&app, alice.get("/api/secrets/zebracorn")).await;

    assert!(list_logs.contains("/api/secrets "), "{list_logs}");
    for logs in [&detail_logs, &missing_logs] {
        assert!(logs.contains("/api/secrets/{title}"), "{logs}");
    }
    for logs in [&list_logs, &detail_logs, &missing_logs] {
        for leak in [
            "GitHub",
            "zebracorn",
            "alice",
            NOTES,
            REGION,
            PASSWORD_VALUE,
        ] {
            assert!(!logs.contains(leak), "{leak:?} in {logs}");
        }
    }
}
