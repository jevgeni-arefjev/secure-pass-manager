//! Revealing one hidden field over the HTTP API: exactly one value per request, the
//! CSRF token, 404s for unknown titles and fields, plain fields refused, the audit
//! event, and nothing revealed in logs or errors.

mod common;

use axum::body::Body;
use axum::http::{Method, StatusCode, header};
use common::*;
use serde_json::{Value, json};
use vault_core::session::{CustomField, HiddenValue, Secret};

/// The password of [`github`].
const PASSWORD_VALUE: &str = "pa55-only-on-reveal";
/// The hidden custom field value of [`github`].
const RECOVERY_VALUE: &str = "recovery-only-on-reveal";
/// The plain custom field value of [`github`].
const REGION: &str = "eu-west-1";

/// A secret with a password, a hidden custom field and a plain one.
///
/// ```text
/// app.vault_with("alice", [github()]).await;
/// ```
fn github() -> Secret {
    Secret::new("GitHub")
        .with_username("alice")
        .with_password(HiddenValue::new(PASSWORD_VALUE.into()))
        .with_custom_field(CustomField::hidden(
            "recovery code",
            HiddenValue::new(RECOVERY_VALUE.into()),
        ))
        .with_custom_field(CustomField::plain("region", REGION))
}

/// `POST /api/secrets/{path_title}/reveal` for `field`, from `session`.
///
/// ```text
/// let response = app.send(reveal(&alice, "GitHub", "password")).await;
/// ```
fn reveal(session: &Unlocked, path_title: &str, field: &str) -> axum::http::Request<Body> {
    session.post_json(
        &format!("/api/secrets/{path_title}/reveal"),
        &json!({"field": field}),
    )
}

/// The JSON body of a response, asserting its status and the security headers.
///
/// ```text
/// let body = expect(app.send(request).await, StatusCode::OK).await;
/// ```
async fn expect(response: axum::http::Response<Body>, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_security_headers(response.headers());
    body_json(response).await
}

#[tokio::test]
async fn reveals_the_password() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;

    let body = expect(
        app.send(reveal(&alice, "GitHub", "password")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(body, json!({"value": PASSWORD_VALUE}));
}

#[tokio::test]
async fn reveals_a_hidden_custom_field_and_only_that_one_value() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;

    let response = app.send(reveal(&alice, "github", "recovery code")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let text = body_text(response).await;
    assert!(!text.contains(PASSWORD_VALUE), "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap(),
        json!({"value": RECOVERY_VALUE})
    );
}

#[tokio::test]
async fn a_plain_custom_field_is_refused() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;

    let body = expect(
        app.send(reveal(&alice, "GitHub", "region")).await,
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(
        body,
        json!({"error": "not a hidden field", "field": "field"})
    );
}

#[tokio::test]
async fn unknown_title_or_field_is_404_without_echoing_either() {
    let app = TestApp::new();
    let alice = app
        .vault_with("alice", [github(), Secret::new("no password")])
        .await;

    for (title, field) in [
        ("zebracorn", "password"),
        ("%FF%FE", "password"), // not UTF-8
        ("GitHub", "unicornfield"),
        ("GitHub", "Password"), // field names match exactly
        ("GitHub", "username"), // not a hidden field, and not a custom one
        ("no%20password", "password"),
    ] {
        let response = app.send(reveal(&alice, title, field)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{title} {field}");
        assert_security_headers(response.headers());
        let text = body_text(response).await;
        for echo in ["zebracorn", "unicornfield", "GitHub", PASSWORD_VALUE] {
            assert!(!text.contains(echo), "{text}");
        }
        let body: Value = serde_json::from_str(&text).unwrap();
        assert!(body["error"].is_string(), "{text}");
    }
    // The session is still there.
    assert_eq!(app.send(alice.session()).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn reveal_requires_the_csrf_token() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;
    let body = json!({"field": "password"}).to_string();
    let path = "/api/secrets/GitHub/reveal";

    let no_token = api(Method::POST, path)
        .header(header::COOKIE, &alice.cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.clone()))
        .unwrap();
    let wrong_token = api(Method::POST, path)
        .header(header::COOKIE, &alice.cookie)
        .header("x-csrf-token", "0".repeat(64))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    for request in [no_token, wrong_token] {
        let response = app.send(request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!body_text(response).await.contains(PASSWORD_VALUE));
    }
    assert!(!app.audit_log("alice").contains("secret_revealed"));
}

#[tokio::test]
async fn a_malformed_body_is_400() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;

    for body in [
        json!({}),
        json!({"field": 1}),
        json!({"field": "password", "also": "recovery code"}),
        json!({"field": ["password", "recovery code"]}),
    ] {
        let response = app
            .send(alice.post_json("/api/secrets/GitHub/reveal", &body))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        assert!(!body_text(response).await.contains(PASSWORD_VALUE));
    }
}

#[tokio::test]
async fn each_reveal_is_one_audit_event_naming_only_the_title() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;

    for field in ["password", "recovery code", "password"] {
        let response = app.send(reveal(&alice, "gitHUB", field)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    // Failed reveals record nothing.
    for field in ["region", "unicornfield"] {
        app.send(reveal(&alice, "GitHub", field)).await;
    }
    app.send(reveal(&alice, "zebracorn", "password")).await;

    let log = app.audit_log("alice");
    let reveals: Vec<Value> = log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| record["kind"] == "secret_revealed")
        .map(|mut record| {
            record.as_object_mut().unwrap().remove("time").unwrap();
            record
        })
        .collect();
    let expected = json!({"kind": "secret_revealed", "title": "GitHub"});
    assert_eq!(
        reveals,
        [expected.clone(), expected.clone(), expected],
        "{log}"
    );
    for leak in [
        PASSWORD_VALUE,
        RECOVERY_VALUE,
        "recovery code",
        REGION,
        "zebracorn",
    ] {
        assert!(!log.contains(leak), "{leak:?} in {log}");
    }
}

#[tokio::test]
async fn a_session_reveals_only_from_the_vault_it_unlocked() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;
    let bob = app.vault_with("bob", [Secret::new("bob's bank")]).await;

    let response = app.send(reveal(&bob, "GitHub", "password")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(!app.audit_log("alice").contains("secret_revealed"));
    assert_eq!(
        app.send(reveal(&alice, "GitHub", "password"))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_locked_session_reveals_nothing() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;
    assert_eq!(
        app.send(alice.lock()).await.status(),
        StatusCode::NO_CONTENT
    );

    let body = expect(
        app.send(reveal(&alice, "GitHub", "password")).await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(body, json!({"error": "vault is locked"}));
}

#[tokio::test]
async fn dot_titles_are_revealed_by_the_paths_the_client_sends() {
    let app = TestApp::new();
    let dots = Secret::new("..").with_password(HiddenValue::new(PASSWORD_VALUE.into()));
    let alice = app.vault_with("alice", [dots]).await;

    let body = expect(
        app.send(reveal(&alice, "..%20", "password")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(body["value"], PASSWORD_VALUE);
}

#[tokio::test]
async fn request_logs_and_errors_carry_no_revealed_value_or_title() {
    let app = TestApp::new();
    let alice = app.vault_with("alice", [github()]).await;

    let (ok, ok_logs) = send_logged(&app, reveal(&alice, "GitHub", "password")).await;
    assert_eq!(ok.status(), StatusCode::OK);
    let (plain, plain_logs) = send_logged(&app, reveal(&alice, "GitHub", "region")).await;
    let (missing, missing_logs) =
        send_logged(&app, reveal(&alice, "zebracorn", "recovery code")).await;
    let (_, unknown_logs) = send_logged(&app, reveal(&alice, "GitHub", "unicornfield")).await;

    for errors in [body_text(plain).await, body_text(missing).await] {
        for leak in ["GitHub", "zebracorn", "recovery code", "region", REGION] {
            assert!(!errors.contains(leak), "{leak:?} in {errors}");
        }
    }
    for logs in [&ok_logs, &plain_logs, &missing_logs, &unknown_logs] {
        assert!(logs.contains("/api/secrets/{title}/reveal"), "{logs}");
        for leak in [
            "GitHub",
            "zebracorn",
            "unicornfield",
            "recovery code",
            "region",
            "alice",
            PASSWORD_VALUE,
            RECOVERY_VALUE,
            REGION,
        ] {
            assert!(!logs.contains(leak), "{leak:?} in {logs}");
        }
    }
}
