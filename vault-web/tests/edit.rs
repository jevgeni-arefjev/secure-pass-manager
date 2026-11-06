//! Adding, editing and deleting secrets over the HTTP API: generated passwords, 409 on
//! a taken title, hidden values kept when sent as unchanged, field-level validation
//! errors, strict parsing, audit events, and a save conflict locking the session.

mod common;

use axum::body::Body;
use axum::http::{Method, Response, StatusCode, header};
use common::*;
use serde_json::{Value, json};
use vault_core::session::{Clock, FILLER_TITLE};

/// The JSON body of a response, asserting its status and the security headers.
///
/// ```text
/// let body = expect(app.send(request).await, StatusCode::CREATED).await;
/// ```
async fn expect(response: Response<Body>, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_security_headers(response.headers());
    body_json(response).await
}

#[tokio::test]
async fn adds_a_secret() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let secret = json!({
        "title": "GitHub",
        "username": "alice",
        "password": "s3cret-pa55",
        "url": "https://github.com",
        "notes": "two lines\nof notes",
        "tags": ["work", "code"],
        "custom_fields": [
            {"name": "region", "hidden": false, "value": "eu-west-1"},
            {"name": "recovery code", "hidden": true, "value": "rc-123"},
        ],
    });

    let body = expect(
        app.send(alice.post_json("/api/secrets", &secret)).await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(body["title"], "GitHub");
    assert_eq!(body["password_generated"], false);
    assert!(!body.to_string().contains("s3cret-pa55"), "{body}");
    assert!(!body.to_string().contains("rc-123"), "{body}");

    let detail = expect(
        app.send(alice.get("/api/secrets/GitHub")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(detail["username"], "alice");
    assert_eq!(detail["url"], "https://github.com");
    assert_eq!(detail["notes"], "two lines\nof notes");
    assert_eq!(detail["tags"], json!(["work", "code"]));
    assert_eq!(detail["has_password"], true);
    assert_eq!(
        detail["custom_fields"],
        json!([
            {"name": "region", "hidden": false, "value": "eu-west-1"},
            {"name": "recovery code", "hidden": true},
        ])
    );
    let revealed = expect(
        app.send(alice.post_json(
            "/api/secrets/GitHub/reveal",
            &json!({"field": "recovery code"}),
        ))
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(revealed["value"], "rc-123");
    assert!(app.audit_log("alice").contains("secret_added"));
}

#[tokio::test]
async fn an_absent_or_empty_password_is_generated_on_the_server() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;

    for (title, password) in [
        ("absent", None),
        ("null", Some(json!(null))),
        ("empty", Some(json!(""))),
    ] {
        let mut secret = json!({"title": title});
        if let Some(password) = password {
            secret["password"] = password;
        }
        let body = expect(
            app.send(alice.post_json("/api/secrets", &secret)).await,
            StatusCode::CREATED,
        )
        .await;
        assert_eq!(body["password_generated"], true, "{title}");
        assert_eq!(body["has_password"], true, "{title}");

        let revealed = expect(
            app.send(alice.post_json(
                &format!("/api/secrets/{title}/reveal"),
                &json!({"field": "password"}),
            ))
            .await,
            StatusCode::OK,
        )
        .await;
        let generated = revealed["value"].as_str().unwrap();
        assert_eq!(generated.len(), 24, "{title}");
        assert!(generated.chars().all(|c| c.is_ascii_graphic()), "{title}");
    }
}

#[tokio::test]
async fn adding_a_taken_title_is_409_and_keeps_the_stored_secret() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let first = json!({"title": "GitHub", "username": "alice"});
    assert_eq!(
        app.send(alice.post_json("/api/secrets", &first))
            .await
            .status(),
        StatusCode::CREATED
    );

    for title in ["GitHub", "github", "  GITHUB "] {
        let body = expect(
            app.send(alice.post_json(
                "/api/secrets",
                &json!({"title": title, "username": "mallory"}),
            ))
            .await,
            StatusCode::CONFLICT,
        )
        .await;
        assert_eq!(
            body,
            json!({"error": "a secret with this title already exists", "field": "title"})
        );
    }
    let detail = expect(
        app.send(alice.get("/api/secrets/GitHub")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(detail["username"], "alice");
}

/// A secret with a password, a hidden custom field and a plain one, as an add body.
///
/// ```text
/// app.send(alice.post_json("/api/secrets", &github())).await;
/// ```
fn github() -> Value {
    json!({
        "title": "GitHub",
        "username": "alice",
        "password": "old-pa55word",
        "custom_fields": [
            {"name": "recovery code", "hidden": true, "value": "old-recovery"},
            {"name": "region", "hidden": false, "value": "eu-west-1"},
        ],
    })
}

/// `app` with vault `alice` holding [`github`], and alice's session.
///
/// ```text
/// let (app, alice) = with_github().await;
/// ```
async fn with_github() -> (TestApp, Unlocked) {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let response = app.send(alice.post_json("/api/secrets", &github())).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    (app, alice)
}

/// The value of hidden field `field` of GitHub, revealed through the API.
///
/// ```text
/// assert_eq!(revealed(&app, &alice, "password").await, "old-pa55word");
/// ```
async fn revealed(app: &TestApp, session: &Unlocked, field: &str) -> String {
    let body = expect(
        app.send(session.post_json("/api/secrets/GitHub/reveal", &json!({"field": field})))
            .await,
        StatusCode::OK,
    )
    .await;
    body["value"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn replace_keeps_hidden_values_sent_as_unchanged() {
    let (app, alice) = with_github().await;
    app.clock.sleep(std::time::Duration::from_secs(60));
    let edit = json!({
        "title": "GitHub",
        "username": "alice2",
        "password": {"unchanged": true},
        "tags": ["work"],
        "custom_fields": [
            {"name": "recovery code", "hidden": true, "value": {"unchanged": true}},
            {"name": "region", "hidden": false, "value": "us-east-1"},
        ],
    });

    let body = expect(
        app.send(alice.put_json("/api/secrets/GitHub", &edit)).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(body["username"], "alice2");
    assert_eq!(body["tags"], json!(["work"]));
    assert_eq!(body["password_generated"], false);
    assert_eq!(body["created_at"], 1_800_000_000u64);
    assert_eq!(body["updated_at"], 1_800_000_060u64);
    assert_eq!(revealed(&app, &alice, "password").await, "old-pa55word");
    assert_eq!(
        revealed(&app, &alice, "recovery code").await,
        "old-recovery"
    );
    assert!(app.audit_log("alice").contains("secret_replaced"));
}

#[tokio::test]
async fn replace_takes_new_hidden_values_and_drops_left_out_fields() {
    let (app, alice) = with_github().await;
    let edit = json!({
        "title": "GitHub",
        "password": "new-pa55word",
        "custom_fields": [{"name": "pin", "hidden": true, "value": "1234"}],
    });

    let body = expect(
        app.send(alice.put_json("/api/secrets/GitHub", &edit)).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(body["username"], Value::Null);
    assert_eq!(
        body["custom_fields"],
        json!([{"name": "pin", "hidden": true}])
    );
    assert!(!body.to_string().contains("1234"), "{body}");
    assert_eq!(revealed(&app, &alice, "password").await, "new-pa55word");
    assert_eq!(revealed(&app, &alice, "pin").await, "1234");
}

#[tokio::test]
async fn replace_refuses_a_changed_title() {
    let (app, alice) = with_github().await;

    for (path, title) in [
        ("GitHub", "GitLab"),
        ("GitHub", "github"),
        ("github", "github"),
    ] {
        let mut edit = github();
        edit["title"] = json!(title);
        let body = expect(
            app.send(alice.put_json(&format!("/api/secrets/{path}"), &edit))
                .await,
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(
            body,
            json!({"error": "the title can't be changed", "field": "title"}),
            "{path} {title}"
        );
    }
    let list = expect(app.send(alice.get("/api/secrets")).await, StatusCode::OK).await;
    assert_eq!(list["secrets"][0]["title"], "GitHub");
}

#[tokio::test]
async fn unchanged_without_a_stored_hidden_value_is_400() {
    let (app, alice) = with_github().await;
    let keep = json!({"unchanged": true});

    let cases = [
        (
            "password",
            json!({"title": "new", "password": keep}),
            "/api/secrets",
            "password",
        ),
        (
            "unknown custom field",
            json!({"title": "GitHub", "custom_fields": [{"name": "pin", "hidden": true, "value": keep}]}),
            "/api/secrets/GitHub",
            "custom_fields",
        ),
        (
            "plain custom field",
            json!({"title": "GitHub", "custom_fields": [{"name": "region", "hidden": true, "value": keep}]}),
            "/api/secrets/GitHub",
            "custom_fields",
        ),
        (
            "kept as plain",
            json!({"title": "GitHub", "custom_fields": [{"name": "recovery code", "hidden": false, "value": keep}]}),
            "/api/secrets/GitHub",
            "custom_fields",
        ),
    ];
    for (case, body, path, field) in cases {
        let method = if path == "/api/secrets" {
            Method::POST
        } else {
            Method::PUT
        };
        let error = expect(
            app.send(alice.send_json(method, path, &body)).await,
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(error["field"], field, "{case}");
        assert!(!error.to_string().contains("old-"), "{case}");
    }
    assert_eq!(
        revealed(&app, &alice, "recovery code").await,
        "old-recovery"
    );
}

#[tokio::test]
async fn replace_of_an_unknown_title_is_404() {
    let (app, alice) = with_github().await;
    let mut edit = github();
    edit["title"] = json!("zebracorn");

    let response = app
        .send(alice.put_json("/api/secrets/zebracorn", &edit))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(!body_text(response).await.contains("zebracorn"));
}

#[tokio::test]
async fn delete_removes_the_secret_and_records_it() {
    let (app, alice) = with_github().await;

    let response = app.send(alice.delete("/api/secrets/github")).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_security_headers(response.headers());
    assert_eq!(
        app.send(alice.get("/api/secrets/GitHub")).await.status(),
        StatusCode::NOT_FOUND
    );
    assert!(app.audit_log("alice").contains("secret_removed"));

    let again = app.send(alice.delete("/api/secrets/GitHub")).await;
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
    let unknown = app.send(alice.delete("/api/secrets/%FF%FE")).await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn changes_require_the_csrf_token() {
    let (app, alice) = with_github().await;
    let without_token = |method: Method, path: &str, body: Option<&Value>| {
        let request = api(method, path).header(header::COOKIE, &alice.cookie);
        match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap()
    };
    let mut edit = github();
    edit["username"] = json!("mallory");

    for request in [
        without_token(Method::POST, "/api/secrets", Some(&json!({"title": "new"}))),
        without_token(Method::PUT, "/api/secrets/GitHub", Some(&edit)),
        without_token(Method::DELETE, "/api/secrets/GitHub", None),
    ] {
        assert_eq!(app.send(request).await.status(), StatusCode::FORBIDDEN);
    }
    let list = expect(app.send(alice.get("/api/secrets")).await, StatusCode::OK).await;
    assert_eq!(list["secrets"].as_array().unwrap().len(), 1);
    assert_eq!(list["secrets"][0]["username"], "alice");
}

#[tokio::test]
async fn refused_secrets_list_every_field_and_never_echo_a_value() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let marker = "zebracorn";
    let long = |n: usize| format!("{marker}{}", "x".repeat(n));
    let field = |name: &str, hidden: bool, value: Value| json!({"name": name, "hidden": hidden, "value": value});
    let at = |field: &str, index: Option<usize>, part: Option<&str>| {
        let mut location = json!({"field": field});
        if let Some(index) = index {
            location["index"] = json!(index);
        }
        if let Some(part) = part {
            location["part"] = json!(part);
        }
        vec![location]
    };

    let cases = [
        ("empty title", json!({"title": ""}), at("title", None, None)),
        (
            "blank title",
            json!({"title": "   "}),
            at("title", None, None),
        ),
        (
            "long title",
            json!({"title": long(64)}),
            at("title", None, None),
        ),
        (
            "escape in title",
            json!({"title": format!("{marker}\u{1b}[2J")}),
            at("title", None, None),
        ),
        (
            "bidi override in title",
            json!({"title": format!("{marker}\u{202e}")}),
            at("title", None, None),
        ),
        (
            "soft hyphen in title",
            json!({"title": format!("{marker}\u{ad}")}),
            at("title", None, None),
        ),
        (
            "tag character in username",
            json!({"title": "t", "username": format!("{marker}\u{e0041}")}),
            at("username", None, None),
        ),
        (
            "javascript URL",
            json!({"title": "t", "url": format!("javascript:alert('{marker}')")}),
            at("url", None, None),
        ),
        (
            "URL without a host",
            json!({"title": "t", "url": "https://"}),
            at("url", None, None),
        ),
        (
            "ssh URL",
            json!({"title": "t", "url": format!("ssh://{marker}")}),
            at("url", None, None),
        ),
        (
            "line separator in notes",
            json!({"title": "t", "notes": format!("{marker}\u{2028}")}),
            at("notes", None, None),
        ),
        (
            "whitespace-only tag",
            json!({"title": "t", "tags": ["work", "   "]}),
            at("tags", Some(1), None),
        ),
        (
            "NFC-equal tags",
            json!({"title": "t", "tags": ["caf\u{e9}", " CAFE\u{301}"]}),
            at("tags", Some(1), None),
        ),
        (
            "zero-width joiner in custom name",
            json!({"title": "t", "custom_fields": [field(&format!("{marker}\u{200d}"), false, json!("v"))]}),
            at("custom_fields", Some(0), Some("name")),
        ),
        (
            "whitespace-only custom name",
            json!({"title": "t", "custom_fields": [field("  ", false, json!("v"))]}),
            at("custom_fields", Some(0), Some("name")),
        ),
        (
            "empty username",
            json!({"title": "t", "username": ""}),
            at("username", None, None),
        ),
        (
            "newline in username",
            json!({"title": "t", "username": format!("{marker}\nx")}),
            at("username", None, None),
        ),
        (
            "long password",
            json!({"title": "t", "password": long(1024)}),
            at("password", None, None),
        ),
        (
            "control in password",
            json!({"title": "t", "password": format!("{marker}\u{7}")}),
            at("password", None, None),
        ),
        (
            "long URL",
            json!({"title": "t", "url": long(2048)}),
            at("url", None, None),
        ),
        (
            "escape in notes",
            json!({"title": "t", "notes": format!("{marker}\u{1b}")}),
            at("notes", None, None),
        ),
        (
            "long notes",
            json!({"title": "t", "notes": long(4096)}),
            at("notes", None, None),
        ),
        (
            "empty tag",
            json!({"title": "t", "tags": [""]}),
            at("tags", Some(0), None),
        ),
        (
            "duplicate tags",
            json!({"title": "t", "tags": ["Work", "work"]}),
            at("tags", Some(1), None),
        ),
        (
            "too many tags",
            json!({"title": "t", "tags": (0..33).map(|i| i.to_string()).collect::<Vec<_>>()}),
            at("tags", None, None),
        ),
        (
            "empty custom name",
            json!({"title": "t", "custom_fields": [field("", false, json!("v"))]}),
            at("custom_fields", Some(0), Some("name")),
        ),
        (
            "standard field name",
            json!({"title": "t", "custom_fields": [field("Password", true, json!("v"))]}),
            at("custom_fields", Some(0), Some("name")),
        ),
        (
            "empty custom value",
            json!({"title": "t", "custom_fields": [field("pin", true, json!(""))]}),
            at("custom_fields", Some(0), Some("value")),
        ),
        (
            "long plain value",
            json!({"title": "t", "custom_fields": [field("region", false, json!(long(1024)))]}),
            at("custom_fields", Some(0), Some("value")),
        ),
        (
            "duplicate custom names",
            json!({"title": "t", "custom_fields": [field("pin", false, json!("1")), field("PIN", true, json!("2"))]}),
            at("custom_fields", Some(1), Some("name")),
        ),
    ];
    for (case, body, expected) in cases {
        let response = app.send(alice.post_json("/api/secrets", &body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case}");
        let text = body_text(response).await;
        assert!(!text.contains(marker), "{case}: {text}");
        let error: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            error["error"], "secret not saved: some fields are invalid",
            "{case}"
        );
        assert!(error.get("field").is_none(), "{case}: {text}");
        assert_eq!(locations(&error), expected, "{case}: {text}");
    }

    let several = json!({
        "title": format!("{marker}\u{1b}"),
        "tags": ["work", "WORK"],
        "custom_fields": [field("pin", true, json!(long(1024)))],
    });
    let response = app.send(alice.post_json("/api/secrets", &several)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let text = body_text(response).await;
    assert!(!text.contains(marker), "{text}");
    let error: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        error["fields"],
        json!([
            {"field": "title", "message": "title must be 1-64 characters, without control or formatting characters"},
            {"field": "tags", "index": 1, "message": "tags must be unique, ignoring case"},
            {
                "field": "custom_fields",
                "index": 0,
                "part": "value",
                "message": "custom field values must be 1-1024 characters, without control or formatting characters (hidden: 1-1024, without control characters)",
            },
        ])
    );

    let list = expect(app.send(alice.get("/api/secrets")).await, StatusCode::OK).await;
    assert_eq!(list["secrets"], json!([]));
    assert!(!app.audit_log("alice").contains("secret_added"));
}

/// The `fields` of a refused-secret error without their messages, each checked to be
/// a non-empty string.
///
/// ```text
/// assert_eq!(locations(&error), [json!({"field": "tags", "index": 1})]);
/// ```
fn locations(error: &Value) -> Vec<Value> {
    error["fields"]
        .as_array()
        .expect("a fields array")
        .iter()
        .map(|problem| {
            let mut location = problem.clone();
            let message = location.as_object_mut().unwrap().remove("message");
            assert!(message.and_then(|m| m.as_str().map(|m| !m.is_empty())) == Some(true));
            location
        })
        .collect()
}

#[tokio::test]
async fn malformed_bodies_are_refused() {
    let (app, alice) = with_github().await;

    for body in [
        json!({}),
        json!({"title": "t", "also": 1}),
        json!({"title": "t", "password": 1234}),
        json!({"title": "t", "password": {"unchanged": false}}),
        json!({"title": "t", "password": {"unchanged": true, "value": "x"}}),
        json!({"title": "t", "password": {"keep": true}}),
        json!({"title": "t", "tags": "work"}),
        json!({"title": "t", "custom_fields": [{"name": "pin", "value": "1"}]}),
        json!({"title": "t", "custom_fields": [{"name": "pin", "hidden": true, "value": "1", "x": 1}]}),
        json!(["t"]),
    ] {
        let response = app.send(alice.post_json("/api/secrets", &body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body_json(response).await,
            json!({"error": "invalid request body"}),
            "{body}"
        );
    }

    let oversized = json!({"title": "t", "notes": "x".repeat(70 * 1024)});
    let response = app.send(alice.post_json("/api/secrets", &oversized)).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let not_json = alice
        .authorize(api(Method::PUT, "/api/secrets/GitHub"))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(github().to_string()))
        .unwrap();
    assert_eq!(
        app.send(not_json).await.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

#[tokio::test]
async fn a_full_vault_is_a_form_error_and_the_session_stays_open() {
    let (app, alice) = with_github().await;
    app.fill_vault("alice");
    let alice = {
        drop(alice);
        app.unlock("alice").await
    };
    let response = app
        .send(alice.post_json("/api/secrets", &json!({"title": "GitLab"})))
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(set_cookie(&response).is_none());
    assert_eq!(body_json(response).await, json!({"error": "vault is full"}));

    // The session goes on: the refused secret isn't there, and removing makes room.
    assert_eq!(
        app.send(alice.get("/api/secrets/GitLab")).await.status(),
        StatusCode::NOT_FOUND
    );
    let response = app
        .send(alice.delete(&format!("/api/secrets/{FILLER_TITLE}")))
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = app
        .send(alice.post_json("/api/secrets", &json!({"title": "GitLab"})))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn a_save_conflict_locks_the_session() {
    let (app, alice) = with_github().await;
    let other = app.unlock("alice").await;
    let response = app
        .send(other.post_json("/api/secrets", &json!({"title": "GitLab"})))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .send(alice.post_json("/api/secrets", &json!({"title": "Codeberg"})))
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(set_cookie(&response).unwrap().contains("Max-Age=0"));
    assert_eq!(body_json(response).await["error"], "vault is locked");
    assert_eq!(
        app.send(alice.session()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(app.audit_log("alice").contains("locked_on_conflict"));

    // Nothing of the refused change was saved; the other session's change was.
    let list = expect(app.send(other.get("/api/secrets")).await, StatusCode::OK).await;
    let titles: Vec<_> = list["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["title"].clone())
        .collect();
    assert_eq!(titles, [json!("GitHub"), json!("GitLab")]);
}

#[tokio::test]
async fn edit_and_delete_conflicts_lock_the_session_too() {
    for change in ["edit", "delete"] {
        let (app, alice) = with_github().await;
        let other = app.unlock("alice").await;
        assert_eq!(
            app.send(other.delete("/api/secrets/GitHub")).await.status(),
            StatusCode::NO_CONTENT
        );
        let request = match change {
            "edit" => alice.put_json("/api/secrets/GitHub", &github()),
            _ => alice.delete("/api/secrets/GitHub"),
        };
        // alice's session still holds GitHub, so the change is attempted and conflicts.
        assert_eq!(
            app.send(request).await.status(),
            StatusCode::UNAUTHORIZED,
            "{change}"
        );
        assert_eq!(
            app.send(alice.session()).await.status(),
            StatusCode::UNAUTHORIZED,
            "{change}"
        );
    }
}

#[tokio::test]
async fn changes_log_neither_titles_nor_values() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let (response, logs) = send_logged(
        &app,
        alice.post_json(
            "/api/secrets",
            &json!({"title": "zebracorn", "password": "unicorn-pa55"}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    for leaked in ["zebracorn", "unicorn-pa55"] {
        assert!(!logs.contains(leaked), "{logs}");
    }
    assert!(logs.contains("/api/secrets"), "{logs}");
}
