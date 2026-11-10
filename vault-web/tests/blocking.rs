//! Slow vault work runs off the async worker threads: a request waiting on its vault
//! (a save waiting for the storage lock, another request of the same session waiting
//! for that save) never stalls unrelated requests.

mod common;

use std::fs::{File, OpenOptions};
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use common::{TestApp, expect, get};

/// Takes the storage lock of `vaultname`'s vault home, as another process (the CLI)
/// saving it would; held until the returned file is dropped. Taken in this process,
/// it still blocks the server's saves: the lock belongs to this open file, not to the
/// process.
///
/// ```text
/// let held = hold_storage_lock(&app, "alice");
/// ```
fn hold_storage_lock(app: &TestApp, vaultname: &str) -> File {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(app.vault_home(vaultname).join("secrets.lock"))
        .unwrap();
    file.lock().unwrap();
    file
}

// One worker thread: any request blocking it would stall every other request.
#[tokio::test(flavor = "current_thread")]
async fn a_save_waiting_for_the_storage_lock_stalls_no_unrelated_request() {
    let app = TestApp::new();
    let alice = app.create_vault("alice").await;
    let bob = app.create_vault("bob").await;
    let held = hold_storage_lock(&app, "alice");

    let save = tokio::spawn(
        app.router()
            .oneshot(alice.post_json("/api/secrets", &json!({"title": "GitHub"}))),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Same session: waits for the save to release the vault.
    let session_check = tokio::spawn(app.router().oneshot(alice.session()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(app.send(get("/app.js")).await.status(), StatusCode::OK);
    let listed = expect(app.send(bob.get("/api/secrets")).await, StatusCode::OK).await;
    assert_eq!(listed, json!({"secrets": []}));
    assert!(!save.is_finished(), "the save still waits for the lock");
    assert!(
        !session_check.is_finished(),
        "the session check waits for the save"
    );

    drop(held);
    expect(save.await.unwrap().unwrap(), StatusCode::CREATED).await;
    expect(session_check.await.unwrap().unwrap(), StatusCode::OK).await;
}
