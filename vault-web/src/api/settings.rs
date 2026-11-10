//! The settings page's requests: `POST /api/master-password` (change the master
//! password) and `POST /api/backup` (download a backup).
//!
//! Security:
//! - Both act only on the vault their session unlocked ([`CurrentSession`]) and need
//!   the CSRF token.
//! - A master password change derives keys on the blocking pool behind the KDF limiter
//!   (503 when saturated), after the new master password's rules are checked, so an
//!   invalid one never takes a slot.
//! - A wrong current master password waits out the `vault-core` failure delay and is
//!   audited; [`MAX_WRONG_MASTER_PASSWORDS`] in a row lock the session, so a stolen
//!   session cookie can't be used to guess the master password for long.
//! - A change locks every other web session on the vault and reissues this one under a
//!   new session ID and CSRF token, so whatever was taken before the change is useless.
//!   Sessions in other processes (the CLI) lock on their next save, as on any conflict.
//! - A backup is the vault file as stored, ciphertext only, checked to be the revision
//!   the session holds and to open with its vault key before it is sent; it is
//!   recorded as made once handed out, since the server can't know the download ended.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use vault_core::session::{SessionError, check_master_password};

use crate::AppState;
use crate::api::vault::issued_session;
use crate::api::{ApiError, Cause, internal_error, kdf_error, read_error};
use crate::auth::CurrentSession;
use crate::json::{MasterPasswordField, StrictJson};

/// Wrong current master passwords in a row after which a session is locked.
const MAX_WRONG_MASTER_PASSWORDS: u32 = 3;

/// The body of `POST /api/master-password`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChangeRequest {
    /// The master password the vault has now, read straight into locked memory.
    current_master_password: MasterPasswordField,
    /// The master password to change it to, read straight into locked memory.
    new_master_password: MasterPasswordField,
}

/// `POST /api/master-password`: changes the master password of the session's vault,
/// locks the vault's other web sessions and reissues this one (200, new cookie).
///
/// Errors: 400 with `field` `new_master_password` for a new master password breaking
/// the rules, or `current_master_password` for a wrong current one (the third in a row
/// is a 401 that ends the session); 503 when the KDF limiter is saturated or the
/// server is stopping.
///
/// ```text
/// POST /api/master-password   (cookie, X-CSRF-Token)
///   {"current_master_password": "...", "new_master_password": "..."}
/// 200 {"csrf_token": "...", "vaultname": "alice", "idle_timeout_minutes": 5}
/// ```
pub(crate) async fn change_master_password(
    State(state): State<AppState>,
    current: CurrentSession,
    StrictJson(request): StrictJson<ChangeRequest>,
) -> Result<Response, ApiError> {
    let ChangeRequest {
        current_master_password,
        new_master_password,
    } = request;
    check_master_password(&new_master_password.0)
        .map_err(|weak| ApiError::field("new_master_password", weak.to_string()))?;
    let sessions = Arc::clone(&state.sessions);
    let reissued = state
        .kdf
        .run(move || {
            let changed = current.with_live_vault_blocking(&sessions, |vault| {
                vault.change_master_password(&current_master_password.0, &new_master_password.0)
            });
            match changed {
                Ok(()) => {
                    sessions.lock_others(current.session().vaultname(), current.key());
                    Ok(sessions.reissue(current.key()))
                }
                Err(SessionError::UnlockFailed) => {
                    let wrong = current.session().count_wrong_master_password();
                    if wrong >= MAX_WRONG_MASTER_PASSWORDS {
                        sessions.remove(current.key());
                        Err(ApiError::LOCKED)
                    } else {
                        Err(ApiError::WRONG_MASTER_PASSWORD)
                    }
                }
                Err(err) => Err(read_error(err)),
            }
        })
        .await
        .map_err(kdf_error)??;
    issued_session(reissued, StatusCode::OK)
}

/// `POST /api/backup`: the session's vault file as stored, as an attachment named
/// `<vaultname>-r<revision>.vault` (200). A POST with the CSRF token, since it writes an
/// audit event.
///
/// Errors: 401 (ending the session) if another session saved since unlock, as on a
/// save conflict; 500 if the stored file doesn't open with the session's vault key.
///
/// ```text
/// POST /api/backup   (cookie, X-CSRF-Token)
/// 200 Content-Disposition: attachment; filename="alice-r3.vault"   <vault file bytes>
/// ```
pub(crate) async fn backup(
    State(state): State<AppState>,
    current: CurrentSession,
) -> Result<Response, ApiError> {
    let file = current
        .with_live_vault(&state.sessions, move |vault| vault.backup_file())
        .await
        .map_err(read_error)?;
    let name = format!(
        "attachment; filename=\"{}-r{}.vault\"",
        current.session().vaultname().as_str(),
        file.revision()
    );
    let disposition =
        HeaderValue::try_from(name).map_err(|_| internal_error(Cause::ResponseHeader, None))?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        file.bytes().to_vec(),
    )
        .into_response())
}
