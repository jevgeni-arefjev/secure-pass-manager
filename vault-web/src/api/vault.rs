//! Vault creation, unlock, lock and the session check: `POST /api/vaults`,
//! `POST /api/unlock`, `POST /api/lock` and `GET /api/session`.
//!
//! Security:
//! - Create and unlock derive keys on the blocking pool behind the KDF limiter (503
//!   when saturated), and each issues a new session ID; a session the request's cookie
//!   still named is locked first, so a cookie from before unlock is never accepted.
//! - Every unlock failure is the same 401 after at least the `vault-core` minimum
//!   failure delay, whether or not the vaultname exists; failed unlocks of an existing
//!   vault land in its audit log (`vault-core::session`). There is no lockout.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use vault_core::audit::FileSink;
use vault_core::session::{
    DEFAULT_IDLE_TIMEOUT, MIN_UNLOCK_FAILURE, Session, SessionConfig, SessionError,
};
use vault_core::storage::FileStore;

use crate::api::ApiError;
use crate::auth::{self, CurrentSession};
use crate::json::{MasterPasswordField, StrictJson};
use crate::kdf_limiter::KdfRejected;
use crate::sessions::WebSession;
use crate::{AppState, SessionTag};

/// Allowed idle timeouts, in minutes.
const IDLE_TIMEOUT_MINUTES: std::ops::RangeInclusive<u64> = 1..=60;

/// The body of `POST /api/vaults` and `POST /api/unlock`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnlockRequest {
    vaultname: String,
    master_password: MasterPasswordField,
    #[serde(default)]
    idle_timeout_minutes: Option<u64>,
}

/// What the client learns about its session: the CSRF token to send back, which vault
/// is open and its idle timeout.
#[derive(Serialize)]
struct SessionInfo<'a> {
    csrf_token: &'a str,
    vaultname: &'a str,
    idle_timeout_minutes: u64,
}

impl<'a> SessionInfo<'a> {
    /// The info for `session`.
    ///
    /// ```ignore
    /// Json(SessionInfo::of(&session))
    /// ```
    fn of(session: &'a WebSession) -> Self {
        Self {
            csrf_token: session.csrf_token(),
            vaultname: session.vaultname().as_str(),
            idle_timeout_minutes: session.idle_timeout().as_secs() / 60,
        }
    }
}

/// `POST /api/vaults`: creates a vault and returns it unlocked (201).
///
/// Errors: 400 with `field` for an invalid vaultname, a weak master password or an
/// idle timeout out of range; 409 if the vaultname is taken; 503 when the KDF limiter
/// is saturated.
///
/// ```text
/// POST /api/vaults {"vaultname": "alice", "master_password": "...", "idle_timeout_minutes": 10}
/// 201 {"csrf_token": "...", "vaultname": "alice", "idle_timeout_minutes": 10}
/// ```
pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<UnlockRequest>,
) -> Result<Response, ApiError> {
    let idle_timeout = idle_timeout(request.idle_timeout_minutes)?;
    let store = store(&state)?;
    let config = session_config(&state, idle_timeout);
    let format = state.config.create_format;
    let UnlockRequest {
        vaultname,
        master_password,
        ..
    } = request;
    let created = state
        .kdf
        .run(move || format.create_session(store, &vaultname, &master_password.0, config))
        .await
        .map_err(kdf_error)?;
    let vault = created.map_err(|err| match err {
        SessionError::InvalidVaultname | SessionError::WeakMasterPassword(_) => {
            ApiError::field(error_field(err), err.to_string())
        }
        SessionError::VaultExists => ApiError::VAULTNAME_TAKEN,
        _ => ApiError::INTERNAL,
    })?;
    open_session(&state, &headers, vault, idle_timeout, StatusCode::CREATED)
}

/// `POST /api/unlock`: unlocks a vault (200).
///
/// Errors: 400 for a malformed body or an idle timeout out of range; otherwise every
/// failure is the same 401 after at least [`MIN_UNLOCK_FAILURE`]; 503 when the KDF
/// limiter is saturated.
///
/// ```text
/// POST /api/unlock {"vaultname": "alice", "master_password": "..."}
/// 200 {"csrf_token": "...", "vaultname": "alice", "idle_timeout_minutes": 5}
/// ```
pub(crate) async fn unlock(
    State(state): State<AppState>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<UnlockRequest>,
) -> Result<Response, ApiError> {
    let idle_timeout = idle_timeout(request.idle_timeout_minutes)?;
    let store = store(&state)?;
    let config = session_config(&state, idle_timeout);
    let clock = state.config.clock.clone();
    let UnlockRequest {
        vaultname,
        master_password,
        ..
    } = request;
    let unlocked = state
        .kdf
        .run(move || {
            let started = clock.now();
            let result = Session::unlock(store, &vaultname, &master_password.0, config);
            // vault-core waits out every failure but a syntactically invalid vaultname.
            if matches!(result, Err(SessionError::InvalidVaultname)) {
                let elapsed = clock.now().saturating_duration_since(started);
                clock.sleep(MIN_UNLOCK_FAILURE.saturating_sub(elapsed));
            }
            result
        })
        .await
        .map_err(kdf_error)?;
    let vault = unlocked.map_err(|_| ApiError::UNLOCK_FAILED)?;
    open_session(&state, &headers, vault, idle_timeout, StatusCode::OK)
}

/// `POST /api/lock`: locks the session, wipes its keys, deletes the cookie and tells
/// the browser to clear its cache and storage (204).
///
/// ```text
/// POST /api/lock   (cookie, X-CSRF-Token)
/// 204   Set-Cookie: __Host-session=; ...; Max-Age=0   Clear-Site-Data: "cache", "storage"
/// ```
pub(crate) async fn lock(State(state): State<AppState>, current: CurrentSession) -> Response {
    state.sessions.remove(current.key());
    (StatusCode::NO_CONTENT, auth::ended_session_headers()).into_response()
}

/// `GET /api/session`: the cookie's session if it is still unlocked (200), else 401.
/// Used on page load; checking doesn't count as activity.
///
/// ```text
/// GET /api/session   (cookie)
/// 200 {"csrf_token": "...", "vaultname": "alice", "idle_timeout_minutes": 5}
/// ```
pub(crate) async fn session(current: CurrentSession) -> Response {
    Json(SessionInfo::of(current.session())).into_response()
}

/// Registers the unlocked `vault` as a new session and builds the response: `status`,
/// the new cookie and the session info. A session the request's cookie named is
/// locked and removed first.
///
/// Security: always a new session ID, so a cookie planted or held before unlock is
/// never accepted afterwards (session fixation).
///
/// ```ignore
/// open_session(&state, &headers, vault, idle_timeout, StatusCode::OK)
/// ```
fn open_session(
    state: &AppState,
    headers: &HeaderMap,
    vault: Session<FileStore>,
    idle_timeout: Duration,
    status: StatusCode,
) -> Result<Response, ApiError> {
    if let Some(previous) = auth::request_session_id(headers) {
        state.sessions.remove(previous.key());
    }
    let (id, session) = state
        .sessions
        .insert(vault, idle_timeout)
        .map_err(|_| ApiError::INTERNAL)?;
    let mut response = (
        status,
        [(header::SET_COOKIE, auth::session_cookie(&id))],
        Json(SessionInfo::of(&session)),
    )
        .into_response();
    response.extensions_mut().insert(SessionTag(id.key().tag()));
    Ok(response)
}

/// The idle timeout asked for, or the default; 400 if outside 1-60 minutes.
///
/// ```ignore
/// let idle_timeout = idle_timeout(Some(10))?; // 10 minutes
/// ```
fn idle_timeout(minutes: Option<u64>) -> Result<Duration, ApiError> {
    match minutes {
        None => Ok(DEFAULT_IDLE_TIMEOUT),
        Some(minutes) if IDLE_TIMEOUT_MINUTES.contains(&minutes) => {
            Ok(Duration::from_secs(minutes * 60))
        }
        Some(_) => Err(ApiError::field(
            "idle_timeout_minutes",
            "idle timeout must be 1-60 minutes",
        )),
    }
}

/// The vault store on the configured vault directory.
///
/// ```ignore
/// let store = store(&state)?;
/// ```
fn store(state: &AppState) -> Result<FileStore, ApiError> {
    FileStore::new(&state.config.vault_dir).map_err(|_| ApiError::INTERNAL)
}

/// A session config with `idle_timeout`, the app's clock and an audit log in each
/// vault home, as the CLI writes it.
///
/// ```ignore
/// let config = session_config(&state, Duration::from_secs(300));
/// ```
fn session_config(state: &AppState, idle_timeout: Duration) -> SessionConfig {
    SessionConfig {
        idle_timeout,
        clock: Arc::clone(&state.config.clock),
        ..SessionConfig::new(Arc::new(FileSink::new(&state.config.vault_dir)))
    }
}

/// The request field a create validation error is about.
///
/// ```ignore
/// assert_eq!(error_field(SessionError::InvalidVaultname), "vaultname");
/// ```
fn error_field(err: SessionError) -> &'static str {
    match err {
        SessionError::InvalidVaultname => "vaultname",
        _ => "master_password",
    }
}

/// Maps a KDF limiter refusal: 503 when busy, 500 if the job failed.
///
/// ```ignore
/// state.kdf.run(job).await.map_err(kdf_error)?
/// ```
fn kdf_error(rejected: KdfRejected) -> ApiError {
    match rejected {
        KdfRejected::Busy => ApiError::BUSY,
        KdfRejected::Failed => ApiError::INTERNAL,
    }
}
