//! The audit log page's request: `GET /api/audit-log`.
//!
//! Security:
//! - Reads only the audit log of the vault the session unlocked ([`CurrentSession`]);
//!   no vaultname is taken from the request.
//! - An audit event names at most a secret's title, never a field value
//!   (`vault-core::audit`); the client shows titles as text.

use axum::Json;
use axum::extract::{RawQuery, State};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use vault_core::audit::{Line, Record};

use crate::AppState;
use crate::api::{ApiError, read_error};
use crate::auth::CurrentSession;

/// Events sent when the request names no `limit`.
const DEFAULT_LIMIT: usize = 20;

/// Most events sent at once; a larger `limit` is capped to it.
const MAX_LIMIT: usize = 1000;

/// The body of `GET /api/audit-log`.
#[derive(Serialize)]
pub(crate) struct AuditLog {
    /// The newest events, newest first.
    events: Vec<AuditEvent>,
}

/// One line of the audit log: its record as stored (`time` in RFC 3339 UTC, `kind`,
/// and `title` or `revision` where the event has one), or `{"kind": "unreadable"}`.
struct AuditEvent(Line);

impl Serialize for AuditEvent {
    /// Writes the record as stored, or the unreadable marker.
    ///
    /// ```ignore
    /// serde_json::to_string(&AuditEvent(Line::Unreadable))? // {"kind":"unreadable"}
    /// ```
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Line::Record(record) => Record::serialize(record, serializer),
            Line::Unreadable => {
                let mut event = serializer.serialize_struct("AuditEvent", 1)?;
                event.serialize_field("kind", "unreadable")?;
                event.end()
            }
        }
    }
}

/// `GET /api/audit-log?limit=N`: up to `limit` (default 20, capped at 1000) of the newest
/// audit events of the session's vault, newest first.
///
/// Errors: 400 with `field` `limit` for any query but `limit` with a whole number of at
/// least 1.
///
/// ```text
/// GET /api/audit-log?limit=2   (cookie)
/// 200 {"events": [{"time": "2026-11-06T10:00:00Z", "kind": "secret_revealed", "title": "GitHub"},
///                 {"time": "2026-11-06T09:59:00Z", "kind": "unlocked"}]}
/// ```
pub(crate) async fn read(
    State(state): State<AppState>,
    current: CurrentSession,
    RawQuery(query): RawQuery,
) -> Result<Json<AuditLog>, ApiError> {
    let limit = limit(query.as_deref())?;
    let lines = current
        .with_live_vault(&state.sessions, |vault| vault.audit_log(limit))
        .map_err(read_error)?;
    Ok(Json(AuditLog {
        events: lines.into_iter().map(AuditEvent).collect(),
    }))
}

/// The `limit` the query asks for, capped at [`MAX_LIMIT`], or the default without a
/// query; 400 for anything else.
///
/// ```ignore
/// assert_eq!(limit(Some("limit=50"))?, 50);
/// assert_eq!(limit(Some("limit=5000"))?, 1000);
/// ```
fn limit(query: Option<&str>) -> Result<usize, ApiError> {
    let Some(query) = query else {
        return Ok(DEFAULT_LIMIT);
    };
    let digits = query
        .strip_prefix("limit=")
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(invalid_limit)?;
    // Past MAX_LIMIT the exact value doesn't matter; leading zeros are dropped first so
    // they can't make a small number look long.
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return Err(invalid_limit());
    }
    Ok(significant
        .parse()
        .map_or(MAX_LIMIT, |n: usize| n.min(MAX_LIMIT)))
}

/// The 400 for a `limit` that isn't a whole number of at least 1.
///
/// ```ignore
/// return Err(invalid_limit());
/// ```
fn invalid_limit() -> ApiError {
    ApiError::field("limit", "limit must be a whole number of at least 1")
}
