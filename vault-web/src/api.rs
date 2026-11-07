//! The JSON API under `/api` and its error responses.
//!
//! Errors are `{"error": "<message>"}`, with a `"field"` naming the input at fault for
//! validation errors. A refused secret instead lists every problem:
//! `{"error", "fields": [{"field", "index"?, "part"?, "message"}]}`. Messages never
//! carry internals or request values.

mod audit_log;
mod edit;
mod secrets;
mod settings;
mod vault;

use std::borrow::Cow;
use std::io;

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;
use vault_core::session::{InternalFailure, SessionError};

use crate::kdf_limiter::KdfRejected;
use crate::{AppState, auth};

/// An API error: a status and a message safe to show the user.
///
/// Security: the message is a fixed string chosen by the handler or a `vault-core`
/// validation message describing the user's own input; never an internal error, path
/// or request value.
///
/// ```ignore
/// return Err(ApiError::NOT_FOUND);
/// ```
#[derive(Clone, Debug)]
pub(crate) struct ApiError {
    /// The HTTP status.
    status: StatusCode,
    /// The fixed message shown to the user.
    message: Cow<'static, str>,
    /// The request field at fault, if one is.
    field: Option<&'static str>,
    /// Every problem of a refused secret; empty for any other error.
    fields: Vec<FieldError>,
    /// Whether the response also ends the session in the browser.
    ends_session: bool,
}

/// One problem of a refused secret: the request field (`index` for a tag or custom
/// field, `part` `"name"` or `"value"` for a custom field) and a fixed message.
///
/// Security: the message is a `vault-core` rule; it never contains the value.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct FieldError {
    /// The request field (`title`, `tags`, `custom_fields`, ...).
    pub(crate) field: &'static str,
    /// For a tag or custom field, its 0-based index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) index: Option<usize>,
    /// For a custom field, `"name"` or `"value"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) part: Option<&'static str>,
    /// The rule that was broken.
    pub(crate) message: String,
}

impl ApiError {
    /// An error with a fixed message and no field.
    ///
    /// ```ignore
    /// const GONE: ApiError = ApiError::fixed(StatusCode::GONE, "gone");
    /// ```
    const fn fixed(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message: Cow::Borrowed(message),
            field: None,
            fields: Vec::new(),
            ends_session: false,
        }
    }

    /// No such route.
    pub(crate) const NOT_FOUND: Self = Self::fixed(StatusCode::NOT_FOUND, "not found");

    /// The request's `Host` (or HTTP/2 authority) doesn't name this server.
    pub(crate) const UNKNOWN_HOST: Self =
        Self::fixed(StatusCode::MISDIRECTED_REQUEST, "unknown host");

    /// A state-changing request without this server's `Origin`.
    pub(crate) const CROSS_ORIGIN: Self =
        Self::fixed(StatusCode::FORBIDDEN, "cross-origin request refused");

    /// A state-changing request without this session's CSRF token.
    pub(crate) const CSRF: Self =
        Self::fixed(StatusCode::FORBIDDEN, "missing or invalid CSRF token");

    /// Every unlock failure, whatever the cause.
    pub(crate) const UNLOCK_FAILED: Self = Self::fixed(
        StatusCode::UNAUTHORIZED,
        "wrong vaultname or master password",
    );

    /// No live session: no cookie, an unknown one, or a locked or expired session. The
    /// response also deletes the cookie and clears the browser's cache and storage
    /// ([`auth::ended_session_headers`]).
    pub(crate) const LOCKED: Self = Self {
        status: StatusCode::UNAUTHORIZED,
        message: Cow::Borrowed("vault is locked"),
        field: None,
        fields: Vec::new(),
        ends_session: true,
    };

    /// No secret with the title in the path. Never echoes the title.
    pub(crate) const SECRET_NOT_FOUND: Self =
        Self::fixed(StatusCode::NOT_FOUND, "no secret with this title");

    /// The secret has no field with the requested name (or no password). Never echoes
    /// the name.
    pub(crate) const FIELD_NOT_FOUND: Self =
        Self::fixed(StatusCode::NOT_FOUND, "no field with this name");

    /// A reveal asked for a field that isn't hidden; its value is in the detail view.
    pub(crate) const NOT_HIDDEN: Self = Self {
        status: StatusCode::BAD_REQUEST,
        message: Cow::Borrowed("not a hidden field"),
        field: Some("field"),
        fields: Vec::new(),
        ends_session: false,
    };

    /// An add was asked for a title that another secret has (ignoring case).
    pub(crate) const SECRET_EXISTS: Self = Self {
        status: StatusCode::CONFLICT,
        message: Cow::Borrowed("a secret with this title already exists"),
        field: Some("title"),
        fields: Vec::new(),
        ends_session: false,
    };

    /// A replace whose body names another title than the path and the stored secret.
    pub(crate) const TITLE_CHANGED: Self = Self {
        status: StatusCode::BAD_REQUEST,
        message: Cow::Borrowed("the title can't be changed"),
        field: Some("title"),
        fields: Vec::new(),
        ends_session: false,
    };

    /// A save would make the vault file too large to open again; nothing was saved and
    /// the session stays open. Shown on the form, like a field error.
    pub(crate) const VAULT_FULL: Self = Self::fixed(StatusCode::PAYLOAD_TOO_LARGE, "vault is full");

    /// A master password change was given a wrong current master password.
    pub(crate) const WRONG_MASTER_PASSWORD: Self = Self {
        status: StatusCode::BAD_REQUEST,
        message: Cow::Borrowed("wrong master password"),
        field: Some("current_master_password"),
        fields: Vec::new(),
        ends_session: false,
    };

    /// Create was asked for a vaultname that already has a vault.
    pub(crate) const VAULTNAME_TAKEN: Self = Self::fixed(StatusCode::CONFLICT, "vaultname taken");

    /// The request body isn't declared as JSON.
    pub(crate) const NOT_JSON: Self = Self::fixed(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "request body must be JSON",
    );

    /// The request body is over the size cap.
    pub(crate) const BODY_TOO_LARGE: Self =
        Self::fixed(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");

    /// The request body isn't valid JSON of the expected shape.
    pub(crate) const INVALID_BODY: Self =
        Self::fixed(StatusCode::BAD_REQUEST, "invalid request body");

    /// Too many unlocks or creates are deriving keys; try again shortly.
    pub(crate) const BUSY: Self = Self::fixed(
        StatusCode::SERVICE_UNAVAILABLE,
        "server busy, try again shortly",
    );

    /// The server is stopping; an unlock or create that finished meanwhile was locked.
    pub(crate) const STOPPING: Self =
        Self::fixed(StatusCode::SERVICE_UNAVAILABLE, "server is stopping");

    /// Anything that went wrong on the server; details stay on the server. Handlers
    /// answer it through [`internal_error`] or [`session_internal_error`], which log the
    /// diagnostic; only a panic, logged by its own events, uses it directly.
    pub(crate) const INTERNAL: Self =
        Self::fixed(StatusCode::INTERNAL_SERVER_ERROR, "internal error");

    /// A 400 for a hidden value of request field `field` sent as unchanged, though the
    /// stored secret has no such hidden value to keep.
    ///
    /// ```ignore
    /// stored.password().ok_or(ApiError::nothing_to_keep("password"))?
    /// ```
    pub(crate) const fn nothing_to_keep(field: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: Cow::Borrowed("no stored hidden value to keep unchanged"),
            field: Some(field),
            fields: Vec::new(),
            ends_session: false,
        }
    }

    /// A 400 for the request field `field`, saying what is wrong with it.
    ///
    /// ```ignore
    /// ApiError::field("master_password", SessionError::WeakMasterPassword(weak).to_string())
    /// ```
    pub(crate) fn field(field: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            field: Some(field),
            fields: Vec::new(),
            ends_session: false,
        }
    }

    /// A 400 for a refused secret, listing every problem in `"fields"`; `"error"`
    /// carries only a generic message.
    ///
    /// ```ignore
    /// ApiError::invalid_secret(vec![FieldError { field: "title", index: None, part: None, message }])
    /// ```
    pub(crate) fn invalid_secret(fields: Vec<FieldError>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: Cow::Borrowed("secret not saved: some fields are invalid"),
            field: None,
            fields,
            ends_session: false,
        }
    }
}

/// Maps a failure reading the vault: locked is 401 (ending the session in the browser),
/// an unknown title 404, anything else a generic 500 ([`session_internal_error`]).
///
/// ```ignore
/// current.with_live_vault(&state.sessions, f).map_err(read_error)?
/// ```
pub(crate) fn read_error(err: SessionError) -> ApiError {
    match err {
        SessionError::Locked => ApiError::LOCKED,
        SessionError::SecretNotFound => ApiError::SECRET_NOT_FOUND,
        err => session_internal_error(&err),
    }
}

/// The generic 500 for an internal failure (ADR-0014), after one
/// `event = "internal_error"` diagnostic naming what failed (`cause`) and, if known,
/// its file system cause kind (`kind`, an [`io::ErrorKind`] such as `StorageFull`).
///
/// Security: the diagnostic holds only these fixed names, never the vaultname, a path,
/// a title or the OS error text, so the request log can't be linked to vaultnames.
///
/// ```ignore
/// IssueRefused::Randomness => internal_error("randomness", None),
/// ```
pub(crate) fn internal_error(cause: &'static str, kind: Option<io::ErrorKind>) -> ApiError {
    tracing::error!(
        event = "internal_error",
        cause,
        kind = kind.map(tracing::field::debug),
    );
    ApiError::INTERNAL
}

/// The generic 500 for a session failure no handler expects ([`internal_failure_error`]).
///
/// Security: as [`internal_error`]; only the failure's fixed cause and kind are logged.
///
/// ```ignore
/// _ => session_internal_error(&err),
/// ```
pub(crate) fn session_internal_error(err: &SessionError) -> ApiError {
    internal_failure_error(err.internal_failure())
}

/// The generic 500 ([`internal_error`]) for `failure`, or with cause `unexpected` for
/// an error that isn't an internal failure but reached a 500 anyway.
///
/// Security: as [`internal_error`]; only fixed names and a kind are logged.
///
/// ```ignore
/// generator::generate_password(16).map_err(|err| internal_failure_error(err.internal_failure()))?
/// ```
pub(crate) fn internal_failure_error(failure: Option<InternalFailure>) -> ApiError {
    let InternalFailure { cause, kind } = failure.unwrap_or(InternalFailure {
        cause: "unexpected",
        kind: None,
    });
    internal_error(cause, kind)
}

/// Maps a KDF limiter refusal: 503 when busy, 500 if the job panicked (cause `panic`;
/// the panic hook logs where).
///
/// ```ignore
/// state.kdf.run(job).await.map_err(kdf_error)?
/// ```
pub(crate) fn kdf_error(rejected: KdfRejected) -> ApiError {
    match rejected {
        KdfRejected::Busy => ApiError::BUSY,
        KdfRejected::Failed => internal_error("panic", None),
    }
}

/// The JSON body of an error response.
#[derive(Serialize)]
struct ErrorBody<'a> {
    /// The message.
    error: &'a str,
    /// The request field at fault, if one is.
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'static str>,
    /// Every problem of a refused secret.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    fields: &'a [FieldError],
}

impl IntoResponse for ApiError {
    /// `status` with `{"error": message}`, plus `"field"` for a validation error or
    /// `"fields"` for a refused secret; for
    /// [`ApiError::LOCKED`], also the headers ending the session in the browser.
    ///
    /// ```ignore
    /// let response = ApiError::NOT_FOUND.into_response();
    /// ```
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: &self.message,
            field: self.field,
            fields: &self.fields,
        };
        let mut response = (self.status, Json(body)).into_response();
        if self.ends_session {
            response.headers_mut().extend(auth::ended_session_headers());
        }
        response
    }
}

/// The `/api` routes; any other path under `/api` is a JSON 404.
///
/// ```ignore
/// Router::new().nest("/api", api::router())
/// ```
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/vaults", post(vault::create))
        .route("/unlock", post(vault::unlock))
        .route("/lock", post(vault::lock))
        .route("/session", get(vault::session))
        .route("/secrets", get(secrets::list).post(edit::add))
        .route(
            "/secrets/{title}",
            get(secrets::detail).put(edit::replace).delete(edit::remove),
        )
        .route("/secrets/{title}/reveal", post(secrets::reveal))
        .route("/master-password", post(settings::change_master_password))
        .route("/backup", post(settings::backup))
        .route("/audit-log", get(audit_log::read))
        .fallback(|| async { ApiError::NOT_FOUND })
}
