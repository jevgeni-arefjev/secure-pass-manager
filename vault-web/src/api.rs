//! The JSON API under `/api` and its error responses.
//!
//! Errors are `{"error": "<message>"}`, with a `"field"` naming the input at fault for
//! validation errors. Messages never carry internals.

mod edit;
mod secrets;
mod vault;

use std::borrow::Cow;

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;

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
    status: StatusCode,
    message: Cow<'static, str>,
    field: Option<&'static str>,
    /// Whether the response also ends the session in the browser.
    ends_session: bool,
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
        ends_session: false,
    };

    /// An add was asked for a title that another secret has (ignoring case).
    pub(crate) const SECRET_EXISTS: Self = Self {
        status: StatusCode::CONFLICT,
        message: Cow::Borrowed("a secret with this title already exists"),
        field: Some("title"),
        ends_session: false,
    };

    /// A replace whose body names another title than the path and the stored secret.
    pub(crate) const TITLE_CHANGED: Self = Self {
        status: StatusCode::BAD_REQUEST,
        message: Cow::Borrowed("the title can't be changed"),
        field: Some("title"),
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

    /// Anything that went wrong on the server; details stay on the server.
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
            ends_session: false,
        }
    }
}

/// The JSON body of an error response.
#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'static str>,
}

impl IntoResponse for ApiError {
    /// `status` with `{"error": message}`, plus `"field"` for a validation error; for
    /// [`ApiError::LOCKED`], also the headers ending the session in the browser.
    ///
    /// ```ignore
    /// let response = ApiError::NOT_FOUND.into_response();
    /// ```
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: &self.message,
            field: self.field,
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
        .fallback(|| async { ApiError::NOT_FOUND })
}
