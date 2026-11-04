//! The JSON API under `/api` and its error responses.
//!
//! Errors are `{"error": "<message>"}` with no internals; later endpoints add a
//! `field` for validation errors.

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::AppConfig;

/// An API error: a status and a generic message safe to show the user.
///
/// Security: the message is a fixed string chosen by the handler, never an internal
/// error, path or request value.
///
/// ```ignore
/// return Err(ApiError::NOT_FOUND);
/// ```
#[derive(Clone, Copy, Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    /// No such route (or, later, no such secret).
    pub(crate) const NOT_FOUND: Self = Self {
        status: StatusCode::NOT_FOUND,
        message: "not found",
    };

    /// The request's `Host` (or HTTP/2 authority) doesn't name this server.
    pub(crate) const UNKNOWN_HOST: Self = Self {
        status: StatusCode::MISDIRECTED_REQUEST,
        message: "unknown host",
    };
}

/// The JSON body of an error response.
#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

impl IntoResponse for ApiError {
    /// `status` with `{"error": message}`.
    ///
    /// ```ignore
    /// let response = ApiError::NOT_FOUND.into_response();
    /// ```
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.message,
        };
        (self.status, Json(body)).into_response()
    }
}

/// The `/api` routes; any other path under `/api` is a JSON 404.
///
/// ```ignore
/// Router::new().nest("/api", api::router())
/// ```
pub(crate) fn router() -> Router<AppConfig> {
    Router::new().fallback(|| async { ApiError::NOT_FOUND })
}
