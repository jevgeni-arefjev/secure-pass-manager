//! The session credential: the `__Host-session` cookie, and the extractor that turns
//! it (plus the CSRF token on state-changing requests) into the caller's session.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::api::ApiError;
use crate::sessions::{SessionId, SessionKey, WebSession};

/// The session cookie's name. The `__Host-` prefix makes browsers insist on `Secure`,
/// `Path=/` and no `Domain`, so no other host can set or read it.
const SESSION_COOKIE: &str = "__Host-session";

/// The header carrying the CSRF token.
const CSRF_HEADER: &str = "x-csrf-token";

/// The session ID in the request's `__Host-session` cookie, if it has the shape of one.
///
/// ```ignore
/// let id = request_session_id(request.headers());
/// ```
pub(crate) fn request_session_id(headers: &HeaderMap) -> Option<SessionId> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .and_then(|(_, value)| SessionId::parse(value))
}

/// The `Set-Cookie` value issuing session `id`.
///
/// Security: `HttpOnly` (no script access), `Secure` (HTTPS only), `SameSite=Strict`
/// (never sent on cross-site requests), and no `Max-Age`/`Expires`, so the browser
/// forgets it when it closes.
///
/// ```ignore
/// response.headers_mut().insert(header::SET_COOKIE, session_cookie(&id));
/// ```
pub(crate) fn session_cookie(id: &SessionId) -> HeaderValue {
    HeaderValue::try_from(format!(
        "{SESSION_COOKIE}={}; {COOKIE_ATTRIBUTES}",
        id.as_str()
    ))
    .expect("hex session ID is a valid header value")
}

/// The session cookie's attributes, as issued and as deleted.
const COOKIE_ATTRIBUTES: &str = "HttpOnly; Secure; SameSite=Strict; Path=/";

/// `Clear-Site-Data` once a session ends: drop the browser's cache and site storage.
const CLEAR_SITE_DATA: &str = "\"cache\", \"storage\"";

/// The headers for a response ending the session in the browser: the cookie deleted
/// and the browser's cache and site storage for this origin cleared.
///
/// ```ignore
/// (StatusCode::NO_CONTENT, ended_session_headers()).into_response()
/// ```
pub(crate) fn ended_session_headers() -> [(HeaderName, HeaderValue); 2] {
    let expired =
        HeaderValue::try_from(format!("{SESSION_COOKIE}=; {COOKIE_ATTRIBUTES}; Max-Age=0"))
            .expect("constant cookie is a valid header value");
    [
        (header::SET_COOKIE, expired),
        (
            HeaderName::from_static("clear-site-data"),
            HeaderValue::from_static(CLEAR_SITE_DATA),
        ),
    ]
}

/// Whether `method` changes state, so it needs the CSRF token and the Origin check.
///
/// ```ignore
/// assert!(is_state_changing(&Method::POST));
/// ```
pub(crate) fn is_state_changing(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// The caller's live session, from its cookie.
///
/// Security: 401 without a live session, with the cookie deleted and the browser's
/// cache and storage cleared (as on lock); on a state-changing
/// request, 403 unless `X-CSRF-Token` is this session's token. Another session's
/// token never matches.
///
/// ```ignore
/// async fn lock(current: CurrentSession) -> Response { .. }
/// ```
pub(crate) struct CurrentSession {
    key: SessionKey,
    session: Arc<WebSession>,
}

impl CurrentSession {
    /// The registry key of this session, e.g. to remove it.
    ///
    /// ```ignore
    /// state.sessions.remove(current.key());
    /// ```
    pub(crate) fn key(&self) -> SessionKey {
        self.key
    }

    /// The session itself.
    ///
    /// ```ignore
    /// let name = current.session().vaultname();
    /// ```
    pub(crate) fn session(&self) -> &WebSession {
        &self.session
    }
}

/// Why there is no [`CurrentSession`]: an [`ApiError`]; a 401 also ends the session in
/// the browser ([`ended_session_headers`]).
pub(crate) struct NoSession(ApiError);

impl IntoResponse for NoSession {
    /// The error response; a 401 also deletes the cookie and clears site data.
    ///
    /// ```ignore
    /// NoSession(ApiError::LOCKED).into_response()
    /// ```
    fn into_response(self) -> Response {
        let locked = self.0.status() == ApiError::LOCKED.status();
        let mut response = self.0.into_response();
        if locked {
            response.headers_mut().extend(ended_session_headers());
        }
        response
    }
}

impl FromRequestParts<AppState> for CurrentSession {
    type Rejection = NoSession;

    /// Looks the cookie's session up and, on a state-changing request, checks the
    /// CSRF token.
    ///
    /// ```ignore
    /// let current = CurrentSession::from_request_parts(&mut parts, &state).await?;
    /// ```
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let key = request_session_id(&parts.headers)
            .ok_or(NoSession(ApiError::LOCKED))?
            .key();
        let session = state.sessions.get(key).ok_or(NoSession(ApiError::LOCKED))?;
        if is_state_changing(&parts.method) {
            let token = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            if !session.csrf_matches(token) {
                return Err(NoSession(ApiError::CSRF));
            }
        }
        Ok(Self { key, session })
    }
}
