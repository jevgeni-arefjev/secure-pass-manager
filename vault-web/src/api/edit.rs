//! Changing secrets: `POST /api/secrets` (add), `PUT /api/secrets/{title}` (replace)
//! and `DELETE /api/secrets/{title}` (remove).
//!
//! Security:
//! - Every handler changes only the vault its session unlocked ([`CurrentSession`]).
//! - Hidden values (the password, hidden custom fields) are deserialized straight into
//!   [`HiddenValue`] (locked memory). An edit never needs the browser to hold one: an
//!   untouched hidden field is sent as `{"unchanged": true}` and the server copies the
//!   stored value. No response carries a hidden value.
//! - Every change goes through `Session::save` or `Session::remove`, so it is
//!   validated, saved at once and recorded in the audit log, as in the CLI. A save
//!   conflict (another session saved the vault first) locks the session: 401.

use std::fmt;

use axum::Json;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use vault_core::generator::{self, DEFAULT_PASSWORD_LENGTH};
use vault_core::session::{
    CustomField, FieldValue, HiddenValue, InvalidSecret, Secret, Session, SessionError,
};
use vault_core::storage::FileStore;

use crate::AppState;
use crate::api::ApiError;
use crate::api::secrets::{SecretDetail, read_error};
use crate::auth::CurrentSession;
use crate::json::StrictJson;

/// The body of `POST /api/secrets` and `PUT /api/secrets/{title}`: the whole secret.
///
/// Optional fields may be absent or `null`; `tags` and `custom_fields` default to
/// empty. Unknown fields are refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretRequest {
    title: String,
    #[serde(default)]
    username: Option<String>,
    /// Absent, `null` or `""`: generate one. `{"unchanged": true}`: keep the stored one.
    #[serde(default)]
    password: Option<HiddenInput>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    custom_fields: Vec<CustomFieldRequest>,
}

/// A custom field of a [`SecretRequest`]: `{"name", "hidden", "value"}`, where a hidden
/// field's value may be `{"unchanged": true}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomFieldRequest {
    name: String,
    hidden: bool,
    value: HiddenInput,
}

/// A value that may be hidden, as sent: a JSON string, or `{"unchanged": true}` to keep
/// the stored one.
///
/// Security: a string goes straight into a [`HiddenValue`] (locked memory, the source
/// string zeroized). No `Debug`, so it can't be logged by accident.
enum HiddenInput {
    Value(HiddenValue),
    Unchanged,
}

impl<'de> Deserialize<'de> for HiddenInput {
    /// Reads a JSON string into a [`HiddenValue`], or `{"unchanged": true}`.
    ///
    /// ```ignore
    /// let kept: HiddenInput = serde_json::from_str(r#"{"unchanged": true}"#)?;
    /// ```
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(HiddenInputVisitor)
    }
}

/// Builds a [`HiddenInput`] from a JSON string or the `unchanged` marker.
struct HiddenInputVisitor;

/// The only key of the marker object for a hidden value kept as stored.
const UNCHANGED: &str = "unchanged";

impl<'de> Visitor<'de> for HiddenInputVisitor {
    type Value = HiddenInput;

    /// Names what was expected, for serde's error (which is never shown).
    ///
    /// ```ignore
    /// // "a string or {\"unchanged\": true}"
    /// ```
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string or {\"unchanged\": true}")
    }

    /// Copies a borrowed string into a [`HiddenValue`], which zeroizes the copy.
    ///
    /// ```ignore
    /// HiddenInputVisitor.visit_str("s3cret!")
    /// ```
    fn visit_str<E: de::Error>(self, value: &str) -> Result<HiddenInput, E> {
        Ok(HiddenInput::Value(HiddenValue::new(value.to_owned())))
    }

    /// Moves an owned string into a [`HiddenValue`], which zeroizes it.
    ///
    /// ```ignore
    /// HiddenInputVisitor.visit_string(String::from("s3cret!"))
    /// ```
    fn visit_string<E: de::Error>(self, value: String) -> Result<HiddenInput, E> {
        Ok(HiddenInput::Value(HiddenValue::new(value)))
    }

    /// Accepts exactly `{"unchanged": true}`.
    ///
    /// ```ignore
    /// // {"unchanged": true} → HiddenInput::Unchanged; {"unchanged": false} → error
    /// ```
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<HiddenInput, A::Error> {
        let key: Option<String> = map.next_key()?;
        let marked = key.as_deref() == Some(UNCHANGED) && map.next_value::<bool>()?;
        if !marked || map.next_key::<String>()?.is_some() {
            return Err(de::Error::custom("expected {\"unchanged\": true}"));
        }
        Ok(HiddenInput::Unchanged)
    }
}

/// The body of a successful add or replace: the saved secret, masked as in the detail
/// view, and whether its password was generated by the server.
#[derive(Serialize)]
pub(crate) struct SavedSecret {
    #[serde(flatten)]
    detail: SecretDetail,
    password_generated: bool,
}

impl SecretRequest {
    /// The [`Secret`] this request describes, and whether its password was generated.
    /// `stored` is the secret being replaced, whose hidden values an `unchanged` marker
    /// keeps; `None` when adding.
    ///
    /// Security: a kept value is copied from the stored secret into a new
    /// [`HiddenValue`] without leaving the server; that is not a reveal and records
    /// nothing. A generated password comes from `vault-core::generator`.
    ///
    /// ```ignore
    /// let (secret, generated) = request.into_secret(vault.get(&title).ok())?;
    /// ```
    fn into_secret(self, stored: Option<&Secret>) -> Result<(Secret, bool), ApiError> {
        let (password, generated) = match self.password {
            Some(HiddenInput::Value(value)) if !value.reveal().is_empty() => (value, false),
            None | Some(HiddenInput::Value(_)) => (
                generator::generate_password(DEFAULT_PASSWORD_LENGTH)
                    .map_err(|_| ApiError::INTERNAL)?,
                true,
            ),
            Some(HiddenInput::Unchanged) => {
                let kept = stored
                    .and_then(Secret::password)
                    .ok_or(ApiError::nothing_to_keep(PASSWORD))?;
                (copy(kept), false)
            }
        };
        let mut secret = Secret::new(self.title).with_password(password);
        if let Some(username) = self.username {
            secret = secret.with_username(username);
        }
        if let Some(url) = self.url {
            secret = secret.with_url(url);
        }
        if let Some(notes) = self.notes {
            secret = secret.with_notes(notes);
        }
        for tag in self.tags {
            secret = secret.with_tag(tag);
        }
        for field in self.custom_fields {
            secret = secret.with_custom_field(field.into_custom_field(stored)?);
        }
        Ok((secret, generated))
    }
}

impl CustomFieldRequest {
    /// The [`CustomField`] this request describes; an `unchanged` hidden value is copied
    /// from `stored`'s hidden custom field with exactly this name.
    ///
    /// ```ignore
    /// secret = secret.with_custom_field(field.into_custom_field(stored)?);
    /// ```
    fn into_custom_field(self, stored: Option<&Secret>) -> Result<CustomField, ApiError> {
        match (self.hidden, self.value) {
            (true, HiddenInput::Value(value)) => Ok(CustomField::hidden(self.name, value)),
            // A plain value was read into locked memory too (the flag may come after it);
            // it leaves as an ordinary zeroizing field.
            (false, HiddenInput::Value(value)) => {
                Ok(CustomField::plain(self.name, value.reveal().to_owned()))
            }
            (true, HiddenInput::Unchanged) => {
                let kept = stored
                    .into_iter()
                    .flat_map(Secret::custom_fields)
                    .find(|field| field.name() == self.name)
                    .and_then(|field| match field.value() {
                        FieldValue::Hidden(hidden) => Some(hidden),
                        FieldValue::Plain(_) => None,
                    })
                    .ok_or(ApiError::nothing_to_keep(CUSTOM_FIELDS))?;
                Ok(CustomField::hidden(self.name, copy(kept)))
            }
            (false, HiddenInput::Unchanged) => Err(ApiError::nothing_to_keep(CUSTOM_FIELDS)),
        }
    }
}

/// A new [`HiddenValue`] holding the same text as `value`.
///
/// ```ignore
/// let kept = copy(stored.password().unwrap());
/// ```
fn copy(value: &HiddenValue) -> HiddenValue {
    HiddenValue::new(value.reveal().to_owned())
}

/// The request field names used in validation errors.
const TITLE: &str = "title";
const USERNAME: &str = "username";
const PASSWORD: &str = "password";
const URL: &str = "url";
const NOTES: &str = "notes";
const TAGS: &str = "tags";
const CUSTOM_FIELDS: &str = "custom_fields";

/// `POST /api/secrets`: adds a secret to the session's vault and saves it at once.
/// An absent or empty password is generated on the server.
///
/// Errors: 409 (`"field": "title"`) if a secret has this title (ignoring case and
/// surrounding spaces); 400 with `"field"` for a field breaking the rules; 413 if the
/// vault is full (the session stays open); 401 on a save conflict, which locks the
/// session.
///
/// ```text
/// POST /api/secrets {"title": "GitHub", "username": "alice", "tags": ["work"]}   (cookie, X-CSRF-Token)
/// 201 {"title": "GitHub", ..., "has_password": true, "password_generated": true}
/// ```
pub(crate) async fn add(
    State(state): State<AppState>,
    current: CurrentSession,
    StrictJson(request): StrictJson<SecretRequest>,
) -> Result<Response, ApiError> {
    let saved = current
        .with_live_vault(&state.sessions, |vault| {
            if vault.contains(&request.title)? {
                return Ok(Err(ApiError::SECRET_EXISTS));
            }
            let title = request.title.clone();
            save(vault, &title, request.into_secret(None))
        })
        .map_err(write_error)??;
    Ok((StatusCode::CREATED, Json(saved)).into_response())
}

/// `PUT /api/secrets/{title}`: replaces the secret titled `title` in the session's vault
/// as a whole and saves it at once. The body's title must be the path's and the stored
/// one exactly (no rename, not even of case). Hidden values sent as
/// `{"unchanged": true}` keep their stored value; `created_at` is kept too.
///
/// Errors: 404 for an unknown title; 400 with `"field"` for a changed title, an
/// `unchanged` marker with nothing stored to keep, or a field breaking the rules; 413
/// if the vault is full (the session stays open); 401 on a save conflict, which locks
/// the session.
///
/// ```text
/// PUT /api/secrets/GitHub {"title": "GitHub", "password": {"unchanged": true}}   (cookie, X-CSRF-Token)
/// 200 {"title": "GitHub", ..., "password_generated": false}
/// ```
pub(crate) async fn replace(
    State(state): State<AppState>,
    current: CurrentSession,
    title: Result<Path<String>, PathRejection>,
    StrictJson(request): StrictJson<SecretRequest>,
) -> Result<Json<SavedSecret>, ApiError> {
    let Path(title) = title.map_err(|_| ApiError::SECRET_NOT_FOUND)?;
    let saved = current
        .with_live_vault(&state.sessions, |vault| {
            let stored = vault.get(&title)?;
            if request.title != title || request.title != stored.title() {
                return Ok(Err(ApiError::TITLE_CHANGED));
            }
            let secret = request.into_secret(Some(stored));
            save(vault, &title, secret)
        })
        .map_err(write_error)??;
    Ok(Json(saved))
}

/// `DELETE /api/secrets/{title}`: removes the secret titled `title` from the session's
/// vault and saves it at once. The client asks for confirmation first.
///
/// Errors: 404 for an unknown title; 401 on a save conflict, which locks the session.
///
/// ```text
/// DELETE /api/secrets/GitHub   (cookie, X-CSRF-Token)
/// 204
/// ```
pub(crate) async fn remove(
    State(state): State<AppState>,
    current: CurrentSession,
    title: Result<Path<String>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(title) = title.map_err(|_| ApiError::SECRET_NOT_FOUND)?;
    current
        .with_live_vault(&state.sessions, |vault| vault.remove(&title))
        .map_err(write_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Saves the secret built from a request (validated, written at once, audited) and
/// returns its masked view, looked up again by `title` since saving trims it. A
/// request that couldn't be turned into a secret is passed through, saving nothing.
///
/// The outer error is the session's (mapped by [`write_error`]); the inner one is the
/// request's own.
///
/// ```ignore
/// save(vault, &title, request.into_secret(None))
/// ```
fn save(
    vault: &mut Session<FileStore>,
    title: &str,
    built: Result<(Secret, bool), ApiError>,
) -> Result<Result<SavedSecret, ApiError>, SessionError> {
    let (secret, password_generated) = match built {
        Ok(built) => built,
        Err(err) => return Ok(Err(err)),
    };
    vault.save(secret)?;
    Ok(Ok(SavedSecret {
        detail: SecretDetail::of(vault.get(title)?),
        password_generated,
    }))
}

/// Maps a failure changing the vault: a field breaking the rules is a 400 naming the
/// request field, a full vault a 413 that leaves the session open, the rest as when
/// reading ([`read_error`]); a conflict has locked the session, so it never gets here.
///
/// ```ignore
/// current.with_live_vault(&state.sessions, f).map_err(write_error)?
/// ```
fn write_error(err: SessionError) -> ApiError {
    match err {
        SessionError::InvalidSecret(invalid) => {
            ApiError::field(field_of(invalid), invalid.to_string())
        }
        SessionError::VaultFull => ApiError::VAULT_FULL,
        err => read_error(err),
    }
}

/// The request field a validation error is about.
///
/// ```ignore
/// assert_eq!(field_of(InvalidSecret::DuplicateTag), "tags");
/// ```
fn field_of(invalid: InvalidSecret) -> &'static str {
    match invalid {
        InvalidSecret::Title => TITLE,
        InvalidSecret::Username => USERNAME,
        InvalidSecret::Password => PASSWORD,
        InvalidSecret::Url => URL,
        InvalidSecret::Notes => NOTES,
        InvalidSecret::TooManyTags | InvalidSecret::Tag | InvalidSecret::DuplicateTag => TAGS,
        InvalidSecret::TooManyCustomFields
        | InvalidSecret::CustomFieldName
        | InvalidSecret::CustomFieldValue
        | InvalidSecret::DuplicateCustomFieldName => CUSTOM_FIELDS,
    }
}
