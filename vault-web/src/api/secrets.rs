//! Reading secrets: `GET /api/secrets` (the list), `GET /api/secrets/{title}` (one
//! secret, masked) and `POST /api/secrets/{title}/reveal` (one hidden field).
//!
//! Security:
//! - Every handler reads only the vault its session unlocked ([`CurrentSession`]); no
//!   vaultname or other identity is taken from the request.
//! - Neither view ever carries a hidden value (password or hidden custom field): those
//!   are named only. The list leaves out notes and plain custom field values too, so it
//!   holds nothing beyond what identifies each secret.
//! - A hidden value leaves only through the reveal handler: one field per request,
//!   behind the CSRF token, recorded in the audit log.

use axum::Json;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use vault_core::session::{CustomField, FieldValue, Secret, SessionError};
use zeroize::Zeroizing;

use crate::AppState;
use crate::api::ApiError;
use crate::auth::CurrentSession;
use crate::json::StrictJson;

/// The body of `GET /api/secrets`.
#[derive(Serialize)]
pub(crate) struct SecretList {
    secrets: Vec<SecretSummary>,
}

/// The fields both views show of a secret: what identifies it and whether it has a
/// password.
///
/// Security: holds no hidden value; the password is only flagged.
#[derive(Serialize)]
struct SecretFields {
    title: String,
    username: Option<String>,
    url: Option<String>,
    tags: Vec<String>,
    has_password: bool,
    created_at: u64,
    updated_at: u64,
}

impl SecretFields {
    /// The shared fields of `secret`.
    ///
    /// ```ignore
    /// SecretSummary { fields: SecretFields::of(secret), .. }
    /// ```
    fn of(secret: &Secret) -> Self {
        Self {
            title: secret.title().to_owned(),
            username: secret.username().map(str::to_owned),
            url: secret.url().map(str::to_owned),
            tags: secret.tags().map(str::to_owned).collect(),
            has_password: secret.password().is_some(),
            created_at: secret.created_at(),
            updated_at: secret.updated_at(),
        }
    }
}

/// One secret in the list: its [`SecretFields`], whether it has notes, and its custom
/// fields by name.
///
/// Security: holds no hidden value, no notes and no custom field value.
#[derive(Serialize)]
struct SecretSummary {
    #[serde(flatten)]
    fields: SecretFields,
    has_notes: bool,
    custom_fields: Vec<FieldName>,
}

impl SecretSummary {
    /// How `secret` appears in the list.
    ///
    /// ```ignore
    /// let summary = SecretSummary::of(secret);
    /// ```
    fn of(secret: &Secret) -> Self {
        Self {
            fields: SecretFields::of(secret),
            has_notes: secret.notes().is_some(),
            custom_fields: secret.custom_fields().iter().map(FieldName::of).collect(),
        }
    }
}

/// A custom field by name only, with whether it is hidden.
#[derive(Serialize)]
struct FieldName {
    name: String,
    hidden: bool,
}

impl FieldName {
    /// The name and hidden flag of `field`, without its value.
    ///
    /// ```ignore
    /// let names: Vec<_> = secret.custom_fields().iter().map(FieldName::of).collect();
    /// ```
    fn of(field: &CustomField) -> Self {
        Self {
            name: field.name().to_owned(),
            hidden: field.value().is_hidden(),
        }
    }
}

/// The body of `GET /api/secrets/{title}`: one secret's [`SecretFields`], its notes and
/// its custom fields.
///
/// Security: hidden fields are named only (`has_password`, custom fields with
/// `"hidden": true` and no value); revealing them is a separate, audited request.
#[derive(Serialize)]
pub(crate) struct SecretDetail {
    #[serde(flatten)]
    fields: SecretFields,
    notes: Option<String>,
    custom_fields: Vec<CustomFieldView>,
}

impl SecretDetail {
    /// The masked detail view of `secret`.
    ///
    /// ```ignore
    /// let view = SecretDetail::of(vault.get(&title)?);
    /// ```
    fn of(secret: &Secret) -> Self {
        Self {
            fields: SecretFields::of(secret),
            notes: secret.notes().map(str::to_owned),
            custom_fields: secret
                .custom_fields()
                .iter()
                .map(CustomFieldView::of)
                .collect(),
        }
    }
}

/// A custom field in the detail view: its value if plain, its name only if hidden.
///
/// Serialized as `{"name", "hidden": false, "value"}` or `{"name", "hidden": true}`.
enum CustomFieldView {
    Plain { name: String, value: String },
    Hidden { name: String },
}

impl CustomFieldView {
    /// The view of `field`; a hidden field's value is left out.
    ///
    /// ```ignore
    /// let fields: Vec<_> = secret.custom_fields().iter().map(CustomFieldView::of).collect();
    /// ```
    fn of(field: &CustomField) -> Self {
        let name = field.name().to_owned();
        match field.value() {
            FieldValue::Plain(text) => Self::Plain {
                name,
                value: text.as_str().to_owned(),
            },
            FieldValue::Hidden(_) => Self::Hidden { name },
        }
    }
}

impl Serialize for CustomFieldView {
    /// Writes the field as an object with its `hidden` flag; `value` only if plain.
    ///
    /// ```ignore
    /// serde_json::to_value(CustomFieldView::Hidden { name: "pin".into() })?; // {"name": "pin", "hidden": true}
    /// ```
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Plain { name, value } => {
                let mut object = serializer.serialize_struct("CustomFieldView", 3)?;
                object.serialize_field("name", name)?;
                object.serialize_field("hidden", &false)?;
                object.serialize_field("value", value)?;
                object.end()
            }
            Self::Hidden { name } => {
                let mut object = serializer.serialize_struct("CustomFieldView", 2)?;
                object.serialize_field("name", name)?;
                object.serialize_field("hidden", &true)?;
                object.end()
            }
        }
    }
}

/// `GET /api/secrets`: every secret of the session's vault, sorted by title ignoring
/// case, with no hidden value, notes or custom field value.
///
/// ```text
/// GET /api/secrets   (cookie)
/// 200 {"secrets": [{"title": "GitHub", "username": "alice", "url": "https://github.com",
///      "tags": ["work"], "has_password": true, "has_notes": false,
///      "custom_fields": [{"name": "recovery code", "hidden": true}],
///      "created_at": 1800000000, "updated_at": 1800000000}]}
/// ```
pub(crate) async fn list(
    State(state): State<AppState>,
    current: CurrentSession,
) -> Result<Json<SecretList>, ApiError> {
    let secrets = current
        .with_live_vault(&state.sessions, |vault| {
            Ok(vault.list()?.into_iter().map(SecretSummary::of).collect())
        })
        .map_err(read_error)?;
    Ok(Json(SecretList { secrets }))
}

/// `GET /api/secrets/{title}`: the secret titled `title` (percent-decoded; matched
/// ignoring case and surrounding spaces) in the session's vault, with hidden fields
/// named only. 404 for an unknown title, including a path that doesn't decode to UTF-8.
///
/// ```text
/// GET /api/secrets/my%20bank   (cookie)
/// 200 {"title": "my bank", "username": null, "url": null, "notes": "...", "tags": [],
///      "has_password": true, "custom_fields": [{"name": "region", "hidden": false,
///      "value": "eu-west-1"}], "created_at": 1800000000, "updated_at": 1800000000}
/// ```
pub(crate) async fn detail(
    State(state): State<AppState>,
    current: CurrentSession,
    title: Result<Path<String>, PathRejection>,
) -> Result<Json<SecretDetail>, ApiError> {
    let Path(title) = title.map_err(|_| ApiError::SECRET_NOT_FOUND)?;
    let detail = current
        .with_live_vault(&state.sessions, |vault| {
            Ok(SecretDetail::of(vault.get(&title)?))
        })
        .map_err(read_error)?;
    Ok(Json(detail))
}

/// The field name standing for a secret's password in a reveal request. No custom
/// field can have it: `vault-core` refuses custom fields named like a standard field.
const PASSWORD_FIELD: &str = "password";

/// The body of `POST /api/secrets/{title}/reveal`: which one field to reveal.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevealRequest {
    field: String,
}

/// The body of a reveal response: the one hidden value asked for.
///
/// Security: no `Debug`; built only while the response is serialized, from a
/// zeroizing copy of the value.
#[derive(Serialize)]
struct Revealed<'a> {
    value: &'a str,
}

/// Why a reveal returned no value; failing the reveal closure records no audit event.
enum RevealError {
    Session(SessionError),
    FieldNotFound,
    NotHidden,
}

impl From<SessionError> for RevealError {
    /// Wraps a session failure (locked, unknown title, ...).
    ///
    /// ```ignore
    /// let err: RevealError = SessionError::SecretNotFound.into();
    /// ```
    fn from(err: SessionError) -> Self {
        Self::Session(err)
    }
}

/// `POST /api/secrets/{title}/reveal`: the value of one hidden field, `"password"` or
/// a hidden custom field's exact name, of the secret titled `title` in the session's
/// vault. Each success records a reveal audit event naming the title only.
///
/// Errors: 403 without the CSRF token; 404 for an unknown title or field (neither
/// echoed); 400 with `"field": "field"` for a plain custom field.
///
/// Security: one value per request, read through `Session::reveal` so it is audited;
/// the copy taken out of the vault is zeroized once serialized (the response bytes in
/// hyper are beyond reach). The route template, not the title, is what gets logged.
///
/// ```text
/// POST /api/secrets/GitHub/reveal {"field": "password"}   (cookie, X-CSRF-Token)
/// 200 {"value": "s3cret!"}
/// ```
pub(crate) async fn reveal(
    State(state): State<AppState>,
    current: CurrentSession,
    title: Result<Path<String>, PathRejection>,
    StrictJson(request): StrictJson<RevealRequest>,
) -> Result<Response, ApiError> {
    let Path(title) = title.map_err(|_| ApiError::SECRET_NOT_FOUND)?;
    let value = current
        .with_live_vault(&state.sessions, |vault| {
            Ok(vault.reveal(&title, |secret| hidden_value(secret, &request.field)))
        })
        .map_err(read_error)?
        .map_err(|err| match err {
            RevealError::Session(err) => read_error(err),
            RevealError::FieldNotFound => ApiError::FIELD_NOT_FOUND,
            RevealError::NotHidden => ApiError::NOT_HIDDEN,
        })?;
    Ok(Json(Revealed { value: &value }).into_response())
}

/// A zeroizing copy of the hidden field `field` of `secret`: its password for
/// `"password"`, else the custom field with exactly that name.
///
/// ```ignore
/// let value = hidden_value(secret, "recovery code")?;
/// ```
fn hidden_value(secret: &Secret, field: &str) -> Result<Zeroizing<String>, RevealError> {
    let hidden = if field == PASSWORD_FIELD {
        secret.password().ok_or(RevealError::FieldNotFound)?
    } else {
        let custom = secret
            .custom_fields()
            .iter()
            .find(|custom| custom.name() == field)
            .ok_or(RevealError::FieldNotFound)?;
        match custom.value() {
            FieldValue::Hidden(hidden) => hidden,
            FieldValue::Plain(_) => return Err(RevealError::NotHidden),
        }
    };
    Ok(Zeroizing::new(hidden.reveal().to_owned()))
}

/// Maps a failure reading the vault: locked is 401 (ending the session in the browser),
/// an unknown title 404, anything else a generic 500.
///
/// ```ignore
/// current.with_live_vault(&state.sessions, f).map_err(read_error)?
/// ```
fn read_error(err: SessionError) -> ApiError {
    match err {
        SessionError::Locked => ApiError::LOCKED,
        SessionError::SecretNotFound => ApiError::SECRET_NOT_FOUND,
        _ => ApiError::INTERNAL,
    }
}
