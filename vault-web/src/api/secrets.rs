//! Reading secrets: `GET /api/secrets` (the list) and `GET /api/secrets/{title}` (one
//! secret, masked).
//!
//! Security:
//! - Every handler reads only the vault its session unlocked ([`CurrentSession`]); no
//!   vaultname or other identity is taken from the request.
//! - Neither view ever carries a hidden value (password or hidden custom field): those
//!   are named only. The list leaves out notes and plain custom field values too, so it
//!   holds nothing beyond what identifies each secret.

use axum::Json;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use vault_core::session::{CustomField, FieldValue, Secret, SessionError};

use crate::AppState;
use crate::api::ApiError;
use crate::auth::CurrentSession;

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
