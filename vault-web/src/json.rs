//! Strict request parsing: a capped JSON body, unknown fields refused by each request
//! type (`#[serde(deny_unknown_fields)]`), and secrets deserialized straight into
//! wiped-on-drop memory.

use std::fmt;

use axum::body::to_bytes;
use axum::extract::{FromRequest, Request};
use axum::http::header;
use serde::Deserialize;
use serde::de::{self, DeserializeOwned, Deserializer, Visitor};
use vault_core::crypto::MasterPassword;
use zeroize::Zeroizing;

use crate::api::ApiError;

/// Largest request body accepted, in bytes.
pub(crate) const MAX_BODY_BYTES: usize = 64 * 1024;

/// A JSON request body of type `T`, which must be a JSON object.
///
/// Security: refuses a body over [`MAX_BODY_BYTES`] (413), one not declared
/// `application/json` (415), and anything but an object `T` parses (400, no details);
/// serde would otherwise also take a struct's fields positionally from an array. The raw
/// body is zeroized once parsed; buffers inside hyper are beyond reach.
///
/// ```ignore
/// async fn unlock(StrictJson(request): StrictJson<UnlockRequest>) -> Response { .. }
/// ```
pub(crate) struct StrictJson<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for StrictJson<T> {
    type Rejection = ApiError;

    /// Reads, caps and parses the body.
    ///
    /// ```ignore
    /// let StrictJson(body) = StrictJson::<UnlockRequest>::from_request(request, &state).await?;
    /// ```
    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        if !is_json(&request) {
            return Err(ApiError::NOT_JSON);
        }
        let bytes = to_bytes(request.into_body(), MAX_BODY_BYTES)
            .await
            .map_err(|_| ApiError::BODY_TOO_LARGE)?;
        let body = Zeroizing::new(Vec::from(bytes));
        if body.trim_ascii_start().first() != Some(&b'{') {
            return Err(ApiError::INVALID_BODY);
        }
        serde_json::from_slice(&body)
            .map(Self)
            .map_err(|_| ApiError::INVALID_BODY)
    }
}

/// Whether `request` declares a JSON body (`application/json`, any parameters).
///
/// ```ignore
/// assert!(is_json(&request));
/// ```
fn is_json(request: &Request) -> bool {
    request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

/// A master password field of a request body.
///
/// Security: deserialized straight into a [`MasterPassword`] (locked memory, the
/// source string zeroized), never kept as a plain `String`. Has no `Debug`, so it
/// can't be logged by accident.
///
/// ```ignore
/// #[derive(Deserialize)]
/// struct UnlockRequest { master_password: MasterPasswordField }
/// ```
pub(crate) struct MasterPasswordField(pub MasterPassword);

impl<'de> Deserialize<'de> for MasterPasswordField {
    /// Reads a JSON string into a [`MasterPassword`].
    ///
    /// ```ignore
    /// let password: MasterPasswordField = serde_json::from_slice(br#""correct horse""#)?;
    /// ```
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_string(MasterPasswordVisitor)
    }
}

/// Builds a [`MasterPasswordField`] from a JSON string.
struct MasterPasswordVisitor;

impl Visitor<'_> for MasterPasswordVisitor {
    type Value = MasterPasswordField;

    /// Names what was expected, for serde's error (which is never shown).
    ///
    /// ```ignore
    /// // "a master password string"
    /// ```
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a master password string")
    }

    /// Copies a borrowed string into a [`MasterPassword`], which zeroizes the copy.
    ///
    /// ```ignore
    /// MasterPasswordVisitor.visit_str("correct horse battery")
    /// ```
    fn visit_str<E: de::Error>(self, value: &str) -> Result<MasterPasswordField, E> {
        Ok(MasterPasswordField(MasterPassword::new(value.to_owned())))
    }

    /// Moves an owned string into a [`MasterPassword`], which zeroizes it.
    ///
    /// ```ignore
    /// MasterPasswordVisitor.visit_string(String::from("correct horse battery"))
    /// ```
    fn visit_string<E: de::Error>(self, value: String) -> Result<MasterPasswordField, E> {
        Ok(MasterPasswordField(MasterPassword::new(value)))
    }
}
