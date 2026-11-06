//! The client bundle: files built from `web/` into `vault-web/assets/` and embedded at
//! compile time, so nothing is fetched from elsewhere at runtime. Without a built
//! bundle, `/` serves a "client not built" page instead.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Every top-level file of `assets/` with an embedded extension, from `build.rs`.
static EMBEDDED: &[(&str, &[u8])] = include!(concat!(env!("OUT_DIR"), "/embedded_assets.rs"));

/// Served at `/` when no `index.html` was embedded. No inline script or style, so it
/// passes the CSP like the real client.
const CLIENT_NOT_BUILT: &str = "<!doctype html>\n<html lang=\"en\">\n<head>\n\
    <meta charset=\"utf-8\">\n<title>Client not built</title>\n</head>\n<body>\n\
    <h1>Client not built</h1>\n<p>client not built: run <code>npm run build</code> in \
    <code>web/</code>, then rebuild and restart <code>vault-web</code>.</p>\n\
    </body>\n</html>\n";

/// The client bundle, by file name (e.g. `index.html`, `app.js`).
///
/// ```
/// use vault_web::Assets;
/// let assets = Assets::from_files([("index.html", b"<!doctype html>".to_vec())]);
/// # let _ = assets;
/// ```
#[derive(Clone, Debug, Default)]
pub struct Assets {
    /// The files by request path, shared by every clone.
    files: Arc<HashMap<String, Bytes>>,
}

impl Assets {
    /// The bundle embedded at compile time; empty if `npm run build` hadn't run.
    ///
    /// ```
    /// let _assets = vault_web::Assets::embedded();
    /// ```
    pub fn embedded() -> Self {
        Self::from_files(
            EMBEDDED
                .iter()
                .map(|&(name, bytes)| (name, Bytes::from_static(bytes))),
        )
    }

    /// A bundle of the given `(file name, contents)` pairs; for tests, which can't rely
    /// on whether the real bundle was built.
    ///
    /// ```
    /// use vault_web::Assets;
    /// let empty = Assets::from_files::<_, &str, Vec<u8>>([]);
    /// # let _ = empty;
    /// ```
    pub fn from_files<I, N, B>(files: I) -> Self
    where
        I: IntoIterator<Item = (N, B)>,
        N: Into<String>,
        B: Into<Bytes>,
    {
        let files = files
            .into_iter()
            .map(|(name, bytes)| (name.into(), bytes.into()))
            .collect();
        Self {
            files: Arc::new(files),
        }
    }

    /// The response for file `name`: its contents with a content type from its
    /// extension, or 404 if it isn't in the bundle.
    ///
    /// ```ignore
    /// let response = assets.file("app.js");
    /// ```
    fn file(&self, name: &str) -> Response {
        match (self.files.get(name), content_type(name)) {
            (Some(bytes), Some(content_type)) => {
                ([(header::CONTENT_TYPE, content_type)], bytes.clone()).into_response()
            }
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }
}

/// The `Content-Type` for a bundle file name, by extension; `None` for any other.
///
/// ```ignore
/// assert_eq!(content_type("app.js"), Some("text/javascript; charset=utf-8"));
/// ```
fn content_type(name: &str) -> Option<&'static str> {
    let (_, ext) = name.rsplit_once('.')?;
    Some(match ext {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        _ => return None,
    })
}

/// `GET /`: the client's `index.html`, or the "client not built" page.
///
/// ```ignore
/// Router::new().route("/", get(index))
/// ```
pub(crate) async fn index(State(assets): State<Assets>) -> Response {
    if assets.files.contains_key("index.html") {
        assets.file("index.html")
    } else {
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            CLIENT_NOT_BUILT,
        )
            .into_response()
    }
}

/// `GET /{file}`: one file of the bundle, or 404.
///
/// ```ignore
/// Router::new().route("/{file}", get(file))
/// ```
pub(crate) async fn file(State(assets): State<Assets>, Path(name): Path<String>) -> Response {
    assets.file(&name)
}
