//! Embeds the client bundle from `assets/` (built by `npm run build` in `web/`) into the
//! binary. Never runs npm: if the bundle hasn't been built, the list is empty and the
//! server serves its "client not built" page.

use std::fmt::Write as _;
use std::path::Path;
use std::{env, fs};

/// File extensions embedded; anything else in `assets/` (e.g. source maps) is skipped.
const EMBEDDED_EXTENSIONS: &[&str] = &["html", "js", "css", "svg", "png", "ico"];

/// Writes `$OUT_DIR/embedded_assets.rs`: a `&[(&str, &[u8])]` of every top-level file
/// in `assets/` with an embedded extension, sorted by name.
///
/// ```text
/// static EMBEDDED: &[(&str, &[u8])] = include!(concat!(env!("OUT_DIR"), "/embedded_assets.rs"));
/// ```
fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let assets = Path::new(&manifest_dir).join("assets");
    println!("cargo::rerun-if-changed={}", assets.display());

    let mut files: Vec<_> = fs::read_dir(&assets)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| EMBEDDED_EXTENSIONS.contains(&ext))
        })
        .collect();
    files.sort();

    let mut code = String::from("&[\n");
    for path in files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("UTF-8 asset name");
        let full = path.to_str().expect("UTF-8 asset path");
        writeln!(code, "    ({name:?}, include_bytes!({full:?})),").expect("write to String");
    }
    code.push(']');

    let out = Path::new(&env::var("OUT_DIR").expect("OUT_DIR")).join("embedded_assets.rs");
    fs::write(out, code).expect("write embedded_assets.rs");
}
