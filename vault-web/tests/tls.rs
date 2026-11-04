//! TLS certificate loading: given PEM files are loaded; without them a self-signed
//! `localhost` certificate is generated once, cached `0600` and reused.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use vault_web::tls::{self, CertSource};

/// Writes a fresh self-signed certificate and key as PEM files into `dir`.
///
/// ```text
/// let (cert, key) = write_pem_pair(dir.path());
/// ```
fn write_pem_pair(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    fs::write(&cert, generated.cert.pem()).unwrap();
    fs::write(&key, generated.signing_key.serialize_pem()).unwrap();
    (cert, key)
}

/// The permission bits of `path`.
///
/// ```text
/// assert_eq!(mode(&key), 0o600);
/// ```
fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn given_certificate_and_key_files_are_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = write_pem_pair(dir.path());
    let config = tls::server_config(&CertSource::Files { cert, key }).unwrap();
    assert_eq!(
        config.alpn_protocols,
        [b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

#[test]
fn unreadable_or_invalid_files_are_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = write_pem_pair(dir.path());
    let missing = dir.path().join("missing.pem");
    assert!(
        tls::server_config(&CertSource::Files {
            cert: missing.clone(),
            key: key.clone()
        })
        .is_err()
    );
    assert!(
        tls::server_config(&CertSource::Files {
            cert: cert.clone(),
            key: missing
        })
        .is_err()
    );
    // Certificate and key swapped: neither parses as the other.
    assert!(
        tls::server_config(&CertSource::Files {
            cert: key,
            key: cert
        })
        .is_err()
    );
}

#[test]
fn key_not_matching_the_certificate_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, _) = write_pem_pair(dir.path());
    let other = tempfile::tempdir().unwrap();
    let (_, other_key) = write_pem_pair(other.path());
    assert!(
        tls::server_config(&CertSource::Files {
            cert,
            key: other_key
        })
        .is_err()
    );
}

#[test]
fn self_signed_certificate_is_generated_cached_0600_and_reused() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("data").join("web-tls");
    let source = CertSource::SelfSigned {
        cache_dir: cache_dir.clone(),
    };

    tls::server_config(&source).unwrap();
    let cert = cache_dir.join("localhost-cert.pem");
    let key = cache_dir.join("localhost-key.pem");
    assert_eq!(mode(&cert), 0o600);
    assert_eq!(mode(&key), 0o600);
    assert_eq!(mode(&cache_dir), 0o700);
    let first = (fs::read(&cert).unwrap(), fs::read(&key).unwrap());
    assert!(String::from_utf8_lossy(&first.0).contains("BEGIN CERTIFICATE"));

    tls::server_config(&source).unwrap();
    let second = (fs::read(&cert).unwrap(), fs::read(&key).unwrap());
    assert_eq!(first, second, "cached certificate reused");
}

#[test]
fn self_signed_certificate_is_regenerated_if_part_of_the_cache_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let source = CertSource::SelfSigned {
        cache_dir: dir.path().to_owned(),
    };
    tls::server_config(&source).unwrap();
    let cert = dir.path().join("localhost-cert.pem");
    let first = fs::read(&cert).unwrap();
    fs::remove_file(dir.path().join("localhost-key.pem")).unwrap();

    tls::server_config(&source).unwrap();
    assert_ne!(fs::read(&cert).unwrap(), first);
    assert_eq!(mode(&dir.path().join("localhost-key.pem")), 0o600);
}
