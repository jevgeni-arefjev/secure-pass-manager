//! TLS for the server (rustls with the ring provider, no OpenSSL): a given PEM
//! certificate and key (e.g. from `mkcert`), or a self-signed `localhost` /
//! `127.0.0.1` certificate generated once and cached in the data directory.

use std::fs::{self, DirBuilder};
use std::io::Write as _;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Cached self-signed certificate, inside [`CertSource::SelfSigned`]'s `cache_dir`.
const CACHED_CERT: &str = "localhost-cert.pem";
/// Cached private key of [`CACHED_CERT`].
const CACHED_KEY: &str = "localhost-key.pem";

/// Names the self-signed certificate is valid for: the only hosts the server accepts.
const SELF_SIGNED_NAMES: [&str; 2] = ["localhost", "127.0.0.1"];

/// Where the server's certificate comes from.
///
/// ```
/// use vault_web::tls::CertSource;
/// let source = CertSource::Files { cert: "localhost.pem".into(), key: "localhost-key.pem".into() };
/// # let _ = source;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertSource {
    /// A PEM certificate chain and its PEM private key, e.g. from `mkcert`.
    Files {
        /// The certificate chain, leaf first.
        cert: PathBuf,
        /// The private key.
        key: PathBuf,
    },
    /// A self-signed certificate for `localhost` and `127.0.0.1`, generated on first
    /// use and cached in `cache_dir`.
    SelfSigned {
        /// Directory holding the cached certificate and key (created `0700`).
        cache_dir: PathBuf,
    },
}

/// Why TLS couldn't be set up. Messages name the step, never key material.
#[derive(Debug)]
pub enum TlsError {
    /// A certificate or key file couldn't be read, or the cache couldn't be written.
    Io(PathBuf, std::io::Error),
    /// The certificate file holds no valid PEM certificate.
    InvalidCertificate(PathBuf),
    /// The key file holds no valid PEM private key.
    InvalidKey(PathBuf),
    /// rustls refused the pair, e.g. the key doesn't match the certificate.
    Rejected(rustls::Error),
    /// The self-signed certificate couldn't be generated.
    Generate(rcgen::Error),
}

impl std::fmt::Display for TlsError {
    /// A one-line description for the operator.
    ///
    /// ```
    /// # use vault_web::tls::TlsError;
    /// let err = TlsError::InvalidKey("key.pem".into());
    /// assert_eq!(err.to_string(), "no valid PEM private key in key.pem");
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: {err}", path.display()),
            Self::InvalidCertificate(path) => {
                write!(f, "no valid PEM certificate in {}", path.display())
            }
            Self::InvalidKey(path) => write!(f, "no valid PEM private key in {}", path.display()),
            Self::Rejected(err) => write!(f, "certificate and key refused: {err}"),
            Self::Generate(err) => write!(f, "could not generate a certificate: {err}"),
        }
    }
}

impl std::error::Error for TlsError {}

/// The rustls server config for `source`, offering HTTP/2 and HTTP/1.1 via ALPN.
/// For [`CertSource::SelfSigned`], a cached certificate is reused; if either cached
/// file is missing, a new pair is generated and cached.
///
/// Security: the cached key and certificate are written `0600` in a `0700`
/// directory, each atomically (temp file, then rename).
///
/// ```no_run
/// use vault_web::tls::{self, CertSource};
/// let config = tls::server_config(&CertSource::SelfSigned { cache_dir: "/tmp/web-tls".into() })?;
/// # Ok::<(), vault_web::tls::TlsError>(())
/// ```
pub fn server_config(source: &CertSource) -> Result<ServerConfig, TlsError> {
    let (cert, key) = match source {
        CertSource::Files { cert, key } => (cert.clone(), key.clone()),
        CertSource::SelfSigned { cache_dir } => cached_self_signed(cache_dir)?,
    };
    let chain = load_certificates(&cert)?;
    let key = PrivateKeyDer::from_pem_file(&key).map_err(|_| TlsError::InvalidKey(key))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Rejected)?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(TlsError::Rejected)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Every PEM certificate in `path`, leaf first; an error if there is none.
///
/// ```ignore
/// let chain = load_certificates(Path::new("localhost.pem"))?;
/// ```
fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    fs::metadata(path).map_err(|err| TlsError::Io(path.to_owned(), err))?;
    let invalid = || TlsError::InvalidCertificate(path.to_owned());
    let chain = CertificateDer::pem_file_iter(path)
        .map_err(|_| invalid())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    if chain.is_empty() {
        return Err(invalid());
    }
    Ok(chain)
}

/// The paths of the cached self-signed certificate and key in `cache_dir`,
/// generating and caching a new pair unless both files already exist.
///
/// ```ignore
/// let (cert, key) = cached_self_signed(Path::new("/home/alice/.local/share/secure-pass-manager/web-tls"))?;
/// ```
fn cached_self_signed(cache_dir: &Path) -> Result<(PathBuf, PathBuf), TlsError> {
    let cert = cache_dir.join(CACHED_CERT);
    let key = cache_dir.join(CACHED_KEY);
    if cert.is_file() && key.is_file() {
        return Ok((cert, key));
    }
    let io = |path: &Path| {
        let path = path.to_owned();
        move |err| TlsError::Io(path, err)
    };
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(cache_dir)
        .map_err(io(cache_dir))?;
    let names = SELF_SIGNED_NAMES.map(str::to_owned).to_vec();
    let generated = rcgen::generate_simple_self_signed(names).map_err(TlsError::Generate)?;
    let key_pem = zeroize::Zeroizing::new(generated.signing_key.serialize_pem());
    write_private(&key, key_pem.as_bytes()).map_err(io(&key))?;
    write_private(&cert, generated.cert.pem().as_bytes()).map_err(io(&cert))?;
    Ok((cert, key))
}

/// Atomically replaces `path` with `contents`, readable by the owner only (`0600`).
///
/// ```ignore
/// write_private(&key_path, key_pem.as_bytes())?;
/// ```
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    // tempfile creates the file 0600 on Unix.
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    file.write_all(contents)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|err| err.error)?;
    Ok(())
}
