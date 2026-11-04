//! The `vault-web` command line: where to listen, where the vaults are, and which TLS
//! certificate to serve.
//!
//! Security: no flag ever carries a master password or other secret.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::Parser;

use crate::tls::CertSource;

/// Address the server listens on unless `--bind` says otherwise: localhost only.
pub const DEFAULT_BIND: &str = "127.0.0.1:8443";

/// Web vault directory inside the app's data directory, apart from the CLI's `vaults`.
const WEB_VAULTS: &str = "web-vaults";

/// Self-signed certificate cache inside the app's data directory.
const WEB_TLS: &str = "web-tls";

/// HTTPS server for the password manager's browser client.
///
/// clap shows the first paragraph of this comment as the help summary; `long_about = None`
/// keeps the rest (and its example) out of `vault-web --help`.
///
/// ```
/// use clap::Parser;
/// use vault_web::args::Args;
/// let args = Args::try_parse_from(["vault-web", "--bind", "127.0.0.1:9443"]).unwrap();
/// assert_eq!(args.bind.port(), 9443);
/// ```
#[derive(Debug, Parser)]
#[command(name = "vault-web", version, long_about = None)]
pub struct Args {
    /// Address to listen on
    #[arg(long, value_name = "ADDR", default_value = DEFAULT_BIND)]
    pub bind: SocketAddr,

    /// Directory holding the web vaults [default: the platform data directory's web-vaults]
    #[arg(long, value_name = "PATH")]
    pub vault_dir: Option<PathBuf>,

    /// PEM certificate chain to serve, e.g. from mkcert (needs --tls-key)
    #[arg(long, value_name = "PATH", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key of --tls-cert (needs --tls-cert)
    #[arg(long, value_name = "PATH", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,
}

impl Args {
    /// The vault directory: `--vault-dir`, else `web-vaults` in `data_dir` (the
    /// app's platform data directory, e.g. `~/.local/share/secure-pass-manager`);
    /// `None` if neither is known.
    ///
    /// ```
    /// use std::path::Path;
    /// use clap::Parser;
    /// use vault_web::args::Args;
    /// let args = Args::try_parse_from(["vault-web"]).unwrap();
    /// let dir = args.vault_dir(Some(Path::new("/data/secure-pass-manager"))).unwrap();
    /// assert_eq!(dir, Path::new("/data/secure-pass-manager/web-vaults"));
    /// ```
    pub fn vault_dir(&self, data_dir: Option<&Path>) -> Option<PathBuf> {
        self.vault_dir
            .clone()
            .or_else(|| data_dir.map(|dir| dir.join(WEB_VAULTS)))
    }

    /// The certificate to serve: `--tls-cert`/`--tls-key` if given, else a self-signed
    /// one cached in `web-tls` in `data_dir`; `None` if neither is known.
    ///
    /// ```
    /// use std::path::Path;
    /// use clap::Parser;
    /// use vault_web::args::Args;
    /// use vault_web::tls::CertSource;
    /// let args = Args::try_parse_from(["vault-web"]).unwrap();
    /// let source = args.cert_source(Some(Path::new("/data/secure-pass-manager"))).unwrap();
    /// assert_eq!(source, CertSource::SelfSigned { cache_dir: "/data/secure-pass-manager/web-tls".into() });
    /// ```
    pub fn cert_source(&self, data_dir: Option<&Path>) -> Option<CertSource> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(cert), Some(key)) => Some(CertSource::Files {
                cert: cert.clone(),
                key: key.clone(),
            }),
            _ => data_dir.map(|dir| CertSource::SelfSigned {
                cache_dir: dir.join(WEB_TLS),
            }),
        }
    }
}
