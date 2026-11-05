//! The app config: everything the HTTP app is built from, and the seam tests use to
//! swap in a temp vault directory, a manual clock and the test vault format.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use vault_core::crypto::MasterPassword;
use vault_core::session::{Clock, Session, SessionConfig, SessionError, SystemClock};
use vault_core::storage::FileStore;

use crate::assets::Assets;

/// Absolute session lifetime: a session ends this long after unlock, whatever its activity.
pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);

/// How often the sweeper ends sessions past their idle timeout or lifetime. Well
/// under the shortest idle timeout (1 minute), so keys don't outlive it by much.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// How many unlocks or creates may derive keys at once (256 MiB Argon2id each).
pub const DEFAULT_KDF_CONCURRENCY: usize = 2;

/// How many unlocks or creates may wait for a KDF slot before further ones get a 503.
pub const DEFAULT_KDF_QUEUE: usize = 2;

/// The vault format new vaults are created in by `POST /api/vaults`.
///
/// Security: [`CreateFormat::InsecureTest`] (cheap KDF, ADR-0005) exists only with the
/// `insecure-test-kdf` feature, which only this crate's tests enable and release
/// builds refuse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CreateFormat {
    /// The current production format: Argon2id, 256 MiB, t=3, p=1.
    #[default]
    Production,
    /// The test format with a cheap KDF. Tests only.
    #[cfg(feature = "insecure-test-kdf")]
    InsecureTest,
}

impl CreateFormat {
    /// Creates vault `vaultname` in this format and returns it unlocked; see
    /// `vault_core::session::Session::create`.
    ///
    /// Security: costs one Argon2id run (256 MiB in production); run it behind the KDF
    /// limiter on the blocking pool.
    ///
    /// ```ignore
    /// let session = config.create_format.create_session(store, "alice", &password, session_config)?;
    /// ```
    pub(crate) fn create_session(
        self,
        store: FileStore,
        vaultname: &str,
        password: &MasterPassword,
        config: SessionConfig,
    ) -> Result<Session<FileStore>, SessionError> {
        match self {
            Self::Production => Session::create(store, vaultname, password, config),
            #[cfg(feature = "insecure-test-kdf")]
            Self::InsecureTest => {
                Session::create_insecure_for_tests(store, vaultname, password, config)
            }
        }
    }
}

/// Limits on concurrent key derivation, so a burst of unlocks can't exhaust memory.
///
/// ```
/// let limits = vault_web::KdfLimits::default();
/// assert_eq!(limits.concurrency, 2);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfLimits {
    /// Key derivations allowed to run at once.
    pub concurrency: usize,
    /// Requests allowed to wait for a slot; beyond this, 503.
    pub queue: usize,
}

impl Default for KdfLimits {
    /// [`DEFAULT_KDF_CONCURRENCY`] running, [`DEFAULT_KDF_QUEUE`] waiting.
    ///
    /// ```
    /// assert_eq!(vault_web::KdfLimits::default().queue, vault_web::config::DEFAULT_KDF_QUEUE);
    /// ```
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_KDF_CONCURRENCY,
            queue: DEFAULT_KDF_QUEUE,
        }
    }
}

/// Everything the HTTP app is built from; the binary fills it from its flags, tests
/// from a temp directory. Start from [`AppConfig::new`] and override fields.
///
/// ```
/// let config = vault_web::AppConfig::new("/tmp/web-vaults", 8443);
/// let _app = vault_web::App::new(config);
/// ```
#[derive(Clone)]
pub struct AppConfig {
    /// The vault directory holding one vault home per vaultname.
    pub vault_dir: PathBuf,
    /// Where time comes from; [`SystemClock`] outside tests.
    pub clock: Arc<dyn Clock>,
    /// Limits on concurrent unlocks and creates.
    pub kdf_limits: KdfLimits,
    /// Absolute session lifetime, whatever the activity.
    pub session_lifetime: Duration,
    /// How often the sweeper runs ([`crate::App::spawn_sweeper`]).
    pub sweep_interval: Duration,
    /// The port the server is reached on; only `localhost:<port>` and
    /// `127.0.0.1:<port>` are accepted as `Host`.
    pub port: u16,
    /// The format new vaults are created in.
    pub create_format: CreateFormat,
    /// The client bundle; [`Assets::embedded`] outside tests.
    pub assets: Assets,
}

impl AppConfig {
    /// The production config for a server reached on `port` with vaults in `vault_dir`:
    /// the system clock, default limits, lifetime and sweep interval, the production vault format and
    /// the client bundle embedded at compile time.
    ///
    /// ```
    /// let config = vault_web::AppConfig::new("/tmp/web-vaults", 8443);
    /// assert_eq!(config.session_lifetime, vault_web::config::DEFAULT_SESSION_LIFETIME);
    /// ```
    pub fn new(vault_dir: impl Into<PathBuf>, port: u16) -> Self {
        Self {
            vault_dir: vault_dir.into(),
            clock: Arc::new(SystemClock),
            kdf_limits: KdfLimits::default(),
            session_lifetime: DEFAULT_SESSION_LIFETIME,
            sweep_interval: DEFAULT_SWEEP_INTERVAL,
            port,
            create_format: CreateFormat::default(),
            assets: Assets::embedded(),
        }
    }

    /// Whether `host` (a `Host` header or URI authority) names this server: exactly
    /// `localhost:<port>` or `127.0.0.1:<port>`, ignoring ASCII case. On port 443 the
    /// port may be left out, as browsers do.
    ///
    /// Security: this is the DNS rebinding defence; any other name is refused.
    ///
    /// ```
    /// let config = vault_web::AppConfig::new("/tmp/web-vaults", 8443);
    /// assert!(config.is_own_host("localhost:8443"));
    /// assert!(!config.is_own_host("evil.example:8443"));
    /// ```
    pub fn is_own_host(&self, host: &str) -> bool {
        let (name, port) = match host.rsplit_once(':') {
            Some((name, port)) => (name, port.parse::<u16>().ok()),
            None => (host, Some(443)),
        };
        port == Some(self.port) && (name.eq_ignore_ascii_case("localhost") || name == "127.0.0.1")
    }
}
