//! The session registry: every unlocked vault, by session ID.
//!
//! A browser holds only the session ID (in the `__Host-session` cookie) and the CSRF
//! token (in memory). Everything else (the `vault-core` [`Session`] with its keys) stays
//! here, server-side (ADR-0012).
//!
//! Security:
//! - Session IDs and CSRF tokens are 256 bits from the OS random number generator.
//! - The registry is keyed by the SHA-256 of the session ID, never the ID itself, so
//!   lookups never compare the secret and logs can carry a short hash of it.
//! - A session that has auto-locked (idle timeout) or outlived the absolute lifetime is
//!   removed and wiped on its next lookup.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use vault_core::session::{Clock, Session, SessionError};
use vault_core::storage::{FileStore, Vaultname};
use zeroize::Zeroizing;

/// Bytes of randomness in a session ID and a CSRF token.
const TOKEN_BYTES: usize = 32;

/// Bytes of the session key shown in request logs.
const TAG_BYTES: usize = 4;

/// The OS random number generator failed; no session can be issued.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RandomnessFailed;

/// A session ID as the browser sends it: 64 lowercase hex digits.
///
/// Security: a bearer credential. Never logged; only its [`SessionKey`] is kept.
///
/// ```ignore
/// let id = SessionId::parse(cookie_value)?;
/// ```
pub(crate) struct SessionId(Zeroizing<String>);

impl SessionId {
    /// A fresh random session ID.
    ///
    /// ```ignore
    /// let id = SessionId::generate()?;
    /// ```
    fn generate() -> Result<Self, RandomnessFailed> {
        random_hex().map(Self)
    }

    /// `value` as a session ID, if it has the shape of one; anything else (a planted or
    /// mangled cookie) is `None`.
    ///
    /// ```ignore
    /// assert!(SessionId::parse("../etc").is_none());
    /// ```
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let valid = value.len() == TOKEN_BYTES * 2
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        valid.then(|| Self(Zeroizing::new(value.to_owned())))
    }

    /// The ID's text, for the `Set-Cookie` header only.
    ///
    /// ```ignore
    /// format!("__Host-session={}", id.as_str())
    /// ```
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// The registry key of this ID: its SHA-256.
    ///
    /// ```ignore
    /// let session = sessions.get(id.key());
    /// ```
    pub(crate) fn key(&self) -> SessionKey {
        SessionKey(Sha256::digest(self.0.as_bytes()).into())
    }
}

/// The SHA-256 of a session ID: what the registry is keyed by.
///
/// ```ignore
/// tracing::info!(session = %key.tag());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionKey([u8; 32]);

impl SessionKey {
    /// A short hex tag of this key for request logs: enough to follow one session
    /// through the log, useless for finding its ID.
    ///
    /// ```ignore
    /// assert_eq!(key.tag().len(), 8);
    /// ```
    pub(crate) fn tag(&self) -> String {
        hex(&self.0[..TAG_BYTES])
    }
}

/// One browser session: an unlocked vault and what guards it.
pub(crate) struct WebSession {
    /// The unlocked vault; `None` once locked. The mutex serialises this session's
    /// requests.
    vault: Mutex<Option<Session<FileStore>>>,
    /// The vaultname this session unlocked.
    vaultname: Vaultname,
    /// Required in `X-CSRF-Token` on every state-changing request.
    csrf_token: Zeroizing<String>,
    /// When the session was opened, for the absolute lifetime.
    created: Instant,
    /// The idle timeout the session was unlocked with.
    idle_timeout: Duration,
}

impl WebSession {
    /// The vaultname this session unlocked.
    ///
    /// ```ignore
    /// let name = session.vaultname().as_str();
    /// ```
    pub(crate) fn vaultname(&self) -> &Vaultname {
        &self.vaultname
    }

    /// The CSRF token, for the unlock and session responses only.
    ///
    /// ```ignore
    /// SessionInfo { csrf_token: session.csrf_token(), .. }
    /// ```
    pub(crate) fn csrf_token(&self) -> &str {
        &self.csrf_token
    }

    /// The idle timeout the session was unlocked with.
    ///
    /// ```ignore
    /// let minutes = session.idle_timeout().as_secs() / 60;
    /// ```
    pub(crate) fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Whether `token` is this session's CSRF token.
    ///
    /// Security: compared in constant time, so timing reveals nothing about the token.
    ///
    /// ```ignore
    /// if !session.csrf_matches(header_value) { return Err(ApiError::CSRF) }
    /// ```
    pub(crate) fn csrf_matches(&self, token: &str) -> bool {
        self.csrf_token.as_bytes().ct_eq(token.as_bytes()).into()
    }

    /// Runs `f` on the vault under the session's mutex; [`SessionError::Locked`]
    /// without running it if the vault is already locked.
    ///
    /// ```ignore
    /// let count = session.with_vault(|vault| Ok(vault.list()?.len()))?;
    /// ```
    pub(crate) fn with_vault<R>(
        &self,
        f: impl FnOnce(&mut Session<FileStore>) -> Result<R, SessionError>,
    ) -> Result<R, SessionError> {
        self.vault().as_mut().map_or(Err(SessionError::Locked), f)
    }

    /// Whether the vault is still unlocked; auto-locks it first if the idle timeout has
    /// passed. Checking doesn't count as activity.
    ///
    /// ```ignore
    /// if !session.is_unlocked() { sessions.remove(key) }
    /// ```
    pub(crate) fn is_unlocked(&self) -> bool {
        self.vault().as_mut().is_some_and(Session::is_unlocked)
    }

    /// Locks the vault and wipes its keys; later calls do nothing.
    ///
    /// ```ignore
    /// session.lock();
    /// ```
    pub(crate) fn lock(&self) {
        if let Some(session) = self.vault().take() {
            session.lock();
        }
    }

    /// Whether the session may still be used at `now`: unlocked (not auto-locked by
    /// its idle timeout) and younger than `lifetime`.
    ///
    /// ```ignore
    /// if !session.is_alive(clock.now(), lifetime) { session.lock() }
    /// ```
    fn is_alive(&self, now: Instant, lifetime: Duration) -> bool {
        let young = now.saturating_duration_since(self.created) < lifetime;
        young && self.is_unlocked()
    }

    /// The vault slot. A mutex poisoned by a panicking request is recovered: the slot
    /// still holds a valid `Option`, and the caller decides whether to keep it.
    ///
    /// ```ignore
    /// let vault = self.vault();
    /// ```
    fn vault(&self) -> MutexGuard<'_, Option<Session<FileStore>>> {
        self.vault.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Every open session, keyed by the SHA-256 of its ID.
///
/// ```ignore
/// let sessions = Sessions::new(config.clock.clone(), config.session_lifetime);
/// ```
pub(crate) struct Sessions {
    map: Mutex<HashMap<SessionKey, Arc<WebSession>>>,
    clock: Arc<dyn Clock>,
    lifetime: Duration,
}

impl Sessions {
    /// An empty registry whose sessions end `lifetime` after unlock, timed by `clock`.
    ///
    /// ```ignore
    /// let sessions = Sessions::new(Arc::new(SystemClock), Duration::from_secs(8 * 3600));
    /// ```
    pub(crate) fn new(clock: Arc<dyn Clock>, lifetime: Duration) -> Self {
        Self {
            map: Mutex::default(),
            clock,
            lifetime,
        }
    }

    /// Registers the unlocked `vault` under a fresh session ID and CSRF token.
    ///
    /// ```ignore
    /// let (id, session) = sessions.insert(vault, idle_timeout)?;
    /// ```
    pub(crate) fn insert(
        &self,
        vault: Session<FileStore>,
        idle_timeout: Duration,
    ) -> Result<(SessionId, Arc<WebSession>), RandomnessFailed> {
        let id = SessionId::generate()?;
        let session = Arc::new(WebSession {
            vaultname: vault.vaultname().clone(),
            vault: Mutex::new(Some(vault)),
            csrf_token: random_hex()?,
            created: self.clock.now(),
            idle_timeout,
        });
        self.map().insert(id.key(), session.clone());
        Ok((id, session))
    }

    /// The live session under `key`. A session that has auto-locked or outlived the
    /// absolute lifetime is removed, wiped and reported as absent.
    ///
    /// ```ignore
    /// let session = sessions.get(id.key()).ok_or(ApiError::LOCKED)?;
    /// ```
    pub(crate) fn get(&self, key: SessionKey) -> Option<Arc<WebSession>> {
        let session = self.map().get(&key).cloned()?;
        if session.is_alive(self.clock.now(), self.lifetime) {
            Some(session)
        } else {
            self.remove(key);
            None
        }
    }

    /// Removes the session under `key`, if any, and locks it.
    ///
    /// ```ignore
    /// sessions.remove(current.key());
    /// ```
    pub(crate) fn remove(&self, key: SessionKey) {
        let removed = self.map().remove(&key);
        if let Some(session) = removed {
            session.lock();
        }
    }

    /// The session map; recovered if a panicking request poisoned it, since every
    /// update to it is a single insert or remove.
    ///
    /// ```ignore
    /// self.map().insert(key, session);
    /// ```
    fn map(&self) -> MutexGuard<'_, HashMap<SessionKey, Arc<WebSession>>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// [`TOKEN_BYTES`] random bytes as lowercase hex.
///
/// ```ignore
/// let token = random_hex()?; // 64 hex digits
/// ```
fn random_hex() -> Result<Zeroizing<String>, RandomnessFailed> {
    let mut bytes = Zeroizing::new([0u8; TOKEN_BYTES]);
    getrandom::fill(&mut *bytes).map_err(|_| RandomnessFailed)?;
    Ok(Zeroizing::new(hex(&*bytes)))
}

/// `bytes` as lowercase hex.
///
/// ```ignore
/// assert_eq!(hex(&[0xab, 0x01]), "ab01");
/// ```
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("write to String");
    }
    out
}
