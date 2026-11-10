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
//!   removed and wiped on its next lookup, or by the periodic sweep, whichever comes
//!   first.
//!
//! Every method that takes a session's vault mutex (a lookup, a lock, a request's
//! vault work) may wait for another request's save, backup or master password change,
//! so async code runs it through [`off_worker`], never on an async worker thread.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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

/// A session just issued (by [`Sessions::insert`] or [`Sessions::reissue`]): the ID to
/// hand to the browser and the session itself.
pub(crate) type Issued = (SessionId, Arc<WebSession>);

/// Why [`Sessions::insert`] or [`Sessions::reissue`] issued no session. The vault
/// concerned is locked and wiped either way.
#[derive(Clone, Copy, Debug)]
pub(crate) enum IssueRefused {
    /// The OS random number generator failed.
    Randomness,
    /// [`Sessions::lock_all`] ran: the server is stopping.
    Stopping,
    /// The session to reissue had already ended (reissue only).
    Ended,
}

impl From<RandomnessFailed> for IssueRefused {
    /// A randomness failure while issuing the session.
    ///
    /// ```ignore
    /// let id = SessionId::generate()?; // in a fn returning Result<_, IssueRefused>
    /// ```
    fn from(_: RandomnessFailed) -> Self {
        Self::Randomness
    }
}

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
    /// Wrong current master passwords given to a master password change in a row; a
    /// right one reissues the session, which starts the count over.
    wrong_master_passwords: AtomicU32,
}

impl WebSession {
    /// A session holding the unlocked `vault`, opened at `created`.
    ///
    /// ```ignore
    /// let session = WebSession::new(vault, csrf_token, clock.now(), idle_timeout);
    /// ```
    fn new(
        vault: Session<FileStore>,
        csrf_token: Zeroizing<String>,
        created: Instant,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            vaultname: vault.vaultname().clone(),
            vault: Mutex::new(Some(vault)),
            csrf_token,
            created,
            idle_timeout,
            wrong_master_passwords: AtomicU32::new(0),
        }
    }

    /// Counts one more wrong current master password in a row and returns the count.
    ///
    /// ```ignore
    /// if session.count_wrong_master_password() >= 3 { sessions.remove(key) }
    /// ```
    pub(crate) fn count_wrong_master_password(&self) -> u32 {
        self.wrong_master_passwords.fetch_add(1, Ordering::SeqCst) + 1
    }

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
    /// Blocks while another request holds the vault, and `f` may do file I/O; run it on
    /// the blocking pool ([`off_worker`]).
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
    /// Takes the vault mutex, so it blocks while another request holds the vault (an
    /// auto-lock also writes the audit log); run it on the blocking pool
    /// ([`off_worker`]).
    ///
    /// ```ignore
    /// if !session.is_unlocked() { sessions.remove(key) }
    /// ```
    pub(crate) fn is_unlocked(&self) -> bool {
        self.vault().as_mut().is_some_and(Session::is_unlocked)
    }

    /// Locks the vault and wipes its keys; later calls do nothing.
    ///
    /// Blocks while another request holds the vault; run it on the blocking pool
    /// ([`off_worker`]).
    ///
    /// ```ignore
    /// session.lock();
    /// ```
    pub(crate) fn lock(&self) {
        if let Some(session) = self.vault().take() {
            session.lock();
        }
    }

    /// Locks the vault and wipes its keys because the server is stopping, recorded in
    /// the audit log as a termination signal; later calls do nothing.
    ///
    /// ```ignore
    /// session.lock_on_signal();
    /// ```
    fn lock_on_signal(&self) {
        if let Some(session) = self.vault().take() {
            session.lock_on_signal();
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
    /// The open sessions, by the SHA-256 of their ID.
    map: Mutex<HashMap<SessionKey, Arc<WebSession>>>,
    /// Set by [`Sessions::lock_all`]; written and read only under the `map` lock, so
    /// no insert can slip in after it.
    stopping: AtomicBool,
    /// Clock for idle and lifetime expiry.
    clock: Arc<dyn Clock>,
    /// Longest a session lives after unlock, idle or not.
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
            stopping: AtomicBool::new(false),
            clock,
            lifetime,
        }
    }

    /// Registers the unlocked `vault` under a fresh session ID and CSRF token.
    ///
    /// Security: once [`Sessions::lock_all`] has run, `vault` is locked at once
    /// (recorded as a termination signal) instead, so an unlock that finished while the
    /// server was stopping can't leave a vault open.
    ///
    /// Locking writes the audit log; run it on the blocking pool.
    ///
    /// ```ignore
    /// let (id, session) = sessions.insert(vault, idle_timeout)?;
    /// ```
    pub(crate) fn insert(
        &self,
        vault: Session<FileStore>,
        idle_timeout: Duration,
    ) -> Result<Issued, IssueRefused> {
        let id = SessionId::generate()?;
        let session = Arc::new(WebSession::new(
            vault,
            random_hex()?,
            self.clock.now(),
            idle_timeout,
        ));
        self.register(id, session)
    }

    /// Moves the session under `key` to a fresh session ID and CSRF token, keeping its
    /// vault, idle timeout and absolute lifetime; the old ID and token stop working.
    ///
    /// Security: used after a master password change, like the new ID unlock issues,
    /// so a cookie or token taken before the change is useless afterwards. The old
    /// session is removed whatever happens: if no new ID or token can be made, it is
    /// locked rather than left usable under the old ones.
    ///
    /// Blocks while another request holds the vault; run it on the blocking pool.
    ///
    /// ```ignore
    /// let (id, session) = sessions.reissue(current.key())?;
    /// ```
    pub(crate) fn reissue(&self, key: SessionKey) -> Result<Issued, IssueRefused> {
        let fresh = SessionId::generate().and_then(|id| Ok((id, random_hex()?)));
        let old = self.map().remove(&key).ok_or(IssueRefused::Ended)?;
        let Ok((id, csrf_token)) = fresh else {
            old.lock();
            return Err(IssueRefused::Randomness);
        };
        let vault = old.vault().take().ok_or(IssueRefused::Ended)?;
        let session = Arc::new(WebSession::new(
            vault,
            csrf_token,
            old.created,
            old.idle_timeout,
        ));
        self.register(id, session)
    }

    /// Locks and removes every session on `vaultname` but the one under `keep`.
    /// Returns how many were locked.
    ///
    /// Security: used after a master password change, so no other web session keeps
    /// the old vault key. A session whose unlock is still deriving keys is registered
    /// after this runs and is not reached; it locks on its next save or backup, as on
    /// any conflict.
    ///
    /// Blocks while a request holds one of their vaults; run it on the blocking pool.
    ///
    /// ```ignore
    /// sessions.lock_others(session.vaultname(), current.key());
    /// ```
    pub(crate) fn lock_others(&self, vaultname: &Vaultname, keep: SessionKey) -> usize {
        let others: Vec<_> = {
            let mut map = self.map();
            let keys: Vec<_> = map
                .iter()
                .filter(|(key, session)| **key != keep && session.vaultname == *vaultname)
                .map(|(key, _)| *key)
                .collect();
            keys.iter().filter_map(|key| map.remove(key)).collect()
        };
        for session in &others {
            session.lock();
        }
        others.len()
    }

    /// Adds `session` under `id`, unless the server is stopping: then the session is
    /// locked at once, recorded as a termination signal.
    ///
    /// ```ignore
    /// self.register(id, session)
    /// ```
    fn register(&self, id: SessionId, session: Arc<WebSession>) -> Result<Issued, IssueRefused> {
        let mut map = self.map();
        if self.stopping.load(Ordering::SeqCst) {
            drop(map);
            session.lock_on_signal();
            return Err(IssueRefused::Stopping);
        }
        map.insert(id.key(), session.clone());
        Ok((id, session))
    }

    /// The live session under `key`. A session that has auto-locked or outlived the
    /// absolute lifetime is removed, wiped and reported as absent.
    ///
    /// Blocks while a request holds the session's vault; run it on the blocking pool.
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
    /// Blocks while a request holds the session's vault; run it on the blocking pool.
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

    /// Ends every session that has auto-locked or outlived the absolute lifetime:
    /// removes it and wipes its keys. Returns how many ended.
    ///
    /// Blocks while a request holds a session's vault; run it on the blocking pool.
    ///
    /// ```ignore
    /// let ended = sessions.sweep();
    /// ```
    pub(crate) fn sweep(&self) -> usize {
        let snapshot: Vec<_> = self
            .map()
            .iter()
            .map(|(key, session)| (*key, Arc::clone(session)))
            .collect();
        let now = self.clock.now();
        let mut ended = 0;
        for (key, session) in snapshot {
            if !session.is_alive(now, self.lifetime) {
                self.remove(key);
                ended += 1;
            }
        }
        ended
    }

    /// Removes every session and wipes its keys, recorded as a termination signal in
    /// each vault's audit log, and refuses every later insert. Returns how many were
    /// open.
    ///
    /// Blocks while a request holds a session's vault; run it on the blocking pool.
    ///
    /// ```ignore
    /// sessions.lock_all(); // on SIGTERM
    /// ```
    pub(crate) fn lock_all(&self) -> usize {
        let drained: Vec<_> = {
            let mut map = self.map();
            self.stopping.store(true, Ordering::SeqCst);
            map.drain().map(|(_, session)| session).collect()
        };
        for session in &drained {
            session.lock_on_signal();
        }
        drained.len()
    }

    /// How many sessions are registered, live or not yet swept.
    ///
    /// ```ignore
    /// let open = sessions.len();
    /// ```
    pub(crate) fn len(&self) -> usize {
        self.map().len()
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

/// Runs `job` on Tokio's blocking pool and returns its result; a panic in `job`
/// resumes in the caller, so `catch_panic` still ends the request's session.
///
/// Security: vault work (a session's mutex, file I/O, the storage lock's wait of up to
/// 5 s) goes through here, so a slow vault never stalls an async worker thread and with
/// it every other request, other vaults' included.
///
/// ```ignore
/// let session = off_worker(move || sessions.get(key)).await;
/// ```
pub(crate) async fn off_worker<R, F>(job: F) -> R
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    match tokio::task::spawn_blocking(job).await {
        Ok(result) => result,
        Err(err) => match err.try_into_panic() {
            Ok(payload) => std::panic::resume_unwind(payload),
            // Only when the runtime shuts down mid-request.
            Err(_) => panic!("blocking job cancelled"),
        },
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
