//! Memory handling of secrets, observed from outside the process's code: page locking
//! (`mlock`) of every secret type, the zeroize-only fallback when the OS refuses to
//! lock, its one warning, and disabled core dumps (`RLIMIT_CORE` and the dumpable flag).
//!
//! The limits and flag changed here (`RLIMIT_MEMLOCK`, `RLIMIT_CORE`,
//! `PR_SET_DUMPABLE`) are process-wide, so this file holds a single test that runs its
//! steps in order; other test files run in their own processes and are unaffected.
#![cfg(target_os = "linux")]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use rlimit::Resource;
use rustix::process::{self, DumpableBehavior};
use tempfile::TempDir;
use tracing_subscriber::fmt::MakeWriter;
use vault_core::audit::MemorySink;
use vault_core::crypto::{self, MasterPassword, Plaintext};
use vault_core::session::{HiddenValue, Secret, Session, SessionConfig};
use vault_core::storage::FileStore;

const PASSWORD: &str = "correct horse battery";
const HIDDEN: &str = "p4ss-w0rd-in-locked-memory";

/// Below this soft `RLIMIT_MEMLOCK` the first step can't expect every buffer to lock.
const ENOUGH_MEMLOCK: u64 = 1 << 20;

/// Log output captured from `tracing`, shared between the subscriber and the test.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    /// The log text written so far.
    ///
    /// ```text
    /// assert!(captured.text().contains("memory_lock_unavailable"));
    /// ```
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Captured {
    /// Appends a formatted log line to the shared buffer.
    ///
    /// ```text
    /// captured.write_all(b"WARN ...")?;
    /// ```
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Nothing is buffered, so there is nothing to flush.
    ///
    /// ```text
    /// captured.flush()?;
    /// ```
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Self;

    /// Hands `tracing` a writer into the same shared buffer.
    ///
    /// ```text
    /// tracing_subscriber::fmt().with_writer(captured.clone())
    /// ```
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Runs `f` with `tracing` events on this thread written to a fresh buffer, and
/// returns what was logged.
///
/// ```text
/// let log = capture_log(|| { session.save(secret).unwrap(); });
/// ```
fn capture_log(f: impl FnOnce()) -> String {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    captured.text()
}

/// Whether this process may lock memory regardless of `RLIMIT_MEMLOCK` (e.g. root), read
/// from the effective capabilities in `/proc/self/status`.
///
/// ```text
/// if has_cap_ipc_lock() { return; } // the limit can't force the fallback
/// ```
fn has_cap_ipc_lock() -> bool {
    const CAP_IPC_LOCK: u32 = 14;
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .is_some_and(|caps| caps & (1 << CAP_IPC_LOCK) != 0)
}

/// Whether every secret type built now (master password, vault key, decrypted body and
/// hidden value) reports its memory locked, checked against `expected`; the vault still
/// round-trips either way.
///
/// ```text
/// assert_secret_types_locked(true);
/// ```
fn assert_secret_types_locked(expected: bool) {
    let password = MasterPassword::new(PASSWORD.into());
    let (key, sealed) =
        crypto::create_insecure_for_tests(&password, &Plaintext::new(b"[]".to_vec())).unwrap();
    let opened = crypto::open_body(&key, &sealed).unwrap();
    let hidden = HiddenValue::new(HIDDEN.into());

    assert_eq!(opened.as_bytes(), b"[]");
    assert_eq!(hidden.reveal(), HIDDEN);
    assert_eq!(
        [
            password.is_memory_locked(),
            key.is_memory_locked(),
            opened.is_memory_locked(),
            hidden.is_memory_locked(),
        ],
        [expected; 4],
        "master password, vault key, body, hidden value"
    );
}

/// Unlocks `alice`, saves a secret with a hidden password, and returns the log.
///
/// ```text
/// let log = unlock_and_save(&dir);
/// ```
fn unlock_and_save(dir: &TempDir) -> String {
    capture_log(|| {
        let mut session = Session::unlock(
            FileStore::new(dir.path()).unwrap(),
            "alice",
            &MasterPassword::new(PASSWORD.into()),
            SessionConfig::new(Arc::new(MemorySink::default())),
        )
        .unwrap();
        session
            .save(Secret::new("github").with_password(HiddenValue::new(HIDDEN.into())))
            .unwrap();
        session.lock();
    })
}

#[test]
fn secrets_are_locked_out_of_swap_or_fall_back_to_zeroize_with_one_warning() {
    // Core dumps: hardening sets both limits to 0 and marks the process non-dumpable,
    // so a crash writes no secrets, not even to a piped crash handler.
    crypto::harden_process().unwrap();
    assert_eq!(Resource::CORE.get().unwrap(), (0, 0));
    assert_eq!(
        process::dumpable_behavior().unwrap(),
        DumpableBehavior::NotDumpable
    );

    let dir = TempDir::new().unwrap();
    Session::create_insecure_for_tests(
        FileStore::new(dir.path()).unwrap(),
        "alice",
        &MasterPassword::new(PASSWORD.into()),
        SessionConfig::new(Arc::new(MemorySink::default())),
    )
    .unwrap()
    .lock();

    // Under a usual limit, every secret is locked and nothing is logged.
    let (soft, hard) = Resource::MEMLOCK.get().unwrap();
    if soft >= ENOUGH_MEMLOCK {
        assert_secret_types_locked(true);
        let log = unlock_and_save(&dir);
        assert!(!log.contains("memory_lock_unavailable"), "{log}");
    } else {
        eprintln!("RLIMIT_MEMLOCK is {soft} bytes; skipped the locked step");
    }

    // With no lockable memory, secrets still work, zeroize-only, and the session warns
    // once without naming any secret.
    if has_cap_ipc_lock() {
        eprintln!("CAP_IPC_LOCK ignores RLIMIT_MEMLOCK; skipped the fallback step");
        return;
    }
    Resource::MEMLOCK.set(0, hard).unwrap();
    assert_secret_types_locked(false);
    let log = unlock_and_save(&dir);
    Resource::MEMLOCK.set(soft, hard).unwrap();

    assert_eq!(log.matches("memory_lock_unavailable").count(), 1, "{log}");
    assert!(!log.contains(PASSWORD) && !log.contains(HIDDEN), "{log}");
}
