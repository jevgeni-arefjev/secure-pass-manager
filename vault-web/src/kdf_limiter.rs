//! The KDF limiter: unlock, create and a master password change each cost one or more
//! 256 MiB Argon2id runs, so only a few run at once, a few more wait, and the rest are
//! turned away.

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::KdfLimits;
use crate::sessions::off_worker;

/// Why [`KdfLimiter::run`] didn't run the job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KdfRejected {
    /// Every running slot and queue place is taken; try again later.
    Busy,
}

/// Runs key-deriving jobs on the blocking pool, at most `concurrency` at once with at
/// most `queue` more waiting.
///
/// Security: bounds the server's memory under a burst of unlock requests; excess
/// requests fail fast instead of piling up.
///
/// ```ignore
/// let session = limiter.run(move || Session::unlock(store, &name, &password, config)).await?;
/// ```
pub(crate) struct KdfLimiter {
    /// Permits for running or waiting; taken without waiting.
    admitted: Arc<Semaphore>,
    /// Permits for running.
    running: Arc<Semaphore>,
}

impl KdfLimiter {
    /// A limiter with `limits`.
    ///
    /// ```ignore
    /// let limiter = KdfLimiter::new(KdfLimits::default());
    /// ```
    pub(crate) fn new(limits: KdfLimits) -> Self {
        Self {
            admitted: Arc::new(Semaphore::new(limits.concurrency + limits.queue)),
            running: Arc::new(Semaphore::new(limits.concurrency)),
        }
    }

    /// Runs `job` on the blocking pool once a slot is free, or refuses at once with
    /// [`KdfRejected::Busy`] if the queue is full too. A panic in `job` resumes in the
    /// caller, like [`off_worker`].
    ///
    /// Security:
    /// - The permits move into the job, so a request dropped mid-derivation (client
    ///   gone) still holds its slot until the derivation really ends.
    /// - A panic reaches `catch_panic`, which ends the request's session, so a master
    ///   password change that panicked can't leave a half-used vault open (ADR-0014).
    ///
    /// ```ignore
    /// match limiter.run(|| derive()).await { Err(KdfRejected::Busy) => /* 503 */, .. }
    /// ```
    pub(crate) async fn run<R, F>(&self, job: F) -> Result<R, KdfRejected>
    where
        R: Send + 'static,
        F: FnOnce() -> R + Send + 'static,
    {
        let admitted = self
            .admitted
            .clone()
            .try_acquire_owned()
            .map_err(|_| KdfRejected::Busy)?;
        let running = self
            .running
            .clone()
            .acquire_owned()
            .await
            .expect("the KDF semaphore is never closed");
        Ok(off_worker(move || {
            let _permits = (admitted, running);
            job()
        })
        .await)
    }
}
