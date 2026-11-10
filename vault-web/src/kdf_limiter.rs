//! The KDF limiter: unlock, create and a master password change each cost one or more
//! 256 MiB Argon2id runs, so only a few run at once, a few more wait, and the rest are
//! turned away.

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::KdfLimits;

/// Why [`KdfLimiter::run`] didn't return the job's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KdfRejected {
    /// Every running slot and queue place is taken; try again later.
    Busy,
    /// The job panicked on the blocking pool.
    Failed,
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
    /// [`KdfRejected::Busy`] if the queue is full too.
    ///
    /// Security: the permits move into the job, so a request dropped mid-derivation
    /// (client gone) still holds its slot until the derivation really ends.
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
            .map_err(|_| KdfRejected::Failed)?;
        tokio::task::spawn_blocking(move || {
            let _permits = (admitted, running);
            job()
        })
        .await
        .map_err(|_| KdfRejected::Failed)
    }
}
