//! Where the session reads time from: idle timeouts, the unlock failure delay and
//! secret timestamps. Front ends use [`SystemClock`]; tests inject their own clock so
//! they can move time forward instead of sleeping.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A source of time for a session.
///
/// ```
/// use std::time::{Duration, Instant};
/// use vault_core::session::{Clock, SystemClock};
///
/// let clock = SystemClock;
/// let before = clock.now();
/// clock.sleep(Duration::from_millis(1));
/// assert!(clock.now() > before);
/// ```
pub trait Clock: Send + Sync {
    /// A monotonic instant, for idle timeouts and delays.
    ///
    /// ```
    /// # use vault_core::session::{Clock, SystemClock};
    /// let started = SystemClock.now();
    /// ```
    fn now(&self) -> Instant;

    /// Seconds since the Unix epoch, for a secret's created and updated times.
    ///
    /// ```
    /// # use vault_core::session::{Clock, SystemClock};
    /// assert!(SystemClock.unix_time() > 1_700_000_000);
    /// ```
    fn unix_time(&self) -> u64;

    /// Blocks for `duration`. Used to give every failed unlock the same minimum length.
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use vault_core::session::{Clock, SystemClock};
    /// SystemClock.sleep(Duration::from_millis(1));
    /// ```
    fn sleep(&self, duration: Duration);
}

/// The real clock: [`Instant::now`], the system time and [`std::thread::sleep`].
///
/// ```
/// use vault_core::session::{Clock, SystemClock};
/// let _now = SystemClock.now();
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// [`Instant::now`].
    ///
    /// ```
    /// # use vault_core::session::{Clock, SystemClock};
    /// let _now = SystemClock.now();
    /// ```
    fn now(&self) -> Instant {
        Instant::now()
    }

    /// The system time in whole seconds; 0 if the system clock is before 1970.
    ///
    /// ```
    /// # use vault_core::session::{Clock, SystemClock};
    /// let _seconds = SystemClock.unix_time();
    /// ```
    fn unix_time(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }

    /// [`std::thread::sleep`].
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use vault_core::session::{Clock, SystemClock};
    /// SystemClock.sleep(Duration::ZERO);
    /// ```
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}
