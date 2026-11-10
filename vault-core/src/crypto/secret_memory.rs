//! Buffers for key material and plaintext: page-locked where the OS allows it, and
//! zeroized before their memory is freed.
//!
//! None of these types implement `Clone` or `Debug`, so a secret can't be copied or
//! printed by accident. These examples must fail to compile:
//!
//! ```compile_fail
//! # use vault_core::crypto::MasterPassword;
//! let password = MasterPassword::new("hunter2".into());
//! let _copy = password.clone();
//! ```
//!
//! ```compile_fail
//! # use vault_core::crypto::MasterPassword;
//! let password = MasterPassword::new("hunter2".into());
//! println!("{password:?}");
//! ```
//!
//! ```compile_fail
//! # use vault_core::crypto::{self, MasterPassword, Plaintext};
//! # let password = MasterPassword::new("hunter2".into());
//! let (key, _) = crypto::create_insecure_for_tests(&password, &Plaintext::new(vec![]))?;
//! let _copy = key.clone();
//! # Ok::<(), crypto::CryptoError>(())
//! ```
//!
//! ```compile_fail
//! # use vault_core::crypto::{self, MasterPassword, Plaintext};
//! # let password = MasterPassword::new("hunter2".into());
//! let (key, _) = crypto::create_insecure_for_tests(&password, &Plaintext::new(vec![]))?;
//! println!("{key:?}");
//! # Ok::<(), crypto::CryptoError>(())
//! ```
//!
//! ```compile_fail
//! # use vault_core::crypto::Plaintext;
//! let body = Plaintext::new(b"[]".to_vec());
//! let _copy = body.clone();
//! ```
//!
//! ```compile_fail
//! # use vault_core::crypto::Plaintext;
//! let body = Plaintext::new(b"[]".to_vec());
//! println!("{body:?}");
//! ```

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

/// A fixed-length byte buffer kept in pages that belong to it alone.
///
/// The usable window starts on a page boundary and spans whole pages, so locking
/// (`mlock`) and unlocking it never touches another allocation's pages. Locking is
/// best-effort: if it fails (e.g. `RLIMIT_MEMLOCK` reached) the buffer is still
/// zeroized on drop, and [`LockedBytes::is_locked`] reports `false`.
pub(crate) struct LockedBytes {
    /// The `mlock` guard; `None` if locking failed. Declared before `buf` so the pages are unlocked before they are freed.
    lock: Option<region::LockGuard>,
    /// The allocation: the page-aligned window plus up to one page of slack before it.
    buf: Box<[u8]>,
    /// Offset of the page-aligned window in `buf`.
    start: usize,
    /// Length of the contents, in bytes, from `start`.
    len: usize,
}

impl LockedBytes {
    /// Allocates `len` zeroed bytes in page-aligned, page-locked memory.
    ///
    /// ```ignore
    /// let mut key = LockedBytes::zeroed(32);
    /// key.as_mut_bytes().copy_from_slice(&derived);
    /// ```
    pub(crate) fn zeroed(len: usize) -> Self {
        let page = region::page::size();
        let window = len.div_ceil(page).max(1) * page;
        // One extra page of slack so a page-aligned window always fits.
        let buf = vec![0u8; window + page].into_boxed_slice();
        // `align_offset` may in theory give up (usize::MAX); the window then still fits
        // from 0, just without page alignment.
        let start = Some(buf.as_ptr().align_offset(page))
            .filter(|&s| s < page)
            .unwrap_or(0);
        let lock = region::lock(buf[start..].as_ptr(), window).ok();
        Self {
            lock,
            buf,
            start,
            len,
        }
    }

    /// Copies `bytes` into a new locked buffer. The caller still owns (and must
    /// zeroize) the source.
    ///
    /// ```ignore
    /// let copy = LockedBytes::from_slice(&decrypted);
    /// ```
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        let mut locked = Self::zeroed(bytes.len());
        locked.as_mut_bytes().copy_from_slice(bytes);
        locked
    }

    /// The buffer's contents.
    ///
    /// ```ignore
    /// let hkdf = Hkdf::<Sha256>::new(None, key.as_bytes());
    /// ```
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[self.start..self.start + self.len]
    }

    /// The buffer's contents, writable in place (e.g. as a KDF or decryption output).
    ///
    /// ```ignore
    /// getrandom::fill(key.as_mut_bytes())?;
    /// ```
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.start + self.len]
    }

    /// Whether the OS agreed to keep these pages out of swap.
    ///
    /// ```ignore
    /// if !key.is_locked() { /* warn: zeroize-only protection */ }
    /// ```
    pub(crate) fn is_locked(&self) -> bool {
        self.lock.is_some()
    }
}

impl Drop for LockedBytes {
    /// Zeroizes the whole allocation; the lock guard and the allocation are dropped
    /// afterwards, in that order.
    ///
    /// ```ignore
    /// drop(kek); // zeroized, then unlocked, then freed
    /// ```
    fn drop(&mut self) {
        self.wipe();
    }
}

impl LockedBytes {
    /// Zeroizes the whole allocation, slack pages included; only [`Drop`] calls it.
    ///
    /// ```ignore
    /// self.wipe(); // every byte of `buf` is 0, not just the usable window
    /// ```
    fn wipe(&mut self) {
        self.buf.zeroize();
    }
}

/// A master password, held in locked memory for as long as it is needed.
///
/// Security: build it straight from the hidden terminal prompt; the source string is
/// zeroized on construction. Never log or display it. The password is NFC-normalized
/// (ADR-0007), so the same characters typed on different systems derive the same KEK.
///
/// ```
/// use vault_core::crypto::MasterPassword;
/// let password = MasterPassword::new(String::from("correct horse battery staple"));
/// ```
pub struct MasterPassword(LockedBytes);

impl MasterPassword {
    /// Moves `password` into locked memory, NFC-normalized (ADR-0007), and zeroizes the
    /// original string.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// let password = MasterPassword::new(String::from("hunter2"));
    /// ```
    #[must_use]
    pub fn new(mut password: String) -> Self {
        let locked = nfc_into_locked(&password);
        password.zeroize();
        Self(locked)
    }

    /// The password bytes, for the KDF only.
    ///
    /// ```ignore
    /// argon2.hash_password_into(password.as_bytes(), salt, kek.as_mut_bytes())?;
    /// ```
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether `self` and `other` are the same password, compared after NFC
    /// normalization (ADR-0007). For "type it again" confirmation prompts.
    ///
    /// Security: both sides stay in locked memory; no copy is made. The comparison is
    /// not constant-time, which is fine for comparing two inputs the same user just
    /// typed, but don't use it to check a password against a stored value.
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// let first = MasterPassword::new("correct horse battery".into());
    /// assert!(first.matches(&MasterPassword::new("correct horse battery".into())));
    /// assert!(!first.matches(&MasterPassword::new("correct horse batterx".into())));
    /// ```
    #[must_use]
    pub fn matches(&self, other: &MasterPassword) -> bool {
        self.as_bytes() == other.as_bytes()
    }

    /// Whether the password's memory is locked out of swap (false means zeroize-only).
    ///
    /// ```
    /// # use vault_core::crypto::MasterPassword;
    /// let password = MasterPassword::new("hunter2".into());
    /// if !password.is_memory_locked() { /* log a warning, never the password */ }
    /// ```
    #[must_use]
    pub fn is_memory_locked(&self) -> bool {
        self.0.is_locked()
    }
}

/// Copies `text` into a new locked buffer as NFC, without an intermediate unlocked
/// string: one pass measures the normalized length, a second encodes into the buffer.
///
/// Security: the normalizer's small internal buffers aren't zeroized; they hold a few
/// characters at a time and are accepted.
///
/// ```ignore
/// let locked = nfc_into_locked("e\u{301}"); // stored as "\u{e9}"
/// ```
fn nfc_into_locked(text: &str) -> LockedBytes {
    let len = text.nfc().map(char::len_utf8).sum();
    let mut locked = LockedBytes::zeroed(len);
    let mut at = 0;
    for c in text.nfc() {
        at += c.encode_utf8(&mut locked.as_mut_bytes()[at..]).len();
    }
    locked
}

/// The random 32-byte key a vault is encrypted under, available only while unlocked.
///
/// Security: opaque by design. It can't be cloned, printed or read out; the session
/// keeps it until lock, and dropping it zeroizes and unlocks its memory.
///
/// ```
/// # use vault_core::crypto::{self, MasterPassword, Plaintext};
/// # let password = MasterPassword::new("hunter2".into());
/// # let (key, _) = crypto::create_insecure_for_tests(&password, &Plaintext::new(vec![]))?;
/// drop(key); // lock: key wiped
/// # Ok::<(), crypto::CryptoError>(())
/// ```
pub struct VaultKey(pub(crate) LockedBytes);

impl VaultKey {
    /// Whether the key's memory is locked out of swap (false means zeroize-only).
    ///
    /// ```
    /// # use vault_core::crypto::{self, MasterPassword, Plaintext};
    /// # let password = MasterPassword::new("hunter2".into());
    /// # let (key, _) = crypto::create_insecure_for_tests(&password, &Plaintext::new(vec![]))?;
    /// if !key.is_memory_locked() { /* log a warning, never the key */ }
    /// # Ok::<(), crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn is_memory_locked(&self) -> bool {
        self.0.is_locked()
    }
}

/// A decrypted vault body (the serialized secrets), held in locked memory.
///
/// Security: the session owns the only copy while unlocked; dropping it zeroizes it.
///
/// ```
/// use vault_core::crypto::Plaintext;
/// let body = Plaintext::new(br#"[{"title":"github"}]"#.to_vec());
/// assert_eq!(body.as_bytes(), br#"[{"title":"github"}]"#);
/// ```
pub struct Plaintext(pub(crate) LockedBytes);

impl Plaintext {
    /// Moves `bytes` into locked memory and zeroizes the original vector.
    ///
    /// ```
    /// # use vault_core::crypto::Plaintext;
    /// let body = Plaintext::new(b"[]".to_vec());
    /// ```
    #[must_use]
    pub fn new(mut bytes: Vec<u8>) -> Self {
        let locked = LockedBytes::from_slice(&bytes);
        bytes.zeroize();
        Self(locked)
    }

    /// The decrypted bytes. Security: don't copy them into unprotected buffers that
    /// outlive the session.
    ///
    /// ```
    /// # use vault_core::crypto::Plaintext;
    /// let body = Plaintext::new(b"[]".to_vec());
    /// assert_eq!(body.as_bytes(), b"[]");
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether the body's memory is locked out of swap (false means zeroize-only,
    /// e.g. a body larger than `RLIMIT_MEMLOCK` allows).
    ///
    /// ```
    /// # use vault_core::crypto::Plaintext;
    /// let body = Plaintext::new(b"[]".to_vec());
    /// let _locked = body.is_memory_locked();
    /// ```
    #[must_use]
    pub fn is_memory_locked(&self) -> bool {
        self.0.is_locked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wiping zeroes every byte of the allocation, including the slack outside the
    /// usable window, so nothing a secret touched survives the free.
    #[test]
    fn wipe_zeroes_the_whole_allocation() {
        let mut bytes = LockedBytes::zeroed(100);
        bytes.buf.fill(0xa5);

        bytes.wipe();

        assert!(bytes.buf.iter().all(|&b| b == 0));
    }

    /// The usable window starts on a page boundary and its pages fit inside the
    /// allocation, so locking it never touches another allocation's pages.
    #[test]
    fn window_is_page_aligned_and_inside_the_allocation() {
        let page = region::page::size();
        for len in [0, 1, 32, page - 1, page, page + 1, 3 * page] {
            let bytes = LockedBytes::zeroed(len);
            let window = len.div_ceil(page).max(1) * page;

            assert_eq!(bytes.as_bytes().len(), len, "len {len}");
            assert_eq!(bytes.as_bytes().as_ptr().align_offset(page), 0, "len {len}");
            assert!(bytes.start + window <= bytes.buf.len(), "len {len}");
        }
    }

    /// Copies keep the source's bytes exactly, and new buffers start zeroed.
    #[test]
    fn from_slice_copies_and_zeroed_starts_at_zero() {
        assert_eq!(LockedBytes::from_slice(b"key").as_bytes(), b"key");
        assert!(LockedBytes::zeroed(64).as_bytes().iter().all(|&b| b == 0));
    }
}
