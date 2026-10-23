//! System clipboard for `get --copy`: copies one hidden value and clears it again.
//!
//! Security:
//! - The copy is marked as excluded from clipboard history, so clipboard managers that
//!   honour the hint don't keep it.
//! - It is cleared [`CLEAR_AFTER`] after copying, on lock, and when the CLI exits, but
//!   only if the clipboard still holds our value; something the person copied since is
//!   left alone.
//! - The value is kept (in locked memory) only to recognise it when clearing.

use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

#[cfg(target_os = "macos")]
use arboard::SetExtApple as _;
#[cfg(target_os = "linux")]
use arboard::SetExtLinux as _;
#[cfg(target_os = "windows")]
use arboard::SetExtWindows as _;
use vault_core::session::HiddenValue;
use zeroize::Zeroizing;

/// How long a copied value stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(20);

/// The system clipboard, opened on first use (a terminal without a display has none).
///
/// ```no_run
/// # use vault_cli::clipboard::Clipboard;
/// # use vault_core::session::HiddenValue;
/// let clipboard = Clipboard::new();
/// clipboard.copy(&HiddenValue::new("s3cret!".into()))?;
/// clipboard.clear_if_ours();
/// # Ok::<(), arboard::Error>(())
/// ```
#[derive(Clone, Default)]
pub struct Clipboard {
    state: Arc<Mutex<State>>,
}

/// What we know about the clipboard.
#[derive(Default)]
struct State {
    board: Option<arboard::Clipboard>,
    /// Our last copy, until it is cleared or overwritten by someone else.
    copied: Option<HiddenValue>,
    /// Bumped on every copy, so an older timer doesn't clear a newer copy early.
    generation: u64,
}

impl Clipboard {
    /// A clipboard handle; nothing is opened until the first copy.
    ///
    /// ```
    /// let clipboard = vault_cli::clipboard::Clipboard::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Puts `value` on the clipboard and clears it after [`CLEAR_AFTER`].
    ///
    /// ```no_run
    /// # use vault_core::session::HiddenValue;
    /// # let clipboard = vault_cli::clipboard::Clipboard::new();
    /// clipboard.copy(&HiddenValue::new("s3cret!".into()))?;
    /// # Ok::<(), arboard::Error>(())
    /// ```
    pub fn copy(&self, value: &HiddenValue) -> Result<(), arboard::Error> {
        let mut state = self.lock();
        if state.board.is_none() {
            state.board = Some(arboard::Clipboard::new()?);
        }
        let board = state.board.as_mut().expect("opened above");
        board.set().exclude_from_history().text(value.reveal())?;
        state.copied = Some(HiddenValue::new(value.reveal().to_owned()));
        state.generation += 1;
        let generation = state.generation;
        drop(state);

        let handle = self.clone();
        thread::spawn(move || {
            thread::sleep(CLEAR_AFTER);
            handle.clear_copy(Some(generation));
        });
        Ok(())
    }

    /// Clears the clipboard if it still holds our last copy.
    ///
    /// ```
    /// // Safe to call when nothing was copied: it does nothing.
    /// vault_cli::clipboard::Clipboard::new().clear_if_ours();
    /// ```
    pub fn clear_if_ours(&self) {
        self.clear_copy(None);
    }

    /// Clears our copy, if it is still on the clipboard; with `only`, only if that copy
    /// is still the latest one.
    ///
    /// ```ignore
    /// handle.clear_copy(Some(generation));
    /// ```
    fn clear_copy(&self, only: Option<u64>) {
        let mut state = self.lock();
        if only.is_some_and(|generation| generation != state.generation) {
            return;
        }
        let Some(copied) = state.copied.take() else {
            return;
        };
        let Some(board) = state.board.as_mut() else {
            return;
        };
        let current = board.get_text().map(Zeroizing::new);
        if current.is_ok_and(|text| text.as_str() == copied.reveal()) {
            let _ = board.clear();
        }
    }

    /// The state, even if a thread panicked while holding it (clearing must still work).
    ///
    /// ```ignore
    /// let state = self.lock();
    /// ```
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
