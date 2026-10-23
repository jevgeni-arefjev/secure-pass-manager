//! Masked prompt for the master password and hidden fields: echoes one `*` per
//! character typed (ADR-0008).
//!
//! The key handling is a pure state machine ([`MaskedInput`]) so it can be tested
//! without a terminal; [`read_masked`] drives it from `crossterm` raw-mode events.
//!
//! Security:
//! - Input goes straight into a zeroizing buffer allocated once with room for
//!   [`MAX_HIDDEN_CHARS`], so it never reallocates and leaves a copy behind.
//! - A paste holding a line break is refused whole, so the rest of it can't spill into
//!   the next prompt or the shell history.
//! - Raw mode and bracketed paste are switched off again by a drop guard, on every exit
//!   path including errors and panics.

use std::io::{self, IsTerminal, Write};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::{execute, terminal};
use zeroize::{Zeroize, Zeroizing};

use super::TerminalError;

/// Most characters a hidden input may have; matches the longest hidden field the vault
/// accepts.
pub(crate) const MAX_HIDDEN_CHARS: usize = 1024;

/// One key press (or paste), already decoded from the terminal.
#[derive(Debug)]
pub(crate) enum Key<'a> {
    /// A typed character.
    Char(char),
    /// Backspace: removes the last character.
    Backspace,
    /// Ctrl-U: clears everything typed.
    ClearLine,
    /// Enter: submits the input.
    Enter,
    /// Ctrl-C: cancels the prompt.
    Interrupt,
    /// Ctrl-D: cancels the prompt when nothing is typed, ignored otherwise.
    EndOfInput,
    /// Text pasted in one go (bracketed paste).
    Paste(&'a str),
}

/// What the terminal should show after a key, and whether the prompt is over.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Keep reading; first print this many stars, or erase this many.
    Continue(Echo),
    /// The input is complete.
    Submit,
    /// The prompt ended without input.
    Abort(TerminalError),
}

/// Screen change for one step. Stars are one column wide, so erasing is exact.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Echo {
    /// Print this many `*`.
    Stars(usize),
    /// Erase this many `*` to the left of the cursor.
    Erase(usize),
    /// Ring the bell: the key was ignored (input full, or control character).
    Bell,
    /// Nothing to show.
    Nothing,
}

/// The masked input typed so far.
///
/// ```ignore
/// let mut input = MaskedInput::new();
/// assert_eq!(input.press(Key::Char('a')), Step::Continue(Echo::Stars(1)));
/// assert_eq!(input.press(Key::Enter), Step::Submit);
/// assert_eq!(input.into_text().as_str(), "a");
/// ```
pub(crate) struct MaskedInput {
    text: Zeroizing<String>,
    chars: usize,
}

impl MaskedInput {
    /// An empty input with room for [`MAX_HIDDEN_CHARS`] characters of any width.
    ///
    /// ```ignore
    /// let input = MaskedInput::new();
    /// ```
    pub(crate) fn new() -> Self {
        Self {
            text: Zeroizing::new(String::with_capacity(MAX_HIDDEN_CHARS * 4)),
            chars: 0,
        }
    }

    /// Applies one key and says what to show next.
    ///
    /// ```ignore
    /// assert_eq!(input.press(Key::Interrupt), Step::Abort(TerminalError::Interrupted));
    /// ```
    pub(crate) fn press(&mut self, key: Key<'_>) -> Step {
        match key {
            Key::Char(c) => Step::Continue(if self.push(c) {
                Echo::Stars(1)
            } else {
                Echo::Bell
            }),
            Key::Backspace => Step::Continue(match self.text.pop() {
                Some(_) => {
                    self.chars -= 1;
                    Echo::Erase(1)
                }
                None => Echo::Nothing,
            }),
            Key::ClearLine => {
                let erased = self.chars;
                self.clear();
                Step::Continue(Echo::Erase(erased))
            }
            Key::Enter => Step::Submit,
            Key::Interrupt => Step::Abort(TerminalError::Interrupted),
            Key::EndOfInput if self.chars == 0 => Step::Abort(TerminalError::EndOfInput),
            Key::EndOfInput => Step::Continue(Echo::Nothing),
            Key::Paste(text) if text.contains(['\n', '\r']) => {
                Step::Abort(TerminalError::MultilinePaste)
            }
            Key::Paste(text) => {
                let added = text.chars().filter(|&c| self.push(c)).count();
                let all_taken = added == text.chars().count();
                Step::Continue(if all_taken {
                    Echo::Stars(added)
                } else {
                    Echo::Bell
                })
            }
        }
    }

    /// The finished input.
    ///
    /// ```ignore
    /// let password = MasterPassword::new(std::mem::take(&mut *input.into_text()));
    /// ```
    pub(crate) fn into_text(self) -> Zeroizing<String> {
        self.text
    }

    /// Adds `c` unless it is a control character or the input is full.
    ///
    /// ```ignore
    /// assert!(input.push('a'));
    /// ```
    fn push(&mut self, c: char) -> bool {
        if c.is_control() || self.chars == MAX_HIDDEN_CHARS {
            return false;
        }
        self.text.push(c);
        self.chars += 1;
        true
    }

    /// Wipes everything typed, keeping the buffer.
    ///
    /// ```ignore
    /// input.clear();
    /// ```
    fn clear(&mut self) {
        self.text.zeroize();
        self.chars = 0;
    }
}

/// Switches the terminal into raw mode with bracketed paste, and back again on drop.
struct RawMode;

impl RawMode {
    /// Enters raw mode and enables bracketed paste.
    ///
    /// ```ignore
    /// let _raw = RawMode::enter()?;
    /// ```
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let guard = Self;
        execute!(io::stderr(), event::EnableBracketedPaste)?;
        Ok(guard)
    }
}

impl Drop for RawMode {
    /// Restores the terminal; errors are ignored because nothing better can be done.
    ///
    /// ```ignore
    /// drop(raw);
    /// ```
    fn drop(&mut self) {
        let _ = execute!(io::stderr(), event::DisableBracketedPaste);
        let _ = terminal::disable_raw_mode();
    }
}

/// Shows `prompt` on stderr and reads a masked line from the terminal.
///
/// Security: refuses with [`TerminalError::NotATerminal`] when stdin is not a terminal,
/// so a master password can't be piped in. The result is zeroized on drop; move it
/// straight into a `MasterPassword` or `HiddenValue`.
///
/// ```ignore
/// let typed = read_masked("Master password: ")?;
/// let password = MasterPassword::new(std::mem::take(&mut *typed));
/// ```
pub(crate) fn read_masked(prompt: &str) -> Result<Zeroizing<String>, TerminalError> {
    if !io::stdin().is_terminal() {
        return Err(TerminalError::NotATerminal);
    }
    let mut err = io::stderr();
    write!(err, "{prompt}")?;
    err.flush()?;
    let mut input = MaskedInput::new();
    let outcome = {
        let _raw = RawMode::enter()?;
        loop {
            let step = match event::read()? {
                Event::Key(key) => match decode(key) {
                    Some(key) => input.press(key),
                    None => continue,
                },
                Event::Paste(text) => {
                    let text = Zeroizing::new(text);
                    input.press(Key::Paste(&text))
                }
                _ => continue,
            };
            match step {
                Step::Continue(echo) => show(&mut err, echo)?,
                Step::Submit => break Ok(()),
                Step::Abort(why) => break Err(why),
            }
        }
    };
    writeln!(err)?;
    outcome.map(|()| input.into_text())
}

/// Maps a crossterm key event to a [`Key`]; `None` for releases and keys we ignore.
///
/// ```ignore
/// decode(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)) // Some(Key::Enter)
/// ```
fn decode(key: KeyEvent) -> Option<Key<'static>> {
    if key.kind == KeyEventKind::Release {
        return None;
    }
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    Some(match key.code {
        KeyCode::Char('c') if ctrl => Key::Interrupt,
        KeyCode::Char('d') if ctrl => Key::EndOfInput,
        KeyCode::Char('u') if ctrl => Key::ClearLine,
        KeyCode::Char(_) if ctrl => return None,
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Enter => Key::Enter,
        _ => return None,
    })
}

/// Draws one [`Echo`] on `out`.
///
/// ```ignore
/// show(&mut io::stderr(), Echo::Stars(3))?; // prints "***"
/// ```
fn show(out: &mut impl Write, echo: Echo) -> io::Result<()> {
    match echo {
        Echo::Stars(n) => write!(out, "{}", "*".repeat(n))?,
        Echo::Erase(n) => write!(out, "{}", "\u{8} \u{8}".repeat(n))?,
        Echo::Bell => write!(out, "\u{7}")?,
        Echo::Nothing => return Ok(()),
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `keys` into a fresh input and returns every step plus the final text.
    fn type_keys(keys: Vec<Key<'_>>) -> (Vec<Step>, String) {
        let mut input = MaskedInput::new();
        let steps = keys.into_iter().map(|key| input.press(key)).collect();
        (steps, input.into_text().as_str().to_owned())
    }

    #[test]
    fn each_typed_character_echoes_one_star() {
        let (steps, text) = type_keys(vec![Key::Char('a'), Key::Char('ä'), Key::Char('😀')]);
        assert!(steps.iter().all(|s| *s == Step::Continue(Echo::Stars(1))));
        assert_eq!(text, "aä😀");
    }

    #[test]
    fn backspace_removes_one_character_and_one_star() {
        let (steps, text) = type_keys(vec![Key::Char('a'), Key::Char('😀'), Key::Backspace]);
        assert_eq!(steps[2], Step::Continue(Echo::Erase(1)));
        assert_eq!(text, "a");
    }

    #[test]
    fn backspace_on_empty_input_shows_nothing() {
        let (steps, _) = type_keys(vec![Key::Backspace]);
        assert_eq!(steps, [Step::Continue(Echo::Nothing)]);
    }

    #[test]
    fn ctrl_u_erases_every_star() {
        let (steps, text) = type_keys(vec![
            Key::Char('a'),
            Key::Char('b'),
            Key::Char('c'),
            Key::ClearLine,
        ]);
        assert_eq!(steps[3], Step::Continue(Echo::Erase(3)));
        assert_eq!(text, "");
    }

    #[test]
    fn enter_submits() {
        let mut input = MaskedInput::new();
        input.press(Key::Char('x'));
        assert_eq!(input.press(Key::Enter), Step::Submit);
    }

    #[test]
    fn ctrl_c_cancels() {
        let mut input = MaskedInput::new();
        input.press(Key::Char('x'));
        assert_eq!(
            input.press(Key::Interrupt),
            Step::Abort(TerminalError::Interrupted)
        );
    }

    #[test]
    fn ctrl_d_cancels_only_when_empty() {
        let mut input = MaskedInput::new();
        assert_eq!(
            input.press(Key::EndOfInput),
            Step::Abort(TerminalError::EndOfInput)
        );
        input.press(Key::Char('x'));
        assert_eq!(input.press(Key::EndOfInput), Step::Continue(Echo::Nothing));
    }

    #[test]
    fn control_characters_are_ignored_with_a_bell() {
        let (steps, text) = type_keys(vec![Key::Char('\t'), Key::Char('\u{1b}')]);
        assert!(steps.iter().all(|s| *s == Step::Continue(Echo::Bell)));
        assert_eq!(text, "");
    }

    #[test]
    fn single_line_paste_echoes_one_star_per_character() {
        let (steps, text) = type_keys(vec![Key::Paste("hünter")]);
        assert_eq!(steps, [Step::Continue(Echo::Stars(6))]);
        assert_eq!(text, "hünter");
    }

    #[test]
    fn paste_with_a_line_break_is_refused_whole() {
        for paste in ["pass\nword", "password\r\n", "\rx"] {
            let (steps, text) = type_keys(vec![Key::Char('a'), Key::Paste(paste)]);
            assert_eq!(steps[1], Step::Abort(TerminalError::MultilinePaste));
            assert_eq!(text, "a");
        }
    }

    #[test]
    fn input_stops_at_the_maximum_length() {
        let mut input = MaskedInput::new();
        for _ in 0..MAX_HIDDEN_CHARS {
            assert_eq!(input.press(Key::Char('x')), Step::Continue(Echo::Stars(1)));
        }
        assert_eq!(input.press(Key::Char('x')), Step::Continue(Echo::Bell));
        assert_eq!(input.into_text().chars().count(), MAX_HIDDEN_CHARS);
    }

    #[test]
    fn buffer_never_reallocates_even_with_four_byte_characters() {
        let mut input = MaskedInput::new();
        let capacity = input.text.capacity();
        for _ in 0..MAX_HIDDEN_CHARS + 5 {
            input.press(Key::Char('😀'));
        }
        assert_eq!(input.text.capacity(), capacity);
    }
}
