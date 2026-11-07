//! What the CLI prints to stderr besides a command's own messages (ADR-0014): each
//! `tracing` diagnostic as one plain sentence, and a panic as its location only.
//!
//! Security:
//! - A sentence is fixed text; only diagnostics about a vault's own files (permissions,
//!   audit log, memory lock) name the vaultname, so the person knows which vault home
//!   to fix. No other field of a diagnostic is ever printed.
//! - The panic message is never printed, since it can carry data.
//! - There is no diagnostic log file.

use std::fmt;

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// The sentence the person sees for diagnostic `code`, naming `vaultname` if the code
/// is about that vault's own files; `None` for `internal_error`, whose error the CLI
/// already prints itself. An unknown code is printed bare.
///
/// Security: fixed text, plus the vaultname for a vault's own files only.
///
/// ```
/// use vault_cli::diagnostics;
/// assert_eq!(
///     diagnostics::sentence("vault_temp_cleanup_failed", None).as_deref(),
///     Some("vault: warning: a temporary file left by an earlier save could not be removed")
/// );
/// assert_eq!(diagnostics::sentence("internal_error", None), None);
/// ```
#[must_use]
pub fn sentence(code: &str, vaultname: Option<&str>) -> Option<String> {
    let of_vault = |what: &str| match vaultname {
        Some(name) => format!("{what} of vault '{name}'"),
        None => what.to_owned(),
    };
    let loose = |what: &str| {
        format!(
            "{} is writable by other users; run `chmod go-w` on it",
            of_vault(what)
        )
    };
    let text = match code {
        "internal_error" => return None,
        "audit_write_failed" => format!(
            "{} could not be written; this session's events are not recorded",
            of_vault("the audit log")
        ),
        "audit_log_permissions_loose" => loose("the audit log"),
        "memory_lock_unavailable" => {
            let memory = match vaultname {
                Some(name) => format!("memory for vault '{name}'"),
                None => "memory for the vault".to_owned(),
            };
            format!("{memory} could not be locked; its secrets may be written to swap")
        }
        "vault_directory_permissions_loose" => {
            "the vault directory is writable by other users; run `chmod go-w` on it".to_owned()
        }
        "vault_home_permissions_loose" => loose("the vault home"),
        "vault_file_permissions_loose" => loose("the vault file"),
        "vault_temp_cleanup_failed" => {
            "a temporary file left by an earlier save could not be removed".to_owned()
        }
        "vault_directory_sync_failed" => {
            "the last save could not be flushed to disk; it may be lost if the system crashes"
                .to_owned()
        }
        "signal_handlers_unavailable" => concat!(
            "termination signals can't be caught; ",
            "if this process is killed, the clipboard is not cleared"
        )
        .to_owned(),
        unknown => unknown.to_owned(),
    };
    Some(format!("vault: warning: {text}"))
}

/// Sends warnings and errors to stderr as sentences ([`sentence`]); call once, at
/// start-up.
///
/// ```no_run
/// vault_cli::diagnostics::init();
/// ```
pub fn init() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(LevelFilter::WARN)
        .event_format(Sentences)
        .init();
}

/// Replaces the default panic hook, which prints the panic message, with one printing
/// only `vault: internal error at <file>:<line>`; call once, at start-up. The vault
/// shell then wipes the session and clears the clipboard before the process exits.
///
/// Security: a panic message can carry data (e.g. an `unwrap` printing a value); the
/// location identifies the bug without it. No audit event is written (ADR-0014).
///
/// ```no_run
/// vault_cli::diagnostics::print_panics_without_message();
/// ```
pub fn print_panics_without_message() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map_or_else(
            || "unknown".to_owned(),
            |l| format!("{}:{}", l.file(), l.line()),
        );
        eprintln!("vault: internal error at {location}");
    }));
}

/// Formats each `tracing` event as its [`sentence`], ignoring every other field.
///
/// ```ignore
/// tracing_subscriber::fmt().event_format(Sentences).init();
/// ```
struct Sentences;

impl<S, N> FormatEvent<S, N> for Sentences
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    /// Writes the event's sentence and a newline, or nothing if it has none; an event
    /// without an `event` code is printed as code `unknown`.
    ///
    /// ```ignore
    /// Sentences.format_event(&ctx, writer, event)?;
    /// ```
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let code = fields.event.as_deref().unwrap_or("unknown");
        match sentence(code, fields.vaultname.as_deref()) {
            Some(text) => writeln!(writer, "{text}"),
            None => Ok(()),
        }
    }
}

/// The two fields a sentence can use: the `event` code and the `vaultname`.
///
/// Security: every other field of the event is dropped unread.
///
/// ```ignore
/// let mut fields = Fields::default();
/// event.record(&mut fields);
/// ```
#[derive(Default)]
struct Fields {
    /// The event code.
    event: Option<String>,
    /// The vaultname, for diagnostics about a vault's own files.
    vaultname: Option<String>,
}

impl Visit for Fields {
    /// Keeps `event` and `vaultname` given as strings.
    ///
    /// ```ignore
    /// event.record(&mut fields);
    /// ```
    fn record_str(&mut self, field: &Field, value: &str) {
        self.keep(field, value.to_owned());
    }

    /// Keeps `event` and `vaultname` given by `%` (Display) or `?` (Debug).
    ///
    /// ```ignore
    /// event.record(&mut fields);
    /// ```
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.keep(field, format!("{value:?}"));
    }
}

impl Fields {
    /// Stores `value` if `field` is one a sentence uses; drops anything else.
    ///
    /// ```ignore
    /// self.keep(field, value.to_owned());
    /// ```
    fn keep(&mut self, field: &Field, value: String) {
        match field.name() {
            "event" => self.event = Some(value),
            "vaultname" => self.vaultname = Some(value),
            _ => {}
        }
    }
}
