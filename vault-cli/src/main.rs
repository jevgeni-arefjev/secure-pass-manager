//! `vault` command-line interface. Commands: `secure-password-manager.md` §5.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use vault_cli::shell::{self, Env, Exit};
use vault_cli::terminal::StdTerminal;
use vault_core::session::SystemClock;

/// Entry point: replaces the panic hook and hardens the process before anything else,
/// prints diagnostics to stderr as sentences, then runs the CLI on the real terminal.
///
/// ```text
/// $ vault unlock alice
/// ```
fn main() -> ExitCode {
    vault_cli::diagnostics::print_panics_without_message();
    if vault_core::crypto::harden_process().is_err() {
        eprintln!("vault: could not disable core dumps; refusing to run");
        return Exit::Failure.into();
    }
    vault_cli::diagnostics::init();
    let mut terminal = match StdTerminal::new() {
        Ok(terminal) => terminal,
        Err(err) => {
            eprintln!("vault: {err}");
            return Exit::Failure.into();
        }
    };
    let env = Env {
        default_vault_dir: dirs::data_dir()
            .map(|dir| dir.join("secure-pass-manager").join("vaults")),
        clock: Arc::new(SystemClock),
        lock_check_interval: Duration::from_secs(1),
        handle_signals: true,
    };
    shell::run(std::env::args_os(), &mut terminal, &env).into()
}
