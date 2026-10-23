//! `vault` command-line interface. Commands: `secure-password-manager.md` §5.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::filter::LevelFilter;
use vault_cli::shell::{self, Env, Exit};
use vault_cli::terminal::StdTerminal;
use vault_core::session::SystemClock;

/// Entry point: hardens the process before anything else, sends warnings to stderr,
/// then runs the CLI on the real terminal.
///
/// ```text
/// $ vault unlock alice
/// ```
fn main() -> ExitCode {
    if vault_core::crypto::harden_process().is_err() {
        eprintln!("vault: could not disable core dumps; refusing to run");
        return Exit::Failure.into();
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(LevelFilter::WARN)
        .without_time()
        .with_target(false)
        .init();
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
