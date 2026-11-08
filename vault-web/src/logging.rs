//! The server's diagnostics subscriber: JSON lines at a fixed `INFO` level (ADR-0014).
//! `main.rs` and the test log capture both install it, so tests check the real format.

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Installs the global subscriber, printing each event to `writer` as one JSON object
/// per line: `timestamp`, `level` and the event's fields (`event`, `method`, `route`,
/// `status`, `cause`, `kind`, ...) as top-level JSON fields. Panics if a global
/// subscriber is already installed.
///
/// Security: the level is fixed at `INFO`, with no `RUST_LOG` override, since `debug`
/// and `trace` output from dependencies (hyper, rustls) hasn't been checked for secrets.
///
/// ```
/// vault_web::logging::init(std::io::sink); // main.rs passes std::io::stderr
/// tracing::info!(event = "request", method = "GET", status = 200);
/// // {"timestamp":"2026-11-08T10:00:00.000000Z","level":"INFO","event":"request","method":"GET","status":200}
/// ```
pub fn init<W>(writer: W)
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_max_level(LevelFilter::INFO)
        .with_writer(writer)
        .init();
}
