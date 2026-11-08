# Error classes: what the person sees and what is logged

Every error belongs to one of four classes, and the class fixes what the person is shown, whether an audit event is written (ADR-0010) and whether a diagnostic is printed. The person gets a message they can act on, without internals or anything they typed. Whoever runs the app gets enough in the diagnostics to tell a full disk from a denied permission. On the CLI, the person and the operator are the same, so the CLI message also names the cause kind.

| Class | Examples | Shown to the person | Audit event | Diagnostic |
| --- | --- | --- | --- | --- |
| Input mistake | invalid field, weak master password, no secret with this title, backup path already exists, invalid vaultname | A specific message naming the field and the rule, never the value | No | No |
| Security refusal | unlock failed, CSRF token, Origin, Host, wrong current master password | One generic message per refusal; unlock failure is the same whether or not the vaultname exists, after the same minimum delay | Unlock failed and master password change failed, if the vault exists | Web: the request log line only |
| Session ended | locked (idle, lifetime, conflict, three wrong current master passwords) | A fixed message saying the vault is locked and must be unlocked again | The lock that ended it (auto-locked, locked on conflict, ...) | No |
| Internal failure | file system, OS random number generator, a vault file that can't be read, a panic | A generic message (web: `internal error`, status 500). CLI: the generic message plus a cause kind in words, e.g. `vault storage failed (disk full)` | No | One line with what failed and its cause kind, e.g. `{"event":"internal_error","cause":"storage","kind":"StorageFull"}` |

## Rules for diagnostics

- A diagnostic never holds a field value, a master password, a path, a request URL or query, a header, a cookie, a session ID or a panic message.
- The cause kind is `std::io::ErrorKind` (or the equivalent fixed name), never the OS error text, which can carry a path.
- A diagnostic names the vaultname only when it is about that vault's own files (loose permissions, an audit log that can't be written, memory that can't be locked), so the operator knows which vault home to fix. Request lines and internal-failure lines never name it, so the request log can't be linked to vaultnames.
- The CLI prints its diagnostics to stderr as plain sentences (`vault: warning: the audit log could not be written; this session's events are not recorded`); the event code is for tests. The CLI has no diagnostic log file.
- vault-web prints its diagnostics to stderr as JSON lines at a fixed `INFO` level. There is no `RUST_LOG` override, since `debug` and `trace` output from dependencies (hyper, rustls) has not been checked for secrets.
- The CLI words a fixed set of cause kinds: `StorageFull` "disk full", `PermissionDenied` "permission denied", `ReadOnlyFilesystem` "read-only file system", a lock held too long "vault is busy in another session". Any other kind is "unexpected file system error", with the exact kind only in the diagnostic.

## Panics

A panic is an internal failure. Both front ends replace the default panic hook with one that prints only the location (CLI: `vault: internal error at src/x.rs:12`; web: `{"event":"panic","location":"src/x.rs:12"}`), since a panic message can carry data. The session's keys are wiped before the process or request ends. No audit event is written: there is no reliable "locked" to record mid-panic, and ADR-0010 records an event only after its action succeeds.

## Considered Options

- **Pass the full error (`io::Error` text) to the person or the log.** Rejected: OS error text can carry the path, which holds the vaultname, and a backup path the person chose.
- **One generic message for every error.** Rejected: input mistakes need to name the rule, or the person can't fix them.
- **A diagnostic log file for the CLI.** Rejected: another file that could leak, while the audit log already records the key events and the person running the CLI sees stderr anyway.
- **Log failed unlocks of an unknown vaultname.** Rejected (as in ADR-0010): it would create a file for every guessed name and record which vaultnames were tried. On the web the request log already shows each attempt as a `401` on the unlock route.

## Consequences

- An error type that collapses a failure to a bare "I/O failed" has to keep its cause kind as far as the front end, so it can be logged and, on the CLI, shown.
- Each front end maps every error it can receive to one class; a new error variant needs a class before it can be shown.
- The "structured logging of key events" requirement is met by the audit log (owner-facing, JSON Lines) and the web diagnostics (operator-facing, JSON lines); the CLI's stderr diagnostics are for a person reading the terminal and are not structured.
