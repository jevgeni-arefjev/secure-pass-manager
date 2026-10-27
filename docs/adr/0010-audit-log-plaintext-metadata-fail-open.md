# Audit log: plaintext metadata per vault, fail-open, no tamper evidence

Each vault's audit events are appended as JSON Lines to `audit.log` in its vault home (ADR-0009), in plaintext. An audit event holds a UTC timestamp, its kind and at most the title of the secret it concerns, never a field value, hidden or not. The vaultname isn't repeated in it, since the vault home already names the vault. The log has to be plaintext because a failed unlock has no vault key to encrypt under; encrypting everything else would need a second key scheme for little gain. Anyone who can read or write a vault home is effectively its owner (root or that OS user) and could just as well run a keylogger, which is out of scope. So the log is a record for the owner, not forensic evidence: it has no tamper evidence, and failing to write it never blocks the operation it records.

## Considered Options

- **Encrypted under the vault key**: failed unlocks can't be recorded, since there is no key yet; recording them needs a plaintext side buffer or a public-key wrap, i.e. new crypto.
- **Inside the vault file's encrypted body**: the same failed-unlock problem, plus every save rewrites the log and ties it to the revision counter.
- **Hash chain or MAC over the audit events**: a chain only catches edits in the middle, not truncation or a rewritten chain; a MAC needs a key that a failed unlock doesn't have.
- **Fail-closed (refuse the operation if the log can't be written)**: a full disk would lock owners out of their own secrets, and a save would have to log before committing, leaving false events when it then fails.
- **SQLite table**: queryable, but heavier, and needs the same defensive open as a vault file (ADR-0006).

## Consequences

- Audit events are a typed `audit::Event` enum, so a secret type can't be logged, and are written through an `AuditSink` trait: a file sink for the CLI, an in-memory one for tests, and `vault-web` can bring its own. `tracing` is kept for diagnostics only, on stderr.
- Logged: vault created, unlocked, unlock failed, locked, auto-locked, locked on conflict, terminated by signal, secret saved (added or replaced), secret removed, secret revealed (`--show` or `--copy`), master password changed, master password change failed, and backup exported once backup exists. Not logged: `gen`, `list` and masked `get`.
- An event is written only after its action succeeds, so the log never claims what didn't happen. A failed write gives one visible warning per session and an `audit_write_failed` diagnostic.
- A failed unlock of an existing vault is logged within the constant minimum unlock delay, so the write doesn't reveal that the vaultname exists. A failed unlock of an unknown vaultname writes nothing and creates no file.
- The file is opened with `O_APPEND` and `O_NOFOLLOW`, created `0600`, and draws the same loose-permission warning as a vault file. When an append would take it past 1 MiB, it is renamed to `audit.log.1`, replacing any older one, and a new log is started.
- Titles are in plaintext: the vault file encrypts them, the log doesn't. A copy of a vault home (e.g. synced to the cloud) reveals the titles of secrets that were saved, removed or revealed, and when. This is accepted; `export-cypher` copies only `secrets.vault`.
- The owner reads the log with `log [--limit 20]` in the vault shell, newest first. Titles are escaped like all stored text, and a line that doesn't parse shows as `<unreadable event>`.
