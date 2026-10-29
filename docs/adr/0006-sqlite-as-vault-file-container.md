# SQLite as the vault file container

**Superseded by [ADR-0011](0011-flat-file-as-vault-file-container.md): the vault file is now a flat `header ‖ body` file.**

Each vault file is a SQLite database holding one row: the encoded header, the encrypted body, and the revision. A flat `header ‖ body` file written with temp file, fsync and rename would fit the format more naturally, since storage only ever handles two blobs: it needs no C code, its only parser is the strict `Header::decode`, and it leaves no stale pages behind. SQLite is kept because the ICS0027 requirements explicitly ask for prepared, parameterized statements against SQL injection, and arguing "there is no SQL" would be a third deviation for the instructor to approve. It also gives atomic, crash-safe saves and cross-process locking without hand-written file juggling. Storage sits behind the `VaultStore` trait, so a flat-file backend can replace it without touching the other modules.

## Considered Options

- **Flat binary file, temp file + fsync + atomic rename**: smallest attack surface and pure Rust, but atomic writes and locking are ours to get right, and there is no SQL to show for the course requirement.
- **Embedded pure-Rust key-value store (`redb`, `sled`)**: ACID without C, but the same "database around one row" overhead as SQLite without satisfying the SQL requirement.
- **Server database (Postgres)**: conflicts with one file per vault (ADR-0001) and with the CLI being fully local.

## Consequences

- SQLite parses vault files, which may come from untrusted places (e.g. a restored backup). Every connection enables `SQLITE_DBCONFIG_DEFENSIVE`, sets `trusted_schema=OFF`, and checks `application_id` and `user_version` before any table is read.
- Freed pages would keep old ciphertext, including a header wrapped under a rotated master password, so every connection sets `secure_delete=ON`. Blocks of the deleted rollback journal may still linger on disk; this is accepted.
- `journal_mode=DELETE` keeps a vault to a single file; `synchronous=FULL` makes a committed save survive a crash. No previous version is kept: it would be wrapped under the old master password after a password change.
- Two sessions on the same vault can't overwrite each other: a save only succeeds if the stored revision is the one the new revision follows, otherwise it fails with a conflict.
- `rusqlite` builds SQLite from source (`bundled`), so a clean-machine build needs a C compiler.
