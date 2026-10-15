# One vault file per user, named by its vaultname

Each user's vault is its own SQLite file, named after its plain vaultname, instead of one shared database with per-record ownership checks. A session only ever opens the vault it unlocked, so another user's secrets are unreachable by construction, and their file wouldn't decrypt anyway. This deliberately differs from the course requirement to "enforce per-user ownership on every record operation", which implies a shared store; the instructor still has to confirm it.

## Considered Options

- **Shared database, ownership check on every query**: what the requirements imply. Rejected because every handler becomes a place to forget the check, and the per-user row layout already made per-record checks meaningless (all secrets are in one encrypted body).
- **File named by a hash of the vaultname**: hides which vaultnames exist from other local users. Rejected because a forgotten vaultname would make the vault practically unrecoverable, and the contents are protected by the encryption regardless.

## Consequences

- Vaultnames become file names, so they must be allowlisted (charset, length) and the path confined to the vault directory.
- Anyone on the device can list which vaultnames exist; this is accepted.
