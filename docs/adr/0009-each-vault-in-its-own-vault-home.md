# Each vault lives in its own vault home

Amends ADR-0001 and ADR-0004. Each vault gets its own directory inside the vault directory, named after its vaultname: its vault home. The vault home holds the vault file `secrets.vault` and its audit log `audit.log` (ADR-0010), instead of a `<vaultname>.vault` file at the top of the vault directory. The audit log needs a place next to its vault, kept apart from other vaults' logs so one owner never sees another's activity (ADR-0001). A vault home groups a vault's files so they are renamed, copied and permissioned together. The file names inside are fixed, so the directory name stays the only place the vaultname lives: renaming the vault home renames the vault, as ADR-0004 had it for the file.

## Considered Options

- **Log file next to the vault file (`<vaultname>.log` beside `<vaultname>.vault`)**: no layout change, but a rename has to touch two files, and nothing ties the pair together.
- **Files inside the vault home named after the vaultname (`alice/alice.vault`)**: stores the vaultname three times; a rename has to change all three, and they can disagree.
- **One shared log for the whole vault directory**: every owner could read every other vault's activity.

## Consequences

- `init` creates the vault home (mode `0700`), or reuses an existing one, builds the vault in a temp file inside it and hard-links it to `secrets.vault`, as before (ADR-0006, ADR-0011). The hard link is what claims the vaultname: it fails if `secrets.vault` already exists.
- A vault home without `secrets.vault`, left by an interrupted `init`, is not a vault: unlock fails exactly as for an unknown vaultname, and a later `init` with that vaultname takes it over. Two concurrent `init`s stay safe, because the hard link refuses an existing target.
- A vault home that is a symlink is refused; loose permissions on it draw the same warning as on the vault directory.
- The vaultname allowlist (ADR-0001) still guards the path; the vaultname is now a directory name instead of a file name.
- Saves also keep an empty lock file `secrets.lock` in the vault home (ADR-0011). It holds nothing and may be deleted while no session is saving.
- Restoring a backup by hand means creating a vault home and putting the backup in it as `secrets.vault`.
- Vaults in the old flat layout (`<vaultname>.vault` at the top of the vault directory) are ignored. There is no migration.
