# Vaultname is only the file name, not part of the crypto

**Amended by [ADR-0009](0009-each-vault-in-its-own-vault-home.md): the vaultname is now only the name of the vault home, so renaming the vault home renames the vault.**

Supersedes ADR-0003. The vaultname is no longer stored in the vault header or bound into the associated data; it is only the name of the vault file (ADR-0001). The header keeps a fixed layout and stays fully authenticated: the key wrap covers the format fields, KDF params and salt, and the body covers the whole header.

Binding the vaultname only caught one case: two vaults sharing the same master password swapped on disk. Swapping vaults with different passwords already fails at unlock, and nothing can be read either way. Pulling off a swap needs write access to the vault directory, and an attacker who controls the server can capture master passwords at unlock anyway. Rolling a vault back to an older copy of itself was never caught by the binding. That small gain didn't justify a variable-length header, a rename that had to re-encrypt the vault, and backups that couldn't be restored under another file name by hand.

## Consequences

- Renaming the vault file renames the vault; a backup can be restored under any vaultname.
- Two vaults with the same master password can be swapped on disk without detection. This is accepted.
- The vaultname allowlist (ADR-0001) is enforced where vaultnames become file paths (storage/session), not in crypto.
