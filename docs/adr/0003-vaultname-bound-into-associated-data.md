# Vaultname is bound into the associated data

The vaultname is part of the vault header and is authenticated as associated data in both AEAD operations: the vault key wrap (format version, KDF id, KDF params, salt, vaultname) and the body (the whole encoded header). A vault file copied or renamed under another vaultname therefore fails to unlock. This matters most for the web server, where the vaultname comes from untrusted input and two users' files could otherwise be swapped on disk without detection.

## Consequences

- A vault cannot be renamed by renaming its file. Renaming goes only through a dedicated function that unlocks the vault, writes the new vaultname into the header, re-wraps the vault key and re-encrypts the body under the new header. No other code path may change the vaultname in the header.
- The vaultname is normalised (same allowlist as ADR-0001) before it is used as associated data, so the same name always produces the same bytes.
