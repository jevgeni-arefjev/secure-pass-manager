# Web front end decrypts on the server

`vault-web` unlocks a vault on the server: the browser sends the vaultname and master password over TLS, the server derives the KEK, unwraps the vault key and holds the vault key and decrypted secrets in memory for the session, and the browser only ever receives non-hidden fields and one revealed hidden field per request. Well-known password managers (Bitwarden, 1Password) decrypt in the client instead, so the server never sees plaintext. That protects against an untrusted or compromised server, which is not a threat here: the web front end is a local demo, so the server runs on the user's own machine, while the browser is the semi-trusted side (extensions, other tabs). Server-side decryption keeps all crypto and memory handling in Rust (locked, zeroized pages; ICS0022), keeps plaintext out of the browser heap, and lets the server enforce auto-lock and audit events.

## Considered options

- **Full client-side decryption** (`vault-core::crypto` compiled to WASM). Rejected: the server would have to authenticate before releasing the vault file, or anyone knowing a vaultname could download its header and brute-force it offline, so it needs a stored verifier (e.g. an auth key split from the Argon2 output), which reopens ADR-0002 and changes the header format. Browsers can't lock memory or wipe the master password typed into an input, the whole decrypted vault would sit in the browser heap, and reveal audit events and auto-lock would be reported by an untrusted client instead of enforced.
- **Client-side KDF, server-side decryption** (the browser runs Argon2id and sends the KEK instead of the master password). Not taken now, possible later: the raw master password would never leave the browser and the server would stop running 256 MiB KDFs, but it needs a WASM build and an unauthenticated "prelogin" step that hands out salts (with fake salts for unknown vaultnames), the KEK becomes a password-equivalent, and the master password is still an unwipeable JS string.

## Consequences

- The server sees the master password on every unlock and holds plaintext secrets for the life of each session; a compromise of the running server process exposes every unlocked vault.
- Every unlock costs a 256 MiB Argon2id run on the server, so concurrent unlocks are capped to stop memory exhaustion.
