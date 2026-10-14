# Secure App

This repo is a project for TalTech courses ICS0022 Secure Programming and ICS0027 Web Application Security.

It is a password manager with one shared Rust core and two front ends:

- **CLI** (ICS0022): a downloadable, local, multi-user-on-one-device app. Spec: [`secure-password-manager.md`](secure-password-manager.md)
- **Web** (ICS0027): a server that keeps all data remotely and serves a browser UI over TLS. Currently planned as a local demo only. Spec: [`web-app-security.md`](web-app-security.md)

> **Status:** scaffolding only. The crates are empty stubs; nothing is implemented yet.

## Project layout

```
.
├── Cargo.toml              # workspace root
├── vault-core/             # shared library, no I/O front end
│   └── src/
│       ├── lib.rs
│       ├── crypto.rs       # Encryption: password KDF, key wrap, body AEAD, zeroizing secrets (algorithms TBD)
│       ├── storage.rs      # Storage: SQL schema, parameterized queries, header + ciphertext rows
│       ├── audit.rs        # Audit log: structured events, never secrets
│       ├── backup.rs       # Backup: ciphertext-only export
│       └── user.rs         # User management: master password, unlock/lock, session (single user in MVP)
├── vault-cli/              # `vault` binary: command parsing, terminal prompts, one-entry reveal
│   └── src/main.rs
│
│   # planned, not created yet
├── vault-web/              # HTTP server: TLS, sessions, CSRF, authz; serves the client bundle
└── web/                    # TypeScript browser client, built into vault-web/assets
```

How the modules map to the specs:

| Module | Crate | Course |
| --- | --- | --- |
| Encryption | `vault-core::crypto` | ICS0022 (reused by ICS0027) |
| Storage | `vault-core::storage` | ICS0022 (reused by ICS0027) |
| Audit log | `vault-core::audit` | ICS0022 (reused by ICS0027) |
| Backup | `vault-core::backup` | ICS0022 |
| User management | `vault-core::user` (single user in MVP) | both |
| CLI | `vault-cli` | ICS0022 |
| Web server + client | `vault-web`, `web/` *(planned)* | ICS0027 |

## Build and run

### Prerequisites

Rust 1.85 or newer (edition 2024). On a clean machine, install it with [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### CLI

```bash
cargo build --release               # builds the whole workspace into target/release/
cargo run -p vault-cli -- <command> # run the `vault` binary, e.g. `cargo run -p vault-cli -- list`
./target/release/vault <command>    # or run the built binary directly
```

Planned commands are listed in [`secure-password-manager.md` §5](secure-password-manager.md#5-planned-commands).

### Tests and checks

```bash
cargo test                          # all workspace tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

### Web

Not implemented yet. Planned steps are in [`web-app-security.md` §6](web-app-security.md#6-build-and-run).
