# Secure App

This repo is a project for TalTech courses ICS0022 Secure Programming and ICS0027 Web Application Security.

It is a password manager with one shared Rust core and two front ends:

- **CLI** (ICS0022): a downloadable, local, multi-user-on-one-device app. Spec: [`secure-password-manager.md`](secure-password-manager.md)
- **Web** (ICS0027): a server that keeps all data remotely and serves a browser UI over TLS. Currently planned as a local demo only. Spec: [`web-app-security.md`](web-app-security.md)

> **Status:** early MVP. The encryption (`vault-core::crypto`), storage (`vault-core::storage`) session (`vault-core::session`) and password generator (`vault-core::generator`) modules are implemented and tested; audit, backup and the CLI are still stubs.

## Project layout

```
.
├── Cargo.toml              # workspace root
├── Cargo.lock              # pinned dependency versions
├── CONTEXT.md              # domain glossary: vault, vaultname, secret, hidden field, unlock/lock
├── docs/agents/            # notes for coding agents: issue tracker, triage labels, domain docs
├── docs/adr/               # architecture decision records
├── vault-core/             # shared library, no I/O front end
│   ├── tests/crypto.rs     # encryption module behaviour, through its public API
│   ├── tests/storage.rs    # storage module behaviour, through its public API
│   ├── tests/session.rs    # session module behaviour, through its public API
│   ├── tests/generator.rs  # password generator behaviour, through its public API
│   └── src/
│       ├── lib.rs
│       ├── crypto.rs       # Encryption: password KDF, key wrap, body AEAD, zeroizing secrets (Argon2id, XChaCha20-Poly1305, HKDF-SHA-256)
│       ├── crypto/         # header encoding, KDF params, locked + zeroized secret memory
│       ├── generator.rs    # Password generator: uniform visible-ASCII passwords from the OS CSPRNG
│       ├── storage.rs      # Storage: one SQLite file per vault (header + encrypted body), hardened open, revision-checked saves (ADR-0006)
│       ├── storage/        # vaultname validation
│       ├── audit.rs        # Audit log: structured events, never secrets
│       ├── backup.rs       # Backup: ciphertext-only export of a user's vault
│       ├── session.rs      # Session: create/unlock/lock, auto-lock, uniform unlock failures, saves every change at once (single user in MVP)
│       └── session/        # secret model + field validation, JSON body, master password policy, clock
├── vault-cli/              # `vault` binary: command parsing, terminal prompts, one-secret reveal
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
| Session | `vault-core::session` (single user in MVP) | both |
| Password generator | `vault-core::generator` | both |
| CLI | `vault-cli` | ICS0022 |
| Web server + client | `vault-web`, `web/` *(planned)* | ICS0027 |

## Build and run

### Prerequisites

Rust 1.85 or newer (edition 2024). On a clean machine, install it with [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

A C compiler is also needed: SQLite is compiled from source (`rusqlite`'s `bundled` feature), so no system SQLite library is required. On Fedora `sudo dnf install gcc`, on Debian/Ubuntu `sudo apt install build-essential`, on macOS `xcode-select --install`.

### CLI

```bash
cargo build --release               # builds the whole workspace into target/release/
cargo run -p vault-cli -- <command> # run the `vault` binary, e.g. `cargo run -p vault-cli -- list`
./target/release/vault <command>    # or run the built binary directly
```

Planned commands are listed in [`secure-password-manager.md` §5](secure-password-manager.md#5-planned-commands). `vault unlock` will ask for a vaultname and master password and open an interactive `vault>` session; the vault keys live only in that process. The master password and hidden fields (e.g. stored passwords) are entered only through hidden prompts, never as arguments.

### Tests and checks

```bash
cargo test                          # all workspace tests
cargo test -- --ignored             # slow tests: the production KDF (256 MiB Argon2id)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Tests create vaults in a cheap test format (feature `insecure-test-kdf`, ADR-0005), which only test builds enable. Run tests in debug: `cargo test --release` is refused on purpose, so the test format can never end up in a release binary.

### Web

Not implemented yet. Planned steps are in [`web-app-security.md` §6](web-app-security.md#6-build-and-run).
