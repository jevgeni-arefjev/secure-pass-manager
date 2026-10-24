# Secure App

This repo is a project for TalTech courses ICS0022 Secure Programming and ICS0027 Web Application Security.

It is a password manager with one shared Rust core and two front ends:

- **CLI** (ICS0022): a downloadable, local, multi-user-on-one-device app. Spec: [`secure-password-manager.md`](secure-password-manager.md)
- **Web** (ICS0027): a server that keeps all data remotely and serves a browser UI over TLS. Currently planned as a local demo only. Spec: [`web-app-security.md`](web-app-security.md)

> **Status:** MVP. The encryption (`vault-core::crypto`), storage (`vault-core::storage`), session (`vault-core::session`) and password generator (`vault-core::generator`) modules and the CLI (`vault-cli`) are implemented and tested; audit and backup are still stubs, and the web front end is not started.

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
│   ├── tests/render.rs     # terminal output (get view, list table, escaping), through its public API
│   ├── tests/shell.rs      # the CLI and vault shell end to end, on a scripted fake terminal
│   └── src/
│       ├── main.rs         # hardens the process, logs warnings to stderr, runs the CLI on the real terminal
│       ├── lib.rs
│       ├── args.rs         # command grammar (clap): `vault` arguments and vault shell commands
│       ├── shell.rs        # init/unlock (3 tries), the vault shell loop, auto-lock watcher, termination signals
│       ├── commands.rs     # get, save, list, rm, gen, passwd, lock; prompts first, then the session
│       ├── clipboard.rs    # `--copy`: excluded from clipboard history, cleared after 20 s, on lock and exit
│       ├── terminal.rs     # Terminal trait (fakeable in tests) and the real stdin/stdout one; in-memory history only
│       ├── terminal/       # masked prompt: one `*` per character, zeroizing buffer (ADR-0008)
│       └── render.rs       # get view and list table; escapes control and bidi characters; hidden fields shown as `*`
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
./target/release/vault init alice   # create a vault and open the vault shell on it
./target/release/vault unlock alice # later: unlock it again
cargo run -p vault-cli -- <command> # or build and run in one step, e.g. `cargo run -p vault-cli -- gen`
```

A session looks like this (`*` is echoed as you type the master password; hidden fields are masked):

```
$ vault unlock alice
Master password: *********************
vault 'alice' unlocked; it locks after 5 idle minute(s). Type `help` for commands.
vault> save github
Username (optional): alice
Password (empty to generate):
URL (optional): https://github.com
Notes (optional):
Tags (comma-separated, optional): work
Add a custom field? [y/N]
generated a 24-character password; `get <title> --copy` copies it
secret added
vault> get github --copy
password copied; the clipboard clears in 20 seconds
vault> lock
vault locked
```

All commands are listed in [`secure-password-manager.md` §5](secure-password-manager.md#5-commands). Notes:

- Vaults live in the platform data directory (`~/.local/share/secure-pass-manager/vaults` on Linux); `--vault-dir <path>` uses another one.
- The master password and hidden fields (e.g. stored passwords) are entered only through hidden prompts, never as arguments, and only from a terminal: piping them in is refused.
- The keys live only in the `vault>` process. It locks after 5 idle minutes (`--idle-timeout 1-60`), and ends when locked.
- `--copy` needs a display (X11 or Wayland on Linux); over plain SSH it reports that the clipboard is not available.
- If the process is killed by a signal while waiting at the `vault>` prompt, the vault is wiped, but the terminal can be left in raw mode; type `reset` to fix it.

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
