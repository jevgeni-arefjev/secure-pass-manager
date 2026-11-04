# Secure App

This repo is a project for TalTech courses ICS0022 Secure Programming and ICS0027 Web Application Security.

It is a password manager with one shared Rust core and two front ends:

- **CLI** (ICS0022): a downloadable, local, multi-user-on-one-device app. Spec: [`secure-password-manager.md`](secure-password-manager.md)
- **Web** (ICS0027): a server that keeps all data remotely and serves a browser UI over TLS. Currently planned as a local demo only. Spec: [`web-app-security.md`](web-app-security.md)

> **Status:** MVP. The encryption (`vault-core::crypto`), storage (`vault-core::storage`), session (`vault-core::session`), audit log (`vault-core::audit`), backup (`vault-core::backup`) and password generator (`vault-core::generator`) modules and the CLI (`vault-cli`) are implemented and tested. The web front end (`vault-web`, `web/`) serves the client over HTTPS with the security headers and lets a browser create, unlock and lock a vault (server-side sessions, cookie, CSRF token, Origin check); the secret pages come next.

## Project layout

```
.
├── Cargo.toml              # workspace root
├── Cargo.lock              # pinned dependency versions
├── CONTEXT.md              # domain glossary: vault, vaultname, secret, hidden field, unlock/lock
├── .github/workflows/      # CI: clippy, tests, client check/test/build and release build on macOS
├── docs/agents/            # notes for coding agents: issue tracker, triage labels, domain docs
├── docs/adr/               # architecture decision records
├── vault-core/             # shared library, no I/O front end
│   ├── tests/crypto.rs     # encryption module behaviour, through its public API
│   ├── tests/storage.rs    # storage module behaviour, through its public API
│   ├── tests/session.rs    # session module behaviour, through its public API
│   ├── tests/audit.rs      # file audit sink behaviour, through the AuditSink trait
│   ├── tests/backup.rs     # backup destinations and Session::backup, through the public API
│   ├── tests/generator.rs  # password generator behaviour, through its public API
│   ├── tests/memory.rs     # page locking of every secret type, the zeroize-only fallback and its warning, core dumps off
│   └── src/
│       ├── lib.rs
│       ├── crypto.rs       # Encryption: password KDF, key wrap, body AEAD, zeroizing secrets (Argon2id, XChaCha20-Poly1305, HKDF-SHA-256)
│       ├── crypto/         # header encoding, KDF params, locked + zeroized secret memory
│       ├── generator.rs    # Password generator: uniform visible-ASCII passwords from the OS CSPRNG
│       ├── storage.rs      # Storage: one vault home per vaultname holding `secrets.vault`, a flat file (header ‖ encrypted body); atomic, locked, revision-checked saves (ADR-0009, ADR-0011)
│       ├── storage/        # vaultname validation
│       ├── audit.rs        # Audit log: typed events as JSON Lines in `audit.log` per vault home, at most a title, rotated at 1 MiB, fail-open (ADR-0010)
│       ├── backup.rs       # Backup: ciphertext-only copy of a vault file to a new file outside the vault directory, verified, never overwriting
│       ├── session.rs      # Session: create/unlock/lock, auto-lock, uniform unlock failures, saves every change at once, records audit events (single user in MVP)
│       └── session/        # secret model + field validation, JSON body, master password policy, clock
├── vault-cli/              # `vault` binary: command parsing, terminal prompts, one-secret reveal
│   ├── tests/args.rs       # command grammar and help text, through its public API
│   ├── tests/render.rs     # terminal output (get view, list table, log view, escaping), through its public API
│   ├── tests/shell.rs      # the CLI and vault shell end to end, on a scripted fake terminal
│   └── src/
│       ├── main.rs         # hardens the process, logs warnings to stderr, runs the CLI on the real terminal
│       ├── lib.rs
│       ├── args.rs         # command grammar (clap): `vault` arguments and vault shell commands
│       ├── shell.rs        # init/unlock (3 tries), the vault shell loop, auto-lock watcher, termination signals
│       ├── commands.rs     # get, save, list, rm, gen, passwd, backup, log, lock; prompts first, then the session
│       ├── clipboard.rs    # `--copy`: excluded from clipboard history, cleared after 20 s, on lock and exit
│       ├── terminal.rs     # Terminal trait (fakeable in tests) and the real stdin/stdout one; in-memory history only
│       ├── terminal/       # masked prompt: one `*` per character, zeroizing buffer (ADR-0008)
│       └── render.rs       # get view, list table and log view; escapes control and bidi characters; hidden fields shown as `*`
├── vault-web/              # `vault-web` binary: HTTPS server for the browser client
│   ├── build.rs            # embeds assets/ into the binary at compile time; never runs npm
│   ├── assets/             # client bundle from `npm run build` in web/ (not committed)
│   ├── tests/common/       # shared test helpers: test app on a temp vault directory with a manual clock, request builders, log capture
│   ├── tests/app.rs        # the HTTP app in-process (tower `oneshot`): security headers, Host check, request logs, "client not built" page
│   ├── tests/unlock.rs     # create, unlock, lock: cookie, CSRF, Origin, generic unlock failure, KDF limiter (503), strict parsing, log contents
│   ├── tests/tls.rs        # certificate loading, self-signed generation, 0600 cache and reuse
│   ├── tests/args.rs       # server flags, through the public `args` API
│   └── src/
│       ├── main.rs         # hardens the process (refuses to start otherwise), logs to stderr, serves HTTPS
│       ├── lib.rs          # `app(config)`: the whole HTTP app, without TLS
│       ├── config.rs       # app config (the test seam): vault directory, clock, KDF limits, session lifetime, port, vault format, assets
│       ├── args.rs         # flags: --bind, --vault-dir, --tls-cert/--tls-key
│       ├── tls.rs          # rustls (ring) config from given PEM files or a cached self-signed localhost certificate (rcgen)
│       ├── middleware.rs   # request log (method, route template, status, latency, session hash), Host and Origin checks, security headers and CSP
│       ├── api.rs          # `/api` routes and JSON errors (`{"error"}`, optional `"field"`)
│       ├── api/vault.rs    # POST /api/vaults (create), /api/unlock, /api/lock; GET /api/session
│       ├── auth.rs         # `__Host-session` cookie; extractor resolving the session and checking the CSRF token
│       ├── sessions.rs     # session registry: SHA-256(session ID) → vault session, CSRF token, creation time, idle timeout
│       ├── kdf_limiter.rs  # unlock/create on the blocking pool, 2 at once plus a short queue, else 503
│       ├── json.rs         # strict JSON bodies (64 KiB cap, objects only); master password straight into `MasterPassword`
│       └── assets.rs       # embedded client bundle; "client not built" page
└── web/                    # vanilla TypeScript browser client, bundled by esbuild into vault-web/assets
    ├── package.json        # scripts: build, check, test; pinned dev tools in package-lock.json
    ├── tsconfig.json       # strict type-checking of src/; tsconfig.test.json adds test/ and emits to .test-build/
    ├── scripts/build.mjs   # `npm run build`: esbuild bundle + static files into vault-web/assets
    ├── static/             # index.html and app.css (no inline scripts or styles)
    ├── src/                # main.ts (create/unlock/vault pages; DOM via createElement/textContent only), api.ts (CSRF header, 401 = locked), forms.ts, url.ts (http/https link allowlist)
    └── test/               # node:test tests of the pure helpers
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
| Web server + client | `vault-web`, `web/` *(create, unlock, lock)* | ICS0027 |

## Build and run

### Prerequisites

Linux or macOS. Windows is not supported, and no Windows support is planned.

On macOS, install the Xcode Command Line Tools first (they provide the linker): `xcode-select --install`.

Rust 1.89 or newer (edition 2024). On a clean machine, install it with [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

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
vault> log --limit 3
2026-10-27 10:47:12  secret revealed 'github'
2026-10-27 10:47:05  secret added 'github'
2026-10-27 10:46:51  unlocked
vault> lock
vault locked
```

All commands are listed in [`secure-password-manager.md` §5](secure-password-manager.md#5-commands). Notes:

- Vaults live in the platform data directory (`~/.local/share/secure-pass-manager/vaults` on Linux, `~/Library/Application Support/secure-pass-manager/vaults` on macOS), each in its own vault home: `vaults/<vaultname>/secrets.vault`, next to an empty lock file `secrets.lock` used while saving and its audit log `audit.log` (and `audit.log.1` once it has passed 1 MiB). `--vault-dir <path>` uses another vault directory.
- The master password and hidden fields (e.g. stored passwords) are entered only through hidden prompts, never as arguments, and only from a terminal: piping them in is refused.
- The keys live only in the `vault>` process. It locks after 5 idle minutes (`--idle-timeout 1-60`), and ends when locked.
- `log [--limit 20]` shows the vault's audit log, newest first, in local time: unlocks, failed unlocks, locks, saved, removed and revealed secrets, master password changes, backups. It holds titles in plaintext but never a field value.
- `backup <path>` writes an encrypted copy of the vault file to a new file outside the vault directory, e.g. `backup /media/usb/alice.vault`; it never overwrites. To restore, create a vault home and put the backup in it: `mkdir -m 700 ~/.local/share/secure-pass-manager/vaults/alice && cp /media/usb/alice.vault ~/.local/share/secure-pass-manager/vaults/alice/secrets.vault`, then `vault unlock alice`. Any vaultname works. On macOS, use the macOS vault directory above, in quotes because of the space.
- `--copy` needs a display (X11 or Wayland on Linux, a logged-in desktop session on macOS); over plain SSH it reports that the clipboard is not available.
- If the process is killed by a signal while waiting at the `vault>` prompt, the vault is wiped, but the terminal can be left in raw mode; type `reset` to fix it.

### Tests and checks

```bash
cargo test                          # all workspace tests
cargo test -- --ignored             # slow tests: the production KDF (256 MiB Argon2id)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Client checks, from `web/` (need Node 22+):

```bash
npm ci                              # install the pinned dev tools (esbuild, TypeScript)
npm run check                       # tsc --noEmit over src/ and test/
npm test                            # node:test tests of the pure helpers
```

CI (`.github/workflows/ci.yml`) runs clippy, both test commands, the client checks and build, and a release build on macOS for every push to `main` and every pull request. The Rust steps never need Node. `tests/memory.rs` runs on Linux only.

Tests create vaults in a cheap test format (feature `insecure-test-kdf`, ADR-0005), which only test builds enable. Run tests in debug: `cargo test --release` is refused on purpose, so the test format can never end up in a release binary.

### Web

The server embeds the client bundle at compile time, so build the client first (Node 22+), then the server:

```bash
cd web && npm ci && npm run build && cd ..   # bundle into vault-web/assets/
cargo run -p vault-web                       # prints `vault-web: serving https://localhost:8443`
```

Open the printed URL. Without Node, `cargo run -p vault-web` still builds and runs, and serves a "client not built" page; after `npm run build`, rebuild the server to embed the bundle.

- Flags: `--bind <addr:port>` (default `127.0.0.1:8443`, localhost only), `--vault-dir <path>` (default `web-vaults` in the platform data directory, apart from the CLI's `vaults`), `--tls-cert <pem>` and `--tls-key <pem>` (both or neither).
- Without certificate flags, a self-signed certificate for `localhost` and `127.0.0.1` is generated on first start and cached (`0600`) in `web-tls/` in the platform data directory; the browser warns about it once. To avoid the warning, use [`mkcert`](https://github.com/FiloSottile/mkcert):

  ```bash
  mkcert -install                              # once: trust mkcert's local CA
  mkcert -cert-file localhost.pem -key-file localhost-key.pem localhost 127.0.0.1
  cargo run -p vault-web -- --tls-cert localhost.pem --tls-key localhost-key.pem
  ```

- Only requests addressed to `localhost:<port>` or `127.0.0.1:<port>` are served (DNS rebinding defence); every response carries a strict CSP with Trusted Types, short HSTS (`max-age=300`) and `Cache-Control: no-store`.
- The server refuses to start if it can't disable core dumps. Request logs (stderr) hold the method, route template, status, latency and a short hash of the session ID only.
