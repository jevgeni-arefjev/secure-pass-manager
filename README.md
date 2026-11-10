# Secure App

This repo is a project for TalTech courses ICS0022 Secure Programming and ICS0027 Web Application Security.

It is a password manager with one shared Rust core and two front ends:

- **CLI** (ICS0022): a downloadable, local, multi-user-on-one-device app. Spec: [`secure-password-manager.md`](secure-password-manager.md)
- **Web** (ICS0027): a server that keeps all data remotely and serves a browser UI over TLS. Currently planned as a local demo only. Spec: [`web-app-security.md`](web-app-security.md)

> **Status:** MVP. The encryption (`vault-core::crypto`), storage (`vault-core::storage`), session (`vault-core::session`), audit log (`vault-core::audit`), backup (`vault-core::backup`) and password generator (`vault-core::generator`) modules and the CLI (`vault-cli`) are implemented and tested. The web front end (`vault-web`, `web/`) serves the client over HTTPS with the security headers and lets a browser create, unlock and lock a vault (server-side sessions, cookie, CSRF token, Origin check), list and search its secrets, view one with hidden fields masked, reveal or copy one hidden field at a time (audited; masked again after 30 s, clipboard cleared after 20 s), and add, edit and delete secrets (an empty password is generated on the server; an edit keeps untouched hidden fields without the browser ever holding them; a refused save shows every invalid field at once). A settings page changes the master password (checked as it is typed; three wrong current master passwords in a row lock the session; a change locks the vault's other web sessions and reissues this one) and downloads a backup (the encrypted vault file as stored, `<vaultname>-r<revision>.vault`), and an audit log page shows the vault's audit events, newest first. Sessions end server-side: a sweeper locks idle sessions and every session 8 h after unlock, SIGINT/SIGTERM lock every session before exit, a panicking request gets a generic 500 and its session is locked, and an open tab returns to the unlock page once its session has ended. Internal failures keep their cause kind (ADR-0014): the CLI shows it in words (`vault: vault storage failed (permission denied)`), and a kind it has no words for by name on the next line (``vault: the exact cause was `NotADirectory` ``), and every web 500 except a panic (which has its own `panic` events) logs one `internal_error` line with what failed and its `io::ErrorKind`, never a path, vaultname or title. The CLI prints its diagnostics as plain sentences (``vault: warning: the vault file of vault 'alice' is readable or writable by other users; run `chmod go-rw` on it``), and a panic only as `vault: internal error at <file>:<line>`, after which the vault shell wipes the session and clears the clipboard.

## Roadmap

Course deliverables:

- [x] MVP with vault at rest, encryption module, storage module & CLI module.
- [x] Build and run instructions that work on a clean machine.
- [x] Basic working web interface with the core flows.
- [x] Basic secure authentication (Argon2id-based unlock, no stored hash; see ADR-0002) and secure session management.
- [x] Application served over TLS in the development setup.
- [x] Full input validation and sanitization on all fields.
- [x] Structured logging of key events and secure error handling.
- [x] Per-user access control: a session can only open the vault it unlocked (ADR-0001).
- [x] Test cases written and passing, including input-validation edge cases and memory handling checks.
- [ ] User manual for the CLI and the web app.
- [ ] Reports: encryption methods, memory management, authentication and security features, how SQL injection, XSS and CSRF are prevented, and test results.

## Project layout

```
.
├── Cargo.toml              # workspace root
├── Cargo.lock              # pinned dependency versions
├── CONTEXT.md              # domain glossary: vault, vaultname, secret, hidden field, unlock/lock
├── CODING_STANDARDS.md     # judgement-call rules for writing and reviewing code (docstrings, where rules live, tests)
├── .github/workflows/      # CI: the same checks on macOS, Ubuntu and Fedora (container)
├── .github/actions/checks/ # those checks: fmt, clippy (docstrings required), tests, client lint/check/test/build, release build
├── docs/agents/            # notes for coding agents: issue tracker, triage labels, domain docs
├── docs/adr/               # architecture decision records
├── fixtures/               # unsafe-characters.json: unsafe characters and safe look-alikes, shared by the core, CLI and web client tests; audit-events.json: how each audit event kind is shown, shared by the CLI and web client tests
├── vault-core/             # shared library, no I/O front end
│   ├── tests/crypto.rs     # encryption module behaviour, through its public API
│   ├── tests/storage.rs    # storage module behaviour, through its public API: one size limit for load and save, a lock held too long
│   ├── tests/session.rs    # session module behaviour, through its public API, including the cause and kind of internal failures
│   ├── tests/text_rules.rs # field text rules through Session: unsafe characters (shared fixture), limits in characters, trimming and NFC, title matching, URL forms, stored secrets breaking the rules
│   ├── tests/field_checks.rs # per-field checks (`session::check`): each field on its own, normalised as a save would
│   ├── tests/audit.rs      # file audit sink behaviour, through the AuditSink trait
│   ├── tests/backup.rs     # backup destinations, Session::backup and Session::backup_file, through the public API
│   ├── tests/generator.rs  # password generator behaviour, through its public API
│   ├── tests/memory.rs     # page locking of every secret type, the zeroize-only fallback and its warning, core dumps off (`RLIMIT_CORE` 0, non-dumpable)
│   └── src/
│       ├── lib.rs
│       ├── crypto.rs       # Encryption: password KDF, key wrap, body AEAD, zeroizing secrets (Argon2id, XChaCha20-Poly1305, HKDF-SHA-256)
│       ├── crypto/         # header encoding, KDF params, locked + zeroized secret memory
│       ├── generator.rs    # Password generator: uniform visible-ASCII passwords from the OS CSPRNG
│       ├── storage.rs      # Storage: one vault home per vaultname holding `secrets.vault`, a flat file (header ‖ encrypted body); atomic, locked, revision-checked saves (ADR-0009, ADR-0011)
│       ├── storage/        # vaultname validation
│       ├── audit.rs        # Audit log: typed events as JSON Lines in `audit.log` per vault home, at most a title, rotated at 1 MiB, fail-open (ADR-0010)
│       ├── backup.rs       # Backup: ciphertext-only copy of a vault file to a new file outside the vault directory, verified, never overwriting; or handed out whole (BackupFile) for a download
│       ├── session.rs      # Session: create/unlock/lock, auto-lock, uniform unlock failures, saves every change at once, records audit events (single user in MVP)
│       └── session/        # secret model + field validation (per-field checks in `check`, used by saves and by the vault shell as each answer is typed; every problem of a save reported at once; text rules: unsafe characters, trimming, NFC, URL forms), JSON body, master password policy, clock
├── vault-cli/              # `vault` binary: command parsing, terminal prompts, one-secret reveal
│   ├── tests/args.rs       # command grammar and help text, through its public API
│   ├── tests/render.rs     # terminal output (get view, list table, log view, escaping against the shared fixture, cause kinds in words), through its public API
│   ├── tests/common/       # shared test helpers: scripted fake terminal (hidden and visible input kept apart), manual (optionally panicking) clock, temp vault directory running `shell::run`
│   ├── tests/shell.rs      # the CLI and vault shell end to end, on a scripted fake terminal, including a panic in the vault shell or the auto-lock watcher (session wiped, clipboard cleared, no audit event)
│   ├── tests/no_secret_leaks.rs # one scripted init and unlock session (wrong, weak, mismatched and changed master passwords, refused and saved hidden fields, `get --show` into a pipe, backup, log): no master password or hidden field value in stdout, stderr, diagnostics captured at every level, or the audit logs
│   ├── tests/diagnostics.rs # each diagnostic code as its sentence, the real binary's stderr for a loose vault file and an unworded cause kind, a panic printed without its message
│   └── src/
│       ├── main.rs         # replaces the panic hook, hardens the process, prints diagnostics to stderr, runs the CLI on the real terminal
│       ├── lib.rs
│       ├── args.rs         # command grammar (clap): `vault` arguments and vault shell commands
│       ├── shell.rs        # init/unlock (3 tries), the vault shell loop, auto-lock watcher, termination signals, panics caught (session wiped)
│       ├── diagnostics.rs  # `tracing` diagnostics as plain sentences on stderr (ADR-0014); panic hook printing only the location
│       ├── commands.rs     # get, save, list, rm, gen, passwd, backup, log, lock; prompts first, then the session
│       ├── clipboard.rs    # `--copy`: excluded from clipboard history, cleared after 20 s, on lock and exit
│       ├── terminal.rs     # Terminal trait (fakeable in tests) and the real stdin/stdout one; in-memory history only
│       ├── terminal/       # masked prompt: one `*` per character, zeroizing buffer (ADR-0008)
│       └── render.rs       # get view, list table, log view and every problem of a refused save; escapes exactly the characters the core refuses; hidden fields shown as `*`
├── vault-web/              # `vault-web` binary: HTTPS server for the browser client
│   ├── build.rs            # embeds assets/ into the binary at compile time; never runs npm
│   ├── assets/             # client bundle from `npm run build` in web/ (not committed)
│   ├── tests/common/       # shared test helpers: test app on a temp vault directory with a manual (optionally panicking) clock, a gate clock holding a KDF slot, request builders, log capture through the server's own subscriber (every line checked to be JSON)
│   ├── tests/app.rs        # the HTTP app in-process (tower `oneshot`): security headers, Host check, request logs (JSON fields, level fixed even with `RUST_LOG=trace`), "client not built" page
│   ├── tests/unlock.rs     # create, unlock, lock: cookie, CSRF, Origin, generic unlock failure, master password rules, KDF limiter (503; cheap create checks first), strict parsing, log contents, a storage failure on unlock (generic 500 with an `internal_error` line, not a 401)
│   ├── tests/secrets.rs    # list and detail: no hidden values, titles in URLs (percent-encoded, unusual characters), 404, one vault per session
│   ├── tests/reveal.rs     # reveal: one hidden value per request, CSRF, 404 for unknown title/field, plain fields refused, audit event, nothing in logs
│   ├── tests/expiry.rs     # sweeper (idle timeout, 8 h lifetime), activity keeping a session open, lock all on shutdown, panicking request (500, session locked)
│   ├── tests/edit.rs       # add, edit, delete: generated password, 409 taken title, unchanged hidden values kept, no rename, every field problem of a refused secret listed (`fields`) and edge cases, strict parsing, CSRF, audit events, full vault (413, session stays open), save conflict locks (401), storage failure (generic 500, one `internal_error` log line)
│   ├── tests/master_password.rs # change master password: new one only after, rules before the KDF, 503, wrong current one audited and the third in a row locks, other sessions locked, session reissued, CSRF, nothing in logs
│   ├── tests/backup.rs     # backup download: the stored vault file byte for byte, file name with revision, audited, CSRF, locks after another session saved
│   ├── tests/audit_log.rs  # audit log: newest first, limit (default 20, capped at 1000), unreadable lines marked, no field values, own vault only
│   ├── tests/tls.rs        # certificate loading, self-signed generation, 0600 cache and reuse
│   ├── tests/args.rs       # server flags, through the public `args` API
│   └── src/
│       ├── main.rs         # hardens the process (refuses to start otherwise), logs JSON lines to stderr via `logging` (panics without their message, start-up failures without paths), serves HTTPS, runs the sweeper, locks every session on SIGINT/SIGTERM
│       ├── lib.rs          # `App`: the whole HTTP app without TLS (router), the session sweep and sweeper task, lock all
│       ├── config.rs       # app config (the test seam): vault directory, clock, KDF limits, session lifetime, sweep interval, port, vault format, assets
│       ├── args.rs         # flags: --bind (loopback only), --vault-dir, --tls-cert/--tls-key
│       ├── tls.rs          # rustls (ring) config from given PEM files or a cached self-signed localhost certificate (rcgen)
│       ├── middleware.rs   # request log (method, route template, status, latency, session hash), panic catcher (generic 500, session locked), Host and Origin checks, security headers and CSP
│       ├── api.rs          # `/api` routes and JSON errors (`{"error"}`, optional `"field"`; a refused secret lists every problem in `"fields"`; every 500 but a panic logs an `internal_error` line)
│       ├── api/vault.rs    # POST /api/vaults (create), /api/unlock, /api/lock; GET /api/session
│       ├── api/secrets.rs  # GET /api/secrets (list), /api/secrets/{title} (detail): hidden fields named, never sent; POST /api/secrets/{title}/reveal: one hidden field, audited
│       ├── api/settings.rs # POST /api/master-password (KDF limiter, 3 wrong in a row lock, other sessions locked, session reissued), POST /api/backup (vault file as an attachment, audited)
│       ├── api/audit_log.rs # GET /api/audit-log?limit=N: the session's vault's audit events, newest first
│       ├── api/edit.rs     # POST /api/secrets (add), PUT /api/secrets/{title} (replace; hidden values sent as {"unchanged": true} kept), DELETE /api/secrets/{title}; hidden values straight into HiddenValue
│       ├── auth.rs         # `__Host-session` cookie; extractor resolving the session and checking the CSRF token; access to that session's vault only
│       ├── sessions.rs     # session registry: SHA-256(session ID) → vault session, CSRF token, creation time, idle timeout, wrong master passwords in a row; reissue under a new ID, lock a vault's other sessions, sweep of expired sessions, lock all
│       ├── kdf_limiter.rs  # unlock/create/master password change on the blocking pool, 2 at once plus a short queue, else 503
│       ├── logging.rs      # the diagnostics subscriber: JSON lines at a fixed `INFO` level, shared by `main.rs` and the test log capture (ADR-0014)
│       ├── json.rs         # strict JSON bodies (64 KiB cap, objects only); master password straight into `MasterPassword`
│       └── assets.rs       # embedded client bundle; "client not built" page
└── web/                    # vanilla TypeScript browser client, bundled by esbuild into vault-web/assets
    ├── package.json        # scripts: build, lint, check, test; pinned dev tools in package-lock.json
    ├── .oxlintrc.json      # lint rules: correctness and suspicious categories, no shadowed names
    ├── tsconfig.json       # strict type-checking of src/; tsconfig.test.json adds test/ and emits to .test-build/
    ├── scripts/build.mjs   # `npm run build`: esbuild bundle + static files into vault-web/assets
    ├── static/             # index.html and app.css (no inline scripts or styles)
    ├── src/                # main.ts (create/unlock/list/detail/add/edit/settings/audit log pages; DOM via createElement/textContent only), api.ts (CSRF header, 401 = locked, backup download), forms.ts (idle timeout, master password rules as typed), audit-log.ts (audit events as table rows), secret-form.ts (form values → add/edit request, unchanged hidden fields, where each field problem is shown), secrets.ts (search, title paths), reveal.ts (30 s reveal, 20 s clipboard clear), session-watch.ts (session check every 30 s and when the tab returns), text.ts (escapes exactly the characters the server refuses), url.ts (http/https link allowlist)
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
| Web server + client | `vault-web`, `web/` *(create, unlock, lock, list, view, reveal, add, edit, delete, change master password, backup, audit log)* | ICS0027 |

## Build and run

### Prerequisites

Linux or macOS. Windows is not supported, and no Windows support is planned.

A C toolchain and git. Rust needs a linker, and the `ring` crate (TLS in `vault-web`) needs a C compiler:

```bash
xcode-select --install                          # macOS: Xcode Command Line Tools
sudo apt install build-essential curl git       # Debian/Ubuntu
sudo dnf install gcc curl git                   # Fedora
```

Rust 1.89 or newer (edition 2024). On a clean machine, install it with [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version                                 # 1.89 or newer
```

Node.js 22 or newer, only to build and check the browser client (`web/`); the CLI never needs it. One way is [nvm](https://github.com/nvm-sh/nvm):

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source "$HOME/.nvm/nvm.sh"
nvm install 22
node --version                                  # v22 or newer
```

Then get the code:

```bash
git clone https://github.com/jevgeni-arefjev/secure-pass-manager.git
cd secure-pass-manager
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
- The master password and hidden fields (e.g. stored passwords) are entered only through hidden prompts, never as arguments, and only from a terminal: piping them in is refused. A hidden prompt takes up to 1024 characters; a paste that would go past that, or that holds a line break or another control character (a tab, ESC), is refused whole, and nothing is entered.
- A new master password (`init`, `passwd`, or creating a vault on the web) must be 12-1024 characters with no control characters. Unlock accepts any master password, so an older vault whose master password breaks these rules still opens and can be given a new one with `passwd`.
- A vault file is at most 64 MiB. A save that would go past that is refused with "vault is full" and nothing is written; remove or shorten secrets to make room.
- The keys live only in the `vault>` process. It locks after 5 idle minutes (`--idle-timeout 1-60`), and ends when locked.
- `log [--limit 20]` shows the vault's audit log, newest first, in local time: unlocks, failed unlocks, locks, saved, removed and revealed secrets, master password changes, backups. It holds titles in plaintext but never a field value.
- `backup <path>` writes an encrypted copy of the vault file to a new file outside the vault directory, e.g. `backup /media/usb/alice.vault`; it never overwrites. To restore, create a vault home and put the backup in it: `mkdir -m 700 ~/.local/share/secure-pass-manager/vaults/alice && cp /media/usb/alice.vault ~/.local/share/secure-pass-manager/vaults/alice/secrets.vault`, then `vault unlock alice`. Any vaultname works. On macOS, use the macOS vault directory above, in quotes because of the space.
- `--copy` needs a display (X11 or Wayland on Linux, a logged-in desktop session on macOS); over plain SSH it reports that the clipboard is not available.
- If the process is killed by a signal while waiting at the `vault>` prompt, the vault is wiped, but the terminal can be left in raw mode; type `reset` to fix it. At a hidden prompt (including the master password prompt of `init` and `unlock`) the terminal is restored before exiting.
- An unknown command or argument at `vault>` is reported without repeating it (``vault: unknown command; type `help` for commands``), so a password pasted there by mistake isn't echoed.

### Secret fields

Both front ends save through the same core rules (ADR-0013); a refused save lists every invalid field at once.

- The vault shell checks `save`'s title before asking for any field, then checks each answer as it is given: a refused answer is asked again with the reason (never the value), until it is valid or Ctrl-C cancels the save. Tags and custom field names are checked against those entered before them. How many tags and custom fields a secret has is checked on save.
- An empty custom field value, hidden or not, is refused: the vault shell asks for it again, and the web form marks it on its row without sending. Leaving the username, URL, notes or tags empty means "not set".

| Field | Accepts |
| --- | --- |
| Title | 1-64 characters; identifies the secret, so lookups (`get`, reveal, `rm`, replace on save) ignore case, surrounding spaces and Unicode composition (`café` typed either way is one secret) |
| Username | 1-256 characters |
| Password | 1-1024 characters, hidden |
| URL | 1-2048 characters: an `http://` or `https://` URL with a host (`https://github.com/login`, `http://localhost:8080`), or a bare host such as `github.com` (optionally with a port and path), stored as typed. Anything else (`javascript:` and `data:` URLs, `file:`, `ssh://`, `https://` without a host) is refused: put other addresses in the notes or a custom field. A name followed only by a port is a bare host, so `javascript:80` is taken as host `javascript`, port 80, which can't run anything |
| Notes | 1-4096 characters; may span several lines (newlines and tabs) |
| Tags | at most 32, each 1-32 characters, no two alike ignoring case and composition |
| Custom fields | at most 32; name 1-64 characters, unique ignoring case and composition, not a standard field name; value 1-1024 characters, hidden or not |

- Lengths count characters, not bytes.
- Fields that aren't hidden refuse control characters (notes allow newline and tab), every Unicode format character (zero-width characters, bidirectional controls, soft hyphen, tag characters, ...) and the line and paragraph separators, so nothing invisible can disguise a title or drive the terminal. They are stored NFC-normalised, and the single-line ones (all but notes) have surrounding spaces trimmed and must hold more than spaces.
- Hidden fields (the password and hidden custom fields) are stored exactly as entered, byte for byte, surrounding spaces included; they refuse only control characters.
- A vault saved under older, looser rules still opens: such a secret lists, shows (with unsafe characters as visible escapes such as `\u{202e}`), reveals and deletes, but saving it is refused with a message naming the field. Fix that field and save again. A title that breaks a rule can't be fixed in place (the web edit form keeps the title read-only): recreate the secret under a new title (CLI: `get <old title> --show`, then `save <new title>` and enter its fields again; web: **Add secret**, then copy the fields over, revealing hidden ones one at a time), check it, then delete the old one (`rm <old title>`, or **Delete** on the web).

### Tests and checks

```bash
cargo test                          # all workspace tests
cargo test --lib --bins --tests -- --ignored  # slow tests: the production KDF (256 MiB Argon2id)
cargo clippy --all-targets -- -D warnings   # also requires a docstring on every item in src/
cargo fmt --all --check
```

Client checks, from `web/` (need Node 22+):

```bash
npm ci                              # install the pinned dev tools (esbuild, TypeScript, Oxlint)
npm run lint                        # Oxlint over src/, test/ and scripts/ (e.g. no shadowed names)
npm run check                       # tsc --noEmit over src/ and test/
npm test                            # node:test tests of the pure helpers
```

CI (`.github/workflows/ci.yml`) runs the same checks (`.github/actions/checks`) on macOS, Ubuntu and Fedora (in a `fedora:latest` container) for every push to `main` and every pull request: formatting, clippy, both test commands, the client lint, checks and build, and a release build. The Rust steps never need Node. `tests/memory.rs` runs on Linux only.

Tests create vaults in a cheap test format (feature `insecure-test-kdf`, ADR-0005), which only test builds enable. Run tests in debug: `cargo test --release` is refused on purpose, so the test format can never end up in a release binary.

### Web

The server embeds the client bundle at compile time, so build the client first (Node 22+), then the server:

```bash
cd web && npm ci && npm run build && cd ..   # bundle into vault-web/assets/
cargo run -p vault-web                       # prints `vault-web: serving https://localhost:8443`
```

Open the printed URL. Without Node, `cargo run -p vault-web` still builds and runs, and serves a "client not built" page; after `npm run build`, rebuild the server to embed the bundle.

- Flags: `--bind <addr:port>` (default `127.0.0.1:8443`; a loopback address only, anything else such as `0.0.0.0` is refused), `--vault-dir <path>` (default `web-vaults` in the platform data directory, apart from the CLI's `vaults`), `--tls-cert <pem>` and `--tls-key <pem>` (both or neither).
- Without certificate flags, a self-signed certificate for `localhost` and `127.0.0.1` is generated on first start and cached (`0600`) in `web-tls/` in the platform data directory; the browser warns about it once. To avoid the warning, use [`mkcert`](https://github.com/FiloSottile/mkcert):

  ```bash
  mkcert -install                              # once: trust mkcert's local CA
  mkcert -cert-file localhost.pem -key-file localhost-key.pem localhost 127.0.0.1
  cargo run -p vault-web -- --tls-cert localhost.pem --tls-key localhost-key.pem
  ```

- Only requests addressed to `localhost:<port>` or `127.0.0.1:<port>` are served (DNS rebinding defence); every response carries a strict CSP with Trusted Types, short HSTS (`max-age=300`) and `Cache-Control: no-store`.
- A backup downloaded from the settings page is the encrypted vault file and opens with the master password the vault had when it was made. There is no restore in the browser: as with the CLI, create a vault home in the vault directory (e.g. `web-vaults/alice/`, mode `700`) and put the backup in it as `secrets.vault`; any vaultname works.
- The server refuses to start if it can't disable core dumps (`RLIMIT_CORE` = 0; on Linux also non-dumpable via `PR_SET_DUMPABLE`, so a piped crash handler gets nothing). Diagnostics go to stderr as JSON lines at a fixed `INFO` level (`RUST_LOG` is ignored); a failure to start is one `startup_failed` line with a fixed cause and, for a file, its kind, never the path (`{"event":"startup_failed","cause":"tls_file","kind":"NotFound"}`). Request lines hold the method, route template, status, latency and a short hash of the session ID only:

  ```text
  {"timestamp":"2026-11-08T10:00:00.000000Z","level":"INFO","event":"request","method":"GET","route":"/api/secrets/{title}","status":200,"latency_ms":1.2,"session":"3f9a1c0e"}
  ```
