# Context

Password manager for two TalTech courses in one repo (instructor-approved): one shared Rust core, two front ends.
- ICS0022 Secure Programming: local CLI app. Spec: `secure-password-manager.md`
- ICS0027 Web App Security: web server + TS client, data stored server-side. Spec: `web-app-security.md`
- Instructor requirements: `course-project-requirements.md`
- Layout, build/run: `README.md`

Cargo workspace: `vault-core` (crypto, storage, audit, backup, user), `vault-cli` (binary `vault`). `vault-web` and `web/` come later.
Toolchain lives in `~/.cargo/bin` (may not be on PATH).

## Decisions

- SQLite for both CLI and web; storage behind a trait so the backend stays swappable.
- MVP is a single-user vault, but auth/unlock code lives in `vault-core::user` so multi-user extends it.
- Core stays as modules in one crate, not separate crates.
- Crypto: Argon2id (m=256 MiB, t=3, p=1) for the KEK, with KDF params stored in the vault header; XChaCha20-Poly1305 for both the vault-key wrap and the body; HKDF-SHA-256 for the body key. Do not change algorithms or params without asking.
- CLI session is an interactive shell: `vault unlock` opens a `vault>` prompt and keys live only in that process, never on disk.
- Secrets are entered only via hidden terminal prompts (e.g. `vault save <name>` prompts for the password).
- Web is a local demo only (no Vercel/serverless: design needs a long-lived process holding session keys).

## General rules

- Do not modify `course-project-requirements.md`, `secure-password-manager.md`, `web-app-security.md` unless EXPLICITLY asked.
- If requirements cause conflict, prefer ICS0022 course requirements.
- No `unsafe` (forbidden workspace-wide). Secrets never in logs, args, env vars or error messages.
- Keep `README.md` layout and build instructions in sync with the code.

## Timeline

- [ ] MVP with vault at rest, encryption module, storage module & CLI module. It should be working and usable code.
- [ ] Build and run instructions that work on a clean machine.
- [ ] Basic working web interface with the core flows.
- [ ] Basic secure authentication implemented with password hashing, and secure session management.
- [ ] Application served over TLS in the development setup.
- [ ] Full input validation and sanitization on all fields.
- [ ] Structured logging of key events and secure error handling.
- [ ] Per-user access control enforced on every record operation (User-management module).
- [ ] Test cases written and passing, including input-validation edge cases and memory handling checks.

## Agent skills

### Issue tracker

Issues live in GitHub Issues (jevgeni-arefjev/secure-pass-manager), managed with the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
