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
- Crypto algorithms and Argon2 memory cost undecided; candidates listed in `vault-core/src/crypto.rs`. Do not pick one without asking.
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
