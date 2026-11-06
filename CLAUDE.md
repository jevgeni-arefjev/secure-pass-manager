# Context

Password manager for two TalTech courses in one repo (instructor-approved): one shared Rust core, two front ends.
- ICS0022 Secure Programming: local CLI app. Spec: `secure-password-manager.md`
- ICS0027 Web App Security: web server + TS client, data stored server-side. Spec: `web-app-security.md`
- Instructor requirements: `course-project-requirements.md`
- Layout, build/run: `README.md`

Cargo workspace: `vault-core` (crypto, storage, audit, backup, session), `vault-cli` (binary `vault`), `vault-web` (HTTPS server); `web/` is the TypeScript client it embeds.

## Decisions

- A flat file (`header ‖ body`) per vault for both CLI and web, no database (ADR-0011); storage behind a trait so the backend stays swappable.
- Each user's vault is a separate file in a vault home named after its vaultname (`vault init` asks for it). MVP handles one user; unlock code lives in `vault-core::session` so multi-user extends it.
- No master password hash is stored: unlock succeeds only if the vault key unwraps.
- Core stays as modules in one crate, not separate crates.
- Crypto: Argon2id (m=256 MiB, t=3, p=1) for the KEK, with KDF params fixed by the format version in the vault header (ADR-0005); XChaCha20-Poly1305 for both the vault-key wrap and the body; HKDF-SHA-256 for the body key. Do not change algorithms or params without asking.
- CLI session is an interactive shell: `vault unlock` opens a `vault>` prompt and keys live only in that process, never on disk.
- Secrets are entered only via hidden terminal prompts (e.g. `vault save <secret>` prompts for the password), and never reach logs, command-line args, env vars or error messages.
- Supported platforms: Linux and macOS (CI runs on macOS, Ubuntu and Fedora, `.github/workflows/ci.yml`). No Windows support is planned: don't add Windows-specific code, docs or CI. Existing `cfg(unix)` code stays as it is.
- Web is a local demo only (no Vercel/serverless: design needs a long-lived process holding session keys).
- Terminology (vault, vaultname, secret, hidden field, unlock/lock, ...) is defined in `CONTEXT.md`; use it in code and docs.

## Deviations from course requirements

Recorded as ADRs in `docs/adr/`.

These are deliberate design choices that differ from `course-project-requirements.md`. All of them are approved by the instructor. Don't "fix" them toward the requirements without asking.

- **Master password storage.** Requirements ask for the master password to be stored as a hash (e.g. bcrypt). Here nothing is stored: unlock derives a KEK with Argon2id and tries to unwrap the vault key, and a failed tag check is a wrong password. This avoids keeping a second offline brute-force target. Approved by the instructor (ADR-0002).
- **Per-user ownership on every record operation.** Requirements imply a shared database with per-record ownership checks. Here each user has a separate vault file, and a session only opens the vault it unlocked, so other users' secrets are never reachable (and wouldn't decrypt anyway). Ownership is enforced once, when the vault file is opened. Approved by the instructor (ADR-0001).
- **No SQL, so no parameterized statements.** Requirements name prepared, parameterized statements as the SQL injection defence. Here the vault file is a flat `header ‖ body` file with no query language, so injection is ruled out by design. Approved by the instructor (ADR-0011).

## General rules

- Do not modify `course-project-requirements.md`, `secure-password-manager.md`, `web-app-security.md` unless EXPLICITLY asked.
- If requirements cause conflict, prefer ICS0022 course requirements.
- Coding standards (docstrings, where rules live, tests): `CODING_STANDARDS.md`.
- Keep `README.md` layout and build instructions in sync with the code.
- Roadmap: the course deliverables checklist is in `README.md` (Roadmap).

## Finishing work

Leave changes uncommitted for the user to review; this overrides skills that commit. End with whether the work is ready to commit (which checks ran and passed, what is still open) and a proposed message in the repo's style: one commit per issue, `<summary> (closes #N)`. Commit or branch only when the user asks.

## Agent skills

### Issue tracker

Issues live in GitHub Issues (jevgeni-arefjev/secure-pass-manager), managed with the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
