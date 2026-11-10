# Coding standards

The judgement calls a reviewer checks in every diff. Rules a tool already enforces are left to the tool: rustfmt, clippy (including docstring presence in `src/`), `unsafe_code = "forbid"`, tsc and Oxlint (`web/`), all run in CI.

## Docstrings

- Every function, method, type and module has a brief docstring (Rust `///` / `//!`, TypeScript `/** */`). Test cases (`#[test]`, `test(...)`) are exempt, since their names state the behaviour; test helpers are not, and clippy doesn't check them, so the reviewer does.
- Say what it does, and in a `Security:` paragraph what matters for security: what it zeroizes or locks, what it never prints, what input it trusts.
- Include a usage example. Public Rust items: a doctest that compiles and runs. Private Rust items: an `ignore` or `text` example, which is never compiled, so every name in it must exist and match the real signature. TypeScript: `@example`.

## Where rules live

- A field or secret rule has one home in `vault-core` (e.g. `session::check`, `Secret::validate`); the CLI and the server call it. A front end may pre-check for a faster answer (the web form marking an empty value), but the core stays authoritative, and the pre-check's docstring says which core rule it mirrors.
- Messages for the person name the field and the rule, never the value.

## Errors and logging

- Every error a front end shows belongs to one class in ADR-0014 (input mistake, security refusal, session ended, internal failure), and the class decides the message, the audit event and the diagnostic. A new error variant gets its class in the same diff.
- Audit events go through the typed `audit::Event`; everything else operational is a diagnostic through `tracing` with an `event = "..."` code. Neither holds a field value, master password, path, request URL or panic message; a diagnostic names the vaultname only when it is about that vault's own files.

## Tests

- Tests sit in each crate's `tests/` and go through the public API: the vault shell through `shell::run` with the scripted fake terminal, the server through HTTP, the web client through its pure helpers.
  Exceptions, kept as `#[cfg(test)] mod tests` in `src/` because what they check is private and has no public seam: `vault-core/src/crypto/secret_memory.rs` (the locked buffer's wipe and page alignment, which no public API can observe) and `vault-cli/src/terminal/masked.rs` (the masked reader's key handling, which the public prompt only reaches through a real raw-mode terminal). Don't add more without the same reason.
- Expected values are literals from the spec or a worked example, not recomputed the way the code computes them.
