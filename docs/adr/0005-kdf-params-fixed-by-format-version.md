# KDF params are fixed by the format version, with test formats behind a feature

The header no longer stores a KDF id or Argon2id params. The format version alone decides them: version `0x0001` means Argon2id, 256 MiB, t=3, p=1. Raising the cost later means adding a new format version; old versions stay readable. This removes 13 bytes from the header, along with the bounds checks that stopped a crafted header from forcing a huge allocation, because no cost parameter is read from untrusted bytes any more.

Tests can't afford a 256 MiB derivation per vault, so every production version has a test twin with the top bit set (`0x8001` for `0x0001`): the same layout with OWASP's minimum params (19 MiB, t=2, p=1). Test formats exist only with the `insecure-test-kdf` Cargo feature, which `vault-core` enables for its own tests through a dev-dependency on itself. A release build refuses to compile with it, so a release binary can neither create nor open a test vault.

## Considered options

- **Params stored per vault (previous design)**: lets each vault pick its own cost, but every vault uses the same params anyway, and the extra fields need validation.
- **A one-byte KDF profile id**: the same as a version-to-params table, with an extra field.
- **Test formats always compiled in**: a bug could create weak vaults in production, and they would open without anyone noticing.

## Consequences

- `crypto::create` takes no params; tests use `crypto::create_insecure_for_tests`.
- A password change keeps the vault's format version.
- One `#[ignore]`d test covers the production params end to end (`cargo test -- --ignored`).
- `cargo test --release` doesn't compile; tests run in debug.
