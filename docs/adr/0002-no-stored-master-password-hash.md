# No stored master password hash; unlock by unwrapping the vault key

The master password is never stored, not even as a hash. Unlock derives a KEK with Argon2id and tries to unwrap the vault key; a failed AEAD tag check means a wrong password. A separate hash (e.g. bcrypt, as the course requirements suggest) would be a second offline brute-force target while proving nothing the wrapped key doesn't already prove. This deliberately differs from the course requirements; the instructor still has to confirm it.

## Consequences

- There is no cheap "check password" step: every unlock attempt, right or wrong, costs a full Argon2id derivation, which also gives the constant-delay behaviour for failed unlocks.
