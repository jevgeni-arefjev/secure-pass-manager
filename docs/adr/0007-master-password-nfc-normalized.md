# Master password is NFC-normalized before key derivation

The master password is normalized to Unicode NFC before it reaches Argon2id. The same password can arrive as different bytes depending on the keyboard, input method or OS (`é` as one code point or as `e` plus a combining accent), and without normalization a vault created on one system would fail to unlock on another with a password the person typed correctly. NFC rather than NFKC: compatibility folding would merge visibly different characters (e.g. `ﬁ` and `fi`), which quietly lowers entropy and is not something the person chose.

## Consequences

- Normalization happens in `MasterPassword::new`, so every path that derives a KEK (create, unlock, password change) gets it, and the normalized copy stays in locked memory.
- This is part of the key derivation for format version `0x0001`. Changing the normalization later would lock out existing vaults whose master passwords contain affected characters, so it needs a new format version.
