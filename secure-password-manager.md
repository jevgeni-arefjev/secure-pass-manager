# Secure Password Manager — Core & CLI

GUI document: `web-app-security.md`

## 1. Scope

This app is:
- Desktop native
- Multi-user on single device: each user has their own vault file, identified by its vaultname (no teams or secret sharing)
- Fully local (no automatic backuping plan yet, only ciphertext export)
- Unlocked with a vaultname and master password (later maybe with MFA, Google SSO or similar)

## 2. Architecture

The app consists of 6 modules with responsibilities split between them. The goal of this app is to securely store secrets and protect against memory leaks, injection attacks and other cryptographic attacks.

| Module | Responsibility |
| --- | --- |
| CLI | Command parsing, terminal output, one-secret reveal, clipboard |
| Session | Unlock/lock state and session lifetime; holds the decrypted secrets, reveals them one at a time; owns the secret model and its serialization; **handles plaintext in memory** |
| Encryption | Encryption/decryption, key derivation, key wrap, nonces, salts, padding, header encoding; passes decrypted plaintext only to Session |
| Storage | Vault files (SQLite), schemas |
| Audit log	| Structured events - unlocks, failed unlock attempts, locks, vault changes |
| Backup | Ciphertext-only export of the user's vault |

```mermaid
flowchart LR
  CLI -->|vaultname + master password| SE[Session] -->|master password, plaintext| ENC[Encryption]
  ENC -->|plaintext| SE
  SE -->|one revealed secret| CLI
  ENC -->|header + ciphertext| ST[(Storage / SQL)] -->|header + ciphertext| ENC
  SE --> LOG[Audit log]; ST -->|ciphertext copy| BK[Backup]
```


### Data Flow

```mermaid
sequenceDiagram
  participant CLI as CLI
  participant SE as Session
  participant ENC as Encryption
  participant ST as Storage
  CLI->>SE: vaultname + master password (terminal prompt)
  SE->>ST: open the vault file for that vaultname
  ST-->>SE: header + ciphertext body
  SE->>ENC: header + master password
  ENC->>ENC: check format version, derive KEK, unwrap vault key
  SE->>ENC: vault key + ciphertext body
  ENC-->>SE: plaintext body (held for the session)
  CLI->>SE: reveal one secret
  SE-->>CLI: that secret, hidden fields masked unless revealed
  CLI->>SE: changed secret
  SE->>ENC: new plaintext body
  ENC->>ST: new header + ciphertext
  ST->>ST: save in one transaction, if the revision still matches
```

## 3. Design decisions

**Vault format.** Each user's vault is a separate SQLite file (ADR-0006), named after its vaultname and created by `vault init`. The file name is the plain vaultname (not a hash), so a vault can still be found if its name is half-remembered; the contents stay encrypted. It holds a plaintext header + encrypted body (all secrets), header authenticated as associated data. This way it doesn't leak the number of secrets or existence of a specific secret (e.g. existence of a github account). A secret is everything needed to access one service: its credentials and metadata (title, username, password, URL, tags, ...).

It is also impossible to read other users' secrets: a session only ever opens the one vault it unlocked, and another user's file will not decrypt even if somehow obtained.

Header contains format version, salt, wrap nonce, wrapped vault key, revision counter, body nonce. The format version also fixes the KDF and its params, so no cost parameter is stored (ADR-0005). The vaultname is not in the header: it is only the file name, so renaming the file renames the vault and a backup can be restored under any name (ADR-0004).

Body is a JSON of all secrets *(may be changed later)*, padded to 4 KiB, rewritten whole on every save. Per-secret encryption leaks the number of secrets and their sizes and multiplies nonce management, wchih gains nothing in performance, since the app is so small.

**Unlock.** The master password is never stored, not even as a hash. Unlock derives the KEK and tries to unwrap the vault key; a failed tag check means a wrong password. A separate password hash would be a second offline brute-force target while adding nothing the wrapped key doesn't already prove.

**Cryptographic scheme:**

Each vault has one random vault key, and one body key derived from it. Master password (or MFA/SSO) decrypts vault key. Vault key derives body key, which deciphers JSON block.

1) Argon2id (m=256 MiB, t=3, p=1) derives a KEK from the master password it was chosen to prevent brute force attacks against encrypted vault. The params are fixed by the format version in the header, not stored as separate values (ADR-0005). Raising them later means a new format version, and vaults in older versions keep working. Tests use a test twin of each format (top bit of the version set, OWASP minimum 19 MiB, t=2, p=1) that exists only in test builds;
2) KEK wraps a random 32-byte vault key; the vault key derives a body key via HKDF-SHA-256. XChaCha20-Poly1305 is used for both the wrap and the body (one AEAD, 192-bit random nonces). The format is KDF-agnostic. Details of this scheme may likely be changed in the future.
3) Changing the master password always rotates the vault key: a new random vault key (and with it a new body key, derived from it) re-encrypts the body, and a fresh salt derives a new KEK that wraps it. A copy of the vault taken before the change therefore never decrypts later versions, even with the old master password.

**Programming language - Rust.** It was chosen because it lets you control memory directly the way C does, but stops whole categories of memory bugs the way Java or Go do. I personally, don't have a lot of experience with Rust, and my assumption is that, long-term, avoiding hand-managing memory will result in safer code, as there will be less opportunities for human error bugs.


## 4. Threat model

### Security Assumptions

- **An attacker has access to the encrypted vault files.**
- **An attacker has access to the application source code.**
- **An attacker can use the same device (as a different user) and read memory on target device after the vault has been unlocked and used and is locked again.**
- **App user might not have the best password hygiene or be a proficient PC user.**
They might forget to lock the vault, accidentally copy or display all their secrets, or use an easy password.

### Out of scope - not covered threats:

- **The host device is trusted while unlocked.**
- **The attacker might have a keylogger on target device or do memory snapshots while app is in use.**

### Threat analysis

| Surface | Threat | Mitigation |
| --- | --- | --- |
| Master password | Offline brute force against a stolen vault | Every vault uses Argon2id with 256 MiB of memory per guess, and release builds accept no other params (the cheaper test formats are compiled only into test builds), so brute forcing is not an option; no password hash is stored that could be attacked instead |
| Master password | Old master password leaked together with an old copy of the vault | Accepted: it decrypts only that old snapshot; every master password change rotates the vault key, so later versions stay protected |
| Master password | Weak password chosen by the user | Length rule (at least 12 characters), a single repeated character and a built-in list of common passwords are refused. No strength meter: estimators such as zxcvbn copy the password into heap strings that are freed without zeroizing, breaking the no-implicit-copies rule below |
| Vault at rest | File stolen from disk, backup or cloud sync | Whole body encrypted under a random vault key; only the header is readable |
| Vault at rest | Header tampering | Header is authenticated as associated data so altered fields fail the tag check; no KDF params are read from the header (the format version fixes them), so a crafted header can't force a huge allocation |
| Vault at rest | Two vaults with the same master password swapped on disk | Accepted: needs write access to the vault directory and reveals nothing; vaults with different passwords fail to unlock (ADR-0004) |
| Vault at rest | Rollback: an older copy of the vault file put in place of the current one, bringing back a rotated password or dropping newer secrets | Accepted: detection needs trusted state the attacker can't roll back at the same time (hardware counter, remote server or a per-device state file), which is out of scope. An attacker with write access to the vault directory can usually replace the binary anyway. The authenticated revision counter only orders backups and writes; it is not rollback protection |
| Vault at rest | Corruption or crash mid-write losing the vault | Each save is one SQLite transaction (`journal_mode=DELETE`, `synchronous=FULL`); `init` builds the new vault in a temp file and hard-links it into place (ADR-0006) |
| Vault at rest | Two sessions on the same vault overwriting each other's changes | A save only succeeds if the stored revision is the one it follows; otherwise it fails with a conflict and the session must unlock again |
| Vault at rest | Crafted vault file attacking the SQLite parser (e.g. a restored backup from an untrusted place) | Every connection enables `SQLITE_DBCONFIG_DEFENSIVE` and `trusted_schema=OFF`, and checks `application_id` and `user_version` before reading any table (ADR-0006) |
| Vault at rest | Old ciphertext left in the file after a save, e.g. the header wrapped under a rotated master password | `secure_delete=ON` zeroes freed pages. Accepted: blocks of the deleted rollback journal may remain on disk |
| Vault at rest | Malicious crafted input reaching the parser or a query | #![forbid(unsafe_code)] and parameterized SQL; header parser fuzzed |
| Vault at rest | Vaultname used as a file name: path traversal or overwriting another file | Vaultnames allowlisted (restricted charset and length); vault path is built only inside the vault directory; `init` refuses an existing vaultname |
| Vault at rest | Vault file names reveal vaultnames to other local users | Accepted: keeps a vault recoverable when its name is forgotten; the contents stay encrypted |
| Vault in memory | Memory dump or core file of a running process | Vault key in locked pages, zeroed on lock; core dumps disabled |
| Vault in memory | Key paged to swap or a hibernation file | `mlock` the key material and the decrypted secrets, no swap allocations; if the decrypted body exceeds `RLIMIT_MEMLOCK` it falls back to zeroize-only, with a warning logged |
| Vault in memory | Session left unattended | Auto-lock on idle timeout, on screen lock, on suspend |
| Vault in memory | Runtime copies of secrets | In Rust, `zeroize`/`secrecy`; no implicit copies of secret types, `#[must_use]` on every AEAD output (so tag failure is not ignored) |
| Access control | One user reading or editing another's secrets | Each user's vault is a separate file; a session only opens the vault it unlocked, and another vault doesn't decrypt without its master password |
| Interface | Secrets in shell history / process arguments | Never accept a master password or hidden field as an argument or env variable; prompt on the terminal with echo disabled |
| Interface | Secrets in terminal scrollback | Hidden fields are masked by default and only unmasked with `--show`, for one secret at a time, so this threat exists, but is minimized |
| Interface | Secrets in redirected output or a piped log | Refuse to write hidden fields when stdout is not a TTY (maybe unless an explicit `--raw` flag is passed) |
| Interface | Modified header content received by the terminal | Validate, strip or escape control sequences before printing any stored field or evaluating; |
| Interface | Timing or error msg attacks | One generic unlock failure message and a constant minimum delay, whether or not the vaultname exists |

## 5. Planned commands

Since the app currently doesn't have a name, example name is `vault`.

```
vault init | unlock | lock        # create a vault (asks for a vaultname); start / end session (`unlock` opens an interactive `vault>` shell)
vault get <secret> [--show|--copy] # print a secret by its title, hidden fields masked; `--show` unmasks them; `--copy` copies the password to the clipboard
vault save <secret>               # Save new secret (hidden fields via hidden prompt), or replace the old one
vault list                        # Show all secrets, non-hidden fields only
vault rm <secret>                 # remove a secret
vault gen [--length 24]           # generate a text password
vault export-cypher <path>        # ciphertext copy of your vault file
```
as well as others, e.g. to view logs.

The session is an interactive shell: `vault unlock` prompts for the vaultname and master password and opens a `vault>` prompt where the commands above run. Vault keys live only in that process and are never written to disk; `lock`, exit or idle timeout wipes them. Hidden fields are never accepted as arguments, only through hidden prompts.
