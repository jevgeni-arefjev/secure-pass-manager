# Secure Password Manager

A password manager where each person keeps their secrets in their own encrypted vault, used through a local CLI or a web front end.

## Language

### Vaults

**Vault**:
One person's encrypted file holding all of their secrets, identified by its vaultname.
_Avoid_: vault database, vault db, account

**Vaultname**:
The name of a vault, entered together with the master password to unlock it.
_Avoid_: username, login, account name (those belong to a secret)

**Vault directory**:
The place on a device where all vaults live.
_Avoid_: vault folder, data dir

**Vault home**:
The directory inside the vault directory that is named after a vaultname and holds that vault's file and its audit log; renaming it renames the vault.
_Avoid_: vault subdirectory, user directory

**Master password**:
The password that unlocks a vault, and the only way to open it.
_Avoid_: vault password

### Secrets

**Secret**:
Everything needed to access one service: its credentials and metadata, whatever that set is for that service.
_Avoid_: entry (understood as a synonym, but don't write it), record, credential, item, password

**Title**:
The field that uniquely identifies a secret within its vault and is used to look it up, e.g. `github`.
_Avoid_: name, entry name

**Field**:
One named part of a secret, such as its title, username, password or URL.

**Standard field**:
One of the fields every secret may have: username, password, URL, notes, tags. The password is always a hidden field.

**Custom field**:
A field the person names themselves for a service that needs more than the standard fields, such as a recovery code; each one is marked hidden or not.
_Avoid_: extra field, additional field

**Hidden field**:
A field holding a password, token, key or seed; it is always masked unless explicitly revealed.
_Avoid_: secret field, secret value

**Reveal**:
Showing or copying the hidden fields of one secret, only on an explicit request.
_Avoid_: unmask, decrypt

**Username**:
The field of a secret that names the account at that service; a service may call it a login or an email instead.
_Avoid_: using it for the vaultname

### Sessions

**Unlock**:
Opening a vault with its vaultname and master password, which starts a session.
_Avoid_: login, log in

**Lock**:
Closing a vault, ending its session and wiping its keys from memory.
_Avoid_: logout, log out

**Session**:
The period between unlock and lock, while a vault is open.

**Auto-lock**:
Locking a vault automatically after an idle timeout.
_Avoid_: auto-logout

**Vault shell**:
The interactive `vault>` prompt a CLI session runs in; leaving it locks the vault.
_Avoid_: shell (on its own, that is the user's OS shell), REPL, console

### Audit

**Audit log**:
The record of a vault's audit events, kept in its vault home and readable by its owner from the vault shell; it never holds a field value.
_Avoid_: activity log, history (that is the vault shell's command history)

**Audit event**:
One security-relevant thing that happened to a vault, such as an unlock, a failed unlock, a lock, a saved or removed secret or a reveal; it names at most the title of the secret concerned.
_Avoid_: log entry, audit entry (entry means a secret)

**Diagnostic**:
An operational warning printed to stderr, such as loose file permissions or memory that couldn't be locked; not an audit event and never written to the audit log.
_Avoid_: calling it an audit event
