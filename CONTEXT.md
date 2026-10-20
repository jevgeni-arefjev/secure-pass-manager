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

**Hidden field**:
A field holding a password, token, key or seed; it is always masked unless explicitly revealed.
_Avoid_: secret field, secret value

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
