# User manual

This manual explains how to use the password manager. There are two front ends that share the same core and the same rules:

- **CLI** (`vault`): a local command-line app (ICS0022).
- **Web** (`vault-web`): an HTTPS server on your own machine, used from a browser (ICS0027).

To build and start either of them, see [`README.md`](README.md#build-and-run). Both run on Linux and macOS.

## Contents

1. [Concepts](#1-concepts)
2. [CLI](#2-cli)
3. [Web app](#3-web-app)
4. [Secret fields](#4-secret-fields)
5. [Backup and restore](#5-backup-and-restore)
6. [Audit log](#6-audit-log)
7. [Troubleshooting](#7-troubleshooting)

## 1. Concepts

| Term | Meaning |
| --- | --- |
| **Vault** | Your encrypted file holding all your secrets. Each person has their own vault. |
| **Vaultname** | The name of a vault, e.g. `alice`: 1-32 letters, digits, `-` or `_`, starting with a letter or digit. You enter it together with the master password to unlock. |
| **Master password** | The only way to open your vault. It is never stored anywhere, not even as a hash, so **a forgotten master password can't be recovered or reset.** |
| **Secret** | Everything needed to log in to one service: a title (e.g. `github`), username, password, URL, notes, tags and any custom fields. |
| **Hidden field** | A field holding a password, token or key. It is masked unless you explicitly reveal it. A secret's password is always hidden. Custom fields can be hidden or not. |
| **Unlock / lock** | Opening and closing a vault. While the vault is unlocked, its keys are held in memory. Locking wipes them. |
| **Auto-lock** | The vault locks itself after a number of idle minutes (default 5, settable from 1 to 60). On the web it also locks 8 hours after unlock, however active you are. |

A new master password must be 12-1024 characters long and contain no control characters. A long passphrase of several unrelated words is a good choice.

The CLI and the web server keep their vaults in different directories, so a vault created in one doesn't show up in the other (see [Where vaults are stored](#where-vaults-are-stored)).

## 2. CLI

### Creating a vault

```
$ vault init alice
New master password: ********************
Repeat master password: ********************
vault 'alice' unlocked; it locks after 5 idle minute(s). Type `help` for commands.
vault>
```

If you leave out the vaultname, `vault init` asks for it. A vaultname that is already taken is refused before any password is asked for. After `init`, you are already in the vault shell.

### Unlocking

```
$ vault unlock alice
Master password: ********************
vault 'alice' unlocked; it locks after 5 idle minute(s). Type `help` for commands.
vault>
```

- You get three tries. Every failed unlock shows the same message, whether the master password was wrong or the vault doesn't exist.
- `--idle-timeout <minutes>` (1-60, default 5) sets how long the vault stays unlocked without a command, e.g. `vault unlock alice --idle-timeout 15`.
- `--vault-dir <path>` uses another vault directory. It works with every command.

### Typing passwords

- Master passwords and hidden fields are typed only at **hidden prompts**. Each character shows as one `*`. They are never passed as command-line arguments.
- Hidden prompts need a terminal: piping a password in is refused.
- A paste that contains a line break, a tab or another control character is refused whole, and nothing is entered.
- Ctrl-C at a prompt cancels the current command.

### The vault shell

Commands at the `vault>` prompt:

| Command | What it does |
| --- | --- |
| `list` | Lists all secrets: title, username, URL and tags. It never shows hidden fields. |
| `get <title>` | Shows one secret. Each hidden field shows as a single `*`, whatever its length. |
| `get <title> --show` | Shows the secret with hidden fields unmasked. Only works on a terminal, not into a pipe or file. |
| `get <title> --copy` | Copies the password to the clipboard instead of printing it. The clipboard is cleared after 20 seconds. |
| `save <title>` | Adds a secret, asking for each field in turn. If the title is already taken, it asks before replacing that secret. |
| `rm <title>` | Removes a secret after asking for confirmation. |
| `gen [--length N]` | Prints a random password (12-128 characters, default 24) and offers to copy it. |
| `passwd` | Changes the master password. |
| `backup <path>` | Writes an encrypted copy of the vault to a new file (see [Backup and restore](#5-backup-and-restore)). |
| `log [--limit N]` | Shows the vault's audit log, newest first (default 20 events). |
| `lock`, `exit`, `quit`, Ctrl-D | Locks the vault and leaves the shell. |
| `help` | Lists the commands. |

Titles that contain spaces must be quoted: `get "my bank"`. Title lookups ignore case and surrounding spaces, so `get GitHub` finds `github`.

`vault gen` also works outside the vault shell, without unlocking anything.

### Adding a secret

```
vault> save github
Username (optional): alice
Password (empty to generate):
URL (optional): https://github.com
Notes (optional):
Tags (comma-separated, optional): work, code
Add a custom field? [y/N] y
Field name: recovery code
Hidden? [y/N] y
Value: **************
Add a custom field? [y/N]
generated a 24-character password; `get <title> --copy` copies it
secret added
```

- Press Enter on an optional field to leave it unset.
- If you leave the password empty, a strong 24-character password is generated for you.
- Each answer is checked as soon as you give it. An invalid answer is asked again with the reason (the value itself is never shown back). The rules are listed in [Secret fields](#4-secret-fields).
- Every change is saved to the vault file straight away.

To change a secret, run `save` with its title again, confirm the replacement, and enter all of its fields again.

### Viewing and copying

```
vault> get github
title:         github
username:      alice
password:      *
url:           https://github.com
tags:          work, code
recovery code: *
created:       2026-11-25 10:47
updated:       2026-11-25 10:47
vault> get github --copy
password copied; the clipboard clears in 20 seconds
```

- `--copy` is the safer way to use a password, because the password never appears on screen.
- The clipboard is cleared after 20 seconds, on lock and on exit, but only if it still holds the copied value.
- Copying needs a desktop session (X11 or Wayland on Linux, a logged-in desktop on macOS). Over plain SSH it reports that the clipboard is not available.
- `--show` prints invisible characters as visible escapes (e.g. `\u{200b}`) and every `\` as `\\`, so `a\b` shows as `a\\b`. `--copy` copies the exact password.

### Changing the master password

```
vault> passwd
Current master password: ********************
New master password: ************************
Repeat master password: ************************
master password changed
```

The vault is re-encrypted under a new vault key. A backup made earlier still opens with the **old** master password.

### Locking

The vault locks:

- when you type `lock`, `exit` or `quit`, or press Ctrl-D;
- after the idle timeout (the shell then shows `vault locked (idle); press Enter to close`);
- when the process gets a termination signal, including Ctrl-C while a command is running.

Locking wipes the keys from memory and clears the clipboard if it still holds a copied password. The vault's keys exist only inside the running `vault>` process and are never written to disk.

### Where vaults are stored

| Platform | CLI vault directory |
| --- | --- |
| Linux | `~/.local/share/secure-pass-manager/vaults` |
| macOS | `~/Library/Application Support/secure-pass-manager/vaults` |

Each vault has its own folder (its vault home), named after its vaultname, e.g. `vaults/alice/`. It holds `secrets.vault` (the encrypted vault file), `audit.log` and an empty lock file `secrets.lock`. Renaming that folder renames the vault.

## 3. Web app

Start the server as described in [`README.md`](README.md#web) and open the URL it prints (by default `https://localhost:8443`). If the server uses its own self-signed certificate, the browser shows a warning the first time. Accept it, or use a `mkcert` certificate as the README describes. The server only accepts connections from the same machine.

### Creating a vault

1. On the unlock page, choose **Create a new vault**.
2. Enter a **Vaultname** and a **Master password**. The master password is checked as you type, and the **Master password again** field becomes available once it meets the rules.
3. Optionally change **Lock after idle minutes (1-60)**.
4. Choose **Create vault**. Creating a vault takes a few seconds, because the key is derived with a deliberately slow function. The vault opens straight away.

### Unlocking

Enter the **Vaultname**, the **Master password** and, optionally, the idle minutes, then choose **Unlock**. Every failed unlock shows the same message, whether the master password was wrong or the vault doesn't exist. Failed unlocks are recorded in the vault's audit log.

If the server is busy deriving keys for other unlocks, it asks you to try again shortly.

### Secrets list

The **Secrets** page lists every secret's title, username, URL and tags. Hidden fields never appear here. Use the search box to filter by title, username, URL or tags. Choose a title to open the secret.

### Viewing a secret

The secret page shows all of its fields, plus when it was created and last updated. Hidden fields are masked. For each hidden field:

- **Reveal** shows the value. It is masked again after 30 seconds, or when you choose **Hide**.
- **Copy** copies the value to the clipboard. The clipboard is cleared after 20 seconds, but browsers only allow this while the page has focus, so don't switch away before then.

Each reveal or copy fetches only that one field from the server and is recorded in the audit log.

### Adding, editing and deleting

- **Add secret** (on the Secrets page) opens an empty form. Leave **Password** empty to have a strong password generated. You can then reveal or copy it on the secret's page.
- **Add custom field** adds a row with a name, a value and a **Hidden** checkbox. **Remove** deletes the row.
- **Edit** (on a secret's page) opens the same form, filled in. The title can't be changed: to rename a secret, add a new one and delete the old one. Stored hidden fields show as *unchanged*, and the browser never receives them. Choose **Change** next to one only if you want to replace it.
- **Delete** removes the secret after you confirm.
- If a save is refused, every invalid field is marked at once, next to that field.

### Settings

- **Change master password**: enter the current and the new master password. The change locks any other browser sessions on the same vault. Three wrong current master passwords in a row lock your session.
- **Download backup**: downloads the encrypted vault file as `<vaultname>-r<revision>.vault`. See [Backup and restore](#5-backup-and-restore).

### Audit log page

**Audit log** shows the vault's audit events, newest first. **Show more** loads older ones. See [Audit log](#6-audit-log).

### Locking

- Choose **Lock** at the top of the page.
- The vault also locks after the idle minutes chosen at unlock, 8 hours after unlock, and when the server stops.
- An open tab notices within about 30 seconds and returns to the unlock page with *Your vault was locked.*

Closing the tab doesn't lock the vault by itself; the idle timeout does. Choose **Lock** when you're done, especially on a shared computer.

### Where web vaults are stored

By default the server keeps its vaults in `web-vaults` in the platform data directory (next to the CLI's `vaults`, in the same layout). `--vault-dir <path>` uses another directory.

## 4. Secret fields

Both front ends apply the same rules.

| Field | Rules |
| --- | --- |
| Title | Required, 1-64 characters, unique in the vault. Lookups ignore case, surrounding spaces and Unicode composition. |
| Username | Optional, up to 256 characters. |
| Password | Hidden. Up to 1024 characters. Empty means "generate one". |
| URL | Optional, up to 2048 characters. Accepted forms: `https://…` or `http://…` with a host, or a bare host such as `github.com` (optionally with a port and path). Other schemes (`javascript:`, `data:`, `file:`, `ssh://`) are refused: put such addresses in the notes or a custom field. |
| Notes | Optional, up to 4096 characters. May span several lines. |
| Tags | Optional, comma-separated. At most 32 tags, each 1-32 characters, with no duplicates (case is ignored). |
| Custom fields | At most 32. The name is 1-64 characters, unique, and can't be a standard field name. The value is 1-1024 characters, hidden or not, and can't be empty. |

- Lengths are counted in characters, not bytes.
- Fields that aren't hidden refuse control characters (notes allow line breaks and tabs) and invisible characters (zero-width spaces, text-direction controls and similar), so nothing invisible can disguise a title. Surrounding spaces are trimmed from single-line fields.
- Hidden fields are stored exactly as typed, including surrounding spaces. They refuse only control characters.

A vault saved under older rules still opens and shows all of its secrets. A secret that breaks a current rule can't be saved again until that field is fixed. The error names the field.

## 5. Backup and restore

A backup is the encrypted vault file exactly as stored. It never contains anything decrypted. It opens with the master password the vault had **when the backup was made**. The audit log is not included.

**Making a backup**

- CLI: `backup /media/usb/alice.vault`. The file must not exist yet, and it must be outside the vault directory. The copy is read back and checked before it is put in place.
- Web: **Settings** → **Download backup**.

**Restoring.** There is no restore command. Create a vault home and put the backup in it as `secrets.vault`:

```bash
mkdir -m 700 ~/.local/share/secure-pass-manager/vaults/alice
cp /media/usb/alice.vault ~/.local/share/secure-pass-manager/vaults/alice/secrets.vault
vault unlock alice
```

Any vaultname works. On macOS, use the macOS vault directory (in quotes, because of the space). For the web server, use its `web-vaults` directory instead.

## 6. Audit log

Each vault keeps an audit log of unlocks, failed unlocks, locks and auto-locks, added, replaced, removed and revealed secrets, master password changes and backups. Each event has a time and, at most, the title of the secret concerned. **It never holds a password or any other field value.**

- CLI: `log` (or `log --limit 50`), shown in local time.
- Web: the **Audit log** page.

Several failed unlocks you don't recognise mean someone has tried to guess your master password.

## 7. Troubleshooting

| Problem | What to do |
| --- | --- |
| Forgotten master password | It can't be recovered. Restore a backup whose master password you remember. |
| CLI: `hidden fields are only shown on a terminal` | `get --show` was sent into a pipe or file. Run it on a terminal, or use `--copy`. |
| CLI: the clipboard is not available | There is no desktop session (e.g. plain SSH). Use `get --show` instead. |
| CLI: the terminal behaves oddly after the process was killed | Type `reset`. |
| CLI: `warning: the vault file … is readable or writable by other users` | Run the `chmod go-rw` command the warning gives. |
| CLI: `vault is full` | A vault file is at most 64 MiB. Remove or shorten secrets. |
| A save locked the vault | Another session saved the same vault after you unlocked it. Unlock again and repeat the change. |
| Web: the browser warns about the certificate | Expected with the self-signed certificate. Accept it, or use `mkcert` (see the README). |
| Web: "client not built" page | Build the client (`cd web && npm ci && npm run build`), then rebuild and restart the server. |
| Web: the server is busy | Several unlocks are running at once. Wait a moment and try again. |
| Web: returned to the unlock page | The vault was locked by the idle timeout, the 8-hour limit, a master password change in another tab, or a server restart. Unlock again. |
