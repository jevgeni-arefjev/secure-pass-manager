# Text rules for secret fields: normalise what is shown, keep hidden fields exact

Every non-hidden field of a secret (title, username, URL, notes, tags, custom field names, non-hidden custom field values) is NFC-normalised on save, and every single-line one is also trimmed. The whole Unicode format category (Cf) and the line and paragraph separators (U+2028, U+2029) are refused in them, so that text that looks identical is identical and nothing invisible can disguise a title or drive a display. Hidden fields are stored exactly as entered, refusing only control characters: unlike the master password, which only ever feeds the KDF and is NFC'd for that (ADR-0007), a stored password is compared byte for byte by the service it belongs to, so normalising it could make it stop working.

## Considered Options

- **A hand-written list of invisible characters** (the original rule). Rejected: it missed several (word joiner, soft hyphen, tag characters) and misses whatever Unicode adds later. A category rule doesn't.
- **URL as free text, or any scheme.** Rejected: the URL field accepts only `http://` or `https://` with a host, or a bare host such as `github.com`. Other identifiers (`ssh://`, app IDs) go in notes or a custom field. The core refusing `javascript:` and similar is a second defence behind the web client's link allowlist.

## Consequences

- ZWJ and ZWNJ (U+200D, U+200C) are refused in non-hidden fields, as they already were, so some emoji sequences and some Persian and Indic spellings can't be used in titles, tags or field names.
- A vault is not re-checked against these rules when it is opened: a stored secret that breaks a newer rule still opens and displays (escaped), and only a save of that secret is refused, with an error naming the field. A title that breaks a rule can't be fixed in the web front end, where the title is read-only. The secret has to be recreated under a new title and the old one deleted.
- Tightening these rules later has the same cost again, so changes need the same care as a format change.
