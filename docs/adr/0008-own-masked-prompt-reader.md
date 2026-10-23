# Hidden input is read by our own masked prompt, echoing one `*` per character

The CLI reads the master password and hidden fields with a small reader of its own, built on `crossterm` raw mode, instead of `rpassword` or `inquire`. It echoes one `*` per character typed, so the person can see that input is arriving and roughly how much. Each key goes straight into a `Zeroizing<String>`, which is then moved into `MasterPassword` or `HiddenValue`, so every copy of the input is one we control and wipe. `rpassword` echoes nothing at all, and `inquire::Password` (which can show `*`) keeps the input in its own `String` buffers that are never zeroized and that we can't reach.

The star echo shows the length of what is typed to anyone watching the screen or a recording. We accept this: weak master passwords are already refused by the policy, and knowing the length barely narrows the search. Hidden fields shown later in `get` are masked as a single `*` whatever their length, because there the length would be leaked again with no usability gain.

## Consequences

- The reader handles only what a password prompt needs: printable characters, backspace, Ctrl-U (clear), Ctrl-C (cancel), Enter. A paste that contains a newline is refused rather than split.
- It needs a terminal: if stdin is not a TTY, hidden prompts refuse, so a master password can't be piped in.
- The terminal must be restored from raw mode on every exit path, including cancel and errors; this is our code to get right and to test.
- Tests drive hidden prompts through the CLI's `Terminal` trait, not through a real terminal.
