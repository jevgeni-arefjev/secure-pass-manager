// Client-side checks for the create, unlock and change master password forms. The
// server checks everything again; these only catch mistakes before a costly key
// derivation.

/** Allowed idle timeouts, in whole minutes (the server enforces the same range). */
const MIN_IDLE_MINUTES = 1;
const MAX_IDLE_MINUTES = 60;

/** Fewest and most characters a new master password may have, as `vault-core` counts them. */
export const MIN_MASTER_PASSWORD_CHARS = 12;
const MAX_MASTER_PASSWORD_CHARS = 1024;

/** A control character (Unicode Cc), as Rust's `char::is_control` sees it. */
const CONTROL = /\p{Cc}/u;

const IDLE_TIMEOUT_ERROR = `idle timeout must be ${MIN_IDLE_MINUTES}-${MAX_IDLE_MINUTES} minutes`;

/** An idle timeout field, parsed: minutes (`undefined` for the server default) or an error. */
export type IdleTimeout = { ok: true; minutes: number | undefined } | { ok: false; error: string };

/**
 * Parses the idle timeout field: empty means the server default, otherwise a whole
 * number of minutes from 1 to 60 written as plain digits.
 *
 * @example
 * parseIdleTimeout("10"); // { ok: true, minutes: 10 }
 * parseIdleTimeout("");   // { ok: true, minutes: undefined }
 * parseIdleTimeout("90"); // { ok: false, error: "idle timeout must be 1-60 minutes" }
 */
export function parseIdleTimeout(text: string): IdleTimeout {
  const trimmed = text.trim();
  if (trimmed === "") {
    return { ok: true, minutes: undefined };
  }
  const minutes = /^\d{1,2}$/.test(trimmed) ? Number(trimmed) : NaN;
  if (minutes >= MIN_IDLE_MINUTES && minutes <= MAX_IDLE_MINUTES) {
    return { ok: true, minutes };
  }
  return { ok: false, error: IDLE_TIMEOUT_ERROR };
}

/**
 * Checks a new master password as it is typed: `null` if it passes, else the rule it
 * breaks, worded as the server words it. Mirrors `vault-core`'s `check_master_password`
 * (12-1024 characters after NFC, no control characters) except its list of common
 * passwords, which only the server checks.
 *
 * Security: the message never contains the password.
 *
 * @example
 * masterPasswordProblem("hunter2"); // "master password must be at least 12 characters"
 * masterPasswordProblem("correct horse battery"); // null
 */
export function masterPasswordProblem(password: string): string | null {
  const chars = [...password.normalize("NFC")].length;
  if (chars < MIN_MASTER_PASSWORD_CHARS) {
    return `master password must be at least ${MIN_MASTER_PASSWORD_CHARS} characters`;
  }
  if (chars > MAX_MASTER_PASSWORD_CHARS) {
    return `master password must be at most ${MAX_MASTER_PASSWORD_CHARS} characters`;
  }
  if (CONTROL.test(password)) {
    return "master password must not contain control characters";
  }
  return null;
}

/**
 * Checks a new master password and its repetition on submit: `null` if they are
 * usable, else the message to show. Run {@link masterPasswordProblem} on the new
 * master password before asking for the repetition.
 *
 * Security: the message never contains either password.
 *
 * @example
 * checkNewMasterPassword("correct horse battery", "correct horse batter"); // "master passwords don't match"
 */
export function checkNewMasterPassword(password: string, confirmation: string): string | null {
  if (password === "") {
    return "enter a master password";
  }
  return password === confirmation ? null : "master passwords don't match";
}
