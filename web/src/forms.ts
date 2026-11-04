// Client-side checks for the create and unlock forms. The server checks everything
// again; these only catch mistakes before a costly key derivation.

/** Allowed idle timeouts, in whole minutes (the server enforces the same range). */
const MIN_IDLE_MINUTES = 1;
const MAX_IDLE_MINUTES = 60;

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
 * Checks the two master password entries of the create form: `null` if they are
 * usable, else the message to show. Strength is checked by the server's policy.
 *
 * Security: the message never contains either entry.
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
