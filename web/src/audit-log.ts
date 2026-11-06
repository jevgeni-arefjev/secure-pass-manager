// The audit log page's rows: each event from `GET /api/audit-log` as its time, what
// it means (in the words of the CLI's `log` view) and the title of the secret it
// concerns.

import { displayText } from "./text.js";

/**
 * One event as the server sends it: `time` (RFC 3339 UTC) and `kind`, plus `title`
 * or `revision` where the event has one. An unreadable line is just
 * `{"kind": "unreadable"}`.
 */
export interface AuditEvent {
  kind: string;
  time?: string;
  title?: string;
  revision?: number;
}

/** One row of the audit log table, every cell plain text. */
export interface AuditRow {
  time: string;
  event: string;
  title: string;
}

/**
 * What each event kind means, worded as the CLI's `render::describe`; both are tested
 * against the shared fixture `fixtures/audit-events.json`.
 */
const DESCRIPTIONS: Readonly<Record<string, string>> = {
  vault_created: "vault created",
  unlocked: "unlocked",
  unlock_failed: "unlock failed (wrong master password)",
  locked: "locked",
  auto_locked: "locked (idle)",
  locked_on_conflict: "locked (changed by another session)",
  terminated_by_signal: "locked (terminated by signal)",
  secret_added: "secret added",
  secret_replaced: "secret replaced",
  secret_removed: "secret removed",
  secret_revealed: "secret revealed",
  master_password_changed: "master password changed",
  master_password_change_failed: "master password change failed (wrong current password)",
  backup_created: "backup created",
  unreadable: "unreadable event",
};

/**
 * The table row for `event`, with its time shown by `formatTime`. A kind this client
 * doesn't know (from a newer server) is shown as an unknown event, not dropped.
 *
 * Security: the title goes through `displayText`, so control, format and bidi
 * characters are shown escaped; the caller sets every cell with `textContent`.
 *
 * @example
 * auditRow({ time: "2026-11-06T10:00:00Z", kind: "secret_revealed", title: "GitHub" }, localTime);
 * // { time: "06/11/2026, 12:00:00", event: "secret revealed", title: "GitHub" }
 */
export function auditRow(event: AuditEvent, formatTime: (iso: string) => string): AuditRow {
  const known = Object.hasOwn(DESCRIPTIONS, event.kind) ? DESCRIPTIONS[event.kind] : undefined;
  let description = known ?? "unknown event";
  if (event.kind === "backup_created" && event.revision !== undefined) {
    description += ` (revision ${event.revision})`;
  }
  return {
    time: event.time === undefined ? "" : formatTime(event.time),
    event: description,
    title: event.title === undefined ? "" : displayText(event.title, false),
  };
}
