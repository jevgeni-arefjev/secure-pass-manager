// Behaviour of the audit log helpers: each event as a row of time, words and title.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { type AuditEvent, auditRow } from "../src/audit-log.js";

/** Shows a time as given, so rows don't depend on the test machine's time zone. */
const asGiven = (iso: string): string => `at ${iso}`;

test("an event is its time, its meaning in the CLI's words and its title", () => {
  assert.deepEqual(
    auditRow({ time: "2026-11-06T10:00:00Z", kind: "secret_revealed", title: "GitHub" }, asGiven),
    { time: "at 2026-11-06T10:00:00Z", event: "secret revealed", title: "GitHub" },
  );
  assert.deepEqual(auditRow({ time: "2026-11-06T10:00:00Z", kind: "unlock_failed" }, asGiven), {
    time: "at 2026-11-06T10:00:00Z",
    event: "unlock failed (wrong master password)",
    title: "",
  });
});

test("a backup names its revision", () => {
  assert.deepEqual(auditRow({ time: "2026-11-06T10:00:00Z", kind: "backup_created", revision: 7 }, asGiven), {
    time: "at 2026-11-06T10:00:00Z",
    event: "backup created (revision 7)",
    title: "",
  });
});

// The shared fixture (`fixtures/audit-events.json`), also read by the CLI's render
// tests: every event kind is worded as the CLI's `log` view words it.

interface FixtureCase {
  event: AuditEvent;
  shown: string;
}

const fixture = JSON.parse(
  readFileSync(new URL("../../../fixtures/audit-events.json", import.meta.url), "utf8"),
) as { events: FixtureCase[] };

test("every event kind is worded as the shared fixture says, as in the CLI", () => {
  assert.ok(fixture.events.length > 0);
  for (const { event, shown } of fixture.events) {
    const row = auditRow({ ...event, time: "2026-11-06T10:00:00Z" }, asGiven);
    assert.equal(row.event, shown, event.kind);
    assert.equal(row.title, event.title ?? "", event.kind);
  }
});

test("unreadable and unknown events are marked, not dropped", () => {
  assert.deepEqual(auditRow({ kind: "unreadable" }, asGiven), { time: "", event: "unreadable event", title: "" });
  assert.deepEqual(auditRow({ time: "2026-11-06T10:00:00Z", kind: "from_a_newer_server" }, asGiven), {
    time: "at 2026-11-06T10:00:00Z",
    event: "unknown event",
    title: "",
  });
});

test("a title is shown with unsafe characters escaped", () => {
  const row = auditRow({ time: "2026-11-06T10:00:00Z", kind: "secret_added", title: "evil‮txt" }, asGiven);
  assert.equal(row.title, "evil\\u{202e}txt");
});
