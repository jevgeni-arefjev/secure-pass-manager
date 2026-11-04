// Behaviour of the form helpers for the create and unlock pages.

import assert from "node:assert/strict";
import { test } from "node:test";

import { checkNewMasterPassword, parseIdleTimeout } from "../src/forms.js";

test("idle timeout: empty means the server default, 1-60 whole minutes are accepted", () => {
  assert.deepEqual(parseIdleTimeout(""), { ok: true, minutes: undefined });
  assert.deepEqual(parseIdleTimeout("  "), { ok: true, minutes: undefined });
  assert.deepEqual(parseIdleTimeout("1"), { ok: true, minutes: 1 });
  assert.deepEqual(parseIdleTimeout(" 60 "), { ok: true, minutes: 60 });
});

test("idle timeout: anything else is refused", () => {
  for (const text of ["0", "61", "-5", "1.5", "5m", "1e1", "0x10", "abc"]) {
    assert.deepEqual(parseIdleTimeout(text), { ok: false, error: "idle timeout must be 1-60 minutes" }, text);
  }
});

test("new master password: both entries must match", () => {
  assert.equal(checkNewMasterPassword("correct horse battery", "correct horse battery"), null);
  assert.equal(checkNewMasterPassword("correct horse battery", "correct horse batter"), "master passwords don't match");
  assert.equal(checkNewMasterPassword("", ""), "enter a master password");
});
