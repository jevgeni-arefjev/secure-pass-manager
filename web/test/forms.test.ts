// Behaviour of the form helpers for the create and unlock pages.

import assert from "node:assert/strict";
import { test } from "node:test";

import { checkNewMasterPassword, masterPasswordProblem, parseIdleTimeout } from "../src/forms.js";

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

test("master password rules: 12-1024 characters after NFC, no control characters", () => {
  assert.equal(masterPasswordProblem("correct horse battery"), null);
  assert.equal(masterPasswordProblem("x".repeat(11) + "y"), null);
  assert.equal(masterPasswordProblem(""), "master password must be at least 12 characters");
  assert.equal(masterPasswordProblem("hunter2"), "master password must be at least 12 characters");
  assert.equal(masterPasswordProblem("ab".repeat(512)), null);
  assert.equal(masterPasswordProblem("ab".repeat(512) + "c"), "master password must be at most 1024 characters");
  for (const control of ["\t", "\n", "\u001b", "\u007f", "\u0085"]) {
    assert.equal(
      masterPasswordProblem(`correct horse${control}battery`),
      "master password must not contain control characters",
      JSON.stringify(control),
    );
  }
});

test("master password rules count characters as the server does: code points after NFC", () => {
  // 12 emoji are 24 UTF-16 units but 12 characters.
  assert.equal(masterPasswordProblem("\u{1f511}".repeat(12)), null);
  // "e" + combining acute is one character after NFC: 11 of them are too short.
  assert.equal(masterPasswordProblem("e\u0301".repeat(11)), "master password must be at least 12 characters");
  // Format characters such as a zero-width joiner are not control characters.
  assert.equal(masterPasswordProblem("correct\u200dhorse battery"), null);
});
