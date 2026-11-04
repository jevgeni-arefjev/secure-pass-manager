// Behaviour of the display-text helper, through its public function.

import assert from "node:assert/strict";
import { test } from "node:test";

import { displayText } from "../src/text.js";

test("ordinary text, markup and non-ASCII text are kept as they are", () => {
  for (const text of ["github", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "日本語 🔑", "a & b"]) {
    assert.equal(displayText(text, false), text);
  }
});

test("control characters are shown as visible escapes", () => {
  assert.equal(displayText("\u001b[2Jcleared", false), "\\x1b[2Jcleared");
  assert.equal(displayText("nul\u0000", false), "nul\\x00");
  assert.equal(displayText("del\u007f c1\u0085", false), "del\\x7f c1\\x85");
});

test("newlines and tabs are kept only in multiline text", () => {
  assert.equal(displayText("line 1\nline 2\tend", true), "line 1\nline 2\tend");
  assert.equal(displayText("line 1\nline 2\tend", false), "line 1\\x0aline 2\\x09end");
  assert.equal(displayText("cr\r\n", true), "cr\\x0d\n");
});

test("bidirectional overrides and zero-width characters are shown as escapes", () => {
  assert.equal(displayText("evil‮txt.exe", false), "evil\\u{202e}txt.exe");
  assert.equal(displayText("zero​width", false), "zero\\u{200b}width");
  assert.equal(displayText("﻿bom", false), "\\u{feff}bom");
  assert.equal(displayText("isolate⁦x⁩", false), "isolate\\u{2066}x\\u{2069}");
});
