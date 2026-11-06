// Behaviour of the display-text helper, through its public function.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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

// The shared fixture (`fixtures/unsafe-characters.json`), also read by the core and
// CLI tests: this escaper must escape exactly what the core refuses.

interface UnsafeRange {
  from: string;
  to: string;
  control: boolean;
  name: string;
}

interface Fixture {
  unsafe: UnsafeRange[];
  multiline_safe: string[];
  safe: { char: string; name: string }[];
}

const fixture = JSON.parse(
  readFileSync(new URL("../../../fixtures/unsafe-characters.json", import.meta.url), "utf8"),
) as Fixture;

/**
 * The visible escape for code point `c`: `\x1b` up to U+00FF, else `\u{202e}`.
 *
 * @example
 * escaped(0x1b); // "\\x1b"
 */
function escaped(c: number): string {
  return c <= 0xff ? `\\x${c.toString(16).padStart(2, "0")}` : `\\u{${c.toString(16)}}`;
}

test("every unsafe character of the shared fixture is escaped; notes keep only newline and tab", () => {
  const multilineSafe = new Set(fixture.multiline_safe.map((hex) => parseInt(hex, 16)));
  let checked = 0;
  for (const range of fixture.unsafe) {
    for (let c = parseInt(range.from, 16); c <= parseInt(range.to, 16); c++) {
      const text = `a${String.fromCodePoint(c)}b`;
      const single = `a${escaped(c)}b`;
      assert.equal(displayText(text, false), single, `U+${c.toString(16)} (${range.name})`);
      assert.equal(displayText(text, true), multilineSafe.has(c) ? text : single, `U+${c.toString(16)}`);
      checked++;
    }
  }
  assert.ok(checked > 200);
});

test("the safe look-alikes of the shared fixture are shown as they are", () => {
  for (const { char, name } of fixture.safe) {
    const text = `a${String.fromCodePoint(parseInt(char, 16))}b`;
    assert.equal(displayText(text, false), text, name);
  }
});
