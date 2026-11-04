// Behaviour of the URL scheme allowlist, through its public function.

import assert from "node:assert/strict";
import { test } from "node:test";

import { safeHref } from "../src/url.js";

test("http and https URLs are allowed, normalised", () => {
  assert.equal(safeHref("https://github.com/login"), "https://github.com/login");
  assert.equal(safeHref("  HTTP://Example.com  "), "http://example.com/");
});

test("script and other schemes are refused", () => {
  for (const url of [
    "javascript:alert(1)",
    " JavaScript:alert(1)",
    "java\tscript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
    "blob:https://example.com/uuid",
  ]) {
    assert.equal(safeHref(url), null, url);
  }
});

test("relative and unparsable URLs are refused", () => {
  for (const url of ["", "github.com", "/login", "//evil.example", "https://"]) {
    assert.equal(safeHref(url), null, url);
  }
});
