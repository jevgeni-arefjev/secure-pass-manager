// Behaviour of the secret helpers (search, title paths), through their public functions.

import assert from "node:assert/strict";
import { test } from "node:test";

import type { SecretSummary } from "../src/api.js";
import { filterSecrets, secretPath } from "../src/secrets.js";

/**
 * A secret as listed, titled `title`, with the given other fields.
 *
 * @example
 * summary("GitHub", { username: "alice" });
 */
function summary(title: string, fields: Partial<SecretSummary> = {}): SecretSummary {
  return {
    title,
    username: null,
    url: null,
    tags: [],
    has_password: false,
    has_notes: false,
    custom_fields: [],
    created_at: 1_800_000_000,
    updated_at: 1_800_000_000,
    ...fields,
  };
}

const SECRETS = [
  summary("GitHub", { username: "alice", url: "https://github.com", tags: ["work", "code"] }),
  summary("Bank", { username: "alice.smith@example.com", tags: ["finance"] }),
  summary("Mail", { url: "https://mail.example.com" }),
  summary("Notes only", { has_notes: true, custom_fields: [{ name: "github token", hidden: true }] }),
];

/**
 * The titles of the secrets in `SECRETS` matching `query`.
 *
 * @example
 * titles("alice"); // ["GitHub", "Bank"]
 */
function titles(query: string): string[] {
  return filterSecrets(SECRETS, query).map((secret) => secret.title);
}

test("an empty or blank query matches every secret, in order", () => {
  assert.deepEqual(titles(""), ["GitHub", "Bank", "Mail", "Notes only"]);
  assert.deepEqual(titles("   "), ["GitHub", "Bank", "Mail", "Notes only"]);
});

test("search matches title, username, URL and tags, ignoring case", () => {
  assert.deepEqual(titles("GITHUB"), ["GitHub"]);
  assert.deepEqual(titles("smith"), ["Bank"]);
  assert.deepEqual(titles("mail.example"), ["Mail"]);
  assert.deepEqual(titles("finance"), ["Bank"]);
  assert.deepEqual(titles("alice"), ["GitHub", "Bank"]);
});

test("search ignores custom field names and other metadata", () => {
  assert.deepEqual(titles("token"), []);
  assert.deepEqual(titles("1800000000"), []);
});

test("every word of the query must match, in any of the fields", () => {
  assert.deepEqual(titles("alice work"), ["GitHub"]);
  assert.deepEqual(titles("  alice   finance "), ["Bank"]);
  assert.deepEqual(titles("alice mail"), []);
});

test("search matches non-ASCII text ignoring case", () => {
  const secrets = [summary("Ärzte"), summary("ΣΟΦΙΑ")];
  assert.deepEqual(
    filterSecrets(secrets, "ärz").map((secret) => secret.title),
    ["Ärzte"],
  );
  assert.deepEqual(
    filterSecrets(secrets, "σοφ").map((secret) => secret.title),
    ["ΣΟΦΙΑ"],
  );
});

test("search treats regex and markup characters literally", () => {
  const secrets = [summary("a.b (old)"), summary("axb"), summary("<b>bold</b>")];
  assert.deepEqual(
    filterSecrets(secrets, "a.b").map((secret) => secret.title),
    ["a.b (old)"],
  );
  assert.deepEqual(
    filterSecrets(secrets, "(old").map((secret) => secret.title),
    ["a.b (old)"],
  );
  assert.deepEqual(
    filterSecrets(secrets, "<b>").map((secret) => secret.title),
    ["<b>bold</b>"],
  );
});

test("a title becomes one percent-encoded path segment", () => {
  assert.equal(secretPath("GitHub"), "/api/secrets/GitHub");
  assert.equal(secretPath("my bank / savings"), "/api/secrets/my%20bank%20%2F%20savings");
  assert.equal(secretPath("50% off?#&"), "/api/secrets/50%25%20off%3F%23%26");
  assert.equal(secretPath("日本"), "/api/secrets/%E6%97%A5%E6%9C%AC");
});

test("dot titles get a trailing space so URL parsing can't resolve them into other paths", () => {
  assert.equal(secretPath(".."), "/api/secrets/..%20");
  assert.equal(secretPath("."), "/api/secrets/.%20");
  assert.equal(secretPath("..."), "/api/secrets/...");
  for (const title of ["..", ".", "...", "a/../b"]) {
    const url = new URL(secretPath(title), "https://localhost:8443");
    const segment = url.pathname.slice("/api/secrets/".length);
    assert.ok(url.pathname.startsWith("/api/secrets/") && segment !== "", title);
    assert.equal(decodeURIComponent(segment).trim(), title);
  }
});
