// Behaviour of the secret form helpers: form values to the add/edit request body, and
// a stored secret to the edit form's starting values.

import assert from "node:assert/strict";
import { test } from "node:test";

import { editValues, emptyValues, parseTags, secretRequest } from "../src/secret-form.js";

test("tags: comma-separated, trimmed, blanks dropped", () => {
  assert.deepEqual(parseTags(" work, code ,,  "), ["work", "code"]);
  assert.deepEqual(parseTags(""), []);
  assert.deepEqual(parseTags("a b, c"), ["a b", "c"]);
});

test("blank optional fields and an empty password are left out of the request", () => {
  const values = { ...emptyValues(), title: "GitHub", username: "  ", notes: "\n" };
  assert.deepEqual(secretRequest(values), { title: "GitHub", tags: [], custom_fields: [] });
});

test("filled fields are sent as typed", () => {
  const values = {
    ...emptyValues(),
    title: "GitHub",
    username: "alice",
    password: " pa55 ",
    url: "https://github.com",
    notes: "line one\nline two",
    tags: "work, code",
    customFields: [
      { name: "region", hidden: false, value: "eu-west-1", unchanged: false },
      { name: "pin", hidden: true, value: "1234", unchanged: false },
    ],
  };
  assert.deepEqual(secretRequest(values), {
    title: "GitHub",
    username: "alice",
    password: " pa55 ",
    url: "https://github.com",
    notes: "line one\nline two",
    tags: ["work", "code"],
    custom_fields: [
      { name: "region", hidden: false, value: "eu-west-1" },
      { name: "pin", hidden: true, value: "1234" },
    ],
  });
});

test("untouched hidden fields are sent as unchanged, never with a value", () => {
  const values = {
    ...emptyValues(),
    title: "GitHub",
    passwordUnchanged: true,
    customFields: [{ name: "recovery code", hidden: true, value: "", unchanged: true }],
  };
  assert.deepEqual(secretRequest(values), {
    title: "GitHub",
    password: { unchanged: true },
    tags: [],
    custom_fields: [{ name: "recovery code", hidden: true, value: { unchanged: true } }],
  });
});

test("the edit form starts from the stored secret, hidden values unchanged and never filled", () => {
  const values = editValues({
    title: "GitHub",
    username: "alice",
    url: null,
    notes: "notes",
    tags: ["work", "code"],
    has_password: true,
    created_at: 1,
    updated_at: 2,
    custom_fields: [
      { name: "region", hidden: false, value: "eu-west-1" },
      { name: "recovery code", hidden: true },
    ],
  });
  assert.deepEqual(values, {
    title: "GitHub",
    username: "alice",
    password: "",
    passwordUnchanged: true,
    url: "",
    notes: "notes",
    tags: "work, code",
    customFields: [
      { name: "region", hidden: false, value: "eu-west-1", unchanged: false },
      { name: "recovery code", hidden: true, value: "", unchanged: true },
    ],
  });
});

test("a stored secret without a password starts with an empty password, to be generated", () => {
  const values = editValues({
    title: "t",
    username: null,
    url: null,
    notes: null,
    tags: [],
    has_password: false,
    created_at: 1,
    updated_at: 1,
    custom_fields: [],
  });
  assert.equal(values.passwordUnchanged, false);
  assert.equal(values.password, "");
});
