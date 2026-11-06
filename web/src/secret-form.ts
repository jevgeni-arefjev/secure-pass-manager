// Pure helpers for the add and edit forms: the form's values, the request body built
// from them, the edit form's starting values from a stored secret, and where each
// problem of a refused secret is shown.
//
// Security: the edit form never holds a stored hidden value. An untouched hidden field
// is sent as `{"unchanged": true}` and the server keeps what it has stored.

import type { CustomFieldRequest, FieldProblem, HiddenInput, SecretDetail, SecretRequest } from "./api.js";
import { displayText } from "./text.js";

/** A custom field as the form holds it; `unchanged` means keep the stored hidden value. */
export interface CustomFieldValues {
  name: string;
  hidden: boolean;
  value: string;
  unchanged: boolean;
}

/**
 * Everything the secret form holds, as typed. `tags` is comma-separated;
 * `passwordUnchanged` means keep the stored password and ignore `password`.
 */
export interface SecretFormValues {
  title: string;
  username: string;
  password: string;
  passwordUnchanged: boolean;
  url: string;
  notes: string;
  tags: string;
  customFields: CustomFieldValues[];
}

/** The marker asking the server to keep a stored hidden value. */
const UNCHANGED: HiddenInput = { unchanged: true };

/**
 * The values of an empty add form.
 *
 * @example
 * const values = { ...emptyValues(), title: "GitHub" };
 */
export function emptyValues(): SecretFormValues {
  return {
    title: "",
    username: "",
    password: "",
    passwordUnchanged: false,
    url: "",
    notes: "",
    tags: "",
    customFields: [],
  };
}

/**
 * A new, empty custom field for the form.
 *
 * @example
 * addRow(emptyCustomField());
 */
export function emptyCustomField(): CustomFieldValues {
  return { name: "", hidden: false, value: "", unchanged: false };
}

/**
 * The edit form's starting values for `secret`: every plain field filled in, every
 * hidden field marked unchanged and left empty (the browser never has its value).
 *
 * @example
 * const values = editValues(await api.getSecret("GitHub"));
 */
export function editValues(secret: SecretDetail): SecretFormValues {
  return {
    title: secret.title,
    username: secret.username ?? "",
    password: "",
    passwordUnchanged: secret.has_password,
    url: secret.url ?? "",
    notes: secret.notes ?? "",
    tags: secret.tags.join(", "),
    customFields: secret.custom_fields.map((field) =>
      field.hidden
        ? { name: field.name, hidden: true, value: "", unchanged: true }
        : { name: field.name, hidden: false, value: field.value, unchanged: false },
    ),
  };
}

/**
 * The tags in a comma-separated `text`, each trimmed, blanks dropped.
 *
 * @example
 * parseTags(" work, code ,"); // ["work", "code"]
 */
export function parseTags(text: string): string[] {
  return text
    .split(",")
    .map((tag) => tag.trim())
    .filter((tag) => tag !== "");
}

/**
 * The add or edit request body for `values`. Blank optional fields are left out; an
 * empty password is left out too, so the server generates one; untouched hidden
 * fields are sent as `{"unchanged": true}`. Values are otherwise sent as typed: the
 * server validates every field, trims and NFC-normalises the non-hidden single-line
 * ones, and keeps hidden values exactly as entered.
 *
 * @example
 * await api.addSecret(secretRequest(values));
 */
export function secretRequest(values: SecretFormValues): SecretRequest {
  const request: SecretRequest = {
    title: values.title,
    tags: parseTags(values.tags),
    custom_fields: values.customFields.map(
      (field): CustomFieldRequest => ({
        name: field.name,
        hidden: field.hidden,
        value: field.hidden && field.unchanged ? UNCHANGED : field.value,
      }),
    ),
  };
  if (values.passwordUnchanged) {
    request.password = UNCHANGED;
  } else if (values.password !== "") {
    request.password = values.password;
  }
  for (const key of ["username", "url", "notes"] as const) {
    if (values[key].trim() !== "") {
      request[key] = values[key];
    }
  }
  return request;
}

/** The messages for one custom field row, by the part at fault. */
export interface CustomFieldErrors {
  name: string[];
  value: string[];
}

/**
 * Where a refused secret's problems go on the form: `fields` by request field name
 * (including `custom_fields` for the custom fields' own line), `customFields` by row
 * index, and `general` for anything the form has no place for.
 */
export interface PlacedErrors {
  fields: Record<string, string[]>;
  customFields: Record<number, CustomFieldErrors>;
  general: string[];
}

/** The request fields the secret form has an error line for. */
const FORM_FIELDS = new Set(["title", "username", "password", "url", "notes", "tags", "custom_fields"]);

/**
 * Places each problem of a refused secret: a tag problem on the tags input, naming the
 * tag (from `tags`, the request's tags) or else its position; a custom field problem
 * on its row's name or value; a problem without an index on its field's line.
 *
 * Security: messages come from the server and never contain a value; a named tag is
 * the user's own input, often refused for control or bidi characters, so it is
 * escaped ({@link displayText}) and must still be shown as text (`textContent`).
 *
 * @example
 * const placed = placeFieldErrors(err.fields, request.tags);
 * placed.fields.title; // ["title must be 1-64 characters, ..."]
 */
export function placeFieldErrors(problems: readonly FieldProblem[], tags: readonly string[]): PlacedErrors {
  const placed: PlacedErrors = { fields: {}, customFields: {}, general: [] };
  const addTo = (field: string, message: string): void => {
    (placed.fields[field] ??= []).push(message);
  };
  for (const { field, index, part, message } of problems) {
    if (!FORM_FIELDS.has(field)) {
      placed.general.push(message);
    } else if (index === undefined) {
      addTo(field, message);
    } else if (field === "tags") {
      const tag = tags[index];
      const name = tag === undefined ? `${index + 1}` : `"${displayText(tag, false)}"`;
      addTo(field, `Tag ${name}: ${message}`);
    } else if (field === "custom_fields" && part !== undefined) {
      (placed.customFields[index] ??= { name: [], value: [] })[part].push(message);
    } else if (field === "custom_fields") {
      addTo(field, `Custom field ${index + 1}: ${message}`);
    } else {
      addTo(field, message);
    }
  }
  return placed;
}
