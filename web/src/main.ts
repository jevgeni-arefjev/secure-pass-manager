// Client entry point: the create, unlock and (for now empty) vault pages.
//
// Security: the DOM is built only with createElement/textContent, never innerHTML or
// other HTML sinks; the CSP's `require-trusted-types-for 'script'` makes any such sink
// throw at runtime. Vault data and the CSRF token live in memory only; any 401 wipes
// them and shows the unlock page. Master password inputs are cleared once submitted.

import { Api, ApiError, type SessionInfo, type UnlockRequest } from "./api.js";
import { checkNewMasterPassword, parseIdleTimeout } from "./forms.js";

/** Default idle timeout shown in the forms; the server uses the same default. */
const DEFAULT_IDLE_MINUTES = "5";

/** Where every page is rendered. */
const root = document.getElementById("app");

/** Whether a vault page is showing, i.e. there is vault data on screen to wipe. */
let vaultShown = false;

/** The vault-web API; a 401 while a vault is shown wipes it and shows the unlock page. */
const api = new Api(window.fetch.bind(window), () => {
  if (vaultShown) {
    showUnlock("Your vault was locked.");
  }
});

/** A text input or password input with its label and its own error line. */
interface Field {
  input: HTMLInputElement;
  error: HTMLElement;
  row: HTMLElement;
}

/**
 * A labelled input of `type` named `name`, with an error line under it.
 *
 * @example
 * const vaultname = field("Vaultname", "vaultname", "text", "username");
 */
function field(label: string, name: string, type: string, autocomplete: string): Field {
  const input = document.createElement("input");
  input.type = type;
  input.name = name;
  input.id = `field-${name}`;
  input.autocomplete = autocomplete as AutoFill;
  const labelElement = document.createElement("label");
  labelElement.htmlFor = input.id;
  labelElement.textContent = label;
  const error = document.createElement("p");
  error.className = "field-error";
  error.setAttribute("role", "alert");
  const row = document.createElement("div");
  row.className = "field";
  row.append(labelElement, input, error);
  return { input, error, row };
}

/**
 * An element `tag` holding `text`.
 *
 * @example
 * const heading = textElement("h1", "Unlock your vault");
 */
function textElement<K extends keyof HTMLElementTagNameMap>(tag: K, text: string): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  element.textContent = text;
  return element;
}

/**
 * A button of `type` labelled `text`.
 *
 * @example
 * const lock = button("Lock", "button");
 */
function button(text: string, type: "button" | "submit"): HTMLButtonElement {
  const element = textElement("button", text);
  element.type = type;
  return element;
}

/**
 * Replaces the page contents with `children`.
 *
 * @example
 * render(textElement("h1", "Vault"));
 */
function render(...children: Node[]): void {
  vaultShown = false;
  root?.replaceChildren(...children);
}

/**
 * The idle timeout field, prefilled with the default.
 *
 * @example
 * const idle = idleField();
 */
function idleField(): Field {
  const idle = field("Lock after idle minutes (1-60)", "idle_timeout_minutes", "text", "off");
  idle.input.inputMode = "numeric";
  idle.input.value = DEFAULT_IDLE_MINUTES;
  return idle;
}

/**
 * Shows `err` next to the field it names, else in `general`.
 *
 * @example
 * showError(err, { vaultname }, formError);
 */
function showError(err: unknown, fields: Record<string, Field>, general: HTMLElement): void {
  const message = err instanceof ApiError ? err.message : "the server could not be reached";
  const target = err instanceof ApiError && err.field !== undefined ? fields[err.field] : undefined;
  (target?.error ?? general).textContent = message;
}

/**
 * Clears every field error and the general error.
 *
 * @example
 * clearErrors([vaultname, password], formError);
 */
function clearErrors(fields: Field[], general: HTMLElement): void {
  for (const { error } of fields) {
    error.textContent = "";
  }
  general.textContent = "";
}

/**
 * The create or unlock request from the form values; `null` (with the error shown) if
 * the idle timeout is invalid.
 *
 * @example
 * const request = unlockRequest(vaultname, password, idle);
 */
function unlockRequest(vaultname: Field, password: Field, idle: Field): UnlockRequest | null {
  const timeout = parseIdleTimeout(idle.input.value);
  if (!timeout.ok) {
    idle.error.textContent = timeout.error;
    return null;
  }
  const request: UnlockRequest = { vaultname: vaultname.input.value, master_password: password.input.value };
  if (timeout.minutes !== undefined) {
    request.idle_timeout_minutes = timeout.minutes;
  }
  return request;
}

/**
 * Shows the unlock page, with an optional `notice` (e.g. after an auto-lock).
 *
 * @example
 * showUnlock("Your vault was locked.");
 */
function showUnlock(notice?: string): void {
  const vaultname = field("Vaultname", "vaultname", "text", "username");
  const password = field("Master password", "master_password", "password", "current-password");
  const idle = idleField();
  const formError = textElement("p", "");
  formError.className = "form-error";
  formError.setAttribute("role", "alert");
  const submit = button("Unlock", "submit");
  const form = document.createElement("form");
  form.append(vaultname.row, password.row, idle.row, formError, submit);

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    clearErrors([vaultname, password, idle], formError);
    const request = unlockRequest(vaultname, password, idle);
    if (request === null) {
      return;
    }
    password.input.value = "";
    submit.disabled = true;
    api
      .unlock(request)
      .then(showVault, (err: unknown) => {
        showError(err, { vaultname, idle_timeout_minutes: idle }, formError);
        submit.disabled = false;
      });
  });

  const create = button("Create a new vault", "button");
  create.className = "link";
  create.addEventListener("click", () => showCreate());
  const children: Node[] = [textElement("h1", "Unlock your vault")];
  if (notice !== undefined) {
    const note = textElement("p", notice);
    note.className = "notice";
    children.push(note);
  }
  render(...children, form, create);
  vaultname.input.focus();
}

/**
 * Shows the create page: vaultname, master password twice and idle timeout.
 *
 * @example
 * showCreate();
 */
function showCreate(): void {
  const vaultname = field("Vaultname", "vaultname", "text", "username");
  const hint = textElement("p", "1-32 letters, digits, - or _, starting with a letter or digit.");
  hint.className = "hint";
  vaultname.row.insertBefore(hint, vaultname.error);
  const password = field("Master password (at least 12 characters)", "master_password", "password", "new-password");
  const confirmation = field("Master password again", "confirm_master_password", "password", "new-password");
  const idle = idleField();
  const formError = textElement("p", "");
  formError.className = "form-error";
  formError.setAttribute("role", "alert");
  const submit = button("Create vault", "submit");
  const form = document.createElement("form");
  form.append(vaultname.row, password.row, confirmation.row, idle.row, formError, submit);
  const fields = [vaultname, password, confirmation, idle];

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    clearErrors(fields, formError);
    const mismatch = checkNewMasterPassword(password.input.value, confirmation.input.value);
    if (mismatch !== null) {
      confirmation.error.textContent = mismatch;
      return;
    }
    const request = unlockRequest(vaultname, password, idle);
    if (request === null) {
      return;
    }
    password.input.value = "";
    confirmation.input.value = "";
    submit.disabled = true;
    api
      .createVault(request)
      .then(showVault, (err: unknown) => {
        showError(
          err,
          { vaultname, master_password: password, idle_timeout_minutes: idle },
          formError,
        );
        submit.disabled = false;
      });
  });

  const back = button("Unlock an existing vault", "button");
  back.className = "link";
  back.addEventListener("click", () => showUnlock());
  render(textElement("h1", "Create a vault"), form, back);
  vaultname.input.focus();
}

/**
 * Shows the unlocked vault: its name, (for now) no secrets, and the Lock button.
 *
 * @example
 * api.unlock(request).then(showVault);
 */
function showVault(session: SessionInfo): void {
  const lock = button("Lock", "button");
  const status = textElement("p", "");
  status.setAttribute("role", "alert");
  lock.addEventListener("click", () => {
    lock.disabled = true;
    api.lock().then(
      () => showUnlock("Vault locked."),
      () => {
        status.textContent = "Locking failed; close the browser to be safe.";
        lock.disabled = false;
      },
    );
  });
  const header = document.createElement("header");
  header.append(textElement("h1", session.vaultname), lock);
  const idle = textElement(
    "p",
    `Locks itself after ${session.idle_timeout_minutes} idle minute${session.idle_timeout_minutes === 1 ? "" : "s"}.`,
  );
  idle.className = "hint";
  render(header, idle, status, textElement("p", "No secrets yet."));
  vaultShown = true;
}

if (root !== null) {
  api.session().then(showVault, () => showUnlock());
}
