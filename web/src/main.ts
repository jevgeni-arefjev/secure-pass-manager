// Client entry point: the create and unlock pages, and the vault's secret list,
// secret detail and add/edit pages.
//
// Security: the DOM is built only with createElement/textContent, never innerHTML or
// other HTML sinks; the CSP's `require-trusted-types-for 'script'` makes any such sink
// throw at runtime. Field values are shown through `displayText`, and a secret's URL
// is a link only for http/https (`safeHref`). Vault data and the CSRF token live in
// memory only; any 401 wipes them and shows the unlock page, and an open vault page
// checks its session every 30 s and when the tab returns, so a session the server
// ended doesn't leave vault data on screen. Master password inputs are cleared once
// submitted. Hidden fields are masked; one reaches the browser only when Reveal or
// Copy asks for it (an audited request), and then lives only in the element showing
// it (until hidden, the page is left, or 30 s) or in the clipboard (cleared after
// 20 s if possible). The edit form never holds a stored hidden value:
// untouched hidden fields are sent as unchanged and kept by the server.

import {
  Api,
  ApiError,
  PASSWORD_FIELD,
  type SavedSecret,
  type SecretDetail,
  type SecretSummary,
  type SessionInfo,
  type UnlockRequest,
} from "./api.js";
import { checkNewMasterPassword, parseIdleTimeout } from "./forms.js";
import { copyThenClear, CLEAR_CLIPBOARD_AFTER_MS, RevealedField } from "./reveal.js";
import { type CustomFieldValues, editValues, emptyCustomField, emptyValues, secretRequest } from "./secret-form.js";
import { filterSecrets } from "./secrets.js";
import { watchSession } from "./session-watch.js";
import { displayText } from "./text.js";
import { safeHref } from "./url.js";

/** Default idle timeout shown in the forms; the server uses the same default. */
const DEFAULT_IDLE_MINUTES = "5";

/** Where every page is rendered. */
const root = document.getElementById("app");

/** What every hidden field is shown as; its length says nothing about the value. */
const MASK = "••••••••";

/** Bumped on every page change, so a response for an earlier page is dropped. */
let pageGeneration = 0;

/** What to do when the current page is left, e.g. mask revealed values. */
let leaveHandlers: (() => void)[] = [];

/**
 * The open session; set from unlock to lock, i.e. while vault data may be on screen.
 * `showUnlock` clears it.
 */
let session: SessionInfo | null = null;

/** Stops the periodic session check; set while a vault is open. */
let stopWatchingSession: (() => void) | null = null;

/** The vault-web API; a 401 while a vault is open wipes it and shows the unlock page. */
const api = new Api(window.fetch.bind(window), () => {
  if (session !== null) {
    showUnlock("Your vault was locked.");
  }
});

/** Anything with its own error line, where a field-level server error is shown. */
interface ErrorTarget {
  error: HTMLElement;
}

/** A text input or password input with its label and its own error line. */
interface Field extends ErrorTarget {
  input: HTMLInputElement;
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
  const error = fieldErrorLine();
  const row = document.createElement("div");
  row.className = "field";
  row.append(labelElement, input, error);
  return { input, error, row };
}

/**
 * An empty error line for one field, announced by screen readers when filled.
 *
 * @example
 * const error = fieldErrorLine();
 */
function fieldErrorLine(): HTMLElement {
  const error = document.createElement("p");
  error.className = "field-error";
  error.setAttribute("role", "alert");
  return error;
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
  leavePage();
  pageGeneration += 1;
  root?.replaceChildren(...children);
}

/**
 * Runs and forgets the current page's leave handlers; on every page change, and when
 * the browser leaves or freezes the page.
 *
 * @example
 * window.addEventListener("pagehide", leavePage);
 */
function leavePage(): void {
  const handlers = leaveHandlers;
  leaveHandlers = [];
  for (const handler of handlers) {
    handler();
  }
}

/**
 * Runs `handler` when the page now shown is left. Register only after the page is
 * rendered, or rendering it runs the handler at once.
 *
 * @example
 * onLeave(() => field.hide());
 */
function onLeave(handler: () => void): void {
  leaveHandlers.push(handler);
}

/**
 * An empty or `text`-holding error line that screen readers announce.
 *
 * @example
 * const formError = alertLine();
 */
function alertLine(text = ""): HTMLElement {
  const line = textElement("p", text);
  line.className = "form-error";
  line.setAttribute("role", "alert");
  return line;
}

/**
 * A notice line, e.g. "Vault locked." above a page.
 *
 * @example
 * children.push(noticeLine("Secret deleted."));
 */
function noticeLine(text: string): HTMLElement {
  const note = textElement("p", text);
  note.className = "notice";
  return note;
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
function showError(err: unknown, fields: Record<string, ErrorTarget>, general: HTMLElement): void {
  const message = errorMessage(err);
  const target = err instanceof ApiError && err.field !== undefined ? fields[err.field] : undefined;
  (target?.error ?? general).textContent = message;
}

/**
 * What to tell the user about a failed request: the server's message, or that it
 * could not be reached.
 *
 * @example
 * status.textContent = `Delete failed: ${errorMessage(err)}.`;
 */
function errorMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : "the server could not be reached";
}

/**
 * Clears every field error and the general error.
 *
 * @example
 * clearErrors([vaultname, password], formError);
 */
function clearErrors(fields: ErrorTarget[], general: HTMLElement): void {
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
 * Shows the unlock page, with an optional `notice` (e.g. after an auto-lock), forgets
 * the session and stops checking it.
 *
 * @example
 * showUnlock("Your vault was locked.");
 */
function showUnlock(notice?: string): void {
  session = null;
  stopWatchingSession?.();
  stopWatchingSession = null;
  const vaultname = field("Vaultname", "vaultname", "text", "username");
  const password = field("Master password", "master_password", "password", "current-password");
  const idle = idleField();
  const formError = alertLine();
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
    children.push(noticeLine(notice));
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
  const formError = alertLine();
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
 * Shows the unlocked vault's secret list and starts checking the session; the entry
 * point after create, unlock and a page load with a live session.
 *
 * @example
 * api.unlock(request).then(showVault);
 */
function showVault(info: SessionInfo): void {
  session = info;
  stopWatchingSession?.();
  stopWatchingSession = watchSession(() => api.session(), document);
  showList();
}

/**
 * Renders a vault page: the vaultname with the Lock button, the auto-lock hint, a
 * status line, and `content`.
 *
 * @example
 * vaultPage(textElement("p", "Loading…"));
 */
function vaultPage(...content: Node[]): void {
  if (session === null) {
    showUnlock();
    return;
  }
  const lock = button("Lock", "button");
  const status = alertLine();
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
  const minutes = session.idle_timeout_minutes;
  const idle = textElement("p", `Locks itself after ${minutes} idle minute${minutes === 1 ? "" : "s"}.`);
  idle.className = "hint";
  render(header, idle, status, ...content);
}

/**
 * Shows a vault page saying "Loading…", runs `load`, and shows its result with
 * `show`. A failure goes to `onFailure` if it returns `true`, else it is shown on the
 * page.
 *
 * A result arriving after another page was shown is dropped, so a slow response
 * can't replace the page the user moved on to. That covers a 401 too: the API client
 * has already shown the unlock page.
 *
 * @example
 * loadVaultPage(() => api.listSecrets(), (secrets) => renderList(secrets));
 */
function loadVaultPage<T>(load: () => Promise<T>, show: (value: T) => void, onFailure?: (err: unknown) => boolean): void {
  vaultPage(textElement("p", "Loading…"));
  const generation = pageGeneration;
  load().then(
    (value) => {
      if (generation === pageGeneration) {
        show(value);
      }
    },
    (err: unknown) => {
      if (generation === pageGeneration && onFailure?.(err) !== true) {
        const message = errorMessage(err);
        vaultPage(alertLine(`Could not load: ${message}.`));
      }
    },
  );
}

/**
 * Loads the secret list and shows it, with an optional `notice` above it.
 *
 * @example
 * showList("That secret no longer exists.");
 */
function showList(notice?: string): void {
  loadVaultPage(
    () => api.listSecrets(),
    (secrets) => renderList(secrets, notice),
  );
}

/**
 * Renders the secret list with a search box; searching filters the loaded list in the
 * browser and sends nothing to the server.
 *
 * @example
 * renderList(await api.listSecrets());
 */
function renderList(secrets: SecretSummary[], notice?: string): void {
  const search = field("Search title, username, URL or tags", "search", "search", "off");
  search.input.spellcheck = false;
  const list = document.createElement("ul");
  list.className = "secrets";
  const empty = textElement("p", "");
  empty.className = "hint";
  /**
   * Shows the secrets matching the current search, or why none are shown.
   *
   * @example
   * search.input.addEventListener("input", update);
   */
  const update = (): void => {
    const shown = filterSecrets(secrets, search.input.value);
    list.replaceChildren(...shown.map(secretItem));
    empty.textContent =
      secrets.length === 0 ? "No secrets yet." : shown.length === 0 ? "No secrets match the search." : "";
  };
  search.input.addEventListener("input", update);
  update();
  const add = button("Add secret", "button");
  add.addEventListener("click", () => showSecretForm(null));
  const children: Node[] = [];
  if (notice !== undefined) {
    children.push(noticeLine(notice));
  }
  vaultPage(...children, add, search.row, empty, list);
  search.input.focus();
}

/**
 * One list item: a button opening the secret, showing its title, username, URL (as
 * text) and tags.
 *
 * @example
 * list.append(secretItem(secret));
 */
function secretItem(secret: SecretSummary): HTMLLIElement {
  const open = document.createElement("button");
  open.type = "button";
  open.className = "secret";
  open.append(textElement("strong", displayText(secret.title, false)));
  for (const text of [secret.username, secret.url]) {
    if (text !== null) {
      open.append(textElement("span", displayText(text, false)));
    }
  }
  if (secret.tags.length > 0) {
    open.append(tagList(secret.tags));
  }
  open.addEventListener("click", () => showDetail(secret.title));
  const item = document.createElement("li");
  item.append(open);
  return item;
}

/**
 * The tags of a secret as a list of small labels.
 *
 * @example
 * row.append(tagList(["work", "code"]));
 */
function tagList(tags: string[]): HTMLUListElement {
  const list = document.createElement("ul");
  list.className = "tags";
  list.append(...tags.map((tag) => textElement("li", displayText(tag, false))));
  return list;
}

/**
 * Loads the secret titled `title` and shows it; if it is gone, shows the list again.
 *
 * @example
 * showDetail("GitHub");
 */
function showDetail(title: string): void {
  loadVaultPage(
    () => api.getSecret(title),
    (secret) => renderDetail(secret),
    (err) => {
      const gone = err instanceof ApiError && err.status === 404;
      if (gone) {
        showList("That secret no longer exists.");
      }
      return gone;
    },
  );
}

/**
 * Renders one secret: every field that is set, hidden fields masked, the URL as a
 * link only if it is http or https; with Edit and Delete buttons and an optional
 * `notice` (e.g. after a save).
 *
 * @example
 * renderDetail(await api.getSecret("GitHub"));
 */
function renderDetail(secret: SecretDetail, notice?: string): void {
  const fields = document.createElement("dl");
  /**
   * Appends a `label` / `value` pair to the field list.
   *
   * @example
   * row("Username", text("alice"));
   */
  const row = (label: string, value: Node): void => {
    const dd = document.createElement("dd");
    dd.append(value);
    fields.append(textElement("dt", label), dd);
  };
  /**
   * `value` as a text node, escaped by `displayText`.
   *
   * @example
   * row("Username", text(secret.username));
   */
  const text = (value: string): Text => document.createTextNode(displayText(value, false));
  if (secret.username !== null) {
    row("Username", text(secret.username));
  }
  const hiddenFields: RevealedField[] = [];
  if (secret.has_password) {
    row("Password", hiddenValue(secret.title, PASSWORD_FIELD, hiddenFields));
  }
  if (secret.url !== null) {
    row("URL", urlValue(secret.url));
  }
  if (secret.notes !== null) {
    const notes = textElement("p", displayText(secret.notes, true));
    notes.className = "notes";
    row("Notes", notes);
  }
  if (secret.tags.length > 0) {
    row("Tags", tagList(secret.tags));
  }
  for (const custom of secret.custom_fields) {
    row(
      displayText(custom.name, false),
      custom.hidden ? hiddenValue(secret.title, custom.name, hiddenFields) : text(custom.value),
    );
  }
  row("Created", text(timestamp(secret.created_at)));
  row("Updated", text(timestamp(secret.updated_at)));

  const back = button("All secrets", "button");
  back.className = "link";
  back.addEventListener("click", () => showList());
  const edit = button("Edit", "button");
  edit.addEventListener("click", () => showSecretForm(secret));
  const status = alertLine();
  const remove = button("Delete", "button");
  remove.addEventListener("click", () => deleteSecret(secret.title, remove, status));
  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(edit, remove);
  const children: Node[] = [back];
  if (notice !== undefined) {
    children.push(noticeLine(notice));
  }
  vaultPage(...children, textElement("h2", displayText(secret.title, false)), actions, status, fields);
  onLeave(() => {
    for (const field of hiddenFields) {
      field.hide();
    }
  });
  back.focus();
}

/**
 * A hidden field of the secret titled `title`: its mask with Reveal/Hide and Copy
 * buttons, and a status line. `field` is {@link PASSWORD_FIELD} or the custom field's name. The
 * field's {@link RevealedField} is added to `fields`, for masking when the page is left.
 *
 * Security: each Reveal and each Copy fetches the one value anew (an audited request);
 * a response arriving after the page changed is dropped. The revealed value goes only
 * into the element showing it, or only to the clipboard.
 *
 * @example
 * row("Password", hiddenValue("GitHub", PASSWORD_FIELD, hiddenFields));
 */
function hiddenValue(title: string, field: string, fields: RevealedField[]): HTMLElement {
  const value = masked();
  const toggle = button("Reveal", "button");
  const copy = button("Copy", "button");
  const status = textElement("span", "");
  status.className = "hint";
  status.setAttribute("role", "status");
  const onScreen = new RevealedField((revealed) => {
    if (revealed === null) {
      value.textContent = MASK;
      value.className = "masked";
      value.setAttribute("aria-label", "hidden");
      toggle.textContent = "Reveal";
    } else {
      value.textContent = displayText(revealed, false);
      value.className = "revealed";
      value.removeAttribute("aria-label");
      toggle.textContent = "Hide";
    }
  });
  fields.push(onScreen);
  /**
   * Asks the server to reveal the field and passes the value to `use`, unless the page
   * changed meanwhile; shows a failure in the status line. `buttonUsed` is disabled
   * while waiting.
   *
   * @example
   * fetchValue(toggle, (revealed) => onScreen.reveal(revealed));
   */
  const fetchValue = (buttonUsed: HTMLButtonElement, use: (revealed: string) => Promise<void> | void): void => {
    const generation = pageGeneration;
    buttonUsed.disabled = true;
    status.textContent = "";
    api
      .revealField(title, field)
      .then(async (revealed) => {
        if (generation === pageGeneration) {
          await use(revealed);
        }
      })
      .catch((err: unknown) => {
        if (generation === pageGeneration) {
          status.textContent = err instanceof ApiError ? `Failed: ${err.message}.` : "Failed.";
        }
      })
      .finally(() => {
        buttonUsed.disabled = false;
      });
  };
  toggle.addEventListener("click", () => {
    if (onScreen.isRevealed) {
      onScreen.hide();
    } else {
      fetchValue(toggle, (revealed) => onScreen.reveal(revealed));
    }
  });
  copy.addEventListener("click", () => {
    const clipboard = navigator.clipboard as Clipboard | undefined;
    if (clipboard === undefined) {
      status.textContent = "Copying is not available in this browser.";
      return;
    }
    fetchValue(copy, async (revealed) => {
      await copyThenClear(revealed, clipboard, () => document.hasFocus());
      status.textContent = `Copied; cleared in ${CLEAR_CLIPBOARD_AFTER_MS / 1000} s if this page has focus.`;
    });
  });
  const container = document.createElement("span");
  container.className = "hidden-field";
  container.append(value, toggle, copy, status);
  return container;
}

/**
 * Asks to confirm, then deletes the secret titled `title` and shows the list. A
 * failure is shown in `status`; a secret already gone shows the list too.
 *
 * @example
 * remove.addEventListener("click", () => deleteSecret(secret.title, remove, status));
 */
function deleteSecret(title: string, remove: HTMLButtonElement, status: HTMLElement): void {
  if (!window.confirm(`Delete the secret "${displayText(title, false)}"? This can't be undone.`)) {
    return;
  }
  const generation = pageGeneration;
  remove.disabled = true;
  status.textContent = "";
  api.deleteSecret(title).then(
    () => {
      if (generation === pageGeneration) {
        showList("Secret deleted.");
      }
    },
    (err: unknown) => {
      if (generation !== pageGeneration) {
        return;
      }
      if (err instanceof ApiError && err.status === 404) {
        showList("That secret no longer exists.");
        return;
      }
      status.textContent = `Delete failed: ${errorMessage(err)}.`;
      remove.disabled = false;
    },
  );
}

/** The control for a hidden value in the secret form, and whether it keeps the stored value. */
interface HiddenControl {
  element: HTMLElement;
  isUnchanged: () => boolean;
}

/**
 * The control for a hidden value: `input`, or, when `keepStored`, a mask with a Change
 * button that swaps `input` in (and then calls `onChange`).
 *
 * Security: a kept value is never in the browser; the form sends it as unchanged and
 * the server keeps what it has stored.
 *
 * @example
 * const control = hiddenControl(password.input, secret.has_password);
 */
function hiddenControl(input: HTMLInputElement, keepStored: boolean, onChange: () => void = () => {}): HiddenControl {
  input.remove();
  const element = document.createElement("span");
  element.className = "hidden-field";
  let unchanged = keepStored;
  if (unchanged) {
    const kept = textElement("span", "unchanged");
    kept.className = "hint";
    const change = button("Change", "button");
    change.addEventListener("click", () => {
      unchanged = false;
      element.replaceChildren(input);
      onChange();
      input.focus();
    });
    element.append(masked(), kept, change);
  } else {
    element.append(input);
  }
  return { element, isUnchanged: () => unchanged };
}

/** One custom field in the secret form: its row, its current values and a way to wipe it. */
interface CustomFieldRow {
  row: HTMLElement;
  values: () => CustomFieldValues;
  clear: () => void;
}

/** Numbers the custom field rows, so each input gets a unique ID for its label. */
let customFieldCount = 0;

/**
 * A custom field row: name, Hidden checkbox and value (masked while typing if hidden),
 * and a Remove button calling `onRemove`. A hidden field kept as stored can't be
 * renamed or made plain until Change is pressed, since the server finds the stored
 * value by name.
 *
 * @example
 * const row = customFieldRow(emptyCustomField(), () => {});
 */
function customFieldRow(initial: CustomFieldValues, onRemove: () => void): CustomFieldRow {
  customFieldCount += 1;
  /**
   * `control` with a label `text` before it, in one span; `suffix` makes its ID unique.
   *
   * @example
   * labelled("Name", name, "name");
   */
  const labelled = (text: string, control: HTMLInputElement, suffix: string): HTMLElement => {
    control.id = `custom-${suffix}-${customFieldCount}`;
    const label = textElement("label", text);
    label.htmlFor = control.id;
    const wrapper = document.createElement("span");
    wrapper.append(label, control);
    return wrapper;
  };
  const name = document.createElement("input");
  name.type = "text";
  name.autocomplete = "off";
  name.value = initial.name;
  const hidden = document.createElement("input");
  hidden.type = "checkbox";
  hidden.checked = initial.hidden;
  const value = document.createElement("input");
  value.autocomplete = "off";
  value.type = initial.hidden ? "password" : "text";
  value.value = initial.value;
  hidden.addEventListener("change", () => {
    value.type = hidden.checked ? "password" : "text";
  });
  name.readOnly = initial.unchanged;
  hidden.disabled = initial.unchanged;
  const valueLabel = labelled("Value", value, "value");
  const control = hiddenControl(value, initial.unchanged, () => {
    name.readOnly = false;
    hidden.disabled = false;
  });
  valueLabel.append(control.element);
  const remove = button("Remove", "button");
  const row = document.createElement("div");
  row.className = "custom-field";
  row.append(labelled("Name", name, "name"), labelled("Hidden", hidden, "hidden"), valueLabel, remove);
  remove.addEventListener("click", () => {
    value.value = "";
    row.remove();
    onRemove();
  });
  return {
    row,
    values: () => ({ name: name.value, hidden: hidden.checked, value: value.value, unchanged: control.isUnchanged() }),
    clear: () => {
      value.value = "";
    },
  };
}

/**
 * The labelled notes text area with its error line, holding `text`.
 *
 * @example
 * const notes = notesField(values.notes);
 */
function notesField(text: string): ErrorTarget & { input: HTMLTextAreaElement; row: HTMLElement } {
  const input = document.createElement("textarea");
  input.id = "field-notes";
  input.name = "notes";
  input.rows = 4;
  input.value = text;
  const label = textElement("label", "Notes (optional)");
  label.htmlFor = input.id;
  const error = fieldErrorLine();
  const row = document.createElement("div");
  row.className = "field";
  row.append(label, input, error);
  return { input, error, row };
}

/**
 * Shows the add form (`stored` is `null`) or the edit form for `stored`: title
 * (read-only when editing), username, password, URL, notes, tags and custom fields.
 * Saving shows the saved secret; server errors are shown next to their field.
 *
 * Security: when editing, hidden fields start as "unchanged" and are sent that way
 * unless Change is pressed, so the browser never holds a stored hidden value. Typed
 * hidden values are wiped from the inputs when the page is left. A 401 (e.g. a save
 * conflict with another session) shows the unlock page through the API client.
 *
 * @example
 * showSecretForm(null);   // add
 * showSecretForm(secret); // edit
 */
function showSecretForm(stored: SecretDetail | null): void {
  const values = stored === null ? emptyValues() : editValues(stored);
  const title = field("Title", "title", "text", "off");
  title.input.value = values.title;
  title.input.readOnly = stored !== null;
  const username = field("Username (optional)", "username", "text", "off");
  username.input.value = values.username;
  const password = field("Password", "password", "password", "new-password");
  const passwordControl = hiddenControl(password.input, values.passwordUnchanged);
  const passwordHint = textElement("p", "Leave empty to have a strong password generated.");
  passwordHint.className = "hint";
  password.row.insertBefore(passwordControl.element, password.error);
  password.row.insertBefore(passwordHint, password.error);
  const url = field("URL (optional)", "url", "text", "off");
  url.input.value = values.url;
  const notes = notesField(values.notes);
  const tags = field("Tags (comma-separated, optional)", "tags", "text", "off");
  tags.input.value = values.tags;

  const rows: CustomFieldRow[] = [];
  const customList = document.createElement("div");
  /**
   * Adds a custom field row holding `initial`.
   *
   * @example
   * addRow(emptyCustomField());
   */
  const addRow = (initial: CustomFieldValues): void => {
    const row = customFieldRow(initial, () => rows.splice(rows.indexOf(row), 1));
    rows.push(row);
    customList.append(row.row);
  };
  values.customFields.forEach(addRow);
  const addCustom = button("Add custom field", "button");
  addCustom.addEventListener("click", () => addRow(emptyCustomField()));
  const customError = fieldErrorLine();
  const custom = document.createElement("fieldset");
  custom.append(textElement("legend", "Custom fields"), customList, addCustom, customError);

  const formError = alertLine();
  const submit = button(stored === null ? "Add secret" : "Save", "submit");
  const form = document.createElement("form");
  form.append(title.row, username.row, password.row, url.row, notes.row, tags.row, custom, formError, submit);
  const targets: Record<string, ErrorTarget> = {
    title,
    username,
    password,
    url,
    notes,
    tags,
    custom_fields: { error: customError },
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    clearErrors(Object.values(targets), formError);
    const request = secretRequest({
      title: stored?.title ?? title.input.value,
      username: username.input.value,
      password: password.input.value,
      passwordUnchanged: passwordControl.isUnchanged(),
      url: url.input.value,
      notes: notes.input.value,
      tags: tags.input.value,
      customFields: rows.map((row) => row.values()),
    });
    const generation = pageGeneration;
    submit.disabled = true;
    (stored === null ? api.addSecret(request) : api.editSecret(request)).then(
      (saved) => {
        if (generation === pageGeneration) {
          renderDetail(saved, savedNotice(saved, stored === null));
        }
      },
      (err: unknown) => {
        if (generation === pageGeneration) {
          showError(err, targets, formError);
          submit.disabled = false;
        }
      },
    );
  });

  const cancel = button("Cancel", "button");
  cancel.className = "link";
  cancel.addEventListener("click", () => (stored === null ? showList() : showDetail(stored.title)));
  const heading = stored === null ? "Add a secret" : `Edit ${displayText(stored.title, false)}`;
  vaultPage(cancel, textElement("h2", heading), form);
  onLeave(() => {
    password.input.value = "";
    for (const row of rows) {
      row.clear();
    }
  });
  (stored === null ? title.input : username.input).focus();
}

/**
 * What to say above a secret just saved: added or saved, and whether its password was
 * generated.
 *
 * @example
 * renderDetail(saved, savedNotice(saved, true)); // "Secret added. A password was generated; …"
 */
function savedNotice(saved: SavedSecret, added: boolean): string {
  const done = added ? "Secret added." : "Secret saved.";
  return saved.password_generated
    ? `${done} A password was generated; reveal or copy it below.`
    : done;
}

/**
 * The mask shown for a hidden field, announced as hidden to screen readers.
 *
 * @example
 * row("Password", masked());
 */
function masked(): HTMLElement {
  const mask = textElement("span", MASK);
  mask.className = "masked";
  mask.setAttribute("aria-label", "hidden");
  return mask;
}

/**
 * A secret's URL: a link if `safeHref` allows it, else plain text.
 *
 * Security: the link opens in a new tab without an opener or referrer, so the site
 * can neither script this page nor learn its address.
 *
 * @example
 * row("URL", urlValue("https://github.com"));
 */
function urlValue(url: string): Node {
  const shown = displayText(url, false);
  const href = safeHref(url);
  if (href === null) {
    return document.createTextNode(shown);
  }
  const link = textElement("a", shown);
  link.href = href;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

/**
 * Unix seconds as a local date and time.
 *
 * @example
 * timestamp(1_800_000_000); // e.g. "15/01/2027, 10:40:00"
 */
function timestamp(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString();
}

window.addEventListener("pagehide", leavePage);

if (root !== null) {
  api.session().then(showVault, () => showUnlock());
}
