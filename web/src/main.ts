// Client entry point: the create and unlock pages, and the vault's secret list and
// secret detail pages.
//
// Security: the DOM is built only with createElement/textContent, never innerHTML or
// other HTML sinks; the CSP's `require-trusted-types-for 'script'` makes any such sink
// throw at runtime. Field values are shown through `displayText`, and a secret's URL
// is a link only for http/https (`safeHref`). Vault data and the CSRF token live in
// memory only; any 401 wipes them and shows the unlock page. Master password inputs
// are cleared once submitted. Hidden fields are masked; one reaches the browser only
// when Reveal or Copy asks for it (an audited request), and then lives only in the
// element showing it (until hidden, the page is left, or 30 s) or in the clipboard
// (cleared after 20 s if possible).

import {
  Api,
  ApiError,
  PASSWORD_FIELD,
  type SecretDetail,
  type SecretSummary,
  type SessionInfo,
  type UnlockRequest,
} from "./api.js";
import { checkNewMasterPassword, parseIdleTimeout } from "./forms.js";
import { copyThenClear, CLEAR_CLIPBOARD_AFTER_MS, RevealedField } from "./reveal.js";
import { filterSecrets } from "./secrets.js";
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

/** The vault-web API; a 401 while a vault is open wipes it and shows the unlock page. */
const api = new Api(window.fetch.bind(window), () => {
  if (session !== null) {
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
 * Shows the unlock page, with an optional `notice` (e.g. after an auto-lock), and
 * forgets the session.
 *
 * @example
 * showUnlock("Your vault was locked.");
 */
function showUnlock(notice?: string): void {
  session = null;
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
 * Shows the unlocked vault's secret list; the entry point after create, unlock and a
 * page load with a live session.
 *
 * @example
 * api.unlock(request).then(showVault);
 */
function showVault(info: SessionInfo): void {
  session = info;
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
        const message = err instanceof ApiError ? err.message : "the server could not be reached";
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
  const children: Node[] = [];
  if (notice !== undefined) {
    const note = textElement("p", notice);
    note.className = "notice";
    children.push(note);
  }
  vaultPage(...children, search.row, empty, list);
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
    renderDetail,
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
 * link only if it is http or https.
 *
 * @example
 * renderDetail(await api.getSecret("GitHub"));
 */
function renderDetail(secret: SecretDetail): void {
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
  vaultPage(back, textElement("h2", displayText(secret.title, false)), fields);
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
