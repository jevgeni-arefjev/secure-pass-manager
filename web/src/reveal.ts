// How long revealed hidden values last in the browser: on screen until hidden or for
// 30 s at most, and in the clipboard for 20 s if the page can still clear it.
//
// Security: a revealed value is handed straight to the element showing it and kept
// nowhere else; JavaScript can't wipe strings, so the shortest lifetime is the defence.

/** How long a revealed value stays on screen. */
export const REVEAL_FOR_MS = 30_000;

/** How long a copied value may stay in the clipboard. */
export const CLEAR_CLIPBOARD_AFTER_MS = 20_000;

/** The part of `navigator.clipboard` used here. */
export interface ClipboardText {
  writeText(text: string): Promise<void>;
  readText(): Promise<string>;
}

/**
 * One hidden field on screen: masked, or showing its revealed value for at most
 * {@link REVEAL_FOR_MS}.
 *
 * `display` receives the value to show, or `null` for the mask; it must put the
 * value only into the element showing it and drop the old one.
 *
 * @example
 * const field = new RevealedField((value) => (span.textContent = value ?? MASK));
 * field.reveal(await api.revealField("GitHub", PASSWORD_FIELD));
 */
export class RevealedField {
  readonly #display: (value: string | null) => void;
  #timer: ReturnType<typeof setTimeout> | undefined;

  /**
   * A masked field drawn by `display`.
   *
   * @example
   * const field = new RevealedField(showInSpan);
   */
  constructor(display: (value: string | null) => void) {
    this.#display = display;
  }

  /**
   * Whether the field shows a value right now.
   *
   * @example
   * toggle.textContent = field.isRevealed ? "Hide" : "Reveal";
   */
  get isRevealed(): boolean {
    return this.#timer !== undefined;
  }

  /**
   * Shows `value` and masks it again after {@link REVEAL_FOR_MS}, restarting the
   * countdown if a value was already shown.
   *
   * @example
   * field.reveal("s3cret!");
   */
  reveal(value: string): void {
    clearTimeout(this.#timer);
    this.#display(value);
    this.#timer = setTimeout(() => this.hide(), REVEAL_FOR_MS);
  }

  /**
   * Masks the field and stops the countdown. Safe to call when already masked, e.g.
   * when leaving the page.
   *
   * @example
   * field.hide();
   */
  hide(): void {
    clearTimeout(this.#timer);
    this.#timer = undefined;
    this.#display(null);
  }
}

/**
 * Copies `value` to `clipboard`, then after {@link CLEAR_CLIPBOARD_AFTER_MS} clears
 * the clipboard if `hasFocus()` and it still holds `value`. Rejects if the copy
 * fails, and then schedules nothing.
 *
 * Security: best effort only. Browsers allow reading the clipboard only with focus
 * (and may ask permission); anything copied since is left alone. The value is kept
 * in this closure until the check runs.
 *
 * @example
 * await copyThenClear(value, navigator.clipboard, () => document.hasFocus());
 */
export async function copyThenClear(value: string, clipboard: ClipboardText, hasFocus: () => boolean): Promise<void> {
  await clipboard.writeText(value);
  setTimeout(() => {
    void clearIfStillHolding(value, clipboard, hasFocus);
  }, CLEAR_CLIPBOARD_AFTER_MS);
}

/**
 * Empties `clipboard` if the page has focus and it holds `value`; ignores any failure.
 *
 * @example
 * await clearIfStillHolding("s3cret!", navigator.clipboard, () => document.hasFocus());
 */
async function clearIfStillHolding(value: string, clipboard: ClipboardText, hasFocus: () => boolean): Promise<void> {
  if (!hasFocus()) {
    return;
  }
  try {
    if ((await clipboard.readText()) === value) {
      await clipboard.writeText("");
    }
  } catch {
    // No permission or no focus any more: leave the clipboard as it is.
  }
}
