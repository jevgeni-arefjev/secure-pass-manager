// Display form of field values: the same escaping as the CLI's `render::escape`,
// covering exactly the characters the server refuses in non-hidden fields.

/** Control characters (Cc), the Unicode format category (Cf), line and paragraph separators. */
const UNSAFE = /^[\p{Cc}\p{Cf}\u2028\u2029]$/u;

/**
 * Whether `char` (one code point) is refused by the server in non-hidden fields:
 * the same rule as `vault-core`'s `is_unsafe_char`.
 *
 * @example
 * isUnsafe("\u202e"); // true (right-to-left override)
 * isUnsafe("\u00ad"); // true (soft hyphen)
 */
function isUnsafe(char: string): boolean {
  return UNSAFE.test(char);
}

/**
 * `text` with every character the server refuses in non-hidden fields (control and
 * format characters, line and paragraph separators) replaced by a visible escape
 * (`\x1b`, `\u{202e}`); newlines and tabs are kept when `multiline` (notes).
 *
 * Security: the result is still only ever set with `textContent`, which already keeps
 * markup inert. This also stops terminal escapes, bidi overrides ("Trojan Source")
 * and zero-width characters from making a value look different than it is. The
 * server refuses them on save; this covers vault files written by other means and
 * secrets saved under older rules. Tested against the shared fixture
 * `fixtures/unsafe-characters.json`, like the server's rule and the CLI's escaper.
 *
 * @example
 * displayText("evil‮txt.exe", false); // "evil\\u{202e}txt.exe"
 * displayText("line 1\nline 2", true);     // "line 1\nline 2"
 */
export function displayText(text: string, multiline: boolean): string {
  let out = "";
  for (const char of text) {
    const c = char.codePointAt(0) ?? 0;
    const keptWhitespace = multiline && (char === "\n" || char === "\t");
    if (keptWhitespace || !isUnsafe(char)) {
      out += char;
    } else if (c <= 0xff) {
      out += `\\x${c.toString(16).padStart(2, "0")}`;
    } else {
      out += `\\u{${c.toString(16)}}`;
    }
  }
  return out;
}
