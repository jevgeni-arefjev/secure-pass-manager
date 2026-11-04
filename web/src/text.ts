// Display form of field values: the same escaping as the CLI's `render::escape`.

/**
 * Whether `c` is a control character (C0, DEL or C1) or an invisible formatting
 * character: zero-width characters, bidirectional overrides and isolates, and the BOM.
 *
 * @example
 * isUnsafe("‮"); // true
 */
function isUnsafe(c: number): boolean {
  const control = c <= 0x1f || (c >= 0x7f && c <= 0x9f);
  const invisible =
    (c >= 0x200b && c <= 0x200f) || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c === 0xfeff;
  return control || invisible;
}

/**
 * `text` with every control and invisible formatting character replaced by a visible
 * escape (`\x1b`, `\u{202e}`); newlines and tabs are kept when `multiline` (notes).
 *
 * Security: the result is still only ever set with `textContent`, which already keeps
 * markup inert. This also stops terminal escapes, bidi overrides ("Trojan Source")
 * and zero-width characters from making a value look different than it is. The
 * server refuses them on save; this covers vault files written by other means.
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
    if (keptWhitespace || !isUnsafe(c)) {
      out += char;
    } else if (c <= 0xff) {
      out += `\\x${c.toString(16).padStart(2, "0")}`;
    } else {
      out += `\\u{${c.toString(16)}}`;
    }
  }
  return out;
}
