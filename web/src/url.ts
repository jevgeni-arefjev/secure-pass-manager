// URL scheme allowlist for showing a secret's URL as a link.

/** Schemes a secret's URL may be linked with; anything else is shown as text only. */
const LINKABLE_PROTOCOLS: ReadonlySet<string> = new Set(["http:", "https:"]);

/**
 * The href to link a secret's `url` with, or `null` if it must only be shown as text.
 *
 * Security: only absolute `http:` and `https:` URLs pass, so a stored
 * `javascript:` or `data:` URL can never run script when clicked. The URL is parsed
 * with the WHATWG parser (as the browser would), not matched by prefix, so
 * whitespace or tab tricks like `java\tscript:` don't slip through.
 *
 * @example
 * safeHref("https://github.com/login"); // "https://github.com/login"
 * safeHref("javascript:alert(1)");      // null
 */
export function safeHref(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (!LINKABLE_PROTOCOLS.has(parsed.protocol) || parsed.hostname === "") {
    return null;
  }
  return parsed.href;
}
