// Pure helpers for the secret pages: search over the loaded list, and the API path of
// a secret by its title.

import type { SecretSummary } from "./api.js";

/**
 * The secrets matching `query`, in their original order: every whitespace-separated
 * word of the query must appear, ignoring case, in the title, username, URL or a tag.
 * A blank query matches everything.
 *
 * Runs in the browser over the already loaded list; the query is never sent to the
 * server. Words are matched as plain substrings, never as patterns.
 *
 * @example
 * filterSecrets(secrets, "alice work"); // secrets with both "alice" and "work" in a searched field
 */
export function filterSecrets(secrets: readonly SecretSummary[], query: string): SecretSummary[] {
  const words = query.toLowerCase().split(/\s+/).filter((word) => word !== "");
  if (words.length === 0) {
    return [...secrets];
  }
  return secrets.filter((secret) => {
    const fields = [secret.title, secret.username ?? "", secret.url ?? "", ...secret.tags].map((field) =>
      field.toLowerCase(),
    );
    return words.every((word) => fields.some((field) => field.includes(word)));
  });
}

/** Titles that would be a dot segment of the path, which URL parsing resolves away. */
const DOT_SEGMENTS: ReadonlySet<string> = new Set([".", ".."]);

/**
 * The API path of the secret titled `title`: `/api/secrets/` and the title as one
 * percent-encoded path segment.
 *
 * Security: `encodeURIComponent` encodes `/`, `?`, `#`, `%` and the like, so a title
 * stays one segment. The titles `.` and `..` (even percent-encoded) would still be
 * resolved by URL parsing into another path, so they get an encoded trailing space:
 * the server matches titles ignoring surrounding spaces, and no stored title has one.
 *
 * @example
 * secretPath("my bank / savings"); // "/api/secrets/my%20bank%20%2F%20savings"
 * secretPath("..");                // "/api/secrets/..%20"
 */
export function secretPath(title: string): string {
  const segment = encodeURIComponent(title);
  return `/api/secrets/${DOT_SEGMENTS.has(title) ? `${segment}%20` : segment}`;
}
