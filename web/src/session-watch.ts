// Noticing that the server ended the session while a vault page sits open: a periodic
// `GET /api/session`, and one more as soon as the tab comes back to the front.
//
// Security: the server is authoritative about when a session ends (idle timeout,
// 8 h lifetime, shutdown). This only makes an untouched tab drop the vault data on
// screen soon after; the check doesn't count as activity, so it never keeps a
// session open.

/** How often an open vault page checks that its session is still live. */
export const CHECK_SESSION_EVERY_MS = 30_000;

/** The part of `document` used here: whether the tab is hidden, and when that changes. */
export interface PageVisibility {
  readonly hidden: boolean;
  addEventListener(type: "visibilitychange", listener: () => void): void;
  removeEventListener(type: "visibilitychange", listener: () => void): void;
}

/**
 * Runs `check` every {@link CHECK_SESSION_EVERY_MS} and whenever `page` becomes
 * visible, until the returned function is called. A check still running is not
 * started again, and a failed check is ignored: `check` must itself react to an ended
 * session (the API client's 401 handling shows the unlock page).
 *
 * @example
 * const stop = watchSession(() => api.session(), document);
 * // on lock:
 * stop();
 */
export function watchSession(check: () => Promise<unknown>, page: PageVisibility): () => void {
  let running = false;
  const run = (): void => {
    if (running) {
      return;
    }
    running = true;
    check()
      .catch(() => {
        // Network errors and the like: try again on the next tick.
      })
      .finally(() => {
        running = false;
      });
  };
  const onVisibilityChange = (): void => {
    if (!page.hidden) {
      run();
    }
  };
  const timer = setInterval(run, CHECK_SESSION_EVERY_MS);
  page.addEventListener("visibilitychange", onVisibilityChange);
  return () => {
    clearInterval(timer);
    page.removeEventListener("visibilitychange", onVisibilityChange);
  };
}
