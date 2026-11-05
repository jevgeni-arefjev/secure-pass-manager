// Behaviour of the periodic session check, with mocked timers and a fake page.

import assert from "node:assert/strict";
import { afterEach, beforeEach, mock, test } from "node:test";

import { CHECK_SESSION_EVERY_MS, type PageVisibility, watchSession } from "../src/session-watch.js";

beforeEach(() => mock.timers.enable({ apis: ["setInterval"] }));
afterEach(() => mock.timers.reset());

/**
 * Lets every pending promise callback run (`setImmediate` is not mocked).
 *
 * @example
 * await settle();
 */
async function settle(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
}

/** A page whose visibility the test flips, firing `visibilitychange`. */
class FakePage implements PageVisibility {
  hidden = false;
  #listeners: (() => void)[] = [];

  /**
   * Registers a `visibilitychange` listener.
   *
   * @example
   * page.addEventListener("visibilitychange", onChange);
   */
  addEventListener(_type: "visibilitychange", listener: () => void): void {
    this.#listeners.push(listener);
  }

  /**
   * Unregisters a `visibilitychange` listener.
   *
   * @example
   * page.removeEventListener("visibilitychange", onChange);
   */
  removeEventListener(_type: "visibilitychange", listener: () => void): void {
    this.#listeners = this.#listeners.filter((l) => l !== listener);
  }

  /**
   * Sets `hidden` and fires `visibilitychange`.
   *
   * @example
   * page.setHidden(false); // the tab came back to the front
   */
  setHidden(hidden: boolean): void {
    this.hidden = hidden;
    for (const listener of this.#listeners) {
      listener();
    }
  }
}

/**
 * A check that counts its calls and resolves at once.
 *
 * @example
 * const { check, calls } = countingCheck();
 */
function countingCheck(): { check: () => Promise<unknown>; calls: () => number } {
  let calls = 0;
  return {
    check: async () => {
      calls += 1;
    },
    calls: () => calls,
  };
}

test("the session is checked every interval", async () => {
  const { check, calls } = countingCheck();
  watchSession(check, new FakePage());
  assert.equal(calls(), 0);
  mock.timers.tick(CHECK_SESSION_EVERY_MS);
  await settle();
  assert.equal(calls(), 1);
  mock.timers.tick(CHECK_SESSION_EVERY_MS);
  await settle();
  assert.equal(calls(), 2);
});

test("the interval is thirty seconds", () => {
  assert.equal(CHECK_SESSION_EVERY_MS, 30_000);
});

test("a tab coming back to the front is checked at once", async () => {
  const { check, calls } = countingCheck();
  const page = new FakePage();
  watchSession(check, page);
  page.setHidden(true);
  assert.equal(calls(), 0);
  page.setHidden(false);
  await settle();
  assert.equal(calls(), 1);
});

test("stopping ends both the timer and the visibility check", async () => {
  const { check, calls } = countingCheck();
  const page = new FakePage();
  const stop = watchSession(check, page);
  stop();
  mock.timers.tick(CHECK_SESSION_EVERY_MS * 3);
  page.setHidden(false);
  await settle();
  assert.equal(calls(), 0);
});

test("a failed check is ignored and checking goes on", async () => {
  let calls = 0;
  watchSession(async () => {
    calls += 1;
    throw new Error("network down");
  }, new FakePage());
  mock.timers.tick(CHECK_SESSION_EVERY_MS);
  await settle();
  mock.timers.tick(CHECK_SESSION_EVERY_MS);
  await settle();
  assert.equal(calls, 2);
});

test("a check still running is not started again", async () => {
  let calls = 0;
  let finish: () => void = () => {};
  watchSession(() => {
    calls += 1;
    return new Promise<void>((resolve) => (finish = resolve));
  }, new FakePage());
  mock.timers.tick(CHECK_SESSION_EVERY_MS);
  mock.timers.tick(CHECK_SESSION_EVERY_MS);
  await settle();
  assert.equal(calls, 1);
  finish();
  await settle();
  mock.timers.tick(CHECK_SESSION_EVERY_MS);
  await settle();
  assert.equal(calls, 2);
});
