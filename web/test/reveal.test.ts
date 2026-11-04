// Behaviour of a revealed hidden field on screen and of copying one, with mocked timers.

import assert from "node:assert/strict";
import { afterEach, beforeEach, mock, test } from "node:test";

import { type ClipboardText, copyThenClear, RevealedField } from "../src/reveal.js";

beforeEach(() => mock.timers.enable({ apis: ["setTimeout"] }));
afterEach(() => mock.timers.reset());

/**
 * Lets every pending promise callback run (`setImmediate` is not mocked).
 *
 * @example
 * mock.timers.tick(20_000);
 * await settle();
 */
async function settle(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
}

/**
 * A field whose display records what it was last given (`null`: masked).
 *
 * @example
 * const { field, shown } = recordedField();
 */
function recordedField(): { field: RevealedField; shown: () => string | null } {
  let shown: string | null = null;
  const field = new RevealedField((value) => {
    shown = value;
  });
  return { field, shown: () => shown };
}

test("a revealed value is shown until hidden", () => {
  const { field, shown } = recordedField();
  field.reveal("s3cret!");
  assert.equal(shown(), "s3cret!");
  assert.equal(field.isRevealed, true);
  field.hide();
  assert.equal(shown(), null);
  assert.equal(field.isRevealed, false);
});

test("a revealed value is masked again after 30 seconds", () => {
  const { field, shown } = recordedField();
  field.reveal("s3cret!");
  mock.timers.tick(29_999);
  assert.equal(shown(), "s3cret!");
  mock.timers.tick(1);
  assert.equal(shown(), null);
  assert.equal(field.isRevealed, false);
});

test("revealing again restarts the 30 seconds; hiding cancels them", () => {
  const { field, shown } = recordedField();
  field.reveal("one");
  mock.timers.tick(20_000);
  field.reveal("two");
  mock.timers.tick(20_000);
  assert.equal(shown(), "two");
  mock.timers.tick(10_000);
  assert.equal(shown(), null);

  field.reveal("three");
  field.hide();
  field.reveal("four");
  mock.timers.tick(29_000);
  assert.equal(shown(), "four");
});

/**
 * A fake clipboard holding one text, recording writes.
 *
 * @example
 * const fake = fakeClipboard();
 * await copyThenClear("s3cret!", fake.clipboard, () => true);
 */
function fakeClipboard(): { clipboard: ClipboardText; text: () => string; writes: string[] } {
  let text = "";
  const writes: string[] = [];
  return {
    clipboard: {
      writeText: async (value: string) => {
        writes.push(value);
        text = value;
      },
      readText: async () => text,
    },
    text: () => text,
    writes,
  };
}

test("a copied value is cleared after 20 seconds if the page has focus and it is still there", async () => {
  const fake = fakeClipboard();
  await copyThenClear("s3cret!", fake.clipboard, () => true);
  assert.equal(fake.text(), "s3cret!");
  mock.timers.tick(19_999);
  await settle();
  assert.equal(fake.text(), "s3cret!");
  mock.timers.tick(1);
  await settle();
  assert.equal(fake.text(), "");
});

test("the clipboard is left alone if it holds something else by then", async () => {
  const fake = fakeClipboard();
  await copyThenClear("s3cret!", fake.clipboard, () => true);
  await fake.clipboard.writeText("copied since");
  mock.timers.tick(20_000);
  await settle();
  assert.equal(fake.text(), "copied since");
});

test("the clipboard is left alone if the page has no focus by then", async () => {
  const fake = fakeClipboard();
  await copyThenClear("s3cret!", fake.clipboard, () => false);
  mock.timers.tick(20_000);
  await settle();
  assert.deepEqual(fake.writes, ["s3cret!"]);
});

test("a clipboard that can't be read is left alone without an error", async () => {
  const fake = fakeClipboard();
  fake.clipboard.readText = async () => {
    throw new Error("NotAllowedError");
  };
  await copyThenClear("s3cret!", fake.clipboard, () => true);
  mock.timers.tick(20_000);
  await settle();
  assert.equal(fake.text(), "s3cret!");
});

test("a failed copy rejects and schedules nothing", async () => {
  const fake = fakeClipboard();
  fake.clipboard.writeText = async () => {
    throw new Error("NotAllowedError");
  };
  await assert.rejects(copyThenClear("s3cret!", fake.clipboard, () => true));
  let read = false;
  fake.clipboard.readText = async () => {
    read = true;
    return "";
  };
  mock.timers.tick(20_000);
  await settle();
  assert.equal(read, false);
});
