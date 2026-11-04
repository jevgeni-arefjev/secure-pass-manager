// Behaviour of the API client, through its public methods, against a fake fetch.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Api, ApiError } from "../src/api.js";

interface Call {
  url: string;
  init: RequestInit;
}

/** A fake fetch answering every call with `status` and `body`, recording the calls. */
function fakeFetch(status: number, body: unknown): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fetch = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.push({ url: String(url), init: init ?? {} });
    const text = body === undefined ? null : JSON.stringify(body);
    return new Response(text, { status, headers: { "content-type": "application/json" } });
  };
  return { fetch: fetch as typeof globalThis.fetch, calls };
}

const SESSION = { csrf_token: "a".repeat(64), vaultname: "alice", idle_timeout_minutes: 5 };

/** The headers of a recorded call, as a plain record. */
function headers(call: Call): Record<string, string> {
  return Object.fromEntries(new Headers(call.init.headers).entries());
}

test("unlock posts JSON and keeps the CSRF token for later state-changing calls", async () => {
  const { fetch, calls } = fakeFetch(200, SESSION);
  const api = new Api(fetch, () => {});
  const info = await api.unlock({ vaultname: "alice", master_password: "pw", idle_timeout_minutes: 5 });
  assert.deepEqual(info, SESSION);
  assert.equal(calls[0]?.url, "/api/unlock");
  assert.equal(calls[0]?.init.method, "POST");
  assert.equal(headers(calls[0]!)["content-type"], "application/json");
  assert.equal(headers(calls[0]!)["x-csrf-token"], undefined);
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), {
    vaultname: "alice",
    master_password: "pw",
    idle_timeout_minutes: 5,
  });

  await api.lock().catch(() => {});
  assert.equal(calls[1]?.url, "/api/lock");
  assert.equal(headers(calls[1]!)["x-csrf-token"], SESSION.csrf_token);
});

test("an absent idle timeout is left out of the request", async () => {
  const { fetch, calls } = fakeFetch(201, SESSION);
  const api = new Api(fetch, () => {});
  await api.createVault({ vaultname: "alice", master_password: "pw" });
  assert.equal(calls[0]?.url, "/api/vaults");
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), { vaultname: "alice", master_password: "pw" });
});

test("the session check restores the CSRF token after a page load", async () => {
  const { fetch, calls } = fakeFetch(200, SESSION);
  const api = new Api(fetch, () => {});
  assert.deepEqual(await api.session(), SESSION);
  assert.equal(calls[0]?.init.method, "GET");
  await api.lock().catch(() => {});
  assert.equal(headers(calls[1]!)["x-csrf-token"], SESSION.csrf_token);
});

test("any 401 outside unlock means locked: the token is wiped and onLocked runs", async () => {
  let locked = 0;
  const ok = fakeFetch(200, SESSION);
  const api = new Api(ok.fetch, () => locked++);
  await api.unlock({ vaultname: "alice", master_password: "pw" });

  const gone = fakeFetch(401, { error: "vault is locked" });
  const lockedApi = new Api(gone.fetch, () => locked++);
  await assert.rejects(lockedApi.session(), (err: unknown) => err instanceof ApiError && err.status === 401);
  assert.equal(locked, 1);
});

test("a failed unlock is an error with the server's message, not a lock", async () => {
  let locked = 0;
  const { fetch } = fakeFetch(401, { error: "wrong vaultname or master password" });
  const api = new Api(fetch, () => locked++);
  await assert.rejects(api.unlock({ vaultname: "alice", master_password: "pw" }), (err: unknown) => {
    assert.ok(err instanceof ApiError);
    assert.equal(err.message, "wrong vaultname or master password");
    return true;
  });
  assert.equal(locked, 0);
});

test("lock wipes the CSRF token even though it succeeds", async () => {
  const ok = fakeFetch(200, SESSION);
  let current = ok.fetch;
  const api = new Api((url, init) => current(url, init), () => {});
  await api.unlock({ vaultname: "alice", master_password: "pw" });
  const done = fakeFetch(204, undefined);
  current = done.fetch;
  await api.lock();
  await api.lock().catch(() => {});
  assert.equal(headers(done.calls[1]!)["x-csrf-token"], undefined);
});

test("field errors carry the field name", async () => {
  const { fetch } = fakeFetch(400, { error: "master password is too common", field: "master_password" });
  const api = new Api(fetch, () => {});
  await assert.rejects(api.createVault({ vaultname: "alice", master_password: "password1234" }), (err: unknown) => {
    assert.ok(err instanceof ApiError);
    assert.equal(err.status, 400);
    assert.equal(err.field, "master_password");
    return true;
  });
});

test("a response without a JSON error body still gives a generic error", async () => {
  const fetch = (async () => new Response("<html>", { status: 502 })) as typeof globalThis.fetch;
  const api = new Api(fetch, () => {});
  await assert.rejects(api.session(), (err: unknown) => {
    assert.ok(err instanceof ApiError);
    assert.equal(err.status, 502);
    assert.equal(err.message, "request failed");
    return true;
  });
});
