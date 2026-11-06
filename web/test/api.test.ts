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

test("listSecrets reads the list from GET /api/secrets without a CSRF header", async () => {
  const secrets = [{ title: "GitHub", username: "alice", url: null, tags: [], has_password: true, has_notes: false, custom_fields: [], created_at: 1, updated_at: 1 }];
  const { fetch, calls } = fakeFetch(200, { secrets });
  const api = new Api(fetch, () => {});
  assert.deepEqual(await api.listSecrets(), secrets);
  assert.equal(calls[0]?.url, "/api/secrets");
  assert.equal(calls[0]?.init.method, "GET");
  assert.equal(headers(calls[0]!)["x-csrf-token"], undefined);
});

test("getSecret asks for the percent-encoded title; a 404 is an error, not a lock", async () => {
  const { fetch, calls } = fakeFetch(404, { error: "no secret with this title" });
  let locked = false;
  const api = new Api(fetch, () => {
    locked = true;
  });
  await assert.rejects(api.getSecret("my bank / savings"), (err: unknown) => {
    assert.ok(err instanceof ApiError);
    assert.equal(err.status, 404);
    return true;
  });
  assert.equal(calls[0]?.url, "/api/secrets/my%20bank%20%2F%20savings");
  assert.equal(locked, false);
});

test("revealField posts one field name with the CSRF token and returns that one value", async () => {
  const ok = fakeFetch(200, SESSION);
  let current = ok.fetch;
  const api = new Api((url, init) => current(url, init), () => {});
  await api.unlock({ vaultname: "alice", master_password: "pw" });
  const revealed = fakeFetch(200, { value: "s3cret!" });
  current = revealed.fetch;

  assert.equal(await api.revealField("my bank / savings", "recovery code"), "s3cret!");
  const call = revealed.calls[0]!;
  assert.equal(call.url, "/api/secrets/my%20bank%20%2F%20savings/reveal");
  assert.equal(call.init.method, "POST");
  assert.equal(headers(call)["x-csrf-token"], SESSION.csrf_token);
  assert.deepEqual(JSON.parse(String(call.init.body)), { field: "recovery code" });
});

/** An api unlocked with {@link SESSION}, whose later calls go to `next`. */
async function unlockedApi(next: { fetch: typeof fetch }, onLocked: () => void = () => {}): Promise<Api> {
  const ok = fakeFetch(200, SESSION);
  let current = ok.fetch;
  const api = new Api((url, init) => current(url, init), onLocked);
  await api.unlock({ vaultname: "alice", master_password: "pw" });
  current = next.fetch;
  return api;
}

const SAVED = {
  title: "GitHub",
  username: null,
  url: null,
  notes: null,
  tags: [],
  has_password: true,
  custom_fields: [],
  created_at: 1,
  updated_at: 1,
  password_generated: true,
};

test("addSecret posts the secret to /api/secrets with the CSRF token", async () => {
  const added = fakeFetch(201, SAVED);
  const api = await unlockedApi(added);
  const request = { title: "GitHub", tags: [], custom_fields: [] };

  assert.deepEqual(await api.addSecret(request), SAVED);
  const call = added.calls[0]!;
  assert.equal(call.url, "/api/secrets");
  assert.equal(call.init.method, "POST");
  assert.equal(headers(call)["x-csrf-token"], SESSION.csrf_token);
  assert.deepEqual(JSON.parse(String(call.init.body)), request);
});

test("editSecret puts the secret to its percent-encoded title", async () => {
  const edited = fakeFetch(200, { ...SAVED, title: "my bank / savings", password_generated: false });
  const api = await unlockedApi(edited);
  const request = { title: "my bank / savings", password: { unchanged: true as const }, tags: [], custom_fields: [] };

  await api.editSecret(request);
  const call = edited.calls[0]!;
  assert.equal(call.url, "/api/secrets/my%20bank%20%2F%20savings");
  assert.equal(call.init.method, "PUT");
  assert.equal(headers(call)["x-csrf-token"], SESSION.csrf_token);
  assert.deepEqual(JSON.parse(String(call.init.body)), request);
});

test("deleteSecret sends DELETE with the CSRF token and no body", async () => {
  const deleted = fakeFetch(204, undefined);
  const api = await unlockedApi(deleted);

  assert.equal(await api.deleteSecret(".."), undefined);
  const call = deleted.calls[0]!;
  assert.equal(call.url, "/api/secrets/..%20");
  assert.equal(call.init.method, "DELETE");
  assert.equal(headers(call)["x-csrf-token"], SESSION.csrf_token);
  assert.equal(call.init.body, undefined);
});

test("a save conflict (401) on a change means locked: onLocked runs", async () => {
  let locked = 0;
  const conflict = fakeFetch(401, { error: "vault is locked" });
  const api = await unlockedApi(conflict, () => locked++);

  await assert.rejects(
    api.addSecret({ title: "GitLab", tags: [], custom_fields: [] }),
    (err: unknown) => err instanceof ApiError && err.status === 401,
  );
  assert.equal(locked, 1);
});

test("a 409 on add is an error naming the title field, not a lock", async () => {
  let locked = 0;
  const taken = fakeFetch(409, { error: "a secret with this title already exists", field: "title" });
  const api = await unlockedApi(taken, () => locked++);

  await assert.rejects(api.addSecret({ title: "GitHub", tags: [], custom_fields: [] }), (err: unknown) => {
    assert.ok(err instanceof ApiError);
    assert.equal(err.status, 409);
    assert.equal(err.field, "title");
    return true;
  });
  assert.equal(locked, 0);
});

test("a refused secret's problems are read from its fields array", async () => {
  const refused = fakeFetch(400, {
    error: "secret not saved: some fields are invalid",
    fields: [
      { field: "title", message: "title must be 1-64 characters, without control or formatting characters" },
      { field: "tags", index: 1, message: "tags must be unique, ignoring case" },
      { field: "custom_fields", index: 0, part: "value", message: "custom field values must be ..." },
      { field: "notes", index: "1", message: "a malformed entry is dropped" },
      "not an object",
    ],
  });
  const api = await unlockedApi(refused, () => {});

  await assert.rejects(api.addSecret({ title: "", tags: [], custom_fields: [] }), (err: unknown) => {
    assert.ok(err instanceof ApiError);
    assert.equal(err.status, 400);
    assert.equal(err.field, undefined);
    assert.deepEqual(err.fields, [
      { field: "title", message: "title must be 1-64 characters, without control or formatting characters" },
      { field: "tags", index: 1, message: "tags must be unique, ignoring case" },
      { field: "custom_fields", index: 0, part: "value", message: "custom field values must be ..." },
    ]);
    return true;
  });
});

test("an error without a fields array has no problems listed", async () => {
  const taken = fakeFetch(409, { error: "a secret with this title already exists", field: "title" });
  const api = await unlockedApi(taken, () => {});

  await assert.rejects(api.addSecret({ title: "GitHub", tags: [], custom_fields: [] }), (err: unknown) => {
    assert.ok(err instanceof ApiError);
    assert.deepEqual(err.fields, []);
    return true;
  });
});
